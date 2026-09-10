//! Payjoin receiver daemon.
//!
//! Generates a per-URI nostr session key, prints a BIP21 payjoin URI, then waits
//! on relays for a sender's Original PSBT. When one arrives it walks the full
//! payjoin validation typestate, contributes one UTXO, signs, and publishes the
//! Payjoin Proposal back to the sender's sealed key.
//!
//! The receiver is free to be offline between those steps. That is the entire
//! point: relays hold the sender's payload until we come back.

use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use pjn_transport::{Leg, NostrTransport, PayjoinEnvelope};
use pjn_wallet::receiver::{self, FeePolicy, SeenInputs};
use pjn_wallet::signet::SignetWallet;
use pjn_wallet::uri::NostrRoute;
use pjn_wallet::{Address, Amount};

const DEFAULT_RELAYS: &str = "wss://relay.damus.io,wss://nos.lol";
const DEFAULT_ESPLORA: &str = "https://mutinynet.com/api";

#[derive(Parser)]
#[command(
    name = "pjn-receiver",
    about = "Receive a Payjoin over nostr relays, with no directory and no OHTTP relay"
)]
struct Cli {
    /// External (receive) descriptor.
    #[arg(long, env = "PJN_DESCRIPTOR", global = true)]
    descriptor: Option<String>,

    /// Internal (change) descriptor.
    #[arg(long, env = "PJN_CHANGE_DESCRIPTOR", global = true)]
    change_descriptor: Option<String>,

    /// Esplora instance to sync against.
    #[arg(long, env = "PJN_ESPLORA", default_value = DEFAULT_ESPLORA, global = true)]
    esplora: String,

    /// Comma-separated relay list.
    #[arg(long, env = "PJN_RELAYS", default_value = DEFAULT_RELAYS, global = true)]
    relays: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Sync the wallet and show its balance and next receive address.
    Status,

    /// Print a payjoin URI and wait for a sender.
    Serve {
        /// Amount to request, in satoshis.
        #[arg(long)]
        amount: u64,

        /// How long to wait for the sender's Original PSBT.
        #[arg(long, default_value = "3600")]
        timeout_secs: u64,

        /// Keep serving after completing one payjoin.
        #[arg(long)]
        keep_alive: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "pjn_receiver=info,pjn_transport=info".into()),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    let relays = parse_relays(&cli.relays)?;

    let descriptor = cli
        .descriptor
        .as_deref()
        .context("--descriptor is required (or set PJN_DESCRIPTOR)")?;
    let change_descriptor = cli
        .change_descriptor
        .as_deref()
        .context("--change-descriptor is required (or set PJN_CHANGE_DESCRIPTOR)")?;

    let mut wallet = SignetWallet::new(descriptor, change_descriptor, &cli.esplora)?;

    match cli.command {
        Command::Status => status(&mut wallet),
        Command::Serve {
            amount,
            timeout_secs,
            keep_alive,
        } => {
            serve(
                &mut wallet,
                &relays,
                Amount::from_sat(amount),
                Duration::from_secs(timeout_secs),
                keep_alive,
            )
            .await
        }
    }
}

fn parse_relays(raw: &str) -> Result<Vec<String>> {
    let relays: Vec<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    anyhow::ensure!(!relays.is_empty(), "no relays configured");
    Ok(relays)
}

fn status(wallet: &mut SignetWallet) -> Result<()> {
    tracing::info!("scanning chain, this takes a moment on first run");
    wallet.full_scan()?;

    let balance = wallet.balance();
    let address = wallet.next_address();

    println!(
        "balance        : {} sat confirmed",
        balance.confirmed.to_sat()
    );
    println!(
        "                 {} sat pending",
        balance.trusted_pending.to_sat() + balance.untrusted_pending.to_sat()
    );
    println!("spendable utxos: {}", wallet.spendable_utxo_count());
    println!("receive address: {}", address.address);

    if wallet.spendable_utxo_count() == 0 {
        println!();
        println!("No UTXOs yet. A payjoin receiver must contribute an input, so fund");
        println!("this address before serving — https://faucet.mutinynet.com");
    }
    Ok(())
}

async fn serve(
    wallet: &mut SignetWallet,
    relays: &[String],
    amount: Amount,
    timeout: Duration,
    keep_alive: bool,
) -> Result<()> {
    tracing::info!("syncing wallet");
    wallet.full_scan()?;

    anyhow::ensure!(
        wallet.spendable_utxo_count() > 0,
        "wallet has no UTXOs to contribute — a payjoin receiver must supply an \
         input, so fund it first (https://faucet.mutinynet.com)"
    );

    let address = wallet.next_address().address;

    // A fresh key per URI. Reusing one would let relays link every payment this
    // receiver coordinates; see docs/threat-model.md.
    let transport = NostrTransport::ephemeral(relays).await?;
    let route = NostrRoute::new(transport.public_key().to_hex(), relays.to_vec())?;

    print_uri(&address, amount, &route)?;

    let mut seen = SeenInputs::new();
    loop {
        match run_one_session(wallet, &transport, &mut seen, timeout).await {
            Ok(true) => {
                if !keep_alive {
                    break;
                }
                tracing::info!("payjoin complete, still listening (--keep-alive)");
            }
            Ok(false) => {
                tracing::warn!("no sender arrived within the timeout");
                break;
            }
            Err(e) => {
                // A failed session is often an attack, not a bug — a prober
                // whose PSBT we rejected. Log it and keep serving.
                tracing::warn!(error = %e, "payjoin session failed");
                if !keep_alive {
                    break;
                }
            }
        }
    }

    transport.shutdown().await;
    Ok(())
}

fn print_uri(address: &Address, amount: Amount, route: &NostrRoute) -> Result<()> {
    // Built by hand rather than through payjoin's PjUri Display so the nostr
    // routing survives verbatim; see pjn_wallet::uri for why the endpoint is
    // shaped like a URL it never fetches.
    let uri = format!(
        "bitcoin:{}?amount={}&pj={}",
        address,
        amount.to_btc(),
        route.to_endpoint()
    );

    println!();
    println!("  Payjoin URI (send this to the payer):");
    println!();
    println!("  {uri}");
    println!();
    println!("  session key : {}", route.session_pubkey);
    println!("  relays      : {}", route.relays.join(", "));
    println!();
    println!("  Waiting for the sender. You can close this and come back —");
    println!("  the relays will hold their payload until then.");
    println!();
    Ok(())
}

/// Run one payjoin exchange. Returns `false` if nothing arrived before `timeout`.
async fn run_one_session(
    wallet: &SignetWallet,
    transport: &NostrTransport,
    seen: &mut SeenInputs,
    timeout: Duration,
) -> Result<bool> {
    let Some((sender, envelope)) = transport.recv(timeout).await? else {
        return Ok(false);
    };

    if envelope.leg != Leg::OriginalPsbt {
        tracing::debug!(?envelope.leg, "ignoring envelope that is not an Original PSBT");
        return Ok(false);
    }
    tracing::info!(session = %envelope.session, "received an Original PSBT");

    // Walk the full validation typestate. Any failure here is reported back as a
    // generic error: telling a sender *which* check it failed would help it map
    // our wallet.
    let proposal = match receiver::respond(&envelope.payload, wallet, seen, FeePolicy::default()) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!(error = %e, "rejecting proposal");
            let reply = PayjoinEnvelope {
                leg: Leg::Error,
                session: envelope.session,
                payload: b"payjoin request rejected".to_vec(),
            };
            transport.send(sender, &reply).await?;
            return Err(e);
        }
    };

    let reply = PayjoinEnvelope {
        leg: Leg::Proposal,
        session: envelope.session.clone(),
        payload: proposal,
    };
    let event_id = transport.send(sender, &reply).await?;

    tracing::info!(%event_id, session = %envelope.session, "payjoin proposal sent");
    println!();
    println!("  Contributed an input and returned the Payjoin Proposal.");
    println!("  The sender signs and broadcasts from here.");
    println!();

    Ok(true)
}
