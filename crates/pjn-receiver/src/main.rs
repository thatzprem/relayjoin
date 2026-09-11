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
use pjn_wallet::session::{self, ReceiverSession, DEFAULT_SESSION_FILE};
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

    /// Where to keep session state so a payjoin survives a restart.
    #[arg(long, default_value = DEFAULT_SESSION_FILE, global = true)]
    session_file: std::path::PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a fresh signet descriptor pair.
    ///
    /// Both parties need one. Signet coins have no value, so these are printed
    /// to stdout rather than managed as secrets — do not reuse this command's
    /// output for anything on mainnet.
    Keygen,

    /// Sync the wallet and show its balance and next receive address.
    Status,

    /// Forget any saved session, invalidating its payjoin URI.
    Reset,

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

    // Keygen needs no wallet, and requiring a descriptor to produce one would be
    // a chicken-and-egg problem for a first-time user.
    if matches!(cli.command, Command::Keygen) {
        return keygen();
    }
    if matches!(cli.command, Command::Reset) {
        session::clear(&cli.session_file)?;
        println!("Session cleared. Any URI printed from it can no longer be used.");
        return Ok(());
    }

    let relays = parse_relays(&cli.relays)?;

    let descriptor = cli
        .descriptor
        .as_deref()
        .context("--descriptor is required (or set PJN_DESCRIPTOR); run `keygen` to make one")?;
    let change_descriptor = cli.change_descriptor.as_deref().context(
        "--change-descriptor is required (or set PJN_CHANGE_DESCRIPTOR); run `keygen` to make one",
    )?;

    let mut wallet = SignetWallet::new(descriptor, change_descriptor, &cli.esplora)?;

    match cli.command {
        // Handled above, before the wallet is built.
        Command::Keygen | Command::Reset => unreachable!("handled before the wallet is built"),
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
                &cli.session_file,
            )
            .await
        }
    }
}

/// Print a fresh signet descriptor pair.
fn keygen() -> Result<()> {
    use bitcoin::bip32::Xpriv;
    use bitcoin::Network;

    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).context("gathering entropy for a new key")?;
    let master = Xpriv::new_master(Network::Signet, &seed).context("deriving master key")?;

    // BIP84 account 0 on testnet coin type, which is what signet uses.
    println!("export PJN_DESCRIPTOR=\"wpkh({master}/84'/1'/0'/0/*)\"");
    println!("export PJN_CHANGE_DESCRIPTOR=\"wpkh({master}/84'/1'/0'/1/*)\"");
    println!();
    println!("# Signet coins have no value, so this key is printed in the clear.");
    println!("# Never use this command's output on mainnet.");
    Ok(())
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
    session_file: &std::path::Path,
) -> Result<()> {
    tracing::info!("syncing wallet");
    wallet.full_scan()?;

    anyhow::ensure!(
        wallet.spendable_utxo_count() > 0,
        "wallet has no UTXOs to contribute — a payjoin receiver must supply an \
         input, so fund it first (https://faucet.mutinynet.com)"
    );

    // Resume the previous session if there is one, so the URI already handed to a
    // payer keeps working. Generating a fresh key here would silently invalidate
    // it, which is exactly the bug this file exists to prevent.
    let existing: Option<ReceiverSession> = session::load(session_file)?;

    let (transport, mut state) = match existing {
        Some(state) => {
            tracing::info!(path = %session_file.display(), "resuming saved session");
            let transport = NostrTransport::from_secret_hex(&state.secret_key, relays).await?;
            (transport, state)
        }
        None => {
            // A fresh key per URI. Reusing one across URIs would let relays link
            // every payment this receiver coordinates; see docs/threat-model.md.
            let transport = NostrTransport::ephemeral(relays).await?;
            let state = ReceiverSession {
                secret_key: transport.secret_key_hex(),
                relays: relays.to_vec(),
                address: wallet.next_address().address.to_string(),
                amount_sat: amount.to_sat(),
                seen_inputs: Vec::new(),
            };
            session::save(session_file, &state)?;
            tracing::info!(path = %session_file.display(), "started a new session");
            (transport, state)
        }
    };

    let address: Address = state
        .address
        .parse::<Address<bitcoin::address::NetworkUnchecked>>()
        .context("session file holds an unparseable address")?
        .require_network(bitcoin::Network::Signet)
        .context("session file holds an address for the wrong network")?;
    let amount = Amount::from_sat(state.amount_sat);

    let route = NostrRoute::new(transport.public_key().to_hex(), relays.to_vec())?;
    print_uri(&address, amount, &route)?;

    let mut seen = state.seen();
    loop {
        let outcome = run_one_session(wallet, &transport, &mut seen, timeout).await;

        // Persist what we have seen regardless of outcome. A rejected proposal
        // still taught us outpoints, and forgetting them would let a prober
        // retry after any failure.
        state.record_seen(&seen);
        session::save(session_file, &state)?;

        match outcome {
            Ok(true) => {
                // The session key has served its purpose; leaving it on disk
                // would keep a spent secret around for no reason.
                session::clear(session_file)?;
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
    let proposal = match receiver::respond(
        &envelope.payload,
        &envelope.params,
        wallet,
        seen,
        FeePolicy::default(),
    ) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!(error = %e, "rejecting proposal");
            let reply = PayjoinEnvelope {
                leg: Leg::Error,
                session: envelope.session,
                params: String::new(),
                payload: b"payjoin request rejected".to_vec(),
            };
            transport.send(sender, &reply).await?;
            return Err(e);
        }
    };

    let reply = PayjoinEnvelope {
        leg: Leg::Proposal,
        session: envelope.session.clone(),
        params: String::new(),
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
