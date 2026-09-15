//! Payjoin sender CLI.
//!
//! Parses a nostr-routed payjoin URI, builds and signs an Original PSBT,
//! publishes it to the receiver's session key over relays, waits for the Payjoin
//! Proposal, validates it, signs, and broadcasts.
//!
//! If anything goes wrong after the original is built, the payment still happens:
//! the sender broadcasts the fallback. Payjoin improves a payment; it must never
//! be able to block one.

use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use pjn_transport::{Leg, NostrTransport, PayjoinEnvelope, Timestamp};
use pjn_wallet::sender;
use pjn_wallet::signet::SignetWallet;
use pjn_wallet::{Amount, FeeRate};

const DEFAULT_ESPLORA: &str = "https://mutinynet.com/api";

#[derive(Parser)]
#[command(
    name = "pjn-sender",
    about = "Pay a nostr-routed payjoin URI, with no directory and no OHTTP relay"
)]
struct Cli {
    /// The payjoin URI printed by pjn-receiver.
    uri: String,

    /// External (receive) descriptor.
    #[arg(long, env = "PJN_DESCRIPTOR")]
    descriptor: String,

    /// Internal (change) descriptor.
    #[arg(long, env = "PJN_CHANGE_DESCRIPTOR")]
    change_descriptor: String,

    /// Esplora instance to sync against.
    #[arg(long, env = "PJN_ESPLORA", default_value = DEFAULT_ESPLORA)]
    esplora: String,

    /// Fee rate in sat/vB.
    #[arg(long, default_value = "2")]
    fee_rate: u32,

    /// Amount in satoshis. Overrides the amount in the URI.
    #[arg(long)]
    amount: Option<u64>,

    /// How long to wait for the receiver's proposal.
    #[arg(long, default_value = "300")]
    timeout_secs: u64,

    /// Broadcast the fallback immediately if the payjoin does not complete.
    #[arg(long)]
    fallback_on_failure: bool,

    /// Build and validate everything but broadcast nothing.
    #[arg(long)]
    dry_run: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "pjn_sender=info,pjn_transport=info".into()),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    let invoice = sender::parse_invoice(&cli.uri, bitcoin_network())?;
    let amount = match (cli.amount, invoice.amount) {
        (Some(sats), _) => Amount::from_sat(sats),
        (None, Some(amount)) => amount,
        (None, None) => anyhow::bail!("URI carries no amount; pass --amount"),
    };

    println!("  paying   : {} sat", amount.to_sat());
    println!("  to       : {}", invoice.address);
    println!("  via      : {} relay(s)", invoice.route.relays.len());
    println!();

    let mut wallet = SignetWallet::new(&cli.descriptor, &cli.change_descriptor, &cli.esplora)?;
    tracing::info!("syncing wallet");
    wallet.full_scan()?;

    let fee_rate =
        FeeRate::from_sat_per_vb(cli.fee_rate as u64).context("fee rate is out of range")?;

    // Signed and broadcastable before the receiver ever sees it. This is the
    // fallback, and payjoin requires it to exist up front.
    let original_psbt = wallet.create_original_psbt(&invoice.address, amount, fee_rate)?;
    let fallback = sender::fallback_tx(&original_psbt)?;
    tracing::info!(txid = %fallback.compute_txid(), "original (fallback) transaction ready");

    let (params, request_bytes, context) =
        sender::create_request(original_psbt, invoice.pj_uri, fee_rate)?;

    // Ephemeral identity: the receiver learns our key only after unsealing, and
    // relays never see it at all.
    let transport = NostrTransport::ephemeral(&invoice.route.relays).await?;
    let receiver_key = invoice
        .route
        .session_pubkey
        .parse()
        .map_err(|e| anyhow::anyhow!("URI carries an unparseable session key: {e:?}"))?;

    let session = format!("{:x}", fallback.compute_txid());
    let envelope = PayjoinEnvelope {
        leg: Leg::OriginalPsbt,
        session: session.clone(),
        params,
        payload: request_bytes,
    };

    // Taken before publishing, so the reply can never predate the window.
    let listening_since = Timestamp::now();
    let event_id = transport.send(receiver_key, &envelope).await?;
    tracing::info!(%event_id, "original PSBT published, waiting for the proposal");
    println!(
        "  Sent. Waiting up to {}s for the receiver...",
        cli.timeout_secs
    );
    println!("  (the receiver may be offline; relays will hold this for them)");
    println!();

    let outcome = await_proposal(
        &transport,
        &session,
        listening_since,
        Duration::from_secs(cli.timeout_secs),
    )
    .await;
    transport.shutdown().await;

    let proposal_bytes = match outcome {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            println!("  No proposal arrived before the timeout.");
            return finish_with_fallback(&wallet, &fallback, &cli);
        }
        Err(e) => {
            tracing::warn!(error = %e, "payjoin failed");
            return finish_with_fallback(&wallet, &fallback, &cli);
        }
    };

    // The receiver rewrote our transaction. Validate before signing anything.
    let proposal = match sender::validate_proposal(context, &proposal_bytes) {
        Ok(psbt) => psbt,
        Err(e) => {
            tracing::error!(error = %e, "receiver's proposal failed validation, refusing to sign");
            return finish_with_fallback(&wallet, &fallback, &cli);
        }
    };

    let payjoin_tx = wallet.finalize_payjoin(&proposal)?;
    let txid = payjoin_tx.compute_txid();

    println!("  Payjoin validated and signed.");
    println!("    inputs  : {}", payjoin_tx.input.len());
    println!("    outputs : {}", payjoin_tx.output.len());
    println!("    txid    : {txid}");
    println!();

    if cli.dry_run {
        println!("  --dry-run: not broadcasting.");
        return Ok(());
    }

    wallet.broadcast(&payjoin_tx)?;
    println!("  Broadcast. The transaction has inputs from both parties, so the");
    println!("  common-input-ownership heuristic reads it wrong. That is the point.");
    Ok(())
}

fn bitcoin_network() -> bitcoin::Network {
    bitcoin::Network::Signet
}

/// Wait for a proposal belonging to `session`.
///
/// Envelopes for other sessions are skipped rather than treated as failures: a
/// relay is shared infrastructure and may hand us anything.
async fn await_proposal(
    transport: &NostrTransport,
    session: &str,
    listening_since: Timestamp,
    timeout: Duration,
) -> Result<Option<Vec<u8>>> {
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }

        let Some((_peer, envelope)) = transport.recv(listening_since, remaining).await? else {
            return Ok(None);
        };

        if envelope.session != session {
            tracing::debug!(session = %envelope.session, "ignoring another session's envelope");
            continue;
        }

        match envelope.leg {
            Leg::Proposal => return Ok(Some(envelope.payload)),
            Leg::Error => {
                let msg = String::from_utf8_lossy(&envelope.payload).to_string();
                anyhow::bail!("receiver rejected the payjoin: {msg}");
            }
            Leg::OriginalPsbt => {
                tracing::debug!("ignoring an Original PSBT sent to a sender");
                continue;
            }
        }
    }
}

/// Fall back to the plain payment.
///
/// A failed payjoin must not mean a failed payment. Broadcasting is gated behind
/// an explicit flag so an unattended sender does not silently give up the privacy
/// benefit, and a person can retry instead.
fn finish_with_fallback(
    wallet: &SignetWallet,
    fallback: &bitcoin::Transaction,
    cli: &Cli,
) -> Result<()> {
    let txid = fallback.compute_txid();

    if cli.dry_run {
        println!("  --dry-run: fallback not broadcast. txid would be {txid}");
        return Ok(());
    }

    if !cli.fallback_on_failure {
        println!("  Payjoin did not complete. The signed fallback is ready but was");
        println!("  NOT broadcast. Re-run with --fallback-on-failure to send it as an");
        println!("  ordinary payment. Fallback txid: {txid}");
        return Ok(());
    }

    wallet.broadcast(fallback)?;
    println!("  Payjoin did not complete; broadcast the plain fallback instead.");
    println!("  txid: {txid}");
    Ok(())
}
