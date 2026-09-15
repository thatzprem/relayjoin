//! Payjoin sender CLI.
//!
//! Parses a nostr-routed payjoin URI, builds and signs an Original PSBT,
//! publishes it to the receiver's session key over relays, waits for the Payjoin
//! Proposal, validates it, signs, and broadcasts.
//!
//! A payment survives the process that started it. Its state is saved before
//! anything is published, so if this program is closed while waiting, running it
//! again with no URI picks the payment up where it stopped: same nostr key, same
//! Original PSBT, same relay lookback window.
//!
//! If anything goes wrong after the original is built, the payment can still
//! happen: the sender holds a signed fallback. Payjoin improves a payment; it must
//! never be able to block one.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use pjn_transport::{Leg, NostrTransport, PayjoinEnvelope, Timestamp};
use pjn_wallet::receiver::decode_psbt;
use pjn_wallet::sender::{self, V1Context};
use pjn_wallet::session::{self, SenderSession, DEFAULT_SENDER_SESSION_FILE};
use pjn_wallet::signet::SignetWallet;
use pjn_wallet::{Amount, FeeRate, Psbt};

const DEFAULT_ESPLORA: &str = "https://mutinynet.com/api";

#[derive(Parser)]
#[command(
    name = "pjn-sender",
    about = "Pay a nostr-routed payjoin URI, with no directory and no OHTTP relay"
)]
struct Cli {
    /// The payjoin URI printed by pjn-receiver. Omit it to resume a payment saved
    /// by an earlier run.
    uri: Option<String>,

    /// External (receive) descriptor.
    #[arg(long, env = "PJN_DESCRIPTOR")]
    descriptor: String,

    /// Internal (change) descriptor.
    #[arg(long, env = "PJN_CHANGE_DESCRIPTOR")]
    change_descriptor: String,

    /// Esplora instance to sync against.
    #[arg(long, env = "PJN_ESPLORA", default_value = DEFAULT_ESPLORA)]
    esplora: String,

    /// Fee rate in sat/vB. Ignored when resuming; the saved payment keeps its own.
    #[arg(long, default_value = "2")]
    fee_rate: u32,

    /// Amount in satoshis. Overrides the amount in the URI. Ignored when resuming.
    #[arg(long)]
    amount: Option<u64>,

    /// How long to wait for the receiver's proposal on this run.
    #[arg(long, default_value = "300")]
    timeout_secs: u64,

    /// Broadcast the fallback if the payjoin does not complete.
    #[arg(long)]
    fallback_on_failure: bool,

    /// Build and validate everything but broadcast nothing.
    #[arg(long)]
    dry_run: bool,

    /// Where this payment's state is kept so it survives a restart.
    #[arg(long, default_value = DEFAULT_SENDER_SESSION_FILE)]
    session_file: PathBuf,

    /// Delete the saved payment without broadcasting anything.
    #[arg(long, conflicts_with = "uri")]
    abandon: bool,
}

/// What to do with the session file once this run is over.
enum Ending {
    /// The payment is settled or was a dry run; the saved state is dead weight.
    Clear,
    /// The payment is still open; keep the state so a re-run can resume it.
    Keep,
}

/// Why the payjoin did not complete on this run, which decides what to advise.
enum Stopped {
    /// The receiver has not answered yet. Its reply may still arrive.
    StillWaiting,
    /// The receiver refused, or its proposal failed validation. Waiting longer
    /// will not help: a re-run reads the same reply back off the relays.
    CannotComplete,
}

/// Everything needed to finish a payment, however this run arrived at it.
struct Payment {
    state: SenderSession,
    original: Psbt,
    params: String,
    body: Vec<u8>,
    context: V1Context,
    transport: NostrTransport,
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

    if cli.abandon {
        session::clear(&cli.session_file)?;
        println!("  Saved payment deleted. This only removes local state: nothing was");
        println!("  broadcast by this command, and the coins it reserved can be spent");
        println!("  in a new payment.");
        return Ok(());
    }

    let saved: Option<SenderSession> = session::load(&cli.session_file)?;

    let mut wallet = SignetWallet::new(&cli.descriptor, &cli.change_descriptor, &cli.esplora)?;
    tracing::info!("syncing wallet");
    wallet.full_scan()?;

    let payment = match (saved, cli.uri.as_deref()) {
        (Some(state), Some(uri)) if uri != state.pj_uri => anyhow::bail!(
            "a payment to a different payjoin URI is still open in {}. Re-run without \
             a URI to resume it, or pass --abandon to delete it. Starting a new payment \
             now could try to spend the same coins twice.",
            cli.session_file.display()
        ),
        (Some(state), _) => match resume(&wallet, state).await? {
            Some(payment) => payment,
            None => {
                session::clear(&cli.session_file)?;
                return Ok(());
            }
        },
        (None, Some(uri)) => start(&mut wallet, uri, &cli).await?,
        (None, None) => anyhow::bail!(
            "pass the payjoin URI printed by pjn-receiver; there is no saved payment in {} \
             to resume",
            cli.session_file.display()
        ),
    };

    if let Ending::Clear = run(&wallet, payment, &cli).await? {
        session::clear(&cli.session_file)?;
    }
    Ok(())
}

fn bitcoin_network() -> bitcoin::Network {
    bitcoin::Network::Signet
}

/// Begin a new payment and save it before anything leaves this machine.
async fn start(wallet: &mut SignetWallet, uri: &str, cli: &Cli) -> Result<Payment> {
    let invoice = sender::parse_invoice(uri, bitcoin_network())?;
    let amount = match (cli.amount, invoice.amount) {
        (Some(sats), _) => Amount::from_sat(sats),
        (None, Some(amount)) => amount,
        (None, None) => anyhow::bail!("URI carries no amount; pass --amount"),
    };

    println!("  paying   : {} sat", amount.to_sat());
    println!("  to       : {}", invoice.address);
    println!("  via      : {} relay(s)", invoice.route.relays.len());
    println!();

    let fee_rate =
        FeeRate::from_sat_per_vb(cli.fee_rate as u64).context("fee rate is out of range")?;

    // Signed and broadcastable before the receiver ever sees it. This is the
    // fallback, and payjoin requires it to exist up front.
    let original = wallet.create_original_psbt(&invoice.address, amount, fee_rate)?;
    let session_id = format!("{:x}", sender::fallback_tx(&original)?.compute_txid());
    tracing::info!(txid = %session_id, "original (fallback) transaction ready");

    // Ephemeral identity: the receiver learns this key only after unsealing, and
    // relays never see it at all.
    let transport = NostrTransport::ephemeral(&invoice.route.relays).await?;
    let relays = invoice.route.relays.clone();
    let receiver_pubkey = invoice.route.session_pubkey.clone();

    let (params, body, context) =
        sender::create_request(original.clone(), invoice.pj_uri, fee_rate)?;

    let state = SenderSession {
        secret_key: transport.secret_key_hex(),
        relays,
        receiver_pubkey,
        session_id,
        original_psbt: original.to_string(),
        pj_uri: uri.to_string(),
        fee_rate_sat_vb: cli.fee_rate as u64,
        published_at: 0,
    };

    // Saved before publishing. The other order has a window where the request is
    // on the relays but the key needed to read the reply exists only in memory,
    // and a crash there loses the reply for good. Saved first, the worst case is
    // a request that was never sent, which a resume simply sends.
    session::save(&cli.session_file, &state)?;

    Ok(Payment {
        state,
        original,
        params,
        body,
        context,
        transport,
    })
}

/// Rebuild an interrupted payment from its saved state.
///
/// Returns `None` when there is nothing left to do because the payment's coins
/// are already spent.
async fn resume(wallet: &SignetWallet, state: SenderSession) -> Result<Option<Payment>> {
    let invoice = sender::parse_invoice(&state.pj_uri, bitcoin_network())
        .context("the saved payment's URI no longer parses")?;
    let original = decode_psbt(state.original_psbt.as_bytes())
        .context("the saved original PSBT is unreadable")?;

    // A previous run may have broadcast the payjoin or the fallback and then died
    // before it could delete this file. If any of our inputs is already spent,
    // carrying on would try to spend the same coins a second time.
    let already_spent = original
        .unsigned_tx
        .input
        .iter()
        .any(|input| !wallet.is_unspent(input.previous_output));
    if already_spent {
        println!("  The coins this payment reserved have already been spent, so it");
        println!(
            "  settled on an earlier run. Check transaction {} or the payjoin that",
            state.session_id
        );
        println!("  replaced it. Nothing to resume; deleting the saved state.");
        return Ok(None);
    }

    let fee_rate = FeeRate::from_sat_per_vb(state.fee_rate_sat_vb)
        .context("the saved fee rate is out of range")?;
    let (params, body, context) =
        sender::create_request(original.clone(), invoice.pj_uri, fee_rate)?;

    // The same key as the first run, so a reply sealed to it can still be opened.
    let transport = NostrTransport::from_secret_hex(&state.secret_key, &state.relays).await?;

    println!("  resuming : payment {}", state.session_id);
    println!("  to       : {}", invoice.address);
    if let Some(amount) = invoice.amount {
        println!("  amount   : {} sat", amount.to_sat());
    }
    println!();

    Ok(Some(Payment {
        state,
        original,
        params,
        body,
        context,
        transport,
    }))
}

/// Publish if needed, wait for the reply, and finish the payment one way or another.
async fn run(wallet: &SignetWallet, mut payment: Payment, cli: &Cli) -> Result<Ending> {
    let fallback = sender::fallback_tx(&payment.original)?;

    if payment.state.published_at == 0 {
        // Taken before publishing, so the reply can never predate the window.
        let published_at = Timestamp::now();
        let envelope = PayjoinEnvelope {
            leg: Leg::OriginalPsbt,
            session: payment.state.session_id.clone(),
            params: payment.params.clone(),
            payload: payment.body.clone(),
        };
        let receiver_key = payment
            .state
            .receiver_pubkey
            .parse()
            .map_err(|e| anyhow::anyhow!("URI carries an unparseable session key: {e:?}"))?;

        let event_id = match payment.transport.send(receiver_key, &envelope).await {
            Ok(event_id) => event_id,
            Err(e) => {
                // send only fails when no relay stored the request, so the saved
                // state still reads as unpublished and a re-run will send it.
                payment.transport.shutdown().await;
                return Err(e).context(
                    "the payment request reached no relay; it is saved, and running \
                     pjn-sender again with no URI will retry it",
                );
            }
        };

        payment.state.published_at = published_at.as_secs();
        session::save(&cli.session_file, &payment.state)?;

        tracing::info!(%event_id, "original PSBT published, waiting for the proposal");
        println!(
            "  Sent. Waiting up to {}s for the receiver...",
            cli.timeout_secs
        );
        println!("  (the receiver may be offline; relays will hold this for them)");
        println!("  You can close this and run pjn-sender again later to pick up the reply.");
        println!();
    } else {
        println!(
            "  Request already published. Checking relays for the receiver's reply, for up to {}s...",
            cli.timeout_secs
        );
        println!();
    }

    let outcome = await_proposal(
        &payment.transport,
        &payment.state.session_id,
        Timestamp::from_secs(payment.state.published_at),
        Duration::from_secs(cli.timeout_secs),
    )
    .await;
    payment.transport.shutdown().await;

    let proposal_bytes = match outcome {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            println!("  No proposal arrived before the timeout.");
            return finish_with_fallback(wallet, &fallback, cli, Stopped::StillWaiting);
        }
        Err(e) => {
            tracing::warn!(error = %e, "payjoin failed");
            return finish_with_fallback(wallet, &fallback, cli, Stopped::CannotComplete);
        }
    };

    // The receiver rewrote our transaction. Validate before signing anything.
    let proposal = match sender::validate_proposal(payment.context, &proposal_bytes) {
        Ok(psbt) => psbt,
        Err(e) => {
            tracing::error!(error = %e, "receiver's proposal failed validation, refusing to sign");
            return finish_with_fallback(wallet, &fallback, cli, Stopped::CannotComplete);
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
        return Ok(Ending::Clear);
    }

    wallet.broadcast(&payjoin_tx)?;
    println!("  Broadcast. The transaction has inputs from both parties, so the");
    println!("  common-input-ownership heuristic reads it wrong. That is the point.");
    Ok(Ending::Clear)
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

/// Fall back to the plain payment, or leave the payment open for a later run.
///
/// A failed payjoin must not mean a failed payment. Broadcasting is gated behind
/// an explicit flag so an unattended sender does not silently give up the privacy
/// benefit, and a person can resume instead.
fn finish_with_fallback(
    wallet: &SignetWallet,
    fallback: &bitcoin::Transaction,
    cli: &Cli,
    stopped: Stopped,
) -> Result<Ending> {
    let txid = fallback.compute_txid();

    if cli.dry_run {
        println!("  --dry-run: fallback not broadcast. txid would be {txid}");
        return Ok(Ending::Clear);
    }

    if !cli.fallback_on_failure {
        match stopped {
            Stopped::StillWaiting => {
                println!("  The receiver has not answered yet. The payment is saved: run");
                println!("  pjn-sender again with no URI to pick up the reply when it comes,");
                println!("  or add --fallback-on-failure to send it as an ordinary payment.");
            }
            Stopped::CannotComplete => {
                println!("  This payjoin cannot complete. The payment is saved: run");
                println!("  pjn-sender with no URI and --fallback-on-failure to send it as an");
                println!("  ordinary payment, or --abandon to delete it.");
            }
        }
        println!("  Fallback txid: {txid}");
        return Ok(Ending::Keep);
    }

    wallet.broadcast(fallback)?;
    println!("  Payjoin did not complete; broadcast the plain fallback instead.");
    println!("  txid: {txid}");
    Ok(Ending::Clear)
}
