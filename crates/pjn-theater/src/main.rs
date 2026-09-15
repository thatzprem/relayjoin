//! Payjoin Theater: a live, visual demo of payjoin over nostr.
//!
//! Runs a real sender (Alice) and a real receiver (Bob) in one process, against
//! public nostr relays and signet, and streams every protocol step to a browser
//! page. Nothing on the page is scripted. Each sealed note, safety check and
//! transaction row is emitted by the code that performed it.
//!
//! Binds to 127.0.0.1 only, because this server holds both wallets' signing keys.

use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::Html;
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use pjn_transport::{
    Delivery, EventId, Leg, NostrTransport, PayjoinEnvelope, SendReceipt, Timestamp,
};
use pjn_wallet::receiver::respond_with_progress;
use pjn_wallet::signet::SignetWallet;
use pjn_wallet::uri::NostrRoute;
use pjn_wallet::{sender, Address, Amount, FeePolicy, FeeRate, Psbt, ReceiverStep, SeenInputs};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::{broadcast, oneshot};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt};

const NETWORK: bitcoin::Network = bitcoin::Network::Signet;
const FEE_RATE_SAT_VB: u64 = 2;
const DEFAULT_ESPLORA: &str = "https://mutinynet.com/api";
const DEFAULT_RELAYS: &str = "wss://relay.damus.io,wss://nos.lol,wss://relay.primal.net";

/// How long Alice waits for Bob before giving up on this run.
const ALICE_PATIENCE: Duration = Duration::from_secs(20 * 60);

/// How long one listen call waits before Bob asks the relays again.
///
/// Every call opens a relay subscription, and relays cap how many one connection
/// may hold, so this is deliberately long. Switching Bob offline does not wait
/// for it to expire.
const BOB_LISTEN_WINDOW: Duration = Duration::from_secs(120);

#[derive(Parser)]
#[command(
    name = "pjn-theater",
    about = "A live, visual demo of payjoin over nostr, served on localhost"
)]
struct Cli {
    /// Alice's external descriptor.
    #[arg(long, env = "PJN_ALICE_DESCRIPTOR")]
    alice_descriptor: String,

    /// Alice's change descriptor.
    #[arg(long, env = "PJN_ALICE_CHANGE_DESCRIPTOR")]
    alice_change_descriptor: String,

    /// Bob's external descriptor.
    #[arg(long, env = "PJN_BOB_DESCRIPTOR")]
    bob_descriptor: String,

    /// Bob's change descriptor.
    #[arg(long, env = "PJN_BOB_CHANGE_DESCRIPTOR")]
    bob_change_descriptor: String,

    /// Esplora instance both wallets sync against.
    #[arg(long, env = "PJN_ESPLORA", default_value = DEFAULT_ESPLORA)]
    esplora: String,

    /// Comma-separated relay list.
    #[arg(long, env = "PJN_RELAYS", default_value = DEFAULT_RELAYS)]
    relays: String,

    /// Port to serve the page on.
    #[arg(long, default_value = "7777")]
    port: u16,

    /// Also write every event the page receives to this file, for `pjn-replay`.
    ///
    /// A recording holds only what the page shows: addresses, transaction ids
    /// and sealed-note metadata. It never contains keys or descriptors.
    #[arg(long)]
    record: Option<std::path::PathBuf>,
}

struct Theater {
    alice: Arc<Mutex<SignetWallet>>,
    bob: Arc<Mutex<SignetWallet>>,
    relays: Vec<String>,
    events: broadcast::Sender<String>,
    /// Every event since the last reset, so a page opened mid-run catches up.
    history: Mutex<Vec<String>>,
    inner: tokio::sync::Mutex<Inner>,
    recorder: Option<Recorder>,
}

/// Appends every event the page receives to a file, with its time, so
/// `pjn-replay` can turn one real run into a static page.
struct Recorder {
    started: std::time::Instant,
    file: Mutex<std::fs::File>,
}

impl Recorder {
    fn create(path: &std::path::Path, relays: &[String]) -> Result<Self> {
        use std::io::Write;

        let mut file = std::fs::File::create(path)
            .with_context(|| format!("creating the recording {}", path.display()))?;
        let started_epoch_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis() as u64)
            .unwrap_or(0);
        let header = json!({
            "recording": {
                "started_epoch_ms": started_epoch_ms,
                "network": "signet",
                "relays": relays,
            }
        });
        writeln!(file, "{header}").context("writing the recording header")?;

        Ok(Self {
            started: std::time::Instant::now(),
            file: Mutex::new(file),
        })
    }

    fn write(&self, message: &Value) {
        use std::io::Write;

        let line = json!({
            "t": self.started.elapsed().as_millis() as u64,
            "data": message,
        });
        let mut file = self.file.lock().expect("recording lock poisoned");
        // A failed write must not stop a live demo; the recording is a bonus.
        if let Err(e) = writeln!(file, "{line}").and_then(|()| file.flush()) {
            tracing::warn!(error = %e, "could not write to the recording");
        }
    }
}

#[derive(Default)]
struct Inner {
    invoice: Option<Invoice>,
    bob_online: bool,
    bob_stop: Option<oneshot::Sender<()>>,
    alice_busy: bool,
    paid: bool,
    // Cached, so a page request never waits on a wallet that is mid-sync.
    alice_sat: u64,
    alice_coins: usize,
    bob_sat: u64,
    bob_coins: usize,
}

#[derive(Clone)]
struct Invoice {
    uri: String,
    amount: Amount,
    address: Address,
    session_secret: String,
    session_pubkey: String,
    created_at: Timestamp,
    /// Bob's replay guard for this request. Survives his reconnects.
    seen: Arc<Mutex<SeenInputs>>,
    /// Notes Bob has already handled, so a reconnect does not hand them back.
    handled: Arc<Mutex<Vec<EventId>>>,
}

impl Theater {
    fn emit(&self, message: Value) {
        let text = message.to_string();
        let mut history = self.history.lock().expect("history lock poisoned");
        history.push(text.clone());
        self.publish(&message, text);
    }

    /// Send an event to connected pages, and to the recording if there is one.
    ///
    /// Every event leaves through here, so a recording cannot miss one that a
    /// page received.
    fn publish(&self, message: &Value, text: String) {
        if let Some(recorder) = &self.recorder {
            recorder.write(message);
        }
        // No receivers is normal before any page has connected.
        let _ = self.events.send(text);
    }

    fn step(&self, id: &str, status: &str, detail: impl Into<String>) {
        self.emit(json!({
            "type": "step",
            "id": id,
            "status": status,
            "detail": detail.into(),
        }));
    }

    fn log(&self, who: &str, level: &str, text: impl Into<String>) {
        let text = text.into();
        match level {
            "error" => tracing::error!(%who, "{text}"),
            "warn" => tracing::warn!(%who, "{text}"),
            _ => tracing::info!(%who, "{text}"),
        }
        self.emit(json!({
            "type": "log",
            "who": who,
            "level": level,
            "text": text,
            "at": Timestamp::now().as_secs(),
        }));
    }

    async fn snapshot(&self) -> Value {
        let inner = self.inner.lock().await;
        json!({
            "type": "state",
            "network": "signet",
            "relays": self.relays,
            "alice_sat": inner.alice_sat,
            "alice_coins": inner.alice_coins,
            "bob_sat": inner.bob_sat,
            "bob_coins": inner.bob_coins,
            "bob_online": inner.bob_online,
            "alice_busy": inner.alice_busy,
            "paid": inner.paid,
            "invoice": inner.invoice.as_ref().map(|invoice| json!({
                "uri": invoice.uri,
                "amount_sat": invoice.amount.to_sat(),
                "address": invoice.address.to_string(),
                "session_pubkey": invoice.session_pubkey,
            })),
        })
    }

    /// Sent live but kept out of history: a page that connects later gets one
    /// fresh snapshot rather than a replay of every stale one.
    async fn broadcast_state(&self) {
        let snapshot = self.snapshot().await;
        let text = snapshot.to_string();
        self.publish(&snapshot, text);
    }

    fn clear_history(&self) {
        self.history.lock().expect("history lock poisoned").clear();
        let reset = json!({ "type": "reset" });
        let text = reset.to_string();
        self.publish(&reset, text);
    }

    /// Turn a validation step Bob's code has just passed into something visible.
    fn on_receiver_step(&self, step: ReceiverStep) {
        let check = |id: &str, label: &str| {
            self.emit(json!({ "type": "check", "id": id, "label": label }));
        };
        match step {
            ReceiverStep::Broadcastable => check(
                "broadcastable",
                "Alice's payment is valid on its own, so Bob is not left holding an empty promise.",
            ),
            ReceiverStep::NotOurInputs => check(
                "not-ours",
                "None of the coins Alice is spending are Bob's, so nobody is tricking him into spending his own money.",
            ),
            ReceiverStep::NotSeenBefore => check(
                "not-seen",
                "Bob has never been shown these coins before, so this is not someone probing his wallet.",
            ),
            ReceiverStep::PaysUs => {
                check("pays-bob", "The payment really pays Bob's address.");
                self.step("checks", "done", "All four checks passed.");
                self.step("contribute", "active", "");
            }
            ReceiverStep::InputContributed => self.step(
                "contribute",
                "active",
                "Bob added one of his own coins, chosen so the result looks like any ordinary payment.",
            ),
            ReceiverStep::FeeWithinPolicy => self.log(
                "bob",
                "info",
                "With Bob's coin added, the fee still stays inside his limits.",
            ),
            ReceiverStep::Signed => self.step(
                "contribute",
                "done",
                "Bob added one of his own coins and signed that coin only. He cannot sign Alice's, and does not try.",
            ),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "pjn_theater=info,pjn_transport=warn".into()),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    let relays: Vec<String> = cli
        .relays
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    anyhow::ensure!(!relays.is_empty(), "no relays configured");

    println!("Syncing both wallets, this takes a moment...");
    let mut alice = SignetWallet::new(
        &cli.alice_descriptor,
        &cli.alice_change_descriptor,
        &cli.esplora,
    )
    .context("building Alice's wallet")?;
    alice.full_scan().context("syncing Alice's wallet")?;

    let mut bob = SignetWallet::new(
        &cli.bob_descriptor,
        &cli.bob_change_descriptor,
        &cli.esplora,
    )
    .context("building Bob's wallet")?;
    bob.full_scan().context("syncing Bob's wallet")?;

    let inner = Inner {
        alice_sat: spendable(&alice),
        alice_coins: alice.spendable_utxo_count(),
        bob_sat: spendable(&bob),
        bob_coins: bob.spendable_utxo_count(),
        ..Default::default()
    };
    println!(
        "  Alice: {} sat in {} coin(s)",
        sats(inner.alice_sat),
        inner.alice_coins
    );
    println!(
        "  Bob:   {} sat in {} coin(s)",
        sats(inner.bob_sat),
        inner.bob_coins
    );
    if inner.bob_coins == 0 {
        eprintln!("warning: Bob has no coins. A payjoin receiver must add one of its own, so fund Bob first.");
    }

    let recorder = match &cli.record {
        Some(path) => {
            println!("  Recording every event to {}", path.display());
            Some(Recorder::create(path, &relays)?)
        }
        None => None,
    };

    let (events, _) = broadcast::channel(1024);
    let theater = Arc::new(Theater {
        alice: Arc::new(Mutex::new(alice)),
        bob: Arc::new(Mutex::new(bob)),
        relays,
        events,
        history: Mutex::new(Vec::new()),
        inner: tokio::sync::Mutex::new(inner),
        recorder,
    });

    // A replay starts from what a page sees the moment it connects.
    if let Some(recorder) = &theater.recorder {
        recorder.write(&theater.snapshot().await);
    }

    let app = Router::new()
        .route("/", get(index))
        .route("/events", get(stream_events))
        .route("/api/invoice", post(create_invoice))
        .route("/api/bob", post(set_bob_online))
        .route("/api/pay", post(pay))
        .route("/api/reset", post(reset))
        .with_state(theater);

    // Loopback only: this server can sign with both wallets.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", cli.port))
        .await
        .with_context(|| format!("binding 127.0.0.1:{}", cli.port))?;
    println!();
    println!(
        "  Payjoin Theater is running: http://127.0.0.1:{}",
        cli.port
    );
    println!();
    axum::serve(listener, app)
        .await
        .context("serving the page")?;
    Ok(())
}

// ------------------------------------------------------------------ handlers

type ApiResult = Result<Json<Value>, (StatusCode, String)>;

fn api_error(status: StatusCode, message: impl Into<String>) -> (StatusCode, String) {
    (status, message.into())
}

#[derive(Deserialize)]
struct InvoiceRequest {
    amount_sat: u64,
}

#[derive(Deserialize)]
struct BobRequest {
    online: bool,
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn stream_events(
    State(t): State<Arc<Theater>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let snapshot = t.snapshot().await.to_string();
    let (history, live) = {
        let history = t.history.lock().expect("history lock poisoned");
        // Subscribed while holding the lock, so nothing emitted between the copy
        // and the subscription is lost.
        (history.clone(), t.events.subscribe())
    };

    let backlog = tokio_stream::iter(std::iter::once(snapshot).chain(history));
    let live = BroadcastStream::new(live).filter_map(|message| message.ok());
    let stream = backlog
        .chain(live)
        .map(|text| Ok(Event::default().data(text)));

    Sse::new(stream).keep_alive(KeepAlive::new())
}

async fn create_invoice(
    State(t): State<Arc<Theater>>,
    Json(request): Json<InvoiceRequest>,
) -> ApiResult {
    if request.amount_sat < 1_000 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Ask for at least 1,000 sat.",
        ));
    }

    let mut inner = t.inner.lock().await;
    if inner.alice_busy {
        return Err(api_error(
            StatusCode::CONFLICT,
            "Alice is in the middle of a payment. Wait for it to finish.",
        ));
    }

    let bob = t.bob.clone();
    let address = tokio::task::spawn_blocking(move || {
        bob.lock()
            .expect("Bob's wallet lock poisoned")
            .next_address()
            .address
    })
    .await
    .map_err(|e| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("creating an address: {e}"),
        )
    })?;

    let (session_secret, session_pubkey) = pjn_transport::generate_session_key();
    let route = NostrRoute::new(session_pubkey.clone(), t.relays.clone())
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")))?;
    let amount = Amount::from_sat(request.amount_sat);
    let uri = format!(
        "bitcoin:{address}?amount={}&pj={}",
        amount.to_btc(),
        route.to_endpoint()
    );

    if let Some(stop) = inner.bob_stop.take() {
        let _ = stop.send(());
    }
    inner.invoice = Some(Invoice {
        uri: uri.clone(),
        amount,
        address,
        session_secret,
        session_pubkey: session_pubkey.clone(),
        created_at: Timestamp::now(),
        seen: Arc::new(Mutex::new(SeenInputs::new())),
        handled: Arc::new(Mutex::new(Vec::new())),
    });
    inner.paid = false;
    if inner.bob_online {
        start_bob(&t, &mut inner);
    }
    drop(inner);

    t.clear_history();
    t.step(
        "invoice",
        "done",
        format!(
            "Bob asks for {} sat. His request names a one-time key, {}…, used for this payment and nothing else.",
            sats(request.amount_sat),
            &session_pubkey[..12]
        ),
    );
    t.log("bob", "info", format!("New payment request: {uri}"));
    t.broadcast_state().await;
    Ok(Json(json!({ "uri": uri })))
}

async fn set_bob_online(
    State(t): State<Arc<Theater>>,
    Json(request): Json<BobRequest>,
) -> ApiResult {
    let mut inner = t.inner.lock().await;
    if inner.bob_online == request.online {
        return Ok(Json(json!({ "online": request.online })));
    }
    inner.bob_online = request.online;

    if request.online {
        start_bob(&t, &mut inner);
        let has_invoice = inner.invoice.is_some();
        drop(inner);
        t.log(
            "bob",
            "info",
            if has_invoice {
                "Bob comes online and asks the relays what is waiting for him."
            } else {
                "Bob comes online. He has not asked for a payment yet, so there is nothing to collect."
            },
        );
    } else {
        if let Some(stop) = inner.bob_stop.take() {
            let _ = stop.send(());
        }
        drop(inner);
        t.log(
            "bob",
            "warn",
            "Bob goes offline. Anything sent to him now waits on the relays until he returns.",
        );
    }

    t.broadcast_state().await;
    Ok(Json(json!({ "online": request.online })))
}

async fn pay(State(t): State<Arc<Theater>>) -> ApiResult {
    let mut inner = t.inner.lock().await;
    let Some(invoice) = inner.invoice.clone() else {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Bob has not asked for a payment yet.",
        ));
    };
    if inner.alice_busy {
        return Err(api_error(StatusCode::CONFLICT, "Alice is already paying."));
    }
    if inner.paid {
        return Err(api_error(
            StatusCode::CONFLICT,
            "This request is already paid. Have Bob ask for a new one.",
        ));
    }
    inner.alice_busy = true;
    drop(inner);

    t.broadcast_state().await;
    tokio::spawn(alice_pay(t.clone(), invoice));
    Ok(Json(json!({ "started": true })))
}

async fn reset(State(t): State<Arc<Theater>>) -> ApiResult {
    let mut inner = t.inner.lock().await;
    if inner.alice_busy {
        return Err(api_error(
            StatusCode::CONFLICT,
            "Alice is mid-payment. Reset once it finishes.",
        ));
    }
    if let Some(stop) = inner.bob_stop.take() {
        let _ = stop.send(());
    }
    inner.invoice = None;
    inner.paid = false;
    drop(inner);

    t.clear_history();
    t.broadcast_state().await;
    Ok(Json(json!({ "reset": true })))
}

// ---------------------------------------------------------------------- Bob

fn start_bob(t: &Arc<Theater>, inner: &mut Inner) {
    let Some(invoice) = inner.invoice.clone() else {
        return;
    };
    let (stop, stopped) = oneshot::channel();
    inner.bob_stop = Some(stop);
    tokio::spawn(bob_listen(t.clone(), invoice, stopped));
}

async fn bob_listen(t: Arc<Theater>, invoice: Invoice, mut stopped: oneshot::Receiver<()>) {
    let transport = tokio::select! {
        _ = &mut stopped => return,
        connected = NostrTransport::from_secret_hex(&invoice.session_secret, &t.relays) => match connected {
            Ok(transport) => transport,
            Err(e) => {
                t.log("bob", "error", format!("Bob could not reach any relay: {e:#}"));
                return;
            }
        },
    };

    for id in invoice
        .handled
        .lock()
        .expect("handled lock poisoned")
        .iter()
    {
        transport.mark_delivered(*id);
    }

    loop {
        tokio::select! {
            _ = &mut stopped => break,
            received = transport.recv_detailed(invoice.created_at, BOB_LISTEN_WINDOW) => match received {
                Ok(Some(delivery)) => {
                    invoice
                        .handled
                        .lock()
                        .expect("handled lock poisoned")
                        .push(delivery.event_id);
                    bob_handle(&t, &invoice, &transport, delivery).await;
                }
                Ok(None) => {}
                Err(e) => {
                    t.log("bob", "warn", format!("Bob lost contact with the relays and will retry: {e:#}"));
                    tokio::select! {
                        _ = &mut stopped => break,
                        _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                    }
                }
            }
        }
    }

    transport.shutdown().await;
}

async fn bob_handle(
    t: &Arc<Theater>,
    invoice: &Invoice,
    transport: &NostrTransport,
    delivery: Delivery,
) {
    if delivery.envelope.leg != Leg::OriginalPsbt {
        return;
    }

    t.emit(json!({
        "type": "note_collected",
        "id": delivery.event_id.to_hex(),
        "by": "bob",
    }));
    t.step(
        "collect",
        "done",
        "Bob fetched the note and opened it with his one-time key. Inside: Alice's signed payment, and her limits on what he may change.",
    );
    t.step("checks", "active", "");

    let bob = t.bob.clone();
    let seen = invoice.seen.clone();
    let progress = t.clone();
    let payload = delivery.envelope.payload.clone();
    let params = delivery.envelope.params.clone();
    let outcome = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
        let mut wallet = bob.lock().expect("Bob's wallet lock poisoned");
        wallet.sync().context("syncing Bob's wallet")?;
        let mut seen = seen.lock().expect("seen lock poisoned");
        respond_with_progress(
            &payload,
            &params,
            &*wallet,
            &mut seen,
            FeePolicy::default(),
            |step| progress.on_receiver_step(step),
        )
    })
    .await;

    let session = delivery.envelope.session.clone();
    let proposal = match outcome {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(e)) => {
            t.step("checks", "failed", format!("{e:#}"));
            t.log("bob", "error", format!("Bob refused the request: {e:#}"));
            let refusal = PayjoinEnvelope {
                leg: Leg::Error,
                session,
                params: String::new(),
                // Deliberately generic: naming the failed check would help a
                // prober map Bob's wallet.
                payload: b"payjoin request rejected".to_vec(),
            };
            if let Err(e) = transport.send(delivery.sender, &refusal).await {
                t.log(
                    "bob",
                    "warn",
                    format!("Could not tell Alice about the refusal: {e:#}"),
                );
            }
            return;
        }
        Err(e) => {
            t.step("checks", "failed", format!("Bob's check task stopped: {e}"));
            return;
        }
    };

    t.step("reply", "active", "");
    let reply = PayjoinEnvelope {
        leg: Leg::Proposal,
        session,
        params: String::new(),
        payload: proposal,
    };
    let sent_at = Timestamp::now();
    match transport.send_with_receipt(delivery.sender, &reply).await {
        Ok(receipt) => {
            t.emit(note_json(
                &receipt,
                ("bob", "alice"),
                "proposal",
                sent_at,
                &t.relays,
                "Bob's changed version of the payment: Alice's coin plus one of his, signed on his side only.",
            ));
            t.step(
                "reply",
                "done",
                format!(
                    "Sealed back to Alice the same way and stored on {} of {} relays.",
                    receipt.accepted.len(),
                    t.relays.len()
                ),
            );
        }
        Err(e) => {
            t.step("reply", "failed", format!("{e:#}"));
            t.log(
                "bob",
                "error",
                format!("Bob's reply reached no relay: {e:#}"),
            );
        }
    }
}

// -------------------------------------------------------------------- Alice

async fn alice_pay(t: Arc<Theater>, invoice: Invoice) {
    let outcome = alice_pay_steps(&t, &invoice).await;
    let paid = matches!(outcome, Ok(true));

    let mut inner = t.inner.lock().await;
    inner.alice_busy = false;
    if paid {
        inner.paid = true;
    }
    drop(inner);

    if let Err(e) = outcome {
        t.log("alice", "error", format!("{e:#}"));
    }
    refresh_balances(&t).await;
}

/// Returns `true` once the payjoin has been broadcast.
async fn alice_pay_steps(t: &Arc<Theater>, invoice: &Invoice) -> Result<bool> {
    let fee_rate = FeeRate::from_sat_per_vb(FEE_RATE_SAT_VB).context("fee rate out of range")?;

    t.step("fallback", "active", "");
    let alice = t.alice.clone();
    let uri = invoice.uri.clone();
    let built = tokio::task::spawn_blocking(move || -> Result<(sender::ParsedInvoice, Psbt)> {
        let parsed = sender::parse_invoice(&uri, NETWORK)?;
        let amount = parsed.amount.context("Bob's request carries no amount")?;
        let mut wallet = alice.lock().expect("Alice's wallet lock poisoned");
        wallet.sync().context("syncing Alice's wallet")?;
        let original = wallet.create_original_psbt(&parsed.address, amount, fee_rate)?;
        Ok((parsed, original))
    })
    .await
    .context("Alice's wallet task stopped")?;

    let (parsed, original) = match built {
        Ok(built) => built,
        Err(e) => {
            t.step("fallback", "failed", format!("{e:#}"));
            return Err(e);
        }
    };

    let fallback = sender::fallback_tx(&original)?;
    let session = format!("{:x}", fallback.compute_txid());
    t.step(
        "fallback",
        "done",
        format!(
            "An ordinary payment of {} sat, fully signed. If the payjoin falls through, Alice can still send exactly this.",
            sats(invoice.amount.to_sat())
        ),
    );

    let (params, body, context) =
        sender::create_request(original.clone(), parsed.pj_uri, fee_rate)?;

    t.step("seal", "active", "");
    let transport = NostrTransport::ephemeral(&t.relays)
        .await
        .context("Alice could not reach any relay")?;
    let envelope = PayjoinEnvelope {
        leg: Leg::OriginalPsbt,
        session: session.clone(),
        params,
        payload: body,
    };
    let receiver_key = invoice
        .session_pubkey
        .parse()
        .map_err(|e| anyhow::anyhow!("Bob's request carries an unreadable key: {e:?}"))?;

    // Taken before publishing, so the reply can never predate the window.
    let listening_since = Timestamp::now();
    let receipt = match transport.send_with_receipt(receiver_key, &envelope).await {
        Ok(receipt) => receipt,
        Err(e) => {
            t.step("seal", "failed", format!("{e:#}"));
            transport.shutdown().await;
            return Err(e);
        }
    };

    t.step(
        "seal",
        "done",
        format!(
            "Locked so only Bob's one-time key can open it, then signed on the outside by {}…, a key made for this one message.",
            &receipt.outer_pubkey.to_hex()[..12]
        ),
    );
    t.emit(note_json(
        &receipt,
        ("alice", "bob"),
        "original",
        listening_since,
        &t.relays,
        format!(
            "Alice's signed payment of {} sat to Bob, plus her limits on what he may change.",
            sats(invoice.amount.to_sat())
        ),
    ));
    t.step(
        "stored",
        "done",
        format!(
            "Stored on {} of {} relays. They hold a locked box: no sender, a fake timestamp, contents they cannot read.",
            receipt.accepted.len(),
            t.relays.len()
        ),
    );

    let bob_online = t.inner.lock().await.bob_online;
    if !bob_online {
        t.log(
            "relays",
            "info",
            "Bob is offline. The note waits on the relays until he comes back.",
        );
    }
    t.step(
        "collect",
        "active",
        "Waiting for Bob to come online and pick it up.",
    );

    let deadline = tokio::time::Instant::now() + ALICE_PATIENCE;
    let proposal_bytes = loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            t.step(
                "collect",
                "failed",
                "Bob did not reply in time. Alice still holds her signed ordinary payment and could send that instead.",
            );
            transport.shutdown().await;
            return Ok(false);
        }

        match transport.recv_detailed(listening_since, remaining).await {
            Ok(Some(delivery)) if delivery.envelope.session == session => {
                match delivery.envelope.leg {
                    Leg::Proposal => {
                        t.emit(json!({
                            "type": "note_collected",
                            "id": delivery.event_id.to_hex(),
                            "by": "alice",
                        }));
                        break delivery.envelope.payload;
                    }
                    Leg::Error => {
                        t.step("checks", "failed", "Bob refused the request.");
                        transport.shutdown().await;
                        anyhow::bail!(
                            "Bob refused the payjoin. Alice's ordinary payment is still signed and could be sent instead."
                        );
                    }
                    Leg::OriginalPsbt => continue,
                }
            }
            Ok(_) => continue,
            Err(e) => {
                t.log(
                    "alice",
                    "warn",
                    format!("Alice lost contact with the relays and will retry: {e:#}"),
                );
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    };
    transport.shutdown().await;

    t.step("validate", "active", "");
    let proposal = match sender::validate_proposal(context, &proposal_bytes) {
        Ok(psbt) => psbt,
        Err(e) => {
            t.step(
                "validate",
                "failed",
                format!("Alice refused to sign: {e:#}"),
            );
            return Ok(false);
        }
    };
    t.step(
        "validate",
        "done",
        "Bob only changed what Alice allowed: her payment still pays what she meant, and the fee stayed inside her limit.",
    );

    t.step("broadcast", "active", "");
    let alice = t.alice.clone();
    let bob = t.bob.clone();
    let amount = invoice.amount;
    let finished = tokio::task::spawn_blocking(move || -> Result<(bitcoin::Txid, Value)> {
        let alice = alice.lock().expect("Alice's wallet lock poisoned");
        let tx = alice.finalize_payjoin(&proposal)?;
        alice.broadcast(&tx)?;
        let bob = bob.lock().expect("Bob's wallet lock poisoned");
        Ok((
            tx.compute_txid(),
            describe_tx(&alice, &bob, &proposal, &tx, amount),
        ))
    })
    .await
    .context("Alice's signing task stopped")?;

    let (txid, summary) = match finished {
        Ok(finished) => finished,
        Err(e) => {
            t.step("broadcast", "failed", format!("{e:#}"));
            return Err(e);
        }
    };

    t.emit(summary);
    t.step(
        "broadcast",
        "done",
        format!("Alice signed her coin and sent the finished transaction: {txid}."),
    );
    t.step("confirm", "active", "In the mempool, waiting for a block.");
    tokio::spawn(watch_confirmation(t.clone(), txid));
    Ok(true)
}

async fn watch_confirmation(t: Arc<Theater>, txid: bitcoin::Txid) {
    // Mutinynet mines roughly every 30 seconds; give up after 20 minutes.
    for _ in 0..80 {
        tokio::time::sleep(Duration::from_secs(15)).await;
        let alice = t.alice.clone();
        let height = tokio::task::spawn_blocking(move || {
            alice
                .lock()
                .expect("Alice's wallet lock poisoned")
                .confirmation_height(&txid)
        })
        .await;

        match height {
            Ok(Ok(Some(height))) => {
                t.emit(json!({
                    "type": "confirmed",
                    "txid": txid.to_string(),
                    "height": height,
                }));
                t.step(
                    "confirm",
                    "done",
                    format!("Confirmed in block {height}. It is permanent and public now, and it reads like a one-person payment."),
                );
                refresh_balances(&t).await;
                return;
            }
            Ok(Ok(None)) => {}
            Ok(Err(e)) => tracing::debug!(error = %e, "confirmation check failed, retrying"),
            Err(e) => tracing::debug!(error = %e, "confirmation task stopped, retrying"),
        }
    }
    t.log(
        "system",
        "warn",
        "Still unconfirmed after 20 minutes. Follow the explorer link to check.",
    );
}

// ------------------------------------------------------------------ helpers

async fn refresh_balances(t: &Arc<Theater>) {
    let alice = t.alice.clone();
    let bob = t.bob.clone();
    let result = tokio::task::spawn_blocking(move || -> Result<(u64, usize, u64, usize)> {
        let (alice_sat, alice_coins) = {
            let mut wallet = alice.lock().expect("Alice's wallet lock poisoned");
            wallet.sync()?;
            (spendable(&wallet), wallet.spendable_utxo_count())
        };
        let (bob_sat, bob_coins) = {
            let mut wallet = bob.lock().expect("Bob's wallet lock poisoned");
            wallet.sync()?;
            (spendable(&wallet), wallet.spendable_utxo_count())
        };
        Ok((alice_sat, alice_coins, bob_sat, bob_coins))
    })
    .await;

    match result {
        Ok(Ok((alice_sat, alice_coins, bob_sat, bob_coins))) => {
            let mut inner = t.inner.lock().await;
            inner.alice_sat = alice_sat;
            inner.alice_coins = alice_coins;
            inner.bob_sat = bob_sat;
            inner.bob_coins = bob_coins;
            drop(inner);
            t.broadcast_state().await;
        }
        Ok(Err(e)) => t.log(
            "system",
            "warn",
            format!("Could not refresh balances: {e:#}"),
        ),
        Err(e) => t.log("system", "warn", format!("Balance refresh stopped: {e}")),
    }
}

fn spendable(wallet: &SignetWallet) -> u64 {
    let balance = wallet.balance();
    (balance.confirmed + balance.trusted_pending + balance.untrusted_pending).to_sat()
}

/// Everything the "what the world sees" panel needs, taken from the real transaction.
///
/// Ownership comes from the two wallets this server holds, not from any guess.
fn describe_tx(
    alice: &SignetWallet,
    bob: &SignetWallet,
    proposal: &Psbt,
    tx: &bitcoin::Transaction,
    payment: Amount,
) -> Value {
    let owner = |script: &bitcoin::Script| {
        if alice.owns_script(script) {
            "alice"
        } else if bob.owns_script(script) {
            "bob"
        } else {
            "unknown"
        }
    };
    let address = |script: &bitcoin::Script| {
        bitcoin::Address::from_script(script, NETWORK)
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "non-standard script".to_string())
    };

    let mut total_in = 0u64;
    let inputs: Vec<Value> = proposal
        .inputs
        .iter()
        .map(|input| match &input.witness_utxo {
            Some(utxo) => {
                total_in += utxo.value.to_sat();
                let script = utxo.script_pubkey.as_script();
                json!({
                    "address": address(script),
                    "value": utxo.value.to_sat(),
                    "owner": owner(script),
                })
            }
            None => json!({ "address": "unknown", "value": null, "owner": "unknown" }),
        })
        .collect();

    let total_out: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
    let outputs: Vec<Value> = tx
        .output
        .iter()
        .map(|output| {
            let script = output.script_pubkey.as_script();
            json!({
                "address": address(script),
                "value": output.value.to_sat(),
                "owner": owner(script),
            })
        })
        .collect();

    json!({
        "type": "tx",
        "txid": tx.compute_txid().to_string(),
        "fee": total_in.saturating_sub(total_out),
        "payment_sat": payment.to_sat(),
        "inputs": inputs,
        "outputs": outputs,
    })
}

/// A sealed note as the page draws it: what the relay sees, and what only the
/// recipient can open.
fn note_json(
    receipt: &SendReceipt,
    (from, to): (&str, &str),
    leg: &str,
    sent_at: Timestamp,
    relays: &[String],
    inside: impl Into<String>,
) -> Value {
    json!({
        "type": "note",
        "id": receipt.id.to_hex(),
        "nevent": pjn_transport::nevent(receipt.id, relays),
        "from": from,
        "to": to,
        "leg": leg,
        "outer_pubkey": receipt.outer_pubkey.to_hex(),
        "stamped_at": receipt.created_at.as_secs(),
        "sent_at": sent_at.as_secs(),
        "bytes": receipt.content_len,
        "accepted": receipt.accepted,
        "refused": receipt.refused.len(),
        "inside": inside.into(),
    })
}

fn sats(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::sats;

    #[test]
    fn sats_groups_thousands() {
        assert_eq!(sats(0), "0");
        assert_eq!(sats(999), "999");
        assert_eq!(sats(1_000), "1,000");
        assert_eq!(sats(20_000), "20,000");
        assert_eq!(sats(1_234_567), "1,234,567");
    }
}
