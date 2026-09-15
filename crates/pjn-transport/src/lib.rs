//! Nostr transport for asynchronous Payjoin (BIP77).
//!
//! BIP77 makes Payjoin asynchronous by parking the sender's and receiver's
//! encrypted payloads on a *Payjoin Directory*, with an OHTTP relay in front so
//! the directory never learns either party's IP. That works, but it reintroduces
//! infrastructure: somebody has to run the directory, somebody has to run the
//! relay, and today that "somebody" is a very short list.
//!
//! This crate swaps that transport for nostr relays. The two payloads travel as
//! NIP-59 gift-wrapped events between ephemeral keys. Relays give us
//! store-and-forward for free, there are hundreds of independent operators, and no
//! new server has to exist for a payjoin to complete.
//!
//! # What a relay can see
//!
//! Be precise about this, because it is the first thing anyone will ask.
//!
//! - The gift wrap's outer event is signed by a throwaway key generated per
//!   message, so relays cannot link a payload to a persistent sender identity.
//! - The `p` tag addresses the *session key* from the payjoin URI, not the
//!   receiver's long-term identity. A fresh session key per URI makes that tag a
//!   one-time handle rather than a name.
//! - `created_at` is randomized by NIP-59, so the timestamp is not a send time.
//! - Content is NIP-44 sealed. A relay sees a fixed-shape blob and nothing else.
//!
//! What a relay can still do is correlate by IP if you connect to it directly.
//! Route over Tor for the real thing; see `docs/threat-model.md`.

use std::collections::HashSet;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use base64::prelude::{Engine as _, BASE64_STANDARD};
use futures_util::StreamExt;
use nostr::event::{FinalizeEvent, FinalizeUnsignedEvent};
use nostr::nips::nip59::{GiftWrapBuilder, UnwrappedGift};
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};

/// Application-specific rumor kind carried inside the gift wrap.
///
/// Only the wrapping event (kind 1059) is ever seen by a relay; this kind is
/// visible to the two participants after unsealing.
pub const KIND_PAYJOIN_RUMOR: u16 = 21177;

pub use nostr_sdk::prelude::{EventId, Timestamp};

/// How far NIP-59 may back-date a gift wrap's `created_at`, plus an hour of slack
/// for clock skew between peers and relays.
const GIFT_WRAP_BACKDATE: Duration = Duration::from_secs(48 * 3600 + 3600);

/// Earliest `created_at` a gift wrap can carry if it was published at or after
/// `listening_since`.
///
/// NIP-59 back-dates each wrap by up to two days *from when it was published*, so
/// the lower bound has to be measured from the moment we started expecting
/// messages, never from now. Measured from now, the window slides past a stored
/// payload while the receiver is offline, which defeats the point of a
/// store-and-forward transport.
pub fn backlog_since(listening_since: Timestamp) -> Timestamp {
    listening_since - GIFT_WRAP_BACKDATE
}

/// How long to wait for relay sockets before giving up on a relay.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// How long to spend collecting already-stored events before waiting for new ones.
const BACKLOG_TIMEOUT: Duration = Duration::from_secs(10);

/// Which leg of the BIP77 exchange a payload represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Leg {
    /// Sender to receiver. Carries the Original PSBT.
    OriginalPsbt,
    /// Receiver to sender. Carries the Payjoin Proposal PSBT.
    Proposal,
    /// Either direction. Carries a protocol error the peer should surface.
    Error,
}

/// One opaque payjoin payload plus the routing metadata we need around it.
///
/// `payload` is deliberately untyped. The transport must not care whether it is
/// carrying a raw PSBT, a BIP77 HPKE ciphertext, or an OHTTP-encapsulated blob.
/// That decision belongs to the binding layer, and keeping it opaque here is what
/// lets one transport serve all three.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayjoinEnvelope {
    pub leg: Leg,
    /// Session identifier, echoed back so a receiver can run many payjoins at once.
    pub session: String,
    /// BIP78 protocol parameters, as the query string an HTTP sender would have
    /// put in its request line (`v`, `maxadditionalfeecontribution`, `minfeerate`
    /// and friends).
    ///
    /// These are not decoration. They are the sender's constraints on what the
    /// receiver may change, and a receiver that never sees them will make an
    /// unauthorised edit and have its proposal rejected.
    #[serde(default)]
    pub params: String,
    #[serde(with = "b64")]
    pub payload: Vec<u8>,
}

mod b64 {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&BASE64_STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        BASE64_STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

/// A connected nostr client bound to one ephemeral identity.
pub struct NostrTransport {
    client: Client,
    keys: Keys,
    relays: Vec<String>,
    /// Gift wraps this transport has already handed to its caller.
    ///
    /// `recv` fetches the stored backlog on every call, so without this a
    /// long-running receiver is handed the same payload again after it has
    /// finished with it. Its replay guard then rejects that payload and sends an
    /// error back to a sender whose payjoin already succeeded.
    delivered: Mutex<HashSet<EventId>>,
}

/// What publishing a gift wrap produced, as a relay would see it.
#[derive(Debug, Clone)]
pub struct SendReceipt {
    pub id: EventId,
    /// The throwaway key NIP-59 signed the outer event with. Not ours.
    pub outer_pubkey: PublicKey,
    /// The randomised timestamp written on the outer event.
    pub created_at: Timestamp,
    /// Size of the sealed ciphertext a relay stores.
    pub content_len: usize,
    /// Relays that stored the event.
    pub accepted: Vec<String>,
    /// Relays that refused it, with their reasons.
    pub refused: Vec<(String, String)>,
}

/// A payjoin envelope received from a relay, with the event that carried it.
#[derive(Debug, Clone)]
pub struct Delivery {
    pub event_id: EventId,
    /// Sealed sender key; authenticated by NIP-59, safe to reply to.
    pub sender: PublicKey,
    pub envelope: PayjoinEnvelope,
}

impl NostrTransport {
    /// Connect to `relays` under a freshly generated ephemeral identity.
    pub async fn ephemeral(relays: &[String]) -> Result<Self> {
        Self::with_keys(Keys::generate(), relays).await
    }

    /// Connect using a caller-supplied key.
    ///
    /// The receiver uses this to re-attach to a session key it published in a
    /// payjoin URI and persisted. A sender should use
    /// [`NostrTransport::ephemeral`] instead.
    pub async fn with_keys(keys: Keys, relays: &[String]) -> Result<Self> {
        if relays.is_empty() {
            return Err(anyhow!("at least one relay is required"));
        }
        let client = Client::new();
        for url in relays {
            client
                .add_relay(url.as_str())
                .await
                .with_context(|| format!("adding relay {url}"))?;
        }
        // `connect()` only *starts* the connections and returns immediately, so a
        // send issued right after it fails with "relay not connected" and, before
        // `send` checked its per-relay results, did so silently. Wait for the
        // sockets to actually come up.
        let output = client.try_connect().timeout(CONNECT_TIMEOUT).await;

        for (relay, error) in &output.failed {
            tracing::warn!(%relay, %error, "relay did not connect");
        }

        if output.success.is_empty() {
            let reasons = output
                .failed
                .iter()
                .map(|(relay, error)| format!("{relay}: {error}"))
                .collect::<Vec<_>>()
                .join("; ");
            return Err(anyhow!("could not connect to any relay ({reasons})"));
        }

        tracing::info!(
            connected = output.success.len(),
            unreachable = output.failed.len(),
            "relays connected"
        );

        Ok(Self {
            client,
            keys,
            relays: relays.to_vec(),
            delivered: Mutex::new(HashSet::new()),
        })
    }

    /// Reconnect under a previously persisted session key.
    ///
    /// This is what lets a receiver print a payjoin URI, exit, and come back to
    /// a payload the relays held in the meantime. Without it the key dies with
    /// the process and the URI is permanently unusable.
    pub async fn from_secret_hex(secret_hex: &str, relays: &[String]) -> Result<Self> {
        let keys = Keys::parse(secret_hex).context("parsing persisted session key")?;
        Self::with_keys(keys, relays).await
    }

    pub fn public_key(&self) -> PublicKey {
        self.keys.public_key()
    }

    /// Record a gift wrap as already handled, so `recv` never returns it.
    ///
    /// For a party that reconnects with a fresh transport: the new instance does
    /// not know what the old one delivered, so the caller seeds it.
    pub fn mark_delivered(&self, id: EventId) {
        self.delivered
            .lock()
            .expect("delivered set poisoned")
            .insert(id);
    }

    fn take_if_new(&self, id: EventId) -> bool {
        self.delivered
            .lock()
            .expect("delivered set poisoned")
            .insert(id)
    }

    /// Hex-encoded secret key, for persisting the session.
    ///
    /// Handle as a secret: on signet it guards nothing, but the same value on
    /// mainnet would be worth stealing. Never log it.
    pub fn secret_key_hex(&self) -> String {
        self.keys.secret_key().to_secret_hex()
    }

    pub fn relays(&self) -> &[String] {
        &self.relays
    }

    /// Gift-wrap `envelope` to `peer` and publish it.
    ///
    /// NIP-59 signs the outer event with a throwaway key, so this transport's own
    /// identity never appears on it. `peer` learns who we are only after
    /// unsealing, which is what makes reply routing work without a separate
    /// reply-key handshake.
    pub async fn send(&self, peer: PublicKey, envelope: &PayjoinEnvelope) -> Result<EventId> {
        self.send_with_receipt(peer, envelope)
            .await
            .map(|receipt| receipt.id)
    }

    /// Like [`Self::send`], but reports what relays were given and which kept it.
    pub async fn send_with_receipt(
        &self,
        peer: PublicKey,
        envelope: &PayjoinEnvelope,
    ) -> Result<SendReceipt> {
        let rumor = EventBuilder::new(
            Kind::Custom(KIND_PAYJOIN_RUMOR),
            serde_json::to_string(envelope)?,
        )
        .finalize_unsigned(self.keys.public_key());

        let wrapped = GiftWrapBuilder::new(peer, rumor)
            // Long enough for a receiver that is offline for a weekend, short
            // enough that abandoned sessions do not linger on relays forever.
            .expiration(Duration::from_secs(7 * 24 * 3600))
            .finalize(&self.keys)
            .context("gift-wrapping payjoin envelope")?;

        let output = self
            .client
            .send_event(&wrapped)
            .await
            .context("publishing gift wrap")?;

        // send_event resolves Ok even when every relay refused the event, so the
        // per-relay outcome has to be inspected. Treating a refusal as success is
        // how a sender ends up believing a payjoin is in flight while nothing was
        // ever stored. Relays reject for write policy, proof-of-work and rate
        // limits, and a throwaway key trips exactly those rules.
        let refused: Vec<(String, String)> = output
            .failed
            .iter()
            .map(|(relay, error)| (relay.to_string(), error.to_string()))
            .collect();
        for (relay, error) in &refused {
            tracing::warn!(%relay, %error, "relay refused the gift wrap");
        }

        if output.success.is_empty() {
            let reasons = refused
                .iter()
                .map(|(relay, error)| format!("{relay}: {error}"))
                .collect::<Vec<_>>()
                .join("; ");
            return Err(anyhow!(
                "no relay accepted the payjoin payload, so it is not stored anywhere \
                 and the peer will never see it ({reasons})"
            ));
        }

        tracing::info!(
            accepted = output.success.len(),
            refused = refused.len(),
            "gift wrap published"
        );

        Ok(SendReceipt {
            id: wrapped.id,
            outer_pubkey: wrapped.pubkey,
            created_at: wrapped.created_at,
            content_len: wrapped.content.len(),
            accepted: output.success.keys().map(|r| r.to_string()).collect(),
            refused,
        })
    }

    /// Wait for the next payjoin envelope addressed to us, up to `timeout`.
    ///
    /// `listening_since` is when this party started expecting messages: for a
    /// receiver, when its payjoin URI was created; for a sender, just before it
    /// published. It must be stable across restarts, so a resumed receiver passes
    /// the original creation time, not the time it came back.
    ///
    /// Returns the sealed sender pubkey alongside the envelope. That key is
    /// authenticated by NIP-59 because it comes from the seal rather than the
    /// forgeable outer event, so it is safe to use as the reply address.
    ///
    /// Never returns the same gift wrap twice from one transport.
    pub async fn recv(
        &self,
        listening_since: Timestamp,
        timeout: Duration,
    ) -> Result<Option<(PublicKey, PayjoinEnvelope)>> {
        Ok(self
            .recv_detailed(listening_since, timeout)
            .await?
            .map(|d| (d.sender, d.envelope)))
    }

    /// Like [`Self::recv`], but also reports which event carried the envelope.
    pub async fn recv_detailed(
        &self,
        listening_since: Timestamp,
        timeout: Duration,
    ) -> Result<Option<Delivery>> {
        let since = backlog_since(listening_since);
        let filter = Filter::new()
            .kind(Kind::GiftWrap)
            .pubkey(self.keys.public_key())
            .since(since);

        // Collect the backlog explicitly first. This is the case the whole design
        // exists for: a receiver that was offline when the sender published, and
        // is now back for a payload the relays held. Relying on the live
        // subscription to replay it is not something the notification stream
        // guarantees, so ask for it directly instead of hoping.
        let stored = self
            .client
            .fetch_events(filter.clone())
            .timeout(BACKLOG_TIMEOUT)
            .await
            .context("fetching stored gift wraps")?;

        let fresh: Vec<Event> = stored
            .into_iter()
            .filter(|event| !self.already_delivered(&event.id))
            .collect();
        if !fresh.is_empty() {
            tracing::info!(count = fresh.len(), "found stored gift wraps waiting");
        }
        for event in fresh {
            if let Some(delivery) = self.deliver(&event) {
                return Ok(Some(delivery));
            }
        }

        // Nothing waiting, so wait for something new. Take the notification
        // stream BEFORE issuing the REQ: a relay dumps what it has the instant it
        // sees a subscription, and subscribing first drops anything that lands in
        // the gap.
        let mut notifications = self.client.notifications();

        self.client
            .subscribe(filter)
            .await
            .context("subscribing for gift wraps")?;
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                _ = &mut deadline => return Ok(None),
                maybe = notifications.next() => {
                    let Some(notification) = maybe else { return Ok(None) };
                    let ClientNotification::Event { event, .. } = notification else { continue };
                    if event.kind != Kind::GiftWrap || self.already_delivered(&event.id) {
                        continue;
                    }
                    if let Some(delivery) = self.deliver(&event) {
                        return Ok(Some(delivery));
                    }
                }
            }
        }
    }

    fn already_delivered(&self, id: &EventId) -> bool {
        self.delivered
            .lock()
            .expect("delivered set poisoned")
            .contains(id)
    }

    /// Open a gift wrap and claim it, or skip it.
    ///
    /// A wrap we cannot open, or one carrying somebody else's protocol, is
    /// entirely normal on a shared relay, so it is skipped rather than treated as
    /// an error.
    fn deliver(&self, event: &Event) -> Option<Delivery> {
        match self.unwrap_envelope(event) {
            Ok(Some((sender, envelope))) if self.take_if_new(event.id) => Some(Delivery {
                event_id: event.id,
                sender,
                envelope,
            }),
            Ok(_) => None,
            Err(e) => {
                tracing::debug!(error = %e, "skipping undecryptable gift wrap");
                None
            }
        }
    }

    fn unwrap_envelope(&self, event: &Event) -> Result<Option<(PublicKey, PayjoinEnvelope)>> {
        let gift = UnwrappedGift::from_gift_wrap(&self.keys, event)?;
        if gift.rumor.kind != Kind::Custom(KIND_PAYJOIN_RUMOR) {
            return Ok(None);
        }
        let envelope: PayjoinEnvelope =
            serde_json::from_str(&gift.rumor.content).context("decoding payjoin envelope")?;
        Ok(Some((gift.sender, envelope)))
    }

    pub async fn shutdown(self) {
        self.client.shutdown().await;
    }
}

/// NIP-19 `nevent` identifier for `id` with relay hints.
///
/// Lets a demo link straight to a public event viewer, so anyone can inspect
/// exactly what a relay stored: a kind-1059 event, a throwaway author, and
/// ciphertext.
pub fn nevent(id: EventId, relays: &[String]) -> Option<String> {
    use nostr::nips::nip19::{Nip19Event, ToBech32};
    let hints: Vec<RelayUrl> = relays
        .iter()
        .filter_map(|r| RelayUrl::parse(r).ok())
        .collect();
    Nip19Event::new(id).relays(hints).to_bech32().ok()
}

/// Generate a fresh session keypair without connecting to any relay.
///
/// Returns `(secret_hex, public_hex)`. A receiver needs the public half for its
/// payjoin URI before it ever goes online, and the secret half to reconnect under
/// that identity later.
pub fn generate_session_key() -> (String, String) {
    let keys = Keys::generate();
    (
        keys.secret_key().to_secret_hex(),
        keys.public_key().to_hex(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trips_through_json() {
        let envelope = PayjoinEnvelope {
            leg: Leg::OriginalPsbt,
            session: "s1".into(),
            params: "v=1".into(),
            payload: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let encoded = serde_json::to_string(&envelope).unwrap();
        let decoded: PayjoinEnvelope = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.payload, envelope.payload);
        assert_eq!(decoded.leg, Leg::OriginalPsbt);
    }

    const HOUR: u64 = 3600;
    const DAY: u64 = 24 * HOUR;

    #[test]
    fn a_receiver_away_for_days_still_sees_a_maximally_backdated_payload() {
        // Regression: the window used to be `now - 49h`. A receiver that created
        // its URI at T, went offline, and came back six days later would miss a
        // payload published at T+1h and back-dated the full 48 hours.
        let created = Timestamp::from_secs(1_800_000_000);
        let published = created.as_secs() + HOUR;
        let wrap_created_at = Timestamp::from_secs(published - 2 * DAY);

        assert!(
            wrap_created_at >= backlog_since(created),
            "a wrap published after the URI existed must fall inside the window"
        );

        let returned = Timestamp::from_secs(created.as_secs() + 6 * DAY);
        let old_window = returned - Duration::from_secs(2 * DAY + HOUR);
        assert!(
            wrap_created_at < old_window,
            "the old now-relative window must drop this wrap, or this test no \
             longer reproduces the bug it guards"
        );
    }

    #[test]
    fn window_is_fixed_by_the_anchor_alone() {
        // No dependency on the current time: the same anchor gives the same
        // bound however late the receiver returns.
        let created = Timestamp::from_secs(1_800_000_000);
        assert_eq!(
            backlog_since(created).as_secs(),
            created.as_secs() - 2 * DAY - HOUR
        );
    }

    #[test]
    fn an_unknown_creation_time_fetches_everything_rather_than_underflowing() {
        // Session files written before created_at existed deserialize it as 0.
        // Every event to a per-URI key belongs to that URI, so no bound is safe.
        assert_eq!(backlog_since(Timestamp::from_secs(0)).as_secs(), 0);
    }

    #[test]
    fn payload_is_base64_not_a_byte_array() {
        // Guards the wire format: relays and any non-Rust implementation should
        // see a compact string, not a JSON array of several thousand integers.
        let envelope = PayjoinEnvelope {
            leg: Leg::Proposal,
            session: "s1".into(),
            params: String::new(),
            payload: b"psbt".to_vec(),
        };
        let encoded = serde_json::to_string(&envelope).unwrap();
        assert!(encoded.contains("\"cHNidA==\""), "got {encoded}");
    }
}
