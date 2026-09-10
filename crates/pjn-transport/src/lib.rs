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
        client.connect().await;
        Ok(Self {
            client,
            keys,
            relays: relays.to_vec(),
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
        Ok(*output.id())
    }

    /// Wait for the next payjoin envelope addressed to us, up to `timeout`.
    ///
    /// Returns the sealed sender pubkey alongside the envelope. That key is
    /// authenticated by NIP-59 because it comes from the seal rather than the
    /// forgeable outer event, so it is safe to use as the reply address.
    pub async fn recv(&self, timeout: Duration) -> Result<Option<(PublicKey, PayjoinEnvelope)>> {
        // Gift wraps randomize created_at up to two days into the past, so a
        // naive `since = now` filter silently drops perfectly good messages.
        let since = Timestamp::now() - Duration::from_secs(2 * 24 * 3600 + 3600);
        let filter = Filter::new()
            .kind(Kind::GiftWrap)
            .pubkey(self.keys.public_key())
            .since(since);

        // Take the notification stream BEFORE issuing the REQ. A relay dumps
        // everything it already has the instant it sees the subscription, so
        // subscribing first drops exactly the stored events this transport
        // exists to collect — the payload left for a receiver that was offline.
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
                    if event.kind != Kind::GiftWrap {
                        continue;
                    }
                    match self.unwrap_envelope(&event) {
                        Ok(Some(hit)) => return Ok(Some(hit)),
                        // A gift wrap we cannot open, or one carrying somebody
                        // else's protocol, is entirely normal on a shared relay.
                        // Keep waiting rather than failing the session.
                        Ok(None) => continue,
                        Err(e) => {
                            tracing::debug!(error = %e, "skipping undecryptable gift wrap");
                            continue;
                        }
                    }
                }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trips_through_json() {
        let envelope = PayjoinEnvelope {
            leg: Leg::OriginalPsbt,
            session: "s1".into(),
            payload: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let encoded = serde_json::to_string(&envelope).unwrap();
        let decoded: PayjoinEnvelope = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.payload, envelope.payload);
        assert_eq!(decoded.leg, Leg::OriginalPsbt);
    }

    #[test]
    fn payload_is_base64_not_a_byte_array() {
        // Guards the wire format: relays and any non-Rust implementation should
        // see a compact string, not a JSON array of several thousand integers.
        let envelope = PayjoinEnvelope {
            leg: Leg::Proposal,
            session: "s1".into(),
            payload: b"psbt".to_vec(),
        };
        let encoded = serde_json::to_string(&envelope).unwrap();
        assert!(encoded.contains("\"cHNidA==\""), "got {encoded}");
    }
}
