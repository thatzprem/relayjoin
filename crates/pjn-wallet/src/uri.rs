//! Encoding nostr routing inside a BIP21 payjoin URI.
//!
//! # Why the endpoint looks like a URL but is not one
//!
//! BIP78 requires the `pj=` endpoint to be `https`, or `http` on a `.onion`
//! domain — anything else is rejected as an unsecure endpoint. That rule exists
//! because over HTTP the endpoint *is* the transport, and a plaintext one would
//! expose the PSBT.
//!
//! Our transport is not HTTP. The routing information a sender actually needs is
//! a nostr public key and a set of relays. So we encode exactly that into a URL
//! shaped to satisfy the parser, and never fetch it.
//!
//! The host is deliberately under `.invalid`, which [RFC 2606] reserves and
//! guarantees will never resolve. That makes the failure mode safe in both
//! directions: our sender ignores the URL entirely, and a stock BIP78 sender that
//! tries to POST to it fails immediately against a name that cannot exist, rather
//! than leaking a PSBT to whoever happens to own a real domain.
//!
//! ```text
//! bitcoin:tb1q...?amount=0.001&pj=https://nostr.invalid/<npub>?r=wss://relay.one,wss://relay.two
//!                                                       ^^^^^^   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//!                                                       session key      relays to try
//! ```
//!
//! [RFC 2606]: https://www.rfc-editor.org/rfc/rfc2606

use anyhow::{anyhow, Context, Result};

/// Reserved host that can never resolve. See the module docs.
pub const CARRIER_HOST: &str = "nostr.invalid";

/// Routing details a sender needs to reach a receiver over nostr.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NostrRoute {
    /// The receiver's per-URI session key, hex-encoded.
    ///
    /// Per-URI, not per-identity: reusing this across payjoin URIs would turn it
    /// into a persistent identifier that relays could count payments against.
    pub session_pubkey: String,
    /// Relays to publish to and read from.
    pub relays: Vec<String>,
}

impl NostrRoute {
    pub fn new(session_pubkey: impl Into<String>, relays: Vec<String>) -> Result<Self> {
        let session_pubkey = session_pubkey.into();
        anyhow::ensure!(
            !session_pubkey.is_empty(),
            "session pubkey must not be empty"
        );
        anyhow::ensure!(!relays.is_empty(), "at least one relay is required");
        Ok(Self {
            session_pubkey,
            relays,
        })
    }

    /// Render as the `pj=` endpoint URL.
    pub fn to_endpoint(&self) -> String {
        format!(
            "https://{CARRIER_HOST}/{}?r={}",
            self.session_pubkey,
            self.relays.join(",")
        )
    }

    /// Recover routing from a `pj=` endpoint produced by [`Self::to_endpoint`].
    pub fn from_endpoint(endpoint: &str) -> Result<Self> {
        let rest = endpoint
            .strip_prefix("https://")
            .ok_or_else(|| anyhow!("payjoin endpoint must be https, got {endpoint}"))?;

        let (host, path_and_query) = rest
            .split_once('/')
            .ok_or_else(|| anyhow!("endpoint has no path component: {endpoint}"))?;
        anyhow::ensure!(
            host == CARRIER_HOST,
            "endpoint host is {host}, expected {CARRIER_HOST} — this URI is not \
             routed over nostr, and fetching it is not something we will do"
        );

        let (pubkey, query) = path_and_query
            .split_once('?')
            .ok_or_else(|| anyhow!("endpoint carries no relay list: {endpoint}"))?;

        let relays: Vec<String> = query
            .strip_prefix("r=")
            .context("endpoint query must start with r=")?
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();

        Self::new(pubkey, relays)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route() -> NostrRoute {
        NostrRoute::new(
            "a6145de34070ed1d963c4ed728648cc65d38126be586159cae5619e6a039b80a",
            vec![
                "wss://relay.damus.io".to_string(),
                "wss://nos.lol".to_string(),
            ],
        )
        .unwrap()
    }

    #[test]
    fn endpoint_round_trips() {
        let original = route();
        let parsed = NostrRoute::from_endpoint(&original.to_endpoint()).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn endpoint_uses_the_reserved_invalid_host() {
        // If this ever became a resolvable host, a stock BIP78 sender would POST
        // a PSBT to whoever owned it.
        assert!(route().to_endpoint().starts_with("https://nostr.invalid/"));
    }

    #[test]
    fn rejects_a_real_https_endpoint() {
        // A normal BIP78 URI must not be mistaken for a nostr-routed one.
        let err = NostrRoute::from_endpoint("https://payjo.in/BTC/pj?r=wss://x").unwrap_err();
        assert!(err.to_string().contains("expected nostr.invalid"), "{err}");
    }

    #[test]
    fn rejects_non_https() {
        assert!(NostrRoute::from_endpoint("http://nostr.invalid/abc?r=wss://x").is_err());
        assert!(NostrRoute::from_endpoint("nostr://abc").is_err());
    }

    #[test]
    fn rejects_an_endpoint_with_no_relays() {
        assert!(NostrRoute::from_endpoint("https://nostr.invalid/abc").is_err());
        assert!(NostrRoute::from_endpoint("https://nostr.invalid/abc?r=").is_err());
    }

    #[test]
    fn requires_at_least_one_relay_at_construction() {
        assert!(NostrRoute::new("abc", vec![]).is_err());
    }

    #[test]
    fn parses_a_single_relay() {
        let r =
            NostrRoute::from_endpoint("https://nostr.invalid/deadbeef?r=wss://only.one").unwrap();
        assert_eq!(r.relays, vec!["wss://only.one"]);
        assert_eq!(r.session_pubkey, "deadbeef");
    }
}
