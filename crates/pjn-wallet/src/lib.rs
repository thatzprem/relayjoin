//! Binding between the Payjoin protocol state machines and the nostr transport.
//!
//! # Why the v1 protocol over a v2-style transport
//!
//! BIP78 (Payjoin v1) is a clean two-message protocol: the sender posts an
//! Original PSBT, the receiver answers with a Payjoin Proposal. Its only real
//! deployment problem is that the receiver must be reachable over HTTP at the
//! moment the sender pays, which rules out phones and anything behind NAT.
//!
//! BIP77 (v2) fixes that by adding three things HTTP cannot provide on its own:
//!
//! | Need | BIP77 answer | Nostr answer |
//! |---|---|---|
//! | store-and-forward | Payjoin Directory | relays, already deployed |
//! | payload encryption | HPKE | NIP-44 seal |
//! | metadata / IP privacy | OHTTP relay | ephemeral keys per message |
//!
//! Nostr already supplies all three. So we keep the *v1 protocol semantics*,
//! which are simple and fully exposed by `payjoin` 1.0.0's public API, and let the
//! transport carry the asynchrony. The result is an async payjoin that needs no
//! directory operator, no OHTTP relay, and no new infrastructure of any kind.
//!
//! The seam is deliberately narrow. [`payjoin::Request`] exposes `body` as public
//! bytes, and the receiver parses those same bytes back via
//! `UncheckedOriginalPayload::from_request`. Everything between those two points
//! is opaque to [`pjn_transport`], which is what keeps this swappable.
//!
//! # Interop note
//!
//! Payloads are standard BIP78 bodies and query parameters, so the protocol layer
//! is compatible with any BIP78 implementation. The transport is not: a stock
//! BIP78 sender POSTs over HTTPS and cannot reach a nostr-routed receiver, and
//! the `pj=` endpoint in our URIs sits under the reserved `.invalid` TLD so such a
//! sender fails immediately rather than leaking a PSBT. Paying across the two
//! transports would need a bridge that accepts BIP78 over HTTPS and relays it as
//! gift wraps. No such bridge exists.

pub mod receiver;
pub mod sender;
pub mod session;
pub mod signet;
pub mod uri;
pub use receiver::{FeePolicy, ReceiverStep, ReceiverWallet, SeenInputs};

use anyhow::{Context, Result};
use payjoin::receive::v1::{Headers, UncheckedOriginalPayload};
use payjoin::send::v1::SenderBuilder;
use payjoin::{PjUri, Request};

pub use bitcoin::{Address, Amount, FeeRate, Psbt};

/// Minimal [`Headers`] implementation for payloads that arrived over nostr.
///
/// The v1 receiver API was written against an HTTP server, so it asks for headers.
/// Over nostr there is no HTTP layer, but the protocol only genuinely needs
/// `content-type` and `content-length`, so we synthesize exactly those and nothing
/// else. Anything a real HTTP receiver would have used for authentication is
/// already handled one layer down by the NIP-59 seal.
pub struct NostrHeaders {
    content_length: String,
}

impl NostrHeaders {
    pub fn for_body(body: &[u8]) -> Self {
        Self {
            content_length: body.len().to_string(),
        }
    }
}

impl Headers for NostrHeaders {
    fn get_header(&self, key: &str) -> Option<&str> {
        match key.to_lowercase().as_str() {
            "content-type" => Some("text/plain"),
            "content-length" => Some(&self.content_length),
            _ => None,
        }
    }
}

/// The sender's half: turn a funded, signed PSBT into bytes to put on nostr.
///
/// Returns the payload plus the context needed to validate the receiver's reply.
/// The context must be kept until the proposal comes back, which over an async
/// transport may be hours later, so callers are expected to persist it.
pub fn build_original_psbt(
    psbt: Psbt,
    uri: PjUri,
    min_fee_rate: FeeRate,
) -> Result<(String, Vec<u8>, payjoin::send::v1::V1Context)> {
    let sender = SenderBuilder::new(psbt, uri)
        .build_recommended(min_fee_rate)
        .map_err(|e| anyhow::anyhow!("building payjoin sender: {e:?}"))?;

    let (request, context): (Request, _) = sender.create_v1_post_request();

    // The URL's *host* is meaningless to us — routing lives in the gift wrap's
    // `p` tag. Its *query* is not: payjoin encodes the sender's constraints there
    // (`v`, `maxadditionalfeecontribution`, `minfeerate`, output substitution).
    // Dropping it makes the receiver edit the transaction in ways the sender
    // never authorised, and the proposal is then correctly rejected.
    debug_assert_eq!(request.content_type, "text/plain");
    let query = request
        .url
        .split_once('?')
        .map(|(_, query)| query.to_string())
        .unwrap_or_default();

    Ok((query, request.body, context))
}

/// The receiver's half: parse bytes that arrived over nostr into the protocol's
/// first typestate.
///
/// From here the caller walks the `payjoin` typestate machine — checking
/// broadcast suitability, input ownership, and so on. Those checks are the
/// receiver's protection against a malicious sender probing its UTXO set, so the
/// caller must not skip them.
pub fn parse_original_psbt(body: &[u8], query: &str) -> Result<UncheckedOriginalPayload> {
    let headers = NostrHeaders::for_body(body);
    // `query` carries the sender's constraints, forwarded verbatim from the
    // envelope. An empty string here is almost always a bug in the caller.
    UncheckedOriginalPayload::from_request(body, query, headers)
        .map_err(|e| anyhow::anyhow!("parsing original PSBT from nostr payload: {e:?}"))
}

/// Validate the receiver's proposal against the context saved at send time.
///
/// This is the step that stops a malicious receiver from returning a PSBT that
/// steals funds or inflates fees. It must run before the sender signs anything.
pub fn process_proposal(
    context: payjoin::send::v1::V1Context,
    proposal_bytes: &[u8],
) -> Result<Psbt> {
    context
        .process_response(proposal_bytes)
        .map_err(|e| anyhow::anyhow!("receiver's payjoin proposal was rejected: {e:?}"))
        .context("validating payjoin proposal")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_report_only_what_the_protocol_needs() {
        let headers = NostrHeaders::for_body(b"hello");
        assert_eq!(headers.get_header("content-type"), Some("text/plain"));
        assert_eq!(headers.get_header("Content-Length"), Some("5"));
        // No HTTP layer exists over nostr; anything else must read as absent
        // rather than as an empty string.
        assert_eq!(headers.get_header("authorization"), None);
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        // The payjoin crate queries with varying case depending on the code path.
        let headers = NostrHeaders::for_body(b"xy");
        assert_eq!(headers.get_header("CONTENT-TYPE"), Some("text/plain"));
        assert_eq!(headers.get_header("content-length"), Some("2"));
    }
}
