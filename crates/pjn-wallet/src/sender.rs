//! The sender's side of the Payjoin exchange.
//!
//! Mirror image of [`crate::receiver`], and the smaller half — but it contains
//! the one step that protects the sender's money.
//!
//! A Payjoin Proposal comes back from a party the sender has no reason to trust.
//! It has been rewritten: inputs added, outputs adjusted, fees changed. Signing
//! it blind would let a malicious receiver redirect funds or inflate the fee
//! until the change output vanishes. [`validate_proposal`] is what stands between
//! those two facts, and it must run before any signature.

use anyhow::{Context, Result};
use bitcoin::{Address, Amount, FeeRate, Psbt};
use payjoin::send::v1::V1Context;
use payjoin::{PjUri, Uri};

use crate::uri::NostrRoute;

/// A payjoin URI, split into the parts the sender actually needs.
pub struct ParsedInvoice {
    /// Payjoin's own view of the URI, needed to build the Original PSBT.
    pub pj_uri: PjUri,
    /// Where to reach the receiver over nostr.
    pub route: NostrRoute,
    pub address: Address,
    pub amount: Option<Amount>,
}

/// Parse a `bitcoin:` URI that carries nostr payjoin routing.
///
/// Rejects URIs for the wrong network before anything else happens: the failure
/// mode of getting that wrong is paying real money during a signet demo.
pub fn parse_invoice(uri: &str, network: bitcoin::Network) -> Result<ParsedInvoice> {
    let uri = Uri::try_from(uri)
        .map_err(|e| anyhow::anyhow!("not a valid BIP21 URI: {e:?}"))?
        .require_network(network)
        .map_err(|e| anyhow::anyhow!("URI is for the wrong network, refusing: {e:?}"))?;

    let pj_uri = uri
        .check_pj_supported()
        .map_err(|_| anyhow::anyhow!("URI has no pj= parameter, so it is not a payjoin request"))?;

    let address = pj_uri.address().clone();
    let amount = pj_uri.amount();

    // The endpoint is a carrier for nostr routing, never fetched. This also
    // rejects ordinary https payjoin URIs, which we cannot service over nostr.
    let route = NostrRoute::from_endpoint(&pj_uri.extras().pj_param().endpoint())?;

    Ok(ParsedInvoice {
        pj_uri,
        route,
        address,
        amount,
    })
}

/// Turn a signed Original PSBT into the bytes to publish, plus the context needed
/// to check the reply.
///
/// The context must survive until the proposal returns, which over an async
/// transport can be hours. A sender that loses it cannot validate the reply and
/// must fall back to broadcasting the original.
pub fn create_request(
    original_psbt: Psbt,
    pj_uri: PjUri,
    min_fee_rate: FeeRate,
) -> Result<(Vec<u8>, V1Context)> {
    crate::build_original_psbt(original_psbt, pj_uri, min_fee_rate)
}

/// Validate the receiver's Payjoin Proposal against what we originally sent.
///
/// **Never sign a proposal that has not been through here.** The receiver
/// rewrote our transaction; this confirms it did so within the rules — that our
/// outputs still pay what we intended, that the fee did not balloon, and that
/// inputs we did not authorise were not slipped in as ours to sign.
pub fn validate_proposal(context: V1Context, proposal_bytes: &[u8]) -> Result<Psbt> {
    crate::process_proposal(context, proposal_bytes)
        .context("the receiver's payjoin proposal failed validation and must not be signed")
}

/// Recover the fallback transaction from the Original PSBT.
///
/// If the payjoin does not complete — the receiver never answers, or its
/// proposal fails validation — the sender broadcasts this instead so the payment
/// still happens. Payjoin is an optimisation on a payment, not a precondition for
/// one, and a sender that cannot fall back has made its own payments fragile.
pub fn fallback_tx(original_psbt: &Psbt) -> Result<bitcoin::Transaction> {
    original_psbt
        .clone()
        .extract_tx()
        .context("extracting the fallback transaction from the original PSBT")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;

    const ADDR: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

    fn nostr_uri() -> String {
        format!(
            "bitcoin:{ADDR}?amount=0.001&pj=https://nostr.invalid/\
             a6145de34070ed1d963c4ed728648cc65d38126be586159cae5619e6a039b80a?r=wss://relay.damus.io"
        )
    }

    #[test]
    fn parses_a_nostr_routed_invoice() {
        let parsed = parse_invoice(&nostr_uri(), Network::Signet).expect("should parse");
        assert_eq!(parsed.amount, Some(Amount::from_sat(100_000)));
        assert_eq!(parsed.route.relays, vec!["wss://relay.damus.io"]);
        assert_eq!(
            parsed.route.session_pubkey,
            "a6145de34070ed1d963c4ed728648cc65d38126be586159cae5619e6a039b80a"
        );
    }

    #[test]
    fn rejects_a_mainnet_uri_on_signet() {
        // Paying real money during a signet demo is the expensive mistake here.
        let mainnet = "bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4?amount=0.001\
                       &pj=https://nostr.invalid/abc?r=wss://relay.damus.io";
        assert!(parse_invoice(mainnet, Network::Signet).is_err());
    }

    #[test]
    fn rejects_a_uri_with_no_pj_parameter() {
        let plain = format!("bitcoin:{ADDR}?amount=0.001");
        let err = parse_invoice(&plain, Network::Signet)
            .err()
            .expect("a URI with no pj= must be rejected");
        assert!(err.to_string().contains("no pj="), "{err}");
    }

    #[test]
    fn rejects_an_ordinary_https_payjoin_uri() {
        // A real BIP78 endpoint is well-formed but unreachable over nostr, so the
        // sender must refuse it rather than silently doing nothing.
        let http_pj = format!("bitcoin:{ADDR}?amount=0.001&pj=https://payjo.in/BTC/pj");
        assert!(parse_invoice(&http_pj, Network::Signet).is_err());
    }

    #[test]
    fn rejects_junk() {
        assert!(parse_invoice("not a uri", Network::Signet).is_err());
        assert!(parse_invoice("", Network::Signet).is_err());
    }
}
