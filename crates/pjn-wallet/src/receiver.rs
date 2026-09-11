//! The receiver's side of the Payjoin exchange.
//!
//! This module walks `payjoin`'s v1 receiver typestate from the sender's Original
//! PSBT to a signed Payjoin Proposal. Every step in that walk is a security check,
//! and the typestate exists so they cannot be skipped by accident — each one
//! consumes the previous state and produces the next, so there is no way to reach
//! [`respond`]'s final signature without having run all of them.
//!
//! The checks are not ceremony. A Payjoin receiver contributes one of its own
//! UTXOs to a transaction proposed by a stranger, which is an unusually generous
//! thing for a wallet to do, and each check closes a specific way that generosity
//! can be abused. See `docs/threat-model.md`.

use std::collections::HashSet;

use anyhow::{Context, Result};
use bitcoin::{FeeRate, OutPoint, Psbt, Script, Transaction};
use payjoin::receive::InputPair;
use payjoin::ImplementationError;

/// Everything the typestate walk needs from a wallet.
///
/// Kept as a trait so the protocol logic can be tested against a stub wallet with
/// no network, and so a signer that lives elsewhere (a hardware device, a
/// separate process) can be dropped in without touching the walk.
pub trait ReceiverWallet {
    /// Can this transaction be broadcast right now?
    ///
    /// Used to confirm the Original PSBT is a viable fallback. If the payjoin
    /// never completes, the sender broadcasts this instead, so a receiver that
    /// accepts an unbroadcastable original can be strung along indefinitely.
    fn can_broadcast(&self, tx: &Transaction) -> Result<bool, ImplementationError>;

    /// Does this outpoint belong to us?
    fn is_owned(&self, outpoint: &OutPoint) -> Result<bool, ImplementationError>;

    /// Does this script belong to us?
    fn is_receiver_output(&self, script: &Script) -> Result<bool, ImplementationError>;

    /// UTXOs we are willing to contribute to a payjoin.
    fn candidate_inputs(&self) -> Result<Vec<InputPair>, ImplementationError>;

    /// Sign the inputs we contributed. Must not sign the sender's inputs.
    fn sign_psbt(&self, psbt: &Psbt) -> Result<Psbt, ImplementationError>;
}

/// Outpoints this receiver has already been shown, across all sessions.
///
/// Guards two distinct attacks that share one defence:
///
/// 1. **UTXO probing.** A sender replays near-identical proposals; the receiver
///    contributes a different input each time and hands over a map of its wallet
///    without a single payment ever being broadcast.
/// 2. **Re-entrant payjoin.** A sender feeds back the payjoin PSBT from a
///    previous round as the Original PSBT of a new one.
///
/// Must outlive a single session to be worth anything, so a real deployment
/// persists this. In-memory is fine for a demo and honest about its limits.
#[derive(Debug, Default)]
pub struct SeenInputs {
    seen: HashSet<OutPoint>,
}

impl SeenInputs {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `outpoint` and report whether it had already been seen.
    ///
    /// Recording happens even on a hit: a sender that retries with a known input
    /// must not be able to clear our memory of it by trying again.
    pub fn check_and_record(&mut self, outpoint: &OutPoint) -> bool {
        !self.seen.insert(*outpoint)
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Iterate the recorded outpoints, for persisting across restarts.
    pub fn iter(&self) -> impl Iterator<Item = &OutPoint> + '_ {
        self.seen.iter()
    }
}

/// Fee bounds the receiver is willing to accept on the finished payjoin.
#[derive(Debug, Clone, Copy)]
pub struct FeePolicy {
    /// Reject an Original PSBT paying less than this.
    pub min_fee_rate: Option<FeeRate>,
    /// Refuse to let the finished transaction exceed this effective fee rate.
    ///
    /// Without a ceiling, a malicious sender can propose a fee so large that the
    /// receiver's contributed input is consumed by it.
    pub max_effective_fee_rate: Option<FeeRate>,
}

impl Default for FeePolicy {
    fn default() -> Self {
        Self {
            min_fee_rate: Some(FeeRate::from_sat_per_vb_u32(1)),
            // 100 sat/vB is far above any normal signet or mainnet fee, so this
            // rejects griefing without rejecting legitimate urgency.
            max_effective_fee_rate: Some(FeeRate::from_sat_per_vb_u32(100)),
        }
    }
}

/// Turn a sender's Original PSBT into a signed Payjoin Proposal.
///
/// Returns the base64 PSBT bytes to send back over the transport, which is the
/// same encoding a BIP78 HTTP receiver would put in its response body.
///
/// Every validation step runs in order and any failure aborts the session. That
/// is deliberate: a receiver that answers a failed check with anything other than
/// silence or a generic error leaks information about its own wallet.
pub fn respond(
    original_psbt_bytes: &[u8],
    params: &str,
    wallet: &impl ReceiverWallet,
    seen: &mut SeenInputs,
    fees: FeePolicy,
) -> Result<Vec<u8>> {
    let unchecked = crate::parse_original_psbt(original_psbt_bytes, params)?;

    // 1. Is the fallback transaction actually broadcastable?
    let maybe_inputs_owned = unchecked
        .check_broadcast_suitability(fees.min_fee_rate, |tx| wallet.can_broadcast(tx))
        .map_err(|e| anyhow::anyhow!("original PSBT is not broadcastable: {e:?}"))?;

    // 2. Are any of the sender's inputs actually ours? If so, someone is trying
    //    to get us to help spend our own coins.
    let maybe_inputs_seen = maybe_inputs_owned
        .check_inputs_not_owned(&mut |outpoint| wallet.is_owned(outpoint))
        .map_err(|e| anyhow::anyhow!("original PSBT contains our own inputs: {e:?}"))?;

    // 3. Have we been shown these inputs before? See SeenInputs.
    let outputs_unknown = maybe_inputs_seen
        .check_no_inputs_seen_before(&mut |outpoint| Ok(seen.check_and_record(outpoint)))
        .map_err(|e| anyhow::anyhow!("input replay detected, refusing to proceed: {e:?}"))?;

    // 4. Does this transaction actually pay us anything?
    let wants_outputs = outputs_unknown
        .identify_receiver_outputs(&mut |script| wallet.is_receiver_output(script))
        .map_err(|e| anyhow::anyhow!("original PSBT does not pay us: {e:?}"))?;

    let wants_inputs = wants_outputs.commit_outputs();

    // 5. Contribute exactly one input, chosen to avoid the Unnecessary Input
    //    Heuristic. Picking a bad input can make the payjoin *more* legible to a
    //    chain analyst than a plain payment would have been, so this selection is
    //    a privacy decision, not a convenience.
    let candidates = wallet
        .candidate_inputs()
        .map_err(|e| anyhow::anyhow!("listing candidate inputs: {e:?}"))?;
    anyhow::ensure!(
        !candidates.is_empty(),
        "no spendable UTXOs available to contribute to the payjoin"
    );

    let selected = wants_inputs
        .try_preserving_privacy(candidates)
        .map_err(|e| anyhow::anyhow!("selecting an input that preserves privacy: {e:?}"))?;

    let wants_fee_range = wants_inputs
        .contribute_inputs(vec![selected])
        .map_err(|e| anyhow::anyhow!("contributing our input: {e:?}"))?
        .commit_inputs();

    // 6. Clamp the fee before signing anything.
    let provisional = wants_fee_range
        .apply_fee_range(fees.min_fee_rate, fees.max_effective_fee_rate)
        .map_err(|e| anyhow::anyhow!("proposed fee is outside our policy: {e:?}"))?;

    // 7. Sign only our own inputs.
    let proposal = provisional
        .finalize_proposal(|psbt| wallet.sign_psbt(psbt))
        .map_err(|e| anyhow::anyhow!("signing the payjoin proposal: {e:?}"))?;

    let psbt = proposal.psbt();
    Ok(encode_psbt(psbt))
}

/// Encode a PSBT the way a BIP78 receiver's HTTP response body would.
fn encode_psbt(psbt: &Psbt) -> Vec<u8> {
    psbt.to_string().into_bytes()
}

/// Decode a base64 PSBT that arrived over the transport.
pub fn decode_psbt(bytes: &[u8]) -> Result<Psbt> {
    let text = std::str::from_utf8(bytes).context("PSBT payload was not valid UTF-8")?;
    text.trim()
        .parse::<Psbt>()
        .context("payload was not a valid base64 PSBT")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::Txid;

    fn outpoint(n: u8) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([n; 32]),
            vout: 0,
        }
    }

    #[test]
    fn first_sighting_of_an_input_is_not_a_replay() {
        let mut seen = SeenInputs::new();
        assert!(!seen.check_and_record(&outpoint(1)));
        assert_eq!(seen.len(), 1);
    }

    #[test]
    fn second_sighting_is_flagged_as_a_replay() {
        let mut seen = SeenInputs::new();
        seen.check_and_record(&outpoint(1));
        assert!(
            seen.check_and_record(&outpoint(1)),
            "a repeated outpoint must be reported as already seen"
        );
    }

    #[test]
    fn a_retry_does_not_clear_our_memory_of_an_input() {
        // If re-presenting a known input reset its state, a prober could simply
        // send everything twice to get a clean slate.
        let mut seen = SeenInputs::new();
        seen.check_and_record(&outpoint(7));
        seen.check_and_record(&outpoint(7));
        assert!(
            seen.check_and_record(&outpoint(7)),
            "outpoint must still be remembered after repeated attempts"
        );
        assert_eq!(seen.len(), 1, "repeats must not grow the set");
    }

    #[test]
    fn distinct_inputs_are_tracked_separately() {
        let mut seen = SeenInputs::new();
        assert!(!seen.check_and_record(&outpoint(1)));
        assert!(!seen.check_and_record(&outpoint(2)));
        assert_eq!(seen.len(), 2);
    }

    #[test]
    fn default_fee_policy_bounds_both_ends() {
        // A missing ceiling lets a sender burn the receiver's contributed input
        // as fee, so the default must set one.
        let policy = FeePolicy::default();
        assert!(policy.min_fee_rate.is_some());
        assert!(
            policy.max_effective_fee_rate.is_some(),
            "an unbounded fee ceiling is a griefing vector"
        );
    }

    #[test]
    fn psbt_encoding_round_trips() {
        // Uses the PSBT the payjoin test vectors are built from: a v0 PSBT with
        // one input and one output is enough to prove the base64 seam.
        let raw = "cHNidP8BAHECAAAAAfCEDLBBrhZLsEDoBHNzL/0J6IJ7EMDlJoyGKzhJb0BeAAAAAAD9////AjSPBSoBAAAAFgAUpwGaJmpFVdEUUiOJhOTLBnkYqjmAlpgAAAAAABYAFCFKzUYXhZ+w0RRcbTzOB9d1cPfmAAAAAAABAR8A4fUFAAAAABYAFCFKzUYXhZ+w0RRcbTzOB9d1cPfmAAAA";
        let psbt = decode_psbt(raw.as_bytes()).expect("fixture should parse");
        let reencoded = encode_psbt(&psbt);
        assert_eq!(
            decode_psbt(&reencoded).expect("re-encoded PSBT should parse"),
            psbt
        );
    }

    #[test]
    fn decoding_rejects_garbage() {
        assert!(decode_psbt(b"not a psbt").is_err());
        assert!(decode_psbt(&[0xff, 0xfe, 0xfd]).is_err());
    }
}
