//! On-disk session state, so a payjoin survives the process that started it.
//!
//! This is what makes the asynchrony real rather than aspirational. Relays hold
//! the peer's payload for days, but that is worthless if the local endpoint
//! forgets the key needed to decrypt it. Before this existed, closing the
//! receiver's terminal permanently killed the payjoin URI it had printed.
//!
//! # What is stored
//!
//! A session file contains a **secret key**. On signet that key guards nothing of
//! value, but the same file on mainnet would be worth stealing, so it is written
//! with an atomic replace and never logged.
//!
//! # Why the sender stores a PSBT instead of its validation context
//!
//! `payjoin::send::v1::V1Context` is not serializable — its inner `PsbtContext`
//! is, but the wrapper exposes no way to reach it. Rather than reconstruct
//! private state, the sender persists the inputs that produced the context (the
//! Original PSBT, the URI, the fee rate) and rebuilds it on resume. Deterministic,
//! and it keeps us on the crate's public API.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bitcoin::OutPoint;
use serde::{Deserialize, Serialize};

use crate::receiver::SeenInputs;

/// Default session filename, alongside the working directory.
pub const DEFAULT_SESSION_FILE: &str = ".pjn-session.json";

/// A receiver's session: the key its payjoin URI points at, plus what it has seen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiverSession {
    /// Hex-encoded nostr secret key for this session.
    ///
    /// One per payjoin URI. Reusing it across URIs would let relays link every
    /// payment this receiver coordinates.
    pub secret_key: String,
    pub relays: Vec<String>,
    /// The address the URI pays, kept so a resumed session reprints the same URI.
    pub address: String,
    pub amount_sat: u64,
    /// Outpoints already shown to us, as `txid:vout`.
    ///
    /// Persisting these is the point of the file for security purposes: UTXO
    /// probing protection that resets on restart protects nothing, because an
    /// attacker can just wait for a restart.
    #[serde(default)]
    pub seen_inputs: Vec<String>,
}

impl ReceiverSession {
    /// Rebuild the in-memory probing guard from disk.
    pub fn seen(&self) -> SeenInputs {
        let mut seen = SeenInputs::new();
        for raw in &self.seen_inputs {
            match raw.parse::<OutPoint>() {
                Ok(outpoint) => {
                    seen.check_and_record(&outpoint);
                }
                // A malformed entry must not wipe the rest of the history, or a
                // single bad write would silently disarm the guard.
                Err(e) => tracing::warn!(entry = %raw, error = %e, "skipping unparseable outpoint"),
            }
        }
        seen
    }

    pub fn record_seen(&mut self, seen: &SeenInputs) {
        self.seen_inputs = seen.iter().map(|o| o.to_string()).collect();
    }
}

/// A sender's session: enough to rebuild its validation context after a restart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderSession {
    /// Hex-encoded nostr secret key, so the receiver's reply can still be read.
    pub secret_key: String,
    pub relays: Vec<String>,
    /// The receiver's session key, hex-encoded.
    pub receiver_pubkey: String,
    /// Correlates the reply with this request.
    pub session_id: String,
    /// Base64 Original PSBT. Doubles as the fallback if the payjoin never lands.
    pub original_psbt: String,
    /// The URI this payment was made against, needed to rebuild the context.
    pub pj_uri: String,
    pub fee_rate_sat_vb: u64,
}

/// Read a session file, or `None` if it does not exist.
pub fn load<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading session file {}", path.display()))?;
    let session = serde_json::from_str(&raw)
        .with_context(|| format!("parsing session file {}", path.display()))?;
    Ok(Some(session))
}

/// Write a session file atomically.
///
/// Writes to a sibling temp file and renames, so an interrupted write cannot
/// leave a half-written session that would strand the payjoin. The rename is
/// atomic on both POSIX and Windows.
pub fn save<T: Serialize>(path: &Path, session: &T) -> Result<()> {
    let json = serde_json::to_string_pretty(session).context("serializing session")?;

    let tmp = temp_path(path);
    std::fs::write(&tmp, json.as_bytes()).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("replacing {} with {}", path.display(), tmp.display()))?;
    Ok(())
}

/// Delete a finished session.
///
/// A completed payjoin's session file is a stale secret key with no further use,
/// so it should not linger.
pub fn clear(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("removing session file {}", path.display())),
    }
}

fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::Txid;

    fn tmpdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pjn-session-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn receiver_session() -> ReceiverSession {
        ReceiverSession {
            secret_key: "aa".repeat(32),
            relays: vec!["wss://relay.damus.io".into()],
            address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".into(),
            amount_sat: 50_000,
            seen_inputs: vec![],
        }
    }

    #[test]
    fn missing_file_loads_as_none() {
        let path = tmpdir().join("does-not-exist.json");
        let loaded: Option<ReceiverSession> = load(&path).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn session_round_trips_through_disk() {
        let path = tmpdir().join("roundtrip.json");
        let session = receiver_session();
        save(&path, &session).unwrap();

        let loaded: ReceiverSession = load(&path).unwrap().expect("just wrote it");
        assert_eq!(loaded.secret_key, session.secret_key);
        assert_eq!(loaded.amount_sat, 50_000);
        assert_eq!(loaded.relays, session.relays);
        clear(&path).unwrap();
    }

    #[test]
    fn seen_inputs_survive_a_restart() {
        // The whole security value of persisting: probing protection that resets
        // on restart protects nothing, since an attacker can wait for a restart.
        let path = tmpdir().join("seen.json");
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([7; 32]),
            vout: 1,
        };

        let mut seen = SeenInputs::new();
        seen.check_and_record(&outpoint);

        let mut session = receiver_session();
        session.record_seen(&seen);
        save(&path, &session).unwrap();

        let loaded: ReceiverSession = load(&path).unwrap().unwrap();
        let mut restored = loaded.seen();
        assert!(
            restored.check_and_record(&outpoint),
            "an outpoint seen before the restart must still be recognised after it"
        );
        clear(&path).unwrap();
    }

    #[test]
    fn a_malformed_outpoint_does_not_discard_the_rest() {
        let good = OutPoint {
            txid: Txid::from_byte_array([9; 32]),
            vout: 0,
        };
        let session = ReceiverSession {
            seen_inputs: vec!["not-an-outpoint".into(), good.to_string()],
            ..receiver_session()
        };
        let mut restored = session.seen();
        assert!(
            restored.check_and_record(&good),
            "one bad entry must not disarm the guard for valid ones"
        );
    }

    #[test]
    fn clearing_a_missing_file_is_not_an_error() {
        let path = tmpdir().join("never-existed.json");
        assert!(clear(&path).is_ok());
    }

    #[test]
    fn save_replaces_an_existing_session() {
        let path = tmpdir().join("replace.json");
        save(&path, &receiver_session()).unwrap();

        let updated = ReceiverSession {
            amount_sat: 99_999,
            ..receiver_session()
        };
        save(&path, &updated).unwrap();

        let loaded: ReceiverSession = load(&path).unwrap().unwrap();
        assert_eq!(loaded.amount_sat, 99_999);
        // The temp file must not survive a successful write.
        assert!(!temp_path(&path).exists());
        clear(&path).unwrap();
    }
}
