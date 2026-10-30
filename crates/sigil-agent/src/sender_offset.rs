//! Reader for `sender-offset.json` — the on-disk record of how far the
//! Plan B `sigil-sender` has consumed in the agent's `events/` directory.
//! The sender writes it (`sigil_sender::state::SenderState`):
//! ```json
//! {
//!   "current_file": "events-2026-05-15-002.jsonl",
//!   "byte_offset": 1234567,
//!   "last_acked_sequence": 42
//! }
//! ```
//!
//! - File does not exist → `Ok(None)` ("no sender ever ran" — Plan A
//!   foundation behavior; the GC pretends nothing has been consumed).
//! - File exists but malformed → `Err(...)` (operators triage; the agent
//!   logs and falls back to "treat as no consumption" for safety).

use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

/// Where the packaged sigil-sender keeps its offset (its `offset_path`
/// default). shortcut: an operator who overrides `offset_path` in sender.yaml
/// leaves the GC without a sender record; plumb a flag if that is ever needed.
pub const DEFAULT_PATH: &str = "/var/lib/sigil-sender/sender-offset.json";

/// The fields of sigil-sender's `SenderState` the GC needs (#331). Other
/// fields, such as `last_acked_sequence`, are ignored.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SenderOffset {
    /// Filename (NOT full path) of the segment the sender is currently shipping.
    #[serde(rename = "current_file")]
    pub current_segment: String,
    /// Byte offset within `current_segment` up to which the sender has
    /// successfully shipped + acknowledged.
    pub byte_offset: u64,
}

#[derive(Debug, Error)]
pub enum SenderOffsetError {
    /// I/O failure reading the file (other than "not found").
    #[error("io: {0}")]
    Io(std::io::Error),
    /// JSON parse failure.
    #[error("json: {0}")]
    Json(serde_json::Error),
}

/// Read the sender's offset file at `path`.
/// Returns `Ok(None)` if the file does not exist.
pub fn read(path: &Path) -> Result<Option<SenderOffset>, SenderOffsetError> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(SenderOffsetError::Io(e)),
    };
    let off: SenderOffset = serde_json::from_slice(&bytes).map_err(SenderOffsetError::Json)?;
    Ok(Some(off))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn missing_file_returns_none() {
        let dir = tempdir().unwrap();
        assert_eq!(read(&dir.path().join("sender-offset.json")).unwrap(), None);
    }

    #[test]
    fn reads_what_sigil_sender_writes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sender-offset.json");
        std::fs::write(
            &path,
            br#"{"current_file":"events-2026-05-15-002.jsonl","byte_offset":1234567,"last_acked_sequence":42}"#,
        )
        .unwrap();
        assert_eq!(
            read(&path).unwrap(),
            Some(SenderOffset {
                current_segment: "events-2026-05-15-002.jsonl".into(),
                byte_offset: 1234567,
            })
        );
    }

    #[test]
    fn malformed_or_incomplete_json_returns_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sender-offset.json");
        for body in [&b"not json"[..], br#"{"current_file":"x"}"#] {
            std::fs::write(&path, body).unwrap();
            assert!(matches!(read(&path), Err(SenderOffsetError::Json(_))));
        }
    }
}
