//! The report a running `lodeline-sender` leaves on disk for readers on this host.
//!
//! The sender writes it and `lodeline-diag` reads it, so the schema lives here: the
//! reader must not link the sender's TLS stack. It holds timestamps and enums only.
//! No string field means no URL, server message, or path can reach the file.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;
use time::OffsetDateTime;

/// Bump when a reader of an older version would misread the file.
pub const REPORT_SCHEMA_VERSION: u32 = 1;

/// How often a running sender rewrites the file when nothing changed.
pub const REPORT_INTERVAL: Duration = Duration::from_secs(30);

/// A report older than this means the sender stopped or hung: three writes missed.
pub const STALE_AFTER: Duration = Duration::from_secs(90);

/// A real report is a few hundred bytes.
pub const MAX_REPORT_BYTES: u64 = 16 * 1024;

/// The report sits next to `sender-offset.json`, like `policy-etag.txt`, so a reader
/// can find it from `sender.yaml`.
pub fn status_path_for(offset_path: &Path) -> PathBuf {
    offset_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("sender-status.json")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderReport {
    pub schema_version: u32,
    #[serde(with = "time::serde::rfc3339")]
    pub written_at: OffsetDateTime,
    pub contact: Contact,
    /// The certificate this sender process loaded. `None` when it has none, or could
    /// not read the expiry.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub client_cert_expires_at: Option<OffsetDateTime>,
}

/// What this sender last learned from `lodeline-server`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Contact {
    /// No request has finished since this sender started.
    NoAnswerYet,
    Reached {
        #[serde(with = "time::serde::rfc3339")]
        last_ok_at: OffsetDateTime,
    },
    Failing {
        #[serde(with = "time::serde::rfc3339")]
        since: OffsetDateTime,
        failure: LinkFailure,
        #[serde(with = "time::serde::rfc3339::option")]
        last_ok_at: Option<OffsetDateTime>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LinkFailure {
    Network,
    Tls,
    /// The server answered with a status that is not a success.
    Response {
        last_response_code: u16,
    },
    /// The server answered success with a body the sender cannot use.
    Protocol,
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn report_sits_next_to_the_offset_file() {
        assert_eq!(
            status_path_for(Path::new("/var/lib/lodeline-sender/sender-offset.json")),
            Path::new("/var/lib/lodeline-sender/sender-status.json")
        );
    }

    #[test]
    fn report_round_trips_through_its_wire_form() {
        let report = SenderReport {
            schema_version: REPORT_SCHEMA_VERSION,
            written_at: datetime!(2026-11-01 12:00 UTC),
            contact: Contact::Failing {
                since: datetime!(2026-11-01 11:00 UTC),
                failure: LinkFailure::Response {
                    last_response_code: 503,
                },
                last_ok_at: None,
            },
            client_cert_expires_at: Some(datetime!(2026-12-01 0:00 UTC)),
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains(r#""kind":"response","last_response_code":503"#));
        assert_eq!(serde_json::from_str::<SenderReport>(&json).unwrap(), report);
    }
}
