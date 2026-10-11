//! Canonical bytes and the full-event comparison used by ledger dedup.
//!
//! README dedup rule (N2): the equality domain is the full submitted event, every
//! envelope field and the full payload. Key order is ignored, integers must match
//! exactly, strings must match code point for code point with no Unicode or
//! timestamp normalisation. An equal event under the same `(proxy_id, event_id)`
//! is a duplicate; any difference is a conflict (409).
//!
//! The canonical form is compact JSON with object keys sorted by their UTF-8 bytes.
//! It is an equality device, not a signing format.

use serde_json::Value;

use crate::event::ProxyEvent;

/// Outcome of comparing an incoming event with the stored event that has the
/// same `(proxy_id, event_id)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedupComparison {
    /// Identical in every field: ACK again as a duplicate.
    Duplicate,
    /// Any field differs: 409 `conflict`, never ACKed as a duplicate.
    Conflict,
}

/// Canonical bytes of a JSON value (sorted keys, no whitespace).
pub fn canonical_json(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_value(value, &mut out);
    out
}

fn write_value(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Value::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(item, out);
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            out.push(b'{');
            for (i, (k, v)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(k, out);
                out.push(b':');
                write_value(v, out);
            }
            out.push(b'}');
        }
    }
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    // serde_json's string escaping is deterministic and lossless for any &str.
    out.extend_from_slice(Value::String(s.to_owned()).to_string().as_bytes());
}

/// Canonical bytes of the full event (envelope and payload).
pub fn canonical_event_bytes(event: &ProxyEvent) -> Vec<u8> {
    // Serializing validated DTOs to a Value cannot fail.
    let value = serde_json::to_value(event).unwrap_or(Value::Null);
    canonical_json(&value)
}

/// Compares two events that share `(proxy_id, event_id)` over the full event.
pub fn compare_for_dedup(stored: &ProxyEvent, incoming: &ProxyEvent) -> DedupComparison {
    if canonical_event_bytes(stored) == canonical_event_bytes(incoming) {
        DedupComparison::Duplicate
    } else {
        DedupComparison::Conflict
    }
}
