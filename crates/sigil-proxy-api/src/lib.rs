//! Wire DTOs for the Sigil Proxy contracts.
//!
//! The types mirror `docs/specs/sigil-proxy/contracts/*.schema.json`
//! (proxy event envelope, status report, registry entry) and the error object
//! of the contracts README. Both the proxy and the server depend on this crate
//! so they cannot drift apart.
//!
//! Strictness rules, applied during deserialization:
//!
//! * objects the schema closes (`additionalProperties: false`) reject unknown fields;
//! * a JSON array is never accepted where the schema expects an object;
//! * integers must be JSON integer tokens within the schema bounds
//!   (`1.0`, `1e0`, booleans and values above `2^63-1` are rejected);
//! * UUIDs are lowercase hyphenated, timestamps are UTC RFC 3339 with
//!   calendar validity and no leap second, identifiers match the schema patterns;
//! * conditional (`if/then`) schema rules, array bounds and uniqueness are
//!   enforced by [`Validate`], which the deserializers call. Hand-built values
//!   can call `validate()` themselves.
//!
//! # Parsing untrusted input
//!
//! Raw `serde_json::from_*` errors name unknown fields, variants and sometimes
//! values. **They must not be logged or returned to a peer.** Parse network input
//! with the byte-level entry points in [`parse`] ([`parse_event_batch`],
//! [`parse_status`], [`parse_upload`], ...). They return a [`ParseError`] that holds
//! only a fixed [`ErrorCategory`] and an optional array index, and they also
//! reject duplicate JSON object keys. Direct `serde` deserialization stays
//! available for trusted data and tests.
//!
//! # Request versus response bodies
//!
//! Request bodies and stored documents are closed (unknown fields rejected).
//! Bodies the proxy reads from the server ([`ApiError`], [`IngestResponse`],
//! [`StatusResponse`], [`UploadResponse`]) ignore unknown fields when parsing so a
//! newer server can add fields; they emit only the declared fields.
//!
//! # Validation
//!
//! [`Validate::validate`] is recursive: a hand-built [`ProxyStatus`],
//! [`IngestRequest`] or [`UploadRequest`] validates every nested element.
//!
//! # Notes for consumers
//!
//! * Timestamps are kept as the exact received text: `08:00:00Z` and `08:00:00.0Z`
//!   are different values for dedup, so never re-format them before storing or
//!   retransmitting.
//! * `RegistryEntry::definition` is untrusted tool content for the access-controlled
//!   metadata store only; it must not reach logs or ordinary audit reads.
//!
//! (Review notes L-5 and L-6 were referenced without text; the two notes above are
//! the consumer-facing cautions this crate can state on its own.)
//!
//! This crate has no I/O and no dependency beyond `serde`/`serde_json`.

#[macro_use]
mod macros;

pub mod canonical;
pub mod error;
pub mod event;
pub mod parse;
pub mod registry;
pub mod scalar;
pub mod status;

pub use canonical::{canonical_event_bytes, canonical_json, compare_for_dedup, DedupComparison};
pub use error::{ApiError, ErrorBody, ErrorCode, ErrorItem, UnknownCode, ValidationError};
pub use event::{
    EventPayload, IngestRequest, IngestResponse, InvocationCancelRequested, InvocationCompleted,
    InvocationStarted, ProxyEvent,
};
pub use parse::{
    parse_api_error, parse_event, parse_event_batch, parse_ingest_response, parse_status,
    parse_status_response, parse_upload, parse_upload_response, ErrorCategory, ParseError,
};
pub use registry::{EntryView, RegistryEntry, UploadRequest, UploadResponse};
pub use scalar::{
    ConfigHash, Fingerprint, Id, KeyId, MetadataRef, NonNegativeI64, PositiveI64, SchemaVersion,
    Timestamp, Uuid,
};
pub use status::{GapReport, ProxyStatus, StatusResponse};

/// Cross-field rules the JSON schemas express with `if/then`, array bounds and uniqueness.
pub trait Validate {
    /// Returns the first violated rule.
    fn validate(&self) -> Result<(), ValidationError>;
}

pub(crate) mod helpers {
    use serde::de::{DeserializeOwned, Error as _};
    use serde::{Deserialize, Deserializer};
    use std::collections::HashSet;
    use std::hash::Hash;

    use crate::ValidationError;

    /// Optional field that must not be `null` when present.
    pub fn present<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de>,
    {
        T::deserialize(d).map(Some)
    }

    /// Required field whose value may be `null` (use without `default`).
    pub fn nullable<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de>,
    {
        Option::<T>::deserialize(d)
    }

    /// Buffers a value and requires a JSON object, so a sequence can never
    /// satisfy a struct (serde derives accept arrays for structs by default).
    pub struct ObjectOnly<T>(pub T);

    impl<'de, T: DeserializeOwned> Deserialize<'de> for ObjectOnly<T> {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            let value = serde_json::Value::deserialize(d)?;
            if !value.is_object() {
                return Err(D::Error::custom("expected a JSON object"));
            }
            T::deserialize(value)
                .map(ObjectOnly)
                .map_err(D::Error::custom)
        }
    }

    pub fn check_len(
        field: &str,
        len: usize,
        min: usize,
        max: usize,
    ) -> Result<(), ValidationError> {
        if len < min || len > max {
            return Err(ValidationError::limit(format!(
                "{field}: expected {min}..={max} items"
            )));
        }
        Ok(())
    }

    pub fn check_array<T: Eq + Hash>(
        field: &str,
        items: &[T],
        min: usize,
        max: usize,
        unique: bool,
    ) -> Result<(), ValidationError> {
        check_len(field, items.len(), min, max)?;
        if unique {
            let mut seen = HashSet::with_capacity(items.len());
            if !items.iter().all(|i| seen.insert(i)) {
                return Err(ValidationError::new(format!(
                    "{field}: items must be unique"
                )));
            }
        }
        Ok(())
    }
}
