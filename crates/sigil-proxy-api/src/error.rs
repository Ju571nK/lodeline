//! Error object `{error:{code,message,items?,pending_metadata_refs?}}` and codes.
//!
//! Bodies the proxy reads from the server (`ApiError`, `ErrorBody`, `ErrorItem`)
//! ignore unknown fields when parsing, so a newer server can add fields. They
//! still emit only the declared fields.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::scalar::{MetadataRef, Uuid};
use crate::Validate;

/// Category of a rule violation raised by this crate's own validation code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Raised {
    Semantic,
    Limit,
}

thread_local! {
    /// Set only by [`ValidationError::tagged`], i.e. by code in this crate when it
    /// rejects a value. Input bytes cannot write to it, unlike serde's message
    /// text, which can quote unknown keys, variants and values. The byte-level
    /// parse entry points clear it before and after each parse (see
    /// `parse::RaisedScope`).
    static RAISED: std::cell::Cell<Option<Raised>> = const { std::cell::Cell::new(None) };
}

pub(crate) fn take_raised() -> Option<Raised> {
    RAISED.with(|c| c.take())
}

pub(crate) fn set_raised(r: Option<Raised>) {
    RAISED.with(|c| c.set(r));
}

/// A contract rule was violated. The message is a fixed text and never contains
/// the offending value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    message: String,
    limit: bool,
}

impl ValidationError {
    /// A cross-field or uniqueness violation.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            limit: false,
        }
    }

    /// A size or count bound violation.
    pub fn limit(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            limit: true,
        }
    }

    /// Records the category out of band and returns the fixed message.
    ///
    /// Validation errors must propagate immediately: never swallow, retry or
    /// replace one, because the out-of-band category cell read by `parse::classify`
    /// relies on the last recorded signal belonging to the error that surfaces.
    pub(crate) fn tagged(&self) -> String {
        set_raised(Some(if self.limit {
            Raised::Limit
        } else {
            Raised::Semantic
        }));
        self.message.clone()
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ValidationError {}

/// Text of an error code this crate does not know.
///
/// Opaque and constructible only through [`ErrorCode::parse`] / deserialization:
/// at most 64 characters of `[a-z0-9_]` that are not a known code; anything else is
/// the fixed marker `unknown`. `Unknown("conflict")` is therefore impossible.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnknownCode(String);

impl UnknownCode {
    pub const MARKER: &'static str = "unknown";
    const MAX_LEN: usize = 64;

    fn from_text(text: &str) -> Self {
        let ok = !text.is_empty()
            && text.len() <= Self::MAX_LEN
            && text
                .bytes()
                .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_'));
        Self(if ok { text } else { Self::MARKER }.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Fixed error codes of the contracts README error table.
///
/// The contracts do not say how a reader treats a code it does not know, so
/// unknown codes are preserved as [`ErrorCode::Unknown`] instead of failing the
/// whole response. Treat `Unknown` as a generic failure of the HTTP status class.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    ProxyUnknown,
    Conflict,
    SequenceConflict,
    RegistryConflict,
    InvocationOwnerConflict,
    RevisionConflict,
    Disabled,
    Retired,
    MetadataRefPending,
    SemanticInvalid,
    /// UNSTABLE: "checker-only" in the contracts README and still [OPEN] in the
    /// contract files. The server must not emit it yet.
    SchemaInvalid,
    /// UNSTABLE: "checker-only" in the contracts README and still [OPEN] in the
    /// contract files. The server must not emit it yet.
    InvalidStatus,
    InvalidCursor,
    InvalidFilter,
    /// Management routes: bearer missing, wrong, expired or not bound to the
    /// presenting caller cert. 401.
    Unauthorized,
    /// Management routes: valid credential, insufficient scope. 403.
    Forbidden,
    /// Management routes: the `proxy_id` or fingerprint is already registered. 409.
    AlreadyExists,
    /// Management routes: the lifecycle transition is not allowed from the
    /// current state. 409.
    InvalidState,
    /// `GET` config before any configuration was issued for the proxy. 404.
    /// Distinct from `proxy_unknown`: the identity is valid.
    ConfigUnavailable,
    /// Ingest: the store refuses more data (capacity). 503.
    StorageLimit,
    /// Ingest: the store cannot be reached or written. 503.
    StorageUnavailable,
    /// Request body exceeds the accepted size. 413.
    PayloadTooLarge,
    /// Too many requests. 429.
    RateLimited,
    Unknown(UnknownCode),
}

impl ErrorCode {
    const KNOWN: [(&'static str, ErrorCode); 23] = [
        ("proxy_unknown", ErrorCode::ProxyUnknown),
        ("conflict", ErrorCode::Conflict),
        ("sequence_conflict", ErrorCode::SequenceConflict),
        ("registry_conflict", ErrorCode::RegistryConflict),
        (
            "invocation_owner_conflict",
            ErrorCode::InvocationOwnerConflict,
        ),
        ("revision_conflict", ErrorCode::RevisionConflict),
        ("disabled", ErrorCode::Disabled),
        ("retired", ErrorCode::Retired),
        ("metadata_ref_pending", ErrorCode::MetadataRefPending),
        ("semantic_invalid", ErrorCode::SemanticInvalid),
        ("schema_invalid", ErrorCode::SchemaInvalid),
        ("invalid_status", ErrorCode::InvalidStatus),
        ("invalid_cursor", ErrorCode::InvalidCursor),
        ("invalid_filter", ErrorCode::InvalidFilter),
        ("unauthorized", ErrorCode::Unauthorized),
        ("forbidden", ErrorCode::Forbidden),
        ("already_exists", ErrorCode::AlreadyExists),
        ("invalid_state", ErrorCode::InvalidState),
        ("config_unavailable", ErrorCode::ConfigUnavailable),
        ("storage_limit", ErrorCode::StorageLimit),
        ("storage_unavailable", ErrorCode::StorageUnavailable),
        ("payload_too_large", ErrorCode::PayloadTooLarge),
        ("rate_limited", ErrorCode::RateLimited),
    ];

    pub fn as_str(&self) -> &str {
        match self {
            ErrorCode::Unknown(u) => u.as_str(),
            known => Self::KNOWN
                .iter()
                .find(|(_, c)| c == known)
                .map(|(s, _)| *s)
                .unwrap_or_default(),
        }
    }

    /// Known codes map to their variant (so `"conflict"` is always `Conflict`);
    /// everything else becomes a sanitised [`UnknownCode`].
    pub fn parse(text: &str) -> Self {
        Self::KNOWN
            .iter()
            .find(|(s, _)| *s == text)
            .map(|(_, c)| c.clone())
            .unwrap_or_else(|| ErrorCode::Unknown(UnknownCode::from_text(text)))
    }

    pub fn is_known(&self) -> bool {
        !matches!(self, ErrorCode::Unknown(_))
    }

    /// HTTP status of the README table, `None` where it is open (`disabled`,
    /// `retired`) or the code is not an HTTP-level code of its own.
    pub fn http_status(&self) -> Option<u16> {
        match self {
            ErrorCode::ProxyUnknown | ErrorCode::ConfigUnavailable => Some(404),
            ErrorCode::Conflict
            | ErrorCode::SequenceConflict
            | ErrorCode::RegistryConflict
            | ErrorCode::InvocationOwnerConflict
            | ErrorCode::RevisionConflict
            | ErrorCode::AlreadyExists
            | ErrorCode::InvalidState => Some(409),
            ErrorCode::Unauthorized => Some(401),
            ErrorCode::StorageLimit | ErrorCode::StorageUnavailable => Some(503),
            ErrorCode::PayloadTooLarge => Some(413),
            ErrorCode::RateLimited => Some(429),
            ErrorCode::Forbidden => Some(403),
            ErrorCode::MetadataRefPending => Some(424),
            ErrorCode::SemanticInvalid
            | ErrorCode::SchemaInvalid
            | ErrorCode::InvalidStatus
            | ErrorCode::InvalidCursor
            | ErrorCode::InvalidFilter => Some(422),
            ErrorCode::Disabled | ErrorCode::Retired | ErrorCode::Unknown(_) => None,
        }
    }

    /// Fixed safe message for this code. The README leaves the wording [OPEN];
    /// these texts are provisional and never contain request data.
    pub fn fixed_message(&self) -> &'static str {
        match self {
            ErrorCode::ProxyUnknown => "Proxy not found.",
            ErrorCode::Conflict => "Event conflicts with a stored event.",
            ErrorCode::SequenceConflict => "Sequence already used by another event.",
            ErrorCode::RegistryConflict => "Registry entry conflicts with a stored entry.",
            ErrorCode::InvocationOwnerConflict => "Invocation belongs to another proxy.",
            ErrorCode::RevisionConflict => "Revision does not match.",
            ErrorCode::Disabled => "Proxy is disabled.",
            ErrorCode::Retired => "Proxy is retired.",
            ErrorCode::MetadataRefPending => "Metadata reference is not registered yet.",
            ErrorCode::SemanticInvalid => "Request is semantically invalid.",
            ErrorCode::SchemaInvalid => "Request does not match the schema.",
            ErrorCode::InvalidStatus => "Status report is invalid.",
            ErrorCode::InvalidCursor => "Cursor is invalid.",
            ErrorCode::InvalidFilter => "Filter is invalid.",
            ErrorCode::Unauthorized => "Missing or invalid credential.",
            ErrorCode::Forbidden => "Credential scope is insufficient.",
            ErrorCode::AlreadyExists => "Already registered.",
            ErrorCode::InvalidState => "Not allowed in the current state.",
            ErrorCode::ConfigUnavailable => "No configuration has been issued.",
            ErrorCode::StorageLimit => "Storage limit reached.",
            ErrorCode::StorageUnavailable => "Storage is unavailable.",
            ErrorCode::PayloadTooLarge => "Request body is too large.",
            ErrorCode::RateLimited => "Too many requests.",
            ErrorCode::Unknown(_) => "Request failed.",
        }
    }
}

impl Serialize for ErrorCode {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ErrorCode {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::parse(&String::deserialize(d)?))
    }
}

wire_struct! {
    lenient
    /// Item of a batch error. 422 items carry `index` only; 409/424 carry the
    /// validated `event_id`; status gap conflicts carry `gap_id`. At most one of
    /// `event_id` and `gap_id` may be present.
    pub struct ErrorItem {
        pub index: u32,
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub event_id: Option<Uuid>,
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub gap_id: Option<Uuid>,
        pub code: ErrorCode,
    }
}

impl Validate for ErrorItem {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.event_id.is_some() && self.gap_id.is_some() {
            return Err(ValidationError::new(
                "an error item carries at most one of event_id and gap_id",
            ));
        }
        Ok(())
    }
}

wire_struct! {
    lenient
    /// Body of the `error` member. `message` is a fixed safe text; build it with
    /// [`ApiError::from_code`] rather than by hand.
    pub struct ErrorBody {
        pub code: ErrorCode,
        pub message: String,
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub items: Option<Vec<ErrorItem>>,
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub pending_metadata_refs: Option<Vec<MetadataRef>>,
    }
}

wire_struct! {
    lenient
    /// `{error:{...}}`
    pub struct ApiError {
        pub error: ErrorBody,
    }
}

impl Validate for ErrorBody {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.pending_metadata_refs.is_some() && self.code != ErrorCode::MetadataRefPending {
            return Err(ValidationError::new(
                "pending_metadata_refs requires code metadata_ref_pending",
            ));
        }
        for item in self.items.iter().flatten() {
            item.validate()?;
        }
        Ok(())
    }
}

impl Validate for ApiError {
    fn validate(&self) -> Result<(), ValidationError> {
        self.error.validate()
    }
}

impl ApiError {
    /// Error with the fixed message of `code`; callers cannot inject a message.
    pub fn from_code(code: ErrorCode) -> Self {
        Self {
            error: ErrorBody {
                message: code.fixed_message().to_owned(),
                code,
                items: None,
                pending_metadata_refs: None,
            },
        }
    }

    pub fn with_items(mut self, items: Vec<ErrorItem>) -> Self {
        self.error.items = Some(items);
        self
    }

    pub fn with_pending_metadata_refs(mut self, refs: Vec<MetadataRef>) -> Self {
        self.error.pending_metadata_refs = Some(refs);
        self
    }
}
