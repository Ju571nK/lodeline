//! Error object `{error:{code,message,items?,pending_metadata_refs?}}` and codes.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::scalar::{MetadataRef, Uuid};

/// A contract rule was violated. The message never contains the offending value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError(String);

impl ValidationError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ValidationError {}

/// Fixed error codes of the contracts README error table.
///
/// The contracts do not say how a reader treats a code it does not know, so
/// unknown codes are preserved as [`ErrorCode::Unknown`] instead of failing the
/// whole response. Callers must treat `Unknown` as a generic failure of the HTTP
/// status class and must not echo the string into logs unsanitised.
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
    SchemaInvalid,
    InvalidStatus,
    InvalidCursor,
    InvalidFilter,
    Unknown(String),
}

impl ErrorCode {
    const KNOWN: [(&'static str, ErrorCode); 14] = [
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
    ];

    pub fn as_str(&self) -> &str {
        match self {
            ErrorCode::Unknown(s) => s,
            known => Self::KNOWN
                .iter()
                .find(|(_, c)| c == known)
                .map(|(s, _)| *s)
                .unwrap_or_default(),
        }
    }

    pub fn parse(text: &str) -> Self {
        Self::KNOWN
            .iter()
            .find(|(s, _)| *s == text)
            .map(|(_, c)| c.clone())
            .unwrap_or_else(|| ErrorCode::Unknown(text.to_owned()))
    }

    pub fn is_known(&self) -> bool {
        !matches!(self, ErrorCode::Unknown(_))
    }

    /// HTTP status of the README table, `None` where it is open (`disabled`,
    /// `retired`) or the code is not an HTTP-level code of its own.
    pub fn http_status(&self) -> Option<u16> {
        match self {
            ErrorCode::ProxyUnknown => Some(404),
            ErrorCode::Conflict
            | ErrorCode::SequenceConflict
            | ErrorCode::RegistryConflict
            | ErrorCode::InvocationOwnerConflict
            | ErrorCode::RevisionConflict => Some(409),
            ErrorCode::MetadataRefPending => Some(424),
            ErrorCode::SemanticInvalid
            | ErrorCode::SchemaInvalid
            | ErrorCode::InvalidStatus
            | ErrorCode::InvalidCursor
            | ErrorCode::InvalidFilter => Some(422),
            ErrorCode::Disabled | ErrorCode::Retired | ErrorCode::Unknown(_) => None,
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
    /// Item of a batch error. 422 items carry `index` only; 409/424 carry the
    /// validated `event_id`; status gap conflicts carry `gap_id`.
    pub struct ErrorItem {
        pub index: u32,
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub event_id: Option<Uuid>,
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub gap_id: Option<Uuid>,
        pub code: ErrorCode,
    }
}

wire_struct! {
    /// Body of the `error` member. `message` is a fixed safe text.
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
    /// `{error:{...}}`
    pub struct ApiError {
        pub error: ErrorBody,
    }
}

no_rules!(ErrorItem, ApiError);

impl crate::Validate for ErrorBody {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.pending_metadata_refs.is_some() && self.code != ErrorCode::MetadataRefPending {
            return Err(ValidationError::new(
                "pending_metadata_refs requires code metadata_ref_pending",
            ));
        }
        Ok(())
    }
}
