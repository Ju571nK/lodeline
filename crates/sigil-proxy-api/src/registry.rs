//! Registry entry, read view and upload bodies (`registry-entry.schema.json`).
//!
//! The inventory report (`$defs/inventory_report`) is not modelled here yet.

use serde::{Deserialize, Serialize};

use crate::error::ValidationError;
use crate::helpers::{check_array, check_len};
use crate::scalar::{Fingerprint, Id, KeyId, MetadataRef, SchemaVersion, Timestamp};
use crate::Validate;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Canon {
    #[serde(rename = "sigil-tooldef-fp-v1")]
    SigilTooldefFpV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryProtocolVersion {
    #[serde(rename = "2025-11-25")]
    V2025_11_25,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationSource {
    ProxyLive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentState {
    Present,
    Deleted,
}

wire_struct! {
    /// Upload form (also the schema document root). Untrusted `definition` content
    /// belongs in the access-controlled metadata store only.
    pub struct RegistryEntry {
        pub proxy_id: Id,
        pub metadata_ref: MetadataRef,
        pub upstream_id: Id,
        pub credential_scope_id: Id,
        pub protocol_version: RegistryProtocolVersion,
        pub observation_source: ObservationSource,
        pub canon: Canon,
        pub key_id: KeyId,
        pub fingerprint: Fingerprint,
        pub observed_at: Timestamp,
        /// Complete tool object as observed; a non-empty JSON object.
        pub definition: serde_json::Value,
    }
}

impl Validate for RegistryEntry {
    fn validate(&self) -> Result<(), ValidationError> {
        match self.definition.as_object() {
            Some(m) if !m.is_empty() => Ok(()),
            _ => Err(ValidationError::new(
                "definition must be a non-empty object",
            )),
        }
    }
}

impl RegistryEntry {
    /// Equality over the immutable fields only (`x-immutable-fields`). `observed_at`
    /// and `definition` are volatile; content is bound through the keyed fingerprint.
    pub fn immutable_eq(&self, other: &Self) -> bool {
        self.proxy_id == other.proxy_id
            && self.metadata_ref == other.metadata_ref
            && self.upstream_id == other.upstream_id
            && self.credential_scope_id == other.credential_scope_id
            && self.protocol_version == other.protocol_version
            && self.observation_source == other.observation_source
            && self.canon == other.canon
            && self.key_id == other.key_id
            && self.fingerprint == other.fingerprint
    }
}

wire_struct! {
    /// Ordinary read view: no definition, no name, no keyed fingerprint.
    pub struct EntryView {
        pub proxy_id: Id,
        pub metadata_ref: MetadataRef,
        pub upstream_id: Id,
        pub credential_scope_id: Id,
        pub protocol_version: RegistryProtocolVersion,
        pub observation_source: ObservationSource,
        pub canon: Canon,
        pub key_id: KeyId,
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub first_observed_at: Option<Timestamp>,
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub last_observed_at: Option<Timestamp>,
        pub registered_at: Timestamp,
        pub content_state: ContentState,
    }
}
no_rules!(EntryView);

wire_struct! {
    /// Body of `POST /v1/proxy-metadata` (1..=100 entries).
    pub struct UploadRequest {
        pub schema_version: SchemaVersion,
        pub proxy_id: Id,
        pub entries: Vec<RegistryEntry>,
    }
}

impl Validate for UploadRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        check_len("entries", self.entries.len(), 1, 100)?;
        self.entries.iter().try_for_each(Validate::validate)
    }
}

wire_struct! {
    lenient
    /// Read by the proxy: unknown fields are ignored when parsing.
    pub struct UploadResponse {
        pub registered_metadata_refs: Vec<MetadataRef>,
        pub duplicate_metadata_refs: Vec<MetadataRef>,
    }
}

impl Validate for UploadResponse {
    fn validate(&self) -> Result<(), ValidationError> {
        check_array(
            "registered_metadata_refs",
            &self.registered_metadata_refs,
            0,
            100,
            true,
        )?;
        check_array(
            "duplicate_metadata_refs",
            &self.duplicate_metadata_refs,
            0,
            100,
            true,
        )
    }
}
