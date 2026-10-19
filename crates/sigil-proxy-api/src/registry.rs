//! Registry entry, read view and upload bodies (`registry-entry.schema.json`).
//!
//! Also models the inventory report (`$defs/inventory_report`, registry.md R7).

use serde::{Deserialize, Serialize};

use crate::error::ValidationError;
use crate::helpers::{check_array, check_len};
use crate::scalar::{
    Fingerprint, Id, KeyId, MetadataRef, NonNegativeI64, SchemaVersion, Timestamp, Uuid,
};
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

// ---------------------------------------------------------------- inventory report

wire_struct! {
    /// Scope key without `proxy_id` (the proxy is the authenticated sender).
    pub struct InventoryScope {
        pub upstream_id: Id,
        pub credential_scope_id: Id,
        pub protocol_version: RegistryProtocolVersion,
        pub observation_source: ObservationSource,
    }
}
no_rules!(InventoryScope);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Completeness {
    Complete,
    Incomplete,
}

/// Why a listing chain is incomplete (closed enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncompleteReason {
    PageLimitExceeded,
    ToolLimitExceeded,
    SizeLimitExceeded,
    PageError,
    CursorInvalid,
    AccessDenied,
    SessionEnded,
    CanonicalizationFailed,
    AmbiguousName,
}

/// One difference between two snapshots. Refs only; names never appear.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "change", rename_all = "snake_case", deny_unknown_fields)]
pub enum Change {
    Added {
        metadata_ref: MetadataRef,
    },
    Removed {
        metadata_ref: MetadataRef,
    },
    /// Pairs the new ref with the old ref the proxy matched by its local identity.
    Changed {
        metadata_ref: MetadataRef,
        previous_metadata_ref: MetadataRef,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefinitionComparison {
    Identical,
    Different,
    NotComparable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebaselineReason {
    KeyRotation,
    CanonVersionChange,
}

wire_struct! {
    /// Producer-asserted pairing of the same tool across a key or canon change.
    pub struct Link {
        pub from_metadata_ref: MetadataRef,
        pub to_metadata_ref: MetadataRef,
        pub definition_comparison: DefinitionComparison,
    }
}
no_rules!(Link);

/// How a complete report relates to the previous snapshot (`oneOf` on `kind`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Comparison {
    /// Struct variant (not unit) so that `deny_unknown_fields` applies.
    InitialBaseline {},
    /// `changes` has at most 20,000 items.
    Compared {
        previous_inventory_id: Uuid,
        changes: Vec<Change>,
    },
    /// `links` has at most 10,000 items.
    Rebaseline {
        previous_inventory_id: Uuid,
        reason: RebaselineReason,
        links: Vec<Link>,
    },
}

/// Largest `members` array.
pub const MAX_INVENTORY_MEMBERS: usize = 10_000;
/// Largest `comparison.changes` array.
pub const MAX_INVENTORY_CHANGES: usize = 20_000;
/// Largest `comparison.links` array.
pub const MAX_INVENTORY_LINKS: usize = 10_000;

wire_struct! {
    /// Body of `POST /v1/proxy-inventory`: one observation of a `tools/list` chain.
    ///
    /// Conditional fields follow `completeness`: `complete` requires `inventory_id`,
    /// `members` and `comparison` and forbids `incomplete_reason`; `incomplete`
    /// requires `incomplete_reason` and forbids the other three. [`Validate`]
    /// enforces this, so a hand-built value must be validated before sending.
    pub struct InventoryReport {
        pub schema_version: SchemaVersion,
        pub report_id: Uuid,
        pub proxy_id: Id,
        pub epoch_id: Uuid,
        pub observed_at: Timestamp,
        pub scope: InventoryScope,
        pub canon: Canon,
        pub key_id: KeyId,
        pub completeness: Completeness,
        pub pages_observed: NonNegativeI64,
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub incomplete_reason: Option<IncompleteReason>,
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub inventory_id: Option<Uuid>,
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub members: Option<Vec<MetadataRef>>,
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub comparison: Option<Comparison>,
    }
}

impl Validate for InventoryReport {
    fn validate(&self) -> Result<(), ValidationError> {
        match self.completeness {
            Completeness::Complete => {
                if self.incomplete_reason.is_some() {
                    return Err(ValidationError::new(
                        "a complete report must not carry incomplete_reason",
                    ));
                }
                let (Some(_), Some(members), Some(comparison)) =
                    (&self.inventory_id, &self.members, &self.comparison)
                else {
                    return Err(ValidationError::new(
                        "a complete report requires inventory_id, members and comparison",
                    ));
                };
                check_array("members", members, 0, MAX_INVENTORY_MEMBERS, true)?;
                match comparison {
                    Comparison::InitialBaseline {} => {}
                    Comparison::Compared { changes, .. } => {
                        check_len("changes", changes.len(), 0, MAX_INVENTORY_CHANGES)?;
                    }
                    Comparison::Rebaseline { links, .. } => {
                        check_len("links", links.len(), 0, MAX_INVENTORY_LINKS)?;
                    }
                }
            }
            Completeness::Incomplete => {
                if self.incomplete_reason.is_none() {
                    return Err(ValidationError::new(
                        "an incomplete report requires incomplete_reason",
                    ));
                }
                if self.inventory_id.is_some()
                    || self.members.is_some()
                    || self.comparison.is_some()
                {
                    return Err(ValidationError::new(
                        "an incomplete report must not carry inventory_id, members or comparison",
                    ));
                }
            }
        }
        Ok(())
    }
}
