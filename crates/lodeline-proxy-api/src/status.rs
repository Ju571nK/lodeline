//! Proxy status report and gap reports (`proxy-status.schema.json`).

use serde::{Deserialize, Serialize};

use crate::error::ValidationError;
use crate::helpers::check_array;
use crate::scalar::{
    ConfigHash, Id, KeyId, MetadataRef, NonNegativeI64, PositiveI64, SchemaVersion, Timestamp, Uuid,
};
use crate::Validate;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigState {
    None,
    Valid,
    Expired,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LastUpdateError {
    StaleRevision,
    ValidationFailed,
    FetchFailed,
    ApplyFailed,
    ConfigHashMismatch,
}

wire_struct! {
    pub struct ConfigStatus {
        pub state: ConfigState,
        #[serde(deserialize_with = "crate::helpers::nullable")]
        pub applied_revision: Option<PositiveI64>,
        #[serde(deserialize_with = "crate::helpers::nullable")]
        pub observed_desired_revision: Option<PositiveI64>,
        #[serde(deserialize_with = "crate::helpers::nullable")]
        pub expires_at: Option<Timestamp>,
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub last_update_error: Option<LastUpdateError>,
        /// 3600..=7776000; required when `state` is `valid`.
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub max_offline_retry_age_seconds: Option<i64>,
        /// 3600..=31536000; required when `state` is `valid`.
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub event_retention_seconds: Option<i64>,
        /// Required when `state` is `valid` or `disabled`.
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub config_hash: Option<ConfigHash>,
    }
}

impl Validate for ConfigStatus {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.state == ConfigState::Valid
            && (self.max_offline_retry_age_seconds.is_none()
                || self.event_retention_seconds.is_none())
        {
            return Err(ValidationError::new(
                "valid config requires max_offline_retry_age_seconds and event_retention_seconds",
            ));
        }
        if matches!(self.state, ConfigState::Valid | ConfigState::Disabled)
            && self.config_hash.is_none()
        {
            return Err(ValidationError::new(
                "valid or disabled config requires config_hash",
            ));
        }
        if let Some(r) = self.max_offline_retry_age_seconds {
            if !(3600..=7_776_000).contains(&r) {
                return Err(ValidationError::new(
                    "max_offline_retry_age_seconds out of range",
                ));
            }
        }
        if let Some(e) = self.event_retention_seconds {
            if !(3600..=31_536_000).contains(&e) {
                return Err(ValidationError::new("event_retention_seconds out of range"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpoolState {
    Ok,
    Degraded,
    Full,
}

wire_struct! {
    pub struct SpoolStatus {
        pub state: SpoolState,
        pub depth_events: NonNegativeI64,
        pub unsent_events: NonNegativeI64,
        pub bytes: NonNegativeI64,
        pub capacity_bytes: PositiveI64,
        #[serde(deserialize_with = "crate::helpers::nullable")]
        pub oldest_unsent_age_seconds: Option<NonNegativeI64>,
        pub quarantined_events: NonNegativeI64,
        /// Bytes held in local quarantine. Optional: proxies that predate it omit
        /// the field.
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub quarantined_bytes: Option<NonNegativeI64>,
    }
}

wire_struct! {
    pub struct RegistryStatus {
        pub pending_entries: NonNegativeI64,
        pub sync_stalled: bool,
        /// Entries quarantined after a registry conflict (central 409 or the local
        /// hash check). Optional: proxies that predate it omit the field.
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub quarantined_entries: Option<NonNegativeI64>,
        /// Entries currently paused after a non-retryable refusal (repeated 422,
        /// or too large alone); re-armed periodically and on restart. Optional
        /// like `quarantined_entries`.
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub poisoned_entries: Option<NonNegativeI64>,
        /// Inventory reports the proxy gave up on since it started. Optional like
        /// `quarantined_entries`.
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub discarded_reports: Option<NonNegativeI64>,
    }
}

wire_struct! {
    pub struct CentralStatus {
        #[serde(deserialize_with = "crate::helpers::nullable")]
        pub last_ingest_ack_at: Option<Timestamp>,
        pub consecutive_failures: NonNegativeI64,
        /// The server keeps refusing events and the proxy passed its quarantine
        /// limit (ledger-and-query.md L5). Cleared by the next accepted batch.
        /// Sent only when true. Absent reads as false: a proxy that is not
        /// stopped omits it, and so does one that predates it.
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub ingest_stopped: Option<bool>,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteState {
    Supported,
    Degraded,
    Unsupported,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteReason {
    UpstreamCapabilityUnsupported,
    UpstreamVersionUnsupported,
    UpstreamInitializeUnreadable,
    TaskAugmentationUnsupported,
    HealthCheckFailed,
}

wire_struct! {
    pub struct RouteStatus {
        pub upstream_id: Id,
        pub state: RouteState,
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub reason: Option<RouteReason>,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthFailureReason {
    CredentialMissing,
    CredentialInvalid,
    CredentialExpiredOrRevoked,
    OriginRejected,
    SessionPrincipalMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnmatchedCancelReason {
    NoMatchingRequest,
    WindowExpired,
    SessionMismatch,
}

wire_struct! {
    pub struct AuthFailureCounter {
        #[serde(deserialize_with = "crate::helpers::nullable")]
        pub upstream_id: Option<Id>,
        pub reason: AuthFailureReason,
        pub count: NonNegativeI64,
    }
}

wire_struct! {
    pub struct UnmatchedCancelCounter {
        #[serde(deserialize_with = "crate::helpers::nullable")]
        pub upstream_id: Option<Id>,
        pub reason: UnmatchedCancelReason,
        pub count: NonNegativeI64,
    }
}

wire_struct! {
    /// Cumulative since epoch start. Identifiers, fixed codes and counts only.
    pub struct Counters {
        pub auth_failures: Vec<AuthFailureCounter>,
        pub unmatched_cancels: Vec<UnmatchedCancelCounter>,
    }
}

impl Validate for Counters {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.auth_failures.len() > 1536 || self.unmatched_cancels.len() > 1536 {
            return Err(ValidationError::limit(
                "too many counter entries (max 1536)",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictDetector {
    #[serde(rename = "central_409")]
    Central409,
    LocalHashCheck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineCode {
    Conflict,
    SequenceConflict,
    SemanticInvalid,
}

wire_struct! {
    pub struct RegistryConflictGap {
        pub gap_id: Uuid,
        pub detected_at: Timestamp,
        pub metadata_ref: MetadataRef,
        pub key_id: KeyId,
        pub event_ids: Vec<Uuid>,
        pub detected_by: ConflictDetector,
        /// Same value in every chunk when more than 100 ids are split over several gaps.
        pub affected_event_count: PositiveI64,
    }
}

wire_struct! {
    pub struct EventQuarantinedGap {
        pub gap_id: Uuid,
        pub detected_at: Timestamp,
        pub event_ids: Vec<Uuid>,
        pub code: QuarantineCode,
    }
}

wire_struct! {
    pub struct LocalRecordFailedGap {
        pub gap_id: Uuid,
        pub detected_at: Timestamp,
        pub count: PositiveI64,
        pub invocation_ids: Vec<Uuid>,
    }
}

wire_struct! {
    pub struct SpoolExpiredGap {
        pub gap_id: Uuid,
        pub detected_at: Timestamp,
        pub epoch_id: Uuid,
        pub from_sequence: PositiveI64,
        pub to_sequence: PositiveI64,
        pub count: PositiveI64,
    }
}

wire_struct! {
    pub struct UnrecordedCallsGap {
        pub gap_id: Uuid,
        pub detected_at: Timestamp,
        pub count: PositiveI64,
        pub from_at: Timestamp,
        pub to_at: Timestamp,
    }
}

wire_struct! {
    pub struct CentralOutageGap {
        pub gap_id: Uuid,
        pub detected_at: Timestamp,
        pub started_at: Timestamp,
        #[serde(deserialize_with = "crate::helpers::nullable")]
        pub ended_at: Option<Timestamp>,
    }
}

impl Validate for RegistryConflictGap {
    fn validate(&self) -> Result<(), ValidationError> {
        check_array("event_ids", &self.event_ids, 1, 100, true)?;
        // The count covers every event depending on the entry, so it cannot be
        // smaller than the ids listed in this chunk.
        if (self.affected_event_count.get() as u64) < self.event_ids.len() as u64 {
            return Err(ValidationError::new(
                "affected_event_count is smaller than the number of event_ids",
            ));
        }
        Ok(())
    }
}
impl Validate for EventQuarantinedGap {
    fn validate(&self) -> Result<(), ValidationError> {
        check_array("event_ids", &self.event_ids, 1, 100, true)
    }
}
impl Validate for LocalRecordFailedGap {
    fn validate(&self) -> Result<(), ValidationError> {
        check_array("invocation_ids", &self.invocation_ids, 0, 100, true)
    }
}
no_rules!(
    SpoolStatus,
    RegistryStatus,
    CentralStatus,
    RouteStatus,
    AuthFailureCounter,
    UnmatchedCancelCounter,
    SpoolExpiredGap,
    UnrecordedCallsGap,
    CentralOutageGap
);

impl Validate for GapReport {
    fn validate(&self) -> Result<(), ValidationError> {
        match self {
            GapReport::RegistryConflict(g) => g.validate(),
            GapReport::EventQuarantined(g) => g.validate(),
            GapReport::LocalRecordFailed(g) => g.validate(),
            GapReport::SpoolExpired(g) => g.validate(),
            GapReport::UnrecordedCalls(g) => g.validate(),
            GapReport::CentralOutage(g) => g.validate(),
        }
    }
}

/// Gap report, discriminated by `kind`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GapReport {
    RegistryConflict(RegistryConflictGap),
    EventQuarantined(EventQuarantinedGap),
    LocalRecordFailed(LocalRecordFailedGap),
    SpoolExpired(SpoolExpiredGap),
    UnrecordedCalls(UnrecordedCallsGap),
    CentralOutage(CentralOutageGap),
}

wire_struct! {
    /// Body of `POST /v1/proxy-status`: a state snapshot plus idempotent gap reports.
    pub struct ProxyStatus {
        pub schema_version: SchemaVersion,
        pub report_id: Uuid,
        pub proxy_id: Id,
        pub epoch_id: Uuid,
        /// Monotonic per epoch; the server keeps the highest.
        pub status_sequence: PositiveI64,
        pub sent_at: Timestamp,
        pub config: ConfigStatus,
        pub spool: SpoolStatus,
        pub registry: RegistryStatus,
        pub central: CentralStatus,
        pub routes: Vec<RouteStatus>,
        pub counters: Counters,
        pub gaps: Vec<GapReport>,
        /// Highest sequence assigned in `epoch_id` (0 if none), for tail-loss detection.
        pub last_assigned_sequence: NonNegativeI64,
    }
}

impl Validate for ProxyStatus {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.routes.len() > 256 {
            return Err(ValidationError::limit("too many routes (max 256)"));
        }
        if self.gaps.len() > 100 {
            return Err(ValidationError::limit("too many gaps (max 100)"));
        }
        self.config.validate()?;
        self.spool.validate()?;
        self.registry.validate()?;
        self.central.validate()?;
        self.counters.validate()?;
        for route in &self.routes {
            route.validate()?;
        }
        for gap in &self.gaps {
            gap.validate()?;
        }
        Ok(())
    }
}

wire_struct! {
    lenient
    /// 200 body of `POST /v1/proxy-status`. Read by the proxy: unknown fields are
    /// ignored when parsing.
    pub struct StatusResponse {
        pub state_applied: bool,
        pub acknowledged_gap_ids: Vec<Uuid>,
        pub duplicate_gap_ids: Vec<Uuid>,
    }
}

impl Validate for StatusResponse {
    fn validate(&self) -> Result<(), ValidationError> {
        check_array(
            "acknowledged_gap_ids",
            &self.acknowledged_gap_ids,
            0,
            100,
            true,
        )?;
        check_array("duplicate_gap_ids", &self.duplicate_gap_ids, 0, 100, true)
    }
}
