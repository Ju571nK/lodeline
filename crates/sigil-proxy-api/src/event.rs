//! Proxy event envelope and payload variants (`proxy-event.schema.json`).

use serde::de::Error as _;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::ValidationError;
use crate::helpers::{check_len, ObjectOnly};
use crate::scalar::{Id, MetadataRef, NonNegativeI64, PositiveI64, SchemaVersion, Timestamp, Uuid};
use crate::Validate;

/// Closed audit vocabulary of `invocation.started.protocol_version`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolVersion {
    #[serde(rename = "2025-11-25")]
    V2025_11_25,
    #[serde(rename = "unknown")]
    Unknown,
}

/// Exact parser-recognised audit constants; everything else is `unknown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Method {
    #[serde(rename = "initialize")]
    Initialize,
    #[serde(rename = "ping")]
    Ping,
    #[serde(rename = "tools/list")]
    ToolsList,
    #[serde(rename = "tools/call")]
    ToolsCall,
    #[serde(rename = "unknown")]
    Unknown,
}

/// `human` is not representable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    NonHuman,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationMethod {
    Bearer,
    Mtls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    ProxyCredentialMapping,
}

wire_struct! {
    /// Every field comes from the server-issued credential mapping, never from client input.
    pub struct Actor {
        pub actor_id: Id,
        pub actor_kind: ActorKind,
        pub authentication_method: AuthenticationMethod,
        pub evidence_source: EvidenceSource,
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub credential_owner_id: Option<Id>,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataUnavailableReason {
    NotInInventory,
    NoCompleteInventory,
    AmbiguousInInventory,
    RegistryConflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnavailableReason {
    Malformed,
}

wire_struct! {
    pub struct ToolIdentified {
        pub metadata_ref: MetadataRef,
    }
}
wire_struct! {
    pub struct ToolMetadataUnavailable {
        pub reason: MetadataUnavailableReason,
    }
}
wire_struct! {
    pub struct ToolUnavailable {
        pub reason: UnavailableReason,
    }
}
no_rules!(
    Actor,
    ToolIdentified,
    ToolMetadataUnavailable,
    ToolUnavailable
);

/// Tool identity of a `tools/call` start. Never a raw tool name.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Tool {
    Identified(ToolIdentified),
    MetadataUnavailable(ToolMetadataUnavailable),
    Unavailable(ToolUnavailable),
}

wire_struct! {
    pub struct InvocationStarted {
        pub invocation_id: Uuid,
        pub upstream_id: Id,
        pub route_revision: PositiveI64,
        pub protocol_version: ProtocolVersion,
        pub method: Method,
        pub actor: Actor,
        /// Present exactly when `method` is `tools/call`.
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub tool: Option<Tool>,
    }
}

impl Validate for InvocationStarted {
    fn validate(&self) -> Result<(), ValidationError> {
        match (self.method, &self.tool) {
            (Method::ToolsCall, None) => {
                return Err(ValidationError::new("tools/call start requires tool"))
            }
            (m, Some(_)) if m != Method::ToolsCall => {
                return Err(ValidationError::new("tool is only allowed on tools/call"))
            }
            _ => {}
        }
        if self.method == Method::Initialize && self.protocol_version != ProtocolVersion::Unknown {
            return Err(ValidationError::new(
                "initialize start must carry protocol_version unknown",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    ToolError,
    ProtocolError,
    Timeout,
    Unknown,
    Denied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryState {
    NotSent,
    Sent,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletionReason {
    TaskAugmentationUnsupported,
    UpstreamCapabilityUnsupported,
    UpstreamVersionUnsupported,
    UpstreamInitializeUnreadable,
    ModernRequestUnsupported,
    CancelNoResponse,
    CancelledBeforeDispatch,
}

wire_struct! {
    pub struct InvocationCompleted {
        pub invocation_id: Uuid,
        pub outcome: Outcome,
        pub delivery_state: DeliveryState,
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub reason: Option<CompletionReason>,
        pub duration_ms: NonNegativeI64,
        pub response_bytes: NonNegativeI64,
    }
}

impl Validate for InvocationCompleted {
    /// The outcome/delivery/reason matrix of the schema (`allOf`).
    fn validate(&self) -> Result<(), ValidationError> {
        use CompletionReason as R;
        use DeliveryState as D;
        use Outcome as O;
        let (o, d) = (self.outcome, self.delivery_state);
        let ok_base = match o {
            O::Success | O::ToolError => d == D::Sent,
            O::Denied => d == D::NotSent,
            _ => true,
        };
        let ok_reason = match self.reason {
            None => true,
            Some(R::TaskAugmentationUnsupported) => o == O::ProtocolError && d != D::Unknown,
            Some(R::UpstreamCapabilityUnsupported)
            | Some(R::UpstreamVersionUnsupported)
            | Some(R::UpstreamInitializeUnreadable) => o == O::ProtocolError && d == D::Sent,
            Some(R::ModernRequestUnsupported) => o == O::ProtocolError && d == D::NotSent,
            Some(R::CancelNoResponse) => o == O::Unknown && d != D::NotSent,
            Some(R::CancelledBeforeDispatch) => o == O::Unknown && d == D::NotSent,
        };
        if ok_base && ok_reason {
            Ok(())
        } else {
            Err(ValidationError::new(
                "outcome, delivery_state and reason are inconsistent",
            ))
        }
    }
}

wire_struct! {
    /// Nonterminal observation only.
    pub struct InvocationCancelRequested {
        pub invocation_id: Uuid,
    }
}
no_rules!(InvocationCancelRequested);

/// `event_type` discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    #[serde(rename = "invocation.started")]
    InvocationStarted,
    #[serde(rename = "invocation.completed")]
    InvocationCompleted,
    #[serde(rename = "invocation.cancel_requested")]
    InvocationCancelRequested,
}

/// Payload variants, selected by `event_type`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum EventPayload {
    Started(InvocationStarted),
    Completed(InvocationCompleted),
    CancelRequested(InvocationCancelRequested),
}

impl EventPayload {
    pub fn event_type(&self) -> EventType {
        match self {
            EventPayload::Started(_) => EventType::InvocationStarted,
            EventPayload::Completed(_) => EventType::InvocationCompleted,
            EventPayload::CancelRequested(_) => EventType::InvocationCancelRequested,
        }
    }

    pub fn invocation_id(&self) -> &Uuid {
        match self {
            EventPayload::Started(p) => &p.invocation_id,
            EventPayload::Completed(p) => &p.invocation_id,
            EventPayload::CancelRequested(p) => &p.invocation_id,
        }
    }
}

impl Validate for EventPayload {
    fn validate(&self) -> Result<(), ValidationError> {
        match self {
            EventPayload::Started(p) => p.validate(),
            EventPayload::Completed(p) => p.validate(),
            EventPayload::CancelRequested(p) => p.validate(),
        }
    }
}

/// The event envelope. `event_type` is derived from `payload`.
#[derive(Debug, Clone, PartialEq)]
pub struct ProxyEvent {
    pub schema_version: SchemaVersion,
    pub event_id: Uuid,
    pub proxy_id: Id,
    pub epoch_id: Uuid,
    pub sequence: PositiveI64,
    pub occurred_at: Timestamp,
    pub payload: EventPayload,
}

impl Validate for ProxyEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        self.payload.validate()
    }
}

impl Serialize for ProxyEvent {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("ProxyEvent", 8)?;
        st.serialize_field("schema_version", &self.schema_version)?;
        st.serialize_field("event_id", &self.event_id)?;
        st.serialize_field("proxy_id", &self.proxy_id)?;
        st.serialize_field("epoch_id", &self.epoch_id)?;
        st.serialize_field("sequence", &self.sequence)?;
        st.serialize_field("occurred_at", &self.occurred_at)?;
        st.serialize_field("event_type", &self.payload.event_type())?;
        st.serialize_field("payload", &self.payload)?;
        st.end()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEvent {
    schema_version: SchemaVersion,
    event_id: Uuid,
    proxy_id: Id,
    epoch_id: Uuid,
    sequence: PositiveI64,
    occurred_at: Timestamp,
    event_type: EventType,
    payload: serde_json::Value,
}

impl<'de> Deserialize<'de> for ProxyEvent {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let w = ObjectOnly::<WireEvent>::deserialize(d)?.0;
        let payload = match w.event_type {
            EventType::InvocationStarted => {
                EventPayload::Started(payload_from(w.payload).map_err(D::Error::custom)?)
            }
            EventType::InvocationCompleted => {
                EventPayload::Completed(payload_from(w.payload).map_err(D::Error::custom)?)
            }
            EventType::InvocationCancelRequested => {
                EventPayload::CancelRequested(payload_from(w.payload).map_err(D::Error::custom)?)
            }
        };
        Ok(ProxyEvent {
            schema_version: w.schema_version,
            event_id: w.event_id,
            proxy_id: w.proxy_id,
            epoch_id: w.epoch_id,
            sequence: w.sequence,
            occurred_at: w.occurred_at,
            payload,
        })
    }
}

fn payload_from<T: serde::de::DeserializeOwned>(
    v: serde_json::Value,
) -> Result<T, serde_json::Error> {
    T::deserialize(v)
}

wire_struct! {
    /// Request body of `POST /v1/proxy-events` (1..=100 events).
    ///
    /// The body shape is not fixed by a schema file; `{events:[...]}` follows the
    /// README wording ("events 배열, 최대 100개").
    pub struct IngestRequest {
        pub events: Vec<ProxyEvent>,
    }
}

impl Validate for IngestRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        check_len("events", self.events.len(), 1, 100)?;
        self.events.iter().try_for_each(Validate::validate)
    }
}

wire_struct! {
    lenient
    /// 200 body of `POST /v1/proxy-events`. Read by the proxy: unknown fields are
    /// ignored when parsing.
    pub struct IngestResponse {
        pub accepted_event_ids: Vec<Uuid>,
        pub duplicate_event_ids: Vec<Uuid>,
    }
}
no_rules!(IngestResponse);
