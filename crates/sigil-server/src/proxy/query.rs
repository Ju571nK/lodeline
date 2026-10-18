//! T-11 S5 slice C — read-only proxy and invocation query API.
//!
//! Spec: ledger-and-query.md L3 (DTOs, filters, cursor, order), L4 (gaps),
//! L6 (counters); decisions.md "T-11 S5 범위". PX-006/010/016, AC-05/06/12.
//!
//! * `GET /v1/proxies` (filters `connection_state`, `config_in_sync`; order
//!   `proxy_id` asc), `GET /v1/proxies/{id}`, `GET /v1/proxy-invocations`
//!   (order `created_seq` desc), `GET /v1/proxy-invocations/{id}`.
//! * Auth is the existing read model: host-class mTLS certificate plus the read
//!   bearer. Proxy certs, management certs and registry-held fingerprints are
//!   refused with the host-route `host_unknown` answer.
//! * Responses are built from allowlisted DTOs only. No stored event content
//!   (arguments, results, tool names, session ids, tokens) is ever serialized.
//! * Scope: P1 read scope is every registered proxy, decided in exactly one
//!   place ([`read_scope`]) so it can later become per-token. Unknown and
//!   out-of-scope targets are one byte-identical 404 `proxy_unknown`.
//! * Cursors are opaque, bound to endpoint, order and normalised filters.
//!   Malformed or mismatched cursors are 422 `invalid_cursor`; unknown filter
//!   names or bad values are 422 `invalid_filter`; no input value is echoed.

use super::guard::proxy_unknown;
use super::identity::PeerClass;
use super::mgmt::api_error;
use super::projection::{
    InvocationFilter, Lifecycle, Projection, ProxyScope, TimeBasis, ToolInfo, MAX_GAP_PAGE,
};
use super::registry::ProxyRecord;
use super::store::{parse_counter_key, ProxyEntry, StoreSummary};
use super::ProxyContext;
use crate::auth::{require_bearer, ReadToken};
use crate::tls_accept::PeerIdentity;
use axum::body::Body;
use axum::extract::{Path, RawQuery, State};
use axum::http::request::Parts;
use axum::http::{Request, StatusCode};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, MethodRouter};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sigil_proxy_api::status::{
    CentralStatus, ConfigState, GapReport, RegistryStatus, RouteStatus, SpoolState,
};
use sigil_proxy_api::{ErrorCode, Id, MetadataRef, Timestamp, Uuid};
use std::collections::BTreeMap;
use std::sync::Arc;

pub const PROXIES_PATH: &str = "/v1/proxies";
pub const INVOCATIONS_PATH: &str = "/v1/proxy-invocations";

pub const DEFAULT_LIMIT: usize = 100;
pub const MAX_LIMIT: usize = 500;
/// A proxy is `connected` while `now - last_seen <= stale_after` (L3). Three
/// heartbeat intervals; initial test value (D-04). Not yet a config value.
pub const STALE_AFTER_SECS: i64 = 90;
/// `audit_gaps` page and `outages` list sizes (L3).
pub const MAX_OUTAGES: usize = 16;
/// Query-string limits (no value is ever echoed back).
const MAX_QUERY_LEN: usize = 2048;
const MAX_PARAMS: usize = 16;
const MAX_VALUE_LEN: usize = 256;
const MAX_CURSOR_LEN: usize = 512;
/// Longest `ProxyScope::Only` list; keeps the `IN (?, ...)` list far below
/// SQLite's bound-variable limit.
pub const MAX_SCOPE_PROXIES: usize = 500;

// ---- scope ------------------------------------------------------------------

/// The one place that decides which proxies the caller may read (`proxy.read`
/// range). P1: the read bearer sees every proxy. A per-token model replaces
/// this function only.
pub fn read_scope(_ctx: &ProxyContext, ext: &axum::http::Extensions) -> ProxyScope {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(s) = ext.get::<TestScope>() {
        return bounded_scope(s.0.clone());
    }
    let _ = ext;
    ProxyScope::All
}

/// Test hook: a request extension (server side only, never client input)
/// that narrows the read scope to these proxies.
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug)]
pub struct TestScope(pub Vec<String>);

/// A bounded `Only` scope: sorted, de-duplicated, at most
/// [`MAX_SCOPE_PROXIES`] ids (extra ids are dropped, which can only hide
/// proxies, never expose one).
pub fn bounded_scope(ids: impl IntoIterator<Item = String>) -> ProxyScope {
    let mut v: Vec<String> = ids.into_iter().collect();
    v.sort();
    v.dedup();
    if v.len() > MAX_SCOPE_PROXIES {
        tracing::warn!(
            kept = MAX_SCOPE_PROXIES,
            "proxy read scope truncated to the maximum"
        );
        v.truncate(MAX_SCOPE_PROXIES);
    }
    ProxyScope::Only(v)
}

fn visible(scope: &ProxyScope, proxy_id: &str) -> bool {
    match scope {
        ProxyScope::All => true,
        ProxyScope::Only(ids) => ids.iter().any(|i| i == proxy_id),
    }
}

/// Registered proxies the scope can see, ordered by `proxy_id`.
fn scoped_records(ctx: &ProxyContext, scope: &ProxyScope) -> Vec<ProxyRecord> {
    ctx.registry
        .list()
        .into_iter()
        .filter(|r| visible(scope, &r.proxy_id))
        .collect()
}

// ---- errors -----------------------------------------------------------------

enum QErr {
    Filter,
    Cursor,
    Storage,
}

impl From<super::ledger::LedgerError> for QErr {
    fn from(_: super::ledger::LedgerError) -> Self {
        // QueryTimeout and StorageUnavailable (and anything else a read can
        // raise) are the same transient 503.
        QErr::Storage
    }
}

impl IntoResponse for QErr {
    fn into_response(self) -> Response {
        api_error(match self {
            QErr::Filter => ErrorCode::InvalidFilter,
            QErr::Cursor => ErrorCode::InvalidCursor,
            QErr::Storage => ErrorCode::StorageUnavailable,
        })
    }
}

// ---- query parameters -------------------------------------------------------

fn pct_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let h = b.get(i + 1..i + 3)?;
                let h = std::str::from_utf8(h).ok()?;
                out.push(u8::from_str_radix(h, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// Parsed `name=value` pairs. Unknown or repeated names, empty values and
/// over-long input are `invalid_filter`.
fn parse_params(raw: Option<&str>, allowed: &[&str]) -> Result<BTreeMap<String, String>, QErr> {
    let raw = raw.unwrap_or("");
    let mut m = BTreeMap::new();
    for seg in raw.split('&').filter(|s| !s.is_empty()) {
        if m.len() >= MAX_PARAMS {
            return Err(QErr::Filter);
        }
        let (k, v) = seg.split_once('=').unwrap_or((seg, ""));
        let (Some(k), Some(v)) = (pct_decode(k), pct_decode(v)) else {
            return Err(QErr::Filter);
        };
        if !allowed.contains(&k.as_str()) || v.is_empty() {
            return Err(QErr::Filter);
        }
        if k == "cursor" {
            // An over-long cursor is a cursor defect, not a filter defect.
            if v.len() > MAX_CURSOR_LEN {
                return Err(QErr::Cursor);
            }
        } else if v.len() > MAX_VALUE_LEN {
            return Err(QErr::Filter);
        }
        if m.insert(k, v).is_some() {
            return Err(QErr::Filter);
        }
    }
    if raw.len() > MAX_QUERY_LEN {
        return Err(QErr::Filter);
    }
    Ok(m)
}

/// `limit` defaults to 100. A value of 0, above 500, or not a plain decimal
/// integer is 422 `invalid_filter` (it is never clamped).
fn parse_limit(p: &mut BTreeMap<String, String>) -> Result<usize, QErr> {
    match p.remove("limit") {
        None => Ok(DEFAULT_LIMIT),
        Some(v) => match v.parse::<usize>() {
            Ok(n) if (1..=MAX_LIMIT).contains(&n) && v.bytes().all(|b| b.is_ascii_digit()) => Ok(n),
            _ => Err(QErr::Filter),
        },
    }
}

fn parse_id(v: &str) -> Result<String, QErr> {
    Id::new(v).map(|_| v.to_string()).map_err(|_| QErr::Filter)
}

fn parse_enum(v: &str, allowed: &[&str]) -> Result<String, QErr> {
    allowed
        .contains(&v)
        .then(|| v.to_string())
        .ok_or(QErr::Filter)
}

fn parse_time(v: &str) -> Result<i64, QErr> {
    Timestamp::new(v).map_err(|_| QErr::Filter)?;
    super::projection::timestamp_secs(v).ok_or(QErr::Filter)
}

// ---- cursor -----------------------------------------------------------------

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CursorWire {
    v: u8,
    key: serde_json::Value,
    filter_hash: String,
}

/// Hash binding endpoint, sort definition and normalised filters.
fn filter_hash(endpoint: &str, order: &str, normalised: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"sigil-proxy-cursor-v1\0");
    for part in [endpoint, order, normalised] {
        h.update(part.as_bytes());
        h.update([0]);
    }
    data_encoding::HEXLOWER.encode(&h.finalize())
}

fn encode_cursor(key: serde_json::Value, hash: &str) -> String {
    let w = CursorWire {
        v: 1,
        key,
        filter_hash: hash.to_string(),
    };
    data_encoding::BASE64URL_NOPAD.encode(&serde_json::to_vec(&w).unwrap_or_default())
}

/// The key of a valid cursor for `hash`; every defect is `invalid_cursor`.
fn decode_cursor(raw: &str, hash: &str) -> Result<serde_json::Value, QErr> {
    if raw.len() > MAX_CURSOR_LEN {
        return Err(QErr::Cursor);
    }
    let bytes = data_encoding::BASE64URL_NOPAD
        .decode(raw.as_bytes())
        .map_err(|_| QErr::Cursor)?;
    let w: CursorWire = serde_json::from_slice(&bytes).map_err(|_| QErr::Cursor)?;
    if w.v != 1 || w.filter_hash != hash {
        return Err(QErr::Cursor);
    }
    Ok(w.key)
}

// ---- time and connection state ----------------------------------------------

fn rfc3339(secs: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Connected,
    Disconnected,
    NeverConnected,
}

impl ConnectionState {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "connected" => Some(Self::Connected),
            "disconnected" => Some(Self::Disconnected),
            "never_connected" => Some(Self::NeverConnected),
            _ => None,
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Disconnected => "disconnected",
            Self::NeverConnected => "never_connected",
        }
    }
}

/// Derived at read time, never stored (L3). `connected` when
/// `now - last_seen <= stale_after`. An unparsable stored time is not claimed
/// as connected.
pub fn connection_state(last_seen: Option<&str>, now: i64, stale_after: i64) -> ConnectionState {
    match last_seen {
        None => ConnectionState::NeverConnected,
        Some(t) => match super::projection::timestamp_secs(t) {
            Some(s) if now - s <= stale_after => ConnectionState::Connected,
            _ => ConnectionState::Disconnected,
        },
    }
}

// ---- DTOs -------------------------------------------------------------------

#[derive(Serialize)]
pub struct SpoolDto {
    pub state: SpoolState,
    pub depth_events: i64,
    pub unsent_events: i64,
    pub bytes: i64,
    pub capacity_bytes: i64,
    pub oldest_unsent_age_seconds: Option<i64>,
    /// Server time at which the report these numbers come from was applied
    /// (`status_received_at`). Null for state written before it was recorded.
    pub as_of: Option<String>,
}

#[derive(Serialize)]
pub struct ProxySummary {
    pub proxy_id: String,
    pub display_name: String,
    pub connection_state: ConnectionState,
    pub last_seen: Option<String>,
    pub desired_revision: Option<u64>,
    pub applied_revision: Option<i64>,
    pub config_in_sync: bool,
    pub config_state: ConfigState,
    pub config_expires_at: Option<String>,
    pub current_epoch_id: Option<String>,
    pub spool: Option<SpoolDto>,
    pub open_gap_count: i64,
    /// Server time the status fields were applied; see [`SpoolDto::as_of`].
    pub status_as_of: Option<String>,
}

#[derive(Serialize)]
pub struct CounterDto {
    pub upstream_id: Option<String>,
    pub reason: String,
    pub count: i64,
}

#[derive(Serialize)]
pub struct EpochTotalsDto {
    pub epoch_id: String,
    pub auth_failures: i64,
    pub unmatched_cancels: i64,
}

#[derive(Serialize)]
pub struct CountersDto {
    pub epoch_id: Option<String>,
    pub auth_failures: Vec<CounterDto>,
    pub unmatched_cancels: Vec<CounterDto>,
    pub previous_epoch_totals: Vec<EpochTotalsDto>,
}

#[derive(Serialize)]
pub struct OutageDto {
    pub gap_id: String,
    pub detected_at: String,
    pub started_at: String,
    pub ended_at: Option<String>,
}

#[derive(Serialize)]
pub struct GapDto {
    pub gap_id: String,
    pub kind: String,
    pub source: &'static str,
    pub detected_at: String,
    pub state: &'static str,
    pub details: serde_json::Value,
}

#[derive(Serialize)]
pub struct ProxyDetail {
    #[serde(flatten)]
    pub summary: ProxySummary,
    pub registry: Option<RegistryStatus>,
    pub routes: Vec<RouteStatus>,
    pub central: Option<CentralStatus>,
    pub outages: Vec<OutageDto>,
    pub counters: CountersDto,
    pub audit_gaps: Vec<GapDto>,
    pub audit_gaps_total: i64,
    pub open_gap_counts: BTreeMap<String, i64>,
}

#[derive(Serialize)]
pub struct ActorDto {
    pub actor_id: String,
    pub actor_kind: String,
    pub authentication_method: String,
    pub evidence_source: String,
    pub credential_owner_id: Option<String>,
}

#[derive(Serialize)]
pub struct InvocationSummary {
    pub invocation_id: String,
    pub proxy_id: String,
    pub lifecycle: &'static str,
    pub outcome: Option<String>,
    pub delivery_state: Option<String>,
    pub reason: Option<String>,
    pub reported_outcome: Option<String>,
    pub reported_delivery_state: Option<String>,
    pub reported_reason: Option<String>,
    pub duration_ms: Option<i64>,
    pub response_bytes: Option<i64>,
    pub method: Option<String>,
    pub protocol_version: Option<String>,
    pub upstream_id: Option<String>,
    pub route_revision: Option<i64>,
    pub actor: Option<ActorDto>,
    pub tool: Option<serde_json::Value>,
    pub cancel_observed: bool,
    pub decision: Option<String>,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub first_received_at: String,
    pub last_received_at: String,
    pub start_epoch_id: Option<String>,
    pub epoch_superseded: bool,
    pub flags: Vec<&'static str>,
}

#[derive(Serialize)]
pub struct EventDto {
    pub event_type: String,
    pub event_id: String,
    pub epoch_id: String,
    pub sequence: i64,
    pub occurred_at: String,
    pub received_at: String,
}

#[derive(Serialize)]
pub struct InvocationDetailDto {
    #[serde(flatten)]
    pub invocation: InvocationSummary,
    pub events_total: i64,
    pub events_truncated: bool,
    pub events: Vec<EventDto>,
}

#[derive(Serialize)]
struct Page<T: Serialize> {
    items: Vec<T>,
    next_cursor: Option<String>,
}

fn tool_dto(t: &ToolInfo) -> serde_json::Value {
    match t {
        ToolInfo::Identified { metadata_ref } => {
            serde_json::json!({"status": "identified", "metadata_ref": metadata_ref})
        }
        ToolInfo::MetadataUnavailable { reason } => {
            serde_json::json!({"status": "metadata_unavailable", "reason": reason})
        }
        ToolInfo::Unavailable { reason } => {
            serde_json::json!({"status": "unavailable", "reason": reason})
        }
    }
}

fn invocation_dto(p: &Projection) -> InvocationSummary {
    InvocationSummary {
        invocation_id: p.invocation_id.clone(),
        proxy_id: p.proxy_id.clone(),
        lifecycle: p.lifecycle.as_str(),
        outcome: p.outcome.clone(),
        delivery_state: p.delivery_state.clone(),
        reason: p.reason.clone(),
        reported_outcome: p.reported_outcome.clone(),
        reported_delivery_state: p.reported_delivery_state.clone(),
        reported_reason: p.reported_reason.clone(),
        duration_ms: p.duration_ms,
        response_bytes: p.response_bytes,
        method: p.method.clone(),
        protocol_version: p.protocol_version.clone(),
        upstream_id: p.upstream_id.clone(),
        route_revision: p.route_revision,
        actor: p.actor.as_ref().map(|a| ActorDto {
            actor_id: a.actor_id.clone(),
            actor_kind: a.actor_kind.clone(),
            authentication_method: a.authentication_method.clone(),
            evidence_source: a.evidence_source.clone(),
            credential_owner_id: a.credential_owner_id.clone(),
        }),
        tool: p.tool.as_ref().map(tool_dto),
        cancel_observed: p.cancel_observed,
        decision: p.decision.clone(),
        started_at: p.started_at.clone(),
        completed_at: p.completed_at.clone(),
        first_received_at: rfc3339(p.first_received_at),
        last_received_at: rfc3339(p.last_received_at),
        start_epoch_id: p.start_epoch_id.clone(),
        epoch_superseded: p.epoch_superseded,
        flags: p.flags.iter().map(|f| f.as_str()).collect(),
    }
}

// ---- proxy summary ----------------------------------------------------------

/// Summary without ledger data; `open_gap_count` counts proxy-reported gaps
/// only and is completed by the caller from the ledger.
fn summary_of(rec: &ProxyRecord, st: Option<&StoreSummary>, now: i64) -> ProxySummary {
    let last_seen = st.and_then(|x| x.last_seen.clone());
    let desired = st.and_then(|x| x.desired_revision);
    let applied = st.and_then(|x| x.applied_revision);
    let in_sync = matches!((desired, applied), (Some(d), Some(a)) if i64::try_from(d) == Ok(a));
    ProxySummary {
        proxy_id: rec.proxy_id.clone(),
        display_name: rec.display_name.clone(),
        connection_state: connection_state(last_seen.as_deref(), now, STALE_AFTER_SECS),
        last_seen,
        desired_revision: desired,
        applied_revision: applied,
        config_in_sync: in_sync,
        config_state: st.and_then(|x| x.config_state).unwrap_or(ConfigState::None),
        config_expires_at: st.and_then(|x| x.config_expires_at.clone()),
        // L3: the epoch of the last applied status report, else the newest
        // epoch the store saw. Not the ledger's latest announced epoch (no
        // ledger accessor yet), so it can lag events from a newer epoch.
        current_epoch_id: st.and_then(|x| x.current_epoch_id.clone()),
        spool: st.and_then(|x| {
            x.spool.as_ref().map(|sp| SpoolDto {
                state: sp.state,
                depth_events: sp.depth_events.get(),
                unsent_events: sp.unsent_events.get(),
                bytes: sp.bytes.get(),
                capacity_bytes: sp.capacity_bytes.get(),
                oldest_unsent_age_seconds: sp.oldest_unsent_age_seconds.map(|v| v.get()),
                as_of: x.status_received_at.clone(),
            })
        }),
        open_gap_count: st.map_or(0, |x| x.reported_gap_count as i64),
        status_as_of: st.and_then(|x| x.status_received_at.clone()),
    }
}

fn reported_kind(g: &GapReport) -> &'static str {
    match g {
        GapReport::RegistryConflict(_) => "registry_conflict",
        GapReport::EventQuarantined(_) => "event_quarantined",
        GapReport::LocalRecordFailed(_) => "local_record_failed",
        GapReport::SpoolExpired(_) => "spool_expired",
        GapReport::UnrecordedCalls(_) => "unrecorded_calls",
        GapReport::CentralOutage(_) => "central_outage",
    }
}

/// `(gap_id, detected_at)` of a proxy-reported gap.
fn reported_ids(g: &GapReport) -> (String, String) {
    let (id, at) = match g {
        GapReport::RegistryConflict(x) => (x.gap_id.as_str(), x.detected_at.as_str()),
        GapReport::EventQuarantined(x) => (x.gap_id.as_str(), x.detected_at.as_str()),
        GapReport::LocalRecordFailed(x) => (x.gap_id.as_str(), x.detected_at.as_str()),
        GapReport::SpoolExpired(x) => (x.gap_id.as_str(), x.detected_at.as_str()),
        GapReport::UnrecordedCalls(x) => (x.gap_id.as_str(), x.detected_at.as_str()),
        GapReport::CentralOutage(x) => (x.gap_id.as_str(), x.detected_at.as_str()),
    };
    (id.to_string(), at.to_string())
}

/// Proxy-reported gap as the L4 `AuditGap`: `details` is the report minus its
/// `kind`, `gap_id` and `detected_at` (identifiers, counts and times only).
fn reported_gap_dto(g: &GapReport) -> GapDto {
    let (gap_id, detected_at) = reported_ids(g);
    let mut details = serde_json::to_value(g).unwrap_or_default();
    if let Some(o) = details.as_object_mut() {
        for k in ["kind", "gap_id", "detected_at"] {
            o.remove(k);
        }
    }
    GapDto {
        gap_id,
        kind: reported_kind(g).to_string(),
        source: "proxy_reported",
        detected_at,
        // Only `sequence_gap` can close (L4); proxy-reported gaps stay open.
        state: "open",
        details,
    }
}

fn derived_gap_dto(g: &super::ledger::GapRecord) -> GapDto {
    let (kind, details) = match g.kind {
        super::ledger::GapKind::ProducerEpochChange => (
            "producer_epoch_change",
            serde_json::json!({
                "previous_epoch_id": g.previous_epoch_id,
                "epoch_id": g.epoch_id,
            }),
        ),
        super::ledger::GapKind::SequenceGap => (
            "sequence_gap",
            serde_json::json!({
                "epoch_id": g.epoch_id,
                "from_sequence": g.from_sequence,
                "to_sequence": g.to_sequence,
                "tail": g.tail,
            }),
        ),
    };
    GapDto {
        gap_id: g.gap_id.clone(),
        kind: kind.to_string(),
        source: "server_derived",
        detected_at: rfc3339(g.detected_at),
        state: if g.open { "open" } else { "closed" },
        details,
    }
}

fn counters_dto(e: &ProxyEntry) -> CountersDto {
    let mut c = CountersDto {
        epoch_id: e.counters_epoch.clone(),
        auth_failures: Vec::new(),
        unmatched_cancels: Vec::new(),
        previous_epoch_totals: e
            .previous_epoch_totals
            .iter()
            .map(|t| EpochTotalsDto {
                epoch_id: t.epoch_id.clone(),
                auth_failures: t.auth_failures,
                unmatched_cancels: t.unmatched_cancels,
            })
            .collect(),
    };
    for (k, v) in &e.counter_max {
        let Some((kind, up, reason)) = parse_counter_key(k) else {
            continue;
        };
        let dto = CounterDto {
            upstream_id: up.map(str::to_string),
            reason: reason.to_string(),
            count: *v,
        };
        match kind {
            'a' => c.auth_failures.push(dto),
            'c' => c.unmatched_cancels.push(dto),
            _ => {}
        }
    }
    c
}

// ---- auth layer -------------------------------------------------------------

/// Host-class peers only: proxy, management, ambiguous and registry-held
/// certificates get the host-route `host_unknown` answer (same bytes as
/// `host_route_guard`, which exempts `/v1/proxies*`).
async fn read_class_guard(
    State(ctx): State<Arc<ProxyContext>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let ok = req
        .extensions()
        .get::<Arc<PeerIdentity>>()
        .is_some_and(|p| {
            ctx.peer_class(p) == PeerClass::Host && !ctx.registry.holds_fingerprint(&p.fingerprint)
        });
    if !ok {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "host_unknown"})),
        )
            .into_response();
    }
    next.run(req).await
}

fn guarded(
    mr: MethodRouter<Arc<ProxyContext>>,
    ctx: &Arc<ProxyContext>,
    token: &ReadToken,
) -> MethodRouter<Arc<ProxyContext>> {
    mr.route_layer(from_fn_with_state(token.clone(), require_bearer))
        .route_layer(from_fn_with_state(ctx.clone(), read_class_guard))
}

/// The four read routes. `management` tells whether the management router
/// (which owns `POST /v1/proxies`) is mounted; without it `POST /v1/proxies`
/// keeps answering the router's plain 404 instead of 405 (any method but GET).
pub fn router(ctx: Arc<ProxyContext>, read_token: ReadToken, management: bool) -> Router {
    let mut proxies = guarded(get(list_proxies), &ctx, &read_token);
    if !management {
        proxies = proxies.fallback(|| async { StatusCode::NOT_FOUND });
    }
    Router::new()
        .route(PROXIES_PATH, proxies)
        .route(
            "/v1/proxies/:proxy_id",
            // Other methods keep the plain 404 this path had before the read
            // route existed (no 405 hint).
            guarded(get(get_proxy), &ctx, &read_token).fallback(|| async { StatusCode::NOT_FOUND }),
        )
        .route(
            INVOCATIONS_PATH,
            guarded(get(list_invocations), &ctx, &read_token),
        )
        .route(
            "/v1/proxy-invocations/:invocation_id",
            guarded(get(get_invocation), &ctx, &read_token),
        )
        .with_state(ctx)
}

// ---- handlers ---------------------------------------------------------------

fn now_secs() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, QErr> + Send + 'static,
) -> Result<T, QErr> {
    tokio::task::spawn_blocking(f)
        .await
        .unwrap_or(Err(QErr::Storage))
}

async fn list_proxies(
    State(ctx): State<Arc<ProxyContext>>,
    parts: Parts,
    RawQuery(q): RawQuery,
) -> Response {
    let scope = read_scope(&ctx, &parts.extensions);
    match list_proxies_inner(ctx, scope, q).await {
        Ok(r) => r,
        Err(e) => e.into_response(),
    }
}

async fn list_proxies_inner(
    ctx: Arc<ProxyContext>,
    scope: ProxyScope,
    q: Option<String>,
) -> Result<Response, QErr> {
    let mut p = parse_params(
        q.as_deref(),
        &["connection_state", "config_in_sync", "limit", "cursor"],
    )?;
    let limit = parse_limit(&mut p)?;
    let want_state = p
        .remove("connection_state")
        .map(|v| ConnectionState::parse(&v).ok_or(QErr::Filter))
        .transpose()?;
    let want_sync = p
        .remove("config_in_sync")
        .map(|v| match v.as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(QErr::Filter),
        })
        .transpose()?;
    let norm = format!(
        "connection_state={};config_in_sync={}",
        want_state.map_or("", ConnectionState::as_str),
        want_sync.map_or("", |b| if b { "true" } else { "false" }),
    );
    let hash = filter_hash("proxies", "proxy_id.asc", &norm);
    let after = match p.remove("cursor") {
        None => None,
        Some(c) => match decode_cursor(&c, &hash)? {
            serde_json::Value::String(s) if Id::new(s.as_str()).is_ok() => Some(s),
            _ => return Err(QErr::Cursor),
        },
    };

    let now = now_secs();
    let mut page: Vec<(ProxyRecord, Option<StoreSummary>)> = Vec::new();
    let mut more = false;
    for rec in scoped_records(&ctx, &scope) {
        if after.as_deref().is_some_and(|a| rec.proxy_id.as_str() <= a) {
            continue;
        }
        // One light store read per examined row (no deep clone of the entry).
        let st = ctx.store.summary(&rec.proxy_id);
        let s = summary_of(&rec, st.as_ref(), now);
        if want_state.is_some_and(|w| w != s.connection_state)
            || want_sync.is_some_and(|w| w != s.config_in_sync)
        {
            continue;
        }
        // A match beyond a full page only proves there is a next page; stop.
        if page.len() == limit {
            more = true;
            break;
        }
        page.push((rec, st));
    }
    let next_cursor = if more {
        page.last()
            .map(|(r, _)| encode_cursor(serde_json::Value::String(r.proxy_id.clone()), &hash))
    } else {
        None
    };
    // One ledger call for the whole page.
    let items = blocking(move || {
        let ids: Vec<String> = page.iter().map(|(r, _)| r.proxy_id.clone()).collect();
        let counts = ctx.ledger.open_gap_counts_for(&ids)?;
        Ok(page
            .iter()
            .map(|(rec, st)| {
                let mut s = summary_of(rec, st.as_ref(), now);
                s.open_gap_count += counts
                    .get(&rec.proxy_id)
                    .map_or(0, |m| m.values().sum::<i64>());
                s
            })
            .collect::<Vec<_>>())
    })
    .await?;
    Ok(Json(Page { items, next_cursor }).into_response())
}

async fn get_proxy(
    State(ctx): State<Arc<ProxyContext>>,
    parts: Parts,
    Path(proxy_id): Path<String>,
) -> Response {
    let scope = read_scope(&ctx, &parts.extensions);
    let rec = match ctx.registry.get(&proxy_id) {
        Some(r) if visible(&scope, &r.proxy_id) => r,
        _ => return proxy_unknown(),
    };
    let now = now_secs();
    let r = blocking(move || {
        let entry = ctx.store.entry(&rec.proxy_id);
        let gaps = ctx.ledger.gaps_page(&rec.proxy_id, MAX_GAP_PAGE)?;
        let derived = ctx.ledger.open_gap_counts(&rec.proxy_id)?;
        let st = entry.as_ref().map(StoreSummary::of);
        let mut summary = summary_of(&rec, st.as_ref(), now);
        let reported: &[GapReport] = entry.as_ref().map_or(&[], |e| e.gaps.as_slice());

        let mut open_gap_counts = derived;
        for g in reported {
            *open_gap_counts
                .entry(reported_kind(g).to_string())
                .or_insert(0) += 1;
        }
        summary.open_gap_count = open_gap_counts.values().sum();

        let mut outages: Vec<(i64, OutageDto)> = reported
            .iter()
            .filter_map(|g| match g {
                GapReport::CentralOutage(o) => Some((
                    super::projection::timestamp_secs(o.detected_at.as_str()).unwrap_or(0),
                    OutageDto {
                        gap_id: o.gap_id.as_str().to_string(),
                        detected_at: o.detected_at.as_str().to_string(),
                        started_at: o.started_at.as_str().to_string(),
                        ended_at: o.ended_at.as_ref().map(|t| t.as_str().to_string()),
                    },
                )),
                _ => None,
            })
            .collect();
        outages.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.gap_id.cmp(&a.1.gap_id)));

        // Newest first across both sources.
        let mut all: Vec<(i64, GapDto)> = gaps
            .items
            .iter()
            .map(|g| (g.detected_at, derived_gap_dto(g)))
            .chain(reported.iter().map(|g| {
                let d = reported_gap_dto(g);
                (
                    super::projection::timestamp_secs(&d.detected_at).unwrap_or(0),
                    d,
                )
            }))
            .collect();
        all.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.gap_id.cmp(&a.1.gap_id)));
        all.truncate(MAX_GAP_PAGE);

        let status = entry.as_ref().and_then(|e| e.status.as_ref());
        Ok(ProxyDetail {
            registry: status.map(|s| s.registry.clone()),
            routes: status.map(|s| s.routes.clone()).unwrap_or_default(),
            central: status.map(|s| s.central.clone()),
            outages: outages
                .into_iter()
                .take(MAX_OUTAGES)
                .map(|(_, o)| o)
                .collect(),
            counters: entry.as_ref().map_or_else(
                || CountersDto {
                    epoch_id: None,
                    auth_failures: Vec::new(),
                    unmatched_cancels: Vec::new(),
                    previous_epoch_totals: Vec::new(),
                },
                counters_dto,
            ),
            audit_gaps: all.into_iter().map(|(_, g)| g).collect(),
            audit_gaps_total: gaps.total + reported.len() as i64,
            open_gap_counts,
            summary,
        })
    })
    .await;
    match r {
        Ok(d) => Json(d).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn list_invocations(
    State(ctx): State<Arc<ProxyContext>>,
    parts: Parts,
    RawQuery(q): RawQuery,
) -> Response {
    let scope = read_scope(&ctx, &parts.extensions);
    match list_invocations_inner(ctx, scope, q).await {
        Ok(r) => r,
        Err(e) => e.into_response(),
    }
}

async fn list_invocations_inner(
    ctx: Arc<ProxyContext>,
    scope: ProxyScope,
    q: Option<String>,
) -> Result<Response, QErr> {
    const OUTCOMES: &[&str] = &[
        "success",
        "tool_error",
        "protocol_error",
        "timeout",
        "unknown",
        "denied",
    ];
    const METHODS: &[&str] = &["initialize", "ping", "tools/list", "tools/call", "unknown"];
    let mut p = parse_params(
        q.as_deref(),
        &[
            "proxy_id",
            "upstream_id",
            "actor_id",
            "method",
            "outcome",
            "lifecycle",
            "tool_ref",
            "from",
            "to",
            "time_basis",
            "limit",
            "cursor",
        ],
    )?;
    let limit = parse_limit(&mut p)?;
    let mut f = InvocationFilter::new(scope.clone());
    f.proxy_id = p.remove("proxy_id").map(|v| parse_id(&v)).transpose()?;
    f.upstream_id = p.remove("upstream_id").map(|v| parse_id(&v)).transpose()?;
    f.actor_id = p.remove("actor_id").map(|v| parse_id(&v)).transpose()?;
    f.method = p
        .remove("method")
        .map(|v| parse_enum(&v, METHODS))
        .transpose()?;
    f.outcome = p
        .remove("outcome")
        .map(|v| parse_enum(&v, OUTCOMES))
        .transpose()?;
    f.lifecycle = p
        .remove("lifecycle")
        .map(|v| Lifecycle::parse(&v).ok_or(QErr::Filter))
        .transpose()?;
    f.tool_ref = p
        .remove("tool_ref")
        .map(|v| {
            MetadataRef::new(v.as_str())
                .map(|_| v)
                .map_err(|_| QErr::Filter)
        })
        .transpose()?;
    f.from = p.remove("from").map(|v| parse_time(&v)).transpose()?;
    f.to = p.remove("to").map(|v| parse_time(&v)).transpose()?;
    f.time_basis = match p.remove("time_basis").as_deref() {
        None | Some("received") => TimeBasis::Received,
        Some("occurred") => TimeBasis::Occurred,
        Some(_) => return Err(QErr::Filter),
    };
    let norm = format!(
        "proxy_id={};upstream_id={};actor_id={};method={};outcome={};lifecycle={};tool_ref={};from={};to={};time_basis={}",
        f.proxy_id.as_deref().unwrap_or(""),
        f.upstream_id.as_deref().unwrap_or(""),
        f.actor_id.as_deref().unwrap_or(""),
        f.method.as_deref().unwrap_or(""),
        f.outcome.as_deref().unwrap_or(""),
        f.lifecycle.map_or("", Lifecycle::as_str),
        f.tool_ref.as_deref().unwrap_or(""),
        f.from.map_or(String::new(), |v| v.to_string()),
        f.to.map_or(String::new(), |v| v.to_string()),
        match f.time_basis {
            TimeBasis::Received => "received",
            TimeBasis::Occurred => "occurred",
        },
    );
    let hash = filter_hash("proxy-invocations", "created_seq.desc", &norm);
    let after = match p.remove("cursor") {
        None => None,
        Some(c) => match decode_cursor(&c, &hash)? {
            serde_json::Value::Number(n) => match n.as_i64() {
                Some(k) if k > 0 => Some(k),
                _ => return Err(QErr::Cursor),
            },
            _ => return Err(QErr::Cursor),
        },
    };

    // An out-of-scope or unknown proxy_id filter is an empty list, the same
    // answer for both (no existence leak).
    if let Some(id) = f.proxy_id.as_deref() {
        if !visible(&scope, id) || ctx.registry.get(id).is_none() {
            return Ok(Json(Page::<InvocationSummary> {
                items: Vec::new(),
                next_cursor: None,
            })
            .into_response());
        }
    }
    let page = blocking(move || Ok(ctx.ledger.list_invocations(&f, after, limit)?)).await?;
    let next_cursor = page
        .next_key
        .map(|k| encode_cursor(serde_json::Value::from(k), &hash));
    Ok(Json(Page {
        items: page.items.iter().map(invocation_dto).collect(),
        next_cursor,
    })
    .into_response())
}

async fn get_invocation(
    State(ctx): State<Arc<ProxyContext>>,
    parts: Parts,
    Path(invocation_id): Path<String>,
) -> Response {
    // Not a UUID: nothing can have this id. Same answer as any unknown target.
    if Uuid::new(invocation_id.as_str()).is_err() {
        return proxy_unknown();
    }
    let scope = read_scope(&ctx, &parts.extensions);
    // One ledger call: the owner lookup is restricted to the scope inside the
    // query, so an out-of-scope owner looks like no owner.
    let found =
        blocking(move || Ok(ctx.ledger.get_invocation_scoped(&invocation_id, &scope)?)).await;
    match found {
        Ok(Some(d)) => Json(InvocationDetailDto {
            invocation: invocation_dto(&d.invocation),
            events_total: d.events_total,
            events_truncated: d.events_truncated,
            events: d
                .events
                .iter()
                .map(|e| EventDto {
                    event_type: e.event_type.clone(),
                    event_id: e.event_id.clone(),
                    epoch_id: e.epoch_id.clone(),
                    sequence: e.sequence,
                    occurred_at: e.occurred_at.clone(),
                    received_at: rfc3339(e.received_at),
                })
                .collect(),
        })
        .into_response(),
        Ok(None) => proxy_unknown(),
        Err(e) => e.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_state_boundary() {
        let now = 1_000_000;
        let at = |s: i64| rfc3339(s);
        assert_eq!(
            connection_state(None, now, 90),
            ConnectionState::NeverConnected
        );
        assert_eq!(
            connection_state(Some(&at(now - 90)), now, 90),
            ConnectionState::Connected,
            "exactly stale_after is still connected"
        );
        assert_eq!(
            connection_state(Some(&at(now - 91)), now, 90),
            ConnectionState::Disconnected
        );
        assert_eq!(
            connection_state(Some(&at(now + 5)), now, 90),
            ConnectionState::Connected
        );
        assert_eq!(
            connection_state(Some("garbage"), now, 90),
            ConnectionState::Disconnected
        );
    }

    #[test]
    fn scope_is_bounded_and_filters() {
        let ids = (0..MAX_SCOPE_PROXIES + 50).map(|i| format!("px-{i:05}"));
        match bounded_scope(ids) {
            ProxyScope::Only(v) => {
                assert_eq!(v.len(), MAX_SCOPE_PROXIES);
                assert!(v.windows(2).all(|w| w[0] < w[1]));
            }
            ProxyScope::All => panic!("must stay Only"),
        }
        let only = bounded_scope(["a".to_string(), "a".to_string()]);
        assert!(visible(&only, "a") && !visible(&only, "b"));
        assert!(visible(&ProxyScope::All, "anything"));
    }

    #[test]
    fn params_are_strict() {
        let ok = |q: &str| parse_params(Some(q), &["a", "limit"]).is_ok();
        assert!(ok("a=1&limit=5"));
        assert!(!ok("a=1&a=2"), "duplicate");
        assert!(!ok("b=1"), "unknown name");
        assert!(!ok("a="), "empty value");
        assert!(!ok("a=%zz"), "bad escape");
        assert!(!ok("a=%ff"), "bad utf-8");
        assert!(!ok(&format!("a={}", "x".repeat(MAX_VALUE_LEN + 1))));
        assert!(!ok(&"a=1&".repeat(MAX_QUERY_LEN)));
    }

    #[test]
    fn cursor_round_trip_and_defects() {
        let h = filter_hash("e", "o", "n");
        let c = encode_cursor(serde_json::json!(7), &h);
        assert_eq!(decode_cursor(&c, &h).ok(), Some(serde_json::json!(7)));
        assert!(decode_cursor(&c, &filter_hash("e2", "o", "n")).is_err());
        assert!(decode_cursor("!!!", &h).is_err());
        assert!(decode_cursor(&"A".repeat(MAX_CURSOR_LEN + 1), &h).is_err());
        let extra = data_encoding::BASE64URL_NOPAD
            .encode(br#"{"v":1,"key":1,"filter_hash":"x","extra":1}"#);
        assert!(decode_cursor(&extra, &h).is_err());
    }
}
