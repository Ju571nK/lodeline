//! The built-in mock fleet for `MOCK_FLEET=1` (Go's `internal/fleet/mock.go`): 6 hosts and 33
//! events over the 24 hours before the seed, which is the process start.
//!
//! The fixtures are `testdata/mock-fleet.json`, written once from the Go mock (see
//! `testdata/README.md`). Its times are second offsets from the seed, and its IPv4 addresses
//! are hex (`ipv4:c0000201` for the dotted form of 0xc0000201), so the file holds no literal
//! addresses. Event IDs come from the seed as Go derives them.
//!
//! The proxies are `testdata/mock-proxies.json` and their invocations
//! `testdata/mock-proxy-invocations.json`, both written for this console: 5 proxy details and 10
//! invocation details whose times are second offsets from the seed. A list cursor is the last ID
//! of a page. `testdata/mock-proxy-inventory.json` holds the inventory views of some of them.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use serde::Deserialize;
use serde_json::Value;

use super::{
    go_decode, BoxFuture, Client, CompliancePage, ComplianceParams, ComplianceRow, DriftRecord,
    Event, EventsPage, EventsParams, FleetError, GoTime, HostDetail, HostsPage, HostsParams,
    InventoryPage, InventoryParams, InventoryScope, InventorySnapshot, InventoryView,
    InvocationDetail, InvocationSummary, InvocationsPage, InvocationsParams, Meta, ProxiesPage,
    ProxiesParams, ProxyDetail, RebaselineMarker, Reply, Request, Response, RiskPage, RiskParams,
    RiskRow,
};

const FIXTURES: &str = include_str!("../../testdata/mock-fleet.json");
const PROXY_FIXTURES: &str = include_str!("../../testdata/mock-proxies.json");
const INVOCATION_FIXTURES: &str = include_str!("../../testdata/mock-proxy-invocations.json");
const INVENTORY_FIXTURES: &str = include_str!("../../testdata/mock-proxy-inventory.json");

pub struct Mock {
    seed: GoTime,
    meta: Meta,
    policy_version: i64,
    hosts: Vec<MockHost>,
    /// Newest first, which is also descending event ID order.
    events: Vec<Event>,
    /// In `proxy_id` order, the server's list order.
    proxies: Vec<ProxyDetail>,
    /// Newest first, the server's list order.
    invocations: Vec<InvocationDetail>,
    /// By proxy ID. A listed proxy that has none has empty views.
    inventory: BTreeMap<String, MockInventory>,
}

/// One proxy's three inventory views, each newest first.
#[derive(Default, Deserialize)]
struct MockInventory {
    snapshots: Vec<InventorySnapshot>,
    drift: Vec<DriftRecord>,
    markers: Vec<RebaselineMarker>,
}

#[derive(Deserialize)]
struct MockHost {
    detail: HostDetail,
    signature_failures_24h: i64,
}

#[derive(Deserialize)]
struct Fixtures {
    meta: Meta,
    policy_version: i64,
    hosts: Vec<MockHost>,
    events: Vec<Event>,
}

impl Mock {
    /// The mock fleet anchored at `seed`, in Unix seconds.
    pub fn new(seed: i64) -> Self {
        let mut v: Value = serde_json::from_str(FIXTURES).expect("mock-fleet.json is JSON");
        expand(&mut v, "", seed);
        let v = serde_json::value::to_raw_value(&v).expect("JSON encodes");
        let mut f: Fixtures = go_decode(&v).expect("mock-fleet.json has the fleet types");
        let n = f.events.len() as u64;
        for (i, e) in f.events.iter_mut().enumerate() {
            e.event_id = uuidv7_at(e.ts.unix_millis(), n - i as u64);
        }
        let mut proxies: Value =
            serde_json::from_str(PROXY_FIXTURES).expect("mock-proxies.json is JSON");
        expand_proxy_times(&mut proxies, "", seed);
        // `from_str`, not `from_value`: gap details are raw JSON, which only a text decode keeps.
        let proxies =
            serde_json::from_str(&proxies.to_string()).expect("mock-proxies.json has the types");
        let mut invocations: Value =
            serde_json::from_str(INVOCATION_FIXTURES).expect("mock-proxy-invocations.json is JSON");
        expand_proxy_times(&mut invocations, "", seed);
        let invocations =
            serde_json::from_value(invocations).expect("mock-proxy-invocations.json has the types");
        let mut inventory: Value =
            serde_json::from_str(INVENTORY_FIXTURES).expect("mock-proxy-inventory.json is JSON");
        expand_proxy_times(&mut inventory, "", seed);
        let inventory =
            serde_json::from_value(inventory).expect("mock-proxy-inventory.json has the types");
        Self {
            seed: GoTime::from_unix(seed),
            meta: f.meta,
            policy_version: f.policy_version,
            hosts: f.hosts,
            events: f.events,
            proxies,
            invocations,
            inventory,
        }
    }

    /// The server's checks in its order: an unknown proxy first, then the filters and the limit,
    /// then a cursor that must name a listed row.
    fn inventory(&self, view: InventoryView, p: &InventoryParams) -> Result<Response, FleetError> {
        if !self
            .proxies
            .iter()
            .any(|d| d.summary.proxy_id == p.proxy_id)
        {
            return Err(FleetError::NotFound);
        }
        let time = |v: &str| match v {
            "" => Ok(None),
            v => GoTime::parse(v).map(Some).ok_or(FleetError::InvalidFilter),
        };
        let (from, to) = (time(&p.from)?, time(&p.to)?);
        let change_known = match view {
            InventoryView::Drift => {
                ["", "added", "removed", "changed"].contains(&p.change.as_str())
            }
            _ => p.change.is_empty(),
        };
        if !change_known || p.limit > 500 {
            return Err(FleetError::InvalidFilter);
        }
        let keep = |s: &InventoryScope, at: &str| {
            let at = GoTime::parse(at);
            (p.upstream_id.is_empty() || s.upstream_id == p.upstream_id)
                && (p.credential_scope_id.is_empty()
                    || s.credential_scope_id == p.credential_scope_id)
                && from.is_none_or(|f| at.is_some_and(|t| t >= f))
                && to.is_none_or(|e| at.is_some_and(|t| t < e))
        };
        let none = MockInventory::default();
        let inv = self.inventory.get(&p.proxy_id).unwrap_or(&none);
        Ok(match view {
            InventoryView::Snapshots => Response::Snapshots(inventory_page(
                &inv.snapshots,
                p,
                |r| keep(&r.scope, &r.received_at),
                |r| &r.inventory_id,
            )?),
            InventoryView::Drift => Response::Drift(inventory_page(
                &inv.drift,
                p,
                |r| {
                    keep(&r.scope, &r.detected_at)
                        && (p.change.is_empty() || serde_json::json!(r.change) == p.change.as_str())
                },
                |r| &r.drift_id,
            )?),
            InventoryView::Markers => Response::Markers(inventory_page(
                &inv.markers,
                p,
                |r| keep(&r.scope, &r.detected_at),
                |r| &r.marker_id,
            )?),
        })
    }

    /// The server's filters and limit checks, and a cursor that must name a listed proxy.
    fn proxies(&self, p: &ProxiesParams) -> Result<ProxiesPage, FleetError> {
        let known = |v: &str, allowed: &[&str]| v.is_empty() || allowed.contains(&v);
        if !known(
            &p.connection_state,
            &["connected", "disconnected", "never_connected"],
        ) || !known(&p.config_in_sync, &["true", "false"])
            || p.limit > 500
        {
            return Err(FleetError::InvalidFilter);
        }
        let rows: Vec<_> = self
            .proxies
            .iter()
            .map(|d| &d.summary)
            .filter(|s| {
                let state = serde_json::to_value(s.connection_state).expect("enum encodes");
                (p.connection_state.is_empty() || state == p.connection_state.as_str())
                    && (p.config_in_sync.is_empty()
                        || p.config_in_sync == s.config_in_sync.to_string())
            })
            .collect();
        let (items, next_cursor) = cursor_page(&rows, &p.cursor, p.limit, |s| &s.proxy_id)?;
        Ok(ProxiesPage { items, next_cursor })
    }

    /// The server's filter and limit checks, and a cursor that must name a listed invocation.
    fn invocations(&self, p: &InvocationsParams) -> Result<InvocationsPage, FleetError> {
        let known = |v: &str, allowed: &[&str]| v.is_empty() || allowed.contains(&v);
        let time = |v: &str| match v {
            "" => Ok(None),
            v => GoTime::parse(v).map(Some).ok_or(FleetError::InvalidFilter),
        };
        let (from, to) = (time(&p.from)?, time(&p.to)?);
        if !known(
            &p.method,
            &["initialize", "ping", "tools/list", "tools/call", "unknown"],
        ) || !known(
            &p.outcome,
            &[
                "success",
                "tool_error",
                "protocol_error",
                "timeout",
                "unknown",
                "denied",
            ],
        ) || !known(
            &p.lifecycle,
            &[
                "started",
                "completed",
                "completion_without_start",
                "cancel_without_start",
                "integrity_conflict",
            ],
        ) || !known(&p.time_basis, &["received", "occurred"])
            || p.limit > 500
        {
            return Err(FleetError::InvalidFilter);
        }
        let is = |want: &str, got: Option<&str>| want.is_empty() || got == Some(want);
        let wire = |v: Value| v.as_str().map(str::to_owned);
        let rows: Vec<&InvocationSummary> = self
            .invocations
            .iter()
            .map(|d| &d.invocation)
            .filter(|i| {
                let at = if p.time_basis == "occurred" {
                    i.started_at.as_deref().or(i.completed_at.as_deref())
                } else {
                    Some(i.first_received_at.as_str())
                }
                .and_then(GoTime::parse);
                let outcome = i.outcome.and_then(|o| wire(serde_json::json!(o)));
                let lifecycle = wire(serde_json::json!(i.lifecycle));
                is(&p.proxy_id, Some(&i.proxy_id))
                    && is(&p.upstream_id, i.upstream_id.as_deref())
                    && is(&p.actor_id, i.actor.as_ref().map(|a| a.actor_id.as_str()))
                    && is(&p.method, i.method.as_deref())
                    && is(&p.outcome, outcome.as_deref())
                    && is(&p.lifecycle, lifecycle.as_deref())
                    && is(
                        &p.tool_ref,
                        i.tool.as_ref().and_then(|t| t.metadata_ref.as_deref()),
                    )
                    && from.is_none_or(|f| at.is_some_and(|t| t >= f))
                    && to.is_none_or(|e| at.is_some_and(|t| t < e))
            })
            .collect();
        let (items, next_cursor) = cursor_page(&rows, &p.cursor, p.limit, |i| &i.invocation_id)?;
        Ok(InvocationsPage { items, next_cursor })
    }

    fn events(&self, p: &EventsParams) -> EventsPage {
        let limit = clamp_limit(p.limit);
        let mut events: Vec<Event> = self
            .events
            .iter()
            .filter(|e| (p.cursor.is_empty() || e.event_id < p.cursor) && matches_event(e, p))
            .cloned()
            .collect();
        let mut next_cursor = None;
        if events.len() > limit {
            events.truncate(limit);
            next_cursor = events.last().map(|e| e.event_id.clone());
        }
        EventsPage {
            events: Some(events),
            next_cursor,
        }
    }

    fn hosts(&self, p: &HostsParams) -> HostsPage {
        let rows = self
            .hosts
            .iter()
            .map(|h| &h.detail.summary)
            .filter(|h| p.status.is_empty() || p.status.contains(&h.status))
            .filter(|h| {
                p.bucket.is_empty()
                    || h.current_risk
                        .as_ref()
                        .is_some_and(|r| p.bucket.contains(&r.max_bucket))
            })
            .cloned()
            .collect();
        let (hosts, next_cursor) = page(rows, &p.cursor, p.limit, |h| &h.host_id);
        HostsPage {
            hosts,
            next_cursor,
            total_estimated: self.hosts.len() as i64,
        }
    }

    /// One row per host with a current risk, riskiest first, and a count of the hosts whose
    /// selected tools fail with no score, as the server counts them.
    fn risk(&self, p: &RiskParams) -> RiskPage {
        let mut rows: Vec<RiskRow> = Vec::new();
        let selected = |tool: &String| p.tool.is_empty() || p.tool.contains(tool);
        let mut not_assessed = 0;
        for h in self.hosts.iter().map(|h| &h.detail.summary) {
            let scored = h.current_risk.as_ref().and_then(|r| r.by_tool.as_ref());
            if h.ai_guard_unassessed
                .iter()
                .flatten()
                .any(|(t, _)| selected(t))
                && !scored.iter().flat_map(|b| b.keys()).any(selected)
            {
                not_assessed += 1;
            }
            let Some(risk) = &h.current_risk else {
                continue;
            };
            let by_tool = risk.by_tool.clone().unwrap_or_default();
            // Go picks the first of equal scores in map order, which is random; each mock
            // host has one tool.
            let top_tool = by_tool
                .iter()
                .fold((String::new(), -1.0), |(top, best), (tool, tr)| {
                    if tr.score > best {
                        (tool.clone(), tr.score)
                    } else {
                        (top, best)
                    }
                })
                .0;
            if !p.tool.is_empty() && !p.tool.contains(&top_tool) {
                continue;
            }
            if !p.min_bucket.is_empty() && !bucket_at_least(&risk.max_bucket, &p.min_bucket) {
                continue;
            }
            let top = by_tool.get(&top_tool);
            let counts = h.open_event_counts_24h.as_ref();
            rows.push(RiskRow {
                host_id: h.host_id.clone(),
                hostname: h.hostname.clone(),
                score: risk.max_score,
                bucket: risk.max_bucket.clone(),
                top_tool,
                reasons_count: 0,
                assessed_ts: by_tool
                    .values()
                    .map(|t| t.assessed_ts)
                    .max()
                    .unwrap_or_default(),
                open_alert_count_24h: counts.and_then(|c| c.get("warn")).copied().unwrap_or(0),
                source: top.and_then(|t| t.source.clone()),
                unassessed_since: top.and_then(|t| t.unassessed_since),
            });
        }
        rows.sort_by(|a, b| b.score.total_cmp(&a.score));
        let (rows, next_cursor) = page(rows, &p.cursor, p.limit, |r| &r.host_id);
        RiskPage {
            rows,
            next_cursor,
            not_assessed_host_count: Some(not_assessed),
        }
    }

    fn compliance(&self, p: &ComplianceParams) -> CompliancePage {
        let rows = self
            .hosts
            .iter()
            .map(|h| {
                let state = h.detail.policy_state.clone().unwrap_or_default();
                ComplianceRow {
                    host_id: h.detail.summary.host_id.clone(),
                    hostname: h.detail.summary.hostname.clone(),
                    last_applied_policy_version: state.last_applied_policy_version,
                    server_current_policy_version: self.policy_version,
                    version_drift: self.policy_version - state.last_applied_policy_version,
                    policy_expired_active: state.policy_expired_active,
                    last_policy_reload_ts: state.last_policy_reload_ts,
                    signature_failures_24h: h.signature_failures_24h,
                }
            })
            .collect();
        let (rows, next_cursor) = page(rows, &p.cursor, p.limit, |r| &r.host_id);
        CompliancePage { rows, next_cursor }
    }

    fn answer(&self, req: Request) -> Result<Response, FleetError> {
        Ok(match req {
            Request::Healthz => Response::Healthz(super::Healthz {
                status: "ok".into(),
                ts: self.seed,
            }),
            Request::Meta => Response::Meta(self.meta.clone()),
            Request::Events(p) => Response::Events(self.events(&p)),
            Request::EventById(id) => Response::Event(
                self.events
                    .iter()
                    .find(|e| e.event_id == id)
                    .cloned()
                    .ok_or(FleetError::NotFound)?,
            ),
            Request::Hosts(p) => Response::Hosts(self.hosts(&p)),
            Request::HostById(id) => Response::Host(
                self.hosts
                    .iter()
                    .find(|h| h.detail.summary.host_id == id)
                    .map(|h| h.detail.clone())
                    .ok_or(FleetError::NotFound)?,
            ),
            Request::Risk(p) => Response::Risk(self.risk(&p)),
            Request::Compliance(p) => Response::Compliance(self.compliance(&p)),
            Request::Proxies(p) => Response::Proxies(self.proxies(&p)?),
            Request::ProxyById(id) => Response::Proxy(
                self.proxies
                    .iter()
                    .find(|d| d.summary.proxy_id == id)
                    .cloned()
                    .ok_or(FleetError::NotFound)?,
            ),
            Request::Invocations(p) => Response::Invocations(self.invocations(&p)?),
            Request::InvocationById(id) => Response::Invocation(
                self.invocations
                    .iter()
                    .find(|d| d.invocation.invocation_id == id)
                    .cloned()
                    .ok_or(FleetError::NotFound)?,
            ),
            Request::Inventory(view, p) => self.inventory(view, &p)?,
        })
    }
}

impl Client for Mock {
    fn get(&self, req: Request) -> BoxFuture<'_, Reply> {
        let reply = self.answer(req).map(Arc::new);
        Box::pin(async move { reply })
    }
}

/// A page of a proxy read: the cursor is the last ID of the previous page and must name a row,
/// as a real server refuses a cursor it did not issue for these filters. The limit defaults to 100.
fn cursor_page<T: Clone>(
    rows: &[&T],
    cursor: &str,
    limit: i64,
    id: impl Fn(&T) -> &String,
) -> Result<(Vec<T>, Option<String>), FleetError> {
    let start = match cursor {
        "" => 0,
        c => {
            rows.iter()
                .position(|r| id(r) == c)
                .ok_or(FleetError::InvalidCursor)?
                + 1
        }
    };
    let limit = if limit > 0 { limit as usize } else { 100 };
    let items: Vec<T> = rows
        .iter()
        .skip(start)
        .take(limit)
        .map(|&r| r.clone())
        .collect();
    let more = rows.len() > start + items.len();
    let next = items.last().filter(|_| more).map(|r| id(r).clone());
    Ok((items, next))
}

/// The rows of an inventory view that `keep` passes, paged as [`cursor_page`] does.
fn inventory_page<T: Clone>(
    rows: &[T],
    p: &InventoryParams,
    keep: impl Fn(&T) -> bool,
    id: impl Fn(&T) -> &String,
) -> Result<InventoryPage<T>, FleetError> {
    let rows: Vec<&T> = rows.iter().filter(|r| keep(r)).collect();
    let (items, next_cursor) = cursor_page(&rows, &p.cursor, p.limit, id)?;
    Ok(InventoryPage { items, next_cursor })
}

/// Turns the fixture offsets into times after `seed` and the hex addresses into dotted ones.
fn expand(v: &mut Value, key: &str, seed: i64) {
    match v {
        Value::Object(m) => m.iter_mut().for_each(|(k, e)| expand(e, k, seed)),
        Value::Array(a) => a.iter_mut().for_each(|e| expand(e, key, seed)),
        Value::Number(n)
            if key == "ts" || key.ends_with("_ts") || key == "since" || key.ends_with("_since") =>
        {
            let offset = n.as_i64().expect("time offsets are whole seconds");
            *v = Value::String(GoTime::from_unix(seed + offset).to_string());
        }
        Value::String(s) => *s = expand_addresses(s),
        _ => {}
    }
}

/// Turns the proxy fixture's offsets, under `*_at`, `last_seen` and `*as_of` keys, into RFC 3339
/// times after `seed`.
fn expand_proxy_times(v: &mut Value, key: &str, seed: i64) {
    match v {
        Value::Object(m) => m
            .iter_mut()
            .for_each(|(k, e)| expand_proxy_times(e, k, seed)),
        Value::Array(a) => a.iter_mut().for_each(|e| expand_proxy_times(e, key, seed)),
        Value::Number(n)
            if key.ends_with("_at") || key == "last_seen" || key.ends_with("as_of") =>
        {
            let offset = n.as_i64().expect("time offsets are whole seconds");
            *v = Value::String(GoTime::from_unix(seed + offset).to_string());
        }
        _ => {}
    }
}

fn expand_addresses(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(at) = rest.find("ipv4:") {
        let hex = rest
            .get(at + 5..at + 13)
            .filter(|h| h.bytes().all(|b| b.is_ascii_hexdigit()));
        let Some(hex) = hex else {
            out += &rest[..at + 5];
            rest = &rest[at + 5..];
            continue;
        };
        let addr = Ipv4Addr::from(u32::from_str_radix(hex, 16).expect("hex digits"));
        out += &format!("{}{addr}", &rest[..at]);
        rest = &rest[at + 13..];
    }
    out + rest
}

/// Go's `uuidv7At`: a UUIDv7-shaped ID with the millisecond time in the high 48 bits, so IDs
/// sort by time, and `counter` in the low bits.
fn uuidv7_at(unix_ms: i64, counter: u64) -> String {
    let hi32 = (unix_ms >> 16) as u32;
    let mid16 = (unix_ms & 0xffff) as u16;
    let rand1 = counter & 0xfff;
    let rand2 = (counter >> 12) & 0xfff;
    let rand3 = (counter >> 24) & 0xffff_ffff_ffff;
    format!("{hi32:08x}-{mid16:04x}-7{rand1:03x}-8{rand2:03x}-{rand3:012x}")
}

fn matches_event(e: &Event, p: &EventsParams) -> bool {
    let kind = e.evidence_kind();
    (p.since.is_zero() || e.ts >= p.since)
        && (p.until.is_zero() || e.ts < p.until)
        && (p.host_ids.is_empty() || p.host_ids.contains(&e.host_id))
        && (p.severity.is_empty() || p.severity.contains(&e.severity))
        && (p.evidence_kinds.is_empty() || p.evidence_kinds.contains(&kind))
        && (p.min_ai_guard_bucket.is_empty()
            || kind != "ai_guard_risk_assessed"
            || bucket_at_least(&e.evidence.member_str("bucket"), &p.min_ai_guard_bucket))
}

/// Unknown buckets rank below `low`, so an unknown minimum lets everything through.
fn bucket_at_least(have: &str, min: &str) -> bool {
    let rank = |b: &str| {
        ["low", "medium", "high", "critical"]
            .iter()
            .position(|x| *x == b)
    };
    rank(have).map_or(0, |r| r + 1) >= rank(min).map_or(0, |r| r + 1)
}

/// 100 when unset or not positive, at most 1000.
fn clamp_limit(n: i64) -> usize {
    if n <= 0 {
        100
    } else {
        n.min(1000) as usize
    }
}

/// The rows after the one whose ID is `cursor` (all of them when no row has it), cut at the
/// limit. Go answers `null` rows when nothing is left.
fn page<T>(
    rows: Vec<T>,
    cursor: &str,
    limit: i64,
    id: impl Fn(&T) -> &String,
) -> (Option<Vec<T>>, Option<String>) {
    let start = match cursor {
        "" => 0,
        c => rows.iter().position(|r| id(r) == c).map_or(0, |i| i + 1),
    };
    if start >= rows.len() {
        return (None, None);
    }
    let mut rows: Vec<T> = rows.into_iter().skip(start).collect();
    let limit = clamp_limit(limit);
    let mut next = None;
    if rows.len() > limit {
        rows.truncate(limit);
        next = rows.last().map(|r| id(r).clone());
    }
    (Some(rows), next)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixtures_load_with_go_ids_times_and_addresses() {
        let seed = 1_767_225_600; // 2026-01-01T00:00:00Z
        let m = Mock::new(seed);
        assert_eq!((m.hosts.len(), m.events.len()), (6, 33));
        assert_eq!(m.events[0].event_id, uuidv7_at(seed * 1000, 33));
        assert_eq!(m.events[31].ts, GoTime::from_unix(seed - 31 * 44 * 60));
        assert!(
            m.events.windows(2).all(|w| w[0].event_id > w[1].event_id),
            "newest first is descending ID order, as Go sorts"
        );
        let alice = &m.hosts[0].detail;
        let meta = alice.host_meta.as_ref().unwrap();
        let addr = &meta.interfaces.as_ref().unwrap()[0].ipv4.as_ref().unwrap()[0];
        assert!(addr.contains('.') && !addr.contains("ipv4:"), "{addr}");
        assert_eq!(m.meta.ts, GoTime::from_unix(seed));
        assert_eq!(
            expand_addresses("x ipv4:c0000201/24 ipv4:zz"),
            "x 192.0.2.1/24 ipv4:zz"
        );
    }

    #[test]
    fn proxies_page_filter_and_refuse_a_cursor_they_did_not_issue() {
        let seed = 1_767_225_600;
        let m = Mock::new(seed);
        let list = |p: ProxiesParams| m.proxies(&p);
        let ids = |page: &ProxiesPage| -> Vec<String> {
            page.items.iter().map(|s| s.proxy_id.clone()).collect()
        };
        let first = list(ProxiesParams {
            limit: 2,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(ids(&first), ["px-edge-01", "px-edge-02"]);
        let mut cursor = first.next_cursor.clone().unwrap();
        let mut seen = ids(&first);
        loop {
            let page = list(ProxiesParams {
                limit: 2,
                cursor: cursor.clone(),
                ..Default::default()
            })
            .unwrap();
            seen.extend(ids(&page));
            match page.next_cursor {
                Some(next) => cursor = next,
                None => break,
            }
        }
        assert_eq!(
            seen,
            [
                "px-edge-01",
                "px-edge-02",
                "px-lab-03",
                "px-new-04",
                "px-off-05"
            ]
        );
        let disconnected = list(ProxiesParams {
            connection_state: "disconnected".into(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(ids(&disconnected), ["px-lab-03", "px-off-05"]);
        assert_eq!(disconnected.next_cursor, None);
        let behind = list(ProxiesParams {
            config_in_sync: "false".into(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(ids(&behind), ["px-edge-02", "px-lab-03", "px-new-04"]);
        assert_eq!(
            list(ProxiesParams {
                cursor: "px-unknown".into(),
                ..Default::default()
            }),
            Err(FleetError::InvalidCursor)
        );
        assert_eq!(
            list(ProxiesParams {
                connection_state: "asleep".into(),
                ..Default::default()
            }),
            Err(FleetError::InvalidFilter)
        );
        let lab = &m.proxies[2].summary;
        assert_eq!(
            lab.last_seen.as_deref(),
            Some(GoTime::from_unix(seed - 7200).to_string().as_str())
        );
        assert_eq!(lab.spool.as_ref().unwrap().quarantined_bytes, None);
    }

    #[test]
    fn inventory_views_filter_page_and_refuse_what_the_server_refuses() {
        let seed = 1_767_225_600;
        let m = Mock::new(seed);
        let get = |view, p: InventoryParams| m.inventory(view, &p);
        let of = |proxy: &str| InventoryParams {
            proxy_id: proxy.into(),
            ..Default::default()
        };
        let tail = |id: &str| id[33..].to_owned();
        let Ok(Response::Snapshots(all)) = get(InventoryView::Snapshots, of("px-edge-01")) else {
            panic!("not a snapshot page")
        };
        let ids: Vec<_> = all.items.iter().map(|s| tail(&s.inventory_id)).collect();
        assert_eq!(ids, ["506", "505", "504", "503", "502"]);
        assert_eq!(
            all.items[0].received_at,
            GoTime::from_unix(seed - 590).to_string()
        );
        let Ok(Response::Snapshots(first)) = get(
            InventoryView::Snapshots,
            InventoryParams {
                limit: 2,
                ..of("px-edge-01")
            },
        ) else {
            panic!("not a snapshot page")
        };
        let cursor = first.next_cursor.expect("a second page");
        let Ok(Response::Snapshots(second)) = get(
            InventoryView::Snapshots,
            InventoryParams {
                limit: 2,
                cursor: cursor.clone(),
                ..of("px-edge-01")
            },
        ) else {
            panic!("not a snapshot page")
        };
        assert_eq!(tail(&second.items[0].inventory_id), "504");
        let Ok(Response::Drift(removed)) = get(
            InventoryView::Drift,
            InventoryParams {
                change: "removed".into(),
                ..of("px-edge-01")
            },
        ) else {
            panic!("not a drift page")
        };
        let removed: Vec<_> = removed.items.iter().map(|d| tail(&d.drift_id)).collect();
        assert_eq!(removed, ["603"]);
        let Ok(Response::Markers(docs)) = get(
            InventoryView::Markers,
            InventoryParams {
                upstream_id: "docs-search".into(),
                ..of("px-edge-01")
            },
        ) else {
            panic!("not a marker page")
        };
        assert_eq!(docs.items.len(), 1);
        let Ok(Response::Drift(none)) = get(InventoryView::Drift, of("px-new-04")) else {
            panic!("not a drift page")
        };
        assert_eq!((none.items.len(), none.next_cursor), (0, None));
        for (view, p, want) in [
            (InventoryView::Drift, of("px-missing"), FleetError::NotFound),
            (
                InventoryView::Snapshots,
                InventoryParams {
                    change: "added".into(),
                    ..of("px-edge-01")
                },
                FleetError::InvalidFilter,
            ),
            (
                InventoryView::Drift,
                InventoryParams {
                    change: "approved".into(),
                    ..of("px-edge-01")
                },
                FleetError::InvalidFilter,
            ),
            (
                InventoryView::Snapshots,
                InventoryParams {
                    cursor,
                    ..of("px-edge-02")
                },
                FleetError::InvalidCursor,
            ),
        ] {
            assert_eq!(get(view, p.clone()).unwrap_err(), want, "{view:?} {p:?}");
        }
    }

    #[test]
    fn invocations_page_filter_and_refuse_a_cursor_they_did_not_issue() {
        let seed = 1_767_225_600;
        let m = Mock::new(seed);
        let list = |p: InvocationsParams| m.invocations(&p);
        let ids = |page: &InvocationsPage| -> Vec<String> {
            let id = |i: &InvocationSummary| i.invocation_id[33..].to_owned();
            page.items.iter().map(id).collect()
        };
        let all = list(InvocationsParams::default()).unwrap();
        assert_eq!(
            ids(&all),
            ["401", "402", "403", "404", "405", "406", "409", "410", "408", "407"]
        );
        let first = list(InvocationsParams {
            limit: 4,
            ..Default::default()
        })
        .unwrap();
        let second = list(InvocationsParams {
            limit: 4,
            cursor: first.next_cursor.clone().unwrap(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(ids(&second), ["405", "406", "409", "410"]);
        let edge2 = list(InvocationsParams {
            proxy_id: "px-edge-02".into(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(ids(&edge2), ["401", "402", "409"]);
        let flagged = list(InvocationsParams {
            lifecycle: "integrity_conflict".into(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(ids(&flagged), ["402"]);
        let success = list(InvocationsParams {
            outcome: "success".into(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            ids(&success),
            ["403"],
            "a reported success is never matched"
        );
        let recent = list(InvocationsParams {
            from: GoTime::from_unix(seed - 600).to_string(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(ids(&recent), ["401", "402", "403"]);
        assert_eq!(
            list(InvocationsParams {
                proxy_id: "px-edge-02".into(),
                cursor: first.next_cursor.clone().unwrap(),
                ..Default::default()
            }),
            Err(FleetError::InvalidCursor),
            "a cursor from other filters"
        );
        assert_eq!(
            list(InvocationsParams {
                lifecycle: "asleep".into(),
                ..Default::default()
            }),
            Err(FleetError::InvalidFilter)
        );
        let truncated = &m.invocations[3];
        assert_eq!((truncated.events_total, truncated.events.len()), (40, 32));
        assert!(truncated.events_truncated);
        assert_eq!(
            truncated.invocation.first_received_at,
            GoTime::from_unix(seed - 620).to_string()
        );
    }

    #[test]
    fn risk_rows_carry_the_top_reading_source_and_failures_stay_out() {
        let seed = 1_767_225_600;
        let m = Mock::new(seed);
        let rows = m.risk(&RiskParams::default()).rows.unwrap();
        let name = |r: &RiskRow| r.hostname.clone().unwrap_or_default();
        let carol = rows.iter().find(|r| name(r) == "carol-dev").unwrap();
        assert_eq!(carol.unassessed_since, Some(GoTime::from_unix(seed - 1800)));
        assert_eq!(
            carol.source.as_ref().unwrap().member_str("rule_pack_id"),
            ""
        );
        assert!(
            rows.iter().all(|r| name(r) != "frank-ci"),
            "a host with failures and no score has no risk row"
        );
        let count = |tool: &str| {
            let tool = tool.split(',').filter(|t| !t.is_empty()).map(Into::into);
            let p = RiskParams {
                tool: tool.collect(),
                ..RiskParams::default()
            };
            m.risk(&p).not_assessed_host_count
        };
        // frank-ci counts; carol-dev's failing Claude Desktop source still has a score.
        assert_eq!(count(""), Some(1));
        assert_eq!(count("claude_code"), Some(1));
        assert_eq!(count("claude_desktop,codex"), Some(0));
        assert_eq!(
            m.events[32].evidence.member_str("failing_since"),
            GoTime::from_unix(seed - 32 * 44 * 60).to_string()
        );
    }

    #[test]
    fn bucket_order_and_paging_match_go() {
        assert!(bucket_at_least("critical", "high"));
        assert!(!bucket_at_least("medium", "high"));
        assert!(bucket_at_least("low", "unknown"));
        let ids = |v: Option<Vec<String>>| v.map(|v| v.join(","));
        let rows = || vec!["a".to_string(), "b".into(), "c".into()];
        fn id(s: &String) -> &String {
            s
        }
        assert_eq!(page(rows(), "", 2, id).1.as_deref(), Some("b"));
        assert_eq!(ids(page(rows(), "b", 0, id).0).as_deref(), Some("c"));
        assert_eq!(ids(page(rows(), "zz", 0, id).0).as_deref(), Some("a,b,c"));
        assert_eq!(page(rows(), "c", 0, id).0, None);
    }
}
