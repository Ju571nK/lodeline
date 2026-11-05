//! The built-in mock fleet for `MOCK_FLEET=1` (Go's `internal/fleet/mock.go`): 6 hosts and 33
//! events over the 24 hours before the seed, which is the process start.
//!
//! The fixtures are `testdata/mock-fleet.json`, written once from the Go mock (see
//! `testdata/README.md`). Its times are second offsets from the seed, and its IPv4 addresses
//! are hex (`ipv4:c0000201` for the dotted form of 0xc0000201), so the file holds no literal
//! addresses. Event IDs come from the seed as Go derives them.

use std::net::Ipv4Addr;
use std::sync::Arc;

use serde::Deserialize;
use serde_json::Value;

use super::{
    go_decode, BoxFuture, Client, CompliancePage, ComplianceParams, ComplianceRow, Event,
    EventsPage, EventsParams, FleetError, GoTime, HostDetail, HostsPage, HostsParams, Meta, Reply,
    Request, Response, RiskPage, RiskParams, RiskRow,
};

const FIXTURES: &str = include_str!("../../testdata/mock-fleet.json");

pub struct Mock {
    seed: GoTime,
    meta: Meta,
    policy_version: i64,
    hosts: Vec<MockHost>,
    /// Newest first, which is also descending event ID order.
    events: Vec<Event>,
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
        Self {
            seed: GoTime::from_unix(seed),
            meta: f.meta,
            policy_version: f.policy_version,
            hosts: f.hosts,
            events: f.events,
        }
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

    /// One row per host with a current risk, riskiest first.
    fn risk(&self, p: &RiskParams) -> RiskPage {
        let mut rows: Vec<RiskRow> = Vec::new();
        for h in self.hosts.iter().map(|h| &h.detail.summary) {
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
        RiskPage { rows, next_cursor }
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
        })
    }
}

impl Client for Mock {
    fn get(&self, req: Request) -> BoxFuture<'_, Reply> {
        let reply = self.answer(req).map(Arc::new);
        Box::pin(async move { reply })
    }
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
