//! The contract test: the manager's HTTP client against a real `lodeline-server`, in process,
//! seeded with per-host JSONL as the server keeps it.
//!
//! For each endpoint the console uses, the client must decode the server's answer, and the raw
//! body must decode with the server's own `lodeline-fleet-api` types. Mapping those types onto the
//! console's must give the same body as the console's own decode, so a field the server renamed
//! or dropped shows up as a difference here instead of as a silent zero value. Each mapping
//! destructures the server type in full, so a new server field does not compile until the
//! mapping decides on it.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use lodeline_fleet_api as api;
use lodeline_server::app::{build_router, AppState};
use lodeline_server::auth::ReadToken;
use lodeline_server::boot_rebuild::rebuild_from_jsonl;
use lodeline_server::fleet_index::FleetIndex;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

use super::*;

const READ_TOKEN: &str = "contract-read-token";
const HOST_A: &str = "0190b8a0-0000-7000-8000-00000000000a";
const HOST_B: &str = "0190b8a0-0000-7000-8000-00000000000b";

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Host A has every detail block: host meta, two assessed tools with controls, a heartbeat,
/// a policy reload, a signature failure and agent health signals. Its Claude Code reading names a
/// user and a rule pack and has failed since, and its Codex reading has no user. Host B has one
/// warn event and a failing source with no reading.
fn seed(dir: &Path) -> Vec<String> {
    std::fs::write(
        dir.join("signed-policy.json"),
        json!({"policy_version": 4, "signing_pubkey_id": "k1",
               "signed_at": "2026-10-01T00:00:00Z", "valid_until": "2026-12-01T00:00:00Z"})
        .to_string(),
    )
    .unwrap();
    let per_host = [
        (
            HOST_A,
            vec![
                (
                    5,
                    "info",
                    json!({"kind": "host_meta_snapshot", "is_reattestation": false,
                    "snapshot": {"hostname": "alice", "os_name": "macOS", "os_version": "14.5",
                        "kernel_version": "23.5.0", "architecture": "arm64",
                        "interfaces": [{"name": "en0", "mac": "00:1b:44:11:3a:b7",
                            "ipv4": ["192.0.2.42/24"], "ipv6": []}],
                        "default_gateway_v4": "192.0.2.1", "default_gateway_v6": null,
                        "dns_servers": ["198.51.100.53"]}}),
                ),
                (
                    4,
                    "warn",
                    json!({"kind": "ai_guard_risk_assessed", "tool": "claude_code",
                    "scope": {"kind": "user_global"}, "score": 7.3, "bucket": "critical",
                    "reasons": [{"kind": "destructive_in_inline_command", "pattern": "rm -rf",
                        "hook_event": "PreToolUse", "snippet": "rm -rf /"}],
                    "controls": [{"id": "fixture.restricted", "source_path": "/fixture/config",
                        "setting": "restricted", "value": true}],
                    "user": "alice", "rule_pack_id": "acme-extended",
                    "is_reattestation": false}),
                ),
                (
                    3,
                    "warn",
                    assess_failed("claude_code", Some("alice"), Some(4)),
                ),
                (
                    4,
                    "warn",
                    json!({"kind": "ai_guard_risk_assessed", "tool": "codex",
                    "scope": {"kind": "project", "path": "/fixture/repo"}, "score": 2.1,
                    "bucket": "medium", "reasons": [{"kind": "permissions_deny_empty"}],
                    "is_reattestation": false}),
                ),
                (
                    3,
                    "info",
                    json!({"kind": "heartbeat", "uptime_s": 60, "is_final": false,
                    "channel_stall_events_total": 0, "events_emitted_total": 9,
                    "events_by_kind": {}, "hash_p50_ms": 1, "hash_p99_ms": 4,
                    "watcher_backend": "fsevents", "state_db_size_bytes": 4096,
                    "last_log_rotation_ts": null, "last_applied_policy_version": 3,
                    "policy_expired_active": false, "jsonl_above_soft_floor": false}),
                ),
                (
                    3,
                    "info",
                    json!({"kind": "policy_reloaded", "policy_version": 3}),
                ),
                (
                    2,
                    "warn",
                    json!({"kind": "policy_signature_invalid",
                    "reason": "signature_invalid", "signing_pubkey_id": "k0",
                    "policy_version_in_envelope": 9, "last_applied_policy_version": 3}),
                ),
                (
                    2,
                    "warn",
                    json!({"kind": "watcher_degraded", "from": "fsevents",
                    "to": "poll", "reason": "fixture"}),
                ),
            ],
        ),
        (
            HOST_B,
            vec![
                (
                    30,
                    "warn",
                    json!({"kind": "host_id_conflict", "observed_status": 409}),
                ),
                (29, "warn", assess_failed("cursor", None, None)),
            ],
        ),
    ];
    let now = chrono::Utc::now();
    let mut ids = Vec::new();
    for (host, events) in per_host {
        let host_dir = dir.join(host);
        std::fs::create_dir_all(&host_dir).unwrap();
        for (minutes_ago, severity, evidence) in events {
            let ts = now - chrono::Duration::minutes(minutes_ago);
            // The server finds an event by the time in its UUIDv7, in that day's file.
            let ms = ts.timestamp_millis();
            let id = format!(
                "{:08x}-{:04x}-7000-8000-{:012x}",
                ms >> 16,
                ms & 0xffff,
                ids.len() + 1
            );
            let line = json!({"schema_version": 1, "event_id": id,
                "ts": ts.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                "host_id": host, "agent_version": "fixture-agent", "severity": severity,
                "source": {"kind": "agent"}, "subject": {"kind": "self"},
                "evidence": evidence, "target_id": null});
            let file = host_dir.join(format!("received-{}.jsonl", ts.format("%Y-%m-%d")));
            let mut text = std::fs::read_to_string(&file).unwrap_or_default();
            text += &format!("{line}\n");
            std::fs::write(file, text).unwrap();
            ids.push(id);
        }
    }
    ids
}

/// An `ai_guard_assess_failed` for `tool` at user scope, failing since 3 minutes ago, with its last
/// good reading `last_minutes_ago`.
fn assess_failed(tool: &str, user: Option<&str>, last_minutes_ago: Option<i64>) -> Value {
    let at = |m: i64| {
        (chrono::Utc::now() - chrono::Duration::minutes(m))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    };
    let mut e = json!({"kind": "ai_guard_assess_failed", "tool": tool,
        "scope": {"kind": "user_global"}, "error_kind": "parse", "path": "/fixture/config",
        "failing_since": at(3), "last_assessed_ts": last_minutes_ago.map(at),
        "is_reattestation": false});
    if let Some(user) = user {
        e["user"] = user.into();
        e["rule_pack_id"] = "acme-extended".into();
    }
    e
}

async fn serve(dir: &Path) -> String {
    let index = FleetIndex::new();
    index.replace(rebuild_from_jsonl(dir).unwrap());
    let state = AppState {
        events_out_dir: dir.to_path_buf(),
        policy_bundle_path: dir.join("signed-policy.json"),
        rule_packs_bundle_path: None,
        artifacts_dir: None,
        high_water_path: dir.join(".high-water.json"),
        allowlist: Default::default(),
        high_water: Default::default(),
        fleet_index: index,
        read_token: ReadToken(Some(READ_TOKEN.into())),
        active_window_days: 7,
        audit_key: None,
        audit_head: Default::default(),
        allowlist_path: None,
        enroll: None,
        events_require_cert_host_match: false,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = build_router(Arc::new(state));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    url
}

/// The server's body for `path`, decoded with the server's own type.
async fn server_body<T: DeserializeOwned>(url: &str, path: &str) -> (T, Vec<u8>) {
    let resp = reqwest::Client::new()
        .get(format!("{url}{path}"))
        .bearer_auth(READ_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{path}");
    let bytes = resp.bytes().await.unwrap().to_vec();
    let typed = serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("{path}: the server's type does not decode its body: {e}"));
    (typed, bytes)
}

#[tokio::test]
async fn the_http_client_reads_every_endpoint_of_a_real_server() {
    let dir = TempDir(std::env::temp_dir().join(format!(
        "lodeline-manager-contract-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap()
    )));
    std::fs::create_dir_all(&dir.0).unwrap();
    let ids = seed(&dir.0);
    let url = serve(&dir.0).await;
    let client = HttpClient::new(&url, READ_TOKEN, None, http::TIMEOUT).unwrap();

    let event_path = format!("/v1/events/{}", ids[1]);
    let host_path = format!("/v1/fleet/hosts/{HOST_A}");
    let cases: Vec<(Request, String, Response)> = vec![
        {
            let (b, raw) = server_body::<api::Healthz>(&url, "/v1/healthz").await;
            (
                Request::Healthz,
                String::from_utf8(raw).unwrap(),
                Response::Healthz(healthz(b)),
            )
        },
        {
            let (b, raw) = server_body::<api::Meta>(&url, "/v1/meta").await;
            (
                Request::Meta,
                String::from_utf8(raw).unwrap(),
                Response::Meta(meta(b)),
            )
        },
        {
            let (b, raw) = server_body::<api::EventsPage>(&url, "/v1/events").await;
            let req = Request::Events(EventsParams::default());
            (
                req,
                String::from_utf8(raw).unwrap(),
                Response::Events(events_page(b)),
            )
        },
        {
            let (b, raw) = server_body::<Value>(&url, &event_path).await;
            let req = Request::EventById(ids[1].clone());
            (
                req,
                String::from_utf8(raw).unwrap(),
                Response::Event(event(b)),
            )
        },
        {
            let (b, raw) = server_body::<api::HostsPage>(&url, "/v1/fleet/hosts").await;
            let req = Request::Hosts(HostsParams::default());
            (
                req,
                String::from_utf8(raw).unwrap(),
                Response::Hosts(hosts_page(b)),
            )
        },
        {
            let (b, raw) = server_body::<api::HostDetail>(&url, &host_path).await;
            let req = Request::HostById(HOST_A.into());
            (
                req,
                String::from_utf8(raw).unwrap(),
                Response::Host(host_detail(b)),
            )
        },
        {
            let (b, raw) = server_body::<api::RowsPage<api::RiskRow>>(&url, "/v1/fleet/risk").await;
            let req = Request::Risk(RiskParams::default());
            (
                req,
                String::from_utf8(raw).unwrap(),
                Response::Risk(risk_page(b)),
            )
        },
        {
            let (b, raw) =
                server_body::<api::RowsPage<api::ComplianceRow>>(&url, "/v1/fleet/compliance")
                    .await;
            let req = Request::Compliance(ComplianceParams::default());
            (
                req,
                String::from_utf8(raw).unwrap(),
                Response::Compliance(compliance_page(b)),
            )
        },
    ];

    for (req, raw, from_server_types) in cases {
        let fetched = client.get(req.clone()).await;
        assert!(fetched.is_ok(), "{req:?}: {fetched:?}");
        let ours = http::decode(&req, raw.as_bytes()).unwrap();
        assert_eq!(
            serde_json::to_value(&ours).unwrap(),
            serde_json::to_value(&from_server_types).unwrap(),
            "{req:?}: the console reads the body differently from the server's types: {raw}"
        );
    }

    // The fixture reaches every block the console renders.
    let Response::Host(h) = &*client.get(Request::HostById(HOST_A.into())).await.unwrap() else {
        panic!("not a host")
    };
    assert!(h.host_meta.is_some() && h.summary.current_risk.is_some());
    let tools = h.ai_guard.as_ref().unwrap().by_tool.as_ref().unwrap();
    assert!(tools["claude_code"].controls.is_some() && tools["codex"].controls.is_none());
    let source = |s: &Option<Raw>, key: &str| s.as_ref().map(|s| s.member_str(key));
    let (claude, codex) = (&tools["claude_code"], &tools["codex"]);
    assert_eq!(source(&claude.source, "user").as_deref(), Some("alice"));
    assert_eq!(
        source(&claude.source, "rule_pack_id").as_deref(),
        Some("acme-extended")
    );
    assert_eq!(source(&codex.source, "user").as_deref(), Some(""));
    let codex_source = serde_json::to_value(codex.source.as_ref().unwrap()).unwrap();
    assert_eq!(
        codex_source.get("user"),
        Some(&Value::Null),
        "{codex_source}"
    );
    assert!(claude.unassessed_since.is_some() && codex.unassessed_since.is_none());
    let risk = h.summary.current_risk.as_ref().unwrap();
    assert_eq!(
        risk.by_tool.as_ref().unwrap()["claude_code"].unassessed_since,
        claude.unassessed_since
    );
    let failing = &h.summary.ai_guard_unassessed.as_ref().unwrap()["claude_code"];
    assert_eq!(failing.sources[0].user.as_deref(), Some("alice"));
    assert!(failing.last_assessed_ts.is_some());

    let Response::Hosts(hosts) = &*client
        .get(Request::Hosts(Default::default()))
        .await
        .unwrap()
    else {
        panic!("not hosts")
    };
    let b = hosts.hosts.as_ref().unwrap().iter();
    let b = b.clone().find(|h| h.host_id == HOST_B).unwrap();
    assert!(b.current_risk.is_none(), "failures alone give no score");
    let failing = &b.ai_guard_unassessed.as_ref().unwrap()["cursor"];
    assert_eq!(
        (failing.sources[0].user.as_ref(), failing.last_assessed_ts),
        (None, None)
    );
    let Response::Risk(risk) = &*client.get(Request::Risk(Default::default())).await.unwrap()
    else {
        panic!("not risk")
    };
    let rows = risk.rows.as_ref().unwrap();
    assert_eq!(rows.len(), 1, "host B has no reading, so no risk row");
    assert_eq!(rows[0].unassessed_since, claude.unassessed_since);
    assert_eq!(source(&rows[0].source, "user").as_deref(), Some("alice"));
    let Response::Events(page) = &*client
        .get(Request::Events(Default::default()))
        .await
        .unwrap()
    else {
        panic!("not events")
    };
    assert_eq!(page.events.as_ref().unwrap().len(), ids.len());
}

fn time(s: String) -> GoTime {
    GoTime::parse(&s).unwrap_or_else(|| panic!("{s:?} is not a time Go reads"))
}

fn healthz(b: api::Healthz) -> Healthz {
    let api::Healthz { status, ts } = b;
    Healthz {
        status,
        ts: time(ts),
    }
}

fn meta(b: api::Meta) -> Meta {
    let api::Meta {
        alerts_definition_default,
        audit_head,
        fleet,
        schema_version,
        server_version,
        ts,
    } = b;
    let api::AlertsDefinition {
        additional_kinds,
        ai_guard_buckets,
        evidence_kinds,
    } = alerts_definition_default;
    Meta {
        server_version,
        schema_version: schema_version.into(),
        ts: time(ts),
        alerts_definition_default: AlertsDefinitionDefault {
            evidence_kinds: Some(evidence_kinds),
            ai_guard_buckets: Some(ai_guard_buckets),
            additional_kinds: Some(additional_kinds),
        },
        fleet: fleet.map(
            |api::FleetSize {
                 active_host_count,
                 active_window_days,
             }| {
                ActiveHosts {
                    active_host_count: active_host_count.into(),
                    active_window_days: active_window_days.into(),
                }
            },
        ),
        audit_head: audit_head.map(
            |api::AuditHead {
                 hash,
                 pubkey,
                 pubkey_id,
                 seq,
                 sig,
             }| AuditHead {
                seq: seq as i64,
                hash,
                sig,
                pubkey_id,
                pubkey: pubkey.unwrap_or_default(),
            },
        ),
    }
}

fn event(v: Value) -> Event {
    const GO_FIELDS: [&str; 10] = [
        "schema_version",
        "event_id",
        "ts",
        "host_id",
        "agent_version",
        "severity",
        "source",
        "subject",
        "evidence",
        "target_id",
    ];
    for key in GO_FIELDS {
        assert!(v.get(key).is_some(), "the server's event has no {key}: {v}");
    }
    go_decode(&serde_json::value::to_raw_value(&v).unwrap()).unwrap()
}

fn raw(v: Value) -> Raw {
    serde_json::from_str(&v.to_string()).unwrap()
}

fn events_page(b: api::EventsPage) -> EventsPage {
    let api::EventsPage {
        events,
        next_cursor,
    } = b;
    EventsPage {
        events: Some(events.into_iter().map(event).collect()),
        next_cursor,
    }
}

fn counts(c: api::EventCounts) -> Option<std::collections::BTreeMap<String, i64>> {
    let api::EventCounts { info, warn } = c;
    Some([("info".into(), info.into()), ("warn".into(), warn.into())].into())
}

fn current_risk(r: api::CurrentRisk) -> CurrentRisk {
    let api::CurrentRisk {
        by_tool,
        max_bucket,
        max_score,
    } = r;
    CurrentRisk {
        max_score,
        max_bucket,
        by_tool: Some(
            by_tool
                .into_iter()
                .map(
                    |(
                        tool,
                        api::ToolRisk {
                            assessed_ts,
                            bucket,
                            score,
                            source,
                            unassessed_since,
                        },
                    )| {
                        let ts = time(assessed_ts);
                        (
                            tool,
                            ToolRisk {
                                score,
                                bucket,
                                assessed_ts: ts,
                                source: source.map(risk_source),
                                unassessed_since: unassessed_since.map(time),
                            },
                        )
                    },
                )
                .collect(),
        ),
    }
}

fn hosts_page(b: api::HostsPage) -> HostsPage {
    let api::HostsPage {
        hosts,
        next_cursor,
        total_estimated,
    } = b;
    let hosts = hosts
        .into_iter()
        .map(
            |api::HostListItem {
                 agent_version,
                 ai_guard_unassessed,
                 current_risk: risk,
                 host_id,
                 hostname,
                 last_seen_ts,
                 open_event_counts_24h,
                 status,
             }| HostSummary {
                host_id,
                hostname,
                agent_version,
                last_seen_ts: last_seen_ts.map(time).unwrap_or_default(),
                status,
                current_risk: risk.map(current_risk),
                open_event_counts_24h: counts(open_event_counts_24h),
                ai_guard_unassessed: ai_guard_unassessed.map(unassessed),
            },
        )
        .collect();
    HostsPage {
        hosts: Some(hosts),
        next_cursor,
        total_estimated: total_estimated as i64,
    }
}

fn host_detail(b: api::HostDetail) -> HostDetail {
    let api::HostDetail {
        agent_health,
        agent_version,
        ai_guard,
        ai_guard_unassessed,
        current_risk: risk,
        host_id,
        host_meta,
        hostname,
        last_seen_ts,
        open_event_counts_24h,
        policy_state,
        status,
    } = b;
    let api::AgentHealth {
        hash_p99_ms_latest,
        jsonl_above_soft_floor_latest,
        last_heartbeat_ts,
        recent_channel_stalls_24h,
        recent_sender_lag_critical_24h,
        recent_watcher_degraded_24h,
    } = agent_health;
    let api::PolicyState {
        last_applied_policy_version,
        last_policy_reload_ts,
        policy_expired_active,
    } = policy_state;
    let api::AiGuard { by_tool } = ai_guard;
    HostDetail {
        summary: HostSummary {
            host_id,
            hostname,
            agent_version,
            last_seen_ts: last_seen_ts.map(time).unwrap_or_default(),
            status,
            current_risk: risk.map(current_risk),
            open_event_counts_24h: counts(open_event_counts_24h),
            ai_guard_unassessed: ai_guard_unassessed.map(unassessed),
        },
        host_meta: host_meta.map(
            |api::HostMeta {
                 architecture,
                 default_gateway_v4,
                 default_gateway_v6,
                 dns_servers,
                 // Go's console type has no hostname here; the summary carries it.
                 hostname: _,
                 interfaces,
                 kernel_version,
                 os_name,
                 os_version,
             }| HostMeta {
                os_name: os_name.unwrap_or_default(),
                os_version: os_version.unwrap_or_default(),
                kernel_version: kernel_version.unwrap_or_default(),
                architecture: architecture.unwrap_or_default(),
                interfaces: Some(
                    interfaces
                        .into_iter()
                        .map(
                            |api::NetworkInterface {
                                 ipv4,
                                 ipv6,
                                 mac,
                                 name,
                             }| NetInterface {
                                name,
                                mac: mac.unwrap_or_default(),
                                ipv4: Some(ipv4),
                                ipv6: Some(ipv6),
                            },
                        )
                        .collect(),
                ),
                default_gateway_v4,
                default_gateway_v6,
                dns_servers: Some(dns_servers),
            },
        ),
        policy_state: Some(PolicyState {
            last_applied_policy_version,
            policy_expired_active,
            last_policy_reload_ts: last_policy_reload_ts.map(time),
        }),
        agent_health: Some(AgentHealth {
            recent_channel_stalls_24h: recent_channel_stalls_24h.into(),
            recent_watcher_degraded_24h: recent_watcher_degraded_24h.into(),
            recent_sender_lag_critical_24h: recent_sender_lag_critical_24h.into(),
            last_heartbeat_ts: last_heartbeat_ts.map(time),
            hash_p99_ms_latest: hash_p99_ms_latest.map(i64::from),
            jsonl_above_soft_floor_latest,
        }),
        ai_guard: Some(AiGuard {
            by_tool: Some(
                by_tool
                    .into_iter()
                    .map(|(tool, a)| (tool, assessment(a)))
                    .collect(),
            ),
        }),
    }
}

fn assessment(a: api::AiGuardAssessment) -> ToolAiGuard {
    let api::AiGuardAssessment {
        assessed_ts,
        bucket,
        controls,
        is_reattestation,
        reasons,
        scope,
        score,
        source,
        unassessed_since,
    } = a;
    ToolAiGuard {
        controls: controls.map(|cs| {
            cs.into_iter()
                .map(
                    |api::AiGuardControl {
                         id,
                         setting,
                         source_path,
                         value,
                     }| AiGuardControl {
                        id,
                        source_path,
                        setting,
                        value: raw(value),
                    },
                )
                .collect()
        }),
        score,
        bucket,
        assessed_ts: time(assessed_ts),
        is_reattestation,
        scope: raw(scope),
        reasons: Some(reasons.into_iter().map(raw).collect()),
        source: source.map(risk_source),
        unassessed_since: unassessed_since.map(time),
    }
}

fn risk_source(s: api::RiskSource) -> Raw {
    let api::RiskSource {
        rule_pack_id,
        scope,
        tool_label,
        user,
    } = s;
    raw(
        json!({"rule_pack_id": rule_pack_id, "scope": scope, "tool_label": tool_label,
        "user": user}),
    )
}

fn unassessed(
    by_tool: std::collections::BTreeMap<String, api::ToolUnassessed>,
) -> std::collections::BTreeMap<String, ToolUnassessed> {
    by_tool
        .into_iter()
        .map(
            |(
                tool,
                api::ToolUnassessed {
                    last_assessed_ts,
                    since,
                    sources,
                },
            )| {
                let sources = sources
                    .into_iter()
                    .map(
                        |api::UnassessedSource {
                             error_kind,
                             path,
                             rule_pack_id,
                             scope,
                             user,
                         }| UnassessedSource {
                            scope: raw(scope),
                            user,
                            rule_pack_id,
                            error_kind,
                            path,
                        },
                    )
                    .collect();
                let t = ToolUnassessed {
                    since: time(since),
                    last_assessed_ts: last_assessed_ts.map(time),
                    sources,
                };
                (tool, t)
            },
        )
        .collect()
}

fn risk_page(b: api::RowsPage<api::RiskRow>) -> RiskPage {
    let api::RowsPage { next_cursor, rows } = b;
    let rows = rows
        .into_iter()
        .map(
            |api::RiskRow {
                 assessed_ts,
                 bucket,
                 host_id,
                 hostname,
                 open_alert_count_24h,
                 reasons_count,
                 score,
                 source,
                 top_tool,
                 unassessed_since,
             }| RiskRow {
                host_id,
                hostname,
                score,
                bucket,
                top_tool,
                reasons_count: reasons_count as i64,
                assessed_ts: time(assessed_ts),
                open_alert_count_24h: open_alert_count_24h.into(),
                source: source.map(risk_source),
                unassessed_since: unassessed_since.map(time),
            },
        )
        .collect();
    RiskPage {
        rows: Some(rows),
        next_cursor,
    }
}

fn compliance_page(b: api::RowsPage<api::ComplianceRow>) -> CompliancePage {
    let api::RowsPage { next_cursor, rows } = b;
    let rows = rows
        .into_iter()
        .map(
            |api::ComplianceRow {
                 host_id,
                 hostname,
                 last_applied_policy_version,
                 last_policy_reload_ts,
                 policy_expired_active,
                 server_current_policy_version,
                 signature_failures_24h,
                 version_drift,
             }| ComplianceRow {
                host_id,
                hostname,
                last_applied_policy_version,
                // Go's console type is a plain int, so a server without a bundle reads as 0.
                server_current_policy_version: server_current_policy_version.unwrap_or(0),
                version_drift,
                policy_expired_active,
                last_policy_reload_ts: last_policy_reload_ts.map(time),
                signature_failures_24h: signature_failures_24h.into(),
            },
        )
        .collect();
    CompliancePage {
        rows: Some(rows),
        next_cursor,
    }
}
