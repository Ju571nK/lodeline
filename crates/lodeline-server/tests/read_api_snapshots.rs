//! Byte-level snapshots of every read API response: the status line plus the
//! raw body, before any re-serialization, so key order, `null` versus absent
//! and float formatting are all pinned. Values that change per run (event IDs,
//! timestamps relative to now, the server version) are replaced by fixed tokens.
use axum::body::Body;
use axum::http::{header, Request};
use axum::middleware::from_fn_with_state;
use axum::Router;
use lodeline_server::app::{boot_gate, build_router, AppState};
use lodeline_server::auth::ReadToken;
use lodeline_server::fleet_index::FleetIndex;
use lodeline_server::persist::HighWater;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use time::{Duration, OffsetDateTime};
use tower::ServiceExt;

const HA: &str = "0190b8a0-0000-7000-8000-00000000000a";
const HB: &str = "0190b8a0-0000-7000-8000-00000000000b";
const HC: &str = "0190b8a0-0000-7000-8000-00000000000c";

fn state(dir: &Path) -> AppState {
    AppState {
        events_out_dir: dir.to_path_buf(),
        policy_bundle_path: dir.join("signed-policy.json"),
        high_water_path: dir.join(".high-water.json"),
        allowlist: parking_lot::RwLock::new(None::<HashSet<String>>),
        high_water: Mutex::new(HighWater::default()),
        fleet_index: FleetIndex::new(),
        read_token: ReadToken(Some("tok".into())),
        active_window_days: 7,
        audit_key: None,
        rule_packs_bundle_path: None,
        artifacts_dir: None,
        audit_head: Mutex::new(None),
        allowlist_path: None,
        enroll: None,
        events_require_cert_host_match: false,
    }
}

fn rfc3339(t: OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

/// Replaces each run-specific value with its token, so the snapshot is stable.
struct Redactions(Vec<(String, String)>);

impl Redactions {
    fn apply(&self, mut s: String) -> String {
        for (from, to) in &self.0 {
            s = s.replace(from.as_str(), to);
        }
        s
    }
}

async fn call(app: &Router, path: &str, token: Option<&str>, r: &Redactions) -> String {
    let mut b = Request::builder().method("GET").uri(path);
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let resp = app
        .clone()
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let mut body = String::from_utf8(bytes.to_vec()).unwrap();
    // `ts` on /v1/healthz and /v1/meta is the server clock at request time.
    let clock_ts = path == "/v1/healthz" || path == "/v1/meta";
    if let (true, Ok(Value::Object(m))) = (clock_ts, serde_json::from_str::<Value>(&body)) {
        if let Some(Value::String(ts)) = m.get("ts") {
            body = body.replace(&format!("\"ts\":\"{ts}\""), "\"ts\":\"[request time]\"");
        }
    }
    body = body.replace(
        &format!("\"server_version\":\"{}\"", env!("CARGO_PKG_VERSION")),
        "\"server_version\":\"[server version]\"",
    );
    format!("{}\n{}", status.as_u16(), r.apply(body))
}

/// A three-host fleet ingested through `POST /v1/events`: host A has a host
/// meta snapshot, two tools with risk, a heartbeat, a policy reload and agent
/// health signals; host B has one warn event 30 minutes ago; host C has one
/// medium risk reading 3 hours ago.
async fn populated(dir: &Path) -> (Router, Redactions) {
    std::fs::write(
        dir.join("signed-policy.json"),
        json!({"policy_version": 4, "signing_pubkey_id": "k1",
               "signed_at": "2026-10-01T00:00:00Z", "valid_until": "2026-12-01T00:00:00Z",
               "payload": "unused"})
        .to_string(),
    )
    .unwrap();
    let app = build_router(Arc::new(state(dir)));
    let now = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
    let mut red = Vec::new();
    let mut ts = |minutes: i64| {
        let s = rfc3339(now - Duration::minutes(minutes));
        red.push((s.clone(), format!("[now-{minutes}m]")));
        s
    };
    let (t1, t2, t30, t180) = (ts(1), ts(2), ts(30), ts(180));

    let per_host = vec![
        (
            HA,
            vec![
                (
                    &t2,
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
                    &t1,
                    "warn",
                    json!({"kind": "ai_guard_risk_assessed", "tool": "claude_code",
                    "scope": {"kind": "user_global"}, "score": 7.3, "bucket": "critical",
                    "reasons": [
                        {"kind": "destructive_in_inline_command", "pattern": "rm -rf",
                            "hook_event": "PreToolUse", "snippet": "rm -rf /"},
                        {"kind": "external_script_unscanned", "hook_event": "PostToolUse",
                            "script_path": "/opt/hooks/x.sh"}],
                    "controls": [{"id": "fixture.restricted", "source_path": "/fixture/config",
                        "setting": "restricted", "value": true}],
                    "is_reattestation": false}),
                ),
                (
                    &t1,
                    "warn",
                    json!({"kind": "ai_guard_risk_assessed", "tool": "codex",
                    "scope": {"kind": "project", "path": "/fixture/repo"}, "score": 2.1,
                    "bucket": "medium", "reasons": [{"kind": "permissions_deny_empty"}],
                    "is_reattestation": false}),
                ),
                (
                    &t1,
                    "info",
                    json!({"kind": "heartbeat", "uptime_s": 60, "is_final": false,
                    "channel_stall_events_total": 0, "events_emitted_total": 9,
                    "events_by_kind": {}, "hash_p50_ms": 1, "hash_p99_ms": 4,
                    "watcher_backend": "fsevents", "state_db_size_bytes": 4096,
                    "last_log_rotation_ts": null, "last_applied_policy_version": 3,
                    "policy_expired_active": false, "jsonl_above_soft_floor": false}),
                ),
                (
                    &t1,
                    "info",
                    json!({"kind": "policy_reloaded", "policy_version": 3}),
                ),
                (
                    &t1,
                    "warn",
                    json!({"kind": "policy_signature_invalid",
                    "reason": "signature_invalid", "signing_pubkey_id": "k0",
                    "policy_version_in_envelope": 9, "last_applied_policy_version": 3}),
                ),
                (
                    &t1,
                    "warn",
                    json!({"kind": "channel_stall", "channel": "events",
                    "blocked_seconds_in_window": 1.5, "block_events_in_window": 2,
                    "first_block_ts": t1}),
                ),
                (
                    &t1,
                    "warn",
                    json!({"kind": "watcher_degraded", "from": "fsevents",
                    "to": "poll", "reason": "fixture"}),
                ),
            ],
        ),
        (
            HB,
            vec![(
                &t30,
                "warn",
                json!({"kind": "host_id_conflict", "observed_status": 409}),
            )],
        ),
        (
            HC,
            vec![(
                &t180,
                "info",
                json!({"kind": "ai_guard_risk_assessed", "tool": "continue_dev",
                "scope": {"kind": "application", "app": "continue"}, "score": 1.3,
                "bucket": "medium", "reasons": [], "is_reattestation": false}),
            )],
        ),
    ];

    let mut n = 0;
    for (host, events) in per_host {
        let entries: Vec<Value> = events
            .into_iter()
            .enumerate()
            .map(|(i, (ts, severity, evidence))| {
                let id = uuid::Uuid::now_v7();
                n += 1;
                red.push((id.to_string(), format!("[event-{n}]")));
                let payload = json!({"schema_version": 1, "event_id": id, "ts": ts,
                    "host_id": host, "agent_version": "fixture-agent", "severity": severity,
                    "source": {"kind": "agent"}, "subject": {"kind": "self"},
                    "evidence": evidence, "target_id": null});
                serde_json::from_value::<lodeline_core::event::Event>(payload.clone())
                    .expect("fixture is a valid event");
                json!({"event_id": id, "sequence": i + 1, "payload": payload})
            })
            .collect();
        let count = entries.len();
        let body = json!({"envelope": {"host_id": host, "schema_version": 1}, "events": entries});
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/events")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let ack: Value = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(ack["accepted"].as_array().unwrap().len(), count, "{ack}");
    }
    (app, Redactions(red))
}

#[tokio::test]
async fn populated_fleet_bodies() {
    let dir = tempfile::tempdir().unwrap();
    let (app, r) = populated(dir.path()).await;
    let first_event =
        r.0.iter()
            .find(|(_, t)| t == "[event-2]")
            .unwrap()
            .0
            .clone();
    let cases = [
        ("healthz", "/v1/healthz".to_string()),
        ("meta", "/v1/meta".to_string()),
        ("policy_meta", "/v1/policy/meta".to_string()),
        ("hosts", "/v1/fleet/hosts".to_string()),
        ("hosts_page_1", "/v1/fleet/hosts?limit=1&sort=host_id".to_string()),
        ("hosts_page_2", format!("/v1/fleet/hosts?limit=1&sort=host_id&cursor={HA}")),
        ("hosts_sort_risk", "/v1/fleet/hosts?sort=risk".to_string()),
        ("hosts_status_stale", "/v1/fleet/hosts?status=stale".to_string()),
        ("hosts_bucket_filter", "/v1/fleet/hosts?bucket=low,medium".to_string()),
        ("host_detail_full", format!("/v1/fleet/hosts/{HA}")),
        ("host_detail_sparse", format!("/v1/fleet/hosts/{HB}")),
        ("host_detail_risk_only", format!("/v1/fleet/hosts/{HC}")),
        ("risk", "/v1/fleet/risk".to_string()),
        ("risk_page_1", "/v1/fleet/risk?limit=1".to_string()),
        ("risk_page_2", format!("/v1/fleet/risk?limit=1&cursor={HA}")),
        ("risk_tool_filter", "/v1/fleet/risk?tool=codex,continue_dev".to_string()),
        ("risk_min_bucket", "/v1/fleet/risk?min_bucket=high".to_string()),
        ("compliance", "/v1/fleet/compliance".to_string()),
        ("compliance_page_1", "/v1/fleet/compliance?limit=2".to_string()),
        ("compliance_page_2", format!("/v1/fleet/compliance?limit=2&cursor={HB}")),
        // Every host writes to a file with the same date, and the scan orders
        // those by directory listing, which differs by OS. One host per query.
        ("events_page_1", format!("/v1/events?limit=3&host_id={HA}")),
        ("events_host_filter", format!("/v1/events?host_id={HB}")),
        ("events_kind_filter", format!("/v1/events?host_id={HA}&evidence_kind=ai_guard_risk_assessed&min_ai_guard_bucket=medium")),
        ("event_by_id", format!("/v1/events/{first_event}")),
    ];
    for (name, path) in &cases {
        insta::assert_snapshot!(*name, call(&app, path, Some("tok"), &r).await);
    }
    // Page 2 of the events walk starts from page 1's cursor.
    let page_1: Value = serde_json::from_str(
        call(
            &app,
            &format!("/v1/events?limit=3&host_id={HA}"),
            Some("tok"),
            &Redactions(vec![]),
        )
        .await
        .split_once('\n')
        .unwrap()
        .1,
    )
    .unwrap();
    let cursor = page_1["next_cursor"].as_str().unwrap();
    insta::assert_snapshot!(
        "events_page_2",
        call(
            &app,
            &format!("/v1/events?limit=3&host_id={HA}&cursor={cursor}"),
            Some("tok"),
            &r
        )
        .await
    );
}

#[tokio::test]
async fn empty_fleet_bodies() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(Arc::new(state(dir.path())));
    let r = Redactions(vec![]);
    for (name, path) in [
        ("empty_meta", "/v1/meta"),
        ("empty_hosts", "/v1/fleet/hosts"),
        ("empty_risk", "/v1/fleet/risk"),
        ("empty_compliance", "/v1/fleet/compliance"),
        ("empty_events", "/v1/events"),
    ] {
        insta::assert_snapshot!(name, call(&app, path, Some("tok"), &r).await);
    }
}

#[tokio::test]
async fn meta_audit_head_bodies() {
    use lodeline_core::audit::AuditHead;
    use lodeline_server::audit_key::AuditKey;
    let head = AuditHead {
        seq: 42,
        hash: "fixture-hash".into(),
        sig: "fixture-sig".into(),
        pubkey_id: "key-1".into(),
    };
    for (name, key_id) in [
        ("meta_audit_head_own_key", "key-1"),
        ("meta_audit_head_other_key", "key-2"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut s = state(dir.path());
        s.audit_head = Mutex::new(Some(head.clone()));
        s.audit_key = Some(AuditKey {
            signing_key: ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]),
            pubkey_id: key_id.into(),
            pubkey_b64: "fixture-pubkey".into(),
        });
        let app = build_router(Arc::new(s));
        insta::assert_snapshot!(
            name,
            call(&app, "/v1/meta", Some("tok"), &Redactions(vec![])).await
        );
    }
}

#[tokio::test]
async fn policy_meta_bodies() {
    let r = Redactions(vec![]);
    let cases: [(&str, Option<&[u8]>); 4] = [
        ("policy_meta_missing_keys", Some(br#"{"policy_version":2}"#)),
        ("policy_meta_odd_types", Some(br#"{"policy_version":"2","signed_at":7,"valid_until":{"a":1},"signing_pubkey_id":null}"#)),
        ("error_policy_meta_no_bundle", None),
        ("error_policy_meta_parse", Some(b"not json")),
    ];
    for (name, bundle) in cases {
        let dir = tempfile::tempdir().unwrap();
        if let Some(b) = bundle {
            std::fs::write(dir.path().join("signed-policy.json"), b).unwrap();
        }
        let app = build_router(Arc::new(state(dir.path())));
        insta::assert_snapshot!(name, call(&app, "/v1/policy/meta", Some("tok"), &r).await);
    }
    // A directory at the bundle path fails the read with an error other than NotFound.
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("signed-policy.json")).unwrap();
    let app = build_router(Arc::new(state(dir.path())));
    insta::assert_snapshot!(
        "error_policy_meta_read",
        call(&app, "/v1/policy/meta", Some("tok"), &r).await
    );
}

#[tokio::test]
async fn error_bodies() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(Arc::new(state(dir.path())));
    let r = Redactions(vec![]);
    for (name, path, token) in [
        ("error_missing_token", "/v1/meta", None),
        ("error_wrong_token", "/v1/fleet/hosts", Some("nope")),
        (
            "error_host_not_found",
            "/v1/fleet/hosts/no-such",
            Some("tok"),
        ),
        ("error_events_cursor", "/v1/events?cursor=x", Some("tok")),
        (
            "error_events_since",
            "/v1/events?since=yesterday",
            Some("tok"),
        ),
        (
            "error_events_until",
            "/v1/events?until=tomorrow",
            Some("tok"),
        ),
        ("error_event_id", "/v1/events/not-a-uuid", Some("tok")),
        (
            "error_event_not_found",
            "/v1/events/0190b8a0-0000-7000-8000-000000000000",
            Some("tok"),
        ),
        (
            "error_query_rejected",
            "/v1/fleet/hosts?limit=abc",
            Some("tok"),
        ),
    ] {
        insta::assert_snapshot!(name, call(&app, path, token, &r).await);
    }

    let mut s = state(dir.path());
    s.read_token = ReadToken(None);
    let hidden = build_router(Arc::new(s));
    insta::assert_snapshot!(
        "error_read_api_hidden",
        call(&hidden, "/v1/fleet/risk", Some("tok"), &r).await
    );

    let booting = build_router(Arc::new(state(dir.path()))).layer(from_fn_with_state(
        Arc::new(AtomicBool::new(false)),
        boot_gate,
    ));
    insta::assert_snapshot!(
        "error_rebuilding",
        call(&booting, "/v1/meta", Some("tok"), &r).await
    );
}
