//! Happy-path coverage for the 9 read endpoints.
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use lodeline_server::app::{build_router, AppState};
use lodeline_server::auth::ReadToken;
use lodeline_server::fleet_index::FleetIndex;
use lodeline_server::persist::HighWater;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

fn state_with_token(dir: &std::path::Path, token: &str) -> Arc<AppState> {
    Arc::new(AppState {
        events_out_dir: dir.to_path_buf(),
        policy_bundle_path: dir.join("signed-policy.json"),
        high_water_path: dir.join(".high-water.json"),
        allowlist: parking_lot::RwLock::new(None::<HashSet<String>>),
        high_water: Mutex::new(HighWater::default()),
        fleet_index: FleetIndex::new(),
        read_token: ReadToken(Some(token.into())),
        active_window_days: 7,
        audit_key: None,
        rule_packs_bundle_path: None,
        artifacts_dir: None,
        audit_head: Mutex::new(None),
        allowlist_path: None,
        enroll: None,
        events_require_cert_host_match: false,
    })
}

async fn get(
    app: &axum::Router,
    path: &str,
    token: Option<&str>,
) -> (StatusCode, serde_json::Value) {
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
    let v = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, v)
}

#[tokio::test]
async fn healthz_returns_ok_without_auth() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state_with_token(dir.path(), "tok"));
    let (status, body) = get(&app, "/v1/healthz", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn controls_survive_ingest_replay_and_scope_replacement() {
    use lodeline_core::event::{AiGuardScope, Event};
    use serde_json::json;
    let dir = tempfile::tempdir().unwrap();
    let state = state_with_token(dir.path(), "tok");
    let app = build_router(state.clone());
    let host = uuid::Uuid::now_v7().to_string();
    let controls = json!([{"id":"future.restricted", "setting":"restricted", "value":true, "source_path":"/fixture/config"}]);
    for (i, observed) in [controls.clone(), json!([]), serde_json::Value::Null]
        .into_iter()
        .enumerate()
    {
        let scope = if i == 0 {
            AiGuardScope::UserGlobal
        } else {
            AiGuardScope::Project {
                path: "/fixture/repo".into(),
            }
        };
        let id = uuid::Uuid::now_v7();
        let mut payload = json!({
            "schema_version":1, "event_id":id,
            "ts": time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap(),
            "host_id":host, "agent_version":"fixture", "severity":"warn",
            "source":{"kind":"agent"}, "subject":{"kind":"self"},
            "evidence":{"kind":"ai_guard_risk_assessed", "tool":"codex", "scope":scope,
                "score":0.0, "bucket":"low", "reasons":[], "is_reattestation":false}
        });
        if !observed.is_null() {
            payload["evidence"]["controls"] = observed.clone();
        }
        // Also pin decoding of historical events without the new field.
        serde_json::from_value::<Event>(payload.clone()).unwrap();
        let body = json!({"envelope":{"host_id":host,"schema_version":1}, "events":[{"event_id":id,"sequence":i+1,"payload":payload}]});
        let response = app
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
        assert_eq!(response.status(), StatusCode::OK);
        let ack: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(ack["accepted"].as_array().unwrap().len(), 1, "{ack}");
        for replay in [false, true] {
            if replay {
                state.fleet_index.replace(
                    lodeline_server::boot_rebuild::rebuild_from_jsonl(dir.path()).unwrap(),
                );
            }
            let (status, detail) = get(&app, &format!("/v1/fleet/hosts/{host}"), Some("tok")).await;
            assert_eq!(status, StatusCode::OK);
            let entry = &detail["ai_guard"]["by_tool"]["codex"];
            assert_eq!(entry["controls"], observed);
            assert_eq!(entry["scope"], json!(scope));
            assert_eq!(entry["score"], 0.0);
        }
    }
    let (_, history) = get(&app, &format!("/v1/events?host_id={host}"), Some("tok")).await;
    assert!(history["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["evidence"]["controls"] == controls));
}

#[tokio::test]
async fn resent_events_count_once_live_and_after_rebuild() {
    use serde_json::json;
    let dir = tempfile::tempdir().unwrap();
    let state = state_with_token(dir.path(), "tok");
    let app = build_router(state.clone());
    let host = uuid::Uuid::now_v7().to_string();
    let ts = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let entries: Vec<serde_json::Value> = (1..=3u64)
        .map(|seq| {
            let id = uuid::Uuid::now_v7();
            json!({"event_id":id, "sequence":seq, "payload":{
                "schema_version":1, "event_id":id, "ts":ts,
                "host_id":host, "agent_version":"fixture", "severity":"warn",
                "source":{"kind":"agent"}, "subject":{"kind":"self"},
                "evidence":{"kind":"ai_guard_risk_assessed", "tool":"codex",
                    "scope":{"kind":"user_global"}, "score":0.0, "bucket":"low",
                    "reasons":[], "is_reattestation":false}
            }})
        })
        .collect();
    // First send, an exact resend, then a batch that overlaps by one.
    for batch in [&entries[0..2], &entries[0..2], &entries[1..3]] {
        let body = json!({"envelope":{"host_id":host,"schema_version":1}, "events":batch});
        let response = app
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
        assert_eq!(response.status(), StatusCode::OK);
        let ack: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(ack["accepted"].as_array().unwrap().len(), 2, "{ack}");
    }
    let path = format!("/v1/fleet/hosts/{host}");
    let (_, live) = get(&app, &path, Some("tok")).await;
    state
        .fleet_index
        .replace(lodeline_server::boot_rebuild::rebuild_from_jsonl(dir.path()).unwrap());
    let (_, rebuilt) = get(&app, &path, Some("tok")).await;
    assert_eq!(rebuilt["open_event_counts_24h"]["warn"], 3, "{rebuilt}");
    assert_eq!(
        live["open_event_counts_24h"], rebuilt["open_event_counts_24h"],
        "live index must match a rebuild of the same stored events"
    );
}

#[tokio::test]
async fn risk_source_names_the_newest_top_reading_live_and_after_rebuild() {
    use serde_json::json;
    let dir = tempfile::tempdir().unwrap();
    let state = state_with_token(dir.path(), "tok");
    let app = build_router(state.clone());
    let now = time::OffsetDateTime::now_utc();
    let ts = |mins: i64| {
        (now - time::Duration::minutes(mins))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    };
    let reading = |tool: &str, score: f64, bucket: &str, ts: String, extra: serde_json::Value| {
        let mut evidence = json!({"kind":"ai_guard_risk_assessed", "tool":tool,
            "scope":{"kind":"user_global"}, "score":score, "bucket":bucket,
            "reasons":[], "is_reattestation":false});
        evidence
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        (ts, evidence)
    };
    let older = reading(
        "claude_code",
        7.5,
        "critical",
        ts(3),
        json!({"user":"alice", "rule_pack_id":"acme-extended"}),
    );
    let newer = reading("claude_code", 7.5, "critical", ts(2), json!({"user":"bob"}));
    let own_home_lower = reading("claude_code", 2.0, "medium", ts(1), json!({}));
    let other_tool = reading(
        "other",
        0.5,
        "low",
        ts(1),
        json!({"rule_pack_id":"acme-extended", "tool_label":"Acme CLI"}),
    );
    // The newest of the tied top readings must win whichever arrives first.
    let newer_first = uuid::Uuid::now_v7().to_string();
    let older_first = uuid::Uuid::now_v7().to_string();
    for (host, readings) in [
        (&newer_first, [&newer, &older, &own_home_lower, &other_tool]),
        (&older_first, [&older, &newer, &own_home_lower, &other_tool]),
    ] {
        let events: Vec<serde_json::Value> = readings
            .iter()
            .enumerate()
            .map(|(i, (ts, evidence))| {
                let id = uuid::Uuid::now_v7();
                json!({"event_id":id, "sequence":i+1, "payload":{
                    "schema_version":1, "event_id":id, "ts":ts,
                    "host_id":host, "agent_version":"fixture", "severity":"warn",
                    "source":{"kind":"agent"}, "subject":{"kind":"self"},
                    "evidence":evidence}})
            })
            .collect();
        let body = json!({"envelope":{"host_id":host,"schema_version":1}, "events":events});
        let response = app
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
        assert_eq!(response.status(), StatusCode::OK);
    }

    let bob = json!({"scope":{"kind":"user_global"}, "user":"bob",
        "rule_pack_id":null, "tool_label":null});
    let labelled = json!({"scope":{"kind":"user_global"}, "user":null,
        "rule_pack_id":"acme-extended", "tool_label":"Acme CLI"});
    let paths = [
        "/v1/fleet/hosts?sort=host_id".to_string(),
        format!("/v1/fleet/hosts/{newer_first}"),
        format!("/v1/fleet/hosts/{older_first}"),
        "/v1/fleet/risk".to_string(),
    ];
    let mut live = Vec::new();
    for path in &paths {
        live.push(get_rows_by_host(&app, path).await);
    }
    let hosts = live[0]["hosts"].as_array().unwrap();
    assert_eq!(hosts.len(), 2);
    for h in hosts {
        let by_tool = &h["current_risk"]["by_tool"];
        assert_eq!(by_tool["claude_code"]["source"], bob, "{h}");
        assert_eq!(by_tool["other"]["source"], labelled, "{h}");
    }
    for detail in &live[1..3] {
        let by_tool = &detail["ai_guard"]["by_tool"];
        assert_eq!(by_tool["claude_code"]["source"], bob, "{detail}");
        assert_eq!(by_tool["other"]["source"], labelled, "{detail}");
    }
    let rows = live[3]["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    for row in rows {
        assert_eq!(row["top_tool"], "claude_code", "{row}");
        assert_eq!(row["source"], bob, "{row}");
    }

    state
        .fleet_index
        .replace(lodeline_server::boot_rebuild::rebuild_from_jsonl(dir.path()).unwrap());
    for (path, live) in paths.iter().zip(&live) {
        let rebuilt = get_rows_by_host(&app, path).await;
        assert_eq!(&rebuilt, live, "{path}: a rebuild must match live ingest");
    }
}

/// `get` with `rows` sorted by host, since risk rows that tie have no fixed order.
async fn get_rows_by_host(app: &axum::Router, path: &str) -> serde_json::Value {
    let (status, mut body) = get(app, path, Some("tok")).await;
    assert_eq!(status, StatusCode::OK, "{path}: {body}");
    if let Some(rows) = body["rows"].as_array_mut() {
        rows.sort_by_key(|r| r["host_id"].as_str().unwrap().to_string());
    }
    body
}

#[tokio::test]
async fn meta_returns_alerts_default() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state_with_token(dir.path(), "tok"));
    let (status, body) = get(&app, "/v1/meta", Some("tok")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["alerts_definition_default"]["evidence_kinds"][0],
        "ai_guard_risk_assessed"
    );
}

#[tokio::test]
async fn fleet_hosts_empty_index_returns_empty_list() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state_with_token(dir.path(), "tok"));
    let (status, body) = get(&app, "/v1/fleet/hosts", Some("tok")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["hosts"].as_array().unwrap().is_empty());
    assert_eq!(body["total_estimated"], 0);
}

#[tokio::test]
async fn fleet_risk_empty_returns_empty_rows() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state_with_token(dir.path(), "tok"));
    let (status, body) = get(&app, "/v1/fleet/risk", Some("tok")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["rows"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn fleet_compliance_empty_returns_empty_rows() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state_with_token(dir.path(), "tok"));
    let (status, body) = get(&app, "/v1/fleet/compliance", Some("tok")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["rows"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn events_empty_returns_empty_list() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state_with_token(dir.path(), "tok"));
    let (status, body) = get(&app, "/v1/events", Some("tok")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["events"].as_array().unwrap().is_empty());
    assert!(body["next_cursor"].is_null());
}

#[tokio::test]
async fn events_host_id_filter_does_not_400() {
    // #73: a host_id filter (single or comma-separated) must deserialize and
    // return 200 — the old `Vec<String>` field made serde_urlencoded reject it
    // with "expected a sequence" → HTTP 400, breaking the MCP query_events tool.
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state_with_token(dir.path(), "tok"));

    let (status, body) = get(
        &app,
        "/v1/events?host_id=4376ef7a-4fac-4644-b4cf-128fc471f783&limit=100",
        Some("tok"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "single host_id must not 400: {body}"
    );
    assert!(body["events"].as_array().unwrap().is_empty());

    let (status, body) = get(&app, "/v1/events?host_id=h1,h2&limit=100", Some("tok")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "comma-separated host_id must not 400: {body}"
    );
    assert!(body["events"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn fleet_host_by_id_404_when_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state_with_token(dir.path(), "tok"));
    let (status, body) = get(&app, "/v1/fleet/hosts/no-such", Some("tok")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "not_found");
}

#[tokio::test]
async fn event_by_id_400_for_non_uuid() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state_with_token(dir.path(), "tok"));
    let (status, body) = get(&app, "/v1/events/not-a-uuid", Some("tok")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_query");
}

#[tokio::test]
async fn policy_meta_404_when_no_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state_with_token(dir.path(), "tok"));
    let (status, body) = get(&app, "/v1/policy/meta", Some("tok")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "not_found");
}

fn rfc(ts: time::OffsetDateTime) -> String {
    ts.format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

fn ai_reading(tool: &str, user: &str, score: f64, bucket: &str) -> serde_json::Value {
    serde_json::json!({"kind":"ai_guard_risk_assessed", "tool":tool,
        "scope":{"kind":"user_global"}, "score":score, "bucket":bucket,
        "reasons":[], "is_reattestation":false, "user":user})
}

fn ai_failure(
    tool: &str,
    user: &str,
    error_kind: &str,
    failing_since: time::OffsetDateTime,
    last_assessed_ts: Option<time::OffsetDateTime>,
) -> serde_json::Value {
    serde_json::json!({"kind":"ai_guard_assess_failed", "tool":tool,
        "scope":{"kind":"user_global"}, "user":user, "error_kind":error_kind,
        "path":format!("/Users/{user}/.config/{tool}.json"),
        "failing_since":rfc(failing_since), "last_assessed_ts":last_assessed_ts.map(rfc),
        "is_reattestation":false})
}

/// POSTs `(ts, evidence)` events for `host` and asserts the server took them all.
async fn post_evidence(
    app: &axum::Router,
    host: &str,
    events: &[(time::OffsetDateTime, serde_json::Value)],
) {
    let entries: Vec<serde_json::Value> = events
        .iter()
        .enumerate()
        .map(|(i, (ts, evidence))| {
            let id = uuid::Uuid::now_v7();
            serde_json::json!({"event_id":id, "sequence":i+1, "payload":{
                "schema_version":1, "event_id":id, "ts":rfc(*ts),
                "host_id":host, "agent_version":"fixture", "severity":"warn",
                "source":{"kind":"agent"}, "subject":{"kind":"self"},
                "evidence":evidence}})
        })
        .collect();
    let body =
        serde_json::json!({"envelope":{"host_id":host,"schema_version":1}, "events":entries});
    let response = app
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
    assert_eq!(response.status(), StatusCode::OK);
    let ack: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        ack["accepted"].as_array().unwrap().len(),
        events.len(),
        "{ack}"
    );
}

/// The host list row, host detail and risk rows for `host`.
async fn host_views(app: &axum::Router, host: &str) -> [serde_json::Value; 3] {
    let list = get_rows_by_host(app, "/v1/fleet/hosts").await;
    let row = list["hosts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["host_id"] == host)
        .unwrap()
        .clone();
    let detail = get_rows_by_host(app, &format!("/v1/fleet/hosts/{host}")).await;
    let risk = get_rows_by_host(app, "/v1/fleet/risk").await;
    let risk: Vec<_> = risk["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["host_id"] == host)
        .cloned()
        .collect();
    [row, detail, serde_json::Value::Array(risk)]
}

#[tokio::test]
async fn assess_failure_keeps_the_score_and_the_source_live_and_after_rebuild() {
    use serde_json::json;
    use time::Duration;
    let dir = tempfile::tempdir().unwrap();
    let state = state_with_token(dir.path(), "tok");
    let app = build_router(state.clone());
    let now = time::OffsetDateTime::now_utc();
    let h = |hours: i64| now - Duration::hours(hours);
    let host = uuid::Uuid::now_v7().to_string();
    let mut events = vec![
        (h(100), ai_reading("claude_code", "alice", 7.5, "critical")),
        // Bob's source stops sending both, so it drops after 48h as before.
        (h(90), ai_reading("codex", "bob", 1.0, "medium")),
    ];
    // Alice's parser fails from 80h ago, and the agent re-sends it each 24h.
    for hours in [76, 52, 28, 4] {
        events.push((
            h(hours),
            ai_failure("claude_code", "alice", "unreadable", h(80), Some(h(100))),
        ));
    }
    // Carol's parser fails with no reading the agent could fall back on.
    events.push((h(3), ai_failure("codex", "carol", "too_large", h(3), None)));
    post_evidence(&app, &host, &events).await;

    let live = host_views(&app, &host).await;
    let [row, detail, risk] = &live;
    let claude = &row["current_risk"]["by_tool"]["claude_code"];
    assert_eq!(claude["score"], 7.5, "{row}");
    assert_eq!(claude["source"]["user"], "alice", "{row}");
    assert_eq!(claude["unassessed_since"], rfc(h(80)), "{row}");
    assert_eq!(
        row["current_risk"]["by_tool"].as_object().unwrap().len(),
        1,
        "bob's reading outlived 48h, or carol got a score-less entry: {row}"
    );
    assert_eq!(
        row["ai_guard_unassessed"],
        json!({
            "claude_code": {"since": rfc(h(80)), "last_assessed_ts": rfc(h(100)), "sources": [
                {"scope": {"kind": "user_global"}, "user": "alice", "rule_pack_id": null,
                 "error_kind": "unreadable", "path": "/Users/alice/.config/claude_code.json"}]},
            "codex": {"since": rfc(h(3)), "last_assessed_ts": null, "sources": [
                {"scope": {"kind": "user_global"}, "user": "carol", "rule_pack_id": null,
                 "error_kind": "too_large", "path": "/Users/carol/.config/codex.json"}]}
        })
    );
    assert_eq!(detail["ai_guard_unassessed"], row["ai_guard_unassessed"]);
    assert_eq!(detail["current_risk"], row["current_risk"]);
    assert_eq!(
        detail["ai_guard"]["by_tool"]["claude_code"]["unassessed_since"],
        rfc(h(80))
    );
    assert_eq!(risk[0]["top_tool"], "claude_code", "{risk}");
    assert_eq!(risk[0]["unassessed_since"], rfc(h(80)), "{risk}");

    state
        .fleet_index
        .replace(lodeline_server::boot_rebuild::rebuild_from_jsonl(dir.path()).unwrap());
    assert_eq!(
        host_views(&app, &host).await,
        live,
        "a rebuild must match live ingest"
    );
}

#[tokio::test]
async fn assess_failure_with_no_reading_leaves_current_risk_null() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state_with_token(dir.path(), "tok"));
    let now = time::OffsetDateTime::now_utc();
    let host = uuid::Uuid::now_v7().to_string();
    post_evidence(
        &app,
        &host,
        &[(now, ai_failure("codex", "alice", "parse", now, None))],
    )
    .await;
    let [row, detail, risk] = host_views(&app, &host).await;
    for body in [&row, &detail] {
        assert!(body["current_risk"].is_null(), "{body}");
        assert_eq!(
            body["ai_guard_unassessed"]["codex"]["sources"][0]["error_kind"], "parse",
            "{body}"
        );
    }
    assert_eq!(detail["ai_guard"]["by_tool"], serde_json::json!({}));
    assert_eq!(
        risk,
        serde_json::json!([]),
        "a host with no score got a risk row"
    );
}

#[tokio::test]
async fn reading_after_assess_failure_clears_the_mark() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state_with_token(dir.path(), "tok"));
    let now = time::OffsetDateTime::now_utc();
    let m = |mins: i64| now - time::Duration::minutes(mins);
    let host = uuid::Uuid::now_v7().to_string();
    post_evidence(
        &app,
        &host,
        &[
            (m(3), ai_reading("codex", "alice", 7.5, "critical")),
            (
                m(2),
                ai_failure("codex", "alice", "parse", m(2), Some(m(3))),
            ),
            (m(1), ai_reading("codex", "alice", 2.0, "medium")),
        ],
    )
    .await;
    let [row, detail, risk] = host_views(&app, &host).await;
    assert!(row["ai_guard_unassessed"].is_null(), "{row}");
    assert!(detail["ai_guard_unassessed"].is_null(), "{detail}");
    let codex = &row["current_risk"]["by_tool"]["codex"];
    assert_eq!(codex["score"], 2.0, "{row}");
    assert!(codex.get("unassessed_since").is_none(), "{row}");
    assert!(detail["ai_guard"]["by_tool"]["codex"]
        .get("unassessed_since")
        .is_none());
    assert!(risk[0].get("unassessed_since").is_none(), "{risk}");
}

#[tokio::test]
async fn future_dated_assess_failure_neither_prunes_others_nor_outlives_48h() {
    use lodeline_core::event::Event;
    use time::Duration;
    let dir = tempfile::tempdir().unwrap();
    let state = state_with_token(dir.path(), "tok");
    let app = build_router(state.clone());
    let t0 = time::OffsetDateTime::now_utc() - Duration::days(10);
    let host = uuid::Uuid::now_v7().to_string();
    let apply = |ts: time::OffsetDateTime, evidence: serde_json::Value, received| {
        let event: Event = serde_json::from_value(serde_json::json!({
            "schema_version":1, "event_id":uuid::Uuid::now_v7(), "ts":rfc(ts),
            "host_id":host, "agent_version":"fixture", "severity":"warn",
            "source":{"kind":"agent"}, "subject":{"kind":"self"},
            "evidence":evidence, "target_id":null}))
        .unwrap();
        state.fleet_index.apply_event(&event, received);
    };
    apply(t0, ai_reading("codex", "alice", 7.0, "critical"), t0);
    // The agent clock jumped three days ahead; the server got it a minute later.
    let ahead = t0 + Duration::days(3);
    apply(
        ahead,
        ai_failure("claude_code", "bob", "parse", ahead, None),
        t0 + Duration::minutes(1),
    );
    let [row, ..] = host_views(&app, &host).await;
    assert_eq!(
        row["current_risk"]["by_tool"]["codex"]["score"], 7.0,
        "a future-dated failure pruned the host's other readings: {row}"
    );
    assert!(
        row["ai_guard_unassessed"]["claude_code"].is_object(),
        "{row}"
    );

    let later = t0 + Duration::hours(49);
    apply(later, ai_reading("codex", "alice", 0.0, "low"), later);
    let [row, ..] = host_views(&app, &host).await;
    assert!(
        row["ai_guard_unassessed"].is_null(),
        "a future-dated failure outlived the 48h window: {row}"
    );
}

#[tokio::test]
async fn unassessed_since_follows_only_the_top_reading() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state_with_token(dir.path(), "tok"));
    let now = time::OffsetDateTime::now_utc();
    let m = |mins: i64| now - time::Duration::minutes(mins);
    let clean_top = uuid::Uuid::now_v7().to_string();
    let stale_top = uuid::Uuid::now_v7().to_string();
    post_evidence(
        &app,
        &clean_top,
        &[
            (m(5), ai_reading("claude_code", "alice", 7.5, "critical")),
            (m(4), ai_reading("claude_code", "bob", 1.0, "medium")),
            (
                m(2),
                ai_failure("claude_code", "bob", "parse", m(3), Some(m(4))),
            ),
        ],
    )
    .await;
    post_evidence(
        &app,
        &stale_top,
        &[
            (m(5), ai_reading("claude_code", "alice", 7.5, "critical")),
            (m(4), ai_reading("claude_code", "bob", 1.0, "medium")),
            (
                m(2),
                ai_failure("claude_code", "alice", "parse", m(3), Some(m(5))),
            ),
        ],
    )
    .await;

    let [row, detail, risk] = host_views(&app, &clean_top).await;
    let claude = &row["current_risk"]["by_tool"]["claude_code"];
    assert_eq!(claude["source"]["user"], "alice", "{row}");
    assert!(
        claude.get("unassessed_since").is_none(),
        "a failing lower source marked a clean top reading: {row}"
    );
    assert!(detail["ai_guard"]["by_tool"]["claude_code"]
        .get("unassessed_since")
        .is_none());
    assert!(risk[0].get("unassessed_since").is_none(), "{risk}");
    assert_eq!(
        row["ai_guard_unassessed"]["claude_code"]["sources"][0]["user"], "bob",
        "{row}"
    );

    let [row, detail, risk] = host_views(&app, &stale_top).await;
    let claude = &row["current_risk"]["by_tool"]["claude_code"];
    assert_eq!(claude["source"]["user"], "alice", "{row}");
    assert_eq!(claude["unassessed_since"], rfc(m(3)), "{row}");
    assert_eq!(
        detail["ai_guard"]["by_tool"]["claude_code"]["unassessed_since"],
        rfc(m(3))
    );
    assert_eq!(risk[0]["unassessed_since"], rfc(m(3)), "{risk}");
}

#[tokio::test]
async fn unknown_reason_kind_is_accepted_and_served_as_the_same_value() {
    use serde_json::json;
    let dir = tempfile::tempdir().unwrap();
    let state = state_with_token(dir.path(), "tok");
    let app = build_router(state.clone());
    let host = uuid::Uuid::now_v7().to_string();
    let reasons = json!([{"kind":"sandbox_disabled"},
        {"kind":"future_reason", "detail":{"n":2}, "path":"/x"}]);
    let mut reading = ai_reading("codex", "alice", 3.0, "medium");
    reading["reasons"] = reasons.clone();
    post_evidence(&app, &host, &[(time::OffsetDateTime::now_utc(), reading)]).await;

    let live = host_views(&app, &host).await;
    let [row, detail, risk] = &live;
    assert_eq!(
        row["current_risk"]["by_tool"]["codex"]["score"], 3.0,
        "{row}"
    );
    assert_eq!(detail["ai_guard"]["by_tool"]["codex"]["reasons"], reasons);
    assert_eq!(risk[0]["reasons_count"], 2, "{risk}");
    let (_, history) = get(&app, &format!("/v1/events?host_id={host}"), Some("tok")).await;
    assert_eq!(history["events"][0]["evidence"]["reasons"], reasons);

    state
        .fleet_index
        .replace(lodeline_server::boot_rebuild::rebuild_from_jsonl(dir.path()).unwrap());
    assert_eq!(
        host_views(&app, &host).await,
        live,
        "a rebuild must match live ingest"
    );
}
