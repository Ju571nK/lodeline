//! Ingest keeps, and the readers rank and roll up, a tool, bucket or scope
//! name this build does not know.
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use lodeline_server::app::{build_router, AppState};
use lodeline_server::auth::ReadToken;
use lodeline_server::boot_rebuild::rebuild_from_jsonl;
use lodeline_server::fleet_index::FleetIndex;
use lodeline_server::persist::HighWater;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

fn state(dir: &std::path::Path) -> Arc<AppState> {
    Arc::new(AppState {
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
    })
}

async fn get(app: &axum::Router, path: &str) -> Value {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .header(header::AUTHORIZATION, "Bearer tok")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "{path}");
    serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap()
}

fn rfc(ts: time::OffsetDateTime) -> String {
    ts.format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

fn payload(host: &str, evidence: Value) -> Value {
    json!({
        "schema_version":1, "event_id":uuid::Uuid::now_v7(),
        "ts":rfc(time::OffsetDateTime::now_utc()),
        "host_id":host, "agent_version":"fixture", "severity":"warn",
        "source":{"kind":"agent"}, "subject":{"kind":"self"},
        "evidence":evidence
    })
}

fn reading(tool: &str, bucket: &str, score: f64) -> Value {
    json!({"kind":"ai_guard_risk_assessed", "tool":tool,
        "scope":{"kind":"user_global"}, "score":score, "bucket":bucket,
        "reasons":[], "is_reattestation":false, "user":"alice"})
}

async fn post(app: &axum::Router, host: &str, payloads: &[Value]) -> Value {
    let events: Vec<Value> = payloads
        .iter()
        .enumerate()
        .map(|(i, p)| json!({"event_id":p["event_id"], "sequence":i + 1, "payload":p}))
        .collect();
    let body = json!({"envelope":{"host_id":host,"schema_version":1}, "events":events});
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
    assert_eq!(resp.status(), StatusCode::OK);
    serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap()
}

fn stored_lines(dir: &std::path::Path, host: &str) -> Vec<String> {
    let mut lines = Vec::new();
    for f in std::fs::read_dir(dir.join(host)).unwrap().flatten() {
        if f.file_name().to_string_lossy().ends_with(".jsonl") {
            let text = std::fs::read_to_string(f.path()).unwrap();
            lines.extend(text.lines().map(str::to_owned));
        }
    }
    lines
}

#[tokio::test]
async fn ingest_keeps_an_unknown_tool_bucket_and_scope_kind_byte_for_byte() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state(dir.path()));
    let host = uuid::Uuid::now_v7().to_string();
    let mut ev = reading("newtool", "severe", 5.0);
    ev["scope"] = json!({"kind":"workspace", "root":"/fixture/ws"});
    let p = payload(&host, ev);
    let ack = post(&app, &host, std::slice::from_ref(&p)).await;
    assert_eq!(ack["accepted"].as_array().unwrap().len(), 1, "{ack}");
    assert_eq!(ack["rejected"].as_array().unwrap().len(), 0, "{ack}");
    assert_eq!(stored_lines(dir.path(), &host), vec![p.to_string()]);

    let page = get(&app, &format!("/v1/events?host_id={host}")).await;
    assert_eq!(page["events"], json!([p]));
}

#[tokio::test]
async fn an_unknown_tool_has_a_host_row_a_by_tool_key_and_a_tool_filter_match() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state(dir.path()));
    let host = uuid::Uuid::now_v7().to_string();
    post(
        &app,
        &host,
        &[payload(&host, reading("newtool", "medium", 2.0))],
    )
    .await;

    let list = get(&app, "/v1/fleet/hosts").await;
    let row = &list["hosts"][0];
    assert_eq!(row["current_risk"]["by_tool"]["newtool"]["score"], 2.0);
    let detail = get(&app, &format!("/v1/fleet/hosts/{host}")).await;
    assert_eq!(detail["ai_guard"]["by_tool"]["newtool"]["score"], 2.0);
    let risk = get(&app, "/v1/fleet/risk?tool=newtool").await;
    assert_eq!(risk["rows"][0]["top_tool"], "newtool", "{risk}");
    let other = get(&app, "/v1/fleet/risk?tool=codex").await;
    assert_eq!(other["rows"].as_array().unwrap().len(), 0, "{other}");
}

#[tokio::test]
async fn a_tied_top_tool_goes_to_a_known_tool_then_to_the_first_unknown_name() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state(dir.path()));
    let known_wins = uuid::Uuid::now_v7().to_string();
    let by_name = uuid::Uuid::now_v7().to_string();
    post(
        &app,
        &known_wins,
        &[
            payload(&known_wins, reading("aaa_new", "medium", 3.0)),
            payload(&known_wins, reading("other", "medium", 3.0)),
        ],
    )
    .await;
    post(
        &app,
        &by_name,
        &[
            payload(&by_name, reading("zzz_new", "medium", 3.0)),
            payload(&by_name, reading("mmm_new", "medium", 3.0)),
        ],
    )
    .await;
    let risk = get(&app, "/v1/fleet/risk").await;
    let top = |host: &str| {
        risk["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["host_id"] == host)
            .unwrap()["top_tool"]
            .clone()
    };
    assert_eq!(top(&known_wins), "other", "{risk}");
    assert_eq!(top(&by_name), "mmm_new", "{risk}");
}

const UNKNOWN_BUCKET_BY_SCORE: [(f64, &str); 4] = [
    (0.5, "low"),
    (3.0, "medium"),
    (6.0, "high"),
    (8.0, "critical"),
];

#[tokio::test]
async fn an_unknown_bucket_ranks_by_its_score_in_every_server_reader() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state(dir.path()));
    let mut hosts = Vec::new();
    for (score, _) in UNKNOWN_BUCKET_BY_SCORE {
        let host = uuid::Uuid::now_v7().to_string();
        post(
            &app,
            &host,
            &[payload(&host, reading("codex", "severe", score))],
        )
        .await;
        hosts.push(host);
    }
    let host_ids = |body: &Value, key: &str| -> HashSet<String> {
        body[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["host_id"].as_str().unwrap().to_owned())
            .collect()
    };
    for (min, expected_from) in [("low", 0), ("medium", 1), ("high", 2), ("critical", 3)] {
        let want: HashSet<String> = hosts[expected_from..].iter().cloned().collect();
        let risk = get(&app, &format!("/v1/fleet/risk?min_bucket={min}")).await;
        assert_eq!(host_ids(&risk, "rows"), want, "risk min_bucket={min}");
        let events = get(&app, &format!("/v1/events?min_ai_guard_bucket={min}")).await;
        let seen: HashSet<String> = events["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["host_id"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(seen, want, "events min_ai_guard_bucket={min}");
    }
    for (host, (_, effective)) in hosts.iter().zip(UNKNOWN_BUCKET_BY_SCORE) {
        let list = get(&app, &format!("/v1/fleet/hosts?bucket={effective}")).await;
        assert!(
            host_ids(&list, "hosts").contains(host),
            "bucket={effective}"
        );
        let row = list["hosts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|h| &h["host_id"] == host)
            .unwrap();
        assert_eq!(row["current_risk"]["max_bucket"], "severe", "{row}");
    }
    let list = get(&app, "/v1/fleet/hosts").await;
    let alerts: Vec<u64> = hosts
        .iter()
        .map(|host| {
            list["hosts"]
                .as_array()
                .unwrap()
                .iter()
                .find(|h| &h["host_id"] == host)
                .unwrap()["open_alert_count_24h"]
                .as_u64()
                .unwrap()
        })
        .collect();
    assert_eq!(alerts, vec![0, 0, 1, 1]);
}

#[tokio::test]
async fn the_host_list_sorts_an_unknown_bucket_by_its_score() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state(dir.path()));
    let (low, critical) = (
        uuid::Uuid::now_v7().to_string(),
        uuid::Uuid::now_v7().to_string(),
    );
    post(
        &app,
        &low,
        &[payload(&low, reading("codex", "severe", 0.5))],
    )
    .await;
    post(
        &app,
        &critical,
        &[payload(&critical, reading("codex", "severe", 8.0))],
    )
    .await;
    let list = get(&app, "/v1/fleet/hosts?sort=risk").await;
    assert_eq!(list["hosts"][0]["host_id"], critical.as_str(), "{list}");
}

#[tokio::test]
async fn a_rebuild_matches_live_ingest_with_unknown_values() {
    let dir = tempfile::tempdir().unwrap();
    let st = state(dir.path());
    let app = build_router(st.clone());
    let host = uuid::Uuid::now_v7().to_string();
    let mut scoped = reading("newtool", "severe", 8.0);
    scoped["scope"] = json!({"kind":"workspace", "root":"/fixture/ws"});
    post(
        &app,
        &host,
        &[
            payload(&host, scoped),
            payload(&host, reading("codex", "severe", 3.0)),
        ],
    )
    .await;
    let views = || async {
        [
            get(&app, "/v1/fleet/hosts").await,
            get(&app, &format!("/v1/fleet/hosts/{host}")).await,
            get(&app, "/v1/fleet/risk").await,
        ]
    };
    let live = views().await;
    assert_eq!(
        live[0]["hosts"][0]["current_risk"]["by_tool"]["newtool"]["score"],
        8.0
    );
    st.fleet_index
        .replace(rebuild_from_jsonl(dir.path()).unwrap());
    assert_eq!(views().await, live);
}
