//! T-11 S5 slice C — proxy and invocation query API (L3, L4, L6).
//!
//! In-process through `build_router_with_proxy` (the production router) with
//! `tower::oneshot`; the TLS layer is replaced by a `PeerIdentity` request
//! extension, exactly what the TLS acceptor sets. PX-006/010/016, AC-05/06/12.
#![cfg(unix)]

use axum::body::Body;
use axum::http::Request;
use serde_json::{json, Value};
use sigil_proxy_api::verifier::verifier_for;
use sigil_proxy_api::{parse_config, parse_event, parse_status, ProxyEvent};
use sigil_server::app::{build_router_with_proxy, AppState};
use sigil_server::auth::ReadToken;
use sigil_server::config::ServerConfig;
use sigil_server::fleet_index::FleetIndex;
use sigil_server::persist::HighWater;
use sigil_server::proxy::query::TestScope;
use sigil_server::proxy::registry::{ProxyRecord, ProxyState};
use sigil_server::proxy::store::{ProxyEntry, StoredConfig};
use sigil_server::proxy::verifiers::{Scope, VerifierEntry};
use sigil_server::proxy::ProxyContext;
use sigil_server::tls_accept::PeerIdentity;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

const READ_TOKEN: &str = "read-bearer-CANARY-5c2e";
const MGMT_TOKEN: &str = "tok-mgmt-CANARY-77aa";
const MGMT_FP: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const HOST_FP: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const EP1: &str = "11111111-1111-4111-8111-111111111111";
const T0: i64 = 1_790_000_000;

// Content that must never reach a read response (AC-05): stored config
// (upstream URL, credential reference, origins, verifiers) and fingerprints.
const CANARY_UPSTREAM: &str = "canary-upstream.example";
const CANARY_CRED: &str = "canary-credential-ref";
const CANARY_ORIGIN: &str = "canary-origin.example";
const CANARY_PRINCIPAL_TOKEN: &str = "canary-principal-secret";
const FP_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn uuid(n: u32) -> String {
    format!("00000000-0000-4000-8000-{n:012}")
}
fn mref(n: u32) -> String {
    format!("00000000-0000-8000-8000-{n:012}")
}

// ---- PKI (CA files only; leaves are synthetic PeerIdentity values) ----------

fn make_ca(dir: &Path, name: &str, cn: &str) {
    let openssl = sigil_server::enroll::sign::resolve_openssl().expect("openssl");
    let run = |args: &[&str]| {
        let o = Command::new(&openssl).args(args).output().unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    };
    let key = dir.join(format!("{name}.key"));
    run(&[
        "genpkey",
        "-algorithm",
        "RSA",
        "-pkeyopt",
        "rsa_keygen_bits:2048",
        "-out",
        key.to_str().unwrap(),
    ]);
    run(&[
        "req",
        "-x509",
        "-new",
        "-key",
        key.to_str().unwrap(),
        "-days",
        "1",
        "-subj",
        &format!("/CN={cn}"),
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "subjectKeyIdentifier=hash",
        "-out",
        dir.join(format!("{name}.crt")).to_str().unwrap(),
    ]);
}

fn state(dir: &Path) -> Arc<AppState> {
    Arc::new(AppState {
        events_out_dir: dir.to_path_buf(),
        policy_bundle_path: dir.join("signed-policy.json"),
        rule_packs_bundle_path: None,
        artifacts_dir: None,
        high_water_path: dir.join(".high-water.json"),
        allowlist: parking_lot::RwLock::new(None),
        high_water: Mutex::new(HighWater::default()),
        fleet_index: FleetIndex::new(),
        read_token: ReadToken(Some(READ_TOKEN.into())),
        active_window_days: 7,
        audit_key: None,
        audit_head: Mutex::new(None),
        allowlist_path: None,
        enroll: None,
        events_require_cert_host_match: false,
    })
}

// ---- event builders ---------------------------------------------------------

fn envelope(proxy: &str, seq: i64, event_n: u32, event_type: &str, payload: Value) -> ProxyEvent {
    let v = json!({
        "schema_version": 1,
        "event_id": uuid(event_n),
        "proxy_id": proxy,
        "epoch_id": EP1,
        "sequence": seq,
        "occurred_at": format!("2026-10-10T00:00:{:02}Z", seq % 60),
        "event_type": event_type,
        "payload": payload,
    });
    parse_event(v.to_string().as_bytes()).unwrap()
}

#[allow(clippy::too_many_arguments)]
fn start(
    proxy: &str,
    seq: i64,
    n: u32,
    inv: u32,
    method: &str,
    tool: Option<Value>,
    upstream: &str,
    actor: &str,
) -> ProxyEvent {
    let protocol = if method == "tools/call" {
        "2025-11-25"
    } else {
        "unknown"
    };
    let mut payload = json!({
        "invocation_id": uuid(inv),
        "upstream_id": upstream,
        "route_revision": 1,
        "protocol_version": protocol,
        "method": method,
        "actor": {
            "actor_id": actor,
            "actor_kind": "non_human",
            "authentication_method": "bearer",
            "evidence_source": "proxy_credential_mapping"
        }
    });
    if let Some(t) = tool {
        payload["tool"] = t;
    }
    envelope(proxy, seq, n, "invocation.started", payload)
}

fn done(proxy: &str, seq: i64, n: u32, inv: u32, outcome: &str, delivery: &str) -> ProxyEvent {
    envelope(
        proxy,
        seq,
        n,
        "invocation.completed",
        json!({
            "invocation_id": uuid(inv),
            "outcome": outcome,
            "delivery_state": delivery,
            "duration_ms": 12,
            "response_bytes": 34
        }),
    )
}

fn cancel(proxy: &str, seq: i64, n: u32, inv: u32) -> ProxyEvent {
    envelope(
        proxy,
        seq,
        n,
        "invocation.cancel_requested",
        json!({"invocation_id": uuid(inv)}),
    )
}

fn ident(n: u32) -> Value {
    json!({"status": "identified", "metadata_ref": mref(n)})
}

// ---- fixture ----------------------------------------------------------------

struct Fx {
    _dir: tempfile::TempDir,
    ctx: Arc<ProxyContext>,
    app: axum::Router,
    ledger_path: std::path::PathBuf,
    now: i64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Who {
    Host,
    Proxy,
    Mgmt,
    Ambiguous,
    NoPeer,
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct Resp {
    status: u16,
    content_type: Option<String>,
    body: Vec<u8>,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
    fn code(&self) -> String {
        self.json()["error"]["code"].as_str().unwrap_or("").into()
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into()
    }
}

fn record(id: &str, name: &str, state: ProxyState) -> ProxyRecord {
    ProxyRecord {
        proxy_id: id.into(),
        display_name: name.into(),
        state,
        fp_current: Some(FP_A.into()),
        fp_next: None,
        created_at: "2026-10-01T00:00:00Z".into(),
        updated_at: "2026-10-01T00:00:00Z".into(),
    }
}

fn rfc(secs: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(secs)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

fn config_with(revision: i64) -> StoredConfig {
    let v = json!({
        "schema_version": 1, "proxy_id": "px-a", "revision": revision,
        "issued_at": "2026-10-11T00:00:00Z", "expires_at": "2026-10-11T00:05:00Z",
        "ttl_seconds": 300, "mode": "observe",
        "max_offline_retry_age_seconds": 2592000, "event_retention_seconds": 7776000,
        "allowed_origins": [format!("https://{CANARY_ORIGIN}")],
        "routes": [{"route_id": "r1", "upstream_id": "up-r1",
            "upstream_url": format!("https://{CANARY_UPSTREAM}/mcp"),
            "upstream_protocol": "2025-11-25", "credential_ref": CANARY_CRED,
            "credential_scope_id": "cs-0123456789abcdef0123456789abcdef"}],
        "principals": [{"principal_id": "claude",
            "verifiers": [{"key_id": "k1", "verifier": verifier_for(CANARY_PRINCIPAL_TOKEN)}],
            "routes": ["r1"]}],
    });
    StoredConfig {
        config: parse_config(v.to_string().as_bytes()).unwrap(),
        config_hash: "0".repeat(64),
        updated_at: "2026-10-11T00:00:00Z".into(),
    }
}

fn status_json(applied: Option<i64>, state: &str) -> Value {
    json!({
        "schema_version": 1, "report_id": uuid(900), "proxy_id": "px-a",
        "epoch_id": EP1, "status_sequence": 5, "sent_at": "2026-10-11T00:00:00Z",
        "config": {"state": state, "applied_revision": applied,
            "observed_desired_revision": applied, "expires_at": "2026-10-11T00:05:00Z",
            "max_offline_retry_age_seconds": 2592000, "event_retention_seconds": 7776000,
            "config_hash": "0".repeat(64)},
        "spool": {"state": "degraded", "depth_events": 4, "unsent_events": 3, "bytes": 99,
            "capacity_bytes": 1000, "oldest_unsent_age_seconds": 7, "quarantined_events": 1},
        "registry": {"pending_entries": 2, "sync_stalled": false},
        "central": {"last_ingest_ack_at": "2026-10-11T00:00:00Z", "consecutive_failures": 1},
        "routes": [{"upstream_id": "up1", "state": "degraded", "reason": "health_check_failed"}],
        "counters": {"auth_failures": [], "unmatched_cancels": []},
        "gaps": [], "last_assigned_sequence": 7,
    })
}

fn outage(n: u32, at: &str, ended: Option<&str>) -> sigil_proxy_api::GapReport {
    serde_json::from_value(json!({
        "kind": "central_outage", "gap_id": uuid(5000 + n), "detected_at": at,
        "started_at": at, "ended_at": ended,
    }))
    .unwrap()
}

impl Fx {
    /// `management`: configure the management verifier file.
    /// `outages`: number of proxy-reported central_outage gaps on px-a.
    async fn new(management: bool, outages: u32) -> Fx {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        make_ca(d, "hostca", "test-host-ca");
        make_ca(d, "proxyca", "test-proxy-ca");
        let mut bundle = std::fs::read(d.join("hostca.crt")).unwrap();
        bundle.extend(std::fs::read(d.join("proxyca.crt")).unwrap());
        std::fs::write(d.join("bundle.pem"), bundle).unwrap();
        let p = |f: &str| d.join(f).display().to_string();
        let mut y = format!(
            "bind: \"127.0.0.1:0\"\ntls_cert_path: {}\ntls_key_path: {}\nclient_ca_path: {}\n\
             events_out_dir: {}\npolicy_bundle_path: {}\n\
             proxy:\n  ca_path: {}\n  registry_path: {}\n  registry_init: true\n",
            p("server.crt"),
            p("server.key"),
            p("bundle.pem"),
            d.display(),
            p("signed-policy.json"),
            p("proxyca.crt"),
            p("proxies.json"),
        );
        if management {
            let entry = VerifierEntry {
                key_id: "idk".into(),
                name: "idk-name".into(),
                verifier: verifier_for(MGMT_TOKEN),
                scope: Scope::Identity,
                caller_cert_fingerprint: MGMT_FP.into(),
                not_after: None,
            };
            let vp = d.join("verifiers.json");
            std::fs::write(
                &vp,
                serde_json::to_vec(&json!({"entries": [entry]})).unwrap(),
            )
            .unwrap();
            std::fs::set_permissions(&vp, std::fs::Permissions::from_mode(0o600)).unwrap();
            y.push_str(&format!("  management_verifiers: {}\n", vp.display()));
        }
        let cfg: ServerConfig = serde_yaml::from_str(&y).unwrap();
        let ledger_path = cfg.proxy.as_ref().unwrap().ledger_path();
        let ctx = Arc::new(ProxyContext::load(&cfg).unwrap().unwrap());
        let now = time::OffsetDateTime::now_utc().unix_timestamp();

        // Registry: px-a connected+in sync, px-b disconnected+behind, px-c never
        // connected, px-d (retired history, no state).
        for (id, name, st) in [
            ("px-a", "Proxy A", ProxyState::Active),
            ("px-b", "Proxy B", ProxyState::Active),
            ("px-c", "Proxy C", ProxyState::Pending),
        ] {
            ctx.registry.seed_for_test(record(id, name, st)).unwrap();
        }
        let txn = ctx.store.begin();
        let mut a = ProxyEntry {
            config: Some(config_with(3)),
            status: Some(
                parse_status(status_json(Some(3), "valid").to_string().as_bytes()).unwrap(),
            ),
            last_seen: Some(rfc(now - 30)),
            epochs_seen: vec![EP1.into()],
            counters_epoch: Some(EP1.into()),
            ..Default::default()
        };
        a.counter_max
            .insert("a\u{1f}up1\u{1f}credential_invalid".into(), 5);
        a.counter_max
            .insert("c\u{1f}\u{1f}no_matching_request".into(), 2);
        a.previous_epoch_totals
            .push(sigil_server::proxy::store::EpochTotals {
                epoch_id: uuid(77),
                auth_failures: 9,
                unmatched_cancels: 4,
            });
        for i in 0..outages {
            a.gaps.push(outage(
                i,
                &format!("2026-10-11T00:{:02}:00Z", i % 60),
                (i % 2 == 0).then_some("2026-10-11T01:00:00Z"),
            ));
        }
        txn.commit("px-a", a).unwrap();
        let txn = ctx.store.begin();
        let b = ProxyEntry {
            config: Some(config_with(2)),
            status: Some(
                parse_status(status_json(Some(1), "expired").to_string().as_bytes()).unwrap(),
            ),
            last_seen: Some(rfc(now - 3600)),
            ..Default::default()
        };
        txn.commit("px-b", b).unwrap();

        // Ledger. px-a: inv1 completed, inv2 started, inv3 completed, then a
        // sequence jump (6 missing) and inv4 completion without start.
        let l = &ctx.ledger;
        let at = |k: i64| T0 + k * 1000;
        l.insert_batch(
            "px-a",
            &[
                start(
                    "px-a",
                    1,
                    1,
                    1,
                    "tools/call",
                    Some(ident(1)),
                    "up1",
                    "actor-1",
                ),
                done("px-a", 2, 2, 1, "success", "sent"),
            ],
            at(1),
        )
        .unwrap();
        l.insert_batch(
            "px-a",
            &[start("px-a", 3, 3, 2, "ping", None, "up1", "actor-1")],
            at(2),
        )
        .unwrap();
        l.insert_batch(
            "px-b",
            &[
                start("px-b", 1, 11, 5, "ping", None, "up9", "actor-2"),
                done("px-b", 2, 12, 5, "tool_error", "sent"),
            ],
            at(3),
        )
        .unwrap();
        l.insert_batch(
            "px-a",
            &[
                start("px-a", 4, 4, 3, "initialize", None, "up2", "actor-2"),
                done("px-a", 5, 5, 3, "timeout", "unknown"),
            ],
            at(4),
        )
        .unwrap();
        l.insert_batch("px-a", &[done("px-a", 7, 7, 4, "success", "sent")], at(5))
            .unwrap();

        let app = build_router_with_proxy(state(d), Some(ctx.clone()));
        Fx {
            _dir: dir,
            ctx,
            app,
            ledger_path,
            now,
        }
    }

    fn peer(&self, who: Who) -> Option<PeerIdentity> {
        let mk = |fp: &str, issuer: &str| PeerIdentity {
            fingerprint: fp.into(),
            cn: Some("c".into()),
            san_dns: vec![],
            issuer_dn: Some(issuer.into()),
            issuer_aki: None,
        };
        match who {
            Who::Host => Some(mk(HOST_FP, "CN=test-host-ca")),
            Who::Mgmt => Some(mk(MGMT_FP, "CN=test-host-ca")),
            Who::Proxy => Some(mk(FP_A, &self.ctx.ca.subject_dn)),
            Who::Ambiguous => Some(PeerIdentity::default()),
            Who::NoPeer => None,
        }
    }

    async fn call(
        &self,
        method: &str,
        uri: &str,
        who: Who,
        bearer: Option<&str>,
        scope: Option<&[&str]>,
    ) -> Resp {
        let mut req = Request::builder().method(method).uri(uri);
        if let Some(b) = bearer {
            req = req.header("authorization", format!("Bearer {b}"));
        }
        let mut req = req.body(Body::empty()).unwrap();
        if let Some(p) = self.peer(who) {
            req.extensions_mut().insert(Arc::new(p));
        }
        if let Some(s) = scope {
            req.extensions_mut()
                .insert(TestScope(s.iter().map(|x| x.to_string()).collect()));
        }
        let r = self.app.clone().oneshot(req).await.unwrap();
        let status = r.status().as_u16();
        let content_type = r
            .headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap().into());
        let body = axum::body::to_bytes(r.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        Resp {
            status,
            content_type,
            body,
        }
    }

    async fn get(&self, uri: &str) -> Resp {
        self.call("GET", uri, Who::Host, Some(READ_TOKEN), None)
            .await
    }
    async fn get_scoped(&self, uri: &str, scope: &[&str]) -> Resp {
        self.call("GET", uri, Who::Host, Some(READ_TOKEN), Some(scope))
            .await
    }
}

fn ids(r: &Resp, key: &str) -> Vec<String> {
    r.json()["items"]
        .as_array()
        .unwrap_or_else(|| panic!("no items: {} {}", r.status, r.text()))
        .iter()
        .map(|i| i[key].as_str().unwrap().to_string())
        .collect()
}

fn inv_ids(r: &Resp) -> Vec<String> {
    ids(r, "invocation_id")
}

fn inv(n: u32) -> String {
    uuid(n)
}

// ---- tests ------------------------------------------------------------------

#[tokio::test]
async fn auth_matrix_on_all_four_routes() {
    for management in [false, true] {
        let fx = Fx::new(management, 0).await;
        let urls = [
            "/v1/proxies".to_string(),
            "/v1/proxies/px-a".to_string(),
            "/v1/proxy-invocations".to_string(),
            format!("/v1/proxy-invocations/{}", inv(1)),
        ];
        for u in &urls {
            // No bearer / wrong bearer with a host cert: 401.
            for b in [None, Some("wrong")] {
                let r = fx.call("GET", u, Who::Host, b, None).await;
                assert_eq!(r.status, 401, "{u} mgmt={management} bearer={b:?}");
                assert_eq!(r.code(), "unauthorized");
            }
            // HEAD takes the same guards as GET.
            for b in [None, Some("wrong")] {
                let r = fx.call("HEAD", u, Who::Host, b, None).await;
                assert_eq!(r.status, 401, "HEAD {u} mgmt={management} bearer={b:?}");
            }
            for who in [Who::Proxy, Who::Ambiguous, Who::NoPeer] {
                let r = fx.call("HEAD", u, who, Some(READ_TOKEN), None).await;
                assert_eq!(r.status, 404, "HEAD {u} mgmt={management}");
            }
            if management {
                let r = fx.call("HEAD", u, Who::Mgmt, Some(MGMT_TOKEN), None).await;
                assert_eq!(r.status, 404, "HEAD {u} mgmt cert");
            }
            // Host cert + read bearer: served.
            let r = fx.call("GET", u, Who::Host, Some(READ_TOKEN), None).await;
            assert_eq!(r.status, 200, "{u} mgmt={management}: {}", r.text());
            // Proxy, management, ambiguous and missing identities are refused,
            // even with the right bearer (and the management token).
            for who in [Who::Proxy, Who::Mgmt, Who::Ambiguous, Who::NoPeer] {
                if who == Who::Mgmt && !management {
                    continue; // without a verifier file this is an ordinary host cert
                }
                for b in [READ_TOKEN, MGMT_TOKEN] {
                    let r = fx.call("GET", u, who, Some(b), None).await;
                    assert_eq!(r.status, 404, "{u} mgmt={management}");
                    assert_eq!(r.json()["error"], "host_unknown");
                }
            }
        }
    }
}

#[tokio::test]
async fn proxies_list_filters_order_and_dto() {
    let fx = Fx::new(true, 0).await;
    let r = fx.get("/v1/proxies").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.content_type.as_deref(), Some("application/json"));
    assert_eq!(
        ids(&r, "proxy_id"),
        ["px-a", "px-b", "px-c"],
        "proxy_id asc"
    );
    assert!(r.json()["next_cursor"].is_null());
    let a = &r.json()["items"][0];
    assert_eq!(a["display_name"], "Proxy A");
    assert_eq!(a["connection_state"], "connected");
    assert_eq!(a["desired_revision"], 3);
    assert_eq!(a["applied_revision"], 3);
    assert_eq!(a["config_in_sync"], true);
    assert_eq!(a["config_state"], "valid");
    assert_eq!(a["current_epoch_id"], EP1);
    assert_eq!(a["spool"]["state"], "degraded");
    assert_eq!(a["spool"]["unsent_events"], 3);
    assert_eq!(a["spool"]["as_of"], "2026-10-11T00:00:00Z");
    assert_eq!(a["status_as_of"], "2026-10-11T00:00:00Z");
    // Server-derived: the sequence jump 5 -> 7 opened one sequence_gap.
    assert_eq!(a["open_gap_count"], 1);
    let b = &r.json()["items"][1];
    assert_eq!(b["connection_state"], "disconnected");
    assert_eq!(b["config_in_sync"], false);
    assert_eq!(b["config_state"], "expired");
    let c = &r.json()["items"][2];
    assert_eq!(c["connection_state"], "never_connected");
    assert_eq!(c["config_in_sync"], false);
    assert!(c["last_seen"].is_null() && c["spool"].is_null() && c["desired_revision"].is_null());
    assert_eq!(c["config_state"], "none");

    let f = |q: &'static str| {
        let fx = &fx;
        async move { ids(&fx.get(&format!("/v1/proxies?{q}")).await, "proxy_id") }
    };
    assert_eq!(f("connection_state=connected").await, ["px-a"]);
    assert_eq!(f("connection_state=disconnected").await, ["px-b"]);
    assert_eq!(f("connection_state=never_connected").await, ["px-c"]);
    assert_eq!(f("config_in_sync=true").await, ["px-a"]);
    assert_eq!(f("config_in_sync=false").await, ["px-b", "px-c"]);
    assert_eq!(
        f("config_in_sync=false&connection_state=disconnected").await,
        ["px-b"]
    );
    assert!(f("config_in_sync=true&connection_state=disconnected")
        .await
        .is_empty());

    // Pagination: one per page, filters bound into the cursor.
    let mut seen = Vec::new();
    let mut uri = "/v1/proxies?limit=1".to_string();
    loop {
        let r = fx.get(&uri).await;
        assert_eq!(r.status, 200);
        seen.extend(ids(&r, "proxy_id"));
        match r.json()["next_cursor"].as_str() {
            Some(c) => uri = format!("/v1/proxies?limit=1&cursor={c}"),
            None => break,
        }
    }
    assert_eq!(seen, ["px-a", "px-b", "px-c"]);
}

#[tokio::test]
async fn invalid_filters_are_422_and_never_echoed() {
    let fx = Fx::new(false, 0).await;
    let secret = "ZZ-echo-canary-ZZ";
    for u in [
        format!("/v1/proxies?{secret}=1"),
        format!("/v1/proxies?connection_state={secret}"),
        format!("/v1/proxies?config_in_sync={secret}"),
        "/v1/proxies?config_in_sync=1".to_string(),
        "/v1/proxies?connection_state=connected&connection_state=connected".to_string(),
        "/v1/proxies?connection_state=".to_string(),
        "/v1/proxies?connection_state=%ff".to_string(),
        "/v1/proxies?connection_state=%zz".to_string(),
        "/v1/proxies?proxy_id=px-a".to_string(),
        format!("/v1/proxy-invocations?{secret}=1"),
        format!("/v1/proxy-invocations?outcome={secret}"),
        format!("/v1/proxy-invocations?method={secret}"),
        format!("/v1/proxy-invocations?lifecycle={secret}"),
        format!("/v1/proxy-invocations?tool_ref={secret}"),
        format!("/v1/proxy-invocations?proxy_id={secret}%20x"),
        format!("/v1/proxy-invocations?from={secret}"),
        "/v1/proxy-invocations?from=2026-10-10T00:00:00%2B09:00".to_string(),
        "/v1/proxy-invocations?to=2026-13-10T00:00:00Z".to_string(),
        "/v1/proxy-invocations?time_basis=sent".to_string(),
        "/v1/proxy-invocations?outcome=success&outcome=denied".to_string(),
        // value and query size caps
        format!("/v1/proxy-invocations?actor_id={}", "a".repeat(257)),
        format!("/v1/proxy-invocations?{}", "a=1&".repeat(600)),
        format!(
            "/v1/proxy-invocations?{}",
            (0..17)
                .map(|i| format!("upstream_id=u{i}"))
                .collect::<Vec<_>>()
                .join("&")
        ),
    ] {
        let r = fx.get(&u).await;
        assert_eq!(r.status, 422, "{u}");
        assert_eq!(r.code(), "invalid_filter", "{u}");
        assert!(!r.text().contains(secret), "value echoed for {u}");
        assert_eq!(r.content_type.as_deref(), Some("application/json"));
    }
}

#[tokio::test]
async fn limit_bounds() {
    let fx = Fx::new(false, 0).await;
    for l in ["0", "501", "-1", "abc", "1.5", "+3", "99999999999999999999"] {
        for base in ["/v1/proxies", "/v1/proxy-invocations"] {
            let r = fx.get(&format!("{base}?limit={l}")).await;
            assert_eq!(
                (r.status, r.code().as_str()),
                (422, "invalid_filter"),
                "{base} {l}"
            );
        }
    }
    for l in ["1", "500", "100"] {
        assert_eq!(
            fx.get(&format!("/v1/proxy-invocations?limit={l}"))
                .await
                .status,
            200
        );
    }
    let r = fx.get("/v1/proxy-invocations?limit=1").await;
    assert_eq!(inv_ids(&r).len(), 1);
    assert!(r.json()["next_cursor"].is_string());
    // default page holds everything here
    assert_eq!(inv_ids(&fx.get("/v1/proxy-invocations").await).len(), 5);
}

#[tokio::test]
async fn invocation_list_filters_and_order() {
    let fx = Fx::new(false, 0).await;
    let list = |q: String| {
        let fx = &fx;
        async move {
            let r = fx.get(&format!("/v1/proxy-invocations?{q}")).await;
            assert_eq!(r.status, 200, "{q}: {}", r.text());
            inv_ids(&r)
        }
    };
    // created_seq descending: inv4 (completion only) was created last.
    assert_eq!(
        list(String::new()).await,
        [inv(4), inv(3), inv(5), inv(2), inv(1)]
    );
    assert_eq!(list("proxy_id=px-b".into()).await, [inv(5)]);
    assert_eq!(
        list("proxy_id=px-a".into()).await,
        [inv(4), inv(3), inv(2), inv(1)]
    );
    assert_eq!(list("upstream_id=up2".into()).await, [inv(3)]);
    assert_eq!(list("actor_id=actor-2".into()).await, [inv(3), inv(5)]);
    assert_eq!(list("method=ping".into()).await, [inv(5), inv(2)]);
    assert_eq!(list("method=tools/call".into()).await, [inv(1)]);
    assert_eq!(list("method=tools%2Fcall".into()).await, [inv(1)]);
    // outcome matches completed records only, never completion_without_start.
    assert_eq!(list("outcome=success".into()).await, [inv(1)]);
    assert_eq!(list("outcome=timeout".into()).await, [inv(3)]);
    assert_eq!(list("outcome=tool_error".into()).await, [inv(5)]);
    assert!(list("outcome=denied".into()).await.is_empty());
    assert_eq!(list("lifecycle=started".into()).await, [inv(2)]);
    assert_eq!(
        list("lifecycle=completion_without_start".into()).await,
        [inv(4)]
    );
    assert_eq!(
        list("lifecycle=completed".into()).await,
        [inv(3), inv(5), inv(1)]
    );
    assert!(list("lifecycle=integrity_conflict".into()).await.is_empty());
    assert_eq!(list(format!("tool_ref={}", mref(1))).await, [inv(1)]);
    assert!(list(format!("tool_ref={}", mref(2))).await.is_empty());
    // received time, half-open [from, to)
    let t = |k: i64| rfc(T0 + k * 1000);
    assert_eq!(
        list(format!("from={}", t(3))).await,
        [inv(4), inv(3), inv(5)]
    );
    assert_eq!(list(format!("to={}", t(2))).await, [inv(1)]);
    assert_eq!(
        list(format!("from={}&to={}", t(2), t(4))).await,
        [inv(5), inv(2)]
    );
    assert_eq!(
        list(format!("from={}&to={}&time_basis=received", t(1), t(2))).await,
        [inv(1)]
    );
    // occurred (proxy clock): started_at of inv1 is :01, inv2 :03, inv3 :04,
    // inv5 :01 (px-b), inv4 has only a completion at :07.
    assert_eq!(
        list("from=2026-10-10T00:00:00Z&to=2026-10-10T00:00:02Z&time_basis=occurred".into()).await,
        [inv(5), inv(1)]
    );
    assert_eq!(
        list("from=2026-10-10T00:00:07Z&time_basis=occurred".into()).await,
        [inv(4)]
    );
    // AND-combination
    assert_eq!(
        list("proxy_id=px-a&method=ping&lifecycle=started".into()).await,
        [inv(2)]
    );
    assert!(list("proxy_id=px-b&method=initialize".into())
        .await
        .is_empty());
    // unknown proxy_id filter: empty, not an error
    assert!(list("proxy_id=px-unknown".into()).await.is_empty());

    // Paging with limit=2 returns every row exactly once, newest first.
    let mut seen = Vec::new();
    let mut uri = "/v1/proxy-invocations?limit=2".to_string();
    loop {
        let r = fx.get(&uri).await;
        seen.extend(inv_ids(&r));
        match r.json()["next_cursor"].as_str() {
            Some(c) => uri = format!("/v1/proxy-invocations?limit=2&cursor={c}"),
            None => break,
        }
    }
    assert_eq!(seen, [inv(4), inv(3), inv(5), inv(2), inv(1)]);
}

#[tokio::test]
async fn invocation_dto_shape() {
    let fx = Fx::new(false, 0).await;
    let r = fx.get(&format!("/v1/proxy-invocations/{}", inv(1))).await;
    assert_eq!(r.status, 200);
    let j = r.json();
    assert_eq!(j["lifecycle"], "completed");
    assert_eq!(j["outcome"], "success");
    assert_eq!(j["delivery_state"], "sent");
    assert_eq!(j["proxy_id"], "px-a");
    assert_eq!(j["method"], "tools/call");
    assert_eq!(j["upstream_id"], "up1");
    assert_eq!(j["actor"]["actor_id"], "actor-1");
    assert_eq!(j["actor"]["authentication_method"], "bearer");
    assert_eq!(j["tool"]["status"], "identified");
    assert_eq!(j["tool"]["metadata_ref"], mref(1));
    assert_eq!(j["decision"], Value::Null);
    assert_eq!(j["duration_ms"], 12);
    assert_eq!(j["response_bytes"], 34);
    assert_eq!(j["flags"], json!([]));
    assert_eq!(j["epoch_superseded"], false);
    assert_eq!(j["events_total"], 2);
    assert_eq!(j["events_truncated"], false);
    let ev = j["events"].as_array().unwrap();
    assert_eq!(ev.len(), 2);
    assert_eq!(ev[0]["event_type"], "invocation.started");
    assert_eq!(ev[1]["event_type"], "invocation.completed");
    for e in ev {
        let mut keys: Vec<&str> = e.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "epoch_id",
                "event_id",
                "event_type",
                "occurred_at",
                "received_at",
                "sequence"
            ],
            "events carry envelope identifiers only"
        );
    }
    // no internal order key leaks
    assert!(j.get("created_seq").is_none() && j.get("event_count").is_none());

    // completion without start: headline outcome withheld, claim in reported_*.
    let j = fx
        .get(&format!("/v1/proxy-invocations/{}", inv(4)))
        .await
        .json();
    assert_eq!(j["lifecycle"], "completion_without_start");
    assert_eq!(j["outcome"], Value::Null);
    assert_eq!(j["reported_outcome"], "success");
    assert_eq!(j["actor"], Value::Null);

    // start only
    let j = fx
        .get(&format!("/v1/proxy-invocations/{}", inv(2)))
        .await
        .json();
    assert_eq!(
        (j["lifecycle"].as_str(), j["outcome"].clone()),
        (Some("started"), Value::Null)
    );
}

#[tokio::test]
async fn invocation_detail_caps_events_at_32() {
    let fx = Fx::new(false, 0).await;
    let mut batch = vec![start("px-b", 10, 100, 50, "ping", None, "up9", "actor-2")];
    for i in 0..40u32 {
        batch.push(cancel("px-b", 11 + i64::from(i), 101 + i, 50));
    }
    fx.ctx
        .ledger
        .insert_batch("px-b", &batch, T0 + 9000)
        .unwrap();
    let j = fx
        .get(&format!("/v1/proxy-invocations/{}", inv(50)))
        .await
        .json();
    assert_eq!(j["events_total"], 41);
    assert_eq!(j["events_truncated"], true);
    assert_eq!(j["events"].as_array().unwrap().len(), 32);
    assert_eq!(j["cancel_observed"], true);
}

#[tokio::test]
async fn proxy_detail_gaps_outages_counters() {
    let fx = Fx::new(true, 20).await;
    let r = fx.get("/v1/proxies/px-a").await;
    assert_eq!(r.status, 200, "{}", r.text());
    let j = r.json();
    // flattened ProxySummary
    assert_eq!(j["proxy_id"], "px-a");
    assert_eq!(j["connection_state"], "connected");
    assert_eq!(
        j["registry"],
        json!({"pending_entries": 2, "sync_stalled": false})
    );
    assert_eq!(
        j["routes"],
        json!([{"upstream_id": "up1", "state": "degraded", "reason": "health_check_failed"}])
    );
    assert_eq!(
        j["central"],
        json!({"last_ingest_ack_at": "2026-10-11T00:00:00Z", "consecutive_failures": 1})
    );
    // 20 reported outages -> newest 16
    let outages = j["outages"].as_array().unwrap();
    assert_eq!(outages.len(), 16);
    let times: Vec<&str> = outages
        .iter()
        .map(|o| o["detected_at"].as_str().unwrap())
        .collect();
    assert!(
        times.windows(2).all(|w| w[0] >= w[1]),
        "newest first: {times:?}"
    );
    assert_eq!(times[0], "2026-10-11T00:19:00Z");
    assert!(outages[0].get("ended_at").is_some());
    // counters: current epoch values and previous totals
    let c = &j["counters"];
    assert_eq!(c["epoch_id"], EP1);
    assert_eq!(
        c["auth_failures"],
        json!([{"upstream_id": "up1", "reason": "credential_invalid", "count": 5}])
    );
    assert_eq!(
        c["unmatched_cancels"],
        json!([{"upstream_id": null, "reason": "no_matching_request", "count": 2}])
    );
    assert_eq!(
        c["previous_epoch_totals"],
        json!([{"epoch_id": uuid(77), "auth_failures": 9, "unmatched_cancels": 4}])
    );
    // gaps: 20 proxy-reported + 1 server-derived sequence_gap; page max 50
    assert_eq!(j["audit_gaps_total"], 21);
    let gaps = j["audit_gaps"].as_array().unwrap();
    assert_eq!(gaps.len(), 21);
    let seqgap = gaps
        .iter()
        .find(|g| g["kind"] == "sequence_gap")
        .expect("derived sequence_gap");
    assert_eq!(seqgap["source"], "server_derived");
    assert_eq!(seqgap["state"], "open");
    assert_eq!(
        seqgap["details"],
        json!({"epoch_id": EP1, "from_sequence": 6, "to_sequence": 6, "tail": false})
    );
    let rep = gaps.iter().find(|g| g["kind"] == "central_outage").unwrap();
    assert_eq!(rep["source"], "proxy_reported");
    assert_eq!(rep["state"], "open");
    assert!(rep["details"].get("kind").is_none() && rep["details"].get("gap_id").is_none());
    assert_eq!(
        j["open_gap_counts"],
        json!({"central_outage": 20, "sequence_gap": 1})
    );
    assert_eq!(j["open_gap_count"], 21);

    // px-c has no state at all: nulls and empties, still 200.
    let j = fx.get("/v1/proxies/px-c").await.json();
    assert_eq!(j["connection_state"], "never_connected");
    assert_eq!(j["routes"], json!([]));
    assert_eq!(j["audit_gaps"], json!([]));
    assert_eq!(j["audit_gaps_total"], 0);
    assert_eq!(j["open_gap_counts"], json!({}));
    assert_eq!(j["registry"], Value::Null);
    assert_eq!(j["counters"]["auth_failures"], json!([]));
}

#[tokio::test]
async fn audit_gaps_page_is_capped_at_50() {
    let fx = Fx::new(false, 60).await;
    let j = fx.get("/v1/proxies/px-a").await.json();
    assert_eq!(j["audit_gaps"].as_array().unwrap().len(), 50);
    assert_eq!(j["audit_gaps_total"], 61);
    assert_eq!(j["outages"].as_array().unwrap().len(), 16);
}

#[tokio::test]
async fn cursor_binding_and_forgery() {
    let fx = Fx::new(false, 0).await;
    let first = |u: &'static str| {
        let fx = &fx;
        async move {
            fx.get(u).await.json()["next_cursor"]
                .as_str()
                .unwrap()
                .to_string()
        }
    };
    let c_inv = first("/v1/proxy-invocations?limit=1").await;
    let c_inv_f = first("/v1/proxy-invocations?limit=1&proxy_id=px-a").await;
    let c_inv_o = first("/v1/proxy-invocations?limit=1&proxy_id=px-a&time_basis=occurred").await;
    let c_px = first("/v1/proxies?limit=1").await;
    let c_px_f = first("/v1/proxies?limit=1&config_in_sync=false").await;
    let bad = |r: Resp, what: &str| {
        assert_eq!(
            (r.status, r.code().as_str()),
            (422, "invalid_cursor"),
            "{what}: {}",
            r.text()
        );
        assert!(r.json()["error"]["message"].is_string());
    };
    // sanity: each cursor works where it was minted
    assert_eq!(
        fx.get(&format!("/v1/proxy-invocations?limit=1&cursor={c_inv}"))
            .await
            .status,
        200
    );
    assert_eq!(
        fx.get(&format!("/v1/proxies?limit=1&cursor={c_px}"))
            .await
            .status,
        200
    );
    // another endpoint
    bad(
        fx.get(&format!("/v1/proxy-invocations?cursor={c_px}"))
            .await,
        "px->inv",
    );
    bad(
        fx.get(&format!("/v1/proxies?cursor={c_inv}")).await,
        "inv->px",
    );
    // another filter set (added, removed, changed)
    bad(
        fx.get(&format!(
            "/v1/proxy-invocations?cursor={c_inv}&proxy_id=px-a"
        ))
        .await,
        "filter added",
    );
    bad(
        fx.get(&format!("/v1/proxy-invocations?cursor={c_inv_f}"))
            .await,
        "filter removed",
    );
    bad(
        fx.get(&format!(
            "/v1/proxy-invocations?cursor={c_inv_f}&proxy_id=px-b"
        ))
        .await,
        "filter changed",
    );
    bad(
        fx.get(&format!(
            "/v1/proxy-invocations?cursor={c_inv_o}&proxy_id=px-a"
        ))
        .await,
        "time_basis changed",
    );
    bad(
        fx.get(&format!("/v1/proxies?cursor={c_px_f}")).await,
        "proxies filter removed",
    );
    bad(
        fx.get(&format!("/v1/proxies?cursor={c_px}&config_in_sync=false"))
            .await,
        "proxies filter added",
    );
    // the same filter in another spelling/order still matches (normalised)
    assert_eq!(
        fx.get(&format!(
            "/v1/proxy-invocations?proxy_id=px-a&limit=1&time_basis=received&cursor={c_inv_f}"
        ))
        .await
        .status,
        200
    );
    // malformed / forged / oversized
    let enc = |v: Value| data_encoding::BASE64URL_NOPAD.encode(v.to_string().as_bytes());
    for forged in [
        "!!!not-base64!!!".to_string(),
        "AAAA".to_string(),
        data_encoding::BASE64URL_NOPAD.encode(b"not json"),
        enc(json!({"v": 1, "key": 3})),
        enc(json!({"v": 2, "key": 3, "filter_hash": "x"})),
        enc(json!({"v": 1, "key": 3, "filter_hash": "x"})),
        enc(json!({"v": 1, "key": 3, "filter_hash": "x", "extra": 1})),
        enc(json!([1, 2, 3])),
        "A".repeat(513),
        "A".repeat(60_000),
    ] {
        bad(
            fx.get(&format!("/v1/proxy-invocations?cursor={forged}"))
                .await,
            "forged inv",
        );
        bad(
            fx.get(&format!("/v1/proxies?cursor={forged}")).await,
            "forged px",
        );
    }
    // a right-hash cursor with a wrong key type is still invalid: take a real
    // hash from a minted cursor and swap the key.
    let real: Value = serde_json::from_slice(
        &data_encoding::BASE64URL_NOPAD
            .decode(c_inv.as_bytes())
            .unwrap(),
    )
    .unwrap();
    let hash = real["filter_hash"].clone();
    for key in [
        json!("text"),
        json!(-1),
        json!(0),
        json!(1.5),
        json!(null),
        json!([1]),
    ] {
        bad(
            fx.get(&format!(
                "/v1/proxy-invocations?cursor={}",
                enc(json!({"v": 1, "key": key, "filter_hash": hash}))
            ))
            .await,
            "bad key type",
        );
    }
    // a right-hash proxies cursor with a non-id key
    let real: Value = serde_json::from_slice(
        &data_encoding::BASE64URL_NOPAD
            .decode(c_px.as_bytes())
            .unwrap(),
    )
    .unwrap();
    for key in [json!(5), json!("has space"), json!("")] {
        bad(
            fx.get(&format!(
                "/v1/proxies?cursor={}",
                enc(json!({"v": 1, "key": key, "filter_hash": real["filter_hash"]}))
            ))
            .await,
            "bad proxies key",
        );
    }
    // a forged key with the right hash is just a position in the same listing
    let ok = fx
        .get(&format!(
            "/v1/proxy-invocations?cursor={}",
            enc(json!({"v": 1, "key": 1_000_000, "filter_hash": hash}))
        ))
        .await;
    assert_eq!(ok.status, 200);
    assert_eq!(inv_ids(&ok).len(), 5);
    // filter errors win over cursor errors
    let r = fx
        .get("/v1/proxy-invocations?cursor=garbage&outcome=bogus")
        .await;
    assert_eq!(r.code(), "invalid_filter");
}

#[tokio::test]
async fn unknown_and_out_of_scope_are_byte_identical_404() {
    let fx = Fx::new(false, 0).await;
    let scope: &[&str] = &["px-a"];
    let unknown_proxy = fx.get_scoped("/v1/proxies/px-nope", scope).await;
    assert_eq!(
        (unknown_proxy.status, unknown_proxy.code().as_str()),
        (404, "proxy_unknown")
    );
    let oos_proxy = fx.get_scoped("/v1/proxies/px-b", scope).await;
    assert_eq!(
        oos_proxy, unknown_proxy,
        "out-of-scope proxy == unknown proxy"
    );
    assert_eq!(fx.get("/v1/proxies/px-nope").await, unknown_proxy);
    // the guard's own proxy_unknown (identity failures) uses the same bytes
    assert_eq!(unknown_proxy.body, guard_unknown_body().await);

    let unknown_inv = fx
        .get_scoped(&format!("/v1/proxy-invocations/{}", inv(999)), scope)
        .await;
    assert_eq!(
        (unknown_inv.status, unknown_inv.code().as_str()),
        (404, "proxy_unknown")
    );
    // inv5 belongs to px-b, which is out of scope
    let oos_inv = fx
        .get_scoped(&format!("/v1/proxy-invocations/{}", inv(5)), scope)
        .await;
    assert_eq!(oos_inv, unknown_inv);
    assert_eq!(unknown_inv.body, unknown_proxy.body);
    // in scope still works
    assert_eq!(
        fx.get_scoped(&format!("/v1/proxy-invocations/{}", inv(1)), scope)
            .await
            .status,
        200
    );
    // not a UUID: the same answer, not a 422
    let junk = fx.get("/v1/proxy-invocations/not-a-uuid").await;
    assert_eq!(junk, unknown_inv);

    // out-of-scope and unknown proxy_id filters: identical empty list
    let oos_list = fx
        .get_scoped("/v1/proxy-invocations?proxy_id=px-b", scope)
        .await;
    let unk_list = fx
        .get_scoped("/v1/proxy-invocations?proxy_id=px-nope", scope)
        .await;
    assert_eq!(oos_list.status, 200);
    assert_eq!(oos_list, unk_list);
    assert_eq!(oos_list.json(), json!({"items": [], "next_cursor": null}));
    // lists only contain in-scope rows
    let all = fx.get_scoped("/v1/proxy-invocations", scope).await;
    assert_eq!(inv_ids(&all), [inv(4), inv(3), inv(2), inv(1)]);
    assert_eq!(
        ids(&fx.get_scoped("/v1/proxies", scope).await, "proxy_id"),
        ["px-a"]
    );
    // empty scope sees nothing
    let none: &[&str] = &[];
    assert!(inv_ids(&fx.get_scoped("/v1/proxy-invocations", none).await).is_empty());
    assert!(ids(&fx.get_scoped("/v1/proxies", none).await, "proxy_id").is_empty());
    assert_eq!(fx.get_scoped("/v1/proxies/px-a", none).await, unknown_proxy);
}

async fn guard_unknown_body() -> Vec<u8> {
    use axum::response::IntoResponse as _;
    let r = sigil_server::proxy::guard::proxy_unknown().into_response();
    axum::body::to_bytes(r.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec()
}

#[tokio::test]
async fn ac05_no_stored_content_in_any_response() {
    let fx = Fx::new(true, 20).await;
    let canaries = [
        CANARY_UPSTREAM,
        CANARY_CRED,
        CANARY_ORIGIN,
        CANARY_PRINCIPAL_TOKEN,
        &verifier_for(CANARY_PRINCIPAL_TOKEN),
        FP_A,
        READ_TOKEN,
        MGMT_TOKEN,
        MGMT_FP,
        "verifier",
        "upstream_url",
        "credential_ref",
        "allowed_origins",
        "fp_current",
        "canonical",
        "created_seq",
    ];
    let mut urls = vec![
        "/v1/proxies".to_string(),
        "/v1/proxies/px-a".to_string(),
        "/v1/proxies/px-b".to_string(),
        "/v1/proxies/px-c".to_string(),
        "/v1/proxy-invocations".to_string(),
        "/v1/proxies/px-nope".to_string(),
        "/v1/proxy-invocations?outcome=bogus".to_string(),
        "/v1/proxy-invocations?cursor=zz".to_string(),
    ];
    for n in 1..=5 {
        urls.push(format!("/v1/proxy-invocations/{}", inv(n)));
    }
    for u in urls {
        for r in [
            fx.get(&u).await,
            fx.call("GET", &u, Who::Host, Some("wrong"), None).await,
            fx.call("GET", &u, Who::Proxy, Some(READ_TOKEN), None).await,
            fx.call("GET", &u, Who::Mgmt, Some(MGMT_TOKEN), None).await,
        ] {
            let t = r.text();
            for c in canaries {
                assert!(!t.contains(c), "canary {c:?} in response to {u}: {t}");
            }
        }
    }
}

#[tokio::test]
async fn connection_state_is_derived_at_read_time() {
    let fx = Fx::new(false, 0).await;
    let set = |id: &'static str, last_seen: Option<String>| {
        let txn = fx.ctx.store.begin();
        let mut e = txn.entry(id);
        e.last_seen = last_seen;
        txn.commit(id, e).unwrap();
    };
    let state_of = |id: &'static str| {
        let fx = &fx;
        async move {
            fx.get(&format!("/v1/proxies/{id}")).await.json()["connection_state"]
                .as_str()
                .unwrap()
                .to_string()
        }
    };
    // comfortably inside / outside 90 s; the exact boundary is a unit test in
    // query.rs (a wall-clock race here would flake)
    set("px-b", Some(rfc(fx.now - 60)));
    assert_eq!(state_of("px-b").await, "connected");
    set("px-b", Some(rfc(fx.now - 200)));
    assert_eq!(state_of("px-b").await, "disconnected");
    set("px-b", None);
    assert_eq!(state_of("px-b").await, "never_connected");
    // nothing about it is stored: the list agrees with the detail
    set("px-b", Some(rfc(fx.now)));
    assert_eq!(
        ids(
            &fx.get("/v1/proxies?connection_state=connected").await,
            "proxy_id"
        ),
        ["px-a", "px-b"]
    );
}

#[tokio::test]
async fn get_proxies_is_not_captured_by_management() {
    // Management configured: GET /v1/proxies{,/id} reach the read handlers for
    // a host cert, and a management cert is refused by the read guard (not
    // treated as a management request).
    let on = Fx::new(true, 0).await;
    assert_eq!(on.get("/v1/proxies").await.status, 200);
    assert_eq!(on.get("/v1/proxies/px-a").await.status, 200);
    let r = on
        .call("GET", "/v1/proxies", Who::Mgmt, Some(MGMT_TOKEN), None)
        .await;
    assert_eq!(
        (r.status, r.json()["error"].clone()),
        (404, json!("host_unknown"))
    );
    let r = on
        .call("GET", "/v1/proxies/px-a", Who::Mgmt, Some(MGMT_TOKEN), None)
        .await;
    assert_eq!(
        (r.status, r.json()["error"].clone()),
        (404, json!("host_unknown"))
    );
    // POST /v1/proxies is still the management registration (201 / 422 / 401),
    // never swallowed by the new GET route.
    let post = |bearer: Option<&str>, who: Who, body: &str| {
        let on = &on;
        let body = body.to_string();
        let bearer = bearer.map(str::to_string);
        async move {
            let mut req = Request::builder()
                .method("POST")
                .uri("/v1/proxies")
                .header("content-type", "application/json");
            if let Some(b) = &bearer {
                req = req.header("authorization", format!("Bearer {b}"));
            }
            let mut req = req.body(Body::from(body)).unwrap();
            if let Some(p) = on.peer(who) {
                req.extensions_mut().insert(Arc::new(p));
            }
            on.app.clone().oneshot(req).await.unwrap().status().as_u16()
        }
    };
    assert_eq!(
        post(
            Some(MGMT_TOKEN),
            Who::Mgmt,
            r#"{"proxy_id":"px-new","display_name":"N"}"#
        )
        .await,
        201
    );
    assert_eq!(post(Some("wrong"), Who::Mgmt, "{}").await, 401);
    // the new proxy shows up in the read listing
    assert!(ids(&on.get("/v1/proxies").await, "proxy_id").contains(&"px-new".to_string()));
    // a host cert cannot register
    assert_eq!(
        post(
            Some(READ_TOKEN),
            Who::Host,
            r#"{"proxy_id":"px-x","display_name":"N"}"#
        )
        .await,
        404
    );

    // Management not configured: reads work, POST stays the plain 404.
    let off = Fx::new(false, 0).await;
    assert_eq!(off.get("/v1/proxies").await.status, 200);
    assert_eq!(off.get("/v1/proxies/px-a").await.status, 200);
    let r = off
        .call("POST", "/v1/proxies", Who::Host, Some(READ_TOKEN), None)
        .await;
    assert_eq!((r.status, r.body.len()), (404, 0));
    let r = off
        .call("POST", "/v1/proxies", Who::Mgmt, Some(MGMT_TOKEN), None)
        .await;
    assert_eq!(r.status, 404);
    // other methods on the read paths are not served
    for m in ["PUT", "DELETE", "PATCH"] {
        let r = off
            .call(
                m,
                "/v1/proxy-invocations",
                Who::Host,
                Some(READ_TOKEN),
                None,
            )
            .await;
        assert_eq!(r.status, 405, "{m}");
    }
}

#[tokio::test]
async fn ledger_failure_is_503_storage_unavailable() {
    let fx = Fx::new(false, 0).await;
    // Break the projection table underneath the read connections.
    {
        let c = rusqlite::Connection::open(&fx.ledger_path).unwrap();
        c.execute_batch("DROP TABLE projections;").unwrap();
    }
    let ledger_urls = [
        "/v1/proxy-invocations".to_string(),
        format!("/v1/proxy-invocations/{}", inv(1)),
        "/v1/proxies".to_string(),
        "/v1/proxies/px-a".to_string(),
    ];
    let mut served_503 = 0;
    for u in &ledger_urls {
        let r = fx.get(u).await;
        if r.status == 503 {
            served_503 += 1;
            assert_eq!(r.code(), "storage_unavailable", "{u}");
        }
    }
    // the two projection-backed routes must fail closed
    assert!(served_503 >= 2, "projection reads must answer 503");
    for u in [
        "/v1/proxy-invocations".to_string(),
        format!("/v1/proxy-invocations/{}", inv(1)),
    ] {
        let r = fx.get(&u).await;
        assert_eq!(
            (r.status, r.code().as_str()),
            (503, "storage_unavailable"),
            "{u}"
        );
        assert!(!r.text().contains("projections"), "no SQL detail leaks");
    }
}

#[tokio::test]
async fn query_timeout_maps_to_503() {
    let fx = Fx::new(false, 0).await;
    // a 0 ms limit interrupts every statement that is still running; reading
    // all five projections plus the join is not guaranteed to be interrupted,
    // so accept 200 or 503 but never a 5xx with another code.
    fx.ctx.ledger.set_read_timeout_for_test(0);
    for u in ["/v1/proxy-invocations", "/v1/proxies/px-a", "/v1/proxies"] {
        let r = fx.get(u).await;
        assert!(
            r.status == 200 || (r.status == 503 && r.code() == "storage_unavailable"),
            "{u}: {} {}",
            r.status,
            r.text()
        );
    }
}
