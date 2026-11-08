//! T-13a-server (issue #304) — `POST /v1/proxy-inventory`, the inventory
//! projection and its read views (registry.md R5, R7, R7b; ledger-and-query.md
//! L3, L4).
//!
//! HTTP tests run in-process through `build_router_with_proxy` (the production
//! router) with `tower::oneshot`; the TLS layer is replaced by the
//! `PeerIdentity` extension the TLS acceptor sets. The live mTLS run is in
//! `lodeline-proxy-e2e/tests/server_proxy_inventory_e2e.rs`. Ledger-level tests
//! (reordering, retention, migration) call the storage layer directly.
//! PX-005/009/010/011, AC-02/05/06.
#![cfg(unix)]

use axum::body::Body;
use axum::http::Request;
use lodeline_proxy_api::verifier::verifier_for;
use lodeline_proxy_api::{parse_config, parse_inventory_report, RegistryEntry};
use lodeline_server::app::{build_router_with_proxy, AppState};
use lodeline_server::auth::ReadToken;
use lodeline_server::config::ServerConfig;
use lodeline_server::fleet_index::FleetIndex;
use lodeline_server::persist::HighWater;
use lodeline_server::proxy::identity::proxy_san;
use lodeline_server::proxy::ledger::{Ledger, LedgerError, LedgerOptions, SCHEMA_VERSION};
use lodeline_server::proxy::ledger_inventory::{
    report_digest, InvFilter, InventoryOutcome, RefCheck,
};
use lodeline_server::proxy::query::TestScope;
use lodeline_server::proxy::registry::{ProxyRecord, ProxyState};
use lodeline_server::proxy::store::{ProxyEntry, StoredConfig};
use lodeline_server::proxy::verifiers::{Scope, VerifierEntry};
use lodeline_server::proxy::ProxyContext;
use lodeline_server::tls_accept::PeerIdentity;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};
use tower::ServiceExt;

const READ_TOKEN: &str = "read-bearer-CANARY-inv";
const MGMT_TOKEN: &str = "tok-mgmt-CANARY-inv";
const FP_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const FP_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const FP_D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const FP_X: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const HOST_FP: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const MGMT_FP: &str = "1111111111111111111111111111111111111111111111111111111111111111";

const UP1: &str = "up1";
const UP2: &str = "up2";
const CS1: &str = "cs-0123456789abcdef0123456789abcdef";
const CS2: &str = "cs-fedcba9876543210fedcba9876543210";
const CS_B: &str = "cs-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

// Content that must never reach a response: the tool definition, a fingerprint
// and values supplied in rejected requests.
const CANARY_NAME: &str = "CANARY-TOOL-NAME-7f3a";
const CANARY_DESC: &str = "CANARY-TOOL-DESC-91bc";
const CANARY_UP: &str = "canary-unassigned-upstream";

fn uuid(n: u32) -> String {
    format!("00000000-0000-4000-8000-{n:012}")
}
fn mref(n: u32) -> String {
    format!("00000000-0000-8000-8000-{n:012}")
}
fn inv_id(n: u32) -> String {
    uuid(1000 + n)
}
fn rep_id(n: u32) -> String {
    uuid(2000 + n)
}
fn epoch(n: u32) -> String {
    uuid(3000 + n)
}
fn kid(n: u32) -> String {
    format!("kid-{n:024x}")
}
fn at(s: u32) -> String {
    format!(
        "2026-10-10T{:02}:{:02}:{:02}Z",
        s / 3600,
        (s / 60) % 60,
        s % 60
    )
}

// ---- report builders ----------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn rep(
    proxy: &str,
    rid: u32,
    inv: u32,
    obs: u32,
    up: &str,
    cs: &str,
    key: u32,
    ep: u32,
    members: &[u32],
    cmp: Value,
) -> Value {
    json!({
        "schema_version": 1,
        "report_id": rep_id(rid),
        "proxy_id": proxy,
        "epoch_id": epoch(ep),
        "observed_at": at(obs),
        "scope": {
            "upstream_id": up,
            "credential_scope_id": cs,
            "protocol_version": "2025-11-25",
            "observation_source": "proxy_live",
        },
        "canon": "sigil-tooldef-fp-v1",
        "key_id": kid(key),
        "completeness": "complete",
        "pages_observed": 1,
        "inventory_id": inv_id(inv),
        "members": members.iter().map(|m| mref(*m)).collect::<Vec<_>>(),
        "comparison": cmp,
    })
}

fn incomplete(
    proxy: &str,
    rid: u32,
    obs: u32,
    up: &str,
    cs: &str,
    key: u32,
    reason: &str,
) -> Value {
    json!({
        "schema_version": 1,
        "report_id": rep_id(rid),
        "proxy_id": proxy,
        "epoch_id": epoch(1),
        "observed_at": at(obs),
        "scope": {
            "upstream_id": up,
            "credential_scope_id": cs,
            "protocol_version": "2025-11-25",
            "observation_source": "proxy_live",
        },
        "canon": "sigil-tooldef-fp-v1",
        "key_id": kid(key),
        "completeness": "incomplete",
        "pages_observed": 3,
        "incomplete_reason": reason,
    })
}

fn initial() -> Value {
    json!({"kind": "initial_baseline"})
}
fn compared(prev: u32, changes: Vec<Value>) -> Value {
    json!({"kind": "compared", "previous_inventory_id": inv_id(prev), "changes": changes})
}
fn rebase(prev: u32, reason: &str, links: &[(u32, u32)]) -> Value {
    json!({
        "kind": "rebaseline",
        "previous_inventory_id": inv_id(prev),
        "reason": reason,
        "links": links.iter().map(|(a, b)| json!({
            "from_metadata_ref": mref(*a),
            "to_metadata_ref": mref(*b),
            "definition_comparison": "identical",
        })).collect::<Vec<_>>(),
    })
}
fn added(n: u32) -> Value {
    json!({"change": "added", "metadata_ref": mref(n)})
}
fn removed(n: u32) -> Value {
    json!({"change": "removed", "metadata_ref": mref(n)})
}
fn changed(n: u32, old: u32) -> Value {
    json!({"change": "changed", "metadata_ref": mref(n), "previous_metadata_ref": mref(old)})
}

// ---- shared CA files ----------------------------------------------------------

fn make_ca(dir: &Path, name: &str, cn: &str) {
    let openssl = lodeline_server::enroll::sign::resolve_openssl().expect("openssl");
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

/// CA files are read-only inputs, so every fixture shares one generated set.
fn pki() -> &'static Path {
    static D: OnceLock<tempfile::TempDir> = OnceLock::new();
    D.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        make_ca(d, "hostca", "test-host-ca");
        make_ca(d, "proxyca", "test-proxy-ca");
        let mut bundle = std::fs::read(d.join("hostca.crt")).unwrap();
        bundle.extend(std::fs::read(d.join("proxyca.crt")).unwrap());
        std::fs::write(d.join("bundle.pem"), bundle).unwrap();
        dir
    })
    .path()
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

fn record(id: &str, st: ProxyState, fp: &str) -> ProxyRecord {
    ProxyRecord {
        proxy_id: id.into(),
        display_name: format!("Proxy {id}"),
        state: st,
        fp_current: Some(fp.into()),
        fp_next: None,
        created_at: "2026-10-01T00:00:00Z".into(),
        updated_at: "2026-10-01T00:00:00Z".into(),
    }
}

fn config_with(proxy: &str, routes: &[(&str, &str, &str)]) -> StoredConfig {
    let r: Vec<Value> = routes
        .iter()
        .map(|(rid, up, cs)| {
            json!({"route_id": rid, "upstream_id": up,
                "upstream_url": format!("https://{rid}.canary-origin.example/mcp"),
                "upstream_protocol": "2025-11-25", "credential_ref": "canary-cred",
                "credential_scope_id": cs})
        })
        .collect();
    let ids: Vec<&str> = routes.iter().map(|r| r.0).collect();
    let v = json!({
        "schema_version": 1, "proxy_id": proxy, "revision": 1,
        "issued_at": "2026-10-11T00:00:00Z", "expires_at": "2026-10-11T00:05:00Z",
        "ttl_seconds": 300, "mode": "observe",
        "max_offline_retry_age_seconds": 2592000, "event_retention_seconds": 7776000,
        "allowed_origins": ["https://canary-origin.example"],
        "routes": r,
        "principals": [{"principal_id": "claude",
            "verifiers": [{"key_id": "k1", "verifier": verifier_for("canary-principal")}],
            "routes": ids}],
    });
    StoredConfig {
        config: parse_config(v.to_string().as_bytes()).unwrap(),
        config_hash: "0".repeat(64),
        updated_at: "2026-10-11T00:00:00Z".into(),
    }
}

fn reg_entry(proxy: &str, n: u32, up: &str, cs: &str, key: u32) -> RegistryEntry {
    serde_json::from_value(json!({
        "proxy_id": proxy,
        "metadata_ref": mref(n),
        "upstream_id": up,
        "credential_scope_id": cs,
        "protocol_version": "2025-11-25",
        "observation_source": "proxy_live",
        "canon": "sigil-tooldef-fp-v1",
        "key_id": kid(key),
        "fingerprint": format!("{:064x}", u128::from(n) + 0xfeed_0000),
        "observed_at": "2026-10-10T00:00:00Z",
        "definition": {"name": CANARY_NAME, "description": CANARY_DESC},
    }))
    .unwrap()
}

// ---- fixture -------------------------------------------------------------------

struct Fx {
    _dir: tempfile::TempDir,
    ctx: Arc<ProxyContext>,
    app: axum::Router,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Who {
    Host,
    Mgmt,
    Proxy(&'static str),
    Ambiguous,
    NoPeer,
}
const A: Who = Who::Proxy("px-a");
const B: Who = Who::Proxy("px-b");

#[derive(Debug, PartialEq, Eq, Clone)]
struct Resp {
    status: u16,
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
    fn items(&self) -> Vec<Value> {
        self.json()["items"]
            .as_array()
            .unwrap_or_else(|| panic!("no items: {} {}", self.status, self.text()))
            .clone()
    }
}

impl Fx {
    async fn new() -> Fx {
        Self::build(false).await
    }

    async fn build(management: bool) -> Fx {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let p = pki();
        let pp = |f: &str| p.join(f).display().to_string();
        let mut y = format!(
            "bind: \"127.0.0.1:0\"\ntls_cert_path: {}\ntls_key_path: {}\nclient_ca_path: {}\n\
             events_out_dir: {}\npolicy_bundle_path: {}\n\
             proxy:\n  ca_path: {}\n  registry_path: {}\n  registry_init: true\n",
            pp("server.crt"),
            pp("server.key"),
            pp("bundle.pem"),
            d.display(),
            d.join("signed-policy.json").display(),
            pp("proxyca.crt"),
            d.join("proxies.json").display(),
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
        let ctx = Arc::new(ProxyContext::load(&cfg).unwrap().unwrap());
        for (id, st, fp) in [
            ("px-a", ProxyState::Active, FP_A),
            ("px-b", ProxyState::Active, FP_B),
            ("px-c", ProxyState::Pending, FP_X),
            ("px-d", ProxyState::Disabled, FP_D),
        ] {
            ctx.registry.seed_for_test(record(id, st, fp)).unwrap();
        }
        for (id, routes) in [
            ("px-a", vec![("r1", UP1, CS1), ("r2", UP2, CS2)]),
            ("px-b", vec![("r1", UP1, CS_B)]),
        ] {
            ctx.store
                .begin()
                .commit(
                    id,
                    ProxyEntry {
                        config: Some(config_with(id, &routes)),
                        ..Default::default()
                    },
                )
                .unwrap();
        }
        let app = build_router_with_proxy(state(d), Some(ctx.clone()));
        Fx {
            _dir: dir,
            ctx,
            app,
        }
    }

    /// Register refs `ns` for `proxy` in `(up, cs)` under key number `key`.
    fn reg(&self, proxy: &str, up: &str, cs: &str, key: u32, ns: &[u32]) {
        let entries: Vec<RegistryEntry> = ns
            .iter()
            .map(|n| reg_entry(proxy, *n, up, cs, key))
            .collect();
        self.ctx.metadata.register(proxy, &entries, 1_000).unwrap();
    }

    /// The common set: refs 1..=40 for px-a under (up1, CS1, key 1).
    fn reg_default(&self) {
        let all: Vec<u32> = (1..=40).collect();
        self.reg("px-a", UP1, CS1, 1, &all);
    }

    fn peer(&self, who: Who) -> Option<PeerIdentity> {
        let mk = |fp: &str, issuer: &str| PeerIdentity {
            fingerprint: fp.into(),
            cn: Some("c".into()),
            san_dns: vec![],
            issuer_dn: Some(issuer.into()),
            issuer_aki: None,
        };
        let proxy = |id: &str, fp: &str| PeerIdentity {
            fingerprint: fp.into(),
            cn: Some(id.into()),
            san_dns: vec![proxy_san(id)],
            issuer_dn: Some(self.ctx.ca.subject_dn.clone()),
            issuer_aki: None,
        };
        match who {
            Who::Host => Some(mk(HOST_FP, "CN=test-host-ca")),
            Who::Mgmt => Some(mk(MGMT_FP, "CN=test-host-ca")),
            Who::Proxy("px-a") => Some(proxy("px-a", FP_A)),
            Who::Proxy("px-b") => Some(proxy("px-b", FP_B)),
            Who::Proxy("px-c") => Some(proxy("px-c", FP_X)),
            Who::Proxy("px-d") => Some(proxy("px-d", FP_D)),
            Who::Proxy(other) => Some(proxy(other, FP_X)),
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
        body: Option<String>,
    ) -> Resp {
        let mut req = Request::builder().method(method).uri(uri);
        if let Some(b) = bearer {
            req = req.header("authorization", format!("Bearer {b}"));
        }
        let mut req = req.body(body.map_or_else(Body::empty, Body::from)).unwrap();
        if let Some(p) = self.peer(who) {
            req.extensions_mut().insert(Arc::new(p));
        }
        if let Some(s) = scope {
            req.extensions_mut()
                .insert(TestScope(s.iter().map(|x| x.to_string()).collect()));
        }
        let r = self.app.clone().oneshot(req).await.unwrap();
        let status = r.status().as_u16();
        let body = axum::body::to_bytes(r.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        Resp { status, body }
    }

    async fn post_raw(&self, who: Who, body: String) -> Resp {
        self.call("POST", "/v1/proxy-inventory", who, None, None, Some(body))
            .await
    }
    async fn post(&self, who: Who, report: &Value) -> Resp {
        self.post_raw(who, report.to_string()).await
    }
    /// POST that must be a first-time 200.
    async fn ok(&self, who: Who, report: &Value) {
        let r = self.post(who, report).await;
        assert_eq!(r.status, 200, "{}", r.text());
        assert_eq!(r.json()["duplicate"], false, "{}", r.text());
    }
    async fn get(&self, uri: &str) -> Resp {
        self.call("GET", uri, Who::Host, Some(READ_TOKEN), None, None)
            .await
    }
    async fn snaps(&self, proxy: &str) -> Vec<Value> {
        self.get(&format!(
            "/v1/proxies/{proxy}/inventory-snapshots?limit=500"
        ))
        .await
        .items()
    }
    async fn drift(&self, proxy: &str) -> Vec<Value> {
        self.get(&format!("/v1/proxies/{proxy}/drift?limit=500"))
            .await
            .items()
    }
    async fn markers(&self, proxy: &str) -> Vec<Value> {
        self.get(&format!("/v1/proxies/{proxy}/rebaseline-markers?limit=500"))
            .await
            .items()
    }
    async fn gaps(&self, proxy: &str, kind: &str) -> Vec<Value> {
        let r = self.get(&format!("/v1/proxies/{proxy}")).await;
        assert_eq!(r.status, 200, "{}", r.text());
        r.json()["audit_gaps"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|g| g["kind"] == kind)
            .cloned()
            .collect()
    }
}

fn snap(all: &[Value], inv: u32) -> &Value {
    all.iter()
        .find(|s| s["inventory_id"] == inv_id(inv).as_str())
        .unwrap_or_else(|| panic!("snapshot {inv} not listed in {all:?}"))
}

/// (change, metadata_ref, previous_metadata_ref) of the drift rows, sorted.
fn drift_set(all: &[Value]) -> BTreeSet<(String, String, String)> {
    all.iter()
        .map(|d| {
            (
                d["change"].as_str().unwrap().to_string(),
                d["metadata_ref"].as_str().unwrap().to_string(),
                d["previous_metadata_ref"]
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
            )
        })
        .collect()
}

// ===== Cases (registry.md R7) =======================================================

#[tokio::test]
async fn case_first_complete_listing_is_an_initial_baseline_with_no_drift() {
    let fx = Fx::new().await;
    fx.reg_default();
    fx.ok(
        A,
        &rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1, 2, 3], initial()),
    )
    .await;
    let s = fx.snaps("px-a").await;
    assert_eq!(s.len(), 1);
    let s0 = &s[0];
    assert_eq!(s0["inventory_id"], inv_id(1).as_str());
    assert_eq!(s0["proxy_id"], "px-a");
    assert_eq!(s0["upstream_id"], UP1);
    assert_eq!(s0["credential_scope_id"], CS1);
    assert_eq!(s0["protocol_version"], "2025-11-25");
    assert_eq!(s0["observation_source"], "proxy_live");
    assert_eq!(s0["canon"], "sigil-tooldef-fp-v1");
    assert_eq!(s0["key_id"], kid(1).as_str());
    assert_eq!(s0["member_count"], 3);
    assert_eq!(s0["observed_at"], at(10).as_str());
    assert_eq!(s0["comparison_state"], "baseline");
    assert_eq!(s0["is_latest"], true);
    assert_eq!(s0["is_first_baseline"], true);
    assert!(s0["awaiting_inventory_id"].is_null());
    assert!(fx.drift("px-a").await.is_empty(), "a baseline is not drift");
    assert!(
        fx.markers("px-a").await.is_empty(),
        "first snapshot: no marker"
    );
    // The report ACK names the report and is not a duplicate.
    let again = fx
        .post(
            A,
            &rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1, 2, 3], initial()),
        )
        .await;
    assert_eq!(again.json()["report_id"], rep_id(1).as_str());
    assert_eq!(again.json()["duplicate"], true);
}

#[tokio::test]
async fn case_second_listing_with_one_added_one_changed_one_removed_gives_three_drift_records() {
    let fx = Fx::new().await;
    fx.reg_default();
    fx.ok(
        A,
        &rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1, 2, 3], initial()),
    )
    .await;
    fx.ok(
        A,
        &rep(
            "px-a",
            2,
            2,
            20,
            UP1,
            CS1,
            1,
            1,
            &[1, 4, 5],
            compared(1, vec![changed(4, 2), removed(3), added(5)]),
        ),
    )
    .await;
    let d = fx.drift("px-a").await;
    assert_eq!(d.len(), 3);
    assert_eq!(
        drift_set(&d),
        BTreeSet::from([
            ("added".into(), mref(5), "".into()),
            ("changed".into(), mref(4), mref(2)),
            ("removed".into(), mref(3), "".into()),
        ])
    );
    for row in &d {
        assert_eq!(row["inventory_id"], inv_id(2).as_str());
        assert_eq!(row["previous_inventory_id"], inv_id(1).as_str());
        assert_eq!(row["upstream_id"], UP1);
        assert_eq!(row["credential_scope_id"], CS1);
        assert_eq!(row["proxy_id"], "px-a");
        assert!(row["drift_id"].as_str().is_some_and(|s| s.len() == 36));
        assert!(row["detected_at"].as_str().is_some());
    }
    let s = fx.snaps("px-a").await;
    assert_eq!(snap(&s, 2)["comparison_state"], "compared");
    assert_eq!(snap(&s, 2)["is_latest"], true);
    assert_eq!(snap(&s, 1)["is_latest"], false);
    assert_eq!(snap(&s, 1)["is_first_baseline"], true);
    assert_eq!(snap(&s, 2)["is_first_baseline"], false);
    // filters on the drift view
    let only = |q: &str| {
        let fx = &fx;
        let q = q.to_string();
        async move { fx.get(&format!("/v1/proxies/px-a/drift?{q}")).await.items() }
    };
    assert_eq!(only("change=added").await.len(), 1);
    assert_eq!(only("change=changed").await.len(), 1);
    assert_eq!(only("change=removed").await.len(), 1);
    assert_eq!(only(&format!("upstream_id={UP2}")).await.len(), 0);
    assert_eq!(only(&format!("credential_scope_id={CS1}")).await.len(), 3);
}

#[tokio::test]
async fn case_incomplete_listing_after_a_complete_one_removes_nothing() {
    let fx = Fx::new().await;
    fx.reg_default();
    fx.ok(
        A,
        &rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1, 2, 3], initial()),
    )
    .await;
    // The incomplete observation saw fewer tools; there are no members at all.
    fx.ok(A, &incomplete("px-a", 2, 20, UP1, CS1, 1, "page_error"))
        .await;
    let s = fx.snaps("px-a").await;
    assert_eq!(s.len(), 1, "an incomplete observation is never a snapshot");
    assert_eq!(s[0]["inventory_id"], inv_id(1).as_str());
    assert_eq!(s[0]["is_latest"], true, "latest snapshot unchanged");
    assert_eq!(s[0]["member_count"], 3);
    assert!(fx.drift("px-a").await.is_empty(), "no removal drift");
    let g = fx.gaps("px-a", "inventory_incomplete").await;
    assert_eq!(g.len(), 1);
    assert_eq!(g[0]["source"], "server_derived");
    assert_eq!(g[0]["state"], "open");
    assert_eq!(
        g[0]["details"],
        json!({
            "upstream_id": UP1,
            "credential_scope_id": CS1,
            "incomplete_reason": "page_error",
            "observed_at": at(20),
        })
    );
    // visible in the S5 counts too
    let d = fx.get("/v1/proxies/px-a").await.json();
    assert_eq!(d["open_gap_counts"]["inventory_incomplete"], 1);
    assert_eq!(d["open_gap_count"], 1);
}

#[tokio::test]
async fn case_complete_listing_after_an_incomplete_one_compares_against_the_complete_one() {
    let fx = Fx::new().await;
    fx.reg_default();
    fx.ok(
        A,
        &rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1, 2, 3], initial()),
    )
    .await;
    fx.ok(
        A,
        &incomplete("px-a", 2, 20, UP1, CS1, 1, "tool_limit_exceeded"),
    )
    .await;
    fx.ok(
        A,
        &rep(
            "px-a",
            3,
            2,
            30,
            UP1,
            CS1,
            1,
            1,
            &[1, 2],
            compared(1, vec![removed(3)]),
        ),
    )
    .await;
    let d = fx.drift("px-a").await;
    assert_eq!(d.len(), 1);
    assert_eq!(d[0]["change"], "removed");
    assert_eq!(d[0]["metadata_ref"], mref(3).as_str());
    assert_eq!(d[0]["previous_inventory_id"], inv_id(1).as_str());
    assert_eq!(fx.gaps("px-a", "inventory_incomplete").await.len(), 1);
}

#[tokio::test]
async fn case_declared_key_rotation_makes_a_marker_with_links_and_no_drift() {
    let fx = Fx::new().await;
    fx.reg_default();
    fx.reg("px-a", UP1, CS1, 2, &[51, 52, 53]);
    fx.ok(
        A,
        &rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1, 2, 3], initial()),
    )
    .await;
    fx.ok(
        A,
        &rep(
            "px-a",
            2,
            2,
            20,
            UP1,
            CS1,
            2,
            1,
            &[51, 52, 53],
            rebase(1, "key_rotation", &[(1, 51), (2, 52)]),
        ),
    )
    .await;
    assert!(fx.drift("px-a").await.is_empty(), "rotation is not drift");
    let m = fx.markers("px-a").await;
    assert_eq!(m.len(), 1);
    let m0 = &m[0];
    assert_eq!(m0["cause"], "declared_key_rotation");
    assert_eq!(m0["inventory_id"], inv_id(2).as_str());
    assert_eq!(m0["previous_inventory_id"], inv_id(1).as_str());
    assert_eq!(m0["from_key_id"], kid(1).as_str());
    assert_eq!(m0["to_key_id"], kid(2).as_str());
    assert_eq!(m0["from_canon"], "sigil-tooldef-fp-v1");
    assert_eq!(m0["to_canon"], "sigil-tooldef-fp-v1");
    assert_eq!(m0["links_present"], true);
    assert_eq!(m0["drift_computed"], false);
    assert_eq!(m0["upstream_id"], UP1);
    assert_eq!(m0["credential_scope_id"], CS1);
    assert!(m0["marker_id"].as_str().is_some_and(|s| s.len() == 36));
    // The two keys are two chains: each has its own latest and first baseline.
    let s = fx.snaps("px-a").await;
    assert_eq!(snap(&s, 2)["comparison_state"], "rebaseline");
    assert_eq!(snap(&s, 1)["is_latest"], true);
    assert_eq!(snap(&s, 2)["is_latest"], true);
    assert_eq!(snap(&s, 2)["is_first_baseline"], true);
    // A canon-change declaration is a different cause (same shape).
    fx.reg("px-a", UP1, CS1, 3, &[61]);
    fx.ok(
        A,
        &rep(
            "px-a",
            3,
            3,
            30,
            UP1,
            CS1,
            3,
            1,
            &[61],
            rebase(2, "canon_version_change", &[]),
        ),
    )
    .await;
    let m = fx.markers("px-a").await;
    assert_eq!(m.len(), 2);
    let newest = &m[0];
    assert_eq!(newest["cause"], "declared_canon_change");
    assert_eq!(newest["links_present"], false);
}

#[tokio::test]
async fn case_new_key_without_declaration_is_a_marker_never_drift() {
    let fx = Fx::new().await;
    fx.reg_default();
    fx.reg("px-a", UP1, CS1, 2, &[51, 52]);
    fx.ok(
        A,
        &rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1, 2, 3], initial()),
    )
    .await;
    // state loss: new epoch and new key, so the proxy reports an initial baseline
    fx.ok(
        A,
        &rep("px-a", 2, 2, 20, UP1, CS1, 2, 2, &[51, 52], initial()),
    )
    .await;
    let m = fx.markers("px-a").await;
    assert_eq!(m.len(), 1);
    assert_eq!(m[0]["cause"], "epoch_change_detected");
    assert_eq!(m[0]["previous_inventory_id"], inv_id(1).as_str());
    assert_eq!(m[0]["links_present"], false);
    assert!(fx.drift("px-a").await.is_empty());

    // the same without an epoch change: undeclared key change
    fx.reg("px-a", UP1, CS1, 3, &[71]);
    fx.ok(A, &rep("px-a", 3, 3, 30, UP1, CS1, 3, 2, &[71], initial()))
        .await;
    let m = fx.markers("px-a").await;
    assert_eq!(m[0]["cause"], "key_change_undeclared");
    assert_eq!(m[0]["inventory_id"], inv_id(3).as_str());

    // an initial baseline with the key and canon already known is a restatement
    fx.ok(A, &rep("px-a", 4, 4, 40, UP1, CS1, 3, 2, &[71], initial()))
        .await;
    let m = fx.markers("px-a").await;
    assert_eq!(m[0]["cause"], "baseline_restated");
    assert_eq!(m[0]["previous_inventory_id"], inv_id(3).as_str());
    assert_eq!(m[0]["from_key_id"], m[0]["to_key_id"]);
    assert!(
        fx.drift("px-a").await.is_empty(),
        "no drift across a marker"
    );
    let s = fx.snaps("px-a").await;
    assert_eq!(snap(&s, 4)["comparison_state"], "baseline");
    assert_eq!(snap(&s, 4)["is_first_baseline"], false);
    assert_eq!(snap(&s, 3)["is_first_baseline"], true);
}

#[tokio::test]
async fn case_other_credential_scope_is_a_separate_chain_with_no_marker_and_no_removals() {
    let fx = Fx::new().await;
    fx.reg_default();
    fx.reg("px-a", UP2, CS2, 1, &[81, 82]);
    fx.ok(
        A,
        &rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1, 2, 3], initial()),
    )
    .await;
    // visibility changed: another credential scope (and upstream) lists fewer tools
    fx.ok(A, &rep("px-a", 2, 2, 20, UP2, CS2, 1, 1, &[81], initial()))
        .await;
    assert!(fx.markers("px-a").await.is_empty());
    assert!(
        fx.drift("px-a").await.is_empty(),
        "no removals in the old chain"
    );
    let s = fx.snaps("px-a").await;
    assert_eq!(s.len(), 2);
    assert_eq!(snap(&s, 1)["is_latest"], true);
    assert_eq!(snap(&s, 1)["comparison_state"], "baseline");
    assert_eq!(snap(&s, 2)["is_first_baseline"], true);
    // a `compared` report may not bridge scope keys: 422 and nothing stored
    let r = fx
        .post(
            A,
            &rep(
                "px-a",
                3,
                3,
                30,
                UP2,
                CS2,
                1,
                1,
                &[81],
                compared(1, vec![added(81), removed(1), removed(2), removed(3)]),
            ),
        )
        .await;
    assert_eq!((r.status, r.code().as_str()), (422, "semantic_invalid"));
    assert_eq!(fx.snaps("px-a").await.len(), 2);
    // the filters tell the chains apart
    let r = fx
        .get(&format!(
            "/v1/proxies/px-a/inventory-snapshots?upstream_id={UP2}"
        ))
        .await;
    assert_eq!(r.items().len(), 1);
}

#[tokio::test]
async fn case_changes_not_matching_the_membership_difference() {
    let fx = Fx::new().await;
    fx.reg_default();
    fx.ok(
        A,
        &rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1, 2, 3], initial()),
    )
    .await;
    // previous known: 422, nothing stored
    let bad = |rid, inv, changes| {
        rep(
            "px-a",
            rid,
            inv,
            20,
            UP1,
            CS1,
            1,
            1,
            &[1, 2, 4],
            compared(1, changes),
        )
    };
    for changes in [
        vec![added(4)],                         // missing the removal of 3
        vec![added(4), removed(3), added(9)],   // an extra change
        vec![added(4), removed(3), removed(3)], // a ref twice
        vec![added(3), removed(4)],             // wrong sides
        vec![changed(4, 2), removed(3)],        // 2 is still a member
    ] {
        let r = fx.post(A, &bad(2, 2, changes.clone())).await;
        assert_eq!(
            (r.status, r.code().as_str()),
            (422, "semantic_invalid"),
            "{changes:?}"
        );
    }
    assert_eq!(fx.snaps("px-a").await.len(), 1, "nothing stored");
    assert!(fx.drift("px-a").await.is_empty());
    // the exact difference is accepted
    fx.ok(A, &bad(2, 2, vec![added(4), removed(3)])).await;
    assert_eq!(fx.drift("px-a").await.len(), 2);

    // previous unknown: accepted, pending; when the previous arrives the same
    // check runs, fails, and records a gap instead of drift
    let b = rep(
        "px-a",
        10,
        12,
        120,
        UP1,
        CS1,
        1,
        1,
        &[1, 2, 4],
        compared(11, vec![added(4)]), // omits the removal of 3
    );
    fx.ok(A, &b).await;
    let s = fx.snaps("px-a").await;
    assert_eq!(snap(&s, 12)["comparison_state"], "pending_previous");
    assert_eq!(snap(&s, 12)["awaiting_inventory_id"], inv_id(11).as_str());
    fx.ok(
        A,
        &rep("px-a", 11, 11, 110, UP1, CS1, 1, 1, &[1, 2, 3], initial()),
    )
    .await;
    let s = fx.snaps("px-a").await;
    assert_eq!(snap(&s, 12)["comparison_state"], "inconsistent");
    assert!(snap(&s, 12)["awaiting_inventory_id"].is_null());
    assert_eq!(
        fx.drift("px-a").await.len(),
        2,
        "no drift from the inconsistent report"
    );
    let g = fx.gaps("px-a", "comparison_inconsistent").await;
    assert_eq!(g.len(), 1);
    assert_eq!(g[0]["details"], json!({"inventory_id": inv_id(12)}));
    assert_eq!(g[0]["state"], "open");
}

#[tokio::test]
async fn case_compared_whose_previous_is_another_key() {
    let fx = Fx::new().await;
    fx.reg_default();
    fx.reg("px-a", UP1, CS1, 2, &[51, 52]);
    fx.ok(
        A,
        &rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1, 2, 3], initial()),
    )
    .await;
    // previous known, key differs: 422
    let r = fx
        .post(
            A,
            &rep(
                "px-a",
                2,
                2,
                20,
                UP1,
                CS1,
                2,
                1,
                &[51, 52],
                compared(
                    1,
                    vec![added(51), added(52), removed(1), removed(2), removed(3)],
                ),
            ),
        )
        .await;
    assert_eq!((r.status, r.code().as_str()), (422, "semantic_invalid"));
    assert_eq!(fx.snaps("px-a").await.len(), 1);

    // previous arrives later: accepted; then a gap and no drift
    fx.ok(
        A,
        &rep(
            "px-a",
            3,
            4,
            40,
            UP1,
            CS1,
            2,
            1,
            &[51, 52],
            compared(
                3,
                vec![added(51), added(52), removed(1), removed(2), removed(3)],
            ),
        ),
    )
    .await;
    fx.ok(
        A,
        &rep("px-a", 4, 3, 30, UP1, CS1, 1, 1, &[1, 2, 3], initial()),
    )
    .await;
    let s = fx.snaps("px-a").await;
    assert_eq!(snap(&s, 4)["comparison_state"], "inconsistent");
    assert!(fx.drift("px-a").await.is_empty());
    assert_eq!(fx.gaps("px-a", "comparison_inconsistent").await.len(), 1);
    assert!(fx
        .markers("px-a")
        .await
        .iter()
        .all(|m| m["inventory_id"] != inv_id(4).as_str()));
}

#[tokio::test]
async fn case_rebaseline_with_the_same_key_and_canon_is_422() {
    let fx = Fx::new().await;
    fx.reg_default();
    fx.ok(
        A,
        &rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1, 2, 3], initial()),
    )
    .await;
    let r = fx
        .post(
            A,
            &rep(
                "px-a",
                2,
                2,
                20,
                UP1,
                CS1,
                1,
                1,
                &[1, 2, 3],
                rebase(1, "key_rotation", &[]),
            ),
        )
        .await;
    assert_eq!((r.status, r.code().as_str()), (422, "semantic_invalid"));
    assert_eq!(fx.snaps("px-a").await.len(), 1);
    assert!(fx.markers("px-a").await.is_empty());

    // previous arrives later: the same check, deferred
    fx.ok(
        A,
        &rep(
            "px-a",
            3,
            6,
            60,
            UP1,
            CS1,
            1,
            1,
            &[1, 2, 3],
            rebase(5, "key_rotation", &[]),
        ),
    )
    .await;
    fx.ok(
        A,
        &rep("px-a", 4, 5, 50, UP1, CS1, 1, 1, &[1, 2, 3], initial()),
    )
    .await;
    let s = fx.snaps("px-a").await;
    assert_eq!(snap(&s, 6)["comparison_state"], "inconsistent");
    assert!(fx
        .markers("px-a")
        .await
        .iter()
        .all(|m| m["inventory_id"] != inv_id(6).as_str()));
    assert_eq!(fx.gaps("px-a", "comparison_inconsistent").await.len(), 1);
}

#[tokio::test]
async fn case_rebaseline_link_outside_the_memberships_is_422() {
    let fx = Fx::new().await;
    fx.reg_default();
    fx.reg("px-a", UP1, CS1, 2, &[51, 52]);
    fx.ok(
        A,
        &rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1, 2, 3], initial()),
    )
    .await;
    let with = |links: &[(u32, u32)], rid| {
        rep(
            "px-a",
            rid,
            2,
            20,
            UP1,
            CS1,
            2,
            1,
            &[51, 52],
            rebase(1, "key_rotation", links),
        )
    };
    // `from` not in the previous members (9 is registered, but not a member)
    let r = fx.post(A, &with(&[(9, 51)], 2)).await;
    assert_eq!((r.status, r.code().as_str()), (422, "semantic_invalid"));
    // `to` not in the current members
    let r = fx.post(A, &with(&[(1, 9)], 3)).await;
    assert_eq!((r.status, r.code().as_str()), (422, "semantic_invalid"));
    // a ref used twice on one side
    let r = fx.post(A, &with(&[(1, 51), (1, 52)], 4)).await;
    assert_eq!((r.status, r.code().as_str()), (422, "semantic_invalid"));
    let r = fx.post(A, &with(&[(1, 51), (2, 51)], 5)).await;
    assert_eq!((r.status, r.code().as_str()), (422, "semantic_invalid"));
    assert_eq!(fx.snaps("px-a").await.len(), 1);
    fx.ok(A, &with(&[(1, 51), (2, 52)], 6)).await;
}

#[tokio::test]
async fn case_report_before_its_previous_is_pending_then_identical_to_in_order() {
    // in order
    let fa = Fx::new().await;
    fa.reg_default();
    let a = rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1, 2, 3], initial());
    let b = rep(
        "px-a",
        2,
        2,
        20,
        UP1,
        CS1,
        1,
        1,
        &[1, 4, 5],
        compared(1, vec![changed(4, 2), removed(3), added(5)]),
    );
    fa.ok(A, &a).await;
    fa.ok(A, &b).await;
    // reversed
    let fb = Fx::new().await;
    fb.reg_default();
    fb.ok(A, &b).await;
    let s = fb.snaps("px-a").await;
    assert_eq!(snap(&s, 2)["comparison_state"], "pending_previous");
    assert_eq!(snap(&s, 2)["awaiting_inventory_id"], inv_id(1).as_str());
    assert!(
        fb.drift("px-a").await.is_empty(),
        "no drift until the previous arrives"
    );
    fb.ok(A, &a).await;
    let norm = |v: Vec<Value>| -> Vec<Value> {
        let mut v: Vec<Value> = v
            .into_iter()
            .map(|mut x| {
                x.as_object_mut().unwrap().remove("received_at");
                x.as_object_mut().unwrap().remove("detected_at");
                x
            })
            .collect();
        v.sort_by_key(|x| x.to_string());
        v
    };
    assert_eq!(norm(fa.snaps("px-a").await), norm(fb.snaps("px-a").await));
    assert_eq!(norm(fa.drift("px-a").await), norm(fb.drift("px-a").await));
    assert_eq!(
        norm(fa.markers("px-a").await),
        norm(fb.markers("px-a").await)
    );
}

#[tokio::test]
async fn case_schema_rules_reject_the_forbidden_combinations() {
    let fx = Fx::new().await;
    fx.reg_default();
    let base_complete = rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1], initial());
    let base_incomplete = incomplete("px-a", 2, 20, UP1, CS1, 1, "page_error");
    let mut cases: Vec<(&str, Value)> = Vec::new();
    for (k, v) in [
        ("inventory_id", json!(inv_id(9))),
        ("members", json!([mref(1)])),
        ("comparison", initial()),
    ] {
        let mut x = base_incomplete.clone();
        x[k] = v;
        cases.push(("incomplete + forbidden field", x));
    }
    let mut x = base_complete.clone();
    x.as_object_mut().unwrap().remove("comparison");
    cases.push(("complete without comparison", x));
    let mut x = base_complete.clone();
    x["incomplete_reason"] = json!("page_error");
    cases.push(("complete + incomplete_reason", x));
    let mut x = rep(
        "px-a",
        3,
        3,
        30,
        UP1,
        CS1,
        2,
        1,
        &[2],
        rebase(1, "key_rotation", &[]),
    );
    x["comparison"]["changes"] = json!([]);
    cases.push(("rebaseline + changes", x));
    let mut x = rep("px-a", 4, 4, 40, UP1, CS1, 1, 1, &[2], compared(1, vec![]));
    x["comparison"]["links"] = json!([]);
    cases.push(("compared + links", x));
    let mut x = base_complete.clone();
    x["unexpected"] = json!(1);
    cases.push(("unknown field", x));
    let mut x = base_complete.clone();
    x["members"] = json!([mref(1), mref(1)]);
    cases.push(("duplicate member", x));
    for (what, body) in cases {
        let r = fx.post(A, &body).await;
        assert_eq!(
            (r.status, r.code().as_str()),
            (422, "semantic_invalid"),
            "{what}: {}",
            r.text()
        );
    }
    for raw in ["", "not json", "[]", "{}", "null"] {
        let r = fx.post_raw(A, raw.to_string()).await;
        assert_eq!(r.status, 422, "{raw:?}");
    }
    assert!(fx.snaps("px-a").await.is_empty());
}

// ===== validation order, idempotency, caps ===========================================

#[tokio::test]
async fn identity_404_is_evaluated_first_and_is_byte_equal() {
    let fx = Fx::new().await;
    fx.reg_default();
    let good = rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1], initial());
    let unknown = fx.post(Who::Proxy("px-zz"), &good).await;
    assert_eq!(
        (unknown.status, unknown.code().as_str()),
        (404, "proxy_unknown")
    );
    // body proxy_id of another proxy, even next to a malformed rest of the body
    let mut foreign = good.clone();
    foreign["proxy_id"] = json!("px-b");
    let mut broken = json!({"proxy_id": "px-b", "members": 5, "comparison": "x"});
    broken["schema_version"] = json!("nope");
    for body in [foreign.to_string(), broken.to_string()] {
        let r = fx.post_raw(A, body).await;
        assert_eq!(
            r, unknown,
            "body identity mismatch looks like an unknown proxy"
        );
    }
    // peers that are not a registered proxy, and a pending proxy
    for who in [Who::Host, Who::Ambiguous, Who::NoPeer, Who::Proxy("px-c")] {
        let r = fx.post(who, &good).await;
        assert_eq!(r.status, 404, "{who:?}");
        if who != Who::Host && who != Who::Ambiguous && who != Who::NoPeer {
            assert_eq!(r, unknown, "{who:?}");
        }
    }
    // disabled: the identity is verified, the state is the reason
    let r = fx.post(Who::Proxy("px-d"), &good).await;
    assert_eq!((r.status, r.code().as_str()), (403, "disabled"));
    assert!(fx.snaps("px-a").await.is_empty());
}

#[tokio::test]
async fn scope_must_be_assigned_to_this_proxy() {
    let fx = Fx::new().await;
    fx.reg_default();
    // px-a has up1/CS1 and up2/CS2; px-b has up1/CS_B only
    let r = fx
        .post(A, &rep("px-a", 1, 1, 10, UP1, CS2, 1, 1, &[1], initial()))
        .await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (422, "semantic_invalid"),
        "scope of another upstream"
    );
    let r = fx
        .post(
            A,
            &rep("px-a", 2, 2, 10, CANARY_UP, CS1, 1, 1, &[1], initial()),
        )
        .await;
    assert_eq!((r.status, r.code().as_str()), (422, "semantic_invalid"));
    assert!(
        !r.text().contains(CANARY_UP),
        "no request value is echoed: {}",
        r.text()
    );
    let r = fx
        .post(A, &rep("px-a", 3, 3, 10, UP1, CS_B, 1, 1, &[1], initial()))
        .await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (422, "semantic_invalid"),
        "px-b's scope"
    );
    // incomplete reports are judged by the same scope rule
    let r = fx
        .post(
            A,
            &incomplete("px-a", 4, 10, CANARY_UP, CS1, 1, "page_error"),
        )
        .await;
    assert_eq!(r.status, 422);
    assert!(fx.snaps("px-a").await.is_empty());
    assert!(fx.gaps("px-a", "inventory_incomplete").await.is_empty());
}

#[tokio::test]
async fn unregistered_refs_are_424_and_other_proxies_refs_are_422() {
    let fx = Fx::new().await;
    fx.reg("px-a", UP1, CS1, 1, &[1, 2]);
    fx.reg("px-b", UP1, CS_B, 1, &[3]);
    // 3 is registered, but under px-b: 422 (it could never resolve)
    let r = fx
        .post(
            A,
            &rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1, 3], initial()),
        )
        .await;
    assert_eq!((r.status, r.code().as_str()), (422, "semantic_invalid"));
    // 5 and 4 are registered nowhere: 424 with the sorted list
    let r = fx
        .post(
            A,
            &rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[5, 1, 4], initial()),
        )
        .await;
    assert_eq!((r.status, r.code().as_str()), (424, "metadata_ref_pending"));
    assert_eq!(
        r.json()["error"]["pending_metadata_refs"],
        json!([mref(4), mref(5)])
    );
    assert!(fx.snaps("px-a").await.is_empty(), "nothing stored on 424");
    fx.reg("px-a", UP1, CS1, 1, &[4, 5]);
    fx.ok(
        A,
        &rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[5, 1, 4], initial()),
    )
    .await;
    // change refs and link refs count too
    fx.ok(
        A,
        &rep(
            "px-a",
            2,
            2,
            20,
            UP1,
            CS1,
            1,
            1,
            &[1, 2],
            compared(1, vec![added(2), removed(4), removed(5)]),
        ),
    )
    .await;
    let r = fx
        .post(
            A,
            &rep(
                "px-a",
                3,
                9,
                30,
                UP1,
                CS1,
                1,
                1,
                &[1],
                compared(77, vec![added(90)]),
            ),
        )
        .await;
    assert_eq!((r.status, r.code().as_str()), (424, "metadata_ref_pending"));
    assert_eq!(
        r.json()["error"]["pending_metadata_refs"],
        json!([mref(90)])
    );
}

#[tokio::test]
async fn precedence_is_422_then_409_then_424() {
    let fx = Fx::new().await;
    fx.reg("px-a", UP1, CS1, 1, &[1, 2]);
    fx.ok(
        A,
        &rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1, 2], initial()),
    )
    .await;
    // same report_id, different content, and an unregistered ref: 409 beats 424
    let r = fx
        .post(
            A,
            &rep("px-a", 1, 2, 20, UP1, CS1, 1, 1, &[1, 99], initial()),
        )
        .await;
    assert_eq!((r.status, r.code().as_str()), (409, "conflict"));
    // same report_id, different content, and an unassigned scope: 422 beats 409
    let r = fx
        .post(
            A,
            &rep("px-a", 1, 2, 20, CANARY_UP, CS1, 1, 1, &[1], initial()),
        )
        .await;
    assert_eq!((r.status, r.code().as_str()), (422, "semantic_invalid"));
    // a known-previous inconsistency beats a conflict
    let r = fx
        .post(
            A,
            &rep("px-a", 1, 3, 30, UP1, CS1, 1, 1, &[1], compared(1, vec![])),
        )
        .await;
    assert_eq!((r.status, r.code().as_str()), (422, "semantic_invalid"));
}

#[tokio::test]
async fn idempotent_on_report_id_and_conflicts_on_different_content() {
    let fx = Fx::new().await;
    fx.reg_default();
    let a = rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1, 2, 3], initial());
    fx.ok(A, &a).await;
    // same bytes: same ACK, no second snapshot
    let first = fx.post(A, &a).await;
    let second = fx.post(A, &a).await;
    assert_eq!(first, second);
    assert_eq!(
        (first.status, first.json()["duplicate"].clone()),
        (200, json!(true))
    );
    // the same report with members in another order is the same report
    let mut shuffled = a.clone();
    shuffled["members"] = json!([mref(3), mref(1), mref(2)]);
    let r = fx.post(A, &shuffled).await;
    assert_eq!(
        (r.status, r.json()["duplicate"].clone()),
        (200, json!(true))
    );
    assert_eq!(fx.snaps("px-a").await.len(), 1);
    // different content under the same report_id
    let mut other = a.clone();
    other["members"] = json!([mref(1), mref(2)]);
    let r = fx.post(A, &other).await;
    assert_eq!((r.status, r.code().as_str()), (409, "conflict"));
    let mut other = a.clone();
    other["pages_observed"] = json!(2);
    assert_eq!(fx.post(A, &other).await.status, 409);
    // the same snapshot id under another report id is a conflict too
    let mut other = a.clone();
    other["report_id"] = json!(rep_id(9));
    assert_eq!(fx.post(A, &other).await.status, 409);
    assert_eq!(fx.snaps("px-a").await.len(), 1);

    // an incomplete report is idempotent as well: one gap
    let inc = incomplete("px-a", 5, 20, UP1, CS1, 1, "access_denied");
    fx.ok(A, &inc).await;
    let r = fx.post(A, &inc).await;
    assert_eq!(r.json()["duplicate"], true);
    assert_eq!(fx.gaps("px-a", "inventory_incomplete").await.len(), 1);
    let mut other = inc.clone();
    other["incomplete_reason"] = json!("page_error");
    assert_eq!(fx.post(A, &other).await.status, 409);

    // report ids are per proxy: px-b may use the same id
    fx.reg("px-b", UP1, CS_B, 1, &[1]);
    fx.ok(B, &rep("px-b", 1, 1, 10, UP1, CS_B, 1, 1, &[1], initial()))
        .await;

    // an equal retransmission stays a duplicate after the scope moved on
    let mut cfg = fx.ctx.store.entry("px-a").unwrap();
    cfg.config = Some(config_with(
        "px-a",
        &[("r9", "up9", "cs-99999999999999999999999999999999")],
    ));
    fx.ctx.store.begin().commit("px-a", cfg.clone()).unwrap();
    let mut cfg2 = cfg.clone();
    cfg2.config = Some(config_with(
        "px-a",
        &[("r9", "up9", "cs-88888888888888888888888888888888")],
    ));
    fx.ctx.store.begin().commit("px-a", cfg2).unwrap();
    let r = fx.post(A, &a).await;
    assert_eq!(
        (r.status, r.json()["duplicate"].clone()),
        (200, json!(true))
    );
    // but a new report for the dropped scope is refused
    let r = fx
        .post(A, &rep("px-a", 7, 7, 70, UP1, CS1, 1, 1, &[1], initial()))
        .await;
    assert_eq!(r.status, 422);
}

#[tokio::test]
async fn body_over_four_mib_is_413_before_any_parse() {
    let fx = Fx::new().await;
    fx.reg_default();
    let pad = " ".repeat(4 * 1024 * 1024 + 1);
    // a valid report padded with whitespace, and plain garbage: both are 413
    let valid = rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1], initial());
    for body in [format!("{valid}{pad}"), pad.clone()] {
        let r = fx.post_raw(A, body).await;
        assert_eq!((r.status, r.code().as_str()), (413, "payload_too_large"));
    }
    assert!(fx.snaps("px-a").await.is_empty());
    // exactly at the cap is still read (and judged on its content)
    let mut ok_body = valid.to_string();
    ok_body.push_str(&" ".repeat(4 * 1024 * 1024 - ok_body.len()));
    assert_eq!(ok_body.len(), 4 * 1024 * 1024);
    assert_eq!(fx.post_raw(A, ok_body).await.status, 200);
    // the member count bound is a 413 too (10,001 members)
    let many: Vec<String> = (0..10_001).map(|i| mref(100 + i)).collect();
    let mut big = rep("px-a", 2, 2, 20, UP1, CS1, 1, 1, &[], initial());
    big["members"] = json!(many);
    let r = fx.post(A, &big).await;
    assert!(
        r.status == 413 || r.status == 422,
        "bound exceeded is refused: {}",
        r.status
    );
}

#[tokio::test]
async fn storage_caps_answer_503_and_store_nothing() {
    let fx = Fx::new().await;
    fx.reg_default();
    fx.ctx.ledger.set_inventory_caps_for_test(2, 1_000);
    fx.ok(A, &rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1], initial()))
        .await;
    fx.ok(
        A,
        &rep("px-a", 2, 2, 20, UP1, CS1, 1, 1, &[1], compared(1, vec![])),
    )
    .await;
    let r = fx
        .post(
            A,
            &rep("px-a", 3, 3, 30, UP1, CS1, 1, 1, &[1], compared(2, vec![])),
        )
        .await;
    assert_eq!((r.status, r.code().as_str()), (503, "storage_limit"));
    assert_eq!(fx.snaps("px-a").await.len(), 2, "rolled back");
    // another proxy has its own budget
    fx.reg("px-b", UP1, CS_B, 1, &[1]);
    fx.ok(B, &rep("px-b", 3, 3, 30, UP1, CS_B, 1, 1, &[1], initial()))
        .await;
    // member rows
    fx.ctx.ledger.set_inventory_caps_for_test(100, 3);
    let r = fx
        .post(
            A,
            &rep(
                "px-a",
                4,
                4,
                40,
                UP1,
                CS1,
                1,
                1,
                &[1, 2, 3],
                compared(2, vec![added(2), added(3)]),
            ),
        )
        .await;
    assert_eq!((r.status, r.code().as_str()), (503, "storage_limit"));
    assert_eq!(fx.snaps("px-a").await.len(), 2);
    // the retransmission after the budget grew is accepted (nothing was kept)
    fx.ctx.ledger.set_inventory_caps_for_test(100, 1_000);
    fx.ok(
        A,
        &rep(
            "px-a",
            4,
            4,
            40,
            UP1,
            CS1,
            1,
            1,
            &[1, 2, 3],
            compared(2, vec![added(2), added(3)]),
        ),
    )
    .await;
    // gaps are bounded too: incomplete observations are not free
    assert_eq!(fx.snaps("px-a").await.len(), 3);
}

#[tokio::test]
async fn last_seen_is_refreshed_by_an_accepted_report() {
    let fx = Fx::new().await;
    fx.reg_default();
    assert!(fx.ctx.store.last_seen("px-a").is_none());
    fx.ok(A, &rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1], initial()))
        .await;
    assert!(fx.ctx.store.last_seen("px-a").is_some());
}

// ===== read views ==================================================================

#[tokio::test]
async fn read_auth_matrix_and_unknown_vs_out_of_scope_targets() {
    let fx = Fx::build(true).await;
    fx.reg_default();
    fx.ok(A, &rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1], initial()))
        .await;
    for seg in ["inventory-snapshots", "drift", "rebaseline-markers"] {
        let u = format!("/v1/proxies/px-a/{seg}");
        for b in [None, Some("wrong")] {
            let r = fx.call("GET", &u, Who::Host, b, None, None).await;
            assert_eq!((r.status, r.code().as_str()), (401, "unauthorized"), "{u}");
        }
        let ok = fx
            .call("GET", &u, Who::Host, Some(READ_TOKEN), None, None)
            .await;
        assert_eq!(ok.status, 200, "{u}");
        for who in [A, B, Who::Mgmt, Who::Ambiguous, Who::NoPeer] {
            for b in [READ_TOKEN, MGMT_TOKEN] {
                let r = fx.call("GET", &u, who, Some(b), None, None).await;
                assert_eq!(r.status, 404, "{u} {who:?}");
                assert_eq!(r.json()["error"], "host_unknown", "{u} {who:?}");
            }
        }
        // the same bytes whether the proxy is unknown or out of scope
        let unknown = fx
            .call(
                "GET",
                &format!("/v1/proxies/px-nope/{seg}"),
                Who::Host,
                Some(READ_TOKEN),
                None,
                None,
            )
            .await;
        assert_eq!(
            (unknown.status, unknown.code().as_str()),
            (404, "proxy_unknown")
        );
        let scoped_out = fx
            .call(
                "GET",
                &u,
                Who::Host,
                Some(READ_TOKEN),
                Some(&["px-b"]),
                None,
            )
            .await;
        assert_eq!(scoped_out, unknown, "{seg}: out of scope == unknown");
        let in_scope = fx
            .call(
                "GET",
                &u,
                Who::Host,
                Some(READ_TOKEN),
                Some(&["px-a"]),
                None,
            )
            .await;
        assert_eq!(in_scope, ok);
        let empty_scope = fx
            .call("GET", &u, Who::Host, Some(READ_TOKEN), Some(&[]), None)
            .await;
        assert_eq!(empty_scope, unknown);
        // a bad filter on an unknown proxy still answers the unknown-proxy 404
        let r = fx
            .call(
                "GET",
                &format!("/v1/proxies/px-nope/{seg}?bogus=1&limit=0"),
                Who::Host,
                Some(READ_TOKEN),
                None,
                None,
            )
            .await;
        assert_eq!(r, unknown);
        // writes are not routed here
        for m in ["POST", "PUT", "DELETE"] {
            let r = fx
                .call(m, &u, Who::Host, Some(READ_TOKEN), None, Some("{}".into()))
                .await;
            assert_eq!(r.status, 404, "{m} {u}");
        }
    }
    // POST /v1/proxy-inventory with a read bearer/host cert is not an ingest
    let r = fx
        .call(
            "POST",
            "/v1/proxy-inventory",
            Who::Host,
            Some(READ_TOKEN),
            None,
            Some("{}".into()),
        )
        .await;
    assert_eq!(r.status, 404);
    // a GET on the ingest path is not routed
    let r = fx
        .call("GET", "/v1/proxy-inventory", A, None, None, None)
        .await;
    assert_ne!(r.status, 200);
}

#[tokio::test]
async fn filters_limits_and_cursors() {
    let fx = Fx::new().await;
    fx.reg_default();
    fx.reg("px-a", UP2, CS2, 1, &[81]);
    fx.ok(
        A,
        &rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1, 2, 3], initial()),
    )
    .await;
    // five more snapshots, each adding one member
    for i in 2..=6u32 {
        let members: Vec<u32> = (1..=2 + i).collect();
        fx.ok(
            A,
            &rep(
                "px-a",
                i,
                i,
                10 * i,
                UP1,
                CS1,
                1,
                1,
                &members,
                compared(i - 1, vec![added(2 + i)]),
            ),
        )
        .await;
    }
    fx.ok(A, &rep("px-a", 7, 7, 70, UP2, CS2, 1, 1, &[81], initial()))
        .await;
    // order: newest commit first
    let all = fx.snaps("px-a").await;
    let order: Vec<&str> = all
        .iter()
        .map(|s| s["inventory_id"].as_str().unwrap())
        .collect();
    let expect: Vec<String> = [7, 6, 5, 4, 3, 2, 1].iter().map(|n| inv_id(*n)).collect();
    assert_eq!(order, expect.iter().map(String::as_str).collect::<Vec<_>>());

    // paging, two at a time; an insert between pages never moves or repeats rows
    let mut seen = Vec::new();
    let mut uri = "/v1/proxies/px-a/inventory-snapshots?limit=2".to_string();
    let mut inserted = false;
    loop {
        let r = fx.get(&uri).await;
        assert_eq!(r.status, 200, "{}", r.text());
        seen.extend(
            r.items()
                .iter()
                .map(|s| s["inventory_id"].as_str().unwrap().to_string()),
        );
        if !inserted {
            inserted = true;
            fx.ok(
                A,
                &rep("px-a", 8, 8, 80, UP2, CS2, 1, 1, &[81], compared(7, vec![])),
            )
            .await;
        }
        match r.json()["next_cursor"].as_str() {
            Some(c) => uri = format!("/v1/proxies/px-a/inventory-snapshots?limit=2&cursor={c}"),
            None => break,
        }
    }
    assert_eq!(
        seen, expect,
        "no repeat, no reorder, the newer row waits for a re-list"
    );
    let after = fx.snaps("px-a").await;
    assert_eq!(after[0]["inventory_id"], inv_id(8).as_str());

    // filters
    let n = |q: &str| {
        let fx = &fx;
        let q = q.to_string();
        async move {
            fx.get(&format!("/v1/proxies/px-a/inventory-snapshots?{q}"))
                .await
                .items()
                .len()
        }
    };
    assert_eq!(n(&format!("upstream_id={UP1}")).await, 6);
    assert_eq!(n(&format!("upstream_id={UP2}")).await, 2);
    assert_eq!(n(&format!("credential_scope_id={CS2}")).await, 2);
    assert_eq!(
        n(&format!("upstream_id={UP1}&credential_scope_id={CS2}")).await,
        0
    );
    assert_eq!(n("from=2000-01-01T00:00:00Z").await, 8);
    assert_eq!(n("to=2000-01-01T00:00:00Z").await, 0);
    assert_eq!(n("from=2999-01-01T00:00:00Z").await, 0);
    assert_eq!(n("to=2999-01-01T00:00:00Z").await, 8);
    let drift = fx.get("/v1/proxies/px-a/drift?change=added&limit=3").await;
    assert_eq!(drift.items().len(), 3);
    assert!(drift.json()["next_cursor"].is_string());

    // invalid filters and cursors are 422 and never echoed
    let secret = "ZZ-echo-canary-ZZ";
    for u in [
        format!("/v1/proxies/px-a/inventory-snapshots?{secret}=1"),
        format!("/v1/proxies/px-a/inventory-snapshots?upstream_id={secret}%20x"),
        "/v1/proxies/px-a/inventory-snapshots?change=added".to_string(),
        "/v1/proxies/px-a/rebaseline-markers?change=added".to_string(),
        "/v1/proxies/px-a/drift?change=bogus".to_string(),
        "/v1/proxies/px-a/drift?from=yesterday".to_string(),
        "/v1/proxies/px-a/drift?limit=0".to_string(),
        "/v1/proxies/px-a/drift?limit=501".to_string(),
        "/v1/proxies/px-a/drift?limit=abc".to_string(),
        "/v1/proxies/px-a/drift?limit=-1".to_string(),
        "/v1/proxies/px-a/drift?limit=5&limit=6".to_string(),
        "/v1/proxies/px-a/drift?upstream_id=".to_string(),
        "/v1/proxies/px-a/drift?proxy_id=px-b".to_string(),
    ] {
        let r = fx.get(&u).await;
        assert_eq!(
            (r.status, r.code().as_str()),
            (422, "invalid_filter"),
            "{u}"
        );
        assert!(!r.text().contains(secret), "{u}: {}", r.text());
    }
    assert_eq!(fx.get("/v1/proxies/px-a/drift?limit=500").await.status, 200);
    assert_eq!(fx.get("/v1/proxies/px-a/drift?limit=1").await.status, 200);
    for c in ["!!!", "e30", &"A".repeat(600)] {
        let r = fx.get(&format!("/v1/proxies/px-a/drift?cursor={c}")).await;
        assert_eq!(
            (r.status, r.code().as_str()),
            (422, "invalid_cursor"),
            "{c}"
        );
    }
    // a cursor is bound to endpoint, proxy and filters
    let cur = drift.json()["next_cursor"].as_str().unwrap().to_string();
    let same = format!("/v1/proxies/px-a/drift?change=added&limit=3&cursor={cur}");
    assert_eq!(fx.get(&same).await.status, 200);
    for u in [
        format!("/v1/proxies/px-a/drift?change=removed&limit=3&cursor={cur}"),
        format!("/v1/proxies/px-a/drift?limit=3&cursor={cur}"),
        format!("/v1/proxies/px-a/rebaseline-markers?cursor={cur}"),
        format!("/v1/proxies/px-a/inventory-snapshots?cursor={cur}"),
        format!("/v1/proxies/px-b/drift?change=added&limit=3&cursor={cur}"),
    ] {
        let r = fx.get(&u).await;
        assert_eq!(
            (r.status, r.code().as_str()),
            (422, "invalid_cursor"),
            "{u}"
        );
    }
}

#[tokio::test]
async fn proxies_see_only_their_own_inventory() {
    let fx = Fx::new().await;
    fx.reg_default();
    fx.reg("px-b", UP1, CS_B, 1, &[1, 2]);
    fx.ok(
        A,
        &rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1, 2, 3], initial()),
    )
    .await;
    // the same ref and the same ids under px-b are different rows
    fx.ok(
        B,
        &rep("px-b", 1, 1, 10, UP1, CS_B, 1, 1, &[1, 2], initial()),
    )
    .await;
    assert_eq!(fx.snaps("px-a").await.len(), 1);
    assert_eq!(fx.snaps("px-b").await.len(), 1);
    assert_eq!(fx.snaps("px-a").await[0]["member_count"], 3);
    assert_eq!(fx.snaps("px-b").await[0]["member_count"], 2);
    // px-b cannot name px-a's snapshot as a previous one: it is unknown to px-b
    // (pending, never resolved against px-a's rows)
    fx.ok(
        B,
        &rep(
            "px-b",
            2,
            2,
            20,
            UP1,
            CS_B,
            1,
            1,
            &[1, 2],
            compared(1, vec![]),
        ),
    )
    .await;
    let s = fx.snaps("px-b").await;
    assert_eq!(
        snap(&s, 2)["comparison_state"],
        "compared",
        "px-b's own inv 1"
    );
}

// ===== canary ======================================================================

#[tokio::test]
async fn no_tool_content_or_request_value_is_echoed() {
    let fx = Fx::new().await;
    fx.reg_default();
    let mut bodies: Vec<Resp> = Vec::new();
    let canon = |r: Resp| bodies.push(r);
    let mut canon = canon;

    let a = rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1, 2, 3], initial());
    canon(fx.post(A, &a).await);
    canon(fx.post(A, &a).await);
    canon(
        fx.post(
            A,
            &rep(
                "px-a",
                2,
                2,
                20,
                UP1,
                CS1,
                1,
                1,
                &[1, 4],
                compared(1, vec![changed(4, 2), removed(3)]),
            ),
        )
        .await,
    );
    canon(
        fx.post(A, &incomplete("px-a", 3, 30, UP1, CS1, 1, "ambiguous_name"))
            .await,
    );
    // refusals
    canon(
        fx.post(
            A,
            &rep("px-a", 4, 4, 40, CANARY_UP, CS1, 1, 1, &[1], initial()),
        )
        .await,
    );
    canon(
        fx.post(
            A,
            &rep(
                "px-a",
                5,
                5,
                50,
                UP1,
                CS1,
                1,
                1,
                &[1, 3],
                compared(1, vec![]),
            ),
        )
        .await,
    );
    canon(
        fx.post(A, &rep("px-a", 1, 9, 60, UP1, CS1, 1, 1, &[1], initial()))
            .await,
    );
    canon(
        fx.post(
            A,
            &rep("px-a", 6, 6, 60, UP1, CS1, 1, 1, &[1, 99], initial()),
        )
        .await,
    );
    canon(
        fx.post_raw(A, format!("{{\"proxy_id\":\"{CANARY_NAME}\"}}"))
            .await,
    );
    canon(
        fx.post_raw(A, format!("{{\"members\":\"{CANARY_DESC}\"}}"))
            .await,
    );
    // every read surface
    for u in [
        "/v1/proxies/px-a",
        "/v1/proxies",
        "/v1/proxies/px-a/inventory-snapshots",
        "/v1/proxies/px-a/drift",
        "/v1/proxies/px-a/rebaseline-markers",
        "/v1/proxies/px-a/drift?bogus=1",
    ] {
        canon(fx.get(u).await);
    }
    assert!(bodies.len() > 15);
    let fingerprint_hex = format!("{:064x}", u128::from(1u32) + 0xfeed_0000);
    for b in &bodies {
        let t = b.text();
        for needle in [
            CANARY_NAME,
            CANARY_DESC,
            CANARY_UP,
            fingerprint_hex.as_str(),
            "canary-cred",
            "canary-origin",
            READ_TOKEN,
        ] {
            assert!(!t.contains(needle), "{needle} leaked in {t}");
        }
    }
    // refs are the only 424 payload, and only refs of the request
    let r = fx
        .post(
            A,
            &rep("px-a", 7, 7, 70, UP1, CS1, 1, 1, &[1, 99], initial()),
        )
        .await;
    assert_eq!(r.status, 424);
    let t = r.text();
    assert!(t.contains(&mref(99)) && !t.contains(&mref(1)));
}

// ===== ledger level: reordering, retention, restart, migration ======================

fn open_ledger(dir: &Path) -> Ledger {
    Ledger::open(&dir.join("l.sqlite"), LedgerOptions::default()).unwrap()
}

fn ingest(l: &Ledger, report: &Value, now: i64) -> InventoryOutcome {
    ingest_as(l, "px-a", report, now)
}

fn ingest_as(l: &Ledger, proxy: &str, report: &Value, now: i64) -> InventoryOutcome {
    let r = parse_inventory_report(report.to_string().as_bytes()).expect("valid report");
    l.ingest_inventory(proxy, &r, &report_digest(&r), &RefCheck::default(), now)
        .unwrap()
}

/// The reports of the reordering scenario with the receipt time each one is
/// always delivered at.
fn scenario() -> Vec<(Value, i64)> {
    vec![
        // chain 1: A <- B <- C, then an incomplete observation
        (
            rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1, 2, 3], initial()),
            1001,
        ),
        (
            rep(
                "px-a",
                2,
                2,
                20,
                UP1,
                CS1,
                1,
                1,
                &[1, 4, 5],
                compared(1, vec![changed(4, 2), removed(3), added(5)]),
            ),
            1002,
        ),
        (
            rep(
                "px-a",
                3,
                3,
                30,
                UP1,
                CS1,
                1,
                1,
                &[1, 4, 5, 6],
                compared(2, vec![added(6)]),
            ),
            1003,
        ),
        (incomplete("px-a", 4, 35, UP1, CS1, 1, "page_error"), 1004),
        // declared rotation with links
        (
            rep(
                "px-a",
                5,
                4,
                40,
                UP1,
                CS1,
                2,
                1,
                &[11, 14, 15],
                rebase(3, "key_rotation", &[(1, 11), (4, 14)]),
            ),
            1005,
        ),
        // state loss: new epoch and key, undeclared; later a restatement
        (
            rep("px-a", 6, 5, 50, UP1, CS1, 3, 2, &[21], initial()),
            1006,
        ),
        (
            rep("px-a", 7, 7, 60, UP1, CS1, 3, 2, &[21], initial()),
            1007,
        ),
        // another scope key
        (
            rep("px-a", 8, 6, 15, UP2, CS2, 1, 1, &[31], initial()),
            1008,
        ),
        (
            rep(
                "px-a",
                9,
                8,
                25,
                UP2,
                CS2,
                1,
                1,
                &[31, 32],
                compared(6, vec![added(32)]),
            ),
            1009,
        ),
    ]
}

/// Everything the read views and the gap list show, without commit counters,
/// sorted by identity.
fn to_v<T: serde::Serialize>(v: &[T]) -> Vec<Value> {
    v.iter().map(|x| serde_json::to_value(x).unwrap()).collect()
}

fn projection(l: &Ledger) -> Value {
    let f = InvFilter::default();
    let sort = |mut v: Vec<Value>, key: &str| {
        v.sort_by_key(|x| x[key].as_str().unwrap().to_string());
        v
    };
    let snaps = l.list_inventory_snapshots("px-a", &f, None, 500).unwrap();
    let drift = l.list_inventory_drift("px-a", &f, None, 500).unwrap();
    let markers = l.list_inventory_markers("px-a", &f, None, 500).unwrap();
    let mut gaps: Vec<Value> = l
        .gaps("px-a")
        .unwrap()
        .iter()
        .map(|g| {
            json!({"gap_id": g.gap_id, "kind": format!("{:?}", g.kind), "detected_at": g.detected_at,
                   "open": g.open, "details": g.details})
        })
        .collect();
    gaps.sort_by_key(|g| g["gap_id"].as_str().unwrap().to_string());
    json!({
        "snapshots": sort(to_v(&snaps.items), "inventory_id"),
        "drift": sort(to_v(&drift.items), "drift_id"),
        "markers": sort(to_v(&markers.items), "marker_id"),
        "gaps": gaps,
    })
}

#[test]
fn reordering_the_same_reports_gives_identical_projections() {
    let reports = scenario();
    let reference = {
        let d = tempfile::tempdir().unwrap();
        let l = open_ledger(d.path());
        for (r, now) in &reports {
            assert_eq!(ingest(&l, r, *now), InventoryOutcome::Accepted);
        }
        projection(&l)
    };
    // sanity of the reference itself
    assert_eq!(reference["snapshots"].as_array().unwrap().len(), 8);
    assert_eq!(reference["drift"].as_array().unwrap().len(), 5, "3 + 1 + 1");
    let causes: BTreeSet<String> = reference["markers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["cause"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        causes,
        BTreeSet::from([
            "declared_key_rotation".to_string(),
            "epoch_change_detected".to_string(),
            "baseline_restated".to_string(),
        ])
    );
    assert_eq!(reference["gaps"].as_array().unwrap().len(), 1);
    for s in reference["snapshots"].as_array().unwrap() {
        assert_ne!(s["comparison_state"], "pending_previous");
        assert_ne!(s["comparison_state"], "inconsistent");
    }

    // 9! orders are too many for a file-backed store: the reverse, a rotation
    // of every start, and seeded shuffles.
    let n = reports.len();
    let mut orders: Vec<Vec<usize>> = vec![(0..n).rev().collect()];
    for k in 1..n {
        orders.push((0..n).map(|i| (i + k) % n).collect());
    }
    let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
    for _ in 0..40 {
        let mut o: Vec<usize> = (0..n).collect();
        for i in (1..n).rev() {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            o.swap(i, ((seed >> 33) as usize) % (i + 1));
        }
        orders.push(o);
    }
    for order in orders {
        let d = tempfile::tempdir().unwrap();
        let l = open_ledger(d.path());
        for i in &order {
            let (r, now) = &reports[*i];
            // an order in which a previous snapshot is already known and the
            // report is consistent is accepted too: nothing here is inconsistent
            assert_eq!(
                ingest(&l, r, *now),
                InventoryOutcome::Accepted,
                "order {order:?}"
            );
        }
        assert_eq!(projection(&l), reference, "order {order:?}");
    }
}

#[test]
fn pending_resolution_is_per_report_and_does_not_cascade() {
    let reports = scenario();
    let d = tempfile::tempdir().unwrap();
    let l = open_ledger(d.path());
    // C first (previous B unknown), then B (previous A unknown), then A
    ingest(&l, &reports[2].0, 1003);
    ingest(&l, &reports[1].0, 1002);
    let p = projection(&l);
    let state = |p: &Value, n: u32| {
        p["snapshots"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["inventory_id"] == inv_id(n).as_str())
            .unwrap()["comparison_state"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(
        state(&p, 3),
        "compared",
        "C resolves when B arrives, A or not"
    );
    assert_eq!(state(&p, 2), "pending_previous");
    assert_eq!(p["drift"].as_array().unwrap().len(), 1, "only C's change");
    ingest(&l, &reports[0].0, 1001);
    let p = projection(&l);
    assert_eq!(state(&p, 2), "compared");
    assert_eq!(p["drift"].as_array().unwrap().len(), 4);
}

#[test]
fn restart_keeps_the_projection() {
    let d = tempfile::tempdir().unwrap();
    let before = {
        let l = open_ledger(d.path());
        for (r, now) in scenario() {
            ingest(&l, &r, now);
        }
        projection(&l)
    };
    let l = open_ledger(d.path());
    assert_eq!(projection(&l), before);
    // and the idempotency memory survived: a retransmission is a duplicate
    let (r, now) = scenario().remove(1);
    assert_eq!(ingest(&l, &r, now + 5), InventoryOutcome::Duplicate);
}

#[test]
fn retention_keeps_latest_and_first_baseline_and_expires_the_rest() {
    let d = tempfile::tempdir().unwrap();
    let l = open_ledger(d.path());
    let e = 1_000i64; // event retention for the test
    let t = 5_000i64;
    let opts = LedgerOptions {
        tombstone_retention_secs: t,
        ..LedgerOptions::default()
    };
    drop(l);
    let l = Ledger::open(&d.path().join("l.sqlite"), opts).unwrap();
    // chain: S1 (first) <- S2 <- S3 (latest); S2 superseded when S3 arrives at 3000
    ingest(
        &l,
        &rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1, 2], initial()),
        1000,
    );
    ingest(
        &l,
        &rep(
            "px-a",
            2,
            2,
            20,
            UP1,
            CS1,
            1,
            1,
            &[1, 3],
            compared(1, vec![added(3), removed(2)]),
        ),
        2000,
    );
    ingest(
        &l,
        &rep(
            "px-a",
            3,
            3,
            30,
            UP1,
            CS1,
            1,
            1,
            &[1, 3, 4],
            compared(2, vec![added(4)]),
        ),
        3000,
    );
    ingest(
        &l,
        &incomplete("px-a", 4, 40, UP1, CS1, 1, "page_error"),
        3000,
    );
    let ids = |l: &Ledger| -> Vec<String> {
        l.list_inventory_snapshots("px-a", &InvFilter::default(), None, 500)
            .unwrap()
            .items
            .iter()
            .map(|s| s.inventory_id.clone())
            .collect()
    };
    let count = |sql: &str| -> i64 {
        let c = rusqlite::Connection::open(d.path().join("l.sqlite")).unwrap();
        c.query_row(sql, [], |r| r.get(0)).unwrap()
    };
    // S2 was superseded at 3000: it must survive until 3000 + E
    let st = l.sweep(3000 + e, &|_| e).unwrap();
    assert_eq!(st.inventory_snapshots, 0);
    assert_eq!(ids(&l).len(), 3);
    let st = l.sweep(3000 + e + 1, &|_| e).unwrap();
    assert_eq!(st.inventory_snapshots, 1, "{st:?}");
    let left = ids(&l);
    assert_eq!(
        left,
        vec![inv_id(3), inv_id(1)],
        "latest and first baseline stay"
    );
    assert_eq!(
        count(&format!(
            "SELECT COUNT(*) FROM inv_members WHERE inventory_id = '{}'",
            inv_id(2)
        )),
        0,
        "members go with the snapshot"
    );
    // drift records live E from detection (2000 and 3000): all gone at 4001
    assert_eq!(count("SELECT COUNT(*) FROM inv_drift"), 0);
    l.sweep(13_000, &|_| e).unwrap();
    // the gap record goes after E (the generic gap retention)
    assert_eq!(
        count("SELECT COUNT(*) FROM gaps WHERE kind = 'inventory_incomplete'"),
        0
    );
    // report ids are remembered for max(E, T): the first report id has expired
    // by now (received at 1000, T = 5000, now >= 13000)
    assert_eq!(count("SELECT COUNT(*) FROM inv_reports"), 0);
    // latest and first baseline are still there however old
    assert_eq!(ids(&l), vec![inv_id(3), inv_id(1)]);
    let l2 = ids(&l);
    assert_eq!(l2.len(), 2);
}

/// Event retention E of the chain end tests.
const CHAIN_E: i64 = 1_000;

fn snapshot_ids(l: &Ledger) -> BTreeSet<String> {
    l.list_inventory_snapshots("px-a", &InvFilter::default(), None, 500)
        .unwrap()
        .items
        .iter()
        .map(|s| s.inventory_id.clone())
        .collect()
}

fn ids(ns: &[u32]) -> BTreeSet<String> {
    ns.iter().map(|n| inv_id(*n)).collect()
}

fn rows(d: &Path, table: &str, inv: u32) -> i64 {
    let c = rusqlite::Connection::open(d.join("l.sqlite")).unwrap();
    c.query_row(
        &format!("SELECT COUNT(*) FROM {table} WHERE inventory_id = ?1"),
        [inv_id(inv)],
        |r| r.get(0),
    )
    .unwrap()
}

/// Key-1 chain S1 (first) <- S2 (latest), then `next` as snapshot 3 under key
/// 2 received at 2000 and a key-2 snapshot 4 after it. The key-1 chain stays
/// until 2000 + E and goes whole after it; the key-2 chain stays.
fn assert_key_change_ends_the_old_chain(next: Value, links: i64) {
    let d = tempfile::tempdir().unwrap();
    let l = open_ledger(d.path());
    let k1 =
        |rid: u32, ms: &[u32], cmp: Value| rep("px-a", rid, rid, rid * 10, UP1, CS1, 1, 1, ms, cmp);
    let k2 =
        |rid: u32, ms: &[u32], cmp: Value| rep("px-a", rid, rid, rid * 10, UP1, CS1, 2, 1, ms, cmp);
    ingest(&l, &k1(1, &[1, 2], initial()), 1000);
    ingest(&l, &k1(2, &[1, 2, 3], compared(1, vec![added(3)])), 1100);
    assert_eq!(
        ingest(&l, &k2(3, &[11, 12], next), 2000),
        InventoryOutcome::Accepted
    );
    ingest(&l, &k2(4, &[11, 12], compared(3, vec![])), 2100);

    let st = l.sweep(2000 + CHAIN_E, &|_| CHAIN_E).unwrap();
    assert_eq!(st.inventory_snapshots, 0, "{st:?}");
    assert_eq!(snapshot_ids(&l), ids(&[1, 2, 3, 4]));
    let st = l.sweep(2000 + CHAIN_E + 1, &|_| CHAIN_E).unwrap();
    assert_eq!(st.inventory_snapshots, 2, "{st:?}");
    assert_eq!(
        snapshot_ids(&l),
        ids(&[3, 4]),
        "the ended key-1 chain goes whole"
    );
    for inv in [1, 2] {
        assert_eq!(rows(d.path(), "inv_members", inv), 0);
    }
    assert_eq!(rows(d.path(), "inv_members", 3), 2);
    assert_eq!(
        rows(d.path(), "inv_links", 3),
        links,
        "the new chain keeps its links"
    );
}

#[test]
fn a_declared_rotation_ends_the_old_chain_e_after_the_new_snapshot() {
    assert_key_change_ends_the_old_chain(rebase(2, "key_rotation", &[(1, 11), (2, 12)]), 2);
}

#[test]
fn an_undeclared_key_change_ends_the_old_chain_the_same_way() {
    assert_key_change_ends_the_old_chain(initial(), 0);
}

#[test]
fn a_chain_that_resumes_after_another_key_has_not_ended() {
    let d = tempfile::tempdir().unwrap();
    let l = open_ledger(d.path());
    ingest(
        &l,
        &rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1], initial()),
        1000,
    );
    ingest(
        &l,
        &rep("px-a", 2, 2, 20, UP1, CS1, 2, 1, &[2], initial()),
        1100,
    );
    ingest(
        &l,
        &rep("px-a", 3, 3, 30, UP1, CS1, 1, 1, &[1], compared(1, vec![])),
        1200,
    );
    l.sweep(1200 + 10 * CHAIN_E, &|_| CHAIN_E).unwrap();
    assert_eq!(
        snapshot_ids(&l),
        ids(&[1, 3]),
        "key 1 resumed after the key-2 snapshot; the key-2 chain is the one that ended"
    );
}

#[test]
fn a_later_snapshot_in_another_scope_key_does_not_end_a_chain() {
    let d = tempfile::tempdir().unwrap();
    let l = open_ledger(d.path());
    ingest(
        &l,
        &rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1], initial()),
        1000,
    );
    ingest(
        &l,
        &rep("px-a", 2, 2, 20, UP1, CS2, 2, 1, &[2], initial()),
        1100,
    );
    l.sweep(1100 + 10 * CHAIN_E, &|_| CHAIN_E).unwrap();
    assert_eq!(snapshot_ids(&l), ids(&[1, 2]));
}

#[test]
fn a_chain_ends_the_same_way_in_every_arrival_order() {
    let reports = [
        (rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1], initial()), 1000),
        (
            rep(
                "px-a",
                2,
                2,
                20,
                UP1,
                CS1,
                1,
                1,
                &[1, 2],
                compared(1, vec![added(2)]),
            ),
            3000,
        ),
        (rep("px-a", 3, 3, 30, UP1, CS1, 2, 1, &[3], initial()), 2000),
    ];
    let mut reference: Option<Value> = None;
    for order in permutations(reports.len()) {
        let d = tempfile::tempdir().unwrap();
        let l = open_ledger(d.path());
        for i in &order {
            let (r, now) = &reports[*i];
            assert_eq!(ingest(&l, r, *now), InventoryOutcome::Accepted, "{order:?}");
        }
        l.sweep(2000 + CHAIN_E, &|_| CHAIN_E).unwrap();
        assert_eq!(snapshot_ids(&l), ids(&[1, 2, 3]), "order {order:?}");
        l.sweep(2000 + CHAIN_E + 1, &|_| CHAIN_E).unwrap();
        assert_eq!(snapshot_ids(&l), ids(&[3]), "order {order:?}");
        let p = projection(&l);
        match &reference {
            None => reference = Some(p),
            Some(r) => assert_eq!(&p, r, "order {order:?}"),
        }
    }
}

#[test]
fn a_later_snapshot_waiting_for_its_previous_does_not_end_a_chain() {
    let d = tempfile::tempdir().unwrap();
    let l = open_ledger(d.path());
    ingest(
        &l,
        &rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1], initial()),
        1000,
    );
    // key 2, compared against a snapshot 2 that never arrives
    assert_eq!(
        ingest(
            &l,
            &rep("px-a", 3, 3, 30, UP1, CS1, 2, 1, &[3], compared(2, vec![])),
            1100,
        ),
        InventoryOutcome::Accepted
    );
    l.sweep(1100 + 10 * CHAIN_E, &|_| CHAIN_E).unwrap();
    assert_eq!(
        snapshot_ids(&l),
        ids(&[1]),
        "the waiting snapshot ages out; the key-1 chain has not ended"
    );
}

#[test]
fn ending_a_chain_leaves_other_proxies_alone() {
    let d = tempfile::tempdir().unwrap();
    let l = open_ledger(d.path());
    ingest(
        &l,
        &rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1], initial()),
        1000,
    );
    ingest(
        &l,
        &rep("px-a", 2, 2, 20, UP1, CS1, 2, 1, &[2], initial()),
        2000,
    );
    // the same scope key and key as the px-a chain that ends
    ingest_as(
        &l,
        "px-b",
        &rep("px-b", 11, 11, 10, UP1, CS1, 1, 1, &[11], initial()),
        1000,
    );
    l.sweep(2000 + 10 * CHAIN_E, &|_| CHAIN_E).unwrap();
    assert_eq!(snapshot_ids(&l), ids(&[2]));
    let px_b: BTreeSet<String> = l
        .list_inventory_snapshots("px-b", &InvFilter::default(), None, 500)
        .unwrap()
        .items
        .iter()
        .map(|s| s.inventory_id.clone())
        .collect();
    assert_eq!(px_b, ids(&[11]));
    assert_eq!(rows(d.path(), "inv_members", 11), 1);
}

#[test]
fn an_observed_at_tie_between_chains_is_decided_by_inventory_id() {
    // (key, inventory id) pairs, all observed at the same second
    for (first, second) in [((1, 1), (2, 2)), ((2, 1), (1, 2)), ((1, 2), (2, 1))] {
        let d = tempfile::tempdir().unwrap();
        let l = open_ledger(d.path());
        for (i, (key, inv)) in [first, second].into_iter().enumerate() {
            let r = rep("px-a", inv, inv, 10, UP1, CS1, key, 1, &[inv], initial());
            assert_eq!(ingest(&l, &r, 1000 + i as i64), InventoryOutcome::Accepted);
        }
        l.sweep(1000 + 10 * CHAIN_E, &|_| CHAIN_E).unwrap();
        assert_eq!(
            snapshot_ids(&l),
            ids(&[2]),
            "only the chain of the lower inventory id ends: {first:?} then {second:?}"
        );
    }
}

#[test]
fn report_ids_are_remembered_for_the_longer_of_event_and_tombstone_retention() {
    let d = tempfile::tempdir().unwrap();
    let opts = LedgerOptions {
        tombstone_retention_secs: 5_000,
        ..LedgerOptions::default()
    };
    let l = Ledger::open(&d.path().join("l.sqlite"), opts).unwrap();
    let r = rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1], initial());
    ingest(&l, &r, 1000);
    l.sweep(1000 + 5_000, &|_| 1_000).unwrap();
    assert_eq!(ingest(&l, &r, 6_000), InventoryOutcome::Duplicate);
    l.sweep(1000 + 5_001, &|_| 1_000).unwrap();
    // beyond max(E, T) the memory is gone: the report id is free, but the
    // snapshot id is not, so a late retransmission is a conflict, never a
    // second snapshot
    assert_eq!(ingest(&l, &r, 7_000), InventoryOutcome::Conflict);
}

#[test]
fn schema_v2_files_migrate_to_v3_and_keep_their_data() {
    use std::os::unix::fs::PermissionsExt as _;
    assert_eq!(SCHEMA_VERSION, 3);
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("l.sqlite");
    {
        let l = Ledger::open(&path, LedgerOptions::default()).unwrap();
        drop(l);
        // turn the file back into a v2 one: no inventory tables, no gaps.details
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch(
            "DROP TABLE inv_reports; DROP TABLE inv_snapshots; DROP TABLE inv_members;
             DROP TABLE inv_links; DROP TABLE inv_drift; DROP TABLE inv_markers; DROP TABLE inv_gap_overflow;
             ALTER TABLE gaps DROP COLUMN details;
             INSERT INTO gaps (gap_id, proxy_id, kind, detected_at, epoch_id, from_sequence,
                 to_sequence, open) VALUES ('g1','px-a','sequence_gap',5,'e',4,4,1);
             PRAGMA user_version = 2;",
        )
        .unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o077,
            0
        );
    }
    let l = Ledger::open(&path, LedgerOptions::default()).unwrap();
    let c = rusqlite::Connection::open(&path).unwrap();
    let v: i64 = c
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(v, 3);
    // the old gap survives with no details; inventory works
    let gaps = l.gaps("px-a").unwrap();
    assert_eq!(gaps.len(), 1);
    assert!(gaps[0].details.is_none());
    assert_eq!(
        ingest(
            &l,
            &rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1], initial()),
            100
        ),
        InventoryOutcome::Accepted
    );
    ingest(
        &l,
        &incomplete("px-a", 2, 20, UP1, CS1, 1, "page_error"),
        101,
    );
    assert_eq!(l.gaps("px-a").unwrap().len(), 2);
    drop(l);
    // reopening a v3 file does not migrate again
    let l = Ledger::open(&path, LedgerOptions::default()).unwrap();
    assert_eq!(l.gaps("px-a").unwrap().len(), 2);
}

#[test]
fn the_projection_stores_no_tool_content_columns() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("l.sqlite");
    drop(Ledger::open(&p, LedgerOptions::default()).unwrap());
    let c = rusqlite::Connection::open(&p).unwrap();
    let mut st = c
        .prepare(
            "SELECT m.name, p.name FROM sqlite_master m, pragma_table_info(m.name) p
             WHERE m.type = 'table' AND m.name LIKE 'inv\\_%' ESCAPE '\\'",
        )
        .unwrap();
    let cols: Vec<(String, String)> = st
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(!cols.is_empty());
    for (t, col) in &cols {
        for banned in [
            "name",
            "definition",
            "description",
            "fingerprint",
            "arguments",
            "result",
        ] {
            assert!(
                !col.contains(banned) || col == "definition_comparison",
                "{t}.{col} must not hold tool content"
            );
        }
    }
}

// ===== review fixes: wait list, gap budget, ageing, more orders =======================

fn try_ingest(l: &Ledger, report: &Value, now: i64) -> Result<InventoryOutcome, LedgerError> {
    let r = parse_inventory_report(report.to_string().as_bytes()).expect("valid report");
    l.ingest_inventory("px-a", &r, &report_digest(&r), &RefCheck::default(), now)
}

fn permutations(n: usize) -> Vec<Vec<usize>> {
    fn go(cur: &mut Vec<usize>, used: &mut Vec<bool>, out: &mut Vec<Vec<usize>>) {
        if cur.len() == used.len() {
            out.push(cur.clone());
            return;
        }
        for i in 0..used.len() {
            if !used[i] {
                used[i] = true;
                cur.push(i);
                go(cur, used, out);
                cur.pop();
                used[i] = false;
            }
        }
    }
    let mut out = Vec::new();
    go(&mut Vec::new(), &mut vec![false; n], &mut out);
    out
}

/// Every arrival order accepted by `keep` must be accepted and give the same
/// projection. Returns the number of orders compared and the projection.
fn all_orders_equal(reports: &[(Value, i64)], keep: impl Fn(&[usize]) -> bool) -> (usize, Value) {
    let mut reference: Option<Value> = None;
    let mut n = 0;
    for order in permutations(reports.len()).into_iter().filter(|o| keep(o)) {
        let d = tempfile::tempdir().unwrap();
        let l = open_ledger(d.path());
        for i in &order {
            let (r, now) = &reports[*i];
            assert_eq!(ingest(&l, r, *now), InventoryOutcome::Accepted, "{order:?}");
        }
        let p = projection(&l);
        match &reference {
            None => reference = Some(p),
            Some(r) => assert_eq!(&p, r, "order {order:?}"),
        }
        n += 1;
    }
    (n, reference.expect("at least one order"))
}

#[test]
fn orders_with_a_pending_report_that_turns_inconsistent() {
    let reports = vec![
        (
            rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1, 2, 3], initial()),
            1001,
        ),
        // omits the removal of 3: inconsistent once its previous arrives
        (
            rep(
                "px-a",
                2,
                2,
                20,
                UP1,
                CS1,
                1,
                1,
                &[1, 2, 4],
                compared(1, vec![added(4)]),
            ),
            1002,
        ),
        (
            rep("px-a", 3, 9, 15, UP2, CS2, 1, 1, &[31], initial()),
            1003,
        ),
    ];
    // in-order arrival rejects the bad report (422) by contract; every order in
    // which it comes first is comparable
    let (n, p) = all_orders_equal(&reports, |o| {
        o.iter().position(|i| *i == 1) < o.iter().position(|i| *i == 0)
    });
    assert_eq!(n, 3);
    let snaps = p["snapshots"].as_array().unwrap();
    let bad = snaps
        .iter()
        .find(|s| s["inventory_id"] == inv_id(2).as_str())
        .unwrap();
    assert_eq!(bad["comparison_state"], "inconsistent");
    assert!(p["drift"].as_array().unwrap().is_empty());
    let gaps = p["gaps"].as_array().unwrap();
    assert_eq!(gaps.len(), 1);
    assert_eq!(
        gaps[0]["detected_at"], 1002,
        "the report's own receipt time"
    );
}

#[test]
fn observed_at_ties_are_ordered_by_inventory_id_in_every_order() {
    let reports = vec![
        (rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1], initial()), 1001),
        (rep("px-a", 2, 2, 10, UP1, CS1, 2, 1, &[2], initial()), 1002),
        (rep("px-a", 3, 3, 10, UP1, CS1, 3, 2, &[3], initial()), 1003),
        (rep("px-a", 4, 4, 10, UP1, CS1, 1, 1, &[1], initial()), 1004),
    ];
    let (n, p) = all_orders_equal(&reports, |_| true);
    assert_eq!(n, 24);
    // inv1 < inv2 < inv3 < inv4 by id: three markers (2, 3, 4)
    let m = p["markers"].as_array().unwrap();
    assert_eq!(m.len(), 3);
    let by = |inv: u32| {
        m.iter()
            .find(|x| x["inventory_id"] == inv_id(inv).as_str())
            .unwrap()
    };
    assert_eq!(by(2)["cause"], "key_change_undeclared");
    assert_eq!(by(2)["previous_inventory_id"], inv_id(1).as_str());
    assert_eq!(by(3)["cause"], "epoch_change_detected");
    assert_eq!(by(4)["cause"], "epoch_change_detected");
    assert_eq!(by(4)["previous_inventory_id"], inv_id(3).as_str());
}

#[test]
fn an_initial_baseline_arriving_between_two_others_gives_the_same_markers() {
    let reports = vec![
        (rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1], initial()), 1001),
        (rep("px-a", 2, 2, 20, UP1, CS1, 2, 1, &[2], initial()), 1002),
        (rep("px-a", 3, 3, 30, UP1, CS1, 3, 1, &[3], initial()), 1003),
        (
            rep(
                "px-a",
                4,
                4,
                15,
                UP1,
                CS1,
                1,
                1,
                &[1, 5],
                compared(1, vec![added(5)]),
            ),
            1004,
        ),
    ];
    let (n, p) = all_orders_equal(&reports, |_| true);
    assert_eq!(n, 24);
    let m = p["markers"].as_array().unwrap();
    let by = |inv: u32| {
        m.iter()
            .find(|x| x["inventory_id"] == inv_id(inv).as_str())
            .unwrap()
    };
    // inv2 follows inv4 (obs 15) and inv3 follows inv2, whatever arrived first
    assert_eq!(by(2)["previous_inventory_id"], inv_id(4).as_str());
    assert_eq!(by(3)["previous_inventory_id"], inv_id(2).as_str());
}

#[test]
fn the_wait_list_is_bounded_and_resolves_once_per_arrival() {
    let d = tempfile::tempdir().unwrap();
    let l = open_ledger(d.path());
    l.set_pending_cap_for_test(2);
    // three reports that wait for the same, absent previous snapshot
    let child = |n: u32| {
        rep(
            "px-a",
            n,
            n,
            10 * n,
            UP1,
            CS1,
            1,
            1,
            &[1, 2, 3],
            compared(99, vec![]),
        )
    };
    assert_eq!(ingest(&l, &child(1), 1001), InventoryOutcome::Accepted);
    assert_eq!(ingest(&l, &child(2), 1002), InventoryOutcome::Accepted);
    // 503, not 422: the report is valid and nothing was stored for it
    assert_eq!(
        try_ingest(&l, &child(3), 1003).unwrap_err(),
        LedgerError::StorageLimit
    );
    // a report that waits for nothing is not limited
    assert_eq!(
        ingest(
            &l,
            &rep("px-a", 50, 50, 5, UP2, CS2, 1, 1, &[31], initial()),
            1004
        ),
        InventoryOutcome::Accepted
    );
    // the previous arrives: both children resolve in that one call
    assert_eq!(
        ingest(
            &l,
            &rep("px-a", 60, 99, 5, UP1, CS1, 1, 1, &[1, 2, 3], initial()),
            1005
        ),
        InventoryOutcome::Accepted
    );
    let p = projection(&l);
    let states: Vec<&str> = p["snapshots"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| {
            s["inventory_id"] == inv_id(1).as_str() || s["inventory_id"] == inv_id(2).as_str()
        })
        .map(|s| s["comparison_state"].as_str().unwrap())
        .collect();
    assert_eq!(states, vec!["compared", "compared"]);
    // room again
    assert_eq!(ingest(&l, &child(3), 1006), InventoryOutcome::Accepted);
}

#[test]
fn the_gap_budget_never_refuses_a_previous_snapshot() {
    let d = tempfile::tempdir().unwrap();
    let l = open_ledger(d.path());
    l.fill_inventory_gaps_for_test("px-a", 10_000).unwrap();
    // B waits for A and is inconsistent against it
    let b = rep(
        "px-a",
        2,
        2,
        20,
        UP1,
        CS1,
        1,
        1,
        &[1, 2, 4],
        compared(1, vec![added(4)]),
    );
    assert_eq!(ingest(&l, &b, 1002), InventoryOutcome::Accepted);
    // the legitimate previous snapshot is accepted although the gap record
    // cannot be stored: it is counted instead
    let a = rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1, 2, 3], initial());
    assert_eq!(ingest(&l, &a, 1001), InventoryOutcome::Accepted);
    assert_eq!(l.inventory_gap_overflow("px-a").unwrap(), 1);
    let p = projection(&l);
    let state = |n: u32| {
        p["snapshots"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["inventory_id"] == inv_id(n).as_str())
            .unwrap()["comparison_state"]
            .clone()
    };
    assert_eq!(state(1), "baseline");
    assert_eq!(state(2), "inconsistent");
    assert!(p["drift"].as_array().unwrap().is_empty());
    // an incomplete observation, whose only effect is its gap, is refused
    assert_eq!(
        try_ingest(
            &l,
            &incomplete("px-a", 5, 30, UP1, CS1, 1, "page_error"),
            1003
        )
        .unwrap_err(),
        LedgerError::StorageLimit
    );
}

#[tokio::test]
async fn dropped_gap_records_are_visible_in_the_proxy_detail() {
    let fx = Fx::new().await;
    fx.reg_default();
    fx.ctx
        .ledger
        .fill_inventory_gaps_for_test("px-a", 10_000)
        .unwrap();
    fx.ok(
        A,
        &rep(
            "px-a",
            2,
            2,
            20,
            UP1,
            CS1,
            1,
            1,
            &[1, 2, 4],
            compared(1, vec![added(4)]),
        ),
    )
    .await;
    fx.ok(
        A,
        &rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1, 2, 3], initial()),
    )
    .await;
    let d = fx.get("/v1/proxies/px-a").await.json();
    assert_eq!(d["audit_gaps_dropped"], 1);
    let s = fx.snaps("px-a").await;
    assert_eq!(snap(&s, 2)["comparison_state"], "inconsistent");
}

#[test]
fn waiting_snapshots_age_out_and_a_replay_never_makes_a_forever_row() {
    let d = tempfile::tempdir().unwrap();
    let opts = LedgerOptions {
        tombstone_retention_secs: 5_000,
        ..LedgerOptions::default()
    };
    let l = Ledger::open(&d.path().join("l.sqlite"), opts).unwrap();
    let e = 1_000i64;
    let waiting = rep(
        "px-a",
        1,
        2,
        20,
        UP1,
        CS1,
        1,
        1,
        &[1, 2],
        compared(77, vec![]),
    );
    let count = |sql: &str| -> i64 {
        let c = rusqlite::Connection::open(d.path().join("l.sqlite")).unwrap();
        c.query_row(sql, [], |r| r.get(0)).unwrap()
    };
    assert_eq!(ingest(&l, &waiting, 1000), InventoryOutcome::Accepted);
    assert_eq!(count("SELECT COUNT(*) FROM inv_snapshots"), 1);
    // not yet E old
    l.sweep(1000 + e, &|_| e).unwrap();
    assert_eq!(count("SELECT COUNT(*) FROM inv_snapshots"), 1);
    // E after receipt it is gone, with its members
    let st = l.sweep(1000 + e + 1, &|_| e).unwrap();
    assert_eq!(st.inventory_snapshots, 1);
    assert_eq!(count("SELECT COUNT(*) FROM inv_snapshots"), 0);
    assert_eq!(count("SELECT COUNT(*) FROM inv_members"), 0);
    // a replay inside max(E, T) is a duplicate: no new waiting row
    assert_eq!(ingest(&l, &waiting, 3000), InventoryOutcome::Duplicate);
    assert_eq!(count("SELECT COUNT(*) FROM inv_snapshots"), 0);
    // after the report id expired too, a replay waits again, and ages out again
    l.sweep(1000 + 5_001, &|_| e).unwrap();
    assert_eq!(ingest(&l, &waiting, 7000), InventoryOutcome::Accepted);
    assert_eq!(count("SELECT COUNT(*) FROM inv_snapshots"), 1);
    l.sweep(7000 + e + 1, &|_| e).unwrap();
    assert_eq!(count("SELECT COUNT(*) FROM inv_snapshots"), 0);
}

#[test]
fn a_complete_report_without_a_comparison_is_refused_not_treated_as_incomplete() {
    let d = tempfile::tempdir().unwrap();
    let l = open_ledger(d.path());
    let inc = incomplete("px-a", 1, 10, UP1, CS1, 1, "page_error");
    let mut r = parse_inventory_report(inc.to_string().as_bytes()).unwrap();
    r.completeness = lodeline_proxy_api::Completeness::Complete;
    r.incomplete_reason = None;
    r.inventory_id = Some(lodeline_proxy_api::Uuid::new(inv_id(1)).unwrap());
    r.members = Some(vec![]);
    r.comparison = None;
    let out = l
        .ingest_inventory("px-a", &r, &report_digest(&r), &RefCheck::default(), 1)
        .unwrap();
    assert_eq!(out, InventoryOutcome::Invalid);
    assert!(l.gaps("px-a").unwrap().is_empty());
}

#[test]
fn a_v3_file_without_the_gap_overflow_table_is_repaired_on_open() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("l.sqlite");
    {
        let l = Ledger::open(&path, LedgerOptions::default()).unwrap();
        ingest(
            &l,
            &rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1], initial()),
            1000,
        );
        drop(l);
        // the shape of a v3 file written before the table existed
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch("DROP TABLE inv_gap_overflow;").unwrap();
    }
    let l = Ledger::open(&path, LedgerOptions::default()).unwrap();
    // what GET /v1/proxies/{id} reads, and the retention sweep
    let page = l.gaps_page("px-a", 50).unwrap();
    assert_eq!((page.total, page.dropped), (0, 0));
    assert_eq!(l.inventory_gap_overflow("px-a").unwrap(), 0);
    l.sweep(1_000_000_000, &|_| 1_000).unwrap();
    // and the counter works
    l.fill_inventory_gaps_for_test("px-a", 10_000).unwrap();
    let b = rep(
        "px-a",
        3,
        3,
        20,
        UP1,
        CS1,
        1,
        1,
        &[1, 2],
        compared(2, vec![added(2)]),
    );
    let a = rep("px-a", 2, 2, 15, UP1, CS1, 1, 1, &[1], initial());
    ingest(&l, &b, 1001);
    ingest(&l, &a, 1002);
    assert_eq!(
        l.gaps_page("px-a", 50).unwrap().dropped,
        0,
        "consistent: no gap"
    );
}

fn parse_now(t: &str) -> i64 {
    time::OffsetDateTime::parse(t, &time::format_description::well_known::Rfc3339)
        .unwrap()
        .unix_timestamp()
}

#[tokio::test]
async fn observed_at_may_be_at_most_300_seconds_ahead_of_the_server_clock() {
    assert_eq!(
        lodeline_server::proxy::inventory::MAX_OBSERVED_AHEAD_SECS,
        300
    );
    let fx = Fx::new().await;
    fx.reg_default();
    // the report observed at `at(1000)`, judged at a fixed server clock
    let report = |rid: u32, obs: u32| rep("px-a", rid, rid, obs, UP1, CS1, 1, 1, &[1], initial());
    let base = parse_now(&at(1000));
    let judge = |r: &Value, now: i64| {
        lodeline_server::proxy::inventory::handle_at(&fx.ctx, "px-a", r.to_string().as_bytes(), now)
    };
    let status = |r: axum::response::Response| r.status().as_u16();
    // exactly 300 s ahead: accepted
    assert_eq!(status(judge(&report(1, 1000), base - 300)), 200);
    // 301 s ahead: 422, nothing stored
    let r = judge(&report(2, 1000), base - 301);
    assert_eq!(r.status().as_u16(), 422);
    let body = axum::body::to_bytes(r.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["error"]["code"],
        "semantic_invalid"
    );
    assert!(!String::from_utf8_lossy(&body).contains(&at(1000)));
    assert_eq!(fx.snaps("px-a").await.len(), 1);
    // an incomplete report is bound by the same rule
    let inc = incomplete("px-a", 3, 1000, UP1, CS1, 1, "page_error");
    assert_eq!(status(judge(&inc, base - 301)), 422);
    assert_eq!(status(judge(&inc, base - 300)), 200);
}

#[tokio::test]
async fn an_old_observed_at_is_accepted() {
    let fx = Fx::new().await;
    fx.reg_default();
    let r = rep("px-a", 1, 1, 10, UP1, CS1, 1, 1, &[1], initial());
    // server clock a year after the observation
    let now = parse_now(&at(10)) + 365 * 86_400;
    let resp = lodeline_server::proxy::inventory::handle_at(
        &fx.ctx,
        "px-a",
        r.to_string().as_bytes(),
        now,
    );
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(fx.snaps("px-a").await.len(), 1);
}

// ===== metadata retention (README N9 retention row) ===============================

/// px-a's `event_retention_seconds` (E) in `config_with`.
const E_SECS: i64 = 7_776_000;

/// G = R + M for px-a: R from its stored config, M the server margin.
fn grace(fx: &Fx) -> i64 {
    fx.ctx
        .store
        .config("px-a")
        .unwrap()
        .config
        .max_offline_retry_age_seconds
        + i64::from(fx.ctx.ack_loss_margin)
}

/// The ledger sweep, then the metadata pass, as the scheduler runs them.
fn sweep_at(fx: &Fx, now: i64) {
    fx.ctx.ledger_sweep(now).unwrap();
    fx.ctx.metadata_sweep(now).unwrap();
}

fn kept(fx: &Fx, n: u32) -> bool {
    matches!(
        fx.ctx.metadata.lookup("px-a", &[&mref(n)]).unwrap()[0],
        lodeline_server::proxy::metadata::RefLookup::Own(_)
    )
}

/// Upload px-a entries `ns` (up1, CS1, key 1) at server time `now`.
fn reg_at(fx: &Fx, ns: &[u32], now: i64) -> lodeline_server::proxy::metadata::UploadOutcome {
    let entries: Vec<RegistryEntry> = ns
        .iter()
        .map(|n| reg_entry("px-a", *n, UP1, CS1, 1))
        .collect();
    fx.ctx.metadata.register("px-a", &entries, now).unwrap()
}

fn unix_now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// A px-a `tools/call` start naming ref `r` (event id and sequence `n`).
fn start(n: u32, inv: u32, r: u32) -> Value {
    json!({
        "schema_version": 1,
        "event_id": uuid(n),
        "proxy_id": "px-a",
        "epoch_id": epoch(1),
        "sequence": n,
        "occurred_at": "2026-10-10T00:00:00Z",
        "event_type": "invocation.started",
        "payload": {
            "invocation_id": uuid(5000 + inv),
            "upstream_id": UP1,
            "route_revision": 1,
            "protocol_version": "2025-11-25",
            "method": "tools/call",
            "actor": {
                "actor_id": "actor-1",
                "actor_kind": "non_human",
                "authentication_method": "bearer",
                "evidence_source": "proxy_credential_mapping"
            },
            "tool": {"status": "identified", "metadata_ref": mref(r)},
        },
    })
}

fn events_body(evs: &[Value]) -> String {
    json!({ "events": evs }).to_string()
}

async fn post_events(fx: &Fx, evs: &[Value]) -> Resp {
    fx.call(
        "POST",
        "/v1/proxy-events",
        A,
        None,
        None,
        Some(events_body(evs)),
    )
    .await
}

fn received_at(fx: &Fx, n: u32) -> Option<i64> {
    fx.ctx
        .ledger
        .stored_event("px-a", &uuid(n))
        .unwrap()
        .map(|e| e.received_at)
}

fn judge_at(fx: &Fx, report: &Value, now: i64) -> u16 {
    lodeline_server::proxy::inventory::handle_at(
        &fx.ctx,
        "px-a",
        report.to_string().as_bytes(),
        now,
    )
    .status()
    .as_u16()
}

#[tokio::test]
async fn an_unreferenced_entry_goes_once_its_last_upload_is_older_than_r_plus_m() {
    let fx = Fx::new().await;
    let g = grace(&fx);
    let base = unix_now();
    reg_at(&fx, &[1, 2], base);
    reg_at(&fx, &[3], base + 10);
    assert_eq!(post_events(&fx, &[start(1, 1, 1)]).await.status, 200);

    sweep_at(&fx, base + g);
    assert!(kept(&fx, 2), "exactly G after its upload, the entry stays");
    sweep_at(&fx, base + g + 1);
    assert!(!kept(&fx, 2), "unreferenced and older than G: deleted");
    assert!(kept(&fx, 3), "younger than G: kept");
    assert!(kept(&fx, 1), "named by a retained start: kept");

    // The start lives E after receipt, and its entry with it, however old.
    let received = received_at(&fx, 1).unwrap();
    sweep_at(&fx, received + E_SECS);
    assert!(kept(&fx, 1), "kept while the start is");
    sweep_at(&fx, received + E_SECS + 1);
    assert_eq!(received_at(&fx, 1), None, "the start aged out under E");
    assert!(!kept(&fx, 1), "then its entry goes");
}

#[tokio::test]
async fn a_duplicate_upload_restarts_the_retention_clock() {
    let fx = Fx::new().await;
    let g = grace(&fx);
    let base = unix_now();
    reg_at(&fx, &[4], base);
    let again = reg_at(&fx, &[4], base + g);
    let dup: Vec<&str> = again.duplicate.iter().map(|r| r.as_str()).collect();
    assert_eq!(dup, [mref(4)]);
    sweep_at(&fx, base + g + 1);
    assert!(kept(&fx, 4), "the duplicate upload counts as an upload");
    sweep_at(&fx, base + 2 * g + 1);
    assert!(!kept(&fx, 4));
}

#[tokio::test]
async fn every_start_of_an_invocation_keeps_its_entry() {
    // Two different starts of one invocation: the projection shows one tool,
    // the stored events name both refs.
    let fx = Fx::new().await;
    let base = unix_now();
    reg_at(&fx, &[5, 6], base);
    assert_eq!(
        post_events(&fx, &[start(10, 7, 5), start(11, 7, 6)])
            .await
            .status,
        200
    );
    sweep_at(&fx, base + grace(&fx) + 1);
    assert!(kept(&fx, 5) && kept(&fx, 6));
}

#[tokio::test]
async fn a_drift_record_keeps_its_entries_after_the_snapshot_is_gone() {
    let fx = Fx::new().await;
    let b = parse_now(&at(0)) + 86_400;
    reg_at(&fx, &[1, 2, 3, 4], b);
    let r = |rid: u32, ms: &[u32], cmp: Value| rep("px-a", rid, rid, rid, UP1, CS1, 1, 1, ms, cmp);
    assert_eq!(judge_at(&fx, &r(1, &[1], initial()), b), 200);
    let s2 = r(2, &[1, 2, 3], compared(1, vec![added(2), added(3)]));
    assert_eq!(judge_at(&fx, &s2, b), 200);
    // Snapshot 4 (observed after 3) arrives first: snapshot 2 is superseded now.
    assert_eq!(judge_at(&fx, &r(4, &[1, 4], compared(3, vec![])), b), 200);
    // Snapshot 3 removes ref 2 and replaces ref 3 by ref 4; its drift records
    // are detected 100 s later.
    let s3 = r(3, &[1, 4], compared(2, vec![removed(2), changed(4, 3)]));
    assert_eq!(judge_at(&fx, &s3, b + 100), 200);

    sweep_at(&fx, b + E_SECS + 50);
    let inv: Vec<String> = fx
        .snaps("px-a")
        .await
        .iter()
        .map(|s| s["inventory_id"].as_str().unwrap().to_string())
        .collect();
    assert!(!inv.contains(&inv_id(2)), "snapshot 2 aged out: {inv:?}");
    assert_eq!(drift_set(&fx.drift("px-a").await).len(), 2);
    assert!(kept(&fx, 2), "the removed record names ref 2");
    assert!(
        kept(&fx, 3),
        "the changed record names ref 3 as the previous ref"
    );

    sweep_at(&fx, b + 100 + E_SECS + 1);
    assert!(fx.drift("px-a").await.is_empty());
    assert!(
        !kept(&fx, 2) && !kept(&fx, 3),
        "no retained row names refs 2 and 3"
    );
    assert!(
        kept(&fx, 1) && kept(&fx, 4),
        "the latest snapshot's members stay"
    );
}

#[tokio::test]
async fn a_rotation_link_keeps_its_entry_after_the_snapshot_is_gone() {
    let fx = Fx::new().await;
    let b = parse_now(&at(0)) + 86_400;
    reg_at(&fx, &[1, 2, 5], b);
    let k1 = |rid: u32, ms: &[u32], cmp: Value| rep("px-a", rid, rid, rid, UP1, CS1, 1, 1, ms, cmp);
    assert_eq!(judge_at(&fx, &k1(1, &[5], initial()), b), 200);
    assert_eq!(
        judge_at(&fx, &k1(2, &[5, 1], compared(1, vec![added(1)])), b),
        200
    );
    // Observed last, the rotation snapshot ends the key-1 chain.
    let rot = rep(
        "px-a",
        3,
        3,
        5,
        UP1,
        CS1,
        2,
        1,
        &[2],
        rebase(2, "key_rotation", &[(1, 2)]),
    );
    assert_eq!(judge_at(&fx, &rot, b), 200);
    // A later key-1 snapshot supersedes snapshot 2 (the link's `from` side).
    assert_eq!(
        judge_at(&fx, &k1(4, &[5], compared(2, vec![removed(1)])), b),
        200
    );

    sweep_at(&fx, b + E_SECS + 1);
    let inv: Vec<String> = fx
        .snaps("px-a")
        .await
        .iter()
        .map(|s| s["inventory_id"].as_str().unwrap().to_string())
        .collect();
    assert!(!inv.contains(&inv_id(2)), "snapshot 2 aged out: {inv:?}");
    assert!(fx.drift("px-a").await.is_empty());
    assert!(kept(&fx, 1), "only the link of snapshot 3 names ref 1");
    assert!(kept(&fx, 2));
    assert!(!kept(&fx, 5), "only the ended key-1 chain named ref 5");
}

#[tokio::test]
async fn an_ended_chain_releases_its_entries_e_after_the_new_key_snapshot() {
    let fx = Fx::new().await;
    let b = parse_now(&at(0)) + 86_400;
    reg_at(&fx, &[1, 2, 3], b);
    let old = rep("px-a", 1, 1, 1, UP1, CS1, 1, 1, &[1, 2], initial());
    assert_eq!(judge_at(&fx, &old, b), 200);
    let rot = rep(
        "px-a",
        2,
        2,
        2,
        UP1,
        CS1,
        2,
        1,
        &[3],
        rebase(1, "key_rotation", &[(2, 3)]),
    );
    assert_eq!(judge_at(&fx, &rot, b + 10), 200);

    sweep_at(&fx, b + 10 + E_SECS);
    assert!(kept(&fx, 1), "the key-1 chain has not ended yet");
    sweep_at(&fx, b + 10 + E_SECS + 1);
    let inv: Vec<String> = fx
        .snaps("px-a")
        .await
        .iter()
        .map(|s| s["inventory_id"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(inv, [inv_id(2)], "the key-1 chain ended");
    assert!(!kept(&fx, 1), "only the ended chain named ref 1");
    assert!(kept(&fx, 2), "the link of snapshot 2 names ref 2");
    assert!(kept(&fx, 3));
}

#[tokio::test]
async fn a_held_registry_conflict_gap_keeps_its_entry() {
    let fx = Fx::new().await;
    let base = unix_now();
    reg_at(&fx, &[7], base);
    let gap: lodeline_proxy_api::GapReport = serde_json::from_value(json!({
        "kind": "registry_conflict", "gap_id": uuid(900), "detected_at": "2026-10-10T00:00:00Z",
        "metadata_ref": mref(7), "key_id": kid(1), "event_ids": [uuid(901)],
        "detected_by": "central_409", "affected_event_count": 1,
    }))
    .unwrap();
    let mut e = fx.ctx.store.entry("px-a").unwrap();
    e.gaps.push(gap);
    fx.ctx.store.begin().commit("px-a", e.clone()).unwrap();
    sweep_at(&fx, base + grace(&fx) + 1);
    assert!(kept(&fx, 7), "the held gap names ref 7");
    e.gaps.clear();
    fx.ctx.store.begin().commit("px-a", e).unwrap();
    sweep_at(&fx, base + grace(&fx) + 1);
    assert!(!kept(&fx, 7));
}

/// `(content_state, definition)` of a px-a entry, read from the file.
fn content(fx: &Fx, n: u32) -> (String, Vec<u8>) {
    let c = rusqlite::Connection::open(fx._dir.path().join("proxy-metadata.sqlite")).unwrap();
    c.query_row(
        "SELECT content_state, definition FROM entries
         WHERE proxy_id = 'px-a' AND metadata_ref = ?1",
        [mref(n)],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .unwrap()
}

#[tokio::test]
async fn deleted_content_keeps_the_stub_for_uploads_events_and_the_sweep() {
    let fx = Fx::new().await;
    let base = unix_now();
    reg_at(&fx, &[8, 9], base);
    for n in [8, 9] {
        assert!(fx.ctx.metadata.delete_content("px-a", &mref(n)).unwrap());
    }
    assert!(!fx.ctx.metadata.delete_content("px-a", &mref(10)).unwrap());
    assert!(
        !fx.ctx.metadata.delete_content("px-b", &mref(8)).unwrap(),
        "another proxy's ref is not found"
    );
    assert_eq!(content(&fx, 8), ("deleted".into(), Vec::new()));

    let again = reg_at(&fx, &[8], base + 5);
    let dup: Vec<&str> = again.duplicate.iter().map(|r| r.as_str()).collect();
    assert_eq!(dup, [mref(8)], "an equal upload is a duplicate");
    assert_eq!(
        content(&fx, 8),
        ("deleted".into(), Vec::new()),
        "and does not restore the definition"
    );
    let differing = reg_entry("px-a", 8, UP1, CS1, 2);
    assert_eq!(
        fx.ctx.metadata.register("px-a", &[differing], base + 6),
        Err(lodeline_server::proxy::metadata::UploadError::Conflicts(
            vec![0]
        ))
    );
    assert_eq!(post_events(&fx, &[start(1, 1, 8)]).await.status, 200);

    sweep_at(&fx, base + grace(&fx) + 1);
    assert!(kept(&fx, 8), "named by a retained start");
    assert!(!kept(&fx, 9), "an unreferenced stub older than G goes");
}

#[test]
fn deleted_content_is_in_neither_the_database_file_nor_its_wal() {
    use lodeline_server::proxy::metadata::{MetadataCaps, MetadataStore};
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("m.sqlite");
    let caps = MetadataCaps {
        entries_per_proxy: 10,
        bytes_per_proxy: 1 << 22,
        bytes_total: 1 << 22,
    };
    let s = MetadataStore::open(&path, caps).unwrap();
    // A small definition lives in a b-tree page, a large one in overflow pages.
    let marker = |n: u32| format!("CONTENT-DELETE-MARKER-{n}");
    let entries: Vec<RegistryEntry> = [(1u32, 10usize), (2, 100_000), (3, 10), (4, 10)]
        .iter()
        .map(|&(n, pad)| {
            let mut e = reg_entry("px-a", n, UP1, CS1, 1);
            e.definition = json!({"name": marker(n), "pad": "x".repeat(pad)});
            e
        })
        .collect();
    s.register("px-a", &entries, 1_000).unwrap();
    let raw = || {
        let mut b = std::fs::read(&path).unwrap();
        b.extend(std::fs::read(path.with_extension("sqlite-wal")).unwrap_or_default());
        b
    };
    let has = |b: &[u8], m: &str| b.windows(m.len()).any(|w| w == m.as_bytes());
    let before = raw();
    assert!(
        (1..=3).all(|n| has(&before, &marker(n))),
        "the search sees stored content"
    );
    for n in [1, 2] {
        assert!(s.delete_content("px-a", &mref(n)).unwrap());
    }
    let after = raw();
    assert!(!has(&after, &marker(1)), "small definition left behind");
    assert!(!has(&after, &marker(2)), "large definition left behind");
    assert!(has(&after, &marker(3)), "other content is untouched");

    // A reader on the file keeps the truncate from completing.
    let reader = rusqlite::Connection::open(&path).unwrap();
    reader.execute_batch("BEGIN").unwrap();
    let _: i64 = reader
        .query_row("SELECT COUNT(*) FROM entries", [], |r| r.get(0))
        .unwrap();
    assert!(
        s.delete_content("px-a", &mref(4)).unwrap(),
        "still a success"
    );
    assert!(has(&raw(), &marker(4)), "the reader held the old pages");
    drop(reader);
    assert!(s.delete_content("px-a", &mref(4)).unwrap());
    assert!(
        !has(&raw(), &marker(4)),
        "a repeat call finishes the truncate"
    );
}

#[test]
fn a_v2_metadata_store_migrates_to_v3_with_every_entry_present() {
    use lodeline_server::proxy::metadata::{MetadataCaps, MetadataStore};
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("m.sqlite");
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch(
            "CREATE TABLE entries (
                proxy_id TEXT NOT NULL, metadata_ref TEXT NOT NULL, upstream_id TEXT NOT NULL,
                credential_scope_id TEXT NOT NULL, protocol_version TEXT NOT NULL,
                observation_source TEXT NOT NULL, canon TEXT NOT NULL, key_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL, observed_at TEXT NOT NULL, definition BLOB NOT NULL,
                size INTEGER NOT NULL, registered_at INTEGER NOT NULL,
                last_upload_at INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (proxy_id, metadata_ref)) WITHOUT ROWID;
             CREATE INDEX entries_ref ON entries (metadata_ref);
             CREATE TABLE usage (proxy_id TEXT PRIMARY KEY, entries INTEGER NOT NULL,
                bytes INTEGER NOT NULL) WITHOUT ROWID;
             PRAGMA user_version = 2;",
        )
        .unwrap();
        for n in [1u32, 2] {
            c.execute(
                "INSERT INTO entries VALUES ('px-a', ?1, 'up1', ?2, '2025-11-25', 'proxy_live',
                     'sigil-tooldef-fp-v1', ?3, ?4, '2026-10-10T00:00:00Z', x'7b7d', 400, 1000,
                     1000)",
                rusqlite::params![mref(n), CS1, kid(1), "f".repeat(64)],
            )
            .unwrap();
        }
        c.execute("INSERT INTO usage VALUES ('px-a', 2, 800)", [])
            .unwrap();
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let caps = MetadataCaps {
        entries_per_proxy: 10,
        bytes_per_proxy: 1 << 20,
        bytes_total: 1 << 20,
    };
    let s = MetadataStore::open(&path, caps).unwrap();
    assert_eq!(s.count("px-a").unwrap(), 2, "every v2 entry is kept");
    assert!(s.delete_content("px-a", &mref(2)).unwrap());
    drop(s);
    let c = rusqlite::Connection::open(&path).unwrap();
    let v: i64 = c
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(v, 3);
    let states: Vec<(String, Vec<u8>)> = c
        .prepare("SELECT content_state, definition FROM entries ORDER BY metadata_ref")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        states,
        [
            ("present".into(), b"{}".to_vec()),
            ("deleted".into(), Vec::new())
        ],
        "a migrated entry has its content until it is deleted"
    );
    let usage: i64 = c
        .query_row("SELECT bytes FROM usage WHERE proxy_id = 'px-a'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(usage, 798, "usage drops by the deleted definition");
    assert!(
        c.execute("UPDATE entries SET content_state = 'gone'", [])
            .is_err(),
        "only present or deleted"
    );
}

#[tokio::test]
async fn an_ingest_that_starts_during_the_pass_waits_and_sees_the_deletion() {
    let fx = Fx::new().await;
    let g = grace(&fx);
    let base = unix_now();
    reg_at(&fx, &[8], base);
    let ctx = fx.ctx.clone();
    let mut started = None;
    let deleted = fx
        .ctx
        .metadata
        .sweep(base + g + 1, &|_| g, || {
            let (tx, rx) = std::sync::mpsc::channel();
            let c = ctx.clone();
            let body = events_body(&[start(20, 20, 8)]);
            let h = std::thread::spawn(move || {
                let r = lodeline_server::proxy::ingest::handle(&c, "px-a", body.as_bytes());
                tx.send(r.status().as_u16()).unwrap();
            });
            assert!(
                rx.recv_timeout(std::time::Duration::from_millis(300))
                    .is_err(),
                "an ingest cannot validate a ref while the pass holds the refs"
            );
            started = Some((h, rx));
            ctx.live_metadata_refs()
        })
        .unwrap();
    assert_eq!(deleted, 1);
    let (h, rx) = started.unwrap();
    h.join().unwrap();
    assert_eq!(
        rx.recv().unwrap(),
        424,
        "the start waits for the entry again"
    );
    assert_eq!(received_at(&fx, 20), None);
}

#[tokio::test]
async fn an_inventory_report_that_arrives_during_the_pass_waits_and_sees_the_deletion() {
    let fx = Fx::new().await;
    let g = grace(&fx);
    let b = parse_now(&at(0)) + 86_400;
    reg_at(&fx, &[8], b);
    let ctx = fx.ctx.clone();
    let mut started = None;
    fx.ctx
        .metadata
        .sweep(b + g + 1, &|_| g, || {
            let (tx, rx) = std::sync::mpsc::channel();
            let c = ctx.clone();
            let body = rep("px-a", 1, 1, 1, UP1, CS1, 1, 1, &[8], initial()).to_string();
            let h = std::thread::spawn(move || {
                let r = lodeline_server::proxy::inventory::handle_at(
                    &c,
                    "px-a",
                    body.as_bytes(),
                    b + g + 1,
                );
                tx.send(r.status().as_u16()).unwrap();
            });
            assert!(
                rx.recv_timeout(std::time::Duration::from_millis(300))
                    .is_err(),
                "a report cannot validate a ref while the pass holds the refs"
            );
            started = Some((h, rx));
            ctx.live_metadata_refs()
        })
        .unwrap();
    let (h, rx) = started.unwrap();
    h.join().unwrap();
    assert_eq!(
        rx.recv().unwrap(),
        424,
        "the report waits for the entry again"
    );
    assert!(fx.snaps("px-a").await.is_empty());
}

#[tokio::test]
async fn the_pass_waits_for_an_ingest_that_validated_a_ref() {
    let fx = Fx::new().await;
    let g = grace(&fx);
    let base = unix_now();
    reg_at(&fx, &[9], base);
    let held = fx.ctx.metadata.hold_refs();
    assert!(kept(&fx, 9), "validated");
    let (tx, rx) = std::sync::mpsc::channel();
    let ctx = fx.ctx.clone();
    let pass = std::thread::spawn(move || {
        ctx.metadata
            .sweep(base + g + 1, &|_| g, || {
                tx.send(()).unwrap();
                ctx.live_metadata_refs()
            })
            .unwrap()
    });
    assert!(
        rx.recv_timeout(std::time::Duration::from_millis(300))
            .is_err(),
        "the pass cannot read the live set while a validated ingest holds the refs"
    );
    let evs = lodeline_proxy_api::parse_event_batch(events_body(&[start(21, 21, 9)]).as_bytes())
        .unwrap()
        .events;
    fx.ctx.ledger.insert_batch("px-a", &evs, base).unwrap();
    drop(held);
    assert_eq!(pass.join().unwrap(), 0);
    assert!(
        kept(&fx, 9),
        "the stored start keeps the entry it was validated against"
    );
}

#[test]
fn a_v1_metadata_store_migrates_and_keeps_every_entry() {
    use lodeline_server::proxy::metadata::{MetadataCaps, MetadataStore};
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("m.sqlite");
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch(
            "CREATE TABLE entries (
                proxy_id TEXT NOT NULL, metadata_ref TEXT NOT NULL, upstream_id TEXT NOT NULL,
                credential_scope_id TEXT NOT NULL, protocol_version TEXT NOT NULL,
                observation_source TEXT NOT NULL, canon TEXT NOT NULL, key_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL, observed_at TEXT NOT NULL, definition BLOB NOT NULL,
                size INTEGER NOT NULL, registered_at INTEGER NOT NULL,
                PRIMARY KEY (proxy_id, metadata_ref)) WITHOUT ROWID;
             CREATE INDEX entries_ref ON entries (metadata_ref);
             CREATE TABLE usage (proxy_id TEXT PRIMARY KEY, entries INTEGER NOT NULL,
                bytes INTEGER NOT NULL) WITHOUT ROWID;
             PRAGMA user_version = 1;",
        )
        .unwrap();
        for (n, at) in [(1u32, 1_000i64), (2, 2_000)] {
            c.execute(
                "INSERT INTO entries VALUES ('px-a', ?1, 'up1', ?2, '2025-11-25', 'proxy_live',
                     'sigil-tooldef-fp-v1', ?3, ?4, '2026-10-10T00:00:00Z', x'7b7d', 400, ?5)",
                rusqlite::params![mref(n), CS1, kid(1), "f".repeat(64), at],
            )
            .unwrap();
        }
        c.execute("INSERT INTO usage VALUES ('px-a', 2, 800)", [])
            .unwrap();
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let caps = MetadataCaps {
        entries_per_proxy: 10,
        bytes_per_proxy: 1 << 20,
        bytes_total: 1 << 20,
    };
    let s = MetadataStore::open(&path, caps).unwrap();
    assert_eq!(s.count("px-a").unwrap(), 2, "every v1 entry is kept");
    let none = || Ok(Default::default());
    // The last upload of a v1 entry is its registration: ref 1 is exactly G
    // old at 1_100, ref 2 is younger.
    let scanned = std::cell::Cell::new(false);
    let live = || {
        scanned.set(true);
        Ok(Default::default())
    };
    assert_eq!(s.sweep(1_100, &|_| 100, live).unwrap(), 0);
    assert!(
        !scanned.get(),
        "with nothing expired the pass does not scan the ledger"
    );
    assert_eq!(s.sweep(1_101, &|_| 100, none).unwrap(), 1);
    let left = s.lookup("px-a", &[&mref(1), &mref(2)]).unwrap();
    assert_eq!(
        left[0],
        lodeline_server::proxy::metadata::RefLookup::Unknown
    );
    assert!(matches!(
        left[1],
        lodeline_server::proxy::metadata::RefLookup::Own(_)
    ));
    drop(s);
    let c = rusqlite::Connection::open(&path).unwrap();
    let v: i64 = c
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(v, 3);
    let usage: (i64, i64) = c
        .query_row(
            "SELECT entries, bytes FROM usage WHERE proxy_id = 'px-a'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(usage, (1, 400), "usage is recomputed after the delete");
}
