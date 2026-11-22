#![cfg(unix)]
//! Client certificate rotation with the real `lodeline-server` proxy control
//! plane and the real `lodeline-proxy` on loopback mTLS.
//!
//! An operator pins a second fingerprint (`fp_next`). The first request the
//! proxy authenticates with the new certificate promotes it to `fp_current`
//! and drops the old one. The old certificate is then refused, and retiring
//! the proxy stops the new certificate too. The registry is read through the
//! server's context, the refusals through real handshakes.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use lodeline_proxy::bootstrap::Bootstrap;
use lodeline_proxy::lifecycle::{read_status, run_tuned, RunTuning};
use lodeline_proxy::route::TableHandle;
use lodeline_proxy_api::status::ConfigState;
use lodeline_proxy_api::verifier::verifier_for;
use lodeline_server::proxy::identity::proxy_san;
use lodeline_server::proxy::registry::ProxyState;
use serde_json::{json, Value};

mod common;
use common::{client_ext, fingerprint, mgmt_identity, mtls_client_pooled, pki, Pki, Server, Tweak};

const T_ID: &str = "tok-identity-rot";
const T_CFG: &str = "tok-config-rot";
const PROXY_ID: &str = "px-rot";
const WAIT: Duration = Duration::from_secs(40);

type Cert = (PathBuf, PathBuf);

fn spec() -> Value {
    json!({
        "schema_version": 1,
        "proxy_id": PROXY_ID,
        "allowed_origins": ["https://app.example.com"],
        "routes": [{
            "route_id": "r1",
            "upstream_id": "up1",
            "upstream_url": "http://127.0.0.1:9/mcp",
            "upstream_protocol": "2025-11-25",
            "credential_ref": "gh",
        }],
        "principals": [{
            "principal_id": "alice",
            "verifiers": [{"key_id": "k-alice", "verifier": verifier_for("client-token")}],
            "routes": ["r1"],
        }],
    })
}

struct Proxy {
    state_dir: PathBuf,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Proxy {
    /// Starts a proxy that presents `cert`, with its own state folder `name`.
    fn start(pki: &Pki, server_port: u16, cert: &Cert, name: &str) -> Proxy {
        let d = pki.dir.path();
        let state_dir = d.join(name);
        let secret = d.join(format!("{name}-secret"));
        std::fs::write(&secret, "UPSTREAM-SECRET-VALUE\n").unwrap();
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
        let sock = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let yaml = format!(
            "proxy_id: {PROXY_ID}\nlisten: \"127.0.0.1:0\"\n\
             control_plane_url: \"https://127.0.0.1:{server_port}\"\n\
             state_dir: {}\nclient_cert_file: {}\nclient_key_file: {}\nca_file: {}\n\
             credentials:\n  gh:\n    secret_file: {}\n    upstream_origins: [\"http://127.0.0.1:9\"]\n",
            state_dir.display(),
            cert.0.display(),
            cert.1.display(),
            pki.p("hostca.crt").display(),
            secret.display(),
        );
        let b = Bootstrap::from_yaml(&yaml, d).expect("bootstrap loads");
        let (stop, rx) = tokio::sync::oneshot::channel::<()>();
        let mut t = RunTuning {
            listener: Some(sock),
            ..RunTuning::default()
        };
        t.sync.poll = Duration::from_millis(150);
        t.sync.retry = Duration::from_millis(150);
        t.report.heartbeat = Duration::from_millis(200);
        t.report.retry = Duration::from_millis(150);
        t.report.max_backoff = Duration::from_millis(500);
        t.report.min_spacing = Duration::from_millis(50);
        let table = TableHandle::new();
        let task = tokio::spawn(async move {
            run_tuned(
                &b,
                table,
                async move {
                    let _ = rx.await;
                },
                t,
            )
            .await
        });
        Proxy {
            state_dir,
            stop,
            task,
        }
    }

    async fn shutdown(self) {
        let _ = self.stop.send(());
        tokio::time::timeout(Duration::from_secs(20), self.task)
            .await
            .expect("proxy stops within the grace")
            .expect("proxy task joins")
            .expect("proxy run returns Ok");
    }
}

async fn eventually<F: FnMut() -> bool>(what: &str, mut f: F) {
    let start = Instant::now();
    while start.elapsed() < WAIT {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for: {what}");
}

async fn mgmt(
    c: &reqwest::Client,
    port: u16,
    path: &str,
    bearer: &str,
    body: Option<Value>,
) -> u16 {
    let mut rb = c
        .post(format!("https://127.0.0.1:{port}{path}"))
        .bearer_auth(bearer);
    if let Some(b) = body {
        rb = rb.json(&b);
    }
    rb.send().await.unwrap().status().as_u16()
}

/// What a certificate gets from the config route: status and error code.
async fn config_fetch(pki: &Pki, port: u16, cert: &Cert) -> (u16, String) {
    let c = mtls_client_pooled(&pki.p("hostca.crt"), &cert.0, &cert.1);
    let r = c
        .get(format!("https://127.0.0.1:{port}/v1/proxy-config"))
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    let v: Value = r.json().await.unwrap_or(Value::Null);
    (
        status,
        v["error"]["code"].as_str().unwrap_or("").to_string(),
    )
}

fn local_state(dir: &Path) -> Option<ConfigState> {
    read_status(dir).map(|s| s.config_state)
}

#[tokio::test]
async fn rotating_the_client_certificate_promotes_fp_next_and_retire_ends_it() {
    let Some(pki) = pki("rot") else { return };
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mcert = mgmt_identity(&pki, T_ID, T_CFG);
    let tweak: Tweak = std::sync::Arc::new(|_| {});
    let srv = Server::start(&pki, 0, true, &tweak).await;
    let mc = mtls_client_pooled(&pki.p("hostca.crt"), &mcert.0, &mcert.1);
    let ext = client_ext(&proxy_san(PROXY_ID));
    let old = pki.leaf("proxyca", "proxy-old", PROXY_ID, &ext);
    let new = pki.leaf("proxyca", "proxy-new", PROXY_ID, &ext);
    let (fp_old, fp_new) = (fingerprint(&old.0), fingerprint(&new.0));
    assert_ne!(fp_old, fp_new);
    let ctx = srv.ctx.clone();
    let record = || ctx.registry.get(PROXY_ID).expect("proxy is registered");

    // Enroll with the old certificate; the proxy applies revision 1.
    let register = json!({"proxy_id": PROXY_ID, "display_name": "rot"});
    assert_eq!(
        mgmt(&mc, srv.port, "/v1/proxies", T_ID, Some(register)).await,
        201
    );
    let pin = |fp: &str| Some(json!({ "fingerprint": fp }));
    let fp_path = format!("/v1/proxies/{PROXY_ID}/fingerprints");
    assert_eq!(mgmt(&mc, srv.port, &fp_path, T_ID, pin(&fp_old)).await, 200);
    let put = Some(json!({"expected_revision": 0, "config": spec()}));
    let r = mc
        .put(format!(
            "https://127.0.0.1:{}/v1/proxies/{PROXY_ID}/config",
            srv.port
        ))
        .bearer_auth(T_CFG)
        .json(&put)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let px_old = Proxy::start(&pki, srv.port, &old, "state-old");
    eventually("the old certificate's proxy is seen and applied", || {
        ctx.store.last_seen(PROXY_ID).is_some()
            && local_state(&px_old.state_dir) == Some(ConfigState::Valid)
    })
    .await;
    let rec = record();
    assert_eq!(rec.state, ProxyState::Active);
    assert_eq!(rec.fp_current.as_deref(), Some(fp_old.as_str()));
    assert_eq!(rec.fp_next, None);

    // Pin the new fingerprint as fp_next: the old certificate stays current
    // and the new one has not been used, so nothing is promoted yet.
    assert_eq!(mgmt(&mc, srv.port, &fp_path, T_ID, pin(&fp_new)).await, 200);
    let rec = record();
    assert_eq!(rec.fp_current.as_deref(), Some(fp_old.as_str()));
    assert_eq!(rec.fp_next.as_deref(), Some(fp_new.as_str()));
    let seen = ctx.store.last_seen(PROXY_ID);
    eventually("the old certificate still reports", || {
        ctx.store.last_seen(PROXY_ID) != seen
    })
    .await;
    assert_eq!(record().fp_next.as_deref(), Some(fp_new.as_str()));
    px_old.shutdown().await;

    // A proxy restarted with the new certificate promotes it on first use.
    let px_new = Proxy::start(&pki, srv.port, &new, "state-new");
    eventually("fp_next is promoted to fp_current", || {
        record().fp_current.as_deref() == Some(fp_new.as_str())
    })
    .await;
    assert_eq!(record().fp_next, None);
    eventually(
        "the proxy with the new certificate applies its config",
        || local_state(&px_new.state_dir) == Some(ConfigState::Valid),
    )
    .await;
    let seen = ctx.store.last_seen(PROXY_ID);
    eventually("the new certificate reports", || {
        ctx.store.last_seen(PROXY_ID) != seen
    })
    .await;

    // The old certificate is now an unknown proxy; the new one is served.
    assert_eq!(
        config_fetch(&pki, srv.port, &old).await,
        (404, "proxy_unknown".into())
    );
    assert_eq!(config_fetch(&pki, srv.port, &new).await.0, 200);

    // The audit stream records the promotion.
    let r = mc
        .get(format!(
            "https://127.0.0.1:{}/v1/proxy-management-audit",
            srv.port
        ))
        .bearer_auth("read-bearer")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let audit: Value = r.json().await.unwrap();
    let promotions = audit["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| x["action"] == "proxy.fingerprint_promote")
        .count();
    assert_eq!(promotions, 1, "{audit}");

    // Retire: the new certificate is refused with the fixed code, the old one
    // is still unknown, and the proxy stops forwarding and reporting.
    let retire = format!("/v1/proxies/{PROXY_ID}/retire");
    assert_eq!(mgmt(&mc, srv.port, &retire, T_ID, None).await, 200);
    assert_eq!(record().state, ProxyState::Retired);
    assert_eq!(
        config_fetch(&pki, srv.port, &new).await,
        (403, "retired".into())
    );
    assert_eq!(
        config_fetch(&pki, srv.port, &old).await,
        (404, "proxy_unknown".into())
    );
    eventually("the retired proxy stops forwarding", || {
        local_state(&px_new.state_dir) == Some(ConfigState::Disabled)
    })
    .await;
    let frozen = ctx.store.last_seen(PROXY_ID);
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert_eq!(ctx.store.last_seen(PROXY_ID), frozen);
    // Retired is terminal: no certificate can be pinned again.
    assert_eq!(mgmt(&mc, srv.port, &fp_path, T_ID, pin(&fp_old)).await, 409);

    px_new.shutdown().await;
    srv.stop().await;
}
