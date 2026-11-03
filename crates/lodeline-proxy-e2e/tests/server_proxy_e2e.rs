#![cfg(unix)]
//! #267: the real `lodeline-server` proxy control plane and the real `lodeline-proxy`
//! running together on loopback, over real rustls mTLS (openssl-minted PKI).
//!
//! Both sides run in-process through their library APIs: the server through
//! `build_router_with_proxy` behind `axum_server` + `PeerCertAcceptor`, the
//! proxy through `lifecycle::run_tuned` (test-only pacing knob). The stub
//! upstream is a tiny plain-HTTP loopback listener. Real-time polling with
//! generous timeouts; no paused clock.
//!
//! Flow (issue #267): register + config + fingerprint -> proxy starts and
//! applies -> 200 / 401 -> status report visible on the server -> new revision
//! picked up -> disable (401, report refused) -> enable (forwarding resumes).

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use lodeline_proxy::bootstrap::Bootstrap;
use lodeline_proxy::lifecycle::{read_status, run_tuned, RunTuning};
use lodeline_proxy::route::TableHandle;
use lodeline_proxy_api::status::ConfigState;
use lodeline_proxy_api::verifier::verifier_for;
use lodeline_server::proxy::identity::proxy_san;
use lodeline_server::proxy::ProxyContext;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

mod common;
use common::{client_ext, fingerprint, mgmt_identity, mtls_client_pooled, pki, Pki, Tweak};

const T_ID: &str = "tok-identity-e2e";
const T_CFG: &str = "tok-config-e2e";
const PROXY_ID: &str = "px-e2e";
const TOK_A: &str = "client-token-a";
const TOK_B: &str = "client-token-b";
const WAIT: Duration = Duration::from_secs(40);

// ----------------------------------------------------------------- server

struct Server {
    port: u16,
    ctx: Arc<ProxyContext>,
    handle: axum_server::Handle,
    mgmt: reqwest::Client,
}

impl Server {
    async fn start(pki: &Pki) -> Server {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mgmt_cert = mgmt_identity(pki, T_ID, T_CFG);
        let tweak: Tweak = Arc::new(|_| {});
        let srv = common::Server::start(pki, 0, true, &tweak).await;
        let mgmt = mtls_client_pooled(&pki.p("hostca.crt"), &mgmt_cert.0, &mgmt_cert.1);
        Server {
            port: srv.port,
            ctx: srv.ctx,
            handle: srv.handle,
            mgmt,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}{path}", self.port)
    }

    /// Management call: returns (status, parsed JSON body or null).
    async fn mgmt(
        &self,
        method: &str,
        path: &str,
        bearer: &str,
        body: Option<serde_json::Value>,
    ) -> (u16, serde_json::Value) {
        let mut rb = self.mgmt.request(
            reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
            self.url(path),
        );
        rb = rb.bearer_auth(bearer);
        if let Some(b) = body {
            rb = rb.json(&b);
        }
        let r = rb.send().await.unwrap();
        let status = r.status().as_u16();
        let bytes = r.bytes().await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }
}

// --------------------------------------------------------------- upstream

/// Plain-HTTP loopback upstream: answers every request with 200 and counts them.
struct Upstream {
    port: u16,
    hits: Arc<AtomicUsize>,
}

async fn upstream() -> Upstream {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let h2 = hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            let h3 = h2.clone();
            tokio::spawn(async move {
                // Read one request (head + Content-Length body), answer, close.
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                loop {
                    let n = s.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..i]).to_ascii_lowercase();
                        let want = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if buf.len() >= i + 4 + want {
                            break;
                        }
                    }
                }
                h3.fetch_add(1, Ordering::SeqCst);
                let start = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                let v: serde_json::Value = serde_json::from_slice(&buf[start..]).unwrap();
                let result = if v["method"] == "initialize" {
                    serde_json::json!({"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}})
                } else {
                    serde_json::json!({})
                };
                let body = serde_json::to_vec(
                    &serde_json::json!({"jsonrpc":"2.0","id":v["id"],"result":result}),
                )
                .unwrap();
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(head.as_bytes()).await;
                let _ = s.write_all(&body).await;
                let _ = s.shutdown().await;
            });
        }
    });
    Upstream { port, hits }
}

// ------------------------------------------------------------------ proxy

fn spec(up_port: u16, tokens: &[(&str, &str)], limit_bytes: i64) -> serde_json::Value {
    let principals: Vec<_> = tokens
        .iter()
        .map(|(pid, tok)| {
            serde_json::json!({
                "principal_id": pid,
                "verifiers": [{"key_id": format!("k-{pid}"), "verifier": verifier_for(tok)}],
                "routes": ["r1"],
            })
        })
        .collect();
    serde_json::json!({
        "schema_version": 1,
        "proxy_id": PROXY_ID,
        "allowed_origins": ["https://app.example.com"],
        "routes": [{
            "route_id": "r1",
            "upstream_id": "up1",
            "upstream_url": format!("http://127.0.0.1:{up_port}/mcp"),
            "upstream_protocol": "2025-11-25",
            "credential_ref": "gh",
            "limits": {"max_request_bytes": limit_bytes},
        }],
        "principals": principals,
    })
}

struct RunningProxy {
    listen: u16,
    state_dir: PathBuf,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
    client: reqwest::Client,
}

impl RunningProxy {
    /// POST /mcp/r1 with a bearer; returns the status.
    async fn call(&self, bearer: &str) -> u16 {
        let url = format!("http://127.0.0.1:{}/mcp/r1", self.listen);
        let init = self.client.post(&url).bearer_auth(bearer)
            .json(&serde_json::json!({"jsonrpc":"2.0","id":"initialize","method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}))
            .send().await;
        let Ok(init) = init else { return 0 };
        let Some(sid) = init.headers().get("mcp-session-id").cloned() else {
            return init.status().as_u16();
        };
        self.client
            .post(&url)
            .header("mcp-session-id", sid)
            .header("mcp-protocol-version", "2025-11-25")
            .bearer_auth(bearer)
            .header("content-type", "application/json")
            .body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#)
            .send()
            .await
            .map(|r| r.status().as_u16())
            .unwrap_or(0)
    }

    async fn shutdown(self) {
        let _ = self.stop.send(());
        let r = tokio::time::timeout(Duration::from_secs(20), self.task)
            .await
            .expect("proxy stops within the grace")
            .expect("proxy task joins");
        r.expect("proxy run returns Ok");
    }
}

/// Fast pacing so the whole flow takes seconds (test-only knob).
fn tuning(listener: std::net::TcpListener) -> RunTuning {
    let mut t = RunTuning {
        listener: Some(listener),
        ..RunTuning::default()
    };
    t.sync.poll = Duration::from_millis(150);
    t.sync.retry = Duration::from_millis(150);
    t.report.heartbeat = Duration::from_millis(200);
    t.report.retry = Duration::from_millis(150);
    t.report.max_backoff = Duration::from_millis(500);
    t.report.min_spacing = Duration::from_millis(50);
    t
}

fn start_proxy(
    pki: &Pki,
    server_port: u16,
    up_port: u16,
    proxy_cert: &(PathBuf, PathBuf),
) -> RunningProxy {
    let d = pki.dir.path();
    let state_dir = d.join("proxy-state");
    let secret = d.join("upstream-secret");
    std::fs::write(&secret, "UPSTREAM-SECRET-VALUE\n").unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    // Bound here and handed to the proxy (test-util `RunTuning::listener`), so
    // there is no bind-then-release port race. The bootstrap `listen` is unused.
    let sock = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listen = sock.local_addr().unwrap().port();
    let yaml = format!(
        "proxy_id: {PROXY_ID}\nlisten: \"127.0.0.1:0\"\n\
         control_plane_url: \"https://127.0.0.1:{server_port}\"\n\
         state_dir: {}\nclient_cert_file: {}\nclient_key_file: {}\nca_file: {}\n\
         credentials:\n  gh:\n    secret_file: {}\n    upstream_origins: [\"http://127.0.0.1:{up_port}\"]\n",
        state_dir.display(),
        proxy_cert.0.display(),
        proxy_cert.1.display(),
        pki.p("hostca.crt").display(),
        secret.display(),
    );
    let b = Bootstrap::from_yaml(&yaml, d).expect("bootstrap loads");
    let (stop, rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        run_tuned(
            &b,
            TableHandle::new(),
            async move {
                let _ = rx.await;
            },
            tuning(sock),
        )
        .await
    });
    RunningProxy {
        listen,
        state_dir,
        stop,
        task,
        client: reqwest::Client::new(),
    }
}

async fn eventually<F, Fut>(what: &str, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = Instant::now();
    while start.elapsed() < WAIT {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for: {what}");
}

// ------------------------------------------------------------------- test

#[tokio::test]
async fn server_and_proxy_walk_the_whole_lifecycle() {
    let Some(pki) = pki("e2e") else { return };
    let srv = Server::start(&pki).await;
    let up = upstream().await;

    // 1. Register, fingerprint, config.
    let proxy_cert = pki.leaf(
        "proxyca",
        "proxy",
        PROXY_ID,
        &client_ext(&proxy_san(PROXY_ID)),
    );
    let (st, _) = srv
        .mgmt(
            "POST",
            "/v1/proxies",
            T_ID,
            Some(serde_json::json!({"proxy_id": PROXY_ID, "display_name": "e2e"})),
        )
        .await;
    assert_eq!(st, 201, "register");
    let (st, _) = srv
        .mgmt(
            "POST",
            &format!("/v1/proxies/{PROXY_ID}/fingerprints"),
            T_ID,
            Some(serde_json::json!({"fingerprint": fingerprint(&proxy_cert.0)})),
        )
        .await;
    assert_eq!(st, 200, "fingerprint");
    let cfg_path = format!("/v1/proxies/{PROXY_ID}/config");
    let put = |expected: u64, s: serde_json::Value| serde_json::json!({"expected_revision": expected, "config": s});
    let (st, body) = srv
        .mgmt(
            "PUT",
            &cfg_path,
            T_CFG,
            Some(put(0, spec(up.port, &[("alice", TOK_A)], 65536))),
        )
        .await;
    assert_eq!(st, 200, "config put: {body}");
    assert_eq!(body["revision"], 1);
    let hash1 = body["config_hash"].as_str().unwrap().to_string();

    // 2. Proxy starts from a bootstrap that points at the server.
    let px = start_proxy(&pki, srv.port, up.port, &proxy_cert);

    // 3. Right bearer reaches the upstream (200); wrong bearer is 401.
    eventually("first config applied and forwarding", || async {
        px.call(TOK_A).await == 200
    })
    .await;
    assert!(up.hits.load(Ordering::SeqCst) >= 1);
    let before = up.hits.load(Ordering::SeqCst);
    assert_eq!(px.call("wrong-token").await, 401);
    assert_eq!(
        up.hits.load(Ordering::SeqCst),
        before,
        "a 401 never reaches the upstream"
    );
    assert_eq!(px.call(TOK_B).await, 401, "token B is not configured yet");
    // The per-route limit from the server config is enforced (65536 bytes).
    let big = px
        .client
        .post(format!("http://127.0.0.1:{}/mcp/r1", px.listen))
        .bearer_auth(TOK_A)
        .header("content-type", "application/json")
        .body(vec![b' '; 70_000])
        .send()
        .await
        .unwrap();
    assert_eq!(big.status().as_u16(), 413, "request over the route limit");

    // 4. The status report reaches the server: applied revision + config hash.
    let ctx = srv.ctx.clone();
    let h1 = hash1.clone();
    eventually("server sees applied revision 1 and its hash", || async {
        ctx.store
            .entry(PROXY_ID)
            .and_then(|e| e.status)
            .is_some_and(|s| {
                s.config.state == ConfigState::Valid
                    && s.config.applied_revision.map(|r| r.get()) == Some(1)
                    && s.config
                        .config_hash
                        .as_ref()
                        .map(|h| h.as_str().to_string())
                        == Some(h1.clone())
            })
    })
    .await;
    assert!(ctx.store.last_seen(PROXY_ID).is_some());

    // 5. A new revision (adds token B) is picked up.
    let (st, body) = srv
        .mgmt(
            "PUT",
            &cfg_path,
            T_CFG,
            Some(put(
                1,
                spec(up.port, &[("alice", TOK_A), ("bob", TOK_B)], 65536),
            )),
        )
        .await;
    assert_eq!(st, 200, "second config put: {body}");
    assert_eq!(body["revision"], 2);
    let hash2 = body["config_hash"].as_str().unwrap().to_string();
    assert_ne!(hash1, hash2);
    eventually("token B accepted after revision 2", || async {
        px.call(TOK_B).await == 200
    })
    .await;
    let (ctx, h2) = (srv.ctx.clone(), hash2.clone());
    eventually("server sees applied revision 2 and its hash", || async {
        ctx.store
            .entry(PROXY_ID)
            .and_then(|e| e.status)
            .is_some_and(|s| {
                s.config.applied_revision.map(|r| r.get()) == Some(2)
                    && s.config
                        .config_hash
                        .as_ref()
                        .map(|h| h.as_str().to_string())
                        == Some(h2.clone())
            })
    })
    .await;

    // Scope rule (control-plane.md section 1.3 / H3): disable is safe-direction and
    // needs the `config` scope; enable restores trust and needs `identity`.
    // 6. Disable: forwarding stops on the next fetch; the report is refused.
    let (st, _) = srv
        .mgmt(
            "POST",
            &format!("/v1/proxies/{PROXY_ID}/disable"),
            T_CFG,
            None,
        )
        .await;
    assert_eq!(st, 200, "disable");
    eventually("401 after disable", || async {
        px.call(TOK_A).await == 401
    })
    .await;
    assert_eq!(px.call(TOK_B).await, 401);
    let sd = px.state_dir.clone();
    eventually("proxy publishes config_state disabled", || async {
        read_status(&sd).is_some_and(|s| s.config_state == ConfigState::Disabled && !s.forwarding)
    })
    .await;
    // What this proves: (a) once its view is `disabled` the proxy sends no report
    // by design, so `last_seen` stays frozen across several heartbeats (the proxy
    // goes silent); (b) the server refuses a status POST that carries the proxy
    // certificate (403 `disabled`). It does NOT exercise the proxy's own Rejected
    // path: a proxy-sent report can only be refused in the race window between the
    // server-side disable and the proxy's next fetch, which cannot be made
    // deterministic here. The status_report unit test covers Rejected.
    let local = read_status(&px.state_dir).expect("local status file");
    assert_eq!(local.config_state, ConfigState::Disabled);
    assert!(!local.forwarding);
    assert_eq!(
        local.last_update_error, None,
        "a disabled answer is not an update error"
    );
    tokio::time::sleep(Duration::from_millis(600)).await;
    let frozen = srv.ctx.store.last_seen(PROXY_ID);
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert_eq!(
        srv.ctx.store.last_seen(PROXY_ID),
        frozen,
        "the proxy sends no report while disabled"
    );
    let direct = mtls_client_pooled(&pki.p("hostca.crt"), &proxy_cert.0, &proxy_cert.1)
        .post(srv.url("/v1/proxy-status"))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(direct.status().as_u16(), 403);
    let eb: serde_json::Value = direct.json().await.unwrap();
    assert_eq!(eb["error"]["code"], "disabled");
    let hits_disabled = up.hits.load(Ordering::SeqCst);

    // 7. Re-enable: forwarding resumes and reports flow again.
    let (st, _) = srv
        .mgmt(
            "POST",
            &format!("/v1/proxies/{PROXY_ID}/enable"),
            T_ID,
            None,
        )
        .await;
    assert_eq!(st, 200, "enable");
    eventually("200 again after enable", || async {
        px.call(TOK_A).await == 200
    })
    .await;
    assert!(up.hits.load(Ordering::SeqCst) > hits_disabled);
    let (ctx, before_seen) = (srv.ctx.clone(), frozen.clone());
    eventually("reports accepted again", || async {
        ctx.store.last_seen(PROXY_ID) != before_seen
    })
    .await;

    // The server exposes no per-proxy read DTO (no GET /v1/proxies/{id}); its only
    // read route for this plane is the management audit stream. Check it records
    // the lifecycle the test drove, through the HTTP route a manager would use.
    let r = srv
        .mgmt
        .get(srv.url("/v1/proxy-management-audit"))
        .bearer_auth("read-bearer")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let audit: serde_json::Value = r.json().await.unwrap();
    let actions: Vec<&str> = audit["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|x| x["action"].as_str())
        .collect();
    for want in [
        "proxy.register",
        "proxy.config_put",
        "proxy.disable",
        "proxy.enable",
    ] {
        assert!(actions.contains(&want), "audit lacks {want}: {actions:?}");
    }

    px.shutdown().await;
    srv.handle.graceful_shutdown(Some(Duration::from_secs(1)));
}
