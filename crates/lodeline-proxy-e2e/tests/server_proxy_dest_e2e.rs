#![cfg(unix)]
//! Destination protection (PX-014, AC-08) through the real `lodeline-server`
//! control plane and the real `lodeline-proxy`, over mTLS on loopback.
//!
//! The control plane validates literals on config PUT. The proxy checks
//! literals and resolved addresses before connecting to an upstream.

use std::net::Ipv4Addr;
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
use tokio::net::TcpListener;

mod common;
use common::{client_ext, fingerprint, mgmt_identity, mtls_client_pooled, pki, Pki, Tweak};

const T_ID: &str = "tok-identity-dest";
const T_CFG: &str = "tok-config-dest";
const PROXY_ID: &str = "px-dest";
const TOKEN: &str = "client-token-dest";
const WAIT: Duration = Duration::from_secs(40);

/// A TCP listener on loopback that only counts the connections it accepts.
struct Destination {
    port: u16,
    accepted: Arc<AtomicUsize>,
}

async fn destination() -> Destination {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let seen = accepted.clone();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = l.accept().await {
            seen.fetch_add(1, Ordering::SeqCst);
            held.push(s);
        }
    });
    Destination { port, accepted }
}

/// The server with the proxy registered; config goes in through the
/// management API.
struct Control {
    srv: common::Server,
    mgmt: reqwest::Client,
    proxy_cert: (PathBuf, PathBuf),
}

impl Control {
    async fn start(pki: &Pki) -> Control {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mgmt_cert = mgmt_identity(pki, T_ID, T_CFG);
        let tweak: Tweak = Arc::new(|_| {});
        let srv = common::Server::start(pki, 0, true, &tweak).await;
        let mgmt = mtls_client_pooled(&pki.p("hostca.crt"), &mgmt_cert.0, &mgmt_cert.1);
        let proxy_cert = pki.leaf(
            "proxyca",
            "proxy",
            PROXY_ID,
            &client_ext(&proxy_san(PROXY_ID)),
        );
        let c = Control {
            srv,
            mgmt,
            proxy_cert,
        };
        let st = c
            .send(
                reqwest::Method::POST,
                "/v1/proxies".into(),
                T_ID,
                serde_json::json!({"proxy_id": PROXY_ID, "display_name": "dest"}),
            )
            .await;
        assert_eq!(st, 201, "register");
        let st = c
            .send(
                reqwest::Method::POST,
                format!("/v1/proxies/{PROXY_ID}/fingerprints"),
                T_ID,
                serde_json::json!({"fingerprint": fingerprint(&c.proxy_cert.0)}),
            )
            .await;
        assert_eq!(st, 200, "fingerprint");
        c
    }

    async fn send(
        &self,
        method: reqwest::Method,
        path: String,
        bearer: &str,
        body: serde_json::Value,
    ) -> u16 {
        self.mgmt
            .request(method, format!("https://127.0.0.1:{}{path}", self.srv.port))
            .bearer_auth(bearer)
            .json(&body)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    }

    /// PUT revision 1 with one route `r{i}` per upstream URL and setting.
    async fn put_config(&self, upstreams: &[(&str, Option<bool>)]) -> u16 {
        let routes: Vec<_> = upstreams
            .iter()
            .enumerate()
            .map(|(i, (url, allow_private))| {
                let mut route = serde_json::json!({
                    "route_id": format!("r{i}"),
                    "upstream_id": format!("up{i}"),
                    "upstream_url": url,
                    "upstream_protocol": "2025-11-25",
                    "credential_ref": "gh",
                    "limits": {"max_request_bytes": 65536},
                });
                if let Some(allow_private) = allow_private {
                    route["allow_private_destination"] = serde_json::json!(allow_private);
                }
                route
            })
            .collect();
        let route_ids: Vec<_> = (0..routes.len()).map(|i| format!("r{i}")).collect();
        let config = serde_json::json!({
            "schema_version": 1,
            "proxy_id": PROXY_ID,
            "allowed_origins": ["https://app.example.com"],
            "routes": routes,
            "principals": [{
                "principal_id": "alice",
                "verifiers": [{"key_id": "k-alice", "verifier": verifier_for(TOKEN)}],
                "routes": route_ids,
            }],
        });
        self.send(
            reqwest::Method::PUT,
            format!("/v1/proxies/{PROXY_ID}/config"),
            T_CFG,
            serde_json::json!({"expected_revision": 0, "config": config}),
        )
        .await
    }
}

struct Stack {
    _control: Control,
    listen: u16,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
    client: reqwest::Client,
}

impl Stack {
    /// Applies a config with one route `r{i}` per upstream URL, on one
    /// credential, and waits until the proxy forwards.
    async fn start(pki: &Pki, upstreams: &[(&str, Option<bool>)]) -> Stack {
        let d = pki.dir.path();
        let control = Control::start(pki).await;
        assert_eq!(control.put_config(upstreams).await, 200, "config put");
        let state_dir = d.join("proxy-state");
        let secret = d.join("upstream-secret");
        std::fs::write(&secret, "UPSTREAM-SECRET-VALUE\n").unwrap();
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
        let sock = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let listen = sock.local_addr().unwrap().port();
        let origins: Vec<_> = upstreams
            .iter()
            .map(|(url, _)| {
                let rest = &url["https://".len()..];
                format!("\"https://{}\"", rest.split('/').next().unwrap())
            })
            .collect();
        let yaml = format!(
            "proxy_id: {PROXY_ID}\nlisten: \"127.0.0.1:0\"\n\
             control_plane_url: \"https://127.0.0.1:{}\"\n\
             state_dir: {}\nclient_cert_file: {}\nclient_key_file: {}\nca_file: {}\n\
             credentials:\n  gh:\n    secret_file: {}\n    upstream_origins: [{}]\n",
            control.srv.port,
            state_dir.display(),
            control.proxy_cert.0.display(),
            control.proxy_cert.1.display(),
            pki.p("hostca.crt").display(),
            secret.display(),
            origins.join(", "),
        );
        let b = Bootstrap::from_yaml(&yaml, d).expect("bootstrap loads");
        let (stop, rx) = tokio::sync::oneshot::channel::<()>();
        let mut tune = RunTuning {
            listener: Some(sock),
            ..RunTuning::default()
        };
        tune.sync.poll = Duration::from_millis(150);
        tune.sync.retry = Duration::from_millis(150);
        tune.report.heartbeat = Duration::from_millis(200);
        tune.report.retry = Duration::from_millis(150);
        tune.report.max_backoff = Duration::from_millis(500);
        tune.report.min_spacing = Duration::from_millis(50);
        let task = tokio::spawn(async move {
            run_tuned(
                &b,
                TableHandle::new(),
                async move {
                    let _ = rx.await;
                },
                tune,
            )
            .await
        });
        let start = Instant::now();
        while !read_status(&state_dir)
            .is_some_and(|s| s.config_state == ConfigState::Valid && s.forwarding)
        {
            assert!(start.elapsed() < WAIT, "proxy applied the config");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Stack {
            _control: control,
            listen,
            stop,
            task,
            client: reqwest::Client::builder()
                .pool_max_idle_per_host(0)
                .build()
                .unwrap(),
        }
    }

    /// POST an `initialize` to route `r{i}` and return the status and body.
    async fn initialize(&self, i: usize) -> (u16, String) {
        let r = self
            .client
            .post(format!("http://127.0.0.1:{}/mcp/r{i}", self.listen))
            .bearer_auth(TOKEN)
            .json(&serde_json::json!({"jsonrpc":"2.0","id":"initialize","method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}))
            .send()
            .await
            .unwrap();
        (r.status().as_u16(), r.text().await.unwrap())
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

const REFUSED: &str = "{\"error\":\"destination_refused\"}";

/// An https route whose upstream is a loopback listener is refused: a fixed 502
/// that names no address class, and the listener never sees a connection.
#[tokio::test]
async fn https_upstream_on_loopback_is_refused_before_any_connection() {
    let Some(pki) = pki("dst") else { return };
    let dest = destination().await;
    let url = format!("https://127.0.0.1:{}/mcp", dest.port);
    let stack = Stack::start(&pki, &[(&url, None)]).await;

    let (status, body) = stack.initialize(0).await;
    assert_eq!(status, 502);
    assert_eq!(body, REFUSED);
    assert_eq!(dest.accepted.load(Ordering::SeqCst), 0, "no connection");
    stack.shutdown().await;
}

/// A name that resolves to loopback is refused as the literal is: the check
/// runs on the resolved address, so `localhost` cannot reach the listener.
#[tokio::test]
async fn https_upstream_name_resolving_to_loopback_is_refused() {
    let Some(pki) = pki("dst") else { return };
    let dest = destination().await;
    let url = format!("https://localhost:{}/mcp", dest.port);
    let stack = Stack::start(&pki, &[(&url, Some(true))]).await;

    let (status, body) = stack.initialize(0).await;
    assert_eq!(status, 502);
    assert_eq!(body, REFUSED);
    assert_eq!(dest.accepted.load(Ordering::SeqCst), 0, "no connection");
    stack.shutdown().await;
}

/// The control plane refuses private, link-local and fd00::/8 literals when
/// the setting is omitted.
#[tokio::test]
async fn server_refuses_a_config_with_a_private_or_metadata_upstream_literal() {
    let Some(pki) = pki("dst") else { return };
    let control = Control::start(&pki).await;
    let v4 = |a, b, c, d| Ipv4Addr::new(a, b, c, d);
    for url in [
        format!("https://{}:8443/mcp", v4(10, 0, 0, 5)),
        format!("https://{}:8443/mcp", v4(192, 168, 1, 1)),
        format!("https://{}/latest/meta-data", v4(169, 254, 169, 254)),
        "https://[fd00:ec2::254]:8443/mcp".to_string(),
    ] {
        assert_eq!(control.put_config(&[(&url, None)]).await, 422, "{url}");
    }
    let public = format!("https://{}:8443/mcp", v4(203, 0, 114, 1));
    assert_eq!(
        control.put_config(&[(&public, None)]).await,
        200,
        "a public literal is accepted"
    );
}

#[tokio::test]
async fn proxy_applies_private_destination_opt_in_from_config_put() {
    let Some(pki) = pki("dst") else { return };
    let stack = Stack::start(&pki, &[("https://[fc00::1]:1/mcp", Some(true))]).await;
    let (status, body) = stack.initialize(0).await;
    stack.shutdown().await;

    assert!(
        matches!(
            (status, body.as_str()),
            (502, "{\"error\":\"upstream_unavailable\"}")
                | (504, "{\"error\":\"upstream_timeout\"}")
        ),
        "expected a connection error after the route applied, got {status} {body}"
    );
}
