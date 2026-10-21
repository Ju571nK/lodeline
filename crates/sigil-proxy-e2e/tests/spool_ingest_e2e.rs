#![cfg(unix)]
//! T-14b (#305, fixes #260): the durable event spool on the PRODUCTION path.
//!
//! The proxy is the real `lifecycle::run_tuned` (spool opened after the state_dir
//! lock, `run_ingest` started with the spool as its source, status reports with
//! the spool's real numbers and tail sequence), talking over loopback rustls mTLS
//! to the real `sigil-server` proxy routes. Events enter through the test-only
//! injector (`Spool::inject_test_event`, feature `test-util`), because the relay
//! (T-13) does not produce events yet. One test starts the REAL `sigil-proxy`
//! binary (built without `test-util`) on a state_dir whose spool was filled
//! beforehand.
//!
//! Requirements: PX-011, PX-013, PX-016; acceptance AC-06, AC-12.
//! Real-time polling with tuned short intervals; no paused clock.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use sigil_proxy::bootstrap::Bootstrap;
use sigil_proxy::config_sync::MtlsFetcher;
use sigil_proxy::ingest_client::{IngestParams, IngestTransport};
use sigil_proxy::lifecycle::{run_tuned, Lifecycle, RunTuning};
use sigil_proxy::limits::Limits;
use sigil_proxy::route::TableHandle;
use sigil_proxy::spool::{AppendError, Spool};
use sigil_proxy_api::status::SpoolState;
use sigil_proxy_api::verifier::verifier_for;
use sigil_server::app::{build_router_with_proxy, AppState};
use sigil_server::auth::ReadToken;
use sigil_server::config::{ProxyConfig, ServerConfig};
use sigil_server::fleet_index::FleetIndex;
use sigil_server::persist::HighWater;
use sigil_server::proxy::identity::proxy_san;
use sigil_server::proxy::ledger::GapKind;
use sigil_server::proxy::verifiers::{Scope, VerifierEntry};
use sigil_server::proxy::ProxyContext;
use sigil_server::tls_accept::PeerCertAcceptor;
use tokio::sync::oneshot;

const T_ID: &str = "tok-identity-ingest";
const T_CFG: &str = "tok-config-ingest";
const PROXY: &str = "px-ing";
const WAIT: Duration = Duration::from_secs(20);

// ---------------------------------------------------------------- openssl

fn find_openssl() -> Option<PathBuf> {
    [
        "/usr/bin/openssl",
        "/opt/homebrew/bin/openssl",
        "/opt/homebrew/opt/openssl@3/bin/openssl",
        "/usr/local/bin/openssl",
        "/usr/local/opt/openssl@3/bin/openssl",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.exists())
}

fn run_ossl(ossl: &Path, args: &[&std::ffi::OsStr]) {
    let o = Command::new(ossl)
        .env_remove("OPENSSL_CONF")
        .args(args)
        .output()
        .unwrap();
    assert!(
        o.status.success(),
        "openssl {args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
}

struct Pki {
    dir: tempfile::TempDir,
    ossl: PathBuf,
    serial: AtomicUsize,
}

impl Pki {
    fn p(&self, f: &str) -> PathBuf {
        self.dir.path().join(f)
    }

    fn ca(&self, name: &str, cn: &str, serial: &str) {
        let key = self.p(&format!("{name}.key"));
        run_ossl(
            &self.ossl,
            &[
                "req".as_ref(),
                "-x509".as_ref(),
                "-new".as_ref(),
                "-newkey".as_ref(),
                "rsa:2048".as_ref(),
                "-nodes".as_ref(),
                "-keyout".as_ref(),
                key.as_os_str(),
                "-days".as_ref(),
                "2".as_ref(),
                "-set_serial".as_ref(),
                serial.as_ref(),
                "-subj".as_ref(),
                format!("/CN={cn}").as_ref(),
                "-addext".as_ref(),
                "basicConstraints=critical,CA:TRUE".as_ref(),
                "-addext".as_ref(),
                "subjectKeyIdentifier=hash".as_ref(),
                "-out".as_ref(),
                self.p(&format!("{name}.crt")).as_os_str(),
            ],
        );
    }

    /// CA-signed RSA-2048 leaf, `-set_serial` (never `-CAcreateserial`).
    fn leaf(&self, ca: &str, name: &str, cn: &str, ext: &str) -> (PathBuf, PathBuf) {
        let (key, csr, crt, extf) = (
            self.p(&format!("{name}.key")),
            self.p(&format!("{name}.csr")),
            self.p(&format!("{name}.crt")),
            self.p(&format!("{name}.ext")),
        );
        std::fs::write(&extf, ext).unwrap();
        run_ossl(
            &self.ossl,
            &[
                "req".as_ref(),
                "-new".as_ref(),
                "-newkey".as_ref(),
                "rsa:2048".as_ref(),
                "-nodes".as_ref(),
                "-keyout".as_ref(),
                key.as_os_str(),
                "-subj".as_ref(),
                format!("/CN={cn}").as_ref(),
                "-out".as_ref(),
                csr.as_os_str(),
            ],
        );
        let serial = format!("{}", 100 + self.serial.fetch_add(1, Ordering::Relaxed));
        run_ossl(
            &self.ossl,
            &[
                "x509".as_ref(),
                "-req".as_ref(),
                "-in".as_ref(),
                csr.as_os_str(),
                "-CA".as_ref(),
                self.p(&format!("{ca}.crt")).as_os_str(),
                "-CAkey".as_ref(),
                self.p(&format!("{ca}.key")).as_os_str(),
                "-set_serial".as_ref(),
                serial.as_ref(),
                "-days".as_ref(),
                "2".as_ref(),
                "-extfile".as_ref(),
                extf.as_os_str(),
                "-out".as_ref(),
                crt.as_os_str(),
            ],
        );
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        (crt, key)
    }
}

/// `None` when openssl is missing and `CI` is unset (skip); panics under CI.
fn pki() -> Option<Pki> {
    let Some(ossl) = find_openssl() else {
        assert!(
            std::env::var_os("CI").is_none(),
            "openssl CLI not found but CI is set"
        );
        eprintln!("skipped: openssl CLI not found");
        return None;
    };
    let pki = Pki {
        dir: tempfile::tempdir().unwrap(),
        ossl,
        serial: AtomicUsize::new(0),
    };
    pki.ca("hostca", "ing-host-ca", "1");
    pki.ca("proxyca", "ing-proxy-ca", "2");
    let mut bundle = std::fs::read(pki.p("hostca.crt")).unwrap();
    bundle.extend(std::fs::read(pki.p("proxyca.crt")).unwrap());
    std::fs::write(pki.p("bundle.pem"), bundle).unwrap();
    pki.leaf(
        "hostca",
        "server",
        "localhost",
        "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n",
    );
    Some(pki)
}

fn fingerprint(crt: &Path) -> String {
    let pem = std::fs::read(crt).unwrap();
    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(&pem[..]))
        .collect::<Result<_, _>>()
        .unwrap();
    blake3::hash(certs[0].as_ref()).to_hex().to_string()
}

fn mtls_client(trust: &Path, crt: &Path, key: &Path) -> reqwest::Client {
    let mut id = std::fs::read(key).unwrap();
    id.extend_from_slice(&std::fs::read(crt).unwrap());
    reqwest::Client::builder()
        .use_rustls_tls()
        .pool_max_idle_per_host(0)
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(trust).unwrap()).unwrap(),
        )
        .identity(reqwest::Identity::from_pem(&id).unwrap())
        .build()
        .unwrap()
}

// ----------------------------------------------------------------- server

fn tls_config(pki: &Pki) -> rustls::ServerConfig {
    let rd = |f: &str| std::fs::read(pki.p(f)).unwrap();
    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(&rd("server.crt")[..]))
        .collect::<Result<_, _>>()
        .unwrap();
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(&rd("server.key")[..]))
        .unwrap()
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut std::io::BufReader::new(&rd("bundle.pem")[..])) {
        roots.add(c.unwrap()).unwrap();
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();
    rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .unwrap()
}

fn app_state(dir: &Path) -> Arc<AppState> {
    Arc::new(AppState {
        events_out_dir: dir.to_path_buf(),
        policy_bundle_path: dir.join("signed-policy.json"),
        rule_packs_bundle_path: None,
        artifacts_dir: None,
        high_water_path: dir.join(".high-water.json"),
        allowlist: parking_lot::RwLock::new(None),
        high_water: Mutex::new(HighWater::default()),
        fleet_index: FleetIndex::new(),
        read_token: ReadToken(Some("read-bearer".into())),
        active_window_days: 7,
        audit_key: None,
        audit_head: Mutex::new(None),
        allowlist_path: None,
        enroll: None,
        events_require_cert_host_match: false,
    })
}

type Tweak = Arc<dyn Fn(&mut ProxyConfig) + Send + Sync>;

struct Server {
    port: u16,
    ctx: Arc<ProxyContext>,
    handle: axum_server::Handle,
    task: tokio::task::JoinHandle<()>,
}

impl Server {
    /// `port == 0` picks one; a restart passes the old port. State files are the
    /// same on every start (they live in the PKI temp dir).
    async fn start(pki: &Pki, port: u16, first: bool, tweak: &Tweak) -> Server {
        Self::try_start(pki, port, first, tweak)
            .await
            .expect("server must bind")
    }

    /// `None` when the port could not be bound.
    async fn try_start(pki: &Pki, port: u16, first: bool, tweak: &Tweak) -> Option<Server> {
        let d = pki.dir.path();
        let p = |f: &str| d.join(f).display().to_string();
        let y = format!(
            "bind: \"127.0.0.1:0\"\ntls_cert_path: {}\ntls_key_path: {}\nclient_ca_path: {}\n\
             events_out_dir: {}\npolicy_bundle_path: {}\n\
             proxy:\n  ca_path: {}\n  registry_path: {}\n  registry_init: {first}\n  management_verifiers: {}\n",
            p("server.crt"),
            p("server.key"),
            p("bundle.pem"),
            d.display(),
            p("signed-policy.json"),
            p("proxyca.crt"),
            p("proxies.json"),
            p("verifiers.json"),
        );
        let mut cfg: ServerConfig = serde_yaml::from_str(&y).unwrap();
        tweak(cfg.proxy.as_mut().unwrap());
        let ctx = Arc::new(ProxyContext::load(&cfg).unwrap().unwrap());
        let tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls_config(pki)));
        let app = build_router_with_proxy(app_state(d), Some(ctx.clone()));
        let handle = axum_server::Handle::new();
        let h = handle.clone();
        let task = tokio::spawn(async move {
            let _ = axum_server::bind(format!("127.0.0.1:{port}").parse().unwrap())
                .handle(h)
                .acceptor(PeerCertAcceptor::new(tls))
                .serve(app.into_make_service())
                .await;
        });
        let port = handle.listening().await?.port();
        Some(Server {
            port,
            ctx,
            handle,
            task,
        })
    }

    /// Stop the server for sure: graceful shutdown with a short deadline, then
    /// abort the task and wait for the abort, so the listener is dropped. Returns
    /// the port; the caller checks that connections are refused.
    async fn stop(self) -> u16 {
        self.handle
            .graceful_shutdown(Some(Duration::from_millis(200)));
        let mut task = self.task;
        if tokio::time::timeout(Duration::from_secs(2), &mut task)
            .await
            .is_err()
        {
            task.abort();
            let _ = task.await;
        }
        self.port
    }
}

// ---------------------------------------------------------------- harness

fn verifier_entry(id: &str, token: &str, scope: Scope, fp: &str) -> VerifierEntry {
    VerifierEntry {
        key_id: id.into(),
        name: format!("{id}-name"),
        verifier: verifier_for(token),
        scope,
        caller_cert_fingerprint: fp.into(),
        not_after: None,
    }
}

fn spec() -> Value {
    json!({
        "schema_version": 1,
        "proxy_id": PROXY,
        "allowed_origins": ["https://app.example.com"],
        "routes": [{
            "route_id": "r1",
            "upstream_id": "up1",
            "upstream_url": "https://api.example.com/mcp",
            "upstream_protocol": "2025-11-25",
            "credential_ref": "gh",
        }],
        "principals": [{
            "principal_id": "claude",
            "verifiers": [{"key_id": "k1", "verifier": verifier_for("client-tok")}],
            "routes": ["r1"],
        }],
    })
}

struct H {
    pki: Pki,
    mgmt: reqwest::Client,
    proxy_cert: (PathBuf, PathBuf),
    srv: Option<Server>,
    last_port: u16,
    tweak: Tweak,
}

impl H {
    async fn new(tweak: impl Fn(&mut ProxyConfig) + Send + Sync + 'static) -> Option<H> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let pki = pki()?;
        let mgmt_cert = pki.leaf(
            "hostca",
            "mgmt",
            "mgmt-operator",
            "subjectAltName=DNS:mgmt-operator\nextendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n",
        );
        let fp = fingerprint(&mgmt_cert.0);
        let vpath = pki.p("verifiers.json");
        std::fs::write(
            &vpath,
            serde_json::to_vec(&json!({"entries": [
                verifier_entry("idk", T_ID, Scope::Identity, &fp),
                verifier_entry("cfgk", T_CFG, Scope::Config, &fp),
            ]}))
            .unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&vpath, std::fs::Permissions::from_mode(0o600)).unwrap();
        let proxy_cert = pki.leaf(
            "proxyca",
            "proxy",
            PROXY,
            &format!(
                "subjectAltName=DNS:{}\nextendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n",
                proxy_san(PROXY)
            ),
        );
        let tweak: Tweak = Arc::new(tweak);
        let srv = Server::start(&pki, 0, true, &tweak).await;
        let mgmt = mtls_client(&pki.p("hostca.crt"), &mgmt_cert.0, &mgmt_cert.1);
        let h = H {
            pki,
            mgmt,
            proxy_cert,
            last_port: srv.port,
            srv: Some(srv),
            tweak,
        };
        // Register, bind the certificate, store a config (gives the scope id).
        let (st, _) = h
            .mgmt_call(
                "POST",
                "/v1/proxies",
                T_ID,
                Some(json!({"proxy_id": PROXY, "display_name": "ing"})),
            )
            .await;
        assert_eq!(st, 201, "register");
        let (st, _) = h
            .mgmt_call(
                "POST",
                &format!("/v1/proxies/{PROXY}/fingerprints"),
                T_ID,
                Some(json!({"fingerprint": fingerprint(&h.proxy_cert.0)})),
            )
            .await;
        assert_eq!(st, 200, "fingerprint");
        let (st, body) = h
            .mgmt_call(
                "PUT",
                &format!("/v1/proxies/{PROXY}/config"),
                T_CFG,
                Some(json!({"expected_revision": 0, "config": spec()})),
            )
            .await;
        assert_eq!(st, 200, "config put: {body}");
        Some(h)
    }

    fn srv(&self) -> &Server {
        self.srv.as_ref().expect("server is up")
    }

    fn ctx(&self) -> Arc<ProxyContext> {
        self.srv().ctx.clone()
    }

    async fn mgmt_call(
        &self,
        method: &str,
        path: &str,
        bearer: &str,
        body: Option<Value>,
    ) -> (u16, Value) {
        let url = format!("https://127.0.0.1:{}{path}", self.srv().port);
        let mut rb = self
            .mgmt
            .request(reqwest::Method::from_bytes(method.as_bytes()).unwrap(), url)
            .bearer_auth(bearer);
        if let Some(b) = body {
            rb = rb.json(&b);
        }
        let r = rb.send().await.unwrap();
        let st = r.status().as_u16();
        let bytes = r.bytes().await.unwrap();
        (st, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    /// Stop the server (connections are refused afterwards).
    async fn server_down(&mut self) {
        let port = self.srv.take().expect("server is up").stop().await;
        // The outage phase starts only when the port really refuses connections.
        let start = Instant::now();
        loop {
            if tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_err()
            {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "server still accepts connections after stop"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Start the server again on the same port and the same files.
    async fn server_up(&mut self) {
        let tweak = self.tweak.clone();
        self.server_up_with(tweak).await;
    }

    /// As `server_up`, with other server settings (for example a raised cap).
    ///
    /// The bind is retried a few times: `axum_server::bind` uses
    /// `std::net::TcpListener::bind`, which sets SO_REUSEADDR on Unix, so the
    /// port is reusable at once despite TIME_WAIT connections. The retry only
    /// covers the short window in which the old socket is still being released.
    async fn server_up_with(&mut self, tweak: Tweak) {
        for _ in 0..20 {
            if let Some(s) = Server::try_start(&self.pki, self.last_port, false, &tweak).await {
                self.srv = Some(s);
                self.tweak = tweak;
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("server could not rebind port {}", self.last_port);
    }

    /// Gap records the server holds from status reports, as JSON.
    fn server_gaps(&self) -> Vec<Value> {
        self.ctx()
            .store
            .entry(PROXY)
            .map(|e| {
                e.gaps
                    .iter()
                    .map(|g| serde_json::to_value(g).unwrap())
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Bootstrap of the proxy under test: state_dir inside the PKI temp dir, so a
/// restart (a second `run_tuned` or the binary) finds the same state.
fn bootstrap_for(pki: &Pki, server_port: u16, cert: &(PathBuf, PathBuf)) -> Bootstrap {
    Bootstrap::from_yaml(&bootstrap_yaml(pki, server_port, cert), pki.dir.path())
        .expect("bootstrap loads")
}

fn bootstrap_yaml(pki: &Pki, server_port: u16, cert: &(PathBuf, PathBuf)) -> String {
    let d = pki.dir.path();
    let secret = d.join("upstream-secret");
    std::fs::write(&secret, "UPSTREAM-SECRET-VALUE\n").unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    format!(
        "proxy_id: {PROXY}\nlisten: \"127.0.0.1:0\"\n\
         control_plane_url: \"https://127.0.0.1:{server_port}\"\n\
         state_dir: {}\nclient_cert_file: {}\nclient_key_file: {}\nca_file: {}\n\
         credentials:\n  gh:\n    secret_file: {}\n    upstream_origins: [\"https://api.example.com\"]\n",
        d.join("proxy-state").display(),
        cert.0.display(),
        cert.1.display(),
        pki.p("hostca.crt").display(),
        secret.display(),
    )
}

async fn eventually<F: FnMut() -> bool>(what: &str, mut f: F) {
    let start = Instant::now();
    while start.elapsed() < WAIT {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for: {what}");
}

// ------------------------------------------------------------ server views

const UP: &str = "up1";

impl H {
    /// Events the server ledger holds for the proxy.
    fn rows(&self) -> i64 {
        self.ctx().ledger.usage(PROXY).unwrap().event_rows
    }

    /// Latest applied status snapshot the server holds.
    fn status(&self) -> Option<sigil_proxy_api::ProxyStatus> {
        self.ctx().store.entry(PROXY).and_then(|e| e.status)
    }

    fn spool_state(&self) -> Option<SpoolState> {
        self.status().map(|s| s.spool.state)
    }

    fn tail_gaps(&self) -> Vec<sigil_server::proxy::ledger::GapRecord> {
        self.ctx()
            .ledger
            .gaps(PROXY)
            .unwrap()
            .into_iter()
            .filter(|g| g.kind == GapKind::SequenceGap && g.tail)
            .collect()
    }

    fn bootstrap(&self) -> Bootstrap {
        bootstrap_for(&self.pki, self.last_port, &self.proxy_cert)
    }
}

/// Kinds of the gaps the proxy still holds locally (`gap_queue.json`).
fn local_gap_kinds(state_dir: &Path) -> Vec<String> {
    let Ok(bytes) = std::fs::read(state_dir.join("gap_queue.json")) else {
        return Vec::new();
    };
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    v["pending"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|g| g["kind"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

// ------------------------------------------------------------ proxy runner

fn tuning(listener: std::net::TcpListener, spool_out: oneshot::Sender<Spool>) -> RunTuning {
    let mut t = RunTuning {
        listener: Some(listener),
        spool_out: Some(spool_out),
        ..RunTuning::default()
    };
    t.sync.poll = Duration::from_millis(150);
    t.sync.retry = Duration::from_millis(150);
    t.report.heartbeat = Duration::from_millis(200);
    t.report.retry = Duration::from_millis(150);
    t.report.max_backoff = Duration::from_millis(500);
    t.report.min_spacing = Duration::from_millis(50);
    t.ingest = IngestParams {
        poll: Duration::from_millis(30),
        retry: Duration::from_millis(100),
        max_backoff: Duration::from_millis(400),
        min_spacing: Duration::from_millis(10),
    };
    t
}

/// The proxy through `lifecycle::run_tuned`, which is the production
/// `run_inner`: nothing about the spool or the ingest loop is wired here.
struct Running {
    spool: Spool,
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
    state_dir: PathBuf,
}

async fn start_proxy(h: &H) -> Running {
    let b = h.bootstrap();
    let sock = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let (spool_tx, spool_rx) = oneshot::channel();
    let (stop, rx) = oneshot::channel::<()>();
    let tune = tuning(sock, spool_tx);
    let state_dir = b.state_dir.clone();
    let mut task = tokio::spawn(async move {
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
    let spool = tokio::select! {
        s = spool_rx => s.expect("the lifecycle opened the spool"),
        r = &mut task => panic!("the proxy stopped before opening its spool: {r:?}"),
    };
    Running {
        spool,
        stop,
        task,
        state_dir,
    }
}

impl Running {
    /// Stop gracefully and release the spool, so the next start can open it.
    async fn stop(self) {
        let _ = self.stop.send(());
        let r = tokio::time::timeout(Duration::from_secs(20), self.task)
            .await
            .expect("proxy stops within the grace")
            .expect("proxy task joins");
        r.expect("proxy run returns Ok");
        drop(self.spool);
    }

    /// The proxy applied the first config (it reports `valid`).
    fn config_applied(&self) -> bool {
        sigil_proxy::lifecycle::read_status(&self.state_dir)
            .is_some_and(|s| s.config_state == sigil_proxy_api::status::ConfigState::Valid)
    }
}

async fn inject(spool: &Spool, n: usize) {
    for _ in 0..n {
        spool.inject_test_event(UP).await.expect("admitted");
    }
}

// ------------------------------------------------------------------- tests

/// PX-011/013: the production lifecycle opens the spool and drains it to the
/// server; the status report carries the spool's real numbers and tail
/// sequence, not the placeholders (T-12c1 lesson: prove it is started).
#[tokio::test]
async fn lifecycle_drains_the_spool_and_reports_real_spool_numbers() {
    let Some(h) = H::new(|_| {}).await else {
        return;
    };
    let px = start_proxy(&h).await;
    assert_eq!(
        px.spool.snapshot().capacity_bytes,
        Limits::default().spool_max_bytes
    );
    inject(&px.spool, 5).await;
    eventually("5 events on the server", || h.rows() == 5).await;
    eventually("spool drained", || {
        let s = px.spool.snapshot();
        s.unsent_events == 0 && s.retained_acked_events == 5
    })
    .await;
    assert!(
        h.ctx().ledger.gaps(PROXY).unwrap().is_empty(),
        "no gap while everything is delivered"
    );
    eventually("status shows the real spool", || {
        h.status().is_some_and(|s| {
            s.spool.capacity_bytes.get() == Limits::default().spool_max_bytes as i64
                && s.last_assigned_sequence.get() == 5
                && s.spool.unsent_events.get() == 0
                && s.spool.state == SpoolState::Ok
        })
    })
    .await;
    px.stop().await;
}

/// AC-06: a central outage. Events appended during it stay in the spool, an
/// outage gap is opened and persisted; after recovery everything arrives once
/// and the gap closes on the server.
#[tokio::test]
async fn central_outage_then_recovery_loses_nothing() {
    let Some(mut h) = H::new(|_| {}).await else {
        return;
    };
    let px = start_proxy(&h).await;
    inject(&px.spool, 2).await;
    eventually("first two delivered", || h.rows() == 2).await;

    h.server_down().await;
    inject(&px.spool, 3).await;
    eventually("outage gap opened locally", || {
        local_gap_kinds(&px.state_dir).contains(&"central_outage".to_string())
    })
    .await;
    let snap = px.spool.snapshot();
    assert_eq!(snap.unsent_events, 3, "kept in the spool during the outage");
    assert_eq!(snap.state, SpoolState::Ok);

    h.server_up().await;
    eventually("all five delivered", || h.rows() == 5).await;
    eventually("spool drained", || px.spool.snapshot().unsent_events == 0).await;
    eventually("closed outage gap reaches the server", || {
        h.server_gaps()
            .iter()
            .any(|g| g["kind"] == "central_outage" && g["ended_at"].is_string())
    })
    .await;
    assert!(
        h.ctx()
            .ledger
            .gaps(PROXY)
            .unwrap()
            .iter()
            .all(|g| g.kind != GapKind::SequenceGap || g.tail),
        "no sequence gap inside the stored range"
    );
    px.stop().await;
}

/// AC-06 dedupe: events the server already stored (an acknowledgement lost
/// before the spool recorded it) are sent again after a restart, answered as
/// duplicates and acknowledged, without a second row.
#[tokio::test]
async fn events_the_server_already_has_are_deduplicated_after_restart() {
    let Some(h) = H::new(|_| {}).await else {
        return;
    };
    // Unsent events in the spool, never delivered by the proxy.
    let px = start_proxy(&h).await;
    px.spool.set_delivery_paused_for_test(true);
    inject(&px.spool, 4).await;
    px.stop().await;

    // The "lost acknowledgement": the server stores the events, the spool never
    // learns of it.
    let b = h.bootstrap();
    {
        let lc = Lifecycle::start(&b).unwrap();
        let spool = lc.open_spool(&Limits::default()).unwrap();
        let mut src = spool.clone();
        let events =
            sigil_proxy::ingest_client::EventSource::next_events(&mut src, 10, &Default::default());
        assert_eq!(events.len(), 4);
        let fetcher = MtlsFetcher::from_bootstrap(&b)
            .expect("fetcher builds")
            .with_timeout(Duration::from_secs(5));
        let reply = fetcher
            .post_events(serde_json::to_vec(&json!({ "events": events })).unwrap())
            .await
            .expect("the server answers");
        assert_eq!(
            reply.status,
            200,
            "{}",
            String::from_utf8_lossy(&reply.body)
        );
        let v: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(v["accepted_event_ids"].as_array().unwrap().len(), 4);
        assert_eq!(spool.snapshot().unsent_events, 4, "still unsent locally");
    }
    assert_eq!(h.rows(), 4);

    // Restart: the proxy resends all four, the server says duplicate.
    let px = start_proxy(&h).await;
    eventually("duplicates acknowledged", || {
        px.spool.snapshot().unsent_events == 0
    })
    .await;
    assert_eq!(h.rows(), 4, "no second row for a resent event");
    inject(&px.spool, 1).await;
    eventually("a new event follows", || h.rows() == 5).await;
    assert!(h
        .ctx()
        .ledger
        .gaps(PROXY)
        .unwrap()
        .iter()
        .all(|g| g.kind != GapKind::SequenceGap || g.tail));
    px.stop().await;
}

/// Restart during an outage: the spool, the sequence and the open outage gap
/// survive; after recovery everything arrives in order and the gap closes.
#[tokio::test]
async fn proxy_restart_during_an_outage_recovers_from_the_spool() {
    let Some(mut h) = H::new(|_| {}).await else {
        return;
    };
    let px = start_proxy(&h).await;
    h.server_down().await;
    inject(&px.spool, 3).await;
    eventually("outage gap persisted", || {
        local_gap_kinds(&px.state_dir).contains(&"central_outage".to_string())
    })
    .await;
    px.stop().await;

    let px = start_proxy(&h).await;
    let snap = px.spool.snapshot();
    assert_eq!((snap.unsent_events, snap.last_assigned_sequence), (3, 3));
    assert_eq!(
        px.spool.inject_test_event(UP).await.unwrap().sequence,
        4,
        "the sequence continues after the restart"
    );

    h.server_up().await;
    eventually("all four delivered", || h.rows() == 4).await;
    eventually("spool drained", || px.spool.snapshot().unsent_events == 0).await;
    eventually("outage gap closed on the server", || {
        h.server_gaps()
            .iter()
            .any(|g| g["kind"] == "central_outage" && g["ended_at"].is_string())
    })
    .await;
    assert!(h
        .ctx()
        .ledger
        .gaps(PROXY)
        .unwrap()
        .iter()
        .all(|g| g.kind != GapKind::SequenceGap || g.tail));
    px.stop().await;
}

/// #260 payoff (F13/AC-06): events assigned in the spool but never received show
/// up on the server as a tail `sequence_gap` from the real status report, and
/// close when the events arrive.
#[tokio::test]
async fn tail_sequence_gap_appears_via_the_status_report_and_closes() {
    let Some(h) = H::new(|_| {}).await else {
        return;
    };
    let px = start_proxy(&h).await;
    px.spool.set_delivery_paused_for_test(true);
    inject(&px.spool, 4).await;
    eventually("tail gap 1..=4 on the server", || {
        h.tail_gaps()
            .iter()
            .any(|g| g.open && g.from_sequence == Some(1) && g.to_sequence == Some(4))
    })
    .await;
    // The manager-visible context: the events are in the spool, unsent.
    assert!(h
        .status()
        .is_some_and(|s| s.spool.unsent_events.get() == 4 && s.last_assigned_sequence.get() == 4));
    assert_eq!(h.rows(), 0);

    px.spool.set_delivery_paused_for_test(false);
    eventually("events arrive", || h.rows() == 4).await;
    eventually("tail gap closed", || {
        let g = h.tail_gaps();
        !g.is_empty() && g.iter().all(|g| !g.open)
    })
    .await;
    px.stop().await;
}

/// AC-12: a full spool blocks admission with a typed refusal (no silent drop,
/// no sequence consumed); the status says `full`; admission reopens as the
/// ingest client drains.
#[tokio::test]
async fn full_spool_blocks_admission_and_reopens_after_draining() {
    let Some(h) = H::new(|_| {}).await else {
        return;
    };
    let px = start_proxy(&h).await;
    px.spool.set_delivery_paused_for_test(true);
    inject(&px.spool, 1).await;
    let one = px.spool.snapshot().unsent_bytes;
    px.spool.set_capacity_for_test(one * 3 + 5, 5);
    inject(&px.spool, 2).await;

    for _ in 0..3 {
        assert_eq!(
            px.spool.inject_test_event(UP).await.unwrap_err(),
            AppendError::Full
        );
    }
    let snap = px.spool.snapshot();
    assert_eq!(snap.state, SpoolState::Full);
    assert_eq!(snap.unsent_events, 3);
    assert_eq!(snap.last_assigned_sequence, 3, "refusals take no sequence");

    eventually("server sees a full spool", || {
        h.spool_state() == Some(SpoolState::Full)
            && h.status()
                .is_some_and(|s| s.last_assigned_sequence.get() == 3)
    })
    .await;
    assert_eq!(h.rows(), 0);

    px.spool.set_delivery_paused_for_test(false);
    eventually("drained", || h.rows() == 3).await;
    eventually("server sees the spool ok again", || {
        h.spool_state() == Some(SpoolState::Ok)
    })
    .await;
    inject(&px.spool, 1).await;
    eventually("admitted again and delivered", || h.rows() == 4).await;
    px.stop().await;
}

/// Events older than R expire into quarantine with a `spool_expired` gap; the
/// gap goes through the pump, the gap queue and the status report to the server.
#[tokio::test]
async fn expired_events_reach_the_server_as_a_spool_expired_gap() {
    let Some(h) = H::new(|_| {}).await else {
        return;
    };
    let px = start_proxy(&h).await;
    eventually("config applied", || px.config_applied()).await;
    px.spool.set_delivery_paused_for_test(true);
    inject(&px.spool, 2).await;
    // The spool's own clock moves forward; nothing waits in real time.
    px.spool.advance_clock_for_test(7200);
    px.spool
        .set_max_offline_retry_age(Duration::from_secs(3600));
    let rep = px.spool.expire_now().unwrap();
    assert_eq!((rep.expired_events, rep.gaps_recorded), (2, 1));
    let snap = px.spool.snapshot();
    assert_eq!((snap.unsent_events, snap.quarantined_events), (0, 2));
    eventually("spool_expired gap on the server", || {
        h.server_gaps()
            .iter()
            .any(|g| g["kind"] == "spool_expired" && g["count"] == 2)
    })
    .await;
    eventually("spool gap handed off", || {
        px.spool.snapshot().pending_gaps == 0
    })
    .await;
    px.stop().await;
}

// ------------------------------------------------------- the real binary

/// Build (a no-op when current) and locate the real `sigil-proxy` binary, built
/// WITHOUT the `test-util` feature: the release code path. `None` (with a note on
/// stderr) when it cannot be located or built, so that one test skips.
fn proxy_binary() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let profile_dir = exe.parent()?.parent()?.to_path_buf();
    let profile = profile_dir.file_name()?.to_owned();
    // CARGO_TARGET_DIR wins; otherwise the layout `<target>/<profile>/deps/<exe>`.
    let target_dir = match std::env::var_os("CARGO_TARGET_DIR") {
        Some(d) => PathBuf::from(d),
        None => profile_dir.parent()?.to_path_buf(),
    };
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut c = Command::new(cargo);
    c.args(["build", "-p", "sigil-proxy", "--bin", "sigil-proxy"])
        .arg("--target-dir")
        .arg(&target_dir)
        .current_dir(env!("CARGO_MANIFEST_DIR"));
    if profile == "release" {
        c.arg("--release");
    }
    match c.status() {
        Ok(st) if st.success() => {}
        other => {
            eprintln!("skipped: building the sigil-proxy binary failed ({other:?})");
            return None;
        }
    }
    let bin = target_dir.join(&profile).join("sigil-proxy");
    if !bin.exists() {
        eprintln!("skipped: no sigil-proxy binary at {}", bin.display());
        return None;
    }
    Some(bin)
}

/// Kills the child if the test fails before it stopped it.
struct Child(std::process::Child);

impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A REAL `sigil-proxy` process, with no injector in it, drains a spool that
/// was filled beforehand to the server, and stops cleanly on SIGTERM.
#[tokio::test]
async fn real_sigil_proxy_process_drains_the_spool_to_the_server() {
    let Some(h) = H::new(|_| {}).await else {
        return;
    };
    let b = h.bootstrap();
    // Fill the spool the way a previous run would have left it.
    {
        let lc = Lifecycle::start(&b).unwrap();
        let spool = lc.open_spool(&Limits::default()).unwrap();
        for _ in 0..3 {
            spool.inject_test_event_blocking(UP).unwrap();
        }
    }
    assert_eq!(h.rows(), 0);
    let cfg_path = h.pki.p("proxy.yaml");
    std::fs::write(
        &cfg_path,
        bootstrap_yaml(&h.pki, h.last_port, &h.proxy_cert),
    )
    .unwrap();
    let Some(bin) = proxy_binary() else {
        return;
    };
    let log = std::fs::File::create(h.pki.p("proxy.log")).unwrap();
    let mut child = Child(
        Command::new(bin)
            .args(["run", "--config"])
            .arg(&cfg_path)
            .stdout(std::process::Stdio::null())
            .stderr(log)
            .spawn()
            .expect("spawns the real proxy"),
    );
    eventually("the real process delivered all three", || {
        if let Ok(Some(st)) = child.0.try_wait() {
            panic!("the proxy exited early: {st}");
        }
        h.rows() == 3
    })
    .await;
    // Its status report (real spool numbers) reaches the server too.
    eventually("status with the real spool", || {
        h.status().is_some_and(|s| {
            s.last_assigned_sequence.get() == 3
                && s.spool.capacity_bytes.get() == Limits::default().spool_max_bytes as i64
        })
    })
    .await;
    let kill = Command::new("kill")
        .args(["-TERM", &child.0.id().to_string()])
        .status()
        .unwrap();
    assert!(kill.success());
    let start = Instant::now();
    let st = loop {
        if let Some(st) = child.0.try_wait().unwrap() {
            break st;
        }
        assert!(start.elapsed() < Duration::from_secs(30), "no clean stop");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert!(st.success(), "clean exit, got {st}");
}
