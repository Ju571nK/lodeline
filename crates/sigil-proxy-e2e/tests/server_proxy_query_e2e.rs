#![cfg(unix)]
//! #293 (T-11 S5): ingest -> ledger -> projection -> query, end to end over
//! real loopback rustls mTLS.
//!
//! Two proxies deliver events through the production `IngestClient` /
//! `run_ingest` and `MtlsFetcher` transport (events come from a fixture
//! `EventSource`; relay event production is T-13/T-14). Status reports go
//! through the real `POST /v1/proxy-status` route over the same transport; the
//! body is built here because the production reporter has no spool or
//! `last_assigned_sequence` source yet (it sends a fixed 0). Read calls use the
//! read bearer plus a host-class client certificate.
//!
//! The PKI and server helpers are copied from `server_proxy_ingest_e2e.rs`;
//! sharing them is tracked in #284.
//!
//! Requirements: PX-006, PX-010, PX-011, PX-012, PX-016; acceptance AC-05,
//! AC-06, AC-12. Real-time polling with tuned short intervals; no paused clock.
//! The 90 s `STALE_AFTER_SECS` is a constant without a test knob, so the
//! `connected -> disconnected` step ages the stored `last_seen` through the
//! public store API instead of sleeping; the exact boundary stays with the unit
//! test `connection_state_boundary`.

use std::collections::{BTreeMap, HashSet};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use sigil_proxy::bootstrap::Bootstrap;
use sigil_proxy::config_sync::MtlsFetcher;
use sigil_proxy::ingest_client::{run_ingest, EventSource, IngestClient, IngestParams};
use sigil_proxy::status_report::{CentralHealth, GapQueue, StatusTransport};
use sigil_proxy_api::status::QuarantineCode;
use sigil_proxy_api::verifier::verifier_for;
use sigil_proxy_api::ProxyEvent;
use sigil_server::app::{build_router_with_proxy, AppState};
use sigil_server::auth::ReadToken;
use sigil_server::config::{ProxyConfig, ServerConfig};
use sigil_server::fleet_index::FleetIndex;
use sigil_server::persist::HighWater;
use sigil_server::proxy::identity::proxy_san;
use sigil_server::proxy::query::TestScope;
use sigil_server::proxy::verifiers::{Scope, VerifierEntry};
use sigil_server::proxy::ProxyContext;
use sigil_server::tls_accept::PeerCertAcceptor;
use tokio::sync::oneshot;

const T_ID: &str = "tok-identity-query";
const T_CFG: &str = "tok-config-query";
const READ_BEARER: &str = "read-bearer";
const PA: &str = "px-a";
const PB: &str = "px-b";
const WAIT: Duration = Duration::from_secs(20);
/// Lowercase so it also fits the `Id` patterns of the config and registry.
const CANARY: &str = "canaryzx9q7w3";
const CANARY_ARGS: &str = "canaryargs4k8m2";

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

// ----------------------------------------------------------------- server

type Tweak = Arc<dyn Fn(&mut ProxyConfig) + Send + Sync>;
/// Server-side read-scope switch (the `TestScope` hook of the query module): a
/// request extension set by a layer around the real router, never client input.
type ScopeSwitch = Arc<Mutex<Option<Vec<String>>>>;

async fn inject_scope(
    axum::extract::State(s): axum::extract::State<ScopeSwitch>,
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let ids = s.lock().unwrap().clone();
    if let Some(ids) = ids {
        req.extensions_mut().insert(TestScope(ids));
    }
    next.run(req).await
}

struct Server {
    port: u16,
    ctx: Arc<ProxyContext>,
    handle: axum_server::Handle,
    task: tokio::task::JoinHandle<()>,
}

impl Server {
    /// `None` when the port could not be bound. `port == 0` picks one; a
    /// restart passes the old port. State files live in the PKI temp dir, so
    /// they are the same on every start.
    async fn try_start(
        pki: &Pki,
        port: u16,
        first: bool,
        tweak: &Tweak,
        scope: &ScopeSwitch,
    ) -> Option<Server> {
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
        let app = build_router_with_proxy(app_state(d), Some(ctx.clone())).layer(
            axum::middleware::from_fn_with_state(scope.clone(), inject_scope),
        );
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

    /// Stop for sure: graceful shutdown with a short deadline, then abort the
    /// task and wait for the abort, so the listener is dropped.
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

fn spec(proxy_id: &str, cred_ref: &str, url: &str) -> Value {
    json!({
        "schema_version": 1,
        "proxy_id": proxy_id,
        "allowed_origins": ["https://app.example.com"],
        "routes": [{
            "route_id": "r1",
            "upstream_id": "up1",
            "upstream_url": url,
            "upstream_protocol": "2025-11-25",
            "credential_ref": cred_ref,
        }],
        "principals": [{
            "principal_id": "claude",
            "verifiers": [{"key_id": "k1", "verifier": verifier_for("client-tok")}],
            "routes": ["r1"],
        }],
    })
}

fn fetcher_for(pki: &Pki, server_port: u16, id: &str, cert: &(PathBuf, PathBuf)) -> MtlsFetcher {
    let d = pki.dir.path();
    let secret = d.join("upstream-secret");
    std::fs::write(&secret, "UPSTREAM-SECRET-VALUE\n").unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    let yaml = format!(
        "proxy_id: {id}\nlisten: \"127.0.0.1:0\"\n\
         control_plane_url: \"https://127.0.0.1:{server_port}\"\n\
         state_dir: {}\nclient_cert_file: {}\nclient_key_file: {}\nca_file: {}\n\
         credentials:\n  gh:\n    secret_file: {}\n    upstream_origins: [\"https://api.example.com\"]\n",
        d.join(format!("proxy-state-{id}")).display(),
        cert.0.display(),
        cert.1.display(),
        pki.p("hostca.crt").display(),
        secret.display(),
    );
    let b = Bootstrap::from_yaml(&yaml, d).expect("bootstrap loads");
    MtlsFetcher::from_bootstrap(&b)
        .expect("fetcher builds")
        .with_timeout(Duration::from_secs(5))
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

// ------------------------------------------------------------------ events

fn uid(n: u32) -> String {
    format!("00000000-0000-4000-8000-{n:012}")
}

fn mref(n: u32) -> String {
    format!("00000000-0000-8000-8000-{n:012}")
}

fn epoch(n: u32) -> String {
    uid(9000 + n)
}

/// Invocation id of invocation `n`.
fn inv(n: u32) -> String {
    uid(1000 + n)
}

fn at(s: u32) -> String {
    format!("2026-10-10T00:{:02}:{:02}Z", s / 60, s % 60)
}

fn envelope(proxy: &str, n: u32, ep: u32, seq: u32, at_s: u32, ty: &str, payload: Value) -> Value {
    json!({
        "schema_version": 1,
        "event_id": uid(n),
        "proxy_id": proxy,
        "epoch_id": epoch(ep),
        "sequence": seq,
        "occurred_at": at(at_s),
        "event_type": ty,
        "payload": payload,
    })
}

fn started_payload(i: u32) -> Value {
    json!({
        "invocation_id": inv(i),
        "upstream_id": "up1",
        "route_revision": 1,
        "protocol_version": "unknown",
        "method": "ping",
        "actor": {
            "actor_id": "actor-1",
            "actor_kind": "non_human",
            "authentication_method": "bearer",
            "evidence_source": "proxy_credential_mapping"
        }
    })
}

fn to_event(v: Value) -> ProxyEvent {
    serde_json::from_value(v).expect("valid event")
}

/// `invocation.started` (a `ping`): event id `n`, invocation `i`.
fn started(proxy: &str, n: u32, i: u32, seq: u32, at_s: u32) -> ProxyEvent {
    to_event(envelope(
        proxy,
        n,
        1,
        seq,
        at_s,
        "invocation.started",
        started_payload(i),
    ))
}

/// `invocation.started` of a `tools/call` naming metadata ref `r`.
fn started_tool(proxy: &str, n: u32, i: u32, seq: u32, at_s: u32, r: &str) -> ProxyEvent {
    let mut p = started_payload(i);
    p["protocol_version"] = "2025-11-25".into();
    p["method"] = "tools/call".into();
    p["tool"] = json!({"status": "identified", "metadata_ref": r});
    to_event(envelope(proxy, n, 1, seq, at_s, "invocation.started", p))
}

fn completed(
    proxy: &str,
    n: u32,
    i: u32,
    seq: u32,
    at_s: u32,
    outcome: &str,
    delivery: &str,
) -> ProxyEvent {
    to_event(envelope(
        proxy,
        n,
        1,
        seq,
        at_s,
        "invocation.completed",
        json!({
            "invocation_id": inv(i),
            "outcome": outcome,
            "delivery_state": delivery,
            "duration_ms": 12,
            "response_bytes": 345,
        }),
    ))
}

/// Event ids of proxy B live above A's, so one number never names two events.
const fn eb(n: u32) -> u32 {
    500 + n
}

/// The projection dataset of one proxy: invocation `base+1` completed,
/// `base+2` start-only, `base+3` completion-only, `base+4` integrity conflict
/// (two different completions). Sequences 1..=7, event ids `off+1..=off+7`.
fn dataset(proxy: &str, off: u32, base: u32) -> Vec<ProxyEvent> {
    vec![
        started(proxy, off + 1, base + 1, 1, 1),
        completed(proxy, off + 2, base + 1, 2, 2, "success", "sent"),
        started(proxy, off + 3, base + 2, 3, 3),
        completed(proxy, off + 4, base + 3, 4, 4, "timeout", "unknown"),
        started(proxy, off + 5, base + 4, 5, 5),
        completed(proxy, off + 6, base + 4, 6, 6, "success", "sent"),
        completed(proxy, off + 7, base + 4, 7, 7, "tool_error", "sent"),
    ]
}

// ----------------------------------------------------------------- fixture

#[derive(Default)]
struct FxInner {
    unsent: Vec<ProxyEvent>,
    acked: Vec<String>,
    quarantined: Vec<(String, QuarantineCode)>,
}

/// Fixture `EventSource`: hands out the oldest unsent events.
#[derive(Clone, Default)]
struct Fixture(Arc<Mutex<FxInner>>);

impl Fixture {
    fn push(&self, evs: impl IntoIterator<Item = ProxyEvent>) {
        self.0.lock().unwrap().unsent.extend(evs);
    }
    fn acked_count(&self) -> usize {
        self.0.lock().unwrap().acked.len()
    }
    fn quarantined(&self) -> usize {
        self.0.lock().unwrap().quarantined.len()
    }
}

impl EventSource for Fixture {
    fn next_events(&mut self, max: usize, skip: &HashSet<String>) -> Vec<ProxyEvent> {
        let g = self.0.lock().unwrap();
        g.unsent
            .iter()
            .filter(|e| !skip.contains(e.event_id.as_str()))
            .take(max)
            .cloned()
            .collect()
    }
    fn acknowledged(&mut self, ids: &[String]) {
        let mut g = self.0.lock().unwrap();
        g.unsent
            .retain(|e| !ids.iter().any(|i| i == e.event_id.as_str()));
        g.acked.extend(ids.iter().cloned());
    }
    fn quarantined(&mut self, ids: &[String], code: QuarantineCode) {
        let mut g = self.0.lock().unwrap();
        g.unsent
            .retain(|e| !ids.iter().any(|i| i == e.event_id.as_str()));
        g.quarantined.extend(ids.iter().map(|i| (i.clone(), code)));
    }
}

fn fast_params() -> IngestParams {
    IngestParams {
        poll: Duration::from_millis(30),
        retry: Duration::from_millis(100),
        max_backoff: Duration::from_millis(400),
        min_spacing: Duration::from_millis(10),
    }
}

/// One proxy: its production transport (certificate-bound), event source and
/// ingest state.
struct Proxy {
    id: &'static str,
    fetcher: Arc<MtlsFetcher>,
    cert: (PathBuf, PathBuf),
    fx: Fixture,
    gaps: GapQueue,
    central: CentralHealth,
}

impl Proxy {
    /// Deliver `evs` through the real `IngestClient` and wait until every one
    /// is acknowledged (the server answered 200 for them).
    async fn send(&self, evs: Vec<ProxyEvent>) {
        let target = self.fx.acked_count() + evs.len();
        let (stop, rx) = oneshot::channel::<()>();
        let (f, fx) = (self.fetcher.clone(), self.fx.clone());
        let client = IngestClient::new(self.gaps.clone(), self.central.clone(), fast_params());
        let task = tokio::spawn(async move {
            run_ingest(&*f, fx, client, async move {
                let _ = rx.await;
            })
            .await;
        });
        self.fx.push(evs);
        eventually("events acknowledged", || {
            self.fx.acked_count() >= target || self.fx.quarantined() > 0
        })
        .await;
        let _ = stop.send(());
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("ingest stops promptly")
            .expect("joins");
        assert_eq!(self.fx.quarantined(), 0, "no event may be quarantined");
        assert_eq!(self.fx.acked_count(), target);
    }

    /// `POST /v1/proxy-status` through the real transport; returns the status.
    async fn status(&self, ep: u32, seq: i64, last_assigned: i64, gaps: Vec<Value>) -> u16 {
        let body = json!({
            "schema_version": 1,
            "report_id": uid(7000 + u32::try_from(seq).unwrap()),
            "proxy_id": self.id,
            "epoch_id": epoch(ep),
            "status_sequence": seq,
            "sent_at": "2026-10-11T00:00:00Z",
            "config": {
                "state": "none",
                "applied_revision": null,
                "observed_desired_revision": null,
                "expires_at": null
            },
            "spool": {
                "state": "ok", "depth_events": 3, "unsent_events": 2, "bytes": 100,
                "capacity_bytes": 1000, "oldest_unsent_age_seconds": null,
                "quarantined_events": 0
            },
            "registry": {"pending_entries": 0, "sync_stalled": false},
            "central": {"last_ingest_ack_at": null, "consecutive_failures": 0},
            "routes": [{"upstream_id": "up1", "state": "supported"}],
            "counters": {"auth_failures": [], "unmatched_cancels": []},
            "gaps": gaps,
            "last_assigned_sequence": last_assigned,
        });
        let r = self
            .fetcher
            .post_status(serde_json::to_vec(&body).unwrap())
            .await
            .expect("status answered");
        assert_eq!(
            r.status,
            200,
            "status report: {}",
            String::from_utf8_lossy(&r.body)
        );
        r.status
    }
}

// ----------------------------------------------------------------- harness

struct Resp {
    status: u16,
    body: Vec<u8>,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
    fn code(&self) -> String {
        self.json()["error"]["code"]
            .as_str()
            .unwrap_or("")
            .to_string()
    }
}

struct H {
    pki: Pki,
    mgmt: reqwest::Client,
    /// Host-class client (not a proxy, not a management certificate).
    reader: reqwest::Client,
    a: Proxy,
    b: Proxy,
    srv: Option<Server>,
    last_port: u16,
    tweak: Tweak,
    scope: ScopeSwitch,
    /// Every body a read call returned, for the canary sweep.
    seen: Mutex<Vec<Vec<u8>>>,
}

impl H {
    /// `canary`: put the canary into the config fields the query never shows.
    async fn new(canary: bool) -> Option<H> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let pki = pki()?;
        let client_ext = |san: &str| {
            format!("subjectAltName=DNS:{san}\nextendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n")
        };
        let mgmt_cert = pki.leaf(
            "hostca",
            "mgmt",
            "mgmt-operator",
            &client_ext("mgmt-operator"),
        );
        let reader_cert = pki.leaf("hostca", "reader", "reader", &client_ext("reader-client"));
        let cert_a = pki.leaf("proxyca", "proxy-a", PA, &client_ext(&proxy_san(PA)));
        let cert_b = pki.leaf("proxyca", "proxy-b", PB, &client_ext(&proxy_san(PB)));
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

        let tweak: Tweak = Arc::new(|_| {});
        let scope: ScopeSwitch = Arc::default();
        let srv = Server::try_start(&pki, 0, true, &tweak, &scope)
            .await
            .expect("server must bind");
        let mk = |id: &'static str, cert: (PathBuf, PathBuf)| Proxy {
            id,
            fetcher: Arc::new(fetcher_for(&pki, srv.port, id, &cert)),
            cert,
            fx: Fixture::default(),
            gaps: GapQueue::new(),
            central: CentralHealth::new(),
        };
        let (a, b) = (mk(PA, cert_a), mk(PB, cert_b));
        let mgmt = mtls_client(&pki.p("hostca.crt"), &mgmt_cert.0, &mgmt_cert.1);
        let reader = mtls_client(&pki.p("hostca.crt"), &reader_cert.0, &reader_cert.1);
        let h = H {
            pki,
            mgmt,
            reader,
            a,
            b,
            last_port: srv.port,
            srv: Some(srv),
            tweak,
            scope,
            seen: Mutex::default(),
        };
        for p in [&h.a, &h.b] {
            let (st, _) = h
                .mgmt_call(
                    "POST",
                    "/v1/proxies",
                    T_ID,
                    Some(json!({"proxy_id": p.id, "display_name": format!("{}-name", p.id)})),
                )
                .await;
            assert_eq!(st, 201, "register {}", p.id);
            let (st, _) = h
                .mgmt_call(
                    "POST",
                    &format!("/v1/proxies/{}/fingerprints", p.id),
                    T_ID,
                    Some(json!({"fingerprint": fingerprint(&p.cert.0)})),
                )
                .await;
            assert_eq!(st, 200, "fingerprint {}", p.id);
            let (cred, url) = if canary && p.id == PA {
                (
                    format!("gh-{CANARY}"),
                    format!("https://api.example.com/mcp/{CANARY}"),
                )
            } else {
                ("gh".to_string(), "https://api.example.com/mcp".to_string())
            };
            let (st, body) = h
                .mgmt_call(
                    "PUT",
                    &format!("/v1/proxies/{}/config", p.id),
                    T_CFG,
                    Some(json!({"expected_revision": 0, "config": spec(p.id, &cred, &url)})),
                )
                .await;
            assert_eq!(st, 200, "config put {}: {body}", p.id);
        }
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

    /// GET with `client`; every body is recorded for the canary sweep.
    async fn try_fetch(
        &self,
        client: &reqwest::Client,
        path: &str,
        bearer: Option<&str>,
    ) -> Result<Resp, reqwest::Error> {
        let mut rb = client.get(format!("https://127.0.0.1:{}{path}", self.srv().port));
        if let Some(b) = bearer {
            rb = rb.bearer_auth(b);
        }
        let r = rb.send().await?;
        let status = r.status().as_u16();
        let body = r.bytes().await?.to_vec();
        self.seen.lock().unwrap().push(body.clone());
        Ok(Resp { status, body })
    }

    /// A read call as the operator tool makes it: host certificate + bearer.
    async fn rd(&self, path: &str) -> Resp {
        self.try_fetch(&self.reader, path, Some(READ_BEARER))
            .await
            .unwrap_or_else(|e| panic!("GET {path}: {e}"))
    }

    /// As [`H::rd`], expecting 200, returning the JSON body.
    async fn ok(&self, path: &str) -> Value {
        let r = self.rd(path).await;
        assert_eq!(
            r.status,
            200,
            "GET {path}: {}",
            String::from_utf8_lossy(&r.body)
        );
        r.json()
    }

    /// Stop the server (connections are refused afterwards).
    async fn server_down(&mut self) {
        let port = self.srv.take().expect("server is up").stop().await;
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

    /// Start the server again on the same port and the same state files. The
    /// bind is retried: the old socket may still be being released.
    async fn server_up(&mut self) {
        for _ in 0..20 {
            if let Some(s) =
                Server::try_start(&self.pki, self.last_port, false, &self.tweak, &self.scope).await
            {
                self.srv = Some(s);
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("server could not rebind port {}", self.last_port);
    }

    fn scope_id(&self) -> String {
        self.ctx().store.config(PA).unwrap().config.routes[0]
            .credential_scope_id
            .as_str()
            .to_string()
    }

    /// Upload one registry entry as proxy A (`POST /v1/proxy-metadata`). The
    /// definition carries free text the query API must never show.
    async fn upload_metadata(&self, mref: &str, def_name: &str, def_desc: &str) {
        let c = mtls_client(&self.pki.p("hostca.crt"), &self.a.cert.0, &self.a.cert.1);
        let entry = json!({
            "proxy_id": PA,
            "metadata_ref": mref,
            "upstream_id": "up1",
            "credential_scope_id": self.scope_id(),
            "protocol_version": "2025-11-25",
            "observation_source": "proxy_live",
            "canon": "sigil-tooldef-fp-v1",
            "key_id": "kid-000000000000000000000001",
            "fingerprint": "a".repeat(64),
            "observed_at": "2026-10-10T00:00:00Z",
            "definition": {"name": def_name, "description": def_desc},
        });
        let r = c
            .post(format!(
                "https://127.0.0.1:{}/v1/proxy-metadata",
                self.srv().port
            ))
            .header("content-type", "application/json")
            .body(json!({"schema_version": 1, "proxy_id": PA, "entries": [entry]}).to_string())
            .send()
            .await
            .unwrap();
        let st = r.status().as_u16();
        assert_eq!(st, 200, "metadata upload: {:?}", r.text().await);
    }
}

// ------------------------------------------------------------ json helpers

fn items(v: &Value) -> &Vec<Value> {
    v["items"].as_array().expect("items array")
}

fn inv_ids(v: &Value) -> Vec<String> {
    items(v)
        .iter()
        .map(|i| i["invocation_id"].as_str().unwrap().to_string())
        .collect()
}

fn by_inv(v: &Value, n: u32) -> &Value {
    items(v)
        .iter()
        .find(|i| i["invocation_id"] == inv(n))
        .unwrap_or_else(|| panic!("invocation {n} not listed"))
}

fn proxy_ids(v: &Value) -> Vec<String> {
    items(v)
        .iter()
        .map(|i| i["proxy_id"].as_str().unwrap().to_string())
        .collect()
}

/// An invocation's L2 projection without identities and server receive times:
/// what must not depend on arrival order or on which proxy sent it.
fn core(i: &Value) -> Value {
    let mut o = serde_json::Map::new();
    for k in [
        "lifecycle",
        "outcome",
        "delivery_state",
        "reason",
        "reported_outcome",
        "reported_delivery_state",
        "reported_reason",
        "duration_ms",
        "response_bytes",
        "method",
        "protocol_version",
        "upstream_id",
        "route_revision",
        "actor",
        "tool",
        "cancel_observed",
        "decision",
        "started_at",
        "completed_at",
        "start_epoch_id",
        "epoch_superseded",
        "flags",
    ] {
        o.insert(k.into(), i[k].clone());
    }
    Value::Object(o)
}

// ------------------------------------------------------------------- tests

/// PX-010/PX-011, AC-12: completed, start-only, completion-only and
/// integrity-conflict invocations show the right lifecycle and outcome; a
/// start-only invocation never matches `outcome=success`; `connection_state`
/// follows the traffic; the detail route lists the stored events.
#[tokio::test]
async fn projection_lifecycles_filters_and_detail() {
    let Some(h) = H::new(false).await else {
        return;
    };
    // Registered but silent: never connected.
    let l = h.ok("/v1/proxies").await;
    assert_eq!(proxy_ids(&l), vec![PA, PB]);
    for p in items(&l) {
        assert_eq!(p["connection_state"], "never_connected");
        assert!(p["last_seen"].is_null());
        assert_eq!(p["open_gap_count"], 0);
        assert_eq!(p["config_in_sync"], false);
    }
    let nc = h.ok("/v1/proxies?connection_state=never_connected").await;
    assert_eq!(items(&nc).len(), 2);

    h.a.send(dataset(PA, 0, 0)).await;
    h.b.send(vec![
        started(PB, eb(1), 11, 1, 1),
        completed(PB, eb(2), 11, 2, 2, "success", "sent"),
        started(PB, eb(3), 12, 3, 3),
    ])
    .await;

    // Accepted ingest is a sign of life.
    let l = h.ok("/v1/proxies").await;
    for p in items(&l) {
        assert_eq!(p["connection_state"], "connected", "{p}");
        assert!(p["last_seen"].is_string());
    }
    assert!(items(&h.ok("/v1/proxies?connection_state=never_connected").await).is_empty());
    assert!(items(&h.ok("/v1/proxies?connection_state=disconnected").await).is_empty());

    let la = h.ok("/v1/proxy-invocations?proxy_id=px-a").await;
    // created_seq descending: the newest first invocation first.
    assert_eq!(inv_ids(&la), vec![inv(4), inv(3), inv(2), inv(1)]);
    assert!(la["next_cursor"].is_null());

    let i1 = by_inv(&la, 1);
    assert_eq!(i1["lifecycle"], "completed");
    assert_eq!(i1["outcome"], "success");
    assert_eq!(i1["delivery_state"], "sent");
    assert_eq!(i1["duration_ms"], 12);
    assert_eq!(i1["response_bytes"], 345);
    assert_eq!(i1["method"], "ping");
    assert_eq!(i1["upstream_id"], "up1");
    assert_eq!(i1["started_at"], at(1));
    assert_eq!(i1["completed_at"], at(2));
    assert_eq!(i1["flags"], json!([]));
    assert!(i1["reported_outcome"].is_null());
    assert_eq!(i1["proxy_id"], PA);
    assert_eq!(i1["actor"]["actor_id"], "actor-1");

    let i2 = by_inv(&la, 2);
    assert_eq!(i2["lifecycle"], "started");
    assert!(i2["outcome"].is_null() && i2["delivery_state"].is_null());
    assert!(i2["completed_at"].is_null() && i2["duration_ms"].is_null());
    assert_eq!(i2["method"], "ping");

    // A completion without its start: the claim is reported, not asserted.
    let i3 = by_inv(&la, 3);
    assert_eq!(i3["lifecycle"], "completion_without_start");
    assert!(i3["outcome"].is_null() && i3["delivery_state"].is_null());
    assert_eq!(i3["reported_outcome"], "timeout");
    assert_eq!(i3["reported_delivery_state"], "unknown");
    assert!(i3["method"].is_null() && i3["started_at"].is_null());

    // Two different completions: integrity conflict, nothing asserted.
    let i4 = by_inv(&la, 4);
    assert_eq!(i4["lifecycle"], "integrity_conflict");
    assert!(i4["outcome"].is_null() && i4["delivery_state"].is_null());
    assert_eq!(i4["reported_outcome"], "success");
    assert!(i4["flags"]
        .as_array()
        .unwrap()
        .contains(&json!("duplicate_completion")));

    // Filters. A start-only invocation never matches `outcome=success`.
    let ok = h
        .ok("/v1/proxy-invocations?proxy_id=px-a&outcome=success")
        .await;
    assert_eq!(inv_ids(&ok), vec![inv(1)]);
    let all_ok = h.ok("/v1/proxy-invocations?outcome=success").await;
    let mut ids = inv_ids(&all_ok);
    ids.sort();
    assert_eq!(ids, vec![inv(1), inv(11)]);
    assert!(items(&h.ok("/v1/proxy-invocations?outcome=timeout").await).is_empty());
    let started_only = h
        .ok("/v1/proxy-invocations?proxy_id=px-a&lifecycle=started")
        .await;
    assert_eq!(inv_ids(&started_only), vec![inv(2)]);
    let conflict = h
        .ok("/v1/proxy-invocations?lifecycle=integrity_conflict")
        .await;
    assert_eq!(inv_ids(&conflict), vec![inv(4)]);
    let cws = h
        .ok("/v1/proxy-invocations?lifecycle=completion_without_start")
        .await;
    assert_eq!(inv_ids(&cws), vec![inv(3)]);
    assert_eq!(
        items(
            &h.ok("/v1/proxy-invocations?method=ping&actor_id=actor-1&upstream_id=up1")
                .await
        )
        .len(),
        // A: 1, 2, 4 have a start; B: 11, 12.
        5
    );
    // The occurred-time basis: only the invocation A1 (start at :01) is in
    // the first two seconds of px-a.
    let w = h
        .ok("/v1/proxy-invocations?proxy_id=px-a&time_basis=occurred&from=2026-10-10T00:00:00Z&to=2026-10-10T00:00:02Z")
        .await;
    assert_eq!(inv_ids(&w), vec![inv(1)]);

    // Detail: the stored events of the conflict, no content.
    let d = h.ok(&format!("/v1/proxy-invocations/{}", inv(4))).await;
    assert_eq!(d["lifecycle"], "integrity_conflict");
    assert_eq!(d["events_total"], 3);
    assert_eq!(d["events_truncated"], false);
    let mut evs: Vec<(i64, String)> = d["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["sequence"].as_i64().unwrap(),
                e["event_type"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    evs.sort();
    assert_eq!(
        evs,
        vec![
            (5, "invocation.started".to_string()),
            (6, "invocation.completed".to_string()),
            (7, "invocation.completed".to_string()),
        ]
    );
    let d = h.ok(&format!("/v1/proxy-invocations/{}", inv(2))).await;
    assert_eq!(d["events_total"], 1);
}

/// L2: the projection does not depend on arrival order. Proxy B delivers the
/// same invocations as proxy A in reverse sequence order, one event per batch
/// (completions before starts); the stored projections and event lists agree.
#[tokio::test]
async fn shuffled_arrival_gives_the_same_projection() {
    let Some(h) = H::new(false).await else {
        return;
    };
    h.a.send(dataset(PA, 0, 0)).await;
    for e in dataset(PB, 500, 10).into_iter().rev() {
        h.b.send(vec![e]).await;
    }
    let la = h.ok("/v1/proxy-invocations?proxy_id=px-a").await;
    let lb = h.ok("/v1/proxy-invocations?proxy_id=px-b").await;
    assert_eq!(items(&la).len(), 4);
    assert_eq!(items(&lb).len(), 4);
    for k in 1..=4 {
        assert_eq!(
            core(by_inv(&la, k)),
            core(by_inv(&lb, 10 + k)),
            "invocation {k}"
        );
        let hr = &h;
        let ev = |id: String| async move {
            let h = hr;
            let d = h.ok(&format!("/v1/proxy-invocations/{id}")).await;
            let mut v: Vec<(i64, String, String)> = d["events"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| {
                    (
                        e["sequence"].as_i64().unwrap(),
                        e["event_type"].as_str().unwrap().to_string(),
                        e["occurred_at"].as_str().unwrap().to_string(),
                    )
                })
                .collect();
            v.sort();
            (d["events_total"].clone(), v)
        };
        assert_eq!(ev(inv(k)).await, ev(inv(10 + k)).await, "events {k}");
    }
    // The reversed arrival really opened gaps (they all closed again); the
    // in-order proxy never had one.
    let da = h.ok("/v1/proxies/px-a").await;
    let db = h.ok("/v1/proxies/px-b").await;
    assert_eq!(da["audit_gaps_total"], 0);
    assert!(db["audit_gaps_total"].as_i64().unwrap() >= 1, "{db}");
    assert_eq!(db["open_gap_counts"], json!({}));
    assert_eq!(db["open_gap_count"], 0);
}

/// L3: keyset paging, cursor binding and strict filters.
#[tokio::test]
async fn paging_inserts_between_pages_and_cursor_filter_errors() {
    let Some(h) = H::new(false).await else {
        return;
    };
    h.a.send((1..=6).map(|n| started(PA, n, n, n, n)).collect())
        .await;

    // Walk with limit 2; between pages new invocations arrive, from both
    // proxies. They are newer, so the old ones are neither skipped nor repeated.
    let p1 = h.ok("/v1/proxy-invocations?limit=2").await;
    assert_eq!(inv_ids(&p1), vec![inv(6), inv(5)]);
    let c1 = p1["next_cursor"].as_str().expect("cursor").to_string();
    h.a.send(vec![started(PA, 7, 7, 7, 7), started(PA, 8, 8, 8, 8)])
        .await;
    h.b.send(vec![started(PB, eb(1), 21, 1, 9)]).await;
    let p2 = h
        .ok(&format!("/v1/proxy-invocations?limit=2&cursor={c1}"))
        .await;
    assert_eq!(inv_ids(&p2), vec![inv(4), inv(3)]);
    let c2 = p2["next_cursor"].as_str().expect("cursor").to_string();
    h.b.send(vec![started(PB, eb(2), 22, 2, 10)]).await;
    let p3 = h
        .ok(&format!("/v1/proxy-invocations?limit=2&cursor={c2}"))
        .await;
    assert_eq!(inv_ids(&p3), vec![inv(2), inv(1)]);
    assert!(p3["next_cursor"].is_null(), "the end of the walk");
    // A fresh walk shows the inserted ones first.
    let fresh = h.ok("/v1/proxy-invocations").await;
    assert_eq!(
        inv_ids(&fresh),
        vec![22, 21, 8, 7, 6, 5, 4, 3, 2, 1]
            .into_iter()
            .map(inv)
            .collect::<Vec<_>>()
    );

    // Proxies page in `proxy_id` order.
    let q1 = h.ok("/v1/proxies?limit=1").await;
    assert_eq!(proxy_ids(&q1), vec![PA]);
    let pc = q1["next_cursor"].as_str().expect("cursor").to_string();
    let q2 = h.ok(&format!("/v1/proxies?limit=1&cursor={pc}")).await;
    assert_eq!(proxy_ids(&q2), vec![PB]);
    assert!(q2["next_cursor"].is_null());

    // Cursor defects are 422 invalid_cursor.
    let bad_cursors = [
        // from another endpoint
        format!("/v1/proxy-invocations?cursor={pc}"),
        format!("/v1/proxies?cursor={c1}"),
        // from the same endpoint under another filter
        format!("/v1/proxy-invocations?outcome=success&cursor={c1}"),
        format!("/v1/proxy-invocations?proxy_id=px-a&cursor={c1}"),
        // damaged
        format!("/v1/proxy-invocations?cursor={}", &c1[..c1.len() - 4]),
        "/v1/proxy-invocations?cursor=not-a-cursor".to_string(),
        format!("/v1/proxy-invocations?cursor={}", "A".repeat(600)),
    ];
    for path in &bad_cursors {
        let r = h.rd(path).await;
        assert_eq!(
            (r.status, r.code().as_str()),
            (422, "invalid_cursor"),
            "{path}"
        );
    }

    // Filter defects are 422 invalid_filter; the value is never echoed.
    let bad_filters = [
        "/v1/proxy-invocations?bogus=1",
        "/v1/proxy-invocations?limit=0",
        "/v1/proxy-invocations?limit=501",
        "/v1/proxy-invocations?limit=abc",
        "/v1/proxy-invocations?limit=1&limit=2",
        "/v1/proxy-invocations?outcome=nope-value-xyz",
        "/v1/proxy-invocations?method=nope-value-xyz",
        "/v1/proxy-invocations?lifecycle=nope-value-xyz",
        "/v1/proxy-invocations?time_basis=nope-value-xyz",
        "/v1/proxy-invocations?from=nope-value-xyz",
        "/v1/proxy-invocations?proxy_id=-nope-value-xyz",
        "/v1/proxy-invocations?tool_ref=nope-value-xyz",
        "/v1/proxy-invocations?outcome=",
        "/v1/proxies?connection_state=nope-value-xyz",
        "/v1/proxies?config_in_sync=nope-value-xyz",
        "/v1/proxies?upstream_id=up1",
    ];
    for path in bad_filters {
        let r = h.rd(path).await;
        assert_eq!(
            (r.status, r.code().as_str()),
            (422, "invalid_filter"),
            "{path}"
        );
        let text = String::from_utf8_lossy(&r.body).to_lowercase();
        assert!(!text.contains("nope-value-xyz") && !text.contains("nope_value_xyz"));
    }
}

/// PX-016: the read bearer sees every proxy today, but one function decides
/// the scope. With the scope narrowed to px-b (the server-side test hook),
/// px-a is as absent as a proxy that never existed, byte for byte.
#[tokio::test]
async fn isolation_between_proxies_and_byte_equal_404() {
    let Some(h) = H::new(false).await else {
        return;
    };
    h.a.send(dataset(PA, 0, 0)).await;
    h.b.send(dataset(PB, 500, 10)).await;

    // Full scope: px-a's invocations are never listed under px-b's filter.
    let lb = h.ok("/v1/proxy-invocations?proxy_id=px-b").await;
    assert_eq!(inv_ids(&lb).len(), 4);
    assert!(proxy_ids(&lb).iter().all(|p| p == PB));
    for k in 1..=4 {
        assert!(!inv_ids(&lb).contains(&inv(k)));
    }
    let d = h.ok(&format!("/v1/proxy-invocations/{}", inv(1))).await;
    assert_eq!(d["proxy_id"], PA);

    // The unknown-target answers, for comparison.
    let unknown_inv = h
        .rd(&format!("/v1/proxy-invocations/{}", uid(424242)))
        .await;
    assert_eq!(
        (unknown_inv.status, unknown_inv.code().as_str()),
        (404, "proxy_unknown")
    );
    let not_uuid = h.rd("/v1/proxy-invocations/not-a-uuid").await;
    assert_eq!(not_uuid.body, unknown_inv.body);
    let unknown_proxy = h.rd("/v1/proxies/px-ghost").await;
    assert_eq!(unknown_proxy.status, 404);
    assert_eq!(
        unknown_proxy.body, unknown_inv.body,
        "one 404 for every miss"
    );
    let ghost_list = h.rd("/v1/proxy-invocations?proxy_id=px-ghost").await;
    assert_eq!(ghost_list.status, 200);
    assert_eq!(ghost_list.json(), json!({"items": [], "next_cursor": null}));

    // Narrow the read scope to px-b.
    *h.scope.lock().unwrap() = Some(vec![PB.to_string()]);
    let l = h.ok("/v1/proxies").await;
    assert_eq!(proxy_ids(&l), vec![PB]);
    let inv_all = h.ok("/v1/proxy-invocations").await;
    assert_eq!(inv_ids(&inv_all).len(), 4);
    assert!(proxy_ids(&inv_all).iter().all(|p| p == PB));
    // Out of scope == unknown, byte for byte.
    let out_proxy = h.rd("/v1/proxies/px-a").await;
    assert_eq!(out_proxy.status, 404);
    assert_eq!(out_proxy.body, unknown_proxy.body);
    for k in 1..=4 {
        let r = h.rd(&format!("/v1/proxy-invocations/{}", inv(k))).await;
        assert_eq!(r.status, 404, "invocation {k}");
        assert_eq!(r.body, unknown_inv.body, "invocation {k}");
    }
    // Own proxy still readable.
    assert_eq!(h.rd("/v1/proxies/px-b").await.status, 200);
    assert_eq!(
        h.rd(&format!("/v1/proxy-invocations/{}", inv(11)))
            .await
            .status,
        200
    );
    // A filter naming the out-of-scope proxy is the empty list of a ghost.
    let out_list = h.rd("/v1/proxy-invocations?proxy_id=px-a").await;
    assert_eq!(out_list.status, 200);
    assert_eq!(out_list.body, ghost_list.body);
    *h.scope.lock().unwrap() = None;
    assert_eq!(h.rd("/v1/proxies/px-a").await.status, 200);
}

/// Auth over real TLS: the read bearer and a host-class certificate are both
/// required; proxy and management certificates are refused.
#[tokio::test]
async fn auth_matrix_over_tls() {
    let Some(h) = H::new(false).await else {
        return;
    };
    h.a.send(vec![started(PA, 1, 1, 1, 1)]).await;
    let paths = [
        "/v1/proxies".to_string(),
        "/v1/proxies/px-a".to_string(),
        "/v1/proxy-invocations".to_string(),
        format!("/v1/proxy-invocations/{}", inv(1)),
    ];
    let proxy_client = mtls_client(&h.pki.p("hostca.crt"), &h.a.cert.0, &h.a.cert.1);
    let proxy_b_client = mtls_client(&h.pki.p("hostca.crt"), &h.b.cert.0, &h.b.cert.1);
    // No client certificate at all: the TLS handshake refuses.
    let anonymous = reqwest::Client::builder()
        .use_rustls_tls()
        .pool_max_idle_per_host(0)
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(h.pki.p("hostca.crt")).unwrap()).unwrap(),
        )
        .build()
        .unwrap();

    for path in &paths {
        let get = |c: &reqwest::Client, b: Option<&'static str>| {
            let (c, path) = (c.clone(), path.clone());
            let h = &h;
            async move { h.try_fetch(&c, &path, b).await.expect("answered") }
        };
        // Host certificate: the bearer decides.
        assert_eq!(get(&h.reader, None).await.status, 401, "{path} no bearer");
        assert_eq!(
            get(&h.reader, Some("wrong")).await.status,
            401,
            "{path} wrong"
        );
        assert_eq!(
            get(&h.reader, Some(T_ID)).await.status,
            401,
            "{path} mgmt token"
        );
        assert_eq!(
            get(&h.reader, Some(T_CFG)).await.status,
            401,
            "{path} cfg token"
        );
        assert_eq!(
            get(&h.reader, Some(READ_BEARER)).await.status,
            200,
            "{path} ok"
        );

        // Proxy and management certificates are refused whatever the bearer.
        let mut refused: Vec<Resp> = Vec::new();
        for c in [&proxy_client, &proxy_b_client, &h.mgmt] {
            for b in [None, Some("wrong"), Some(READ_BEARER), Some(T_ID)] {
                refused.push(get(c, b).await);
            }
        }
        for r in &refused {
            assert_eq!(r.status, 404, "{path}");
            assert_eq!(r.json(), json!({"error": "host_unknown"}), "{path}");
        }
        let first = &refused[0].body;
        assert!(
            refused.iter().all(|r| &r.body == first),
            "{path}: one answer for every refused certificate"
        );

        // No certificate: no HTTP answer at all.
        assert!(
            h.try_fetch(&anonymous, path, Some(READ_BEARER))
                .await
                .is_err(),
            "{path} without a client certificate"
        );
    }
}

/// AC-05: no stored content reaches a response. The canary sits in every place
/// the schema lets free text reach the server and the query does not show it:
/// the tool definition of the metadata registry and the route's credential
/// reference and upstream URL. Fields the schema forbids are refused at
/// ingest and never stored. A positive control shows the canary is in the
/// server's state, and no response, for any route or error, carries it.
#[tokio::test]
async fn canary_is_absent_from_every_response() {
    let Some(h) = H::new(true).await else {
        return;
    };
    h.upload_metadata(
        &mref(1),
        &format!("tool-{CANARY}"),
        &format!("describes {CANARY} and {CANARY_ARGS}"),
    )
    .await;
    h.a.send(vec![
        started_tool(PA, 1, 1, 1, 1, &mref(1)),
        completed(PA, 2, 1, 2, 2, "success", "sent"),
        started(PA, 3, 2, 3, 3),
    ])
    .await;
    h.b.send(vec![started(PB, eb(1), 11, 1, 1)]).await;

    // A start carrying forbidden content fields is refused, not stored.
    let mut bad = envelope(PA, 90, 1, 4, 4, "invocation.started", started_payload(9));
    bad["payload"]["arguments"] = json!({"query": CANARY_ARGS});
    bad["payload"]["tool_name"] = CANARY_ARGS.into();
    bad["payload"]["session_id"] = CANARY_ARGS.into();
    let pc = mtls_client(&h.pki.p("hostca.crt"), &h.a.cert.0, &h.a.cert.1);
    let raw = pc
        .post(format!(
            "https://127.0.0.1:{}/v1/proxy-events",
            h.srv().port
        ))
        .header("content-type", "application/json")
        .body(json!({"events": [bad]}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(raw.status().as_u16(), 422);
    let raw_body = raw.bytes().await.unwrap().to_vec();
    assert!(h.ctx().ledger.stored_event(PA, &uid(90)).unwrap().is_none());

    // Sweep every route, with filters and details, and the error answers.
    let list = h.ok("/v1/proxy-invocations").await;
    assert!(!items(&list).is_empty());
    let tool = &by_inv(&list, 1)["tool"];
    assert_eq!(
        *tool,
        json!({"status": "identified", "metadata_ref": mref(1)})
    );
    let by_ref = h
        .ok(&format!("/v1/proxy-invocations?tool_ref={}", mref(1)))
        .await;
    assert_eq!(inv_ids(&by_ref), vec![inv(1)]);
    for id in inv_ids(&list) {
        h.ok(&format!("/v1/proxy-invocations/{id}")).await;
    }
    for p in ["/v1/proxies", "/v1/proxies/px-a", "/v1/proxies/px-b"] {
        h.ok(p).await;
    }
    for p in [
        "/v1/proxy-invocations?bogus=1",
        "/v1/proxy-invocations?cursor=zzz",
        "/v1/proxies/px-ghost",
        "/v1/proxy-invocations/not-a-uuid",
    ] {
        h.rd(p).await;
    }
    h.try_fetch(&h.reader, "/v1/proxies", None).await.unwrap();
    h.try_fetch(&h.mgmt, "/v1/proxies", Some(READ_BEARER))
        .await
        .unwrap();

    // Positive control: the canary really is in the server's state.
    let mut in_state = 0;
    let mut stack = vec![h.pki.dir.path().to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if let Ok(bytes) = std::fs::read(&p) {
                if contains(&bytes, CANARY.as_bytes()) {
                    in_state += 1;
                }
            }
        }
    }
    assert!(in_state >= 1, "the canary never reached the server's state");
    assert!(
        !contains(&raw_body, CANARY_ARGS.as_bytes()),
        "the ingest refusal echoed content"
    );

    let needles = [
        CANARY,
        CANARY_ARGS,
        "api.example.com",
        T_ID,
        T_CFG,
        READ_BEARER,
        "client-tok",
        "UPSTREAM-SECRET-VALUE",
    ];
    let seen = h.seen.lock().unwrap();
    assert!(seen.len() >= 12, "the sweep must have read responses");
    for body in seen.iter().chain(std::iter::once(&raw_body)) {
        for n in needles {
            assert!(
                !contains(body, n.as_bytes()),
                "{n} found in a response: {}",
                String::from_utf8_lossy(body)
            );
        }
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn unrecorded_gap(n: u32) -> Value {
    json!({
        "kind": "unrecorded_calls",
        "gap_id": uid(7500 + n),
        "detected_at": "2026-10-10T00:10:00Z",
        "count": 3,
        "from_at": "2026-10-10T00:05:00Z",
        "to_at": "2026-10-10T00:06:00Z",
    })
}

fn gap_of<'a>(detail: &'a Value, kind: &str) -> Vec<&'a Value> {
    detail["audit_gaps"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|g| g["kind"] == kind)
        .collect()
}

/// PX-012, AC-06: a sequence gap from skipped sequences, closed by the late
/// fill; a tail gap from the status report's `last_assigned_sequence`, extended
/// and then closed by arrival. Closed gaps stay listed; `open_gap_counts` and
/// the summary's `open_gap_count` follow; the other proxy is untouched.
#[tokio::test]
async fn sequence_and_tail_gaps_open_close_and_stay_listed() {
    let Some(h) = H::new(false).await else {
        return;
    };
    let ev = |p: &str, n: u32| {
        let off = if p == PB { 500 } else { 0 };
        started(p, off + n, if p == PB { 100 + n } else { n }, n, n)
    };

    // ---- sequence gap on px-a: 1, 2, then 5.
    h.a.send(vec![ev(PA, 1), ev(PA, 2)]).await;
    h.a.send(vec![ev(PA, 5)]).await;
    let d = h.ok("/v1/proxies/px-a").await;
    let g = gap_of(&d, "sequence_gap");
    assert_eq!(g.len(), 1, "{d}");
    assert_eq!(g[0]["state"], "open");
    assert_eq!(g[0]["source"], "server_derived");
    assert_eq!(g[0]["details"]["tail"], false);
    assert_eq!(g[0]["details"]["from_sequence"], 3);
    assert_eq!(g[0]["details"]["to_sequence"], 4);
    assert_eq!(g[0]["details"]["epoch_id"], epoch(1));
    assert_eq!(d["open_gap_counts"], json!({"sequence_gap": 1}));
    assert_eq!(d["open_gap_count"], 1);
    assert_eq!(d["connection_state"], "connected");
    let l = h.ok("/v1/proxies").await;
    assert_eq!(items(&l)[0]["open_gap_count"], 1);
    assert_eq!(items(&l)[1]["open_gap_count"], 0);

    // The late fill closes it; the record stays.
    h.a.send(vec![ev(PA, 3), ev(PA, 4)]).await;
    let d = h.ok("/v1/proxies/px-a").await;
    let g = gap_of(&d, "sequence_gap");
    assert_eq!(g.len(), 1);
    assert_eq!(g[0]["state"], "closed");
    assert_eq!(d["audit_gaps_total"], 1);
    assert_eq!(d["open_gap_counts"], json!({}));
    assert_eq!(d["open_gap_count"], 0);
    assert_eq!(items(&h.ok("/v1/proxies").await)[0]["open_gap_count"], 0);

    // ---- tail gap on px-b: 1..=3 arrived, the proxy says it assigned 6.
    h.b.send(vec![ev(PB, 1), ev(PB, 2), ev(PB, 3)]).await;
    assert_eq!(h.ok("/v1/proxies/px-b").await["open_gap_count"], 0);
    h.b.status(1, 1, 6, vec![unrecorded_gap(1)]).await;
    let d = h.ok("/v1/proxies/px-b").await;
    let g = gap_of(&d, "sequence_gap");
    assert_eq!(g.len(), 1, "{d}");
    assert_eq!(g[0]["state"], "open");
    assert_eq!(g[0]["details"]["tail"], true);
    assert_eq!(g[0]["details"]["from_sequence"], 4);
    assert_eq!(g[0]["details"]["to_sequence"], 6);
    let u = gap_of(&d, "unrecorded_calls");
    assert_eq!(u.len(), 1);
    assert_eq!(u[0]["source"], "proxy_reported");
    assert_eq!(u[0]["details"]["count"], 3);
    assert_eq!(
        d["open_gap_counts"],
        json!({"sequence_gap": 1, "unrecorded_calls": 1})
    );
    assert_eq!(d["open_gap_count"], 2);
    // The report's state shows too.
    assert_eq!(d["connection_state"], "connected");
    assert_eq!(d["spool"]["state"], "ok");
    assert_eq!(d["spool"]["unsent_events"], 2);
    assert!(d["spool"]["as_of"].is_string() && d["status_as_of"].is_string());
    assert_eq!(d["current_epoch_id"], epoch(1));
    // px-a is unaffected by px-b's gaps.
    assert_eq!(h.ok("/v1/proxies/px-a").await["open_gap_count"], 0);

    // A later report with a higher mark extends the same tail gap.
    h.b.status(1, 2, 8, vec![]).await;
    let d = h.ok("/v1/proxies/px-b").await;
    let g = gap_of(&d, "sequence_gap");
    assert_eq!(g.len(), 1, "extended, not duplicated: {d}");
    assert_eq!(g[0]["details"]["to_sequence"], 8);
    assert_eq!(g[0]["state"], "open");

    // The tail arrives: closed, still listed; the reported gap stays open.
    h.b.send((4..=8).map(|n| ev(PB, n)).collect()).await;
    let d = h.ok("/v1/proxies/px-b").await;
    let g = gap_of(&d, "sequence_gap");
    assert_eq!(g.len(), 1);
    assert_eq!(g[0]["state"], "closed");
    assert_eq!(g[0]["details"]["tail"], true);
    assert_eq!(d["audit_gaps_total"], 2);
    assert_eq!(d["open_gap_counts"], json!({"unrecorded_calls": 1}));
    assert_eq!(d["open_gap_count"], 1);
    let l = h.ok("/v1/proxies").await;
    assert_eq!(items(&l)[1]["open_gap_count"], 1);
}

/// All reads of the restart check, as raw bytes.
async fn snapshot(h: &H, invs: &[u32]) -> BTreeMap<String, Vec<u8>> {
    let mut paths = vec![
        "/v1/proxies".to_string(),
        "/v1/proxies/px-a".to_string(),
        "/v1/proxies/px-b".to_string(),
        "/v1/proxy-invocations".to_string(),
        "/v1/proxy-invocations?proxy_id=px-a&outcome=success".to_string(),
        "/v1/proxy-invocations?lifecycle=integrity_conflict".to_string(),
    ];
    paths.extend(
        invs.iter()
            .map(|n| format!("/v1/proxy-invocations/{}", inv(*n))),
    );
    let mut out = BTreeMap::new();
    for p in paths {
        let r = h.rd(&p).await;
        assert_eq!(r.status, 200, "{p}");
        out.insert(p, r.body);
    }
    out
}

/// AC-12: projection, gaps and `last_seen` survive a server restart on the same
/// state dir (read bodies are byte-identical); a resend of stored events is
/// acknowledged without changing anything; `connection_state` leaves
/// `connected` once `last_seen` is older than `stale_after` and returns with
/// the next accepted event.
///
/// The 90 s `STALE_AFTER_SECS` has no test knob, so the age is applied to the
/// stored `last_seen` through the public store API instead of sleeping; the
/// exact boundary is the unit test `connection_state_boundary`.
#[tokio::test]
async fn projection_survives_restart_and_connection_goes_stale() {
    let Some(mut h) = H::new(false).await else {
        return;
    };
    h.a.send(dataset(PA, 0, 0)).await;
    h.b.send(dataset(PB, 500, 10)).await;
    // A tail gap on px-a: the proxy assigned 9, 7 arrived.
    h.a.status(1, 1, 9, vec![unrecorded_gap(2)]).await;
    let all = [1, 2, 3, 4, 11, 12, 13, 14];
    let before = snapshot(&h, &all).await;
    let da: Value = serde_json::from_slice(&before["/v1/proxies/px-a"]).unwrap();
    assert_eq!(da["connection_state"], "connected");
    assert_eq!(
        da["open_gap_counts"],
        json!({"sequence_gap": 1, "unrecorded_calls": 1})
    );

    h.server_down().await;
    // Down: the connection is refused, not answered with stale data.
    assert!(h
        .reader
        .get(format!("https://127.0.0.1:{}/v1/proxies", h.last_port))
        .bearer_auth(READ_BEARER)
        .send()
        .await
        .is_err());
    h.server_up().await;

    let after = snapshot(&h, &all).await;
    for (p, b) in &before {
        assert_eq!(
            String::from_utf8_lossy(&after[p]),
            String::from_utf8_lossy(b),
            "{p} changed over the restart"
        );
    }

    // Resending stored events: acknowledged (duplicate), nothing changes.
    h.a.send(dataset(PA, 0, 0).into_iter().take(2).collect())
        .await;
    let again = snapshot(&h, &all).await;
    for p in ["/v1/proxy-invocations", "/v1/proxies/px-a"] {
        assert_eq!(
            String::from_utf8_lossy(&again[p]),
            String::from_utf8_lossy(&before[p]),
            "{p} changed by a resend"
        );
    }

    // The gap survives and the tail still closes after the restart.
    h.a.send(vec![started(PA, 8, 8, 8, 8), started(PA, 9, 9, 9, 9)])
        .await;
    let d = h.ok("/v1/proxies/px-a").await;
    assert_eq!(gap_of(&d, "sequence_gap")[0]["state"], "closed");
    assert_eq!(d["open_gap_counts"], json!({"unrecorded_calls": 1}));

    // Stale: px-b was last seen long ago.
    {
        let ctx = h.ctx();
        let txn = ctx.store.begin();
        let mut e = txn.entry(PB);
        e.last_seen = Some("2020-01-01T00:00:00Z".to_string());
        txn.commit(PB, e).unwrap();
    }
    let dis = h.ok("/v1/proxies?connection_state=disconnected").await;
    assert_eq!(proxy_ids(&dis), vec![PB]);
    assert_eq!(items(&dis)[0]["connection_state"], "disconnected");
    assert_eq!(items(&dis)[0]["last_seen"], "2020-01-01T00:00:00Z");
    let con = h.ok("/v1/proxies?connection_state=connected").await;
    assert_eq!(proxy_ids(&con), vec![PA]);
    assert_eq!(
        h.ok("/v1/proxies/px-b").await["connection_state"],
        "disconnected"
    );
    // The projection is untouched by the proxy being away.
    assert_eq!(
        items(&h.ok("/v1/proxy-invocations?proxy_id=px-b").await).len(),
        4
    );
    // The next accepted event brings it back.
    h.b.send(vec![started(PB, eb(50), 50, 8, 8)]).await;
    let d = h.ok("/v1/proxies/px-b").await;
    assert_eq!(d["connection_state"], "connected");
    assert_ne!(d["last_seen"], "2020-01-01T00:00:00Z");
}
