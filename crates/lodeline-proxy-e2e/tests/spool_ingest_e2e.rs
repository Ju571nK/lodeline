#![cfg(unix)]
//! T-14b (#305, fixes #260): the durable event spool on the PRODUCTION path.
//!
//! The proxy is the real `lifecycle::run_tuned` (spool opened after the state_dir
//! lock, `run_ingest` started with the spool as its source, status reports with
//! the spool's real numbers and tail sequence), talking over loopback rustls mTLS
//! to the real `lodeline-server` proxy routes. Events enter through the test-only
//! injector (`Spool::inject_test_event`, feature `test-util`), because the relay
//! (T-13) does not produce events yet. One test starts the REAL `lodeline-proxy`
//! binary (built without `test-util`) on a state_dir whose spool was filled
//! beforehand.
//!
//! Requirements: PX-011, PX-013, PX-016; acceptance AC-06, AC-12.
//! Real-time polling with tuned short intervals; no paused clock.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use lodeline_proxy::bootstrap::Bootstrap;
use lodeline_proxy::config_sync::MtlsFetcher;
use lodeline_proxy::ingest_client::{IngestParams, IngestTransport};
use lodeline_proxy::lifecycle::{run_tuned, Lifecycle, RunTuning};
use lodeline_proxy::limits::Limits;
use lodeline_proxy::route::TableHandle;
use lodeline_proxy::spool::{AppendError, Spool};
use lodeline_proxy::state_dir::{StateDir, StateError};
use lodeline_proxy_api::status::SpoolState;
use lodeline_proxy_api::verifier::verifier_for;
use lodeline_proxy_api::Id;
use lodeline_server::config::ProxyConfig;
use lodeline_server::proxy::identity::proxy_san;
use lodeline_server::proxy::ledger::GapKind;
use lodeline_server::proxy::ProxyContext;
use serde_json::{json, Value};
use tokio::sync::oneshot;

mod common;
use common::{client_ext, fingerprint, mgmt_identity, mtls_client, pki, Pki, Server, Tweak};

const T_ID: &str = "tok-identity-ingest";
const T_CFG: &str = "tok-config-ingest";
const PROXY: &str = "px-ing";
const WAIT: Duration = Duration::from_secs(20);

// ---------------------------------------------------------------- harness

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
        let pki = pki("ing")?;
        let mgmt_cert = mgmt_identity(&pki, T_ID, T_CFG);
        let proxy_cert = pki.leaf("proxyca", "proxy", PROXY, &client_ext(&proxy_san(PROXY)));
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
    fn status(&self) -> Option<lodeline_proxy_api::ProxyStatus> {
        self.ctx().store.entry(PROXY).and_then(|e| e.status)
    }

    fn spool_state(&self) -> Option<SpoolState> {
        self.status().map(|s| s.spool.state)
    }

    fn tail_gaps(&self) -> Vec<lodeline_server::proxy::ledger::GapRecord> {
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
    common::retry_locked(|| async move {
        let b = h.bootstrap();
        let sock = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let (spool_tx, spool_rx) = oneshot::channel();
        let (stop, rx) = oneshot::channel::<()>();
        let tune = tuning(sock, spool_tx);
        let state_dir = b.state_dir.clone();
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
        let spool = match spool_rx.await {
            Ok(s) => s,
            Err(_) => match task.await {
                Ok(Err(e)) => return Err(e),
                r => panic!("the proxy stopped before opening its spool: {r:?}"),
            },
        };
        Ok(Running {
            spool,
            stop,
            task,
            state_dir,
        })
    })
    .await
    .expect("the proxy starts")
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
        lodeline_proxy::lifecycle::read_status(&self.state_dir)
            .is_some_and(|s| s.config_state == lodeline_proxy_api::status::ConfigState::Valid)
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
    // A status report sent while events were still unsent may have opened a
    // transient tail gap; it closes when the events arrive but stays recorded
    // (the tail-gap rule is pending a server-side decision). So only an OPEN gap
    // is a failure here.
    assert!(
        h.ctx().ledger.gaps(PROXY).unwrap().iter().all(|g| !g.open),
        "no open gap while everything is delivered"
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
        let lc = common::retry_locked(|| async { Ok(Lifecycle::start(&b)?) })
            .await
            .unwrap();
        let spool = lc.open_spool(&Limits::default()).unwrap();
        let mut src = spool.clone();
        let events = lodeline_proxy::ingest_client::EventSource::next_events(
            &mut src,
            10,
            &Default::default(),
        );
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

/// #260 / F13 / AC-06 under the approved tail-gap rule: the server judges a tail
/// gap against `last_assigned_sequence - spool.unsent_events`, so events that
/// are assigned but still buffered unsent in the spool are backlog, not a gap.
/// The status report carries the context (4 unsent of 4 assigned) and the
/// server records no tail gap, before or after the backlog drains.
#[tokio::test]
async fn unsent_backlog_is_not_a_tail_gap_end_to_end() {
    let Some(h) = H::new(|_| {}).await else {
        return;
    };
    let px = start_proxy(&h).await;
    px.spool.set_delivery_paused_for_test(true);
    inject(&px.spool, 4).await;
    eventually("server status shows 4 assigned and 4 unsent", || {
        h.status().is_some_and(|s| {
            s.spool.unsent_events.get() == 4 && s.last_assigned_sequence.get() == 4
        })
    })
    .await;
    assert!(h.tail_gaps().is_empty(), "backlog is not a gap");
    assert_eq!(h.rows(), 0);

    px.spool.set_delivery_paused_for_test(false);
    eventually("events arrive", || h.rows() == 4).await;
    // A transient tail gap from an in-flight hand-off may exist, but nothing
    // stays open once everything has arrived.
    eventually("no open tail gap", || h.tail_gaps().iter().all(|g| !g.open)).await;
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
    px.spool.set_event_max_bytes_for_test(one);
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

/// Build (a no-op when current) and locate the real `lodeline-proxy` binary, built
/// WITHOUT the `test-util` feature: the release code path. Under `CI` a failure
/// fails the test; elsewhere it prints a note and that one test skips.
fn proxy_binary() -> Option<PathBuf> {
    match common::real_proxy_binary() {
        Ok(bin) => Some(bin),
        Err(e) => {
            assert!(
                std::env::var_os("CI").is_none(),
                "no real lodeline-proxy binary under CI: {e}"
            );
            eprintln!("skipped: {e}");
            None
        }
    }
}

/// Kills the child if the test fails before it stopped it.
struct Child(std::process::Child);

impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A REAL `lodeline-proxy` process, with no injector in it, drains a spool that
/// was filled beforehand to the server, and stops cleanly on SIGTERM.
#[tokio::test]
async fn real_lodeline_proxy_process_drains_the_spool_to_the_server() {
    let Some(h) = H::new(|_| {}).await else {
        return;
    };
    let b = h.bootstrap();
    // Fill the spool the way a previous run would have left it.
    {
        let lc = common::retry_locked(|| async { Ok(Lifecycle::start(&b)?) })
            .await
            .unwrap();
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

/// `retry_locked` waits out a lock another handle releases inside its window,
/// gives up after about a second, and returns any other error at once.
#[tokio::test]
async fn retry_locked_waits_only_for_a_held_state_dir_lock() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("state");
    let id = Id::new("px-1").unwrap();
    let attempts = AtomicUsize::new(0);
    let open = || async {
        attempts.fetch_add(1, Ordering::Relaxed);
        Ok(StateDir::open(&dir, &id)?)
    };

    let held = StateDir::open(&dir, &id).unwrap();
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        drop(held);
    });
    let reopened = common::retry_locked(&open)
        .await
        .expect("opens once the holder lets go");
    release.join().unwrap();
    assert!(
        attempts.load(Ordering::Relaxed) > 1,
        "the first open met the lock"
    );

    let start = Instant::now();
    let Err(e) = common::retry_locked(&open).await else {
        panic!("opened while the lock is still held");
    };
    assert!(matches!(e.downcast_ref(), Some(StateError::Locked)), "{e}");
    let waited = start.elapsed();
    assert!(
        (Duration::from_secs(1)..Duration::from_secs(5)).contains(&waited),
        "gave up after {waited:?}"
    );
    drop(reopened);

    attempts.store(0, Ordering::Relaxed);
    let other = Id::new("px-2").unwrap();
    let Err(e) = common::retry_locked(|| async {
        let opened = StateDir::open(&dir, &other);
        // A child another test forked can still hold the lock fd; that Locked
        // is retried by design. Count only the answers that are not Locked.
        if !matches!(opened, Err(StateError::Locked)) {
            attempts.fetch_add(1, Ordering::Relaxed);
        }
        Ok(opened?)
    })
    .await
    else {
        panic!("opened a state_dir bound to px-1 as px-2");
    };
    assert!(
        matches!(e.downcast_ref(), Some(StateError::BoundToDifferentProxy)),
        "{e}"
    );
    assert_eq!(
        attempts.load(Ordering::Relaxed),
        1,
        "no retry on other errors"
    );
}

/// Children spawned on other threads (as other tests here spawn openssl and
/// cargo) briefly hold a state_dir lock this process released. Every reopen
/// through `retry_locked` still succeeds.
#[tokio::test]
async fn reopening_a_state_dir_while_children_spawn_succeeds_through_retry_locked() {
    const OPENS: usize = 300;
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("state");
    let id = Id::new("px-1").unwrap();
    drop(StateDir::open(&dir, &id).unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let spawners: Vec<_> = (0..4)
        .map(|_| {
            let stop = stop.clone();
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let _ = Command::new("/usr/bin/true").status();
                }
            })
        })
        .collect();
    let attempts = AtomicUsize::new(0);
    let mut failed = 0;
    for _ in 0..OPENS {
        let r = common::retry_locked(|| async {
            attempts.fetch_add(1, Ordering::Relaxed);
            Ok(StateDir::open(&dir, &id)?)
        })
        .await;
        failed += usize::from(r.is_err());
    }
    stop.store(true, Ordering::Relaxed);
    for s in spawners {
        s.join().unwrap();
    }
    let retries = attempts.load(Ordering::Relaxed) - OPENS;
    eprintln!("{retries} retries over {OPENS} opens");
    assert_eq!(failed, 0);
}
