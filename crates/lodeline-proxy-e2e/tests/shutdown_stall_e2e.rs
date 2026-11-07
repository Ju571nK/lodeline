#![cfg(unix)]
//! The production lifecycle (`lifecycle::run_tuned`) stops promptly while every
//! control-plane request is stalled. The tasks joined after the audit drain
//! (config sync, status report, ingest) watch the stop signal around each
//! request, so a slow control plane cannot hold the shutdown for the 10 s
//! per-attempt timeout and push it past the unit's `TimeoutStopSec`.

use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use lodeline_proxy::bootstrap::Bootstrap;
use lodeline_proxy::ingest_client::IngestParams;
use lodeline_proxy::lifecycle::{run_tuned, RunTuning};
use lodeline_proxy::route::TableHandle;
use lodeline_server::proxy::identity::proxy_san;
use tokio::sync::oneshot;

mod common;
use common::{client_ext, pki};

const PROXY: &str = "px-stall";

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_does_not_wait_for_a_stalled_control_plane() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let Some(pki) = pki("stl") else {
        return;
    };
    let cert = pki.leaf("proxyca", "proxy", PROXY, &client_ext(&proxy_san(PROXY)));
    // Accepts every connection and never answers, so each request stalls in its
    // TLS handshake until the per-attempt timeout.
    let hole = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = hole.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let seen = accepted.clone();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = hole.accept().await {
            seen.fetch_add(1, Ordering::SeqCst);
            held.push(s);
        }
    });
    let d = pki.dir.path();
    let secret = d.join("upstream-secret");
    std::fs::write(&secret, "UPSTREAM-SECRET-VALUE\n").unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    let yaml = format!(
        "proxy_id: {PROXY}\nlisten: \"127.0.0.1:0\"\n\
         control_plane_url: \"https://127.0.0.1:{port}\"\n\
         state_dir: {}\nclient_cert_file: {}\nclient_key_file: {}\nca_file: {}\n\
         credentials:\n  gh:\n    secret_file: {}\n    upstream_origins: [\"https://api.example.com\"]\n",
        d.join("proxy-state").display(),
        cert.0.display(),
        cert.1.display(),
        pki.p("hostca.crt").display(),
        secret.display(),
    );
    let b = Bootstrap::from_yaml(&yaml, d).expect("bootstrap loads");
    let (spool_tx, spool_rx) = oneshot::channel();
    let (stop, stop_rx) = oneshot::channel::<()>();
    let mut tune = RunTuning {
        listener: Some(std::net::TcpListener::bind("127.0.0.1:0").unwrap()),
        spool_out: Some(spool_tx),
        ..RunTuning::default()
    };
    tune.sync.poll = Duration::from_millis(50);
    tune.sync.retry = Duration::from_millis(50);
    tune.report.heartbeat = Duration::from_millis(50);
    tune.report.retry = Duration::from_millis(50);
    tune.report.min_spacing = Duration::from_millis(10);
    tune.ingest = IngestParams {
        poll: Duration::from_millis(10),
        retry: Duration::from_millis(10),
        max_backoff: Duration::from_millis(50),
        min_spacing: Duration::from_millis(10),
    };
    let task = tokio::spawn(async move {
        run_tuned(
            &b,
            TableHandle::new(),
            async move {
                let _ = stop_rx.await;
            },
            tune,
        )
        .await
    });
    let spool = spool_rx.await.expect("the lifecycle opened the spool");
    spool.inject_test_event("up-1").await.expect("admitted");
    // Config fetch, status report and event post are all in flight.
    let start = Instant::now();
    while accepted.load(Ordering::SeqCst) < 3 {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "requests reached the control plane: {}",
            accepted.load(Ordering::SeqCst)
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    drop(spool);
    let signaled = Instant::now();
    stop.send(()).unwrap();
    let r = tokio::time::timeout(Duration::from_secs(60), task)
        .await
        .expect("shutdown ends")
        .expect("proxy task joins");
    let took = signaled.elapsed();
    r.expect("proxy run returns Ok");
    // Measured 40 ms; a join that waited for a stalled request took 9.6 s.
    assert!(
        took < Duration::from_secs(5),
        "shutdown waited for the stalled control plane: {took:?}"
    );
}
