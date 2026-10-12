#![cfg(unix)]
//! T-12c2: the status report over REAL mTLS (rustls on both sides, a CA plus
//! CA-signed leaves minted with the openssl CLI), through the same client as the
//! config fetch.
//!
//! The server side is a stub that records requests and answers with canned
//! statuses and bodies; the real `sigil-server` status route has its own tests.

use std::collections::{BTreeMap, VecDeque};
use std::convert::Infallible;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper::{Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::CertificateDer;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use serde_json::json;
use sigil_proxy::bootstrap::{Bootstrap, Credential};
use sigil_proxy::config_sync::{ConfigView, MtlsFetcher};
use sigil_proxy::limits::Limits;
use sigil_proxy::route::TableHandle;
use sigil_proxy::status_report::{GapQueue, ReportOutcome, Reporter, ReporterParams};
use sigil_proxy_api::status::ConfigState;
use sigil_proxy_api::GapReport;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

// ------------------------------------------------------------------- openssl

fn openssl() -> Option<PathBuf> {
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

fn run(ossl: &Path, args: &[&std::ffi::OsStr]) {
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
    fn new(cn: &str) -> Option<Pki> {
        let ossl = openssl()?;
        let dir = tempfile::tempdir().unwrap();
        let (key, crt) = (dir.path().join("ca.key"), dir.path().join("ca.crt"));
        run(
            &ossl,
            &[
                "genpkey".as_ref(),
                "-algorithm".as_ref(),
                "RSA".as_ref(),
                "-pkeyopt".as_ref(),
                "rsa_keygen_bits:2048".as_ref(),
                "-out".as_ref(),
                key.as_os_str(),
            ],
        );
        run(
            &ossl,
            &[
                "req".as_ref(),
                "-x509".as_ref(),
                "-new".as_ref(),
                "-key".as_ref(),
                key.as_os_str(),
                "-days".as_ref(),
                "2".as_ref(),
                "-set_serial".as_ref(),
                "1".as_ref(),
                "-subj".as_ref(),
                format!("/CN={cn}").as_ref(),
                "-addext".as_ref(),
                "basicConstraints=critical,CA:TRUE".as_ref(),
                "-out".as_ref(),
                crt.as_os_str(),
            ],
        );
        Some(Pki {
            dir,
            ossl,
            serial: AtomicUsize::new(10),
        })
    }

    fn ca(&self) -> PathBuf {
        self.dir.path().join("ca.crt")
    }

    /// CA-signed leaf (RSA-2048, `-set_serial`, never `-CAcreateserial`).
    fn leaf(&self, name: &str, ext: &str) -> (PathBuf, PathBuf) {
        let d = self.dir.path();
        let (key, csr, crt, extf) = (
            d.join(format!("{name}.key")),
            d.join(format!("{name}.csr")),
            d.join(format!("{name}.crt")),
            d.join(format!("{name}.ext")),
        );
        std::fs::write(&extf, ext).unwrap();
        run(
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
                format!("/CN={name}").as_ref(),
                "-out".as_ref(),
                csr.as_os_str(),
            ],
        );
        let serial = self.serial.fetch_add(1, Ordering::Relaxed).to_string();
        run(
            &self.ossl,
            &[
                "x509".as_ref(),
                "-req".as_ref(),
                "-in".as_ref(),
                csr.as_os_str(),
                "-CA".as_ref(),
                self.ca().as_os_str(),
                "-CAkey".as_ref(),
                d.join("ca.key").as_os_str(),
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

    fn server_leaf(&self) -> (PathBuf, PathBuf) {
        self.leaf(
            "server",
            "basicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n",
        )
    }

    fn client_leaf(&self) -> (PathBuf, PathBuf) {
        self.leaf(
            "client",
            "basicConstraints=critical,CA:FALSE\nextendedKeyUsage=clientAuth\nsubjectAltName=DNS:px-1.proxy.sigil.invalid\n",
        )
    }
}

// ---------------------------------------------------------------- stub server

#[derive(Clone)]
struct Reply {
    status: u16,
    body: Vec<u8>,
}

impl Reply {
    fn new(status: u16, body: impl Into<Vec<u8>>) -> Reply {
        Reply {
            status,
            body: body.into(),
        }
    }
    fn json(status: u16, v: serde_json::Value) -> Reply {
        Reply::new(status, serde_json::to_vec(&v).unwrap())
    }
}

#[derive(Clone)]
struct Seen {
    method: String,
    path: String,
    has_cert: bool,
    body: Vec<u8>,
}

struct Stub {
    port: u16,
    seen: Arc<Mutex<Vec<Seen>>>,
    /// Answers for `POST /v1/proxy-status`, consumed in order; the last repeats.
    status_replies: Arc<Mutex<VecDeque<Reply>>>,
    config: Arc<Mutex<Reply>>,
}

impl Stub {
    fn set_status(&self, r: Reply) {
        *self.status_replies.lock().unwrap() = VecDeque::from([r]);
    }
    fn status_posts(&self) -> Vec<Seen> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.method == "POST" && s.path == "/v1/proxy-status")
            .cloned()
            .collect()
    }
}

fn read_certs(p: &Path) -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(p).unwrap(),
    ))
    .collect::<Result<_, _>>()
    .unwrap()
}

/// mTLS stub: the client certificate is REQUIRED (the handshake fails without it).
async fn stub(pki: &Pki, config: Reply, status: Reply) -> Stub {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let (crt, key) = pki.server_leaf();
    let mut roots = RootCertStore::empty();
    for c in read_certs(&pki.ca()) {
        roots.add(c).unwrap();
    }
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .unwrap();
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
        std::fs::File::open(key).unwrap(),
    ))
    .unwrap()
    .unwrap();
    let cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(read_certs(&crt), key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let status_replies = Arc::new(Mutex::new(VecDeque::from([status])));
    let config = Arc::new(Mutex::new(config));
    let (seen2, status2, config2) = (seen.clone(), status_replies.clone(), config.clone());
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let (seen, status, config) = (seen2.clone(), status2.clone(), config2.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let has_cert = tls
                    .get_ref()
                    .1
                    .peer_certificates()
                    .is_some_and(|c| !c.is_empty());
                let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let (seen, status, config) = (seen.clone(), status.clone(), config.clone());
                    async move {
                        let (parts, body) = req.into_parts();
                        let body = body
                            .collect()
                            .await
                            .map(|b| b.to_bytes())
                            .unwrap_or_default();
                        let path = parts.uri.path().to_string();
                        seen.lock().unwrap().push(Seen {
                            method: parts.method.to_string(),
                            path: path.clone(),
                            has_cert,
                            body: body.to_vec(),
                        });
                        let r = if path == "/v1/proxy-status" {
                            let mut q = status.lock().unwrap();
                            if q.len() > 1 {
                                q.pop_front().unwrap()
                            } else {
                                q.front().cloned().unwrap()
                            }
                        } else {
                            config.lock().unwrap().clone()
                        };
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::from_u16(r.status).unwrap())
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(r.body)))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    Stub {
        port,
        seen,
        status_replies,
        config,
    }
}

fn bootstrap(dir: &Path, pki: &Pki, port: u16, trusted_ca: &Path) -> (Bootstrap, MtlsFetcher) {
    let (cert, key) = pki.client_leaf();
    let secret = dir.join("secret");
    std::fs::write(&secret, "UPSTREAM-SECRET-VALUE\n").unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    let b = Bootstrap {
        proxy_id: sigil_proxy_api::Id::new("px-1").unwrap(),
        listen: "127.0.0.1:0".parse().unwrap(),
        listener_tls: None,
        control_plane_url: format!("https://127.0.0.1:{port}"),
        state_dir: dir.join("state"),
        client_cert_file: cert,
        client_key_file: key,
        ca_file: trusted_ca.to_path_buf(),
        limits: Limits::default(),
        credentials: BTreeMap::from([(
            "gh".to_string(),
            Credential {
                secret_file: secret,
                upstream_origins: vec!["https://api.example.com".into()],
            },
        )]),
    };
    let f = MtlsFetcher::from_bootstrap(&b).unwrap();
    (b, f)
}

fn config_body(revision: i64) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema_version": 1, "proxy_id": "px-1", "revision": revision,
        "issued_at": "2026-10-11T00:00:00Z", "expires_at": "2026-10-11T00:05:00Z",
        "ttl_seconds": 300, "mode": "observe",
        "max_offline_retry_age_seconds": 2592000, "event_retention_seconds": 7776000,
        "allowed_origins": ["https://app.example.com"],
        "routes": [{"route_id": "r1", "upstream_id": "up-r1",
            "upstream_url": "https://api.example.com/mcp",
            "upstream_protocol": "2025-11-25", "credential_ref": "gh",
            "credential_scope_id": "cs-0123456789abcdef0123456789abcdef"}],
        "principals": [{"principal_id": "claude",
            "verifiers": [{"key_id": "k1", "verifier": sigil_proxy_api::verifier_for("tok-1")}],
            "routes": ["r1"]}],
    }))
    .unwrap()
}

macro_rules! pki_or_skip {
    ($cn:expr) => {
        match Pki::new($cn) {
            Some(p) => p,
            None => {
                // CI must never go green without exercising the TLS paths.
                assert!(
                    std::env::var_os("CI").is_none(),
                    "openssl CLI not found but CI is set"
                );
                eprintln!("skipped: openssl CLI not found");
                return;
            }
        }
    };
}

fn uid(n: u32) -> String {
    format!("00000000-0000-4000-8000-{n:012x}")
}

fn gap(n: u32) -> GapReport {
    serde_json::from_value(json!({
        "kind": "event_quarantined", "gap_id": uid(n),
        "detected_at": "2026-10-11T00:00:00Z", "event_ids": [uid(900)],
        "code": "semantic_invalid"}))
    .unwrap()
}

fn none_view() -> ConfigView {
    ConfigView {
        state: ConfigState::None,
        last_update_error: None,
        applied_revision: None,
        config_hash: None,
        observed_revision: None,
        expires_at: None,
        max_offline_retry_age_seconds: None,
        event_retention_seconds: None,
    }
}

fn err(code: &str, items: serde_json::Value) -> Reply {
    Reply::json(
        match code {
            "storage_limit" | "storage_unavailable" => 503,
            "semantic_invalid" => 422,
            "conflict" => 409,
            _ => 403,
        },
        json!({"error": {"code": code, "message": "fixed", "items": items}}),
    )
}

fn ids(v: &[u32]) -> Vec<String> {
    v.iter().map(|n| uid(*n)).collect()
}

fn reporter(q: &GapQueue) -> Reporter {
    Reporter::new("px-1", &uid(5), q.clone(), ReporterParams::default())
}

// --------------------------------------------------------------------- tests

/// The report goes out over the SAME client as the config fetch: a client
/// certificate, the proxy-status path, a body the shared parser accepts.
#[tokio::test]
async fn report_over_mtls_reuses_the_config_client() {
    let pki = pki_or_skip!("st-mtls-ca");
    let dir = tempfile::tempdir().unwrap();
    let s = stub(
        &pki,
        Reply::new(200, config_body(7)),
        Reply::json(
            200,
            json!({"state_applied": true, "acknowledged_gap_ids": [uid(1)], "duplicate_gap_ids": []}),
        ),
    )
    .await;
    let (_b, fetcher) = bootstrap(dir.path(), &pki, s.port, &pki.ca());
    let q = GapQueue::new();
    q.push(gap(1)).unwrap();
    let mut r = reporter(&q);
    let o = r.send_once(&fetcher, &none_view()).await.unwrap();
    assert_eq!(
        o,
        ReportOutcome::Accepted {
            acknowledged: ids(&[1]),
            duplicate: vec![]
        }
    );
    assert!(q.pending_ids().is_empty());
    let posts = s.status_posts();
    assert_eq!(posts.len(), 1);
    assert!(posts[0].has_cert, "client certificate presented");
    let st = sigil_proxy_api::parse_status(&posts[0].body).unwrap();
    assert_eq!(st.proxy_id.as_str(), "px-1");
    assert_eq!(st.gaps.len(), 1);
    // the config fetch still works through the same client
    assert!(matches!(
        sigil_proxy::config_sync::Fetcher::fetch(&fetcher).await,
        sigil_proxy::config_sync::FetchResult::Config(_)
    ));
}

/// Every response class over real TLS.
#[tokio::test]
async fn every_response_class_is_handled() {
    let pki = pki_or_skip!("st-class-ca");
    let dir = tempfile::tempdir().unwrap();
    let s = stub(
        &pki,
        Reply::new(200, config_body(1)),
        Reply::new(500, b"x".to_vec()),
    )
    .await;
    let (_b, fetcher) = bootstrap(dir.path(), &pki, s.port, &pki.ca());
    let v = none_view();

    // 503 storage_limit: not an outage; only the refused gap stays pending, and
    // the next report carries only it.
    let q = GapQueue::new();
    for n in 1..=3 {
        q.push(gap(n)).unwrap();
    }
    let mut r = reporter(&q);
    s.set_status(err(
        "storage_limit",
        json!([{"index": 1, "gap_id": uid(2), "code": "storage_limit"}]),
    ));
    let o = r.send_once(&fetcher, &v).await.unwrap();
    assert!(matches!(o, ReportOutcome::StorageLimit { .. }));
    assert!(!o.signals_central_outage());
    assert_eq!(q.pending_ids(), ids(&[2]));
    s.set_status(Reply::json(
        200,
        json!({"state_applied": true, "acknowledged_gap_ids": [uid(2)], "duplicate_gap_ids": []}),
    ));
    r.send_once(&fetcher, &v).await.unwrap();
    assert!(q.pending_ids().is_empty());
    let posts = s.status_posts();
    let last = sigil_proxy_api::parse_status(&posts.last().unwrap().body).unwrap();
    assert_eq!(last.gaps.len(), 1, "only the refused gap was resent");
    for p in &posts {
        let st = sigil_proxy_api::parse_status(&p.body).unwrap();
        assert!(st
            .gaps
            .iter()
            .all(|g| !matches!(g, GapReport::CentralOutage(_))));
    }

    // 422 with an item: that gap only.
    let q = GapQueue::new();
    for n in 1..=3 {
        q.push(gap(n)).unwrap();
    }
    let mut r = reporter(&q);
    s.set_status(err(
        "semantic_invalid",
        json!([{"index": 0, "code": "semantic_invalid"}]),
    ));
    let o = r.send_once(&fetcher, &v).await.unwrap();
    assert!(matches!(
        o,
        ReportOutcome::Quarantine {
            whole_report: false,
            ..
        }
    ));
    assert_eq!(q.quarantined_ids(), ids(&[1]));
    assert_eq!(q.pending_ids(), ids(&[2, 3]));

    // 422 without items: unattributed. Nothing is quarantined; the gaps stay
    // pending and the next report is a snapshot-only probe.
    let q = GapQueue::new();
    for n in 1..=3 {
        q.push(gap(n)).unwrap();
    }
    let mut r = reporter(&q);
    s.set_status(Reply::json(
        422,
        json!({"error": {"code": "semantic_invalid", "message": "fixed"}}),
    ));
    let o = r.send_once(&fetcher, &v).await.unwrap();
    assert_eq!(o, ReportOutcome::Ambiguous);
    assert!(q.quarantined_ids().is_empty());
    assert_eq!(q.pending_ids(), ids(&[1, 2, 3]));
    r.send_once(&fetcher, &v).await.unwrap();
    let last = sigil_proxy_api::parse_status(&s.status_posts().last().unwrap().body).unwrap();
    assert!(last.gaps.is_empty(), "probe carries no gaps");
    assert_eq!(
        q.pending_ids(),
        ids(&[1, 2, 3]),
        "snapshot also 422: gaps stay"
    );

    // 409: the named gap is quarantined, the rest resent.
    let q = GapQueue::new();
    for n in 1..=2 {
        q.push(gap(n)).unwrap();
    }
    let mut r = reporter(&q);
    s.set_status(err(
        "conflict",
        json!([{"index": 1, "gap_id": uid(2), "code": "conflict"}]),
    ));
    r.send_once(&fetcher, &v).await.unwrap();
    assert_eq!(q.quarantined_ids(), ids(&[2]));
    assert_eq!(q.pending_ids(), ids(&[1]));

    // 403 disabled / retired: rejected, nothing dropped, local state untouched.
    for code in ["disabled", "retired"] {
        let q = GapQueue::new();
        q.push(gap(1)).unwrap();
        let mut r = reporter(&q);
        s.set_status(err(code, json!([])));
        let o = r.send_once(&fetcher, &v).await.unwrap();
        assert_eq!(o, ReportOutcome::Rejected);
        assert_eq!(q.pending_ids(), ids(&[1]));
    }

    // Other 503, 500, 429: retryable, nothing dropped.
    for reply in [
        err("storage_unavailable", json!([])),
        Reply::new(500, b"boom".to_vec()),
        Reply::new(429, b"".to_vec()),
        Reply::new(302, b"".to_vec()),
    ] {
        let q = GapQueue::new();
        q.push(gap(1)).unwrap();
        let mut r = reporter(&q);
        s.set_status(reply);
        let o = r.send_once(&fetcher, &v).await.unwrap();
        assert!(matches!(
            o,
            ReportOutcome::Unavailable | ReportOutcome::Retry
        ));
        assert_eq!(q.pending_ids(), ids(&[1]));
    }
}

/// No answer (closed port, untrusted server): retryable, nothing dropped.
#[tokio::test]
async fn transport_failure_is_retryable() {
    let pki = pki_or_skip!("st-tf-ca");
    let other = pki_or_skip!("st-tf-other-ca");
    let dir = tempfile::tempdir().unwrap();
    let s = stub(
        &pki,
        Reply::new(200, config_body(1)),
        Reply::new(200, b"{}".to_vec()),
    )
    .await;
    // the client trusts a different CA: the handshake fails
    let (_b, untrusting) = bootstrap(dir.path(), &pki, s.port, &other.ca());
    let q = GapQueue::new();
    q.push(gap(1)).unwrap();
    let mut r = reporter(&q);
    let o = r.send_once(&untrusting, &none_view()).await.unwrap();
    assert_eq!(o, ReportOutcome::Unreachable);
    assert!(o.signals_central_outage());
    assert_eq!(q.pending_ids(), ids(&[1]));
    assert!(s.status_posts().is_empty());
    // a closed port
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let (_b, f) = bootstrap(dir.path(), &pki, closed, &pki.ca());
    assert_eq!(
        r.send_once(&f, &none_view()).await.unwrap(),
        ReportOutcome::Unreachable
    );
}

/// A slow server hits the per-attempt bound and counts as no answer.
#[tokio::test]
async fn silent_server_times_out() {
    let pki = pki_or_skip!("st-slow-ca");
    let dir = tempfile::tempdir().unwrap();
    // A listener that accepts and never answers (no TLS): the handshake stalls.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let hold = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((c, _)) = l.accept().await {
            held.push(c);
        }
    });
    let (_b, f) = bootstrap(dir.path(), &pki, port, &pki.ca());
    let f = f.with_timeout(Duration::from_millis(300));
    let q = GapQueue::new();
    q.push(gap(1)).unwrap();
    let mut r = reporter(&q);
    assert_eq!(
        r.send_once(&f, &none_view()).await.unwrap(),
        ReportOutcome::Unreachable
    );
    assert_eq!(q.pending_ids(), ids(&[1]));
    hold.abort();
}

/// The production wiring: `run_with_shutdown` fetches, applies, and the status
/// reporter then POSTs a report carrying the applied revision and hash, without
/// waiting a heartbeat.
#[tokio::test]
async fn run_reports_the_applied_config() {
    let pki = pki_or_skip!("st-run-ca");
    let dir = tempfile::tempdir().unwrap();
    let s = stub(
        &pki,
        Reply::new(200, config_body(3)),
        Reply::json(
            200,
            json!({"state_applied": true, "acknowledged_gap_ids": [], "duplicate_gap_ids": []}),
        ),
    )
    .await;
    let (b, _f) = bootstrap(dir.path(), &pki, s.port, &pki.ca());
    let want_hash = sigil_proxy_api::parse_config(&config_body(3))
        .unwrap()
        .config_hash()
        .as_str()
        .to_string();
    let table = TableHandle::new();
    let (b2, t2) = (b.clone(), table.clone());
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        sigil_proxy::lifecycle::run_with_shutdown(&b2, t2, async {
            let _ = stop_rx.await;
        })
        .await
    });

    let mut found = None;
    for _ in 0..400 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        found = s
            .status_posts()
            .into_iter()
            .filter_map(|p| sigil_proxy_api::parse_status(&p.body).ok())
            .find(|st| st.config.state == ConfigState::Valid);
        if found.is_some() {
            break;
        }
    }
    let _ = stop_tx.send(());
    let stopped = tokio::time::timeout(Duration::from_secs(20), task).await;
    let st = found.expect("no valid status report was sent");
    assert_eq!(st.config.applied_revision.unwrap().get(), 3);
    assert_eq!(st.config.config_hash.unwrap().as_str(), want_hash);
    assert_eq!(st.config.event_retention_seconds, Some(7_776_000));
    assert_eq!(st.proxy_id.as_str(), "px-1");
    assert!(s.status_posts().iter().all(|p| p.has_cert));
    // The sequence bound is persisted on the production path, above what was sent.
    let bound: serde_json::Value =
        serde_json::from_slice(&std::fs::read(b.state_dir.join("sequence.json")).unwrap()).unwrap();
    let max_sent = s
        .status_posts()
        .iter()
        .filter_map(|p| sigil_proxy_api::parse_status(&p.body).ok())
        .map(|st| st.status_sequence.get())
        .max()
        .unwrap();
    assert!(bound["bound"].as_i64().unwrap() > max_sent);
    stopped.expect("run did not stop").unwrap().unwrap();
    let _ = &s.config;
    let _ = &s.status_replies;
}
