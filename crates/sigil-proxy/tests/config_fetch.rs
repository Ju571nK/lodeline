#![cfg(unix)]
//! T-12c1: the control-plane fetch over REAL mTLS (rustls on both sides, a CA
//! plus CA-signed leaves minted with the openssl CLI) feeding the apply state
//! machine and the live listener.
//!
//! The server side here is a stub: it requires a client certificate, records the
//! request path and whether a client certificate was presented, and answers with a
//! canned status and body. The real `sigil-server` routes are covered by its own
//! e2e tests.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::CertificateDer;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use serde_json::json;
use sigil_proxy::bootstrap::{Bootstrap, Credential};
use sigil_proxy::config_sync::{
    ConfigSync, FetchResult, Fetcher, MtlsFetcher, SyncOutcome, MAX_CONFIG_BYTES,
};
use sigil_proxy::limits::Limits;
use sigil_proxy::route::TableHandle;
use sigil_proxy_api::status::ConfigState;
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
    delay: Duration,
}

impl Reply {
    fn new(status: u16, body: impl Into<Vec<u8>>) -> Reply {
        Reply {
            status,
            body: body.into(),
            delay: Duration::ZERO,
        }
    }
}

struct Stub {
    port: u16,
    /// (path, client certificate presented)
    seen: Arc<Mutex<Vec<(String, bool)>>>,
    reply: Arc<Mutex<Reply>>,
}

fn read_certs(p: &Path) -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(p).unwrap(),
    ))
    .collect::<Result<_, _>>()
    .unwrap()
}

/// mTLS stub: the client certificate is REQUIRED (the handshake fails without it).
async fn stub(pki: &Pki, reply: Reply) -> Stub {
    stub_with(pki, reply, pki.server_leaf()).await
}

async fn stub_with(pki: &Pki, reply: Reply, leaf: (PathBuf, PathBuf)) -> Stub {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let (crt, key) = leaf;
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
    let seen: Arc<Mutex<Vec<(String, bool)>>> = Arc::default();
    let reply = Arc::new(Mutex::new(reply));
    let (seen2, reply2) = (seen.clone(), reply.clone());
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let (seen, reply) = (seen2.clone(), reply2.clone());
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
                    let (seen, reply) = (seen.clone(), reply.clone());
                    async move {
                        seen.lock()
                            .unwrap()
                            .push((req.uri().path().to_string(), has_cert));
                        let r = reply.lock().unwrap().clone();
                        tokio::time::sleep(r.delay).await;
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
    Stub { port, seen, reply }
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

fn error_body(code: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"error": {"code": code, "message": "fixed"}})).unwrap()
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

// --------------------------------------------------------------------- tests

/// The proxy identity is presented, the path is the proxy-identity route, and the
/// document applies through the state machine into a live route table.
#[tokio::test]
async fn fetch_over_mtls_and_apply() {
    let pki = pki_or_skip!("cfg-fetch-ca");
    let dir = tempfile::tempdir().unwrap();
    let s = stub(&pki, Reply::new(200, config_body(7))).await;
    let (b, fetcher) = bootstrap(dir.path(), &pki, s.port, &pki.ca());

    let r = fetcher.fetch().await;
    let FetchResult::Config(bytes) = &r else {
        panic!("expected a config, got {r:?}");
    };
    assert_eq!(
        s.seen.lock().unwrap().as_slice(),
        &[("/v1/proxy-config".to_string(), true)],
        "one GET with a client certificate"
    );
    assert_eq!(bytes, &config_body(7));

    let table = TableHandle::new();
    let mut sync = ConfigSync::new(
        b.proxy_id.as_str(),
        b.credentials.clone(),
        b.limits.clone(),
        table.clone(),
        ConfigState::None,
    );
    assert_eq!(
        sync.on_fetch(tokio::time::Instant::now(), r),
        SyncOutcome::Applied { revision: 7 }
    );
    let t = table.current().unwrap();
    assert!(t.route("r1").unwrap().authenticate("tok-1").is_some());
}

/// Fixed server answers map to fixed categories; none of them applies anything.
#[tokio::test]
async fn status_mapping() {
    let pki = pki_or_skip!("cfg-status-ca");
    let dir = tempfile::tempdir().unwrap();
    let s = stub(&pki, Reply::new(200, config_body(1))).await;
    let (_b, fetcher) = bootstrap(dir.path(), &pki, s.port, &pki.ca());
    let set = |status: u16, body: Vec<u8>| {
        *s.reply.lock().unwrap() = Reply::new(status, body);
    };

    set(403, error_body("disabled"));
    assert_eq!(fetcher.fetch().await, FetchResult::Disabled);
    set(403, error_body("retired"));
    assert_eq!(fetcher.fetch().await, FetchResult::Disabled);
    // any other 403 is not a disable
    set(403, error_body("forbidden"));
    assert_eq!(fetcher.fetch().await, FetchResult::Failed);
    set(403, b"<html>".to_vec());
    assert_eq!(fetcher.fetch().await, FetchResult::Failed);
    // the boot gate is a retryable miss
    set(503, error_body("unavailable"));
    assert_eq!(fetcher.fetch().await, FetchResult::Unavailable);
    // unknown proxy / no config / server error: fetch failure
    set(404, error_body("proxy_unknown"));
    assert_eq!(fetcher.fetch().await, FetchResult::Failed);
    set(404, error_body("config_unavailable"));
    assert_eq!(fetcher.fetch().await, FetchResult::Failed);
    set(500, b"boom".to_vec());
    assert_eq!(fetcher.fetch().await, FetchResult::Failed);
    // a redirect is never followed and is a failure
    for code in [301, 302, 307, 308] {
        set(code, b"".to_vec());
        assert_eq!(fetcher.fetch().await, FetchResult::Failed, "{code}");
    }
    // the stub answered every request itself (no second hop)
    assert!(s
        .seen
        .lock()
        .unwrap()
        .iter()
        .all(|(p, _)| p == "/v1/proxy-config"));
}

#[tokio::test]
async fn oversized_body_is_a_fetch_failure() {
    let pki = pki_or_skip!("cfg-big-ca");
    let dir = tempfile::tempdir().unwrap();
    let s = stub(&pki, Reply::new(200, vec![b' '; MAX_CONFIG_BYTES + 1])).await;
    let (_b, fetcher) = bootstrap(dir.path(), &pki, s.port, &pki.ca());
    assert_eq!(fetcher.fetch().await, FetchResult::Failed);
}

#[tokio::test]
async fn slow_server_times_out() {
    let pki = pki_or_skip!("cfg-slow-ca");
    let dir = tempfile::tempdir().unwrap();
    let mut slow = Reply::new(200, config_body(1));
    slow.delay = Duration::from_secs(30);
    let s = stub(&pki, slow).await;
    let (_b, fetcher) = bootstrap(dir.path(), &pki, s.port, &pki.ca());
    let fetcher = fetcher.with_timeout(Duration::from_millis(300));
    let t0 = std::time::Instant::now();
    assert_eq!(fetcher.fetch().await, FetchResult::Failed);
    assert!(t0.elapsed() < Duration::from_secs(10));
}

/// A server whose certificate is not from the configured CA is not trusted: the
/// request is never sent. A closed port is a plain failure.
#[tokio::test]
async fn untrusted_server_and_closed_port_fail() {
    let pki = pki_or_skip!("cfg-trust-ca");
    let other = pki_or_skip!("cfg-other-ca");
    let dir = tempfile::tempdir().unwrap();
    let s = stub(&pki, Reply::new(200, config_body(1))).await;
    // the proxy trusts a different CA than the one that signed the server
    let (_b, fetcher) = bootstrap(dir.path(), &pki, s.port, &other.ca());
    assert_eq!(fetcher.fetch().await, FetchResult::Failed);
    assert!(s.seen.lock().unwrap().is_empty(), "no request was sent");

    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let (_b, fetcher) = bootstrap(dir.path(), &pki, port, &pki.ca());
    assert_eq!(fetcher.fetch().await, FetchResult::Failed);
}

/// The `run` wiring: the process fetches over mTLS on its own, installs the table
/// (the status file turns `valid` and `forwarding`), and stops on its shutdown
/// future.
#[tokio::test]
async fn run_fetches_and_publishes_valid() {
    let pki = pki_or_skip!("cfg-run-ca");
    let dir = tempfile::tempdir().unwrap();
    let s = stub(&pki, Reply::new(200, config_body(3))).await;
    let (b, _f) = bootstrap(dir.path(), &pki, s.port, &pki.ca());
    let table = TableHandle::new();
    let (b2, t2) = (b.clone(), table.clone());
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        sigil_proxy::lifecycle::run_with_shutdown(&b2, t2, async {
            let _ = stop_rx.await;
        })
        .await
    });

    let mut valid = false;
    for _ in 0..400 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let h = sigil_proxy::lifecycle::health(&b.state_dir);
        if table.current().is_some()
            && h.status
                .is_some_and(|s| s.config_state == ConfigState::Valid && s.forwarding)
        {
            valid = true;
            break;
        }
    }
    let _ = stop_tx.send(());
    let stopped = tokio::time::timeout(Duration::from_secs(20), task).await;
    assert!(valid, "config was not fetched and applied");
    assert_eq!(s.seen.lock().unwrap()[0].0, "/v1/proxy-config");
    stopped.expect("run did not stop").unwrap().unwrap();
}

/// A proxy key with any group/other bit is refused locally; nothing is sent.
#[tokio::test]
async fn loose_client_key_is_refused() {
    let pki = pki_or_skip!("cfg-key-ca");
    let dir = tempfile::tempdir().unwrap();
    let s = stub(&pki, Reply::new(200, config_body(1))).await;
    let (b, fetcher) = bootstrap(dir.path(), &pki, s.port, &pki.ca());
    // sanity: the 0600 key works
    assert!(matches!(fetcher.fetch().await, FetchResult::Config(_)));
    s.seen.lock().unwrap().clear();
    for mode in [0o640, 0o604, 0o660, 0o644] {
        std::fs::set_permissions(&b.client_key_file, std::fs::Permissions::from_mode(mode))
            .unwrap();
        assert_eq!(fetcher.fetch().await, FetchResult::Failed, "{mode:o}");
    }
    assert!(s.seen.lock().unwrap().is_empty(), "a request was sent");
}

/// Symlinked trust anchor or client key: refused (`O_NOFOLLOW`), nothing sent.
#[tokio::test]
async fn symlinked_ca_and_key_are_refused() {
    let pki = pki_or_skip!("cfg-link-ca");
    let dir = tempfile::tempdir().unwrap();
    let s = stub(&pki, Reply::new(200, config_body(1))).await;

    let ca_link = dir.path().join("ca-link.crt");
    std::os::unix::fs::symlink(pki.ca(), &ca_link).unwrap();
    let (_b, fetcher) = bootstrap(dir.path(), &pki, s.port, &ca_link);
    assert_eq!(fetcher.fetch().await, FetchResult::Failed, "symlinked ca");

    let (b, fetcher) = bootstrap(dir.path(), &pki, s.port, &pki.ca());
    assert!(matches!(fetcher.fetch().await, FetchResult::Config(_)));
    s.seen.lock().unwrap().clear();
    let real = dir.path().join("key.real");
    std::fs::rename(&b.client_key_file, &real).unwrap();
    std::os::unix::fs::symlink(&real, &b.client_key_file).unwrap();
    assert_eq!(fetcher.fetch().await, FetchResult::Failed, "symlinked key");
    assert!(s.seen.lock().unwrap().is_empty());
}

/// A server leaf whose SAN does not cover the connect host is not trusted.
#[tokio::test]
async fn server_san_mismatch_fails() {
    let pki = pki_or_skip!("cfg-san-ca");
    let dir = tempfile::tempdir().unwrap();
    let leaf = pki.leaf(
        "wrongsan",
        "basicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:other.example\n",
    );
    let s = stub_with(&pki, Reply::new(200, config_body(1)), leaf).await;
    let (_b, fetcher) = bootstrap(dir.path(), &pki, s.port, &pki.ca());
    assert_eq!(fetcher.fetch().await, FetchResult::Failed);
    assert!(s.seen.lock().unwrap().is_empty(), "no request was sent");
}

/// The stub requires a client certificate: a client that presents none gets no
/// HTTP answer and the handler never runs.
#[tokio::test]
async fn handshake_without_client_cert_is_refused() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let pki = pki_or_skip!("cfg-nocert-ca");
    let s = stub(&pki, Reply::new(200, config_body(1))).await;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    for c in read_certs(&pki.ca()) {
        roots.add(c).unwrap();
    }
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", s.port))
        .await
        .unwrap();
    let name = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();
    let mut answer = Vec::new();
    // TLS 1.3 may let the client finish before the server rejects it, so the
    // failure shows up on the first read or write; either way no HTTP comes back.
    if let Ok(mut tls) = connector.connect(name, tcp).await {
        let _ = tls
            .write_all(b"GET /v1/proxy-config HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await;
        let _ = tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut answer)).await;
    }
    assert!(
        !String::from_utf8_lossy(&answer).contains("HTTP/1.1"),
        "answered without a client certificate"
    );
    assert!(s.seen.lock().unwrap().is_empty(), "handler ran");
}
