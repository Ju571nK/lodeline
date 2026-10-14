#![cfg(unix)]
//! T-11 S4 slice C (#275): the event ingest client over REAL mTLS (rustls on both sides, a CA plus
//! CA-signed leaves minted with the openssl CLI), through the same client as the
//! config fetch.
//!
//! The server side is a stub that records requests and answers with canned
//! statuses and bodies; the real `sigil-server` status route has its own tests.

use std::collections::{BTreeMap, HashSet, VecDeque};
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
use sigil_proxy::config_sync::MtlsFetcher;
use sigil_proxy::ingest_client::{
    EventSource, IngestClient, IngestOutcome, IngestParams, IngestTransport,
};
use sigil_proxy::limits::Limits;
use sigil_proxy::status_report::{CentralHealth, GapQueue};
use sigil_proxy_api::status::QuarantineCode;
use sigil_proxy_api::ProxyEvent;
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
    /// Answers for `POST /v1/proxy-events`, consumed in order; the last repeats.
    status_replies: Arc<Mutex<VecDeque<Reply>>>,
    #[allow(dead_code)]
    config: Arc<Mutex<Reply>>,
}

impl Stub {
    fn set_status(&self, r: Reply) {
        *self.status_replies.lock().unwrap() = VecDeque::from([r]);
    }
    fn event_posts(&self) -> Vec<Seen> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.method == "POST" && s.path == "/v1/proxy-events")
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
                        let r = if path == "/v1/proxy-events" {
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

fn event(n: u32) -> ProxyEvent {
    serde_json::from_value(json!({
        "schema_version": 1, "event_id": uid(n), "proxy_id": "px-1",
        "epoch_id": uid(5000), "sequence": n,
        "occurred_at": "2026-10-14T00:00:00Z",
        "event_type": "invocation.started",
        "payload": {"invocation_id": uid(7000 + n), "upstream_id": "up-1",
            "route_revision": 1, "protocol_version": "2025-11-25", "method": "ping",
            "actor": {"actor_id": "a1", "actor_kind": "non_human",
                "authentication_method": "bearer",
                "evidence_source": "proxy_credential_mapping"}}
    }))
    .unwrap()
}

#[derive(Default)]
struct Mem {
    unsent: Vec<ProxyEvent>,
    acked: Vec<String>,
    quarantined: Vec<(String, QuarantineCode)>,
}

impl EventSource for Mem {
    fn next_events(&mut self, max: usize, skip: &HashSet<String>) -> Vec<ProxyEvent> {
        self.unsent
            .iter()
            .filter(|e| !skip.contains(e.event_id.as_str()))
            .take(max)
            .cloned()
            .collect()
    }
    fn acknowledged(&mut self, ids: &[String]) {
        self.unsent
            .retain(|e| !ids.iter().any(|i| i == e.event_id.as_str()));
        self.acked.extend(ids.iter().cloned());
    }
    fn quarantined(&mut self, ids: &[String], code: QuarantineCode) {
        self.unsent
            .retain(|e| !ids.iter().any(|i| i == e.event_id.as_str()));
        self.quarantined
            .extend(ids.iter().map(|i| (i.clone(), code)));
    }
}

fn err(status: u16, code: &str, items: serde_json::Value) -> Reply {
    Reply::json(
        status,
        json!({"error": {"code": code, "message": "fixed", "items": items}}),
    )
}

fn params() -> IngestParams {
    IngestParams {
        poll: Duration::from_millis(10),
        retry: Duration::from_millis(10),
        max_backoff: Duration::from_millis(100),
        min_spacing: Duration::from_millis(1),
    }
}

async fn step(
    c: &mut IngestClient,
    f: &MtlsFetcher,
    s: &mut Mem,
) -> sigil_proxy::ingest_client::IngestStep {
    c.send_once(f, s, tokio::time::Instant::now()).await
}

/// Every answer class over real TLS, through the same client as the config fetch
/// and the status report: a client certificate, the `/v1/proxy-events` path, a
/// body the shared parser accepts.
#[tokio::test]
async fn every_answer_class_over_mtls() {
    let pki = pki_or_skip!("ing-mtls-ca");
    let dir = tempfile::tempdir().unwrap();
    let s = stub(
        &pki,
        Reply::new(200, b"{}".to_vec()),
        Reply::json(
            200,
            json!({"accepted_event_ids": [uid(1)], "duplicate_event_ids": [uid(2)]}),
        ),
    )
    .await;
    let (_b, fetcher) = bootstrap(dir.path(), &pki, s.port, &pki.ca());
    let gaps = GapQueue::new();
    let central = CentralHealth::new();
    let mut c = IngestClient::new(gaps.clone(), central.clone(), params());
    let mut src = Mem {
        unsent: (1..=2).map(event).collect(),
        ..Mem::default()
    };

    // 200: accepted and duplicate are both done
    let st = step(&mut c, &fetcher, &mut src).await;
    assert!(matches!(st.outcome, Some(IngestOutcome::Done { .. })));
    assert_eq!(src.acked, vec![uid(1), uid(2)]);
    assert!(central.last_ingest_ack_at().is_some());
    let posts = s.event_posts();
    assert_eq!(posts.len(), 1);
    assert!(posts[0].has_cert, "client certificate presented");
    let batch = sigil_proxy_api::parse_event_batch(&posts[0].body).unwrap();
    assert_eq!(batch.events.len(), 2);

    // 409 by item -> quarantined unchanged, gap queued, the rest resent
    src.unsent = (3..=5).map(event).collect();
    s.set_status(err(
        409,
        "conflict",
        json!([{"index": 1, "event_id": uid(4), "code": "sequence_conflict"}]),
    ));
    step(&mut c, &fetcher, &mut src).await;
    assert_eq!(
        src.quarantined,
        vec![(uid(4), QuarantineCode::SequenceConflict)]
    );
    assert_eq!(gaps.pending_ids().len(), 1);

    // 422 by index
    s.set_status(err(
        422,
        "semantic_invalid",
        json!([{"index": 0, "code": "semantic_invalid"}]),
    ));
    step(&mut c, &fetcher, &mut src).await;
    assert_eq!(src.quarantined.len(), 2);
    assert_eq!(
        src.quarantined[1],
        (uid(3), QuarantineCode::SemanticInvalid)
    );

    // 424 holds without quarantine
    s.set_status(Reply::json(
        424,
        json!({"error": {"code": "metadata_ref_pending", "message": "x",
            "items": [{"index": 0, "event_id": uid(5), "code": "metadata_ref_pending"}],
            "pending_metadata_refs": ["00000000-0000-8000-8000-000000000900"]}}),
    ));
    step(&mut c, &fetcher, &mut src).await;
    assert_eq!(c.held_events(), 1);
    assert_eq!(src.quarantined.len(), 2);

    // 429, 503 storage_limit, 503 storage_unavailable, 403 disabled, 404:
    // retried later, nothing lost, storage_limit is no outage
    src.unsent = vec![event(6)];
    for (reply, outage) in [
        (err(429, "rate_limited", json!([])), false),
        (err(503, "storage_limit", json!([])), false),
        (err(403, "disabled", json!([])), false),
        (err(404, "proxy_unknown", json!([])), false),
        (err(503, "storage_unavailable", json!([])), true),
    ] {
        s.set_status(reply);
        let st = step(&mut c, &fetcher, &mut src).await;
        assert_eq!(
            st.outcome.as_ref().unwrap().signals_central_outage(),
            outage,
            "{st:?}"
        );
        assert_eq!(src.unsent.len(), 1, "the event stays unsent");
    }
    assert_eq!(central.consecutive_failures(), 1);

    // 413 on a single event: quarantined
    s.set_status(err(413, "payload_too_large", json!([])));
    step(&mut c, &fetcher, &mut src).await;
    assert_eq!(src.quarantined.last().unwrap().0, uid(6));
    assert!(src.unsent.is_empty());
}

/// A server that does not answer is retried and never loses the event.
#[tokio::test]
async fn unreachable_server_keeps_events_and_counts_failures() {
    let pki = pki_or_skip!("ing-down-ca");
    let dir = tempfile::tempdir().unwrap();
    // an unbound port: nothing listens
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    let (_b, fetcher) = bootstrap(dir.path(), &pki, port, &pki.ca());
    let central = CentralHealth::new();
    let mut c = IngestClient::new(GapQueue::new(), central.clone(), params());
    let mut src = Mem {
        unsent: vec![event(1)],
        ..Mem::default()
    };
    let st = step(&mut c, &fetcher, &mut src).await;
    assert_eq!(st.outcome, Some(IngestOutcome::Unreachable));
    assert_eq!(src.unsent.len(), 1);
    assert_eq!(central.consecutive_failures(), 1);
    // the trait is what the loop uses
    let _: &dyn IngestTransport = &fetcher;
}

/// A server that trusts another CA is not a server: no events are sent over a
/// failed handshake.
#[tokio::test]
async fn untrusted_server_gets_nothing() {
    let pki = pki_or_skip!("ing-real-ca");
    let other = pki_or_skip!("ing-other-ca");
    let dir = tempfile::tempdir().unwrap();
    let s = stub(
        &pki,
        Reply::new(200, b"{}".to_vec()),
        Reply::new(200, b"{}".to_vec()),
    )
    .await;
    // the proxy trusts `other`'s CA only
    let (_b, fetcher) = bootstrap(dir.path(), &pki, s.port, &other.ca());
    let mut c = IngestClient::new(GapQueue::new(), CentralHealth::new(), params());
    let mut src = Mem {
        unsent: vec![event(1)],
        ..Mem::default()
    };
    let st = step(&mut c, &fetcher, &mut src).await;
    assert_eq!(st.outcome, Some(IngestOutcome::Unreachable));
    assert!(s.event_posts().is_empty());
}
