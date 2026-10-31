#![cfg(unix)]
//! T-13b (#306): the registry clients over REAL mTLS (rustls on both sides, a CA
//! plus CA-signed leaves minted with the openssl CLI), through
//! `MtlsRegistryTransport`. The server side is a stub that records requests.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper::{Response, StatusCode};
use hyper_util::rt::TokioIo;
use lodeline_proxy::bootstrap::{Bootstrap, Credential};
use lodeline_proxy::inventory::{
    InventoryEngine, InventoryLimits, ListingKey, ListingProgress, PageInput, ToolInput,
};
use lodeline_proxy::limits::Limits;
use lodeline_proxy::registry_client::{
    ConflictReporter, MtlsRegistryTransport, NoDependents, RegistryClient, RegistryParams,
    RegistryTransport, StepKind,
};
use lodeline_proxy::registry_key::ScopeKey;
use lodeline_proxy::registry_store::RegistryStore;
use lodeline_proxy::status_report::GapQueue;
use rustls::pki_types::CertificateDer;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use serde_json::json;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

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

fn read_certs(p: &Path) -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(p).unwrap(),
    ))
    .collect::<Result<_, _>>()
    .unwrap()
}

#[derive(Clone)]
struct Seen {
    path: String,
    has_cert: bool,
    content_type: String,
    body: Vec<u8>,
}

async fn stub(pki: &Pki, seen: Arc<Mutex<Vec<Seen>>>) -> u16 {
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
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let seen = seen.clone();
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
                    let seen = seen.clone();
                    async move {
                        let (parts, body) = req.into_parts();
                        let body = body
                            .collect()
                            .await
                            .map(|b| b.to_bytes())
                            .unwrap_or_default();
                        let path = parts.uri.path().to_string();
                        let ct = parts
                            .headers
                            .get("content-type")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_string();
                        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
                        let resp = if path == "/v1/proxy-metadata" {
                            let refs: Vec<_> = v["entries"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .map(|e| e["metadata_ref"].clone())
                                .collect();
                            json!({"registered_metadata_refs": refs, "duplicate_metadata_refs": []})
                        } else {
                            json!({})
                        };
                        seen.lock().unwrap().push(Seen {
                            path,
                            has_cert,
                            content_type: ct,
                            body: body.to_vec(),
                        });
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(serde_json::to_vec(&resp).unwrap())))
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
    port
}

fn bootstrap(dir: &Path, pki: &Pki, port: u16, trusted_ca: &Path) -> Bootstrap {
    let (cert, key) = pki.client_leaf();
    let secret = dir.join("secret");
    std::fs::write(&secret, "UPSTREAM-SECRET-VALUE\n").unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    Bootstrap {
        proxy_id: lodeline_proxy_api::Id::new("px-1").unwrap(),
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
    }
}

fn skip_or_pki(cn: &str) -> Option<Pki> {
    match Pki::new(cn) {
        Some(p) => Some(p),
        None => {
            assert!(
                std::env::var_os("CI").is_none(),
                "openssl CLI not found but CI is set"
            );
            eprintln!("skipped: openssl CLI not found");
            None
        }
    }
}

fn setup() -> (tempfile::TempDir, RegistryStore, InventoryEngine) {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let sd = d.path().join("state");
    std::fs::create_dir(&sd).unwrap();
    std::fs::set_permissions(&sd, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (store, _) = RegistryStore::open(&sd, "px-1").unwrap();
    let engine = InventoryEngine::new(
        store.clone(),
        "0f0f0f0f-1111-4222-8333-444444444444",
        InventoryLimits::default(),
    );
    (d, store, engine)
}

fn list_one(e: &mut InventoryEngine) {
    let def =
        json!({"name": "t", "description": "d", "inputSchema": {"type": "object"}}).to_string();
    let p = e
        .observe_page(
            &ListingKey {
                session: 1,
                scope: ScopeKey::live("px-1", "up-1", "cs-1"),
            },
            PageInput::Tools {
                request_cursor: None,
                tools: vec![ToolInput {
                    name: "t".into(),
                    definition: def,
                }],
                next_cursor: None,
            },
        )
        .unwrap();
    assert!(matches!(p, ListingProgress::Complete(_)));
}

#[tokio::test]
async fn upload_and_report_travel_over_mutual_tls() {
    let Some(pki) = skip_or_pki("test-ca") else {
        return;
    };
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let port = stub(&pki, seen.clone()).await;
    let (d, store, mut engine) = setup();
    let b = bootstrap(d.path(), &pki, port, &pki.ca());
    let transport = MtlsRegistryTransport::from_bootstrap(&b).unwrap();
    list_one(&mut engine);
    let mut client = RegistryClient::new(
        store.clone(),
        transport,
        ConflictReporter::new(store.clone(), GapQueue::new(), Box::new(NoDependents)),
        RegistryParams::default(),
    );
    for _ in 0..3 {
        client.sync_once().await;
    }
    assert_eq!(client.sync_once().await.kind, StepKind::Idle);
    let s = seen.lock().unwrap().clone();
    assert_eq!(
        s.iter().map(|x| x.path.as_str()).collect::<Vec<_>>(),
        ["/v1/proxy-metadata", "/v1/proxy-inventory"]
    );
    assert!(s
        .iter()
        .all(|x| x.has_cert && x.content_type == "application/json"));
    lodeline_proxy_api::parse_upload(&s[0].body).unwrap();
    lodeline_proxy_api::parse_inventory_report(&s[1].body).unwrap();
    assert_eq!(store.pending_entry_count().unwrap(), 0);
    assert!(store.pending_reports(5).unwrap().is_empty());
}

#[tokio::test]
async fn an_untrusted_server_gets_nothing_and_nothing_is_lost() {
    let Some(pki) = skip_or_pki("server-ca") else {
        return;
    };
    let Some(other) = skip_or_pki("other-ca") else {
        return;
    };
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let port = stub(&pki, seen.clone()).await;
    let (d, store, mut engine) = setup();
    // The client trusts a different CA than the one that signed the server.
    let b = bootstrap(d.path(), &pki, port, &other.ca());
    let transport = MtlsRegistryTransport::from_bootstrap(&b).unwrap();
    list_one(&mut engine);
    let reply = transport.post_metadata(b"{}".to_vec()).await;
    assert!(reply.is_none());
    assert!(seen.lock().unwrap().is_empty());
    assert_eq!(store.pending_entry_count().unwrap(), 1);
}
