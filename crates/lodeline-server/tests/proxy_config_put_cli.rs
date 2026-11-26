//! `lodeline-server proxy config-put`: the BUILT binary against a real loopback
//! mutual-TLS server (an openssl test PKI, the router `main` uses). Every test
//! runs argv strings and reads the exit status, stdout and stderr.
// home-isolation: exempt (lodeline-server takes every path from its flags and config)

#![cfg(unix)]

use lodeline_proxy_api::verifier::verifier_for;
use lodeline_server::app::{build_router_with_proxy, AppState};
use lodeline_server::auth::ReadToken;
use lodeline_server::config::ServerConfig;
use lodeline_server::fleet_index::FleetIndex;
use lodeline_server::persist::HighWater;
use lodeline_server::proxy::identity::proxy_san;
use lodeline_server::proxy::verifiers::{Scope, VerifierEntry};
use lodeline_server::proxy::ProxyContext;
use lodeline_server::tls_accept::PeerCertAcceptor;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

const READ_TOKEN: &str = "read-bearer-token";
const T_ID: &str = "tok-identity-cfgput";
const T_CFG: &str = "tok-config-cfgput";
const CAP: usize = 1024 * 1024;

// ---- PKI helpers (openssl, as the other end-to-end tests) -----------------------

fn next_serial() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(1);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos() as u64);
    format!("0x{:x}", (t << 20) | N.fetch_add(1, Ordering::Relaxed))
}

fn run(args: &[&std::ffi::OsStr]) {
    let bin = lodeline_server::enroll::sign::resolve_openssl().expect("openssl must be installed");
    let o = Command::new(bin).args(args).output().unwrap();
    assert!(
        o.status.success(),
        "openssl {args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
}

fn genkey(path: &Path) {
    run(&[
        "genpkey".as_ref(),
        "-algorithm".as_ref(),
        "RSA".as_ref(),
        "-pkeyopt".as_ref(),
        "rsa_keygen_bits:2048".as_ref(),
        "-out".as_ref(),
        path.as_os_str(),
    ]);
}

fn make_ca(dir: &Path, name: &str) {
    let key = dir.join(format!("{name}.key"));
    genkey(&key);
    run(&[
        "req".as_ref(),
        "-x509".as_ref(),
        "-new".as_ref(),
        "-key".as_ref(),
        key.as_os_str(),
        "-days".as_ref(),
        "1".as_ref(),
        "-subj".as_ref(),
        format!("/CN=test-{name}").as_ref(),
        "-addext".as_ref(),
        "basicConstraints=critical,CA:TRUE".as_ref(),
        "-addext".as_ref(),
        "subjectKeyIdentifier=hash".as_ref(),
        "-out".as_ref(),
        dir.join(format!("{name}.crt")).as_os_str(),
    ]);
}

fn make_leaf(dir: &Path, ca: &str, name: &str, cn: &str, ext: &str) -> (PathBuf, PathBuf) {
    let key = dir.join(format!("{name}.key"));
    let csr = dir.join(format!("{name}.csr"));
    let crt = dir.join(format!("{name}.crt"));
    let extf = dir.join(format!("{name}.ext"));
    std::fs::write(&extf, ext).unwrap();
    genkey(&key);
    run(&[
        "req".as_ref(),
        "-new".as_ref(),
        "-key".as_ref(),
        key.as_os_str(),
        "-subj".as_ref(),
        format!("/CN={cn}").as_ref(),
        "-out".as_ref(),
        csr.as_os_str(),
    ]);
    run(&[
        "x509".as_ref(),
        "-req".as_ref(),
        "-in".as_ref(),
        csr.as_os_str(),
        "-CA".as_ref(),
        dir.join(format!("{ca}.crt")).as_os_str(),
        "-CAkey".as_ref(),
        dir.join(format!("{ca}.key")).as_os_str(),
        "-set_serial".as_ref(),
        next_serial().as_str().as_ref(),
        "-days".as_ref(),
        "1".as_ref(),
        "-extfile".as_ref(),
        extf.as_os_str(),
        "-out".as_ref(),
        crt.as_os_str(),
    ]);
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    (crt, key)
}

fn fingerprint(crt: &Path) -> String {
    let pem = std::fs::read(crt).unwrap();
    let mut rd = std::io::BufReader::new(&pem[..]);
    let certs: Vec<_> = rustls_pemfile::certs(&mut rd)
        .collect::<Result<_, _>>()
        .unwrap();
    blake3::hash(certs[0].as_ref()).to_hex().to_string()
}

fn entry(id: &str, token: &str, scope: Scope, fp: &str) -> VerifierEntry {
    VerifierEntry {
        key_id: id.into(),
        name: format!("{id}-name"),
        verifier: verifier_for(token),
        scope,
        caller_cert_fingerprint: fp.into(),
        not_after: None,
    }
}

fn write_secret(path: &Path, content: &str) {
    std::fs::write(path, content).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn tls_config(server_crt: &Path, server_key: &Path, bundle: &Path) -> rustls::ServerConfig {
    let read = |p: &Path| std::fs::read(p).unwrap();
    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(&read(server_crt)[..]))
        .collect::<Result<_, _>>()
        .unwrap();
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(&read(server_key)[..]))
        .unwrap()
        .unwrap();
    let cas: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(&read(bundle)[..]))
        .collect::<Result<_, _>>()
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    for c in cas {
        roots.add(c).unwrap();
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();
    rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .unwrap()
}

fn state(dir: &Path) -> Arc<AppState> {
    Arc::new(AppState {
        events_out_dir: dir.to_path_buf(),
        policy_bundle_path: dir.join("signed-policy.json"),
        rule_packs_bundle_path: None,
        artifacts_dir: None,
        high_water_path: dir.join(".high-water.json"),
        allowlist: parking_lot::RwLock::new(None),
        high_water: Mutex::new(HighWater::default()),
        fleet_index: FleetIndex::new(),
        read_token: ReadToken(Some(READ_TOKEN.into())),
        active_window_days: 7,
        audit_key: None,
        audit_head: Mutex::new(None),
        allowlist_path: None,
        enroll: None,
        events_require_cert_host_match: false,
    })
}

fn server_config(dir: &Path) -> ServerConfig {
    let p = |f: &str| dir.join(f).display().to_string();
    let y = format!(
        "bind: \"127.0.0.1:0\"\ntls_cert_path: {}\ntls_key_path: {}\nclient_ca_path: {}\n\
         events_out_dir: {}\npolicy_bundle_path: {}\n\
         proxy:\n  ca_path: {}\n  registry_path: {}\n  registry_init: true\n  management_verifiers: {}\n",
        p("server.crt"),
        p("server.key"),
        p("bundle.pem"),
        dir.display(),
        p("signed-policy.json"),
        p("proxyca.crt"),
        p("proxies.json"),
        p("verifiers.json"),
    );
    serde_yaml::from_str(&y).unwrap()
}

// ---- the server fixture ---------------------------------------------------------

/// One request the server saw: method, path, content type, body bytes.
type Seen = (String, String, Option<String>, Vec<u8>);

struct Fx {
    dir: tempfile::TempDir,
    port: u16,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Fx {
    fn p(&self, f: &str) -> PathBuf {
        self.dir.path().join(f)
    }

    async fn start() -> Fx {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        make_ca(d, "hostca");
        make_ca(d, "proxyca");
        let mut bundle = std::fs::read(d.join("hostca.crt")).unwrap();
        bundle.extend(std::fs::read(d.join("proxyca.crt")).unwrap());
        std::fs::write(d.join("bundle.pem"), bundle).unwrap();
        make_leaf(
            d,
            "hostca",
            "server",
            "localhost",
            "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n",
        );
        let (mcrt, _) = make_leaf(
            d,
            "hostca",
            "mgmt",
            "mgmt-operator",
            "subjectAltName=DNS:mgmt-operator\nextendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n",
        );
        let fp = fingerprint(&mcrt);
        std::fs::write(
            d.join("verifiers.json"),
            serde_json::to_vec(&serde_json::json!({"entries": [
                entry("idk", T_ID, Scope::Identity, &fp),
                entry("cfgk", T_CFG, Scope::Config, &fp),
            ]}))
            .unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(
            d.join("verifiers.json"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        write_secret(&d.join("id.tok"), T_ID);
        write_secret(&d.join("cfg.tok"), T_CFG);
        write_secret(&d.join("read.tok"), READ_TOKEN);

        let ctx = Arc::new(ProxyContext::load(&server_config(d)).unwrap().unwrap());
        let tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls_config(
            &d.join("server.crt"),
            &d.join("server.key"),
            &d.join("bundle.pem"),
        )));
        let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
        let log = seen.clone();
        let app = build_router_with_proxy(state(d), Some(ctx)).layer(axum::middleware::from_fn(
            move |req: axum::extract::Request, next: axum::middleware::Next| {
                let log = log.clone();
                async move {
                    let (parts, body) = req.into_parts();
                    let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
                    log.lock().unwrap().push((
                        parts.method.to_string(),
                        parts.uri.path().to_string(),
                        parts
                            .headers
                            .get("content-type")
                            .map(|v| v.to_str().unwrap().to_string()),
                        bytes.to_vec(),
                    ));
                    next.run(axum::extract::Request::from_parts(
                        parts,
                        axum::body::Body::from(bytes),
                    ))
                    .await
                }
            },
        ));
        let handle = axum_server::Handle::new();
        let h = handle.clone();
        tokio::spawn(async move {
            axum_server::bind("127.0.0.1:0".parse().unwrap())
                .handle(h)
                .acceptor(PeerCertAcceptor::new(tls))
                .serve(app.into_make_service())
                .await
                .unwrap();
        });
        let port = handle.listening().await.expect("server must bind").port();
        Fx { dir, port, seen }
    }

    /// A fixture with proxy `id` registered and fingerprinted through the binary.
    async fn with_proxy(id: &str) -> Fx {
        let fx = Fx::start().await;
        let (crt, _) = make_leaf(
            fx.dir.path(),
            "proxyca",
            id,
            id,
            &format!(
                "subjectAltName=DNS:{}\nextendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n",
                proxy_san(id)
            ),
        );
        let r = fx
            .cli(
                "register",
                "id.tok",
                &["--proxy-id", id, "--display-name", "Proxy"],
            )
            .await;
        assert!(r.status.success(), "{}", stderr(&r));
        let cert = crt.display().to_string();
        let r = fx
            .cli(
                "fingerprint",
                "id.tok",
                &["--proxy-id", id, "--cert-file", &cert],
            )
            .await;
        assert!(r.status.success(), "{}", stderr(&r));
        fx
    }

    /// Run `lodeline-server proxy <sub> <connection flags> <extra>` and wait.
    async fn cli(&self, sub: &str, token: &str, extra: &[&str]) -> Output {
        let mut args: Vec<String> = vec![
            "proxy".into(),
            sub.into(),
            "--server-url".into(),
            format!("https://127.0.0.1:{}", self.port),
            "--cert".into(),
            self.p("mgmt.crt").display().to_string(),
            "--key".into(),
            self.p("mgmt.key").display().to_string(),
            "--ca".into(),
            self.p("hostca.crt").display().to_string(),
            "--token-file".into(),
            self.p(token).display().to_string(),
        ];
        args.extend(extra.iter().map(|s| s.to_string()));
        tokio::task::spawn_blocking(move || {
            Command::new(env!("CARGO_BIN_EXE_lodeline-server"))
                .args(args)
                .output()
                .unwrap()
        })
        .await
        .unwrap()
    }

    /// `config-put` for `proxy_id` with the file `name` in the fixture folder.
    async fn put(&self, proxy_id: &str, name: &str) -> Output {
        let file = self.p(name).display().to_string();
        self.cli(
            "config-put",
            "cfg.tok",
            &["--proxy-id", proxy_id, "--file", &file],
        )
        .await
    }

    fn write(&self, name: &str, content: &[u8]) {
        std::fs::write(self.p(name), content).unwrap();
    }

    fn put_requests(&self) -> Vec<Seen> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.1.ends_with("/config"))
            .cloned()
            .collect()
    }
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

/// A request body whose key order and spacing a re-serialization would change.
fn body_text(proxy_id: &str, expected: u64, pad: usize) -> String {
    format!(
        "{{\n  \"config\" : {{{}\n    \"routes\": [{{\"route_id\": \"r1\", \"upstream_id\": \"up1\",\n      \"upstream_url\": \"https://api.example.com/mcp\", \"upstream_protocol\": \"2025-11-25\",\n      \"credential_ref\": \"gh\"}}],\n    \"proxy_id\": \"{proxy_id}\",\n    \"schema_version\": 1,\n    \"allowed_origins\": [\"https://app.example.com\"],\n    \"principals\": [{{\"principal_id\": \"claude\", \"routes\": [\"r1\"],\n      \"verifiers\": [{{\"key_id\": \"k1\", \"verifier\": \"{}\"}}]}}]\n  }},\n  \"expected_revision\": {expected}\n}}\n",
        " ".repeat(pad),
        verifier_for("tok-a"),
    )
}

// ---- tests ----------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn config_put_end_to_end_through_the_binary() {
    let fx = Fx::with_proxy("px1").await;
    fx.write("body.json", body_text("px1", 0, 0).as_bytes());

    let ok = fx.put("px1", "body.json").await;
    assert!(ok.status.success(), "{}", stderr(&ok));
    let answer: serde_json::Value = serde_json::from_str(stdout(&ok).trim()).unwrap();
    assert_eq!(answer["revision"], 1);
    assert_eq!(answer["config_hash"].as_str().map(str::len), Some(64));

    let audit = fx.cli("audit", "read.tok", &[]).await;
    assert!(audit.status.success(), "{}", stderr(&audit));
    let audit: serde_json::Value = serde_json::from_str(stdout(&audit).trim()).unwrap();
    let put = audit["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["action"] == "proxy.config_put")
        .expect("the config PUT is audited");
    assert_eq!(put["to_revision"], 1);
    assert_eq!(put["config_hash"], answer["config_hash"]);

    let again = fx.put("px1", "body.json").await;
    assert_eq!(again.status.code(), Some(1), "{}", stderr(&again));
    assert!(
        stderr(&again).contains("revision_conflict"),
        "{}",
        stderr(&again)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn config_put_sends_the_file_bytes_with_a_json_content_type() {
    let fx = Fx::with_proxy("px1").await;
    let body = body_text("px1", 0, 3);
    fx.write("body.json", body.as_bytes());
    let ok = fx.put("px1", "body.json").await;
    assert!(ok.status.success(), "{}", stderr(&ok));
    let sent = fx.put_requests();
    assert_eq!(sent.len(), 1, "one request reached the config route");
    let (method, path, content_type, bytes) = &sent[0];
    assert_eq!(method, "PUT");
    assert_eq!(path, "/v1/proxies/px1/config");
    assert_eq!(content_type.as_deref(), Some("application/json"));
    assert_eq!(
        bytes,
        body.as_bytes(),
        "the file bytes, not a re-serialization"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn config_put_refuses_a_proxy_id_mismatch() {
    let fx = Fx::with_proxy("px1").await;
    fx.write("body.json", body_text("px1", 0, 0).as_bytes());
    let bad = fx.put("px2", "body.json").await;
    assert_eq!(bad.status.code(), Some(1), "{}", stderr(&bad));
    let msg = stderr(&bad);
    assert!(
        msg.contains("px1") && msg.contains("px2") && msg.contains("does not match"),
        "{msg}"
    );
    assert!(fx.put_requests().is_empty(), "refused before any request");
    let ok = fx.put("px1", "body.json").await;
    assert!(ok.status.success(), "{}", stderr(&ok));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn config_put_refuses_a_file_over_one_mib() {
    let fx = Fx::with_proxy("px1").await;
    let base = body_text("px1", 0, 0).len();
    fx.write("over.json", body_text("px1", 0, CAP + 1 - base).as_bytes());
    fx.write("exact.json", body_text("px1", 0, CAP - base).as_bytes());
    assert_eq!(
        std::fs::metadata(fx.p("over.json")).unwrap().len() as usize,
        CAP + 1
    );
    assert_eq!(
        std::fs::metadata(fx.p("exact.json")).unwrap().len() as usize,
        CAP
    );

    let bad = fx.put("px1", "over.json").await;
    assert_eq!(bad.status.code(), Some(1), "{}", stderr(&bad));
    assert!(
        stderr(&bad).contains("larger than 1048576 bytes"),
        "{}",
        stderr(&bad)
    );
    assert!(fx.put_requests().is_empty(), "refused before any request");
    let ok = fx.put("px1", "exact.json").await;
    assert!(ok.status.success(), "{}", stderr(&ok));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn config_put_refuses_a_body_the_server_would_not_parse() {
    let fx = Fx::with_proxy("px1").await;
    fx.write("nocfg.json", br#"{"expected_revision": 0}"#);
    fx.write("body.json", body_text("px1", 0, 0).as_bytes());
    let bad = fx.put("px1", "nocfg.json").await;
    assert_eq!(bad.status.code(), Some(1), "{}", stderr(&bad));
    assert!(
        stderr(&bad).contains("not a valid config PUT body"),
        "{}",
        stderr(&bad)
    );
    assert!(fx.put_requests().is_empty(), "refused before any request");
    let ok = fx.put("px1", "body.json").await;
    assert!(ok.status.success(), "{}", stderr(&ok));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn config_put_has_no_token_argument() {
    let fx = Fx::with_proxy("px1").await;
    fx.write("body.json", body_text("px1", 0, 0).as_bytes());
    let file = fx.p("body.json").display().to_string();
    let ok = fx
        .cli(
            "config-put",
            "cfg.tok",
            &["--proxy-id", "px1", "--file", &file],
        )
        .await;
    assert!(ok.status.success(), "{}", stderr(&ok));
    let bad = fx
        .cli(
            "config-put",
            "cfg.tok",
            &["--proxy-id", "px1", "--file", &file, "--token", "x"],
        )
        .await;
    assert_eq!(bad.status.code(), Some(2));
    assert!(
        stderr(&bad).contains("unexpected argument '--token'"),
        "{}",
        stderr(&bad)
    );
}
