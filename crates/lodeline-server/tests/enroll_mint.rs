//! #553: `POST /v1/enroll-tokens`. Real mutual TLS (an openssl test PKI, the
//! `PeerCertAcceptor` and router `main` uses), the real enrollment listener for the
//! redeem, and the real binary for the start refusal and `verifier-new`.

use lodeline_core::audit::GENESIS_PREV_HASH;
use lodeline_fleet_api::mint::{MintResponse, MINT_PATH};
use lodeline_proxy_api::verifier::verifier_for;
use lodeline_server::app::{build_router, build_router_with_proxy, AppState};
use lodeline_server::auth::ReadToken;
use lodeline_server::config::{EnrollMintConfig, ServerConfig};
use lodeline_server::enroll::audit::SignedEnrollmentRecord;
use lodeline_server::enroll::mint::MintApi;
use lodeline_server::enroll::tokens::{hash_token, RedeemErr, TokenStore};
use lodeline_server::enroll::{listener, EnrollState};
use lodeline_server::fleet_index::FleetIndex;
use lodeline_server::persist::HighWater;
use lodeline_server::proxy::verifiers::{MgmtAuth, Scope, VerifierEntry};
use lodeline_server::proxy::ProxyContext;
use lodeline_server::tls_accept::PeerCertAcceptor;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, Once};
use time::{Duration, OffsetDateTime};

const T_MINT: &str = "tok-mint-console";
const T_OTHER: &str = "tok-other-entry";
const T_EXPIRED: &str = "tok-expired-entry";
const T_CONFIG: &str = "tok-config-scope";
const T_READ: &str = "tok-the-read-bearer";

// ---- logging: every log line of this test binary goes to one buffer -----------

static LOG: Mutex<Vec<u8>> = Mutex::new(Vec::new());

struct LogWriter;
impl std::io::Write for LogWriter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        LOG.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn init_logging() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let _ = tracing::subscriber::set_global_default(
            tracing_subscriber::fmt()
                .with_writer(|| LogWriter)
                .with_ansi(false)
                .with_max_level(tracing::Level::INFO)
                .finish(),
        );
    });
}

fn logged() -> String {
    String::from_utf8_lossy(&LOG.lock().unwrap()).into_owned()
}

// ---- PKI helpers (openssl, as the other end-to-end tests) -----------------------

fn next_serial() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(1);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos() as u64);
    format!("0x{:x}", (t << 20) | N.fetch_add(1, Ordering::Relaxed))
}

fn openssl() -> PathBuf {
    lodeline_server::enroll::sign::resolve_openssl().expect("openssl must be installed")
}

fn run(args: &[&std::ffi::OsStr]) {
    let o = Command::new(openssl()).args(args).output().unwrap();
    assert!(
        o.status.success(),
        "openssl {args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
}

fn set_mode(p: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    #[cfg(not(unix))]
    let _ = (p, mode);
}

/// A CA:TRUE certificate named `name`.crt/.key in `dir`.
fn make_ca(dir: &Path, name: &str) {
    let (key, crt) = (
        dir.join(format!("{name}.key")),
        dir.join(format!("{name}.crt")),
    );
    run(&[
        "genpkey".as_ref(),
        "-algorithm".as_ref(),
        "RSA".as_ref(),
        "-pkeyopt".as_ref(),
        "rsa_keygen_bits:2048".as_ref(),
        "-out".as_ref(),
        key.as_os_str(),
    ]);
    run(&[
        "req".as_ref(),
        "-x509".as_ref(),
        "-new".as_ref(),
        "-key".as_ref(),
        key.as_os_str(),
        "-days".as_ref(),
        "3650".as_ref(),
        "-subj".as_ref(),
        format!("/CN=test-{name}").as_ref(),
        "-addext".as_ref(),
        "basicConstraints=critical,CA:TRUE".as_ref(),
        "-out".as_ref(),
        crt.as_os_str(),
    ]);
    set_mode(&key, 0o600);
}

/// A leaf signed by CA `ca`, key and certificate files `name`.key/.crt.
fn make_leaf(dir: &Path, ca: &str, name: &str, cn: &str, ext: &str) -> (PathBuf, PathBuf) {
    let key = dir.join(format!("{name}.key"));
    let csr = dir.join(format!("{name}.csr"));
    let crt = dir.join(format!("{name}.crt"));
    let extf = dir.join(format!("{name}.ext"));
    std::fs::write(&extf, ext).unwrap();
    run(&[
        "genpkey".as_ref(),
        "-algorithm".as_ref(),
        "RSA".as_ref(),
        "-pkeyopt".as_ref(),
        "rsa_keygen_bits:2048".as_ref(),
        "-out".as_ref(),
        key.as_os_str(),
    ]);
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
        "3".as_ref(),
        "-extfile".as_ref(),
        extf.as_os_str(),
        "-out".as_ref(),
        crt.as_os_str(),
    ]);
    (crt, key)
}

const CLIENT_EXT: &str = "extendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n";
const SERVER_EXT: &str =
    "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n";

fn make_csr(dir: &Path, cn: &str) -> String {
    let key = dir.join(format!("{cn}.csr.key"));
    let csr = dir.join(format!("{cn}.csr"));
    run(&[
        "genpkey".as_ref(),
        "-algorithm".as_ref(),
        "RSA".as_ref(),
        "-pkeyopt".as_ref(),
        "rsa_keygen_bits:2048".as_ref(),
        "-out".as_ref(),
        key.as_os_str(),
    ]);
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
    std::fs::read_to_string(&csr).unwrap()
}

/// blake3 of the first certificate's DER, computed from the PEM file.
fn fingerprint(crt: &Path) -> String {
    let data = std::fs::read(crt).unwrap();
    let der = rustls_pemfile::certs(&mut std::io::BufReader::new(&data[..]))
        .next()
        .unwrap()
        .unwrap();
    blake3::hash(der.as_ref()).to_hex().to_string()
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

fn client(dir: &Path, crt: &Path, key: &Path) -> reqwest::Client {
    let mut id = std::fs::read(key).unwrap();
    id.extend_from_slice(&std::fs::read(crt).unwrap());
    reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(dir.join("ca.crt")).unwrap()).unwrap(),
        )
        .identity(reqwest::Identity::from_pem(&id).unwrap())
        .build()
        .unwrap()
}

// ---- the fixture ------------------------------------------------------------------

fn entry(id: &str, token: &str, scope: Scope, fp: &str, na: Option<&str>) -> VerifierEntry {
    VerifierEntry {
        key_id: id.into(),
        name: format!("{id}-name"),
        verifier: verifier_for(token),
        scope,
        caller_cert_fingerprint: fp.into(),
        not_after: na.map(str::to_string),
    }
}

fn write_verifiers(path: &Path, entries: &[VerifierEntry]) {
    // Write and rename, as the docs say, so a reader never sees a half file.
    let tmp = path.with_extension("tmp");
    std::fs::write(
        &tmp,
        serde_json::to_vec(&serde_json::json!({"entries": entries})).unwrap(),
    )
    .unwrap();
    set_mode(&tmp, 0o600);
    std::fs::rename(&tmp, path).unwrap();
}

#[derive(Clone, Copy)]
struct Opt {
    mint: bool,
    proxy: bool,
}

struct Fx {
    dir: tempfile::TempDir,
    st: Arc<AppState>,
    port: u16,
    enroll_port: u16,
    mint: (PathBuf, PathBuf),
    other: (PathBuf, PathBuf),
    host: (PathBuf, PathBuf),
    proxy: (PathBuf, PathBuf),
    ctx: Option<Arc<ProxyContext>>,
}

impl Fx {
    fn p(&self, f: &str) -> PathBuf {
        self.dir.path().join(f)
    }
    fn en(&self) -> &EnrollState {
        self.st.enroll.as_ref().unwrap()
    }
    fn tokens(&self) -> PathBuf {
        self.en().tokens_path.clone()
    }
    fn audit(&self) -> PathBuf {
        self.en().audit_path.clone()
    }
    fn mint_client(&self) -> reqwest::Client {
        client(self.dir.path(), &self.mint.0, &self.mint.1)
    }
    fn other_client(&self) -> reqwest::Client {
        client(self.dir.path(), &self.other.0, &self.other.1)
    }
    fn host_client(&self) -> reqwest::Client {
        client(self.dir.path(), &self.host.0, &self.host.1)
    }
    fn proxy_client(&self) -> reqwest::Client {
        client(self.dir.path(), &self.proxy.0, &self.proxy.1)
    }

    async fn new() -> Fx {
        Self::start(Opt {
            mint: true,
            proxy: false,
        })
        .await
    }

    async fn start(opt: Opt) -> Fx {
        init_logging();
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        make_ca(d, "ca");
        make_leaf(d, "ca", "server", "127.0.0.1", SERVER_EXT);
        let mint = make_leaf(d, "ca", "mint", "lodeline-console-mint", CLIENT_EXT);
        let other = make_leaf(d, "ca", "other", "lodeline-other", CLIENT_EXT);
        let host = make_leaf(d, "ca", "host", HOST_CN, CLIENT_EXT);
        let mut bundle = std::fs::read(d.join("ca.crt")).unwrap();
        let proxy = if opt.proxy {
            make_ca(d, "proxyca");
            bundle.extend(std::fs::read(d.join("proxyca.crt")).unwrap());
            make_leaf(d, "proxyca", "px", "px-one", CLIENT_EXT)
        } else {
            (PathBuf::new(), PathBuf::new())
        };
        std::fs::write(d.join("bundle.pem"), bundle).unwrap();

        let (mint_fp, other_fp) = (fingerprint(&mint.0), fingerprint(&other.0));
        write_verifiers(
            &d.join("mint-verifiers.json"),
            &[
                entry("mint-1", T_MINT, Scope::Enroll, &mint_fp, None),
                entry("other-1", T_OTHER, Scope::Enroll, &other_fp, None),
                entry(
                    "expired-1",
                    T_EXPIRED,
                    Scope::Enroll,
                    &mint_fp,
                    Some("2000-01-01T00:00:00Z"),
                ),
            ],
        );

        let ctx = if opt.proxy {
            let reg = d.join("proxies.json");
            lodeline_server::proxy::registry::ProxyRegistry::open(&reg, true)
                .unwrap()
                .seed_for_test(lodeline_server::proxy::registry::ProxyRecord {
                    proxy_id: "px-one".into(),
                    display_name: "px".into(),
                    state: lodeline_server::proxy::registry::ProxyState::Active,
                    fp_current: Some(fingerprint(&proxy.0)),
                    fp_next: None,
                    created_at: "2026-10-11T00:00:00Z".into(),
                    updated_at: "2026-10-11T00:00:00Z".into(),
                })
                .unwrap();
            let cfg = Self::config(d, true);
            Some(Arc::new(ProxyContext::load(&cfg).unwrap().unwrap()))
        } else {
            None
        };

        let st = Self::state(d, opt.mint);
        let tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls_config(
            &d.join("server.crt"),
            &d.join("server.key"),
            &d.join("bundle.pem"),
        )));
        let app = match &ctx {
            Some(c) => build_router_with_proxy(st.clone(), Some(c.clone())),
            None => build_router(st.clone()),
        };
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

        let sock = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let enroll_port = sock.local_addr().unwrap().port();
        let etls = listener::tls_config(&d.join("server.crt"), &d.join("server.key")).unwrap();
        tokio::spawn(listener::serve(sock, etls, st.clone()));

        Fx {
            dir,
            st,
            port,
            enroll_port,
            mint,
            other,
            host,
            proxy,
            ctx,
        }
    }

    fn config(d: &Path, proxy: bool) -> ServerConfig {
        let p = |f: &str| d.join(f).display().to_string();
        let mut y = format!(
            "bind: \"127.0.0.1:0\"\ntls_cert_path: {}\ntls_key_path: {}\nclient_ca_path: {}\n\
             events_out_dir: {}\npolicy_bundle_path: {}\n",
            p("server.crt"),
            p("server.key"),
            p("bundle.pem"),
            d.display(),
            p("signed-policy.json"),
        );
        if proxy {
            y.push_str(&format!(
                "proxy:\n  ca_path: {}\n  registry_path: {}\n  registry_init: true\n",
                p("proxyca.crt"),
                p("proxies.json")
            ));
        }
        serde_yaml::from_str(&y).unwrap()
    }

    /// An `AppState` with enrollment on; the mint on when `mint` is set.
    fn state(d: &Path, mint: bool) -> Arc<AppState> {
        let tokens_path = d.join("tokens.json");
        let allowlist_path = d.join("hosts.json");
        std::fs::write(&allowlist_path, r#"{"hosts":[]}"#).unwrap();
        let allowlist = lodeline_server::allowlist::load(Some(&allowlist_path)).unwrap();
        let mut enroll = EnrollState::load(
            Some(&d.join("ca.crt")),
            Some(&d.join("ca.key")),
            Some(&tokens_path),
            Some(&allowlist_path),
            true,
            Some(30),
            d.join("enrollment-audit.jsonl"),
            None,
        )
        .expect("enrollment must load");
        if mint {
            let cfg = EnrollMintConfig {
                verifiers: d.join("mint-verifiers.json"),
                ttl_seconds: None,
                max_tokens: None,
            };
            enroll.mint_api = Some(MintApi::boot(&cfg, Some(&enroll), true).unwrap());
        }
        Arc::new(AppState {
            events_out_dir: d.to_path_buf(),
            policy_bundle_path: d.join("signed-policy.json"),
            rule_packs_bundle_path: None,
            artifacts_dir: None,
            high_water_path: d.join(".high-water.json"),
            allowlist: parking_lot::RwLock::new(allowlist),
            high_water: Mutex::new(HighWater::default()),
            fleet_index: FleetIndex::new(),
            read_token: ReadToken(Some(T_READ.into())),
            active_window_days: 7,
            audit_key: lodeline_server::audit_key::AuditKey::load_or_create(d),
            audit_head: Mutex::new(None),
            allowlist_path: Some(allowlist_path),
            enroll: Some(enroll),
            events_require_cert_host_match: false,
        })
    }
}

const HOST_CN: &str = "018f9c1a-0000-4000-8000-0000000000aa";

fn host_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

// ---- requests -----------------------------------------------------------------------

#[derive(Debug)]
struct Resp {
    status: u16,
    headers: reqwest::header::HeaderMap,
    body: Vec<u8>,
}

impl Resp {
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }
    fn code(&self) -> String {
        self.json()["error"]["code"].as_str().unwrap_or("").into()
    }
    fn minted(&self) -> MintResponse {
        assert_eq!(self.status, 201, "{}", String::from_utf8_lossy(&self.body));
        serde_json::from_slice(&self.body).unwrap()
    }
}

struct Req<'a> {
    method: &'a str,
    path: &'a str,
    bearer: Option<&'a str>,
    content_type: Option<&'a str>,
    requested_by: Option<&'a str>,
    body: Vec<u8>,
}

impl<'a> Req<'a> {
    fn mint(bearer: &'a str, host: &str) -> Req<'a> {
        Req {
            method: "POST",
            path: MINT_PATH,
            bearer: Some(bearer),
            content_type: Some("application/json"),
            requested_by: None,
            body: serde_json::to_vec(&serde_json::json!({ "host_id": host })).unwrap(),
        }
    }
    fn with_body(mut self, body: &[u8]) -> Self {
        self.body = body.to_vec();
        self
    }
    fn by(mut self, who: &'a str) -> Self {
        self.requested_by = Some(who);
        self
    }
}

async fn send(c: &reqwest::Client, port: u16, r: Req<'_>) -> Resp {
    let url = format!("https://127.0.0.1:{port}{}", r.path);
    let mut rb = c.request(r.method.parse().unwrap(), url).body(r.body);
    if let Some(b) = r.bearer {
        rb = rb.bearer_auth(b);
    }
    if let Some(t) = r.content_type {
        rb = rb.header("content-type", t);
    }
    if let Some(w) = r.requested_by {
        rb = rb.header("x-lodeline-requested-by", w);
    }
    let resp = rb.send().await.unwrap();
    Resp {
        status: resp.status().as_u16(),
        headers: resp.headers().clone(),
        body: resp.bytes().await.unwrap().to_vec(),
    }
}

async fn mint(fx: &Fx, bearer: &str, host: &str) -> Resp {
    send(&fx.mint_client(), fx.port, Req::mint(bearer, host)).await
}

fn audit_lines(p: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(p)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn read_bytes(p: &Path) -> Vec<u8> {
    std::fs::read(p).unwrap_or_default()
}

async fn redeem(fx: &Fx, token: &str, host: &str) -> (u16, serde_json::Value) {
    let csr = make_csr(fx.dir.path(), host);
    let c = reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(fx.p("ca.crt")).unwrap()).unwrap(),
        )
        .build()
        .unwrap();
    let r = c
        .post(format!("https://127.0.0.1:{}/v1/enroll", fx.enroll_port))
        .json(&serde_json::json!({"token": token, "host_id": host, "csr_pem": csr}))
        .send()
        .await
        .unwrap();
    (r.status().as_u16(), r.json().await.unwrap_or_default())
}

// ---- tests: the credential --------------------------------------------------------------

#[tokio::test]
async fn credential_matrix_over_real_mutual_tls() {
    let fx = Fx::new().await;
    let before = read_bytes(&fx.tokens());

    // pinned certificate, right bearer
    let host = host_id();
    let r = mint(&fx, T_MINT, &host).await;
    assert_eq!(r.headers["cache-control"], "no-store");
    let m = r.minted();
    assert_eq!(m.host_id, host);
    assert_eq!(m.token.len(), 43);
    let exp = OffsetDateTime::parse(
        &m.expires_at,
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    let ttl = exp - OffsetDateTime::now_utc();
    assert!(
        ttl > Duration::minutes(59) && ttl <= Duration::hours(1),
        "{ttl}"
    );
    let after_ok = read_bytes(&fx.tokens());
    assert_ne!(before, after_ok);

    // every refusal leaves the token file and the audit file as they were
    let audit_before = read_bytes(&fx.audit());
    let host_c = fx.host_client();
    let mint_c = fx.mint_client();
    let other_c = fx.other_client();
    let h = host_id();
    let cases: Vec<(&str, Resp, u16)> = vec![
        (
            "host certificate with a valid bearer",
            send(&host_c, fx.port, Req::mint(T_MINT, &h)).await,
            404,
        ),
        (
            "pinned certificate with the read bearer",
            send(&mint_c, fx.port, Req::mint(T_READ, &h)).await,
            401,
        ),
        (
            "the read bearer without a pinned certificate",
            send(&host_c, fx.port, Req::mint(T_READ, &h)).await,
            404,
        ),
        (
            "another entry's bearer",
            send(&mint_c, fx.port, Req::mint(T_OTHER, &h)).await,
            401,
        ),
        (
            "an expired entry",
            send(&mint_c, fx.port, Req::mint(T_EXPIRED, &h)).await,
            401,
        ),
        (
            "an entry bound to another certificate",
            send(&other_c, fx.port, Req::mint(T_MINT, &h)).await,
            401,
        ),
        (
            "no bearer",
            send(
                &mint_c,
                fx.port,
                Req {
                    bearer: None,
                    ..Req::mint("", &h)
                },
            )
            .await,
            401,
        ),
    ];
    for (what, r, want) in cases {
        assert_eq!(
            r.status,
            want,
            "{what}: {}",
            String::from_utf8_lossy(&r.body)
        );
        if want == 404 {
            assert!(r.body.is_empty(), "{what}: the router's own empty 404");
        }
    }
    assert_eq!(read_bytes(&fx.tokens()), after_ok);
    assert_eq!(read_bytes(&fx.audit()), audit_before);
}

#[tokio::test]
async fn a_config_scope_entry_in_the_file_gets_403() {
    let fx = Fx::new().await;
    let (mint_fp, other_fp) = (fingerprint(&fx.mint.0), fingerprint(&fx.other.0));
    write_verifiers(
        &fx.p("mint-verifiers.json"),
        &[
            entry("mint-1", T_MINT, Scope::Enroll, &mint_fp, None),
            entry("cfg-1", T_CONFIG, Scope::Config, &mint_fp, None),
            entry("other-1", T_OTHER, Scope::Enroll, &other_fp, None),
        ],
    );
    let r = mint(&fx, T_CONFIG, &host_id()).await;
    assert_eq!((r.status, r.code().as_str()), (403, "forbidden"));
    assert!(read_bytes(&fx.tokens()).is_empty(), "no token was made");
    assert_eq!(mint(&fx, T_MINT, &host_id()).await.status, 201);
}

#[tokio::test]
async fn an_unpinned_caller_gets_the_routers_own_404_for_every_method_and_body() {
    for mint_on in [true, false] {
        let fx = Fx::start(Opt {
            mint: mint_on,
            proxy: false,
        })
        .await;
        let host_c = fx.host_client();
        let unknown = send(
            &host_c,
            fx.port,
            Req {
                method: "GET",
                path: "/v1/no-such-route",
                bearer: None,
                content_type: None,
                requested_by: None,
                body: vec![],
            },
        )
        .await;
        assert_eq!(unknown.status, 404);
        assert!(unknown.body.is_empty());
        let big = vec![b'x'; 8 * 1024];
        let probes = [
            Req {
                method: "GET",
                ..Req::mint(T_MINT, "x")
            },
            Req::mint(T_MINT, &host_id()),
            Req::mint(T_MINT, &host_id()).with_body(&big),
            Req {
                content_type: Some("text/plain"),
                ..Req::mint(T_MINT, &host_id())
            },
            Req {
                method: "PUT",
                ..Req::mint(T_MINT, "x")
            },
            Req {
                method: "DELETE",
                bearer: None,
                ..Req::mint("", "x")
            },
        ];
        for p in probes {
            let (what, ct) = (format!("{} mint_on={mint_on}", p.method), p.content_type);
            let r = send(&host_c, fx.port, p).await;
            assert_eq!((r.status, &r.body), (404, &unknown.body), "{what} {ct:?}");
            assert_eq!(r.headers, unknown.headers, "{what}: same headers too");
        }
        if !mint_on {
            // the pinned certificate does not help when the mint is off
            assert_eq!(mint(&fx, T_MINT, &host_id()).await.status, 404);
        }
    }
}

#[tokio::test]
async fn proxy_certificates_get_404_and_the_mint_certificate_still_mints_with_a_proxy_section() {
    let fx = Fx::start(Opt {
        mint: true,
        proxy: true,
    })
    .await;
    let r = send(&fx.proxy_client(), fx.port, Req::mint(T_MINT, &host_id())).await;
    assert_eq!(r.status, 404, "a registered proxy certificate");
    assert!(read_bytes(&fx.tokens()).is_empty(), "and it made no token");
    assert_eq!(mint(&fx, T_MINT, &host_id()).await.status, 201);
    assert!(fx.ctx.is_some());
}

#[tokio::test]
async fn an_authenticated_caller_meets_method_type_size_and_body_checks_in_that_order() {
    let fx = Fx::new().await;
    let c = fx.mint_client();
    let host = host_id();
    let check = |what: &'static str, r: Resp, status: u16, code: &'static str| {
        assert_eq!((r.status, r.code()), (status, code.to_string()), "{what}");
    };
    check(
        "wrong method",
        send(
            &c,
            fx.port,
            Req {
                method: "GET",
                ..Req::mint(T_MINT, &host)
            },
        )
        .await,
        405,
        "method_not_allowed",
    );
    check(
        "wrong type",
        send(
            &c,
            fx.port,
            Req {
                content_type: Some("text/plain"),
                ..Req::mint(T_MINT, &host)
            },
        )
        .await,
        415,
        "unsupported_media_type",
    );
    check(
        "no type",
        send(
            &c,
            fx.port,
            Req {
                content_type: None,
                ..Req::mint(T_MINT, &host)
            },
        )
        .await,
        415,
        "unsupported_media_type",
    );
    let big = vec![b' '; 1025];
    check(
        "1 KiB + 1 byte",
        send(&c, fx.port, Req::mint(T_MINT, &host).with_body(&big)).await,
        413,
        "payload_too_large",
    );
    // exactly 1 KiB of valid JSON passes the limit
    let mut fits = serde_json::to_vec(&serde_json::json!({ "host_id": host })).unwrap();
    fits.resize(1024, b' ');
    assert_eq!(
        send(&c, fx.port, Req::mint(T_MINT, &host).with_body(&fits))
            .await
            .status,
        201
    );
    for (what, body) in [
        (
            "upper-case UUID",
            serde_json::json!({"host_id": host_id().to_uppercase()}).to_string(),
        ),
        (
            "version 7 UUID",
            serde_json::json!({"host_id": uuid::Uuid::now_v7().to_string()}).to_string(),
        ),
        (
            "unhyphenated",
            serde_json::json!({"host_id": host_id().replace('-', "")}).to_string(),
        ),
    ] {
        let r = send(
            &c,
            fx.port,
            Req::mint(T_MINT, &host).with_body(body.as_bytes()),
        )
        .await;
        check(what, r, 422, "invalid_host_id");
    }
    for (what, body) in [
        ("missing field", "{}".to_string()),
        (
            "unknown field",
            format!(r#"{{"host_id":"{}","ttl_seconds":5}}"#, host_id()),
        ),
        ("not JSON", "host_id".to_string()),
    ] {
        let r = send(
            &c,
            fx.port,
            Req::mint(T_MINT, &host).with_body(body.as_bytes()),
        )
        .await;
        check(what, r, 422, "invalid_request");
    }
    assert_eq!(audit_lines(&fx.audit()).len(), 1, "only the one valid mint");
}

// ---- tests: the rules of a mint ---------------------------------------------------------------

#[tokio::test]
async fn the_hundred_and_first_token_is_refused_and_writes_nothing() {
    let fx = Fx::new().await;
    for _ in 0..100 {
        assert_eq!(mint(&fx, T_MINT, &host_id()).await.status, 201);
    }
    let (tokens, audit) = (read_bytes(&fx.tokens()), read_bytes(&fx.audit()));
    let r = mint(&fx, T_MINT, &host_id()).await;
    assert_eq!((r.status, r.code().as_str()), (429, "too_many_tokens"));
    assert_eq!(read_bytes(&fx.tokens()), tokens);
    assert_eq!(read_bytes(&fx.audit()), audit);
}

#[tokio::test]
async fn a_mint_prunes_what_is_old_and_keeps_what_a_redeem_could_still_use() {
    let fx = Fx::new().await;
    let path = fx.tokens();
    let now = OffsetDateTime::now_utc();
    let (m59, m61) = (Duration::minutes(59), Duration::minutes(61));
    let tok =
        |host: &str, expires: OffsetDateTime| TokenStore::issue(&path, host, expires, now).unwrap();
    let live = tok("live", now + Duration::hours(2));
    let spent = |host: &str, ago: Duration| {
        let t = tok(host, now + Duration::hours(2));
        TokenStore::mark_used(&path, &t, host, now - ago).unwrap();
        t
    };
    let (s59, s61) = (spent("spent59", m59), spent("spent61", m61));
    let (e59, e61) = (tok("expired59", now - m59), tok("expired61", now - m61));

    let fresh = mint(&fx, T_MINT, &host_id()).await.minted();
    let idx = &fx.en().index;
    let verdict = |t: &str, h: &str| idx.check(t, h, now);
    assert_eq!(verdict(&live, "live"), Ok(()), "live and unspent survives");
    assert_eq!(
        verdict(&s59, "spent59"),
        Err(RedeemErr::Used),
        "59 minutes stays"
    );
    assert_eq!(verdict(&e59, "expired59"), Err(RedeemErr::Expired));
    assert_eq!(
        verdict(&s61, "spent61"),
        Err(RedeemErr::NotFound),
        "61 minutes goes"
    );
    assert_eq!(verdict(&e61, "expired61"), Err(RedeemErr::NotFound));
    assert_eq!(verdict(&fresh.token, &fresh.host_id), Ok(()));
}

#[tokio::test]
async fn host_exists_through_the_allowlist_and_through_a_certificate_head() {
    let fx = Fx::new().await;
    // on the allowlist
    let listed = host_id();
    fx.st
        .allowlist
        .write()
        .as_mut()
        .unwrap()
        .insert(listed.clone());
    let r = mint(&fx, T_MINT, &listed).await;
    assert_eq!((r.status, r.code().as_str()), (409, "host_exists"));
    assert!(read_bytes(&fx.tokens()).is_empty());

    // enrolled through the listener, then dropped from the in-memory allowlist
    let enrolled = host_id();
    let t = mint(&fx, T_MINT, &enrolled).await.minted().token;
    assert_eq!(redeem(&fx, &t, &enrolled).await.0, 200);
    assert!(fx.en().renewal.as_ref().unwrap().head(&enrolled).is_some());
    fx.st.allowlist.write().as_mut().unwrap().remove(&enrolled);
    let r = mint(&fx, T_MINT, &enrolled).await;
    assert_eq!((r.status, r.code().as_str()), (409, "host_exists"));
}

#[tokio::test]
async fn a_second_live_token_is_refused_and_a_spent_one_without_a_certificate_is_not_a_block() {
    let fx = Fx::new().await;
    let host = host_id();
    let first = mint(&fx, T_MINT, &host).await.minted();
    let r = mint(&fx, T_MINT, &host).await;
    assert_eq!((r.status, r.code().as_str()), (409, "token_outstanding"));

    // a token the CLI made counts too
    let cli_host = host_id();
    let now = OffsetDateTime::now_utc();
    TokenStore::issue(&fx.tokens(), &cli_host, now + Duration::hours(1), now).unwrap();
    assert_eq!(
        mint(&fx, T_MINT, &cli_host).await.code(),
        "token_outstanding"
    );

    // spent, no certificate: a new token is allowed (the recovery path)
    TokenStore::mark_used(&fx.tokens(), &first.token, &host, now).unwrap();
    assert_eq!(mint(&fx, T_MINT, &host).await.status, 201);
}

#[tokio::test]
async fn the_minted_token_redeems_on_the_real_listener_and_the_chain_shows_both_steps() {
    let fx = Fx::new().await;
    let host = host_id();
    let sent = send(
        &fx.mint_client(),
        fx.port,
        Req::mint(T_MINT, &host).by("alice"),
    )
    .await;
    let m = sent.minted();

    // the file holds a hash only; neither the token nor its hash is in the audit
    // file or in any log line
    let tokens = String::from_utf8(read_bytes(&fx.tokens())).unwrap();
    let audit = String::from_utf8(read_bytes(&fx.audit())).unwrap();
    let hash = hash_token(&m.token);
    assert!(tokens.contains(&hash) && !tokens.contains(&m.token));
    for (what, text) in [("audit file", &audit), ("log", &logged())] {
        assert!(!text.contains(&m.token), "{what} holds the token");
        assert!(!text.contains(&hash), "{what} holds the token hash");
    }
    assert!(logged().contains("enroll: token minted"), "the info line");

    let (status, body) = redeem(&fx, &m.token, &host).await;
    assert_eq!(status, 200, "{body}");
    let lines = audit_lines(&fx.audit());
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["decision"], "token_minted");
    assert_eq!(lines[0]["reason"], "ok");
    assert_eq!(lines[0]["host_id"], host.as_str());
    assert_eq!(lines[0]["not_after"], m.expires_at.as_str());
    assert_eq!(
        lines[0]["caller_fingerprint"],
        fingerprint(&fx.mint.0).as_str()
    );
    assert_eq!(lines[0]["management_key_id"], "mint-1");
    assert_eq!(lines[0]["requested_by_asserted"], "alice");
    for f in ["csr_fingerprint", "cert_fingerprint", "serial"] {
        assert_eq!(lines[0][f], "");
    }
    assert_eq!(lines[1]["decision"], "issued");
    assert_eq!(lines[1]["prev_hash"], lines[0]["hash"]);

    // the token cannot be used a second time, and the listener has no mint route
    assert_eq!(redeem(&fx, &m.token, &host).await.0, 403);
    let c = reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(fx.p("ca.crt")).unwrap()).unwrap(),
        )
        .build()
        .unwrap();
    let r = c
        .post(format!("https://127.0.0.1:{}{MINT_PATH}", fx.enroll_port))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
}

#[tokio::test]
async fn the_asserted_subject_is_cleaned_and_absent_when_unusable() {
    let fx = Fx::new().await;
    let long = format!("ali\tce{}", "x".repeat(200));
    mint_by(&fx, Some(&long)).await;
    mint_by(&fx, None).await;
    let lines = audit_lines(&fx.audit());
    let who = lines[0]["requested_by_asserted"].as_str().unwrap();
    assert_eq!(who.chars().count(), 128);
    assert!(who.starts_with("alicexxx") && !who.contains('\t'));
    assert!(lines[1].get("requested_by_asserted").is_none());
    assert_eq!(
        lodeline_fleet_api::mint::REQUESTED_BY_HEADER,
        lodeline_server::proxy::mgmt::REQUESTED_BY_HEADER
    );

    async fn mint_by(fx: &Fx, who: Option<&str>) {
        let h = host_id();
        let mut r = Req::mint(T_MINT, &h);
        r.requested_by = who;
        assert_eq!(send(&fx.mint_client(), fx.port, r).await.status, 201);
    }
}

#[tokio::test]
async fn a_failed_audit_append_answers_503_with_no_token_and_withdraws_the_entry() {
    let fx = Fx::new().await;
    // A directory where the audit file belongs makes every append fail.
    std::fs::create_dir(fx.audit()).unwrap();
    let host = host_id();
    let r = mint(&fx, T_MINT, &host).await;
    assert_eq!((r.status, r.code().as_str()), (503, "audit_unavailable"));
    assert!(
        !String::from_utf8_lossy(&r.body).contains("token\":"),
        "no token in the answer"
    );
    assert!(
        !String::from_utf8(read_bytes(&fx.tokens()))
            .unwrap()
            .contains("token_hash"),
        "the entry was removed again"
    );
    // nothing is stuck: with the audit file back, the same host gets its token
    std::fs::remove_dir(fx.audit()).unwrap();
    assert_eq!(mint(&fx, T_MINT, &host).await.status, 201);
}

#[tokio::test]
async fn many_refused_requests_leave_the_audit_and_token_files_byte_identical() {
    let fx = Fx::new().await;
    mint(&fx, T_MINT, &host_id()).await.minted();
    let (audit, tokens) = (read_bytes(&fx.audit()), read_bytes(&fx.tokens()));
    let (mint_c, other_c, host_c) = (fx.mint_client(), fx.other_client(), fx.host_client());
    for i in 0..300 {
        let h = host_id();
        let r = match i % 5 {
            0 => send(&mint_c, fx.port, Req::mint(&format!("wrong-{i}"), &h)).await,
            1 => send(&mint_c, fx.port, Req::mint(T_OTHER, &h)).await,
            2 => send(&other_c, fx.port, Req::mint(T_MINT, &h)).await,
            3 => send(&host_c, fx.port, Req::mint(T_MINT, &h)).await,
            _ => send(&mint_c, fx.port, Req::mint(T_EXPIRED, &h)).await,
        };
        assert!(matches!(r.status, 401 | 404), "{}", r.status);
    }
    assert_eq!(read_bytes(&fx.audit()), audit);
    assert_eq!(read_bytes(&fx.tokens()), tokens);
    let log = logged();
    assert!(
        log.contains("enroll request refused"),
        "the refusals reach the deny log"
    );
    assert!(
        !log.contains("wrong-3"),
        "a presented bearer is never logged"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_mints_cli_tokens_and_a_redeem_lose_nothing_and_the_chain_stays_whole() {
    let fx = Arc::new(Fx::new().await);
    let d = fx.dir.path().to_path_buf();
    // the CLI is a separate process with its own flock holder
    let cfg = d.join("cli.yaml");
    std::fs::write(
        &cfg,
        format!(
            "bind: '127.0.0.1:0'\nevents_out_dir: '{0}'\npolicy_bundle_path: '{0}/p.json'\n\
             enroll_tokens_path: '{1}'\n",
            d.display(),
            fx.tokens().display()
        ),
    )
    .unwrap();
    // The token file lock is a no-op off unix, so a second process can only write there
    // when no mint does; the CLI part runs on unix.
    let cli_hosts: Vec<String> = (0..if cfg!(unix) { 6 } else { 0 })
        .map(|_| host_id())
        .collect();
    let cli = {
        let (cfg, hosts) = (cfg.clone(), cli_hosts.clone());
        tokio::task::spawn_blocking(move || {
            hosts
                .iter()
                .map(|h| {
                    let o = Command::new(env!("CARGO_BIN_EXE_lodeline-server"))
                        .args(["enroll-token", "--config"])
                        .arg(&cfg)
                        .args(["--host-id", h])
                        .output()
                        .unwrap();
                    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
                    (
                        h.clone(),
                        String::from_utf8(o.stdout).unwrap().trim().to_string(),
                    )
                })
                .collect::<Vec<_>>()
        })
    };
    let redeem_host = host_id();
    let seed = mint(&fx, T_MINT, &redeem_host).await.minted().token;
    // a redeem on the main listener waits for the same lock the mints hold
    let redeemer = {
        let (fx, h) = (fx.clone(), redeem_host.clone());
        tokio::spawn(async move {
            let csr = make_csr(fx.dir.path(), &h);
            let r = fx
                .host_client()
                .post(format!("https://127.0.0.1:{}/v1/enroll", fx.port))
                .json(&serde_json::json!({"token": seed, "host_id": h, "csr_pem": csr}))
                .send()
                .await
                .unwrap();
            r.status().as_u16()
        })
    };
    let minters: Vec<_> = (0..64)
        .map(|_| {
            let fx = fx.clone();
            tokio::spawn(async move {
                let h = host_id();
                let m = mint(&fx, T_MINT, &h).await.minted();
                (h, m.token)
            })
        })
        .collect();
    let mut made = vec![];
    for m in minters {
        made.push(m.await.unwrap());
    }
    assert_eq!(redeemer.await.unwrap(), 200);
    made.extend(cli.await.unwrap());

    // the token file: every plaintext is found, nothing was lost
    let now = OffsetDateTime::now_utc();
    for (h, t) in &made {
        assert_eq!(
            TokenStore::check(&fx.tokens(), t, h, now),
            Ok(()),
            "{h} lost"
        );
    }
    // the chain: gapless, linked, every hash right, one line per mint and one issued
    let text = std::fs::read_to_string(fx.audit()).unwrap();
    let lines: Vec<SignedEnrollmentRecord> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 65 + 1);
    let mut prev = GENESIS_PREV_HASH.to_string();
    for (i, l) in lines.iter().enumerate() {
        assert_eq!(l.record.seq, i as u64);
        assert_eq!(l.record.prev_hash, prev);
        let canonical = lodeline_core::policy::canonical::to_canonical_bytes(&l.record).unwrap();
        assert_eq!(blake3::hash(&canonical).to_hex().to_string(), l.hash);
        prev = l.hash.clone();
    }
    assert_eq!(
        lines
            .iter()
            .filter(|l| l.record.decision == "issued")
            .count(),
        1
    );
}

/// The mint appends to the signed chain, so it must hold the lock every other
/// writer of the chain holds. A mint that does not would run while it is held.
#[tokio::test]
async fn a_mint_waits_for_the_lock_that_every_other_writer_of_the_chain_holds() {
    let fx = Arc::new(Fx::new().await);
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    let st = fx.st.clone();
    let holder = std::thread::spawn(move || {
        let _g = st.enroll.as_ref().unwrap().mint.lock().unwrap();
        held_tx.send(()).unwrap();
        go_rx.recv().unwrap();
    });
    held_rx.recv().unwrap();
    let pending = {
        let fx = fx.clone();
        tokio::spawn(async move { mint(&fx, T_MINT, &host_id()).await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(700)).await;
    assert!(
        !pending.is_finished(),
        "the mint ran while the lock was held"
    );
    assert!(read_bytes(&fx.audit()).is_empty());
    go_tx.send(()).unwrap();
    holder.join().unwrap();
    assert_eq!(pending.await.unwrap().status, 201);
}

// ---- tests: start rules and the operator command -------------------------------------------------

fn boot_cfg(verifiers: PathBuf) -> EnrollMintConfig {
    EnrollMintConfig {
        verifiers,
        ttl_seconds: None,
        max_tokens: None,
    }
}

/// A scratch dir with a CA, an enrollment state and a good mint verifier file.
struct Boot {
    dir: tempfile::TempDir,
    en: EnrollState,
    mint_fp: String,
}

fn boot_fixture(audit_is_dir: bool) -> Boot {
    init_logging();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    make_ca(d, "ca");
    let mint = make_leaf(d, "ca", "mint", "console", CLIENT_EXT);
    let mint_fp = fingerprint(&mint.0);
    write_verifiers(
        &d.join("v.json"),
        &[entry("mint-1", T_MINT, Scope::Enroll, &mint_fp, None)],
    );
    std::fs::write(d.join("hosts.json"), r#"{"hosts":[]}"#).unwrap();
    let audit = d.join("enrollment-audit.jsonl");
    if audit_is_dir {
        std::fs::create_dir(&audit).unwrap();
    }
    let en = EnrollState::load(
        Some(&d.join("ca.crt")),
        Some(&d.join("ca.key")),
        Some(&d.join("tokens.json")),
        Some(&d.join("hosts.json")),
        true,
        None,
        audit,
        None,
    )
    .unwrap();
    Boot { dir, en, mint_fp }
}

fn refusal(r: anyhow::Result<MintApi>) -> String {
    format!("{:#}", r.err().expect("the start must be refused"))
}

#[test]
fn the_start_succeeds_with_everything_in_place() {
    let b = boot_fixture(false);
    let api = MintApi::boot(&boot_cfg(b.dir.path().join("v.json")), Some(&b.en), true).unwrap();
    assert_eq!((api.ttl, api.max_tokens), (Duration::hours(1), 100));
}

#[test]
fn boot_refuses_when_enrollment_is_off() {
    let b = boot_fixture(false);
    let why = refusal(MintApi::boot(
        &boot_cfg(b.dir.path().join("v.json")),
        None,
        true,
    ));
    assert!(why.contains("enrollment is off"), "{why}");
}

#[test]
fn boot_refuses_when_the_renewal_record_is_not_loaded() {
    let b = boot_fixture(true);
    assert!(b.en.renewal.is_none());
    let why = refusal(MintApi::boot(
        &boot_cfg(b.dir.path().join("v.json")),
        Some(&b.en),
        true,
    ));
    assert!(why.contains("renewal record is not loaded"), "{why}");
}

#[test]
fn boot_refuses_without_the_audit_signing_key() {
    let b = boot_fixture(false);
    let why = refusal(MintApi::boot(
        &boot_cfg(b.dir.path().join("v.json")),
        Some(&b.en),
        false,
    ));
    assert!(why.contains("audit signing key"), "{why}");
}

#[test]
fn boot_refuses_a_verifier_file_that_does_not_load() {
    let b = boot_fixture(false);
    let d = b.dir.path();
    let try_file = |p: PathBuf| refusal(MintApi::boot(&boot_cfg(p), Some(&b.en), true));
    assert!(try_file(d.join("missing.json")).contains("enroll_mint.verifiers"));
    write_verifiers(&d.join("empty.json"), &[]);
    assert!(try_file(d.join("empty.json")).contains("no entries"));
    std::fs::write(d.join("junk.json"), "{not json").unwrap();
    set_mode(&d.join("junk.json"), 0o600);
    assert!(try_file(d.join("junk.json")).contains("parse verifier file"));
    assert!(
        try_file(d.to_path_buf()).contains("enroll_mint.verifiers"),
        "a directory"
    );
    #[cfg(unix)]
    {
        let loose = d.join("loose.json");
        std::fs::copy(d.join("v.json"), &loose).unwrap();
        set_mode(&loose, 0o644);
        assert!(try_file(loose).contains("owner-only"));
        let link = d.join("link.json");
        std::os::unix::fs::symlink(d.join("v.json"), &link).unwrap();
        assert!(try_file(link).contains("symlink"));
    }
}

#[test]
fn boot_refuses_a_verifier_entry_whose_scope_is_not_enroll() {
    let b = boot_fixture(false);
    let d = b.dir.path();
    write_verifiers(
        &d.join("mixed.json"),
        &[
            entry("mint-1", T_MINT, Scope::Enroll, &b.mint_fp, None),
            entry("cfg-1", T_CONFIG, Scope::Config, &b.mint_fp, None),
        ],
    );
    let why = refusal(MintApi::boot(
        &boot_cfg(d.join("mixed.json")),
        Some(&b.en),
        true,
    ));
    assert!(why.contains("scope is not enroll"), "{why}");
}

/// Boot with a proxy section: the registry and the management file of the proxy.
fn proxy_ctx(
    b: &Boot,
    mgmt_entries: Option<&[VerifierEntry]>,
    registered: Option<&str>,
) -> ProxyContext {
    let d = b.dir.path();
    make_ca(d, "proxyca");
    std::fs::write(
        d.join("bundle.pem"),
        [
            read_bytes(&d.join("ca.crt")),
            read_bytes(&d.join("proxyca.crt")),
        ]
        .concat(),
    )
    .unwrap();
    let reg = d.join("proxies.json");
    let r = lodeline_server::proxy::registry::ProxyRegistry::open(&reg, true).unwrap();
    if let Some(fp) = registered {
        r.seed_for_test(lodeline_server::proxy::registry::ProxyRecord {
            proxy_id: "px-one".into(),
            display_name: "px".into(),
            state: lodeline_server::proxy::registry::ProxyState::Active,
            fp_current: Some(fp.into()),
            fp_next: None,
            created_at: "2026-10-11T00:00:00Z".into(),
            updated_at: "2026-10-11T00:00:00Z".into(),
        })
        .unwrap();
    }
    let mut y = format!(
        "bind: \"127.0.0.1:0\"\ntls_cert_path: {0}/s.crt\ntls_key_path: {0}/s.key\n\
         client_ca_path: {0}/bundle.pem\nevents_out_dir: {0}\npolicy_bundle_path: {0}/p.json\n\
         proxy:\n  ca_path: {0}/proxyca.crt\n  registry_path: {0}/proxies.json\n",
        d.display()
    );
    if let Some(entries) = mgmt_entries {
        write_verifiers(&d.join("proxy-mgmt.json"), entries);
        y.push_str(&format!(
            "  management_verifiers: {}/proxy-mgmt.json\n",
            d.display()
        ));
    }
    let cfg: ServerConfig = serde_yaml::from_str(&y).unwrap();
    ProxyContext::load(&cfg).unwrap().unwrap()
}

#[test]
fn boot_refuses_a_caller_that_is_a_registered_proxy() {
    let b = boot_fixture(false);
    let api = MintApi::boot(&boot_cfg(b.dir.path().join("v.json")), Some(&b.en), true).unwrap();
    let ctx = proxy_ctx(&b, None, Some(&b.mint_fp));
    let why = format!("{:#}", api.check_proxy_overlap(&ctx).unwrap_err());
    assert!(why.contains("registered proxy fingerprint"), "{why}");
}

#[test]
fn boot_refuses_a_caller_that_is_also_a_proxy_management_caller() {
    let b = boot_fixture(false);
    let api = MintApi::boot(&boot_cfg(b.dir.path().join("v.json")), Some(&b.en), true).unwrap();
    let both = [entry("px-cfg", "tok-px", Scope::Config, &b.mint_fp, None)];
    let ctx = proxy_ctx(&b, Some(&both), None);
    let why = format!("{:#}", api.check_proxy_overlap(&ctx).unwrap_err());
    assert!(why.contains("proxy management caller"), "{why}");
    // distinct callers are fine
    let other = [entry(
        "px-cfg",
        "tok-px",
        Scope::Config,
        &"b".repeat(64),
        None,
    )];
    api.check_proxy_overlap(&proxy_ctx(&b, Some(&other), None))
        .unwrap();
}

#[test]
fn the_real_binary_refuses_enroll_mint_with_enrollment_off_and_names_the_cause() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().display();
    let cfg = dir.path().join("server.yaml");
    std::fs::write(
        &cfg,
        format!(
            "bind: '127.0.0.1:0'\nevents_out_dir: '{d}/events'\npolicy_bundle_path: '{d}/p.json'\n\
             tls_cert_path: '{d}/s.crt'\ntls_key_path: '{d}/s.key'\nclient_ca_path: '{d}/ca.pem'\n\
             events_require_cert_host_match: true\nenroll_listener:\n  bind: '127.0.0.1:1'\n\
             enroll_mint:\n  verifiers: '{d}/v.json'\n"
        ),
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_lodeline-server"))
        .args(["serve", "--config"])
        .arg(&cfg)
        .env_remove("LODELINE_SERVER_READ_TOKEN")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("enroll_mint is set but enrollment is off"),
        "{stderr}"
    );
}

#[test]
fn verifier_new_makes_an_enroll_entry_bound_to_a_certificate_file() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    make_ca(d, "ca");
    let (crt, _) = make_leaf(d, "ca", "mint", "console", CLIENT_EXT);
    let out = Command::new(env!("CARGO_BIN_EXE_lodeline-server"))
        .args([
            "proxy",
            "verifier-new",
            "--scope",
            "enroll",
            "--caller-cert",
        ])
        .arg(&crt)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let token = String::from_utf8(out.stdout).unwrap().trim().to_string();
    let stderr = String::from_utf8(out.stderr).unwrap();
    let json = &stderr[stderr.find('{').unwrap()..];
    let e: VerifierEntry = serde_json::from_str(json).unwrap();
    assert_eq!(e.scope, Scope::Enroll);
    assert_eq!(e.caller_cert_fingerprint, fingerprint(&crt));
    assert_eq!(e.verifier, verifier_for(&token));
    // the entry is one the server accepts as the mint's file, and the token opens it
    write_verifiers(&d.join("v.json"), &[e]);
    let auth = MgmtAuth::load(&d.join("v.json")).unwrap();
    assert!(auth.only_scope(Scope::Enroll));
    assert!(matches!(
        auth.authenticate(&fingerprint(&crt), Some(&token), OffsetDateTime::now_utc()),
        lodeline_server::proxy::verifiers::AuthOutcome::Ok(_)
    ));
    // a fingerprint and a certificate together are refused
    let both = Command::new(env!("CARGO_BIN_EXE_lodeline-server"))
        .args([
            "proxy",
            "verifier-new",
            "--scope",
            "enroll",
            "--caller-fingerprint",
        ])
        .arg("a".repeat(64))
        .arg("--caller-cert")
        .arg(&crt)
        .output()
        .unwrap();
    assert!(!both.status.success());
}
