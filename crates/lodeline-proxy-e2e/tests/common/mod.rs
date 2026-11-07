//! Helpers shared by the proxy end-to-end test binaries: an openssl PKI, the
//! mTLS control plane and the management-caller setup. Each test binary
//! compiles this module on its own, so an item one binary does not use carries
//! `#[allow(dead_code)]`.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lodeline_proxy_api::verifier::verifier_for;
use lodeline_server::app::{build_router_with_proxy, AppState};
use lodeline_server::auth::ReadToken;
use lodeline_server::config::{ProxyConfig, ServerConfig};
use lodeline_server::fleet_index::FleetIndex;
use lodeline_server::persist::HighWater;
use lodeline_server::proxy::verifiers::{Scope, VerifierEntry};
use lodeline_server::proxy::ProxyContext;
use lodeline_server::tls_accept::PeerCertAcceptor;

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

pub struct Pki {
    pub dir: tempfile::TempDir,
    ossl: PathBuf,
    serial: AtomicUsize,
}

impl Pki {
    pub fn p(&self, f: &str) -> PathBuf {
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
    pub fn leaf(&self, ca: &str, name: &str, cn: &str, ext: &str) -> (PathBuf, PathBuf) {
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
/// `cn_prefix` names the two CAs (`{cn_prefix}-host-ca`, `{cn_prefix}-proxy-ca`).
pub fn pki(cn_prefix: &str) -> Option<Pki> {
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
    pki.ca("hostca", &format!("{cn_prefix}-host-ca"), "1");
    pki.ca("proxyca", &format!("{cn_prefix}-proxy-ca"), "2");
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

pub fn fingerprint(crt: &Path) -> String {
    let pem = std::fs::read(crt).unwrap();
    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(&pem[..]))
        .collect::<Result<_, _>>()
        .unwrap();
    blake3::hash(certs[0].as_ref()).to_hex().to_string()
}

fn mtls_client_builder(trust: &Path, crt: &Path, key: &Path) -> reqwest::ClientBuilder {
    let mut id = std::fs::read(key).unwrap();
    id.extend_from_slice(&std::fs::read(crt).unwrap());
    reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(trust).unwrap()).unwrap(),
        )
        .identity(reqwest::Identity::from_pem(&id).unwrap())
}

/// A client that opens a fresh connection per request.
#[allow(dead_code)]
pub fn mtls_client(trust: &Path, crt: &Path, key: &Path) -> reqwest::Client {
    mtls_client_builder(trust, crt, key)
        .pool_max_idle_per_host(0)
        .build()
        .unwrap()
}

/// A client with reqwest's default connection pool.
#[allow(dead_code)]
pub fn mtls_client_pooled(trust: &Path, crt: &Path, key: &Path) -> reqwest::Client {
    mtls_client_builder(trust, crt, key).build().unwrap()
}

pub fn tls_config(pki: &Pki) -> rustls::ServerConfig {
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

pub fn app_state(dir: &Path) -> Arc<AppState> {
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

#[allow(dead_code)]
pub type Tweak = Arc<dyn Fn(&mut ProxyConfig) + Send + Sync>;

#[allow(dead_code)]
pub struct Server {
    pub port: u16,
    pub ctx: Arc<ProxyContext>,
    pub handle: axum_server::Handle,
    pub task: tokio::task::JoinHandle<()>,
}

impl Server {
    /// `port == 0` picks one; a restart passes the old port. State files are the
    /// same on every start (they live in the PKI temp dir).
    #[allow(dead_code)]
    pub async fn start(pki: &Pki, port: u16, first: bool, tweak: &Tweak) -> Server {
        Self::try_start(pki, port, first, tweak)
            .await
            .expect("server must bind")
    }

    /// `None` when the port could not be bound.
    #[allow(dead_code)]
    pub async fn try_start(pki: &Pki, port: u16, first: bool, tweak: &Tweak) -> Option<Server> {
        Self::try_start_with(pki, port, first, tweak, |app| app).await
    }

    /// Like `try_start`; `wrap` adds layers to the router before it serves.
    pub async fn try_start_with(
        pki: &Pki,
        port: u16,
        first: bool,
        tweak: &Tweak,
        wrap: impl FnOnce(axum::Router) -> axum::Router,
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
        let app = wrap(build_router_with_proxy(app_state(d), Some(ctx.clone())));
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
    #[allow(dead_code)]
    pub async fn stop(self) -> u16 {
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

#[allow(dead_code)]
pub fn verifier_entry(id: &str, token: &str, scope: Scope, fp: &str) -> VerifierEntry {
    VerifierEntry {
        key_id: id.into(),
        name: format!("{id}-name"),
        verifier: verifier_for(token),
        scope,
        caller_cert_fingerprint: fp.into(),
        not_after: None,
    }
}

/// Extension text for a client certificate whose only SAN is `san`.
pub fn client_ext(san: &str) -> String {
    format!("subjectAltName=DNS:{san}\nextendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n")
}

/// The management caller: a `hostca` client certificate plus a
/// `verifiers.json` that grants it the identity (`t_id`) and config (`t_cfg`)
/// scopes. Returns the certificate and key paths.
#[allow(dead_code)]
pub fn mgmt_identity(pki: &Pki, t_id: &str, t_cfg: &str) -> (PathBuf, PathBuf) {
    let mgmt_cert = pki.leaf(
        "hostca",
        "mgmt",
        "mgmt-operator",
        &client_ext("mgmt-operator"),
    );
    let fp = fingerprint(&mgmt_cert.0);
    let vpath = pki.p("verifiers.json");
    std::fs::write(
        &vpath,
        serde_json::to_vec(&serde_json::json!({"entries": [
            verifier_entry("idk", t_id, Scope::Identity, &fp),
            verifier_entry("cfgk", t_cfg, Scope::Config, &fp),
        ]}))
        .unwrap(),
    )
    .unwrap();
    std::fs::set_permissions(&vpath, std::fs::Permissions::from_mode(0o600)).unwrap();
    mgmt_cert
}

/// Runs `start` again while it fails only because the `state_dir` lock is
/// still held, every 20 ms for at most 1 s. Any other error returns at once.
// A child another test forks keeps a copy of the lock fd until its exec, so a
// flock this process released can stay held for that window.
#[allow(dead_code)]
pub async fn retry_locked<T, F, Fut>(mut start: F) -> anyhow::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    loop {
        match start().await {
            Err(e)
                if matches!(
                    e.downcast_ref(),
                    Some(lodeline_proxy::state_dir::StateError::Locked)
                ) && std::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(20)).await
            }
            r => return r,
        }
    }
}
