//! Test fixtures: a throwaway PKI made with openssl, and Go's `internal/testutil/oidc.go`, a local
//! HTTPS OIDC provider with discovery, PKCE authorization and signed ID tokens.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::auth::base64url;

/// A CA, a server certificate for 127.0.0.1 and a client certificate, in a temp dir removed on
/// drop.
pub struct Pki {
    dir: PathBuf,
}

impl Drop for Pki {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Pki {
    pub fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "lodeline-manager-mtls-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pki = Self { dir };
        pki.key("ca");
        pki.openssl(
            &["req", "-x509", "-new", "-key", "ca.key", "-days", "1"],
            &[
                "-subj",
                &format!("/CN=test-ca-{name}"),
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-out",
                "ca.crt",
            ],
        );
        pki.leaf(
            "server",
            "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n",
        );
        pki.leaf("client", "extendedKeyUsage=clientAuth\n");
        pki
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// Runs openssl in the PKI dir and returns its standard output.
    fn openssl(&self, args: &[&str], more: &[&str]) -> String {
        let openssl = lodeline_server::enroll::sign::resolve_openssl().expect("openssl");
        let out = Command::new(openssl)
            .args(args)
            .args(more)
            .current_dir(&self.dir)
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "openssl {args:?}: {err}");
        String::from_utf8(out.stdout).unwrap()
    }

    /// RSA, which ring reads from every openssl and LibreSSL PKCS#8 output.
    fn key(&self, name: &str) {
        let out = format!("{name}.key");
        self.openssl(
            &["genpkey", "-algorithm", "RSA"],
            &["-pkeyopt", "rsa_keygen_bits:2048", "-out", &out],
        );
    }

    pub fn leaf(&self, name: &str, ext: &str) {
        self.key(name);
        std::fs::write(self.path(&format!("{name}.ext")), ext).unwrap();
        let (key, csr, crt) = (
            format!("{name}.key"),
            format!("{name}.csr"),
            format!("{name}.crt"),
        );
        self.openssl(
            &["req", "-new", "-key", &key, "-subj"],
            &[&format!("/CN={name}"), "-out", &csr],
        );
        let serial = if name == "server" { "0x1001" } else { "0x1002" };
        self.openssl(
            &[
                "x509", "-req", "-in", &csr, "-CA", "ca.crt", "-CAkey", "ca.key",
            ],
            &[
                "-set_serial",
                serial,
                "-days",
                "1",
                "-extfile",
                &format!("{name}.ext"),
                "-out",
                &crt,
            ],
        );
    }

    /// A new RSA key as jsonwebtoken signs with it, and its JWK modulus.
    fn signing_key(&self, name: &str) -> (EncodingKey, String) {
        self.key(name);
        let key = format!("{name}.key");
        let der = format!("{name}.p8");
        self.openssl(
            &["pkcs8", "-topk8", "-nocrypt", "-in", &key],
            &["-outform", "DER", "-out", &der],
        );
        // A 2048-bit PKCS#8 key wraps its PKCS#1 key at a fixed offset.
        let p8 = std::fs::read(self.path(&der)).unwrap();
        assert_eq!(&p8[22..24], [0x04, 0x82], "PKCS#8 octet string");
        let modulus = self.openssl(&["rsa", "-noout", "-modulus", "-in", &key], &[]);
        let hex = modulus.trim().trim_start_matches("Modulus=");
        let n: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        (EncodingKey::from_rsa_der(&p8[26..]), base64url(&n))
    }
}

pub fn pem_certs(path: &Path) -> Vec<rustls::pki_types::CertificateDer<'static>> {
    let pem = std::fs::read(path).unwrap();
    rustls_pemfile::certs(&mut pem.as_slice())
        .collect::<Result<_, _>>()
        .unwrap()
}

/// Changes the ID token claims before signing, for the negative cases.
pub type Mutate = fn(&mut Map<String, Value>);

/// The provider's client: `console` with secret `test-secret`, subject `employee-1`.
pub struct OidcProvider {
    pub url: String,
    /// The CA that signed the provider's certificate.
    pub ca: reqwest::Certificate,
    fixture: Arc<Fixture>,
    _pki: Pki,
}

#[derive(Default)]
struct Settings {
    /// Changes the ID token claims.
    mutate: Option<Mutate>,
    /// Changes the discovery document.
    discovery: Option<Mutate>,
    /// Refuses the client secret in a basic auth header, as a `client_secret_post` client.
    form_auth_only: bool,
    /// Served as the key set in place of the signing key's.
    keys: Option<String>,
}

struct Fixture {
    url: String,
    key: EncodingKey,
    /// Signs instead of `key` when the case wants a bad signature.
    wrong_key: Option<EncodingKey>,
    modulus: String,
    settings: Mutex<Settings>,
    token_requests: std::sync::atomic::AtomicUsize,
    key_requests: std::sync::atomic::AtomicUsize,
    codes: Mutex<HashMap<String, HashMap<&'static str, String>>>,
}

impl OidcProvider {
    pub async fn start(invalid_signature: bool) -> Self {
        let pki = Pki::new(&format!("oidc-{}", unique()));
        let (key, modulus) = pki.signing_key("signing");
        let wrong_key = invalid_signature.then(|| pki.signing_key("other").0);

        let _ = rustls::crypto::ring::default_provider().install_default();
        let key_pem = std::fs::read(pki.path("server.key")).unwrap();
        let server_key = rustls_pemfile::private_key(&mut key_pem.as_slice())
            .unwrap()
            .unwrap();
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(pem_certs(&pki.path("server.crt")), server_key)
            .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("https://{}", listener.local_addr().unwrap());
        let fixture = Arc::new(Fixture {
            url: url.clone(),
            key,
            wrong_key,
            modulus,
            settings: Mutex::default(),
            token_requests: Default::default(),
            key_requests: Default::default(),
            codes: Mutex::default(),
        });
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/keys", get(keys))
            .route("/authorize", get(authorize))
            .route("/token", post(token))
            .with_state(fixture.clone());
        let config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls));
        tokio::spawn(async move {
            axum_server::from_tcp_rustls(listener, config)
                .serve(app.into_make_service())
                .await
                .unwrap()
        });
        let ca = std::fs::read(pki.path("ca.crt")).unwrap();
        Self {
            url,
            ca: reqwest::Certificate::from_pem(&ca).unwrap(),
            fixture,
            _pki: pki,
        }
    }

    pub fn mutate(&self, f: Option<Mutate>) {
        self.fixture.settings.lock().unwrap().mutate = f;
    }

    pub fn mutate_discovery(&self, f: Option<Mutate>) {
        self.fixture.settings.lock().unwrap().discovery = f;
    }

    pub fn form_auth_only(&self, on: bool) {
        self.fixture.settings.lock().unwrap().form_auth_only = on;
    }

    /// Token requests so far, refused ones included.
    pub fn token_requests(&self) -> usize {
        self.fixture
            .token_requests
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn serve_keys(&self, body: Option<String>) {
        self.fixture.settings.lock().unwrap().keys = body;
    }

    /// Key set requests so far.
    pub fn key_requests(&self) -> usize {
        self.fixture
            .key_requests
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// A client that trusts the provider, built as the console builds its own.
    pub fn client(&self) -> reqwest::Client {
        crate::auth::oidc::http_client(std::slice::from_ref(&self.ca)).unwrap()
    }
}

/// A distinct PKI dir name for each provider in this process.
fn unique() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

async fn discovery(State(f): State<Arc<Fixture>>) -> Json<Value> {
    let mut doc = json!({
        "issuer": f.url,
        "authorization_endpoint": format!("{}/authorize", f.url),
        "token_endpoint": format!("{}/token", f.url),
        "jwks_uri": format!("{}/keys", f.url),
        "id_token_signing_alg_values_supported": ["RS256"],
    });
    if let Some(change) = f.settings.lock().unwrap().discovery {
        change(doc.as_object_mut().unwrap());
    }
    Json(doc)
}

async fn keys(State(f): State<Arc<Fixture>>) -> Response {
    f.key_requests
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if let Some(body) = f.settings.lock().unwrap().keys.clone() {
        return ([(header::CONTENT_TYPE, "application/json")], body).into_response();
    }
    Json(json!({"keys": [{
        "kty": "RSA", "kid": "test-key", "alg": "RS256", "use": "sig", "n": f.modulus, "e": "AQAB",
    }]}))
    .into_response()
}

async fn authorize(
    State(f): State<Arc<Fixture>>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let get = |k: &str| q.get(k).cloned().unwrap_or_default();
    if get("code_challenge_method") != "S256" || get("nonce").is_empty() {
        return (StatusCode::BAD_REQUEST, "PKCE/nonce required\n").into_response();
    }
    let code = get("state");
    let attempt = HashMap::from([
        ("nonce", get("nonce")),
        ("challenge", get("code_challenge")),
        ("redirect", get("redirect_uri")),
    ]);
    f.codes.lock().unwrap().insert(code.clone(), attempt);
    let to = format!("{}?code={code}&state={}", get("redirect_uri"), get("state"));
    (StatusCode::FOUND, [(header::LOCATION, to)]).into_response()
}

async fn token(State(f): State<Arc<Fixture>>, headers: HeaderMap, body: String) -> Response {
    f.token_requests
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let (mutate, form_only) = {
        let s = f.settings.lock().unwrap();
        (s.mutate, s.form_auth_only)
    };
    let form = crate::api::Query::parse(Some(&body));
    let basic = !form_only
        && headers
            .get(header::AUTHORIZATION)
            .is_some_and(|v| v == "Basic Y29uc29sZTp0ZXN0LXNlY3JldA==");
    let in_form = form.get("client_id") == "console" && form.get("client_secret") == "test-secret";
    if !basic && !in_form {
        return (StatusCode::UNAUTHORIZED, "invalid client\n").into_response();
    }
    let attempt = f.codes.lock().unwrap().remove(form.get("code"));
    let challenge = base64url(&Sha256::digest(form.get("code_verifier").as_bytes()));
    let Some(a) = attempt
        .filter(|a| a["challenge"] == challenge && a["redirect"] == form.get("redirect_uri"))
    else {
        return (StatusCode::BAD_REQUEST, "invalid grant\n").into_response();
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut claims = json!({
        "iss": f.url, "sub": "employee-1", "aud": "console", "exp": now + 3600, "iat": now,
        "nonce": a["nonce"],
    });
    if let Some(mutate) = mutate {
        mutate(claims.as_object_mut().unwrap());
    }
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key".to_owned());
    let key = f.wrong_key.as_ref().unwrap_or(&f.key);
    let id_token = jsonwebtoken::encode(&header, &claims, key).unwrap();
    Json(json!({"access_token": "opaque", "token_type": "Bearer", "id_token": id_token}))
        .into_response()
}

/// Follows the browser's first hop: the provider's answer to `location`, and the callback URL
/// it redirects to.
pub async fn authorize_redirect(client: &reqwest::Client, location: &str) -> reqwest::Url {
    let res = client.get(location).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::FOUND, "authorize");
    let to = res.headers()[header::LOCATION].to_str().unwrap();
    reqwest::Url::parse(to).unwrap()
}

/// A request body that sends `prefix`, then `filler` bytes 16 KiB a frame until `total` bytes
/// have gone out, then either ends or, with `stall`, stops sending without ending. `sent` counts
/// the bytes handed to the reader.
pub struct Trickle {
    pub prefix: &'static [u8],
    pub filler: u8,
    pub total: usize,
    pub stall: bool,
    pub sent: Arc<std::sync::atomic::AtomicUsize>,
}

impl axum::body::HttpBody for Trickle {
    type Data = axum::body::Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        use std::sync::atomic::Ordering::Relaxed;
        let sent = self.sent.load(Relaxed);
        if sent >= self.total {
            return if self.stall {
                std::task::Poll::Pending
            } else {
                std::task::Poll::Ready(None)
            };
        }
        let chunk = if sent == 0 {
            self.prefix.to_vec()
        } else {
            vec![self.filler; (self.total - sent).min(16 * 1024)]
        };
        self.sent.fetch_add(chunk.len(), Relaxed);
        std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(chunk.into()))))
    }
}

pub const SESSION_SECRET: &str = "0123456789abcdefghijklmnopqrstuv";
/// The console's own origin in the enrollment tests.
pub const ORIGIN: &str = "https://console.example.com";

/// A session cookie for `subject`, signed with [`SESSION_SECRET`].
pub fn session_cookie(subject: &str) -> String {
    let claims = json!({"iss": "lodeline-manager", "sub": subject, "exp": 4_000_000_000_i64});
    let key = EncodingKey::from_secret(SESSION_SECRET.as_bytes());
    let token = jsonwebtoken::encode(&Header::default(), &claims, &key).unwrap();
    format!("lodeline_session={token}")
}

pub struct Reply {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
    pub fn code(&self) -> String {
        self.json()["error"]["code"].as_str().unwrap_or("").into()
    }
}

/// `POST /api/v1/enrollment/files` as the console's own page sends it: the session of `who`
/// (none for no cookie), `Origin` [`ORIGIN`], `Sec-Fetch-Site: same-origin` and a JSON body.
/// `edits` replace a default header, or remove it with `None`.
pub async fn post_files(
    app: &Router,
    who: Option<&str>,
    edits: &[(&str, Option<&str>)],
    body: &str,
) -> Reply {
    use tower::ServiceExt;
    let cookie = who.map(session_cookie);
    let mut headers = vec![
        ("host", Some("console.example.com")),
        ("cookie", cookie.as_deref()),
        ("origin", Some(ORIGIN)),
        ("sec-fetch-site", Some("same-origin")),
        ("content-type", Some("application/json")),
    ];
    for (name, value) in edits {
        headers.retain(|(n, _)| n != name);
        headers.push((*name, *value));
    }
    let mut req = axum::http::Request::builder()
        .method("POST")
        .uri("/api/v1/enrollment/files");
    for (name, value) in headers {
        if let Some(v) = value {
            req = req.header(name, v);
        }
    }
    let res = app
        .clone()
        .oneshot(req.body(axum::body::Body::from(body.to_owned())).unwrap())
        .await
        .unwrap();
    let (parts, body) = res.into_parts();
    let body = axum::body::to_bytes(body, usize::MAX)
        .await
        .unwrap()
        .to_vec();
    Reply {
        status: parts.status.as_u16(),
        headers: parts.headers,
        body,
    }
}
