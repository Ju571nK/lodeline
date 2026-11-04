//! The optional OIDC login of Go's `internal/auth/oidc.go`, with the behavior of the libraries it
//! uses: discovery and ID token checks as go-oidc v3.21 does them, and the authorization URL and
//! token exchange as x/oauth2 v0.36 does them. Every failure looks the same to the caller.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::value::RawValue;
use sha2::{Digest, Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;
use tokio::sync::watch;

use super::{base64url, go_base64, go_fold, Members};
use crate::config::{self, OidcConfig};
use crate::fleet::env_proxy;
use crate::triage::go_compact;

/// How long a started login can be completed.
pub const LOGIN_ATTEMPT_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_LOGIN_ATTEMPTS: usize = 1024;
const TIMEOUT: Duration = Duration::from_secs(10);
/// go-oidc's `supportedAlgorithms`. jsonwebtoken has no ES512, so such tokens fail here.
const SUPPORTED_ALGS: [&str; 10] = [
    "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA",
];
/// The largest discovery document, key set or token response read.
const BODY_LIMIT: usize = 1 << 20;
/// go-oidc's allowance for a provider clock ahead of ours.
const NBF_LEEWAY: Duration = Duration::from_secs(5 * 60);

struct Attempt {
    binding: String,
    nonce: String,
    verifier: String,
    expires: Instant,
}

struct Key {
    kid: String,
    key: DecodingKey,
}

/// A key set fetch's answer: `None` when it failed.
type Answer = Option<Arc<Vec<Key>>>;

#[derive(Default)]
struct KeyCache {
    keys: Arc<Vec<Key>>,
    /// The fetch under way, whose answer every cache miss meanwhile waits for.
    fetch: Option<watch::Receiver<Option<Answer>>>,
}

/// x/oauth2's two ways to send the client secret. It tries the header first and remembers the
/// first that works.
#[derive(Clone, Copy)]
enum AuthStyle {
    Header,
    Params,
}

/// One discovered provider and the logins in flight. Attempts live in memory, so a restart
/// drops them and replicas need sticky routing.
pub struct Oidc {
    issuer: String,
    client_id: String,
    client_secret: String,
    redirect_url: String,
    allowed_subjects: Vec<String>,
    auth_url: String,
    token_url: String,
    jwks_url: String,
    algorithms: Vec<String>,
    http: reqwest::Client,
    keys: Arc<Mutex<KeyCache>>,
    auth_style: Mutex<Option<AuthStyle>>,
    attempts: Mutex<HashMap<String, Attempt>>,
    now: Box<dyn Fn() -> Instant + Send + Sync>,
}

/// The client for every provider call: a 10 s limit, no redirects followed, the OS trust store
/// and the proxy variables Go reads. `roots` adds trusted CAs (tests only).
pub fn http_client(roots: &[reqwest::Certificate]) -> reqwest::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .tls_built_in_webpki_certs(false)
        .proxy(env_proxy(|k| std::env::var(k).ok()));
    for root in roots {
        builder = builder.add_root_certificate(root.clone());
    }
    builder.build()
}

impl Oidc {
    /// Go's `discoverOIDC`: reads the provider's discovery document, which must name the
    /// configured issuer and HTTPS authorization and token endpoints.
    pub async fn discover(c: &OidcConfig, http: reqwest::Client) -> Result<Self, String> {
        let failed = || "OIDC discovery failed; check issuer, TLS and connectivity".to_owned();
        let base = c.issuer.strip_suffix('/').unwrap_or(&c.issuer);
        let url = format!("{base}/.well-known/openid-configuration");
        let res = get(&http, &url, false).await.ok_or_else(failed)?;
        if res.status() != reqwest::StatusCode::OK {
            return Err(failed());
        }
        let body = read_capped(res, BODY_LIMIT)
            .await
            .ok()
            .flatten()
            .ok_or_else(failed)?;
        let d = discovery(&body).ok_or_else(failed)?;
        if d.issuer != c.issuer {
            return Err(failed());
        }
        for raw in [&d.auth_url, &d.token_url] {
            let ok = config::go_url(raw).is_some_and(|u| {
                u.scheme == "https" && !u.host.is_empty() && !u.has_user && !u.has_fragment
            });
            if !ok {
                return Err(
                    "OIDC discovery requires HTTPS authorization and token endpoints".to_owned(),
                );
            }
        }
        let mut algorithms: Vec<String> = d
            .algorithms
            .into_iter()
            .filter(|a| SUPPORTED_ALGS.contains(&a.as_str()))
            .collect();
        if algorithms.is_empty() {
            algorithms.push("RS256".to_owned());
        }
        Ok(Self {
            issuer: c.issuer.clone(),
            client_id: c.client_id.clone(),
            client_secret: c.client_secret.clone(),
            redirect_url: c.redirect_url.clone(),
            allowed_subjects: c.allowed_subjects.clone(),
            auth_url: d.auth_url,
            token_url: d.token_url,
            jwks_url: d.jwks_url,
            algorithms,
            http,
            keys: Arc::default(),
            auth_style: Mutex::default(),
            attempts: Mutex::default(),
            now: Box::new(Instant::now),
        })
    }

    /// Go's `Begin`: records a new attempt and returns the provider URL to send the browser to
    /// and the binding value for its cookie. `None` while 1024 attempts are pending.
    pub fn begin(&self) -> Option<(String, String)> {
        let [state, binding, nonce, verifier] = [(); 4].map(|()| random_value());
        let mut attempts = self.attempts.lock().unwrap_or_else(PoisonError::into_inner);
        let now = (self.now)();
        attempts.retain(|_, a| a.expires > now);
        if attempts.len() >= MAX_LOGIN_ATTEMPTS {
            return None;
        }
        let location = self.authorization_url(&state, &nonce, &verifier);
        attempts.insert(
            state,
            Attempt {
                binding: binding.clone(),
                nonce,
                verifier,
                expires: now + LOGIN_ATTEMPT_TTL,
            },
        );
        Some((location, binding))
    }

    /// x/oauth2's `AuthCodeURL` with the nonce, a PKCE S256 challenge and `response_mode=query`.
    fn authorization_url(&self, state: &str, nonce: &str, verifier: &str) -> String {
        let challenge = base64url(&Sha256::digest(verifier.as_bytes()));
        let query = encode_form(vec![
            ("response_type", "code"),
            ("client_id", &self.client_id),
            ("redirect_uri", &self.redirect_url),
            ("scope", "openid"),
            ("state", state),
            ("nonce", nonce),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("response_mode", "query"),
        ]);
        let sep = if self.auth_url.contains('?') {
            '&'
        } else {
            '?'
        };
        format!("{}{sep}{query}", self.auth_url)
    }

    /// Takes the attempt for `state` when `binding` matches it. A matched attempt is used up
    /// even when it has expired or a later step fails; a wrong binding leaves it in place.
    fn consume(&self, state: &str, binding: &str) -> Option<Attempt> {
        let mut attempts = self.attempts.lock().unwrap_or_else(PoisonError::into_inner);
        let a = attempts.get(state)?;
        if binding.is_empty() || !bool::from(a.binding.as_bytes().ct_eq(binding.as_bytes())) {
            return None;
        }
        let a = attempts.remove(state)?;
        (a.expires > (self.now)()).then_some(a)
    }

    /// Go's `Complete`: exchanges `code` for tokens and checks the ID token. Returns the session
    /// subject, `oidc:` and a hash of issuer and subject, and the ID token's expiry in Unix
    /// seconds. Only an exact subject in the configured list gets in.
    pub async fn complete(&self, state: &str, binding: &str, code: &str) -> Option<(String, i64)> {
        let attempt = self.consume(state, binding)?;
        if code.is_empty() {
            return None;
        }
        let token = self.exchange(code, &attempt.verifier).await?;
        let (alg, payload) = self.verify_signature(&token.id_token?).await?;
        let id = id_claims(payload.get().as_bytes())?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let at = |secs: i64| Duration::from_secs(secs.max(0) as u64);
        let issuer_ok = id.iss == self.issuer
            || (self.issuer == "https://accounts.google.com" && id.iss == "accounts.google.com");
        // A missing `exp` is Go's zero time, which has passed.
        let exp = id.exp?;
        let expired = exp < 0 || at(exp) < now;
        let early = id.nbf.is_some_and(|nbf| now + NBF_LEEWAY < at(nbf));
        if !issuer_ok || !id.aud.contains(&self.client_id) || expired || early {
            return None;
        }

        let nonce_ok: bool = id.nonce.as_bytes().ct_eq(attempt.nonce.as_bytes()).into();
        if id.sub.is_empty() || !nonce_ok || !self.allowed_subjects.contains(&id.sub) {
            return None;
        }
        // azp is required with several audiences and must name this client when present.
        if (id.aud.len() > 1 && id.azp.is_empty())
            || (!id.azp.is_empty() && id.azp != self.client_id)
        {
            return None;
        }
        if !id.at_hash.is_empty() && at_hash(alg, &token.access_token)? != id.at_hash {
            return None;
        }
        Some((identity(&id.iss, &id.sub), exp))
    }

    /// x/oauth2's `Exchange` with PKCE, probing for the client secret style on first use.
    async fn exchange(&self, code: &str, verifier: &str) -> Option<Token> {
        let form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.redirect_url.as_str()),
            ("code_verifier", verifier),
        ];
        let known = *self
            .auth_style
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(style) = known {
            return self.token_request(&form, style).await;
        }
        let (token, style) = match self.token_request(&form, AuthStyle::Header).await {
            Some(t) => (Some(t), AuthStyle::Header),
            None => (
                self.token_request(&form, AuthStyle::Params).await,
                AuthStyle::Params,
            ),
        };
        if token.is_some() {
            *self
                .auth_style
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(style);
        }
        token
    }

    async fn token_request(&self, form: &[(&str, &str)], style: AuthStyle) -> Option<Token> {
        let url = https(&self.token_url)?;
        let mut pairs = form.to_vec();
        if matches!(style, AuthStyle::Params) {
            pairs.push(("client_id", &self.client_id));
            if !self.client_secret.is_empty() {
                pairs.push(("client_secret", &self.client_secret));
            }
        }
        let mut req = self
            .http
            .post(url)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(encode_form(pairs));
        if matches!(style, AuthStyle::Header) {
            req = req.basic_auth(
                query_escape(&self.client_id),
                Some(query_escape(&self.client_secret)),
            );
        }
        let res = req.send().await.ok()?;
        if !res.status().is_success() {
            return None;
        }
        let media_type = res
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|v| {
                v.split(';')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_ascii_lowercase()
            });
        let body = read_capped(res, BODY_LIMIT).await.ok().flatten()?;
        let token = match media_type.as_deref() {
            Some("application/x-www-form-urlencoded" | "text/plain") => {
                let vals = parse_form(&String::from_utf8_lossy(&body))?;
                let get = |key: &str| {
                    vals.iter()
                        .find(|(k, _)| k == key)
                        .map(|(_, v)| v.clone())
                        .unwrap_or_default()
                };
                Token {
                    access_token: get("access_token"),
                    error: get("error"),
                    id_token: vals
                        .iter()
                        .any(|(k, _)| k == "id_token")
                        .then(|| get("id_token")),
                }
            }
            _ => token_json(&body)?,
        };
        (token.error.is_empty() && !token.access_token.is_empty()).then_some(token)
    }

    /// go-oidc's signature check: the header's algorithm must be one the provider lists, and a
    /// key with the token's `kid` (any key without one) must verify it. Keys come from the
    /// cache first, then from a fresh fetch of the key set.
    async fn verify_signature(&self, raw: &str) -> Option<(Algorithm, Box<RawValue>)> {
        protected_header(raw)?;
        let header = jsonwebtoken::decode_header(raw).ok()?;
        if !self.algorithms.contains(&format!("{:?}", header.alg)) {
            return None;
        }
        let kid = header.kid.unwrap_or_default();
        let mut validation = Validation::new(header.alg);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;
        let verify = |keys: &[Key]| {
            keys.iter()
                .filter(|k| kid.is_empty() || k.kid == kid)
                .find_map(|k| jsonwebtoken::decode::<Box<RawValue>>(raw, &k.key, &validation).ok())
        };
        let cached = self
            .keys
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .keys
            .clone();
        if let Some(t) = verify(&cached) {
            return Some((header.alg, t.claims));
        }
        verify(&self.fetch_shared().await?).map(|t| (header.alg, t.claims))
    }

    /// go-oidc's `keysFromRemote`: one fetch at a time, and every cache miss while it runs gets
    /// its answer. The fetch runs as its own task, so it finishes even when its callers have
    /// gone, and a success replaces the cache.
    async fn fetch_shared(&self) -> Answer {
        let mut rx = {
            let mut cache = self.keys.lock().unwrap_or_else(PoisonError::into_inner);
            match &cache.fetch {
                // A closed channel is a fetch that panicked; start another.
                Some(rx) if rx.has_changed().is_ok() => rx.clone(),
                _ => {
                    let (tx, rx) = watch::channel(None);
                    cache.fetch = Some(rx.clone());
                    let (http, url) = (self.http.clone(), self.jwks_url.clone());
                    let shared = self.keys.clone();
                    tokio::spawn(async move {
                        let answer = fetch_keys(&http, &url).await.map(Arc::new);
                        let mut cache = shared.lock().unwrap_or_else(PoisonError::into_inner);
                        if let Some(keys) = &answer {
                            cache.keys = keys.clone();
                        }
                        cache.fetch = None;
                        drop(cache);
                        tx.send_replace(Some(answer));
                    });
                    rx
                }
            }
        };
        let answer = rx.wait_for(Option::is_some).await.ok()?.clone();
        answer.flatten()
    }
}

/// go-oidc's key set: a key whose `alg` go-oidc does not support is skipped, and each other one
/// must pass go-jose's checks (see `jwk`). jsonwebtoken may still be unable to use a key Go
/// keeps; that key is left out.
async fn fetch_keys(http: &reqwest::Client, url: &str) -> Option<Vec<Key>> {
    let res = get(http, url, true).await?;
    if res.status() != reqwest::StatusCode::OK {
        return None;
    }
    let body = read_capped(res, BODY_LIMIT).await.ok().flatten()?;
    let mut raw_keys = Vec::new();
    for (key, value) in go_fields(&body)? {
        if go_fold(&key) == "keys" {
            raw_keys = serde_json::from_str::<Option<Vec<Box<RawValue>>>>(value.get())
                .ok()?
                .unwrap_or_default();
        }
    }
    let mut keys = Vec::new();
    for raw in raw_keys {
        let mut alg = String::new();
        for (key, value) in go_fields(raw.get().as_bytes())? {
            if go_fold(&key) == "alg" {
                string(&mut alg, &value)?;
            }
        }
        if (!alg.is_empty() && !SUPPORTED_ALGS.contains(&alg.as_str())) || !jwk::check(&raw)? {
            continue;
        }
        let Ok(jwk) = serde_json::from_str::<Jwk>(raw.get()) else {
            continue;
        };
        if let Ok(key) = DecodingKey::from_jwk(&jwk) {
            let kid = jwk.common.key_id.unwrap_or_default();
            keys.push(Key { kid, key });
        }
    }
    Some(keys)
}

/// go-jose's protected header rules that jsonwebtoken does not apply: a repeated member fails,
/// `crit` may name only `b64`, and `b64: false` means the raw payload was signed, which this
/// port refuses.
fn protected_header(token: &str) -> Option<()> {
    let json = go_base64(token.split('.').next()?, true)?;
    let members: Members<Box<RawValue>> = serde_json::from_slice(&json).ok()?;
    let mut seen = HashSet::new();
    for (key, value) in &members.0 {
        let refused = match key.as_str() {
            "crit" => strings(value)?.iter().any(|name| name != "b64"),
            "b64" => value.get() == "false",
            _ => false,
        };
        if refused || !seen.insert(key) {
            return None;
        }
    }
    Some(())
}

/// `oidc:` and the hex SHA-256 of Go's `json.Marshal([]string{iss, sub})`, so a person keeps the
/// triage actor name the Go build gave them.
pub fn identity(iss: &str, sub: &str) -> String {
    let json = go_compact(&serde_json::to_string(&[iss, sub]).expect("strings encode"));
    let digest = Sha256::digest(json.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("oidc:{hex}")
}

/// x/oauth2's `GenerateVerifier`: 32 bytes from the OS random source, base64url.
fn random_value() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("the OS random source");
    base64url(&bytes)
}

/// go-oidc's `VerifyAccessToken`: the left half of the access token's hash under the ID token's
/// algorithm.
fn at_hash(alg: Algorithm, access_token: &str) -> Option<String> {
    use Algorithm::*;
    let digest = match alg {
        RS256 | ES256 | PS256 => Sha256::digest(access_token).to_vec(),
        RS384 | ES384 | PS384 => Sha384::digest(access_token).to_vec(),
        RS512 | PS512 | EdDSA => Sha512::digest(access_token).to_vec(),
        _ => return None,
    };
    Some(base64url(&digest[..digest.len() / 2]))
}

/// Go's `httpsTransport`: a provider URL must be HTTPS and carry no user part, even an empty
/// one, as Go's parser reads it. Go cannot send to a URL without a host.
fn https(raw: &str) -> Option<reqwest::Url> {
    let go = config::go_url(raw)?;
    if go.scheme != "https" || go.has_user || go.host.is_empty() {
        return None;
    }
    reqwest::Url::parse(raw).ok()
}

/// The whole body, or `None` past `limit` bytes without reading the rest.
pub(crate) async fn read_capped(
    mut res: reqwest::Response,
    limit: usize,
) -> reqwest::Result<Option<Vec<u8>>> {
    let mut body = Vec::new();
    while let Some(chunk) = res.chunk().await? {
        if body.len() + chunk.len() > limit {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(body))
}

async fn get(http: &reqwest::Client, raw: &str, no_cache: bool) -> Option<reqwest::Response> {
    let mut req = http.get(https(raw)?);
    if no_cache {
        req = req.header(reqwest::header::CACHE_CONTROL, "no-cache");
    }
    req.send().await.ok()
}

/// Go's `url.QueryEscape`.
fn query_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(b))
            }
            b' ' => out.push('+'),
            _ => out += &format!("%{b:02X}"),
        }
    }
    out
}

/// Go's `url.Values.Encode`: pairs sorted by key, each side query-escaped.
fn encode_form(mut pairs: Vec<(&str, &str)>) -> String {
    pairs.sort_by_key(|(k, _)| *k);
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", query_escape(k), query_escape(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Go's `url.ParseQuery`, which fails on a pair holding `;` or a bad escape.
fn parse_form(body: &str) -> Option<Vec<(String, String)>> {
    let unescape = |s: &str| {
        config::unescape(&s.replace('+', " ")).map(|b| String::from_utf8_lossy(&b).into_owned())
    };
    body.split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| {
            if kv.contains(';') {
                return None;
            }
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            Some((unescape(k)?, unescape(v)?))
        })
        .collect()
}

type Fields = Vec<(String, Box<RawValue>)>;

/// The members of a body as Go's `json.Unmarshal` reads it into a struct: the body is one JSON
/// value, `null` sets nothing, and any other value but an object fails. Keys match struct fields
/// case-insensitively (see `go_fold`), and a repeated key's last value wins.
///
/// shortcut: invalid UTF-8 fails here; Go reads it as U+FFFD. Fix when a provider sends it.
fn go_fields(body: &[u8]) -> Option<Fields> {
    let members: Option<Members<Box<RawValue>>> = serde_json::from_slice(body).ok()?;
    Some(members.map_or_else(Vec::new, |m| m.0))
}

/// A string field: `null` leaves it as it was, any other type fails.
fn string(slot: &mut String, value: &RawValue) -> Option<()> {
    if let Some(s) = serde_json::from_str::<Option<String>>(value.get()).ok()? {
        *slot = s;
    }
    Some(())
}

/// A `[]string` field: a `null` element reads as "".
fn strings(value: &RawValue) -> Option<Vec<String>> {
    let items: Option<Vec<Option<String>>> = serde_json::from_str(value.get()).ok()?;
    Some(
        items
            .unwrap_or_default()
            .into_iter()
            .map(Option::unwrap_or_default)
            .collect(),
    )
}

/// The text of a `json.Number`: a JSON number, or a string holding one. `null` reads as "".
fn go_number(value: &RawValue) -> Option<String> {
    let text = value.get();
    match text.as_bytes().first()? {
        b'n' => Some(String::new()),
        b'"' => {
            let s: String = serde_json::from_str(text).ok()?;
            let valid = !s.starts_with(|c: char| c.is_ascii_whitespace())
                && !s.ends_with(|c: char| c.is_ascii_whitespace())
                && serde_json::from_str::<serde_json::Number>(&s).is_ok();
            valid.then_some(s)
        }
        b'-' | b'0'..=b'9' => Some(text.to_owned()),
        _ => None,
    }
}

/// go-oidc's `jsonTime`: whole seconds, a fraction cut off. `null` fails.
fn json_time(value: &RawValue) -> Option<i64> {
    let n = go_number(value)?;
    n.parse::<i64>().ok().or_else(|| {
        n.parse::<f64>()
            .ok()
            .filter(|f| f.is_finite())
            .map(|f| f as i64)
    })
}

#[derive(Default)]
struct Discovery {
    issuer: String,
    auth_url: String,
    token_url: String,
    jwks_url: String,
    algorithms: Vec<String>,
}

/// go-oidc's `providerJSON`. The endpoints it does not use still have to be strings.
fn discovery(body: &[u8]) -> Option<Discovery> {
    let (mut d, mut unused) = (Discovery::default(), String::new());
    for (key, value) in go_fields(body)? {
        match go_fold(&key).as_str() {
            "issuer" => string(&mut d.issuer, &value)?,
            "authorization_endpoint" => string(&mut d.auth_url, &value)?,
            "token_endpoint" => string(&mut d.token_url, &value)?,
            "jwks_uri" => string(&mut d.jwks_url, &value)?,
            "device_authorization_endpoint" | "userinfo_endpoint" => string(&mut unused, &value)?,
            "id_token_signing_alg_values_supported" => d.algorithms = strings(&value)?,
            _ => {}
        }
    }
    Some(d)
}

struct Token {
    access_token: String,
    error: String,
    id_token: Option<String>,
}

/// x/oauth2's `tokenJSON`, then `id_token` from the raw map, where keys match exactly.
fn token_json(body: &[u8]) -> Option<Token> {
    let mut token = Token {
        access_token: String::new(),
        error: String::new(),
        id_token: None,
    };
    let mut unused = String::new();
    for (key, value) in go_fields(body)? {
        match go_fold(&key).as_str() {
            "access_token" => string(&mut token.access_token, &value)?,
            "error" => string(&mut token.error, &value)?,
            "token_type" | "refresh_token" | "error_description" | "error_uri" => {
                string(&mut unused, &value)?
            }
            // A number or numeric string that fits an int64, or null.
            "expires_in" if value.get() != "null" => {
                go_number(&value)?.parse::<i64>().ok()?;
            }
            _ => {}
        }
        if key == "id_token" {
            token.id_token = serde_json::from_str::<String>(value.get()).ok();
        }
    }
    Some(token)
}

#[derive(Default)]
struct IdClaims {
    iss: String,
    sub: String,
    aud: Vec<String>,
    exp: Option<i64>,
    nbf: Option<i64>,
    nonce: String,
    at_hash: String,
    azp: String,
}

/// go-oidc's `idToken`, plus `azp`. A mistyped claim fails, as do `exp` and `iat` set to null,
/// and a distributed claim whose source is missing.
fn id_claims(payload: &[u8]) -> Option<IdClaims> {
    let mut c = IdClaims::default();
    let mut names: HashMap<String, String> = HashMap::new();
    let mut sources = HashSet::new();
    for (key, value) in go_fields(payload)? {
        match go_fold(&key).as_str() {
            "iss" => string(&mut c.iss, &value)?,
            "sub" => string(&mut c.sub, &value)?,
            "nonce" => string(&mut c.nonce, &value)?,
            "at_hash" => string(&mut c.at_hash, &value)?,
            "azp" => string(&mut c.azp, &value)?,
            "aud" => c.aud = audience(&value)?,
            "exp" => c.exp = Some(json_time(&value)?),
            "iat" => {
                json_time(&value)?;
            }
            "nbf" if value.get() == "null" => c.nbf = None,
            "nbf" => c.nbf = Some(json_time(&value)?),
            "_claim_names" => {
                let map: Option<HashMap<String, Option<String>>> =
                    serde_json::from_str(value.get()).ok()?;
                names = map
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(k, v)| (k, v.unwrap_or_default()))
                    .collect();
            }
            "_claim_sources" => {
                let map: Option<Members<Box<RawValue>>> = serde_json::from_str(value.get()).ok()?;
                sources.clear();
                for (name, source) in map.map_or_else(Vec::new, |m| m.0) {
                    let mut unused = String::new();
                    for (field, v) in go_fields(source.get().as_bytes())? {
                        if matches!(go_fold(&field).as_str(), "endpoint" | "access_token") {
                            string(&mut unused, &v)?;
                        }
                    }
                    sources.insert(name);
                }
            }
            _ => {}
        }
    }
    if names
        .values()
        .any(|src| src.is_empty() || !sources.contains(src))
    {
        return None;
    }
    Some(c)
}

/// go-oidc's `audience`: one string or a list. `null` reads as one empty audience.
fn audience(value: &RawValue) -> Option<Vec<String>> {
    match serde_json::from_str::<Option<String>>(value.get()) {
        Ok(one) => Some(vec![one.unwrap_or_default()]),
        Err(_) => strings(value),
    }
}

mod jwk;
#[cfg(test)]
mod tests;
