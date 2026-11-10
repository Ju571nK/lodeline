//! Host enrollment files (#553): the settings, the file template, and the client that asks
//! `lodeline-server` to mint a single-use token. The console keeps no token and no file.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use lodeline_fleet_api::enrollment::{
    EnrollmentFile, PolicyKey, PolicyKeystore, ENROLLMENT_FORMAT, MAX_ENROLLMENT_FILE_BYTES,
};
use lodeline_fleet_api::mint::{MintRequest, MintResponse, MINT_PATH, REQUESTED_BY_HEADER};
use reqwest::header::HeaderValue;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::config::{ConfigError, ServerTls};
use crate::fleet::{read_capped, BoxFuture};

pub const MINT_TOKEN: &str = "LODELINE_ENROLL_MINT_TOKEN";
pub const MINT_CERT: &str = "LODELINE_ENROLL_MINT_CERT_PATH";
pub const MINT_KEY: &str = "LODELINE_ENROLL_MINT_KEY_PATH";
pub const FILE_SERVER_URL: &str = "LODELINE_ENROLL_FILE_SERVER_URL";
pub const FILE_ENROLL_URL: &str = "LODELINE_ENROLL_FILE_ENROLL_URL";
pub const FILE_CA: &str = "LODELINE_ENROLL_FILE_CA_PATH";
pub const FILE_KEYSTORE: &str = "LODELINE_ENROLL_FILE_POLICY_KEYSTORE_PATH";
pub const PUBLIC_ORIGIN: &str = "LODELINE_PUBLIC_ORIGIN";
pub const SUBJECTS: &str = "LODELINE_ENROLL_SUBJECTS";
/// The variables that switch the feature on, all or none.
pub const REQUIRED: [&str; 8] = [
    MINT_TOKEN,
    MINT_CERT,
    MINT_KEY,
    FILE_SERVER_URL,
    FILE_ENROLL_URL,
    FILE_CA,
    FILE_KEYSTORE,
    PUBLIC_ORIGIN,
];

const MINT_TIMEOUT: Duration = Duration::from_secs(10);
const ANSWER_LIMIT: usize = 4 << 10;
const ERROR_LIMIT: usize = 1 << 10;

/// The mint bearer. `Debug` prints a fixed word and there is no `Display`.
#[derive(Clone)]
pub struct Bearer(String);

impl fmt::Debug for Bearer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// The host enrollment route: off with the variables still unset, or its settings.
#[derive(Debug)]
pub enum Enroll {
    Off(Vec<&'static str>),
    On(Active),
}

#[derive(Debug)]
pub struct Active {
    pub template: Template,
    pub enroller: Arc<dyn Enroller>,
    pub public_origin: String,
    pub subjects: Vec<String>,
}

impl Active {
    pub fn may_enroll(&self, subject: &str) -> bool {
        self.subjects.is_empty() || self.subjects.iter().any(|s| s == subject)
    }
}

fn invalid(msg: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(msg.into())
}

impl Enroll {
    /// `trimmed` reads a variable. The eight of [`REQUIRED`] are all or none; with
    /// `MOCK_FLEET=1` only `LODELINE_PUBLIC_ORIGIN` is read and the rest are mock values.
    pub fn load(
        trimmed: &dyn Fn(&str) -> String,
        subjects_raw: &str,
        server: (&str, Option<&ServerTls>),
        mock: bool,
    ) -> Result<Self, ConfigError> {
        let subjects = subjects(subjects_raw)?;
        let missing: Vec<_> = REQUIRED
            .into_iter()
            .filter(|n| trimmed(n).is_empty())
            .collect();
        if mock {
            if missing.contains(&PUBLIC_ORIGIN) {
                return Ok(Self::Off(vec![PUBLIC_ORIGIN]));
            }
        } else if missing.len() == REQUIRED.len() {
            return Ok(Self::Off(missing));
        } else if !missing.is_empty() {
            return Err(ConfigError::MissingRequired(missing));
        }
        let public_origin = origin_of(&trimmed(PUBLIC_ORIGIN)).ok_or_else(|| {
            invalid(format!("config: {PUBLIC_ORIGIN} must be one origin such as https://console.example.com, with no path or trailing slash"))
        })?;
        if !mock && !server.0.starts_with("https://") {
            return Err(invalid("config: LODELINE_SERVER_BASE_URL must be an https URL when the enrollment route is on"));
        }
        let (template, enroller): (_, Arc<dyn Enroller>) = if mock {
            (Template::mock(), Arc::new(MockEnroller))
        } else {
            let template = Template {
                server_url: https_origin(&trimmed(FILE_SERVER_URL), FILE_SERVER_URL)?,
                enroll_url: https_origin(&trimmed(FILE_ENROLL_URL), FILE_ENROLL_URL)?,
                ca: Source::File(FILE_CA, trimmed(FILE_CA).into()),
                keystore: Source::File(FILE_KEYSTORE, trimmed(FILE_KEYSTORE).into()),
            };
            let probe = template
                .load()
                .and_then(|l| l.render("", "", &"x".repeat(256)));
            probe.map_err(|e| invalid(format!("config: {e}")))?;
            let identity = mint_identity(
                &trimmed(MINT_CERT),
                &trimmed(MINT_KEY),
                &trimmed("LODELINE_SERVER_CLIENT_CERT_PATH"),
            )?;
            let bearer = Bearer(trimmed(MINT_TOKEN));
            let roots = server.1.map_or(&[][..], |t| &t.roots[..]);
            let http = HttpEnroller::new(server.0, bearer, identity, roots, MINT_TIMEOUT).map_err(
                |e| {
                    invalid(format!(
                        "config: mint client ({MINT_CERT}, {MINT_KEY}): {e}"
                    ))
                },
            )?;
            (template, Arc::new(http))
        };
        Ok(Self::On(Active {
            template,
            enroller,
            public_origin,
            subjects,
        }))
    }
}

/// `LODELINE_ENROLL_SUBJECTS`: a JSON array like `OIDC_ALLOWED_SUBJECTS`. Empty means unset.
fn subjects(raw: &str) -> Result<Vec<String>, ConfigError> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    let list = serde_json::from_str::<Vec<String>>(raw)
        .ok()
        .filter(|l| !l.is_empty() && l.iter().all(|s| !s.trim().is_empty()))
        .ok_or_else(|| {
            invalid(format!(
                "config: {SUBJECTS} must be a non-empty JSON array of subject strings; leave it unset to allow every signed-in subject"
            ))
        })?;
    Ok(list)
}

fn mint_identity(cert: &str, key: &str, read_cert: &str) -> Result<reqwest::Identity, ConfigError> {
    let err = |var: &str, e: &dyn fmt::Display| invalid(format!("config: {var}: {e}"));
    let cert_pem = std::fs::read(cert).map_err(|e| err(MINT_CERT, &e))?;
    let leaf = pem_certs(&cert_pem)
        .and_then(|c| c.into_iter().next())
        .ok_or_else(|| err(MINT_CERT, &"no PEM certificate"))?;
    let read_leaf = std::fs::read(read_cert)
        .ok()
        .and_then(|p| pem_certs(&p)?.into_iter().next());
    if read_leaf.is_some_and(|d| d == leaf) {
        return Err(err(
            MINT_CERT,
            &"must differ from LODELINE_SERVER_CLIENT_CERT_PATH; the mint credential is never the read credential",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(key)
            .map_err(|e| err(MINT_KEY, &e))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(err(
                MINT_KEY,
                &"the key file must not be accessible by group or others (chmod 600)",
            ));
        }
    }
    let mut pem = cert_pem;
    pem.push(b'\n');
    pem.extend(std::fs::read(key).map_err(|e| err(MINT_KEY, &e))?);
    reqwest::Identity::from_pem(&pem).map_err(|e| {
        err(
            "LODELINE_ENROLL_MINT_CERT_PATH / LODELINE_ENROLL_MINT_KEY_PATH",
            &e,
        )
    })
}

/// The DER of every `CERTIFICATE` block; `None` on a PEM error or any other kind of block.
fn pem_certs(pem: &[u8]) -> Option<Vec<Vec<u8>>> {
    use rustls::pki_types::pem::{self, SectionKind};
    let (mut rest, mut out) = (pem, Vec::new());
    loop {
        match pem::from_buf(&mut rest) {
            Ok(None) => return Some(out),
            Ok(Some((SectionKind::Certificate, der))) => out.push(der),
            Ok(Some(_)) | Err(_) => return None,
        }
    }
}

/// One origin in the form a browser sends: `http` or `https`, a host, an optional port, nothing
/// else. The result is the scheme, lower-case host and port with a default port left out.
pub fn origin_of(raw: &str) -> Option<String> {
    let u = reqwest::Url::parse(raw).ok()?;
    let plain = matches!(u.scheme(), "http" | "https")
        && u.host_str().is_some()
        && u.username().is_empty()
        && u.password().is_none()
        && u.query().is_none()
        && u.fragment().is_none()
        && u.path() == "/";
    (plain && !raw.ends_with('/')).then(|| u.origin().ascii_serialization())
}

/// The sender's rule for `server_url` and `enroll_url`: an `https` origin.
fn https_origin(raw: &str, var: &str) -> Result<String, ConfigError> {
    origin_of(raw)
        .filter(|o| o.starts_with("https://"))
        .ok_or_else(|| {
            invalid(format!(
                "config: {var} must be an https origin such as https://lodeline.example.com:8443, with no path"
            ))
        })
}

// ---- the file --------------------------------------------------------------------------

/// A setting that is unusable, named so the operator knows which one to fix.
#[derive(Clone, Debug)]
pub struct TemplateError(String);

impl fmt::Display for TemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn te(var: &str, why: impl fmt::Display) -> TemplateError {
    TemplateError(format!("{var}: {why}"))
}

#[derive(Clone, Debug)]
enum Source {
    File(&'static str, PathBuf),
    Inline(&'static str, &'static str),
}

impl Source {
    fn read(&self) -> Result<Vec<u8>, TemplateError> {
        match self {
            Self::File(var, path) => std::fs::read(path).map_err(|e| te(var, e)),
            Self::Inline(_, text) => Ok(text.as_bytes().to_vec()),
        }
    }
    fn var(&self) -> &'static str {
        match self {
            Self::File(var, _) | Self::Inline(var, _) => var,
        }
    }
}

/// Where the fixed parts of every file come from. The files are read again on each call, so
/// what is shown is what a file made now holds.
#[derive(Clone, Debug)]
pub struct Template {
    server_url: String,
    enroll_url: String,
    ca: Source,
    keystore: Source,
}

#[derive(Serialize)]
pub struct CaInfo {
    pub subject: String,
    pub sha256: String,
}

#[derive(Serialize)]
pub struct KeyInfo {
    pub id: String,
    pub sha256: String,
    pub valid_from: String,
    pub valid_until: String,
}

pub struct Loaded {
    pub server_url: String,
    pub enroll_url: String,
    ca_pem: String,
    keystore: PolicyKeystore,
    pub cas: Vec<CaInfo>,
    pub keys: Vec<KeyInfo>,
}

const MOCK_CA: &str = "-----BEGIN CERTIFICATE-----
MIIBazCCARKgAwIBAgIUUYCWRkvwzUsZ9TYh3OC2IldvHBAwCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQbG9kZWxpbmUtbW9jay1jYTAgFw0yNjExMTAyMTMxNTBaGA8y
MTI2MTAxNzIxMzE1MFowGzEZMBcGA1UEAwwQbG9kZWxpbmUtbW9jay1jYTBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABPFliD3fDrquuAT8NNJEUBhvn1DZj28101Ze
/2XxxKQjaCRGpAmjMhnBufv8sueWVag4AOthP0NJGNReMKHeSQOjMjAwMB0GA1Ud
DgQWBBTnlfFksHOg73+I/T9lmkPVJkFdfTAPBgNVHRMBAf8EBTADAQH/MAoGCCqG
SM49BAMCA0cAMEQCIDdLiK+4NjfhCS6gizDhHq99MU2jUAzkKHprVVuB+DUnAiBL
4uvzZ7k4fTztkz/+PaRDUBvCXHIpO/gMSUjvlesbNA==
-----END CERTIFICATE-----
";
const MOCK_KEYSTORE: &str = r#"{"pubkeys":[{"id":"mock-key-1","ed25519_pubkey_b64":"xKVQIC12z2nEWqPizVT8sAuQLaXtfPgZURnVS0+pcU8=","valid_from":"2020-01-01T00:00:00Z","valid_until":"2099-01-01T00:00:00Z"}]}"#;

impl Template {
    pub(crate) fn mock() -> Self {
        Self {
            server_url: "https://lodeline.example.com:8443".into(),
            enroll_url: "https://lodeline.example.com:8444".into(),
            ca: Source::Inline(FILE_CA, MOCK_CA),
            keystore: Source::Inline(FILE_KEYSTORE, MOCK_KEYSTORE),
        }
    }

    /// Reads and checks both files by the reader's rules, never quoting a value.
    pub fn load(&self) -> Result<Loaded, TemplateError> {
        let (ca, ks) = (self.ca.read()?, self.keystore.read()?);
        let ca_pem = String::from_utf8(ca).map_err(|_| te(self.ca.var(), "not UTF-8 text"))?;
        let cas = ca_info(&ca_pem).map_err(|e| te(self.ca.var(), e))?;
        let (keystore, keys) = keystore_info(&ks).map_err(|e| te(self.keystore.var(), e))?;
        Ok(Loaded {
            server_url: self.server_url.clone(),
            enroll_url: self.enroll_url.clone(),
            ca_pem,
            keystore,
            cas,
            keys,
        })
    }
}

impl Loaded {
    /// The file's bytes: pretty JSON and a newline, checked against the reader's size limit.
    pub fn render(
        &self,
        host_id: &str,
        expires_at: &str,
        token: &str,
    ) -> Result<Vec<u8>, TemplateError> {
        let file = EnrollmentFile {
            enroll_url: self.enroll_url.clone(),
            expires_at: Some(expires_at.into()),
            host_id: host_id.into(),
            lodeline_enrollment: ENROLLMENT_FORMAT,
            policy_keystore: self.keystore.clone(),
            server_ca_pem: self.ca_pem.clone(),
            server_url: self.server_url.clone(),
            token: token.into(),
        };
        let mut out = serde_json::to_vec_pretty(&file).expect("a file of strings serializes");
        out.push(b'\n');
        if out.len() as u64 > MAX_ENROLLMENT_FILE_BYTES {
            return Err(te(
                &format!("{FILE_CA} / {FILE_KEYSTORE}"),
                "the enrollment file would be over 64 KiB, which hosts refuse; use a smaller file",
            ));
        }
        Ok(out)
    }
}

/// SHA-256 as upper-case hex pairs with colons, the form `lodeline-sender enroll` prints.
fn fingerprint(bytes: &[u8]) -> String {
    let hex: Vec<_> = Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect();
    hex.join(":")
}

/// The reader's rules for `server_ca_pem`: certificates only, at least one.
fn ca_info(pem: &str) -> Result<Vec<CaInfo>, &'static str> {
    let blocks = pem.lines().filter(|l| l.starts_with("-----BEGIN "));
    if pem.to_ascii_uppercase().contains("KEY-----")
        || blocks
            .into_iter()
            .any(|l| l.trim_end() != "-----BEGIN CERTIFICATE-----")
    {
        return Err("may hold only CERTIFICATE blocks, never a private key");
    }
    let ders = pem_certs(pem.as_bytes()).ok_or("is not valid PEM")?;
    if ders.is_empty() {
        return Err("holds no certificate");
    }
    ders.iter()
        .map(|der| {
            let (_, c) = x509_parser::parse_x509_certificate(der)
                .map_err(|_| "holds a block that is not an X.509 certificate")?;
            Ok(CaInfo {
                subject: c.subject().to_string(),
                sha256: fingerprint(der),
            })
        })
        .collect()
}

/// The reader's rules for the keystore. A parse error gives a position, never a value.
fn keystore_info(bytes: &[u8]) -> Result<(PolicyKeystore, Vec<KeyInfo>), String> {
    let ks: PolicyKeystore = serde_json::from_slice(bytes).map_err(|e| {
        format!(
            "is not a keystore (line {}, column {})",
            e.line(),
            e.column()
        )
    })?;
    if ks.pubkeys.is_empty() {
        return Err("needs at least one key".into());
    }
    let keys = ks
        .pubkeys
        .iter()
        .enumerate()
        .map(|(i, k): (usize, &PolicyKey)| {
            let raw = b64_decode(&k.ed25519_pubkey_b64).filter(|r| r.len() == 32);
            let time = |s: &str| chrono::DateTime::parse_from_rfc3339(s).ok();
            let (from, until) = (time(&k.valid_from), time(&k.valid_until));
            match (raw, from, until) {
                (None, ..) => Err(format!(
                    "key {i}: ed25519_pubkey_b64 must be base64 of 32 bytes"
                )),
                (_, None, _) | (_, _, None) => Err(format!(
                    "key {i}: valid_from and valid_until must be RFC 3339 times"
                )),
                (_, Some(f), Some(u)) if f >= u => {
                    Err(format!("key {i}: valid_from must be before valid_until"))
                }
                (Some(raw), ..) => Ok(KeyInfo {
                    id: k.id.clone(),
                    sha256: fingerprint(&raw),
                    valid_from: k.valid_from.clone(),
                    valid_until: k.valid_until.clone(),
                }),
            }
        });
    let keys = keys.collect::<Result<Vec<_>, _>>()?;
    Ok((ks, keys))
}

/// Standard base64 with padding, and no leftover bits, as the reader's decoder is.
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let pad = s.bytes().rev().take_while(|&b| b == b'=').count();
    if !s.len().is_multiple_of(4) || pad > 2 {
        return None;
    }
    let (mut out, mut acc, mut bits) = (Vec::new(), 0u32, 0);
    for b in s[..s.len() - pad].bytes() {
        acc = acc << 6 | ALPHABET.iter().position(|&a| a == b)? as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    (acc == 0).then_some(out)
}

// ---- the host id -----------------------------------------------------------------------

/// A random version 4 UUID, lowercase and hyphenated.
pub fn new_host_id() -> Result<String, getrandom::Error> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b)?;
    b[6] = b[6] & 0x0f | 0x40;
    b[8] = b[8] & 0x3f | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
}

/// The form `lodeline-sender enroll` accepts: version 4, RFC 4122 variant, lowercase, hyphenated.
pub fn is_canonical_v4(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(&c),
        })
        && b[14] == b'4'
        && matches!(b[19], b'8' | b'9' | b'a' | b'b')
}

// ---- the mint --------------------------------------------------------------------------

/// Why no token came back. Each maps to one answer of the console's own.
#[derive(Debug, PartialEq, Eq)]
pub enum MintError {
    HostExists,
    TokenOutstanding,
    LimitReached,
    /// The server answered 404: no mint there, or the mint certificate is not accepted.
    Unavailable,
    /// 401 or 403.
    Refused,
    Failed,
}

pub trait Enroller: Send + Sync + fmt::Debug {
    fn mint<'a>(
        &'a self,
        host_id: &'a str,
        subject: &'a str,
    ) -> BoxFuture<'a, Result<MintResponse, MintError>>;
}

/// Posts to the server's mint route with the mint identity. Never retried: a retry after a lost
/// answer would make a second token.
#[derive(Debug)]
pub struct HttpEnroller {
    url: String,
    bearer: Bearer,
    http: reqwest::Client,
}

impl HttpEnroller {
    /// `roots` are the read client's, so the same server is trusted. No redirect is followed and
    /// no environment proxy is used: the bearer goes to the one URL and nowhere else.
    pub fn new(
        base_url: &str,
        bearer: Bearer,
        identity: reqwest::Identity,
        roots: &[reqwest::Certificate],
        timeout: Duration,
    ) -> reqwest::Result<Self> {
        let mut b = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .no_proxy()
            .tls_built_in_webpki_certs(false)
            .identity(identity);
        if !roots.is_empty() {
            b = b.tls_built_in_root_certs(false);
        }
        for root in roots {
            b = b.add_root_certificate(root.clone());
        }
        let url = format!("{}{MINT_PATH}", base_url.trim_end_matches('/'));
        Ok(Self {
            url,
            bearer,
            http: b.build()?,
        })
    }

    async fn post(&self, host_id: &str, subject: &str) -> Result<MintResponse, MintError> {
        // The subject is the admin's name, which may hold any character: escape it, keep visible ASCII.
        let who: String = subject
            .escape_default()
            .to_string()
            .chars()
            .filter(|c| (' '..='~').contains(c))
            .collect();
        let mut req = self
            .http
            .post(&self.url)
            .bearer_auth(&self.bearer.0)
            .json(&MintRequest {
                host_id: host_id.into(),
            });
        if let Ok(v) = HeaderValue::from_str(&who) {
            req = req.header(REQUESTED_BY_HEADER, v);
        }
        let res = req.send().await.map_err(|_| MintError::Failed)?;
        let status = res.status().as_u16();
        match status {
            201 => {
                let body = read_capped(res, ANSWER_LIMIT)
                    .await
                    .ok()
                    .flatten()
                    .ok_or(MintError::Failed)?;
                serde_json::from_slice(&body).map_err(|_| MintError::Failed)
            }
            404 => Err(MintError::Unavailable),
            401 | 403 => Err(MintError::Refused),
            429 => Err(MintError::LimitReached),
            409 => {
                let body = read_capped(res, ERROR_LIMIT)
                    .await
                    .ok()
                    .flatten()
                    .unwrap_or_default();
                let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                Err(match v["error"]["code"].as_str() {
                    Some("host_exists") => MintError::HostExists,
                    Some("token_outstanding") => MintError::TokenOutstanding,
                    _ => MintError::Failed,
                })
            }
            _ => Err(MintError::Failed),
        }
    }
}

impl Enroller for HttpEnroller {
    fn mint<'a>(
        &'a self,
        host_id: &'a str,
        subject: &'a str,
    ) -> BoxFuture<'a, Result<MintResponse, MintError>> {
        Box::pin(self.post(host_id, subject))
    }
}

/// `MOCK_FLEET=1`: a token that works nowhere.
#[derive(Debug)]
struct MockEnroller;

impl Enroller for MockEnroller {
    fn mint<'a>(
        &'a self,
        host_id: &'a str,
        _: &'a str,
    ) -> BoxFuture<'a, Result<MintResponse, MintError>> {
        let expires = chrono::Utc::now() + chrono::Duration::hours(1);
        Box::pin(async move {
            Ok(MintResponse {
                expires_at: expires.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                host_id: host_id.into(),
                token: "mock-enrollment-token-not-valid-anywhere".into(),
            })
        })
    }
}

#[cfg(test)]
mod tests;
