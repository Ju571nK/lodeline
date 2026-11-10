//! Runtime configuration from environment variables, with the names, defaults and validation of
//! the Go `internal/config` package. `.env.example` lists every variable.

use std::fmt;
use std::net::Ipv6Addr;
use std::sync::Arc;

use crate::enroll::{Enroll, SUBJECTS};
use std::time::Duration;

pub struct Config {
    /// `LISTEN_ADDR`, default `:8080`.
    pub listen_addr: String,
    /// `MOCK_FLEET=1` serves the built-in mock fleet and relaxes the server URL and token.
    pub mock_fleet: bool,
    /// `LODELINE_SERVER_BASE_URL`, required unless `mock_fleet`.
    pub server_base_url: String,
    /// `LODELINE_SERVER_READ_TOKEN`, required unless `mock_fleet`.
    pub server_read_token: String,
    /// Set when `LODELINE_SERVER_CA_PATH` or the client certificate pair is set (never in mock mode).
    pub server_tls: Option<ServerTls>,
    /// `TRIAGE_DB_PATH`, default `./var/triage.sqlite`.
    pub triage_db_path: String,
    pub admin_username: String,
    pub admin_password_bcrypt: String,
    /// `JWT_SECRET`, at least 32 bytes after trimming.
    pub jwt_secret: String,
    /// `JWT_TTL_HOURS`, default 12.
    pub jwt_ttl: Duration,
    /// `FLEET_POLL_INTERVAL_SECONDS`, default 5.
    pub fleet_poll_interval: Duration,
    /// `FLEET_CACHE_DISABLED=1`.
    pub fleet_cache_disabled: bool,
    /// `FLEET_CACHE_MAX_ENTRIES`, default 512.
    pub fleet_cache_max_entries: i64,
    /// `None` when every `OIDC_*` variable is unset.
    pub oidc: Option<OidcConfig>,
    /// `TRUSTED_PROXIES`: the peers whose `X-Forwarded-For` the login limiter reads. Empty by
    /// default.
    pub trusted_proxies: Vec<ipnet::IpNet>,
    /// The host enrollment file route (#553): off, or its settings.
    pub enroll: Arc<Enroll>,
}

/// The CA and client certificate for an mTLS `lodeline-server`.
pub struct ServerTls {
    pub roots: Vec<reqwest::Certificate>,
    pub identity: Option<reqwest::Identity>,
}

pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
    pub allowed_subjects: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// Required variables that are unset or empty, all of them in one error.
    MissingRequired(Vec<&'static str>),
    Invalid(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRequired(names) => {
                write!(f, "config: required env var unset: {}", names.join(", "))
            }
            Self::Invalid(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for ConfigError {}

// Public values earlier `.env.example` files set. The hash is compared as text, not checked with
// bcrypt: copying the file is how it gets set, and bcrypt at the hash's own cost slows every start.
const EXAMPLE_READ_TOKEN: &str = "replace-with-your-shared-secret";
const EXAMPLE_ADMIN_HASH: &str = "$2a$10$55LlvKwbVdEZOVEdFBFshuFyd1fqHDSKTTXgK5L890cxNNZxATtg2";
const EXAMPLE_JWT_SECRET: &str = "replace-this-with-a-32-byte-or-longer-secret";

fn invalid(msg: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(msg.into())
}

impl Config {
    /// Reads and validates the configuration. `env` returns a variable's value; an empty value
    /// counts as unset. Checks run in the Go order, so the same bad environment reports the
    /// same first error.
    pub fn load(env: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let raw = |key: &str| env(key).unwrap_or_default();
        let trimmed = |key: &str| raw(key).trim().to_owned();
        let or_default = |key: &str, fallback: &str| match trimmed(key) {
            v if v.is_empty() => fallback.to_owned(),
            v => v,
        };
        let int_or_default = |key: &str, fallback: i64| match trimmed(key) {
            v if v.is_empty() => Ok(fallback),
            v => v
                .parse::<i64>()
                .map_err(|e| invalid(format!("config: {key} must be an integer: {e}"))),
        };

        let mock_fleet = raw("MOCK_FLEET") == "1";
        let server_base_url = trimmed("LODELINE_SERVER_BASE_URL");

        let subjects_raw = raw("OIDC_ALLOWED_SUBJECTS");
        let allowed_subjects = if subjects_raw.is_empty() {
            Vec::new()
        } else {
            serde_json::from_str::<Option<Vec<String>>>(&subjects_raw)
                .map_err(|_| {
                    invalid("OIDC_ALLOWED_SUBJECTS must be a JSON array of subject strings")
                })?
                .unwrap_or_default()
        };
        let oidc = OidcConfig {
            issuer: trimmed("OIDC_ISSUER_URL"),
            client_id: trimmed("OIDC_CLIENT_ID"),
            client_secret: raw("OIDC_CLIENT_SECRET"),
            redirect_url: trimmed("OIDC_REDIRECT_URL"),
            allowed_subjects,
        }
        .validate()?;

        let server_tls = if mock_fleet {
            None
        } else {
            let tls = load_server_tls(&trimmed)?;
            let https = go_url(&server_base_url).is_some_and(|u| u.scheme == "https");
            if tls.is_some() && !https {
                return Err(invalid("config: LODELINE_SERVER_CA_PATH / LODELINE_SERVER_CLIENT_CERT_PATH need an https:// LODELINE_SERVER_BASE_URL"));
            }
            tls
        };

        let ttl_hours = int_or_default("JWT_TTL_HOURS", 12)?;
        let poll_seconds = int_or_default("FLEET_POLL_INTERVAL_SECONDS", 5)?;
        let fleet_cache_max_entries = int_or_default("FLEET_CACHE_MAX_ENTRIES", 512)?;

        let mut missing = Vec::new();
        let server_read_token = trimmed("LODELINE_SERVER_READ_TOKEN");
        if !mock_fleet {
            if server_base_url.is_empty() {
                missing.push("LODELINE_SERVER_BASE_URL");
            }
            if server_read_token.is_empty() {
                missing.push("LODELINE_SERVER_READ_TOKEN");
            }
        }
        let admin_username = trimmed("ADMIN_USERNAME");
        let admin_password_bcrypt = trimmed("ADMIN_PASSWORD_BCRYPT");
        let jwt_secret = trimmed("JWT_SECRET");
        for (name, value) in [
            ("ADMIN_USERNAME", &admin_username),
            ("ADMIN_PASSWORD_BCRYPT", &admin_password_bcrypt),
            ("JWT_SECRET", &jwt_secret),
        ] {
            if value.is_empty() {
                missing.push(name);
            }
        }
        if !missing.is_empty() {
            return Err(ConfigError::MissingRequired(missing));
        }
        let example = [
            (
                "LODELINE_SERVER_READ_TOKEN",
                !mock_fleet && server_read_token == EXAMPLE_READ_TOKEN,
            ),
            (
                "ADMIN_PASSWORD_BCRYPT",
                admin_password_bcrypt == EXAMPLE_ADMIN_HASH,
            ),
            ("JWT_SECRET", jwt_secret == EXAMPLE_JWT_SECRET),
        ];
        if let Some((name, _)) = example.iter().find(|(_, same)| *same) {
            return Err(invalid(format!(
                "config: {name} is the public example value from .env.example; set a secret of your own (.env.example shows how to generate one)"
            )));
        }
        if jwt_secret.len() < 32 {
            return Err(invalid(format!(
                "config: JWT_SECRET must be at least 32 bytes (got {})",
                jwt_secret.len()
            )));
        }
        if !is_bcrypt_hash(&admin_password_bcrypt) {
            return Err(invalid("config: ADMIN_PASSWORD_BCRYPT does not look like a bcrypt hash (must start with $2a$, $2b$, or $2y$)"));
        }
        // Go multiplies into a nanosecond Duration, so it also refuses anything past about 292 years.
        let jwt_ttl = positive_duration("JWT_TTL_HOURS", ttl_hours, 3600)?;
        let fleet_poll_interval =
            positive_duration("FLEET_POLL_INTERVAL_SECONDS", poll_seconds, 1)?;
        let trusted_proxies = trusted_proxies(&raw("TRUSTED_PROXIES"))?;
        let server = (server_base_url.as_str(), server_tls.as_ref());
        let enroll = Enroll::load(&trimmed, &raw(SUBJECTS), server, mock_fleet)?;

        Ok(Self {
            listen_addr: or_default("LISTEN_ADDR", ":8080"),
            mock_fleet,
            server_base_url,
            server_read_token,
            server_tls,
            triage_db_path: or_default("TRIAGE_DB_PATH", "./var/triage.sqlite"),
            admin_username,
            admin_password_bcrypt,
            jwt_secret,
            jwt_ttl,
            fleet_poll_interval,
            fleet_cache_disabled: raw("FLEET_CACHE_DISABLED") == "1",
            fleet_cache_max_entries,
            oidc,
            trusted_proxies,
            enroll: Arc::new(enroll),
        })
    }
}

/// Names, never values, of the former `SIGIL_*` variables. Diagnostic only: `load` never reads them.
pub fn legacy_env_names(vars: impl IntoIterator<Item = String>) -> Vec<String> {
    vars.into_iter()
        .filter(|name| name.starts_with("SIGIL_"))
        .collect()
}

fn positive_duration(key: &str, n: i64, unit_secs: i64) -> Result<Duration, ConfigError> {
    match n.checked_mul(unit_secs) {
        Some(secs) if secs > 0 && secs <= i64::MAX / 1_000_000_000 => {
            Ok(Duration::from_secs(secs as u64))
        }
        _ => Err(invalid(format!("config: {key} must be positive (got {n})"))),
    }
}

/// A comma-separated list of addresses and CIDR networks.
pub fn trusted_proxies(raw: &str) -> Result<Vec<ipnet::IpNet>, ConfigError> {
    raw.split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| {
            item.parse::<ipnet::IpNet>()
                .or_else(|_| item.parse::<std::net::IpAddr>().map(ipnet::IpNet::from))
                .map_err(|_| {
                    invalid(format!(
                        "config: TRUSTED_PROXIES: {item:?} is not an IP address or CIDR network"
                    ))
                })
        })
        .collect()
}

// Shape check only, as in Go: `$2a$`, `$2b$` or `$2y$` and at least 60 bytes.
fn is_bcrypt_hash(s: &str) -> bool {
    s.len() >= 60 && ["$2a$", "$2b$", "$2y$"].iter().any(|p| s.starts_with(p))
}

fn load_server_tls(trimmed: &dyn Fn(&str) -> String) -> Result<Option<ServerTls>, ConfigError> {
    let ca_path = trimmed("LODELINE_SERVER_CA_PATH");
    let cert_path = trimmed("LODELINE_SERVER_CLIENT_CERT_PATH");
    let key_path = trimmed("LODELINE_SERVER_CLIENT_KEY_PATH");
    if ca_path.is_empty() && cert_path.is_empty() && key_path.is_empty() {
        return Ok(None);
    }
    if cert_path.is_empty() != key_path.is_empty() {
        return Err(invalid("config: LODELINE_SERVER_CLIENT_CERT_PATH and LODELINE_SERVER_CLIENT_KEY_PATH must be set together"));
    }
    let mut roots = Vec::new();
    if !ca_path.is_empty() {
        let pem = std::fs::read(&ca_path)
            .map_err(|e| invalid(format!("config: LODELINE_SERVER_CA_PATH: {e}")))?;
        roots = ca_bundle(&pem);
        if roots.is_empty() {
            return Err(invalid(format!(
                "config: LODELINE_SERVER_CA_PATH: no PEM certificate in {ca_path}"
            )));
        }
    }
    let mut identity = None;
    if !cert_path.is_empty() {
        let pair_err = |e: &dyn fmt::Display| {
            invalid(format!(
                "config: LODELINE_SERVER_CLIENT_CERT_PATH / LODELINE_SERVER_CLIENT_KEY_PATH: {e}"
            ))
        };
        let mut pem = std::fs::read(&cert_path).map_err(|e| pair_err(&e))?;
        pem.push(b'\n');
        pem.extend(std::fs::read(&key_path).map_err(|e| pair_err(&e))?);
        identity = Some(reqwest::Identity::from_pem(&pem).map_err(|e| pair_err(&e))?);
    }
    Ok(Some(ServerTls { roots, identity }))
}

/// Go's `AppendCertsFromPEM`: every `CERTIFICATE` block that parses, skipping any block that
/// does not, so one bad entry does not cost the rest of the bundle.
fn ca_bundle(pem: &[u8]) -> Vec<reqwest::Certificate> {
    use rustls::pki_types::pem::{self, SectionKind};
    let mut rest = pem;
    let mut roots = Vec::new();
    loop {
        match pem::from_buf(&mut rest) {
            Ok(None) => return roots,
            Ok(Some((SectionKind::Certificate, der))) => {
                let parses = rustls::RootCertStore::empty()
                    .add(der.clone().into())
                    .is_ok();
                if parses {
                    roots.extend(reqwest::Certificate::from_der(&der).ok());
                }
            }
            // Every error is raised after its block's lines are read, so the loop moves on.
            Ok(Some(_)) | Err(_) => {}
        }
    }
}

impl OidcConfig {
    /// `None` when OIDC is fully unset; an error when it is partly set or insecure.
    fn validate(self) -> Result<Option<Self>, ConfigError> {
        let fields = [
            &self.issuer,
            &self.client_id,
            &self.client_secret,
            &self.redirect_url,
        ];
        if fields.iter().all(|f| f.is_empty()) && self.allowed_subjects.is_empty() {
            return Ok(None);
        }
        if fields.iter().any(|f| f.is_empty()) || self.allowed_subjects.is_empty() {
            return Err(invalid("OIDC requires OIDC_ISSUER_URL, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_REDIRECT_URL and nonempty OIDC_ALLOWED_SUBJECTS"));
        }
        for raw in [&self.issuer, &self.redirect_url] {
            let ok = go_url(raw).is_some_and(|u| {
                u.scheme == "https"
                    && !u.host.is_empty()
                    && !u.has_user
                    && !u.has_query
                    && !u.has_fragment
            });
            if !ok {
                return Err(invalid("OIDC issuer and redirect must be absolute HTTPS URLs without credentials, query or fragment"));
            }
        }
        if go_url(&self.redirect_url).is_none_or(|u| u.path != b"/api/v1/auth/oidc/callback") {
            return Err(invalid(
                "OIDC_REDIRECT_URL path must be /api/v1/auth/oidc/callback",
            ));
        }
        if self.allowed_subjects.iter().any(|s| s.trim().is_empty()) {
            return Err(invalid(
                "OIDC_ALLOWED_SUBJECTS cannot contain empty subjects",
            ));
        }
        Ok(Some(self))
    }
}

/// The parts of Go's `url.Parse` result that validation reads.
pub struct GoUrl {
    pub scheme: String,
    pub has_user: bool,
    pub host: String,
    /// Percent-decoded, as Go's `URL.Path`.
    path: Vec<u8>,
    has_query: bool,
    pub has_fragment: bool,
}

/// Go's `url.Parse` for absolute URLs, `None` where Go returns an error. A relative or opaque URL
/// comes back with an empty host, which every caller refuses.
pub fn go_url(raw: &str) -> Option<GoUrl> {
    if raw.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return None;
    }
    let (rest, fragment) = raw.split_once('#').unwrap_or((raw, ""));
    unescape(fragment)?;
    let (scheme, rest) = match rest.split_once(':') {
        Some((s, r))
            if s.starts_with(|c: char| c.is_ascii_alphabetic())
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c)) =>
        {
            (s.to_ascii_lowercase(), r)
        }
        Some(("", _)) => return None,
        _ => (String::new(), rest),
    };
    let (rest, query) = rest.split_once('?').unwrap_or((rest, ""));
    let mut url = GoUrl {
        scheme,
        has_user: false,
        host: String::new(),
        path: Vec::new(),
        has_query: !query.is_empty(),
        has_fragment: !fragment.is_empty(),
    };
    // Go does not unescape an opaque URL's rest.
    if !url.scheme.is_empty() && !rest.starts_with('/') {
        return Some(url);
    }
    let path = match rest.strip_prefix("//") {
        Some(after) if !url.scheme.is_empty() => {
            let (authority, path) = after.find('/').map_or((after, ""), |i| after.split_at(i));
            let (user, host) = match authority.rsplit_once('@') {
                Some((user, host)) => (Some(user), host),
                None => (None, authority),
            };
            if !valid_go_host(host) {
                return None;
            }
            if let Some(user) = user {
                let user_byte =
                    |b: u8| b.is_ascii_alphanumeric() || b"-._:~!$&'()*+,;=%@".contains(&b);
                if !user.bytes().all(user_byte) || unescape(user).is_none() {
                    return None;
                }
                url.has_user = true;
            }
            url.host = host.to_owned();
            path
        }
        _ => rest,
    };
    url.path = unescape(path)?;
    Some(url)
}

/// Go's `parseHost` (Go 1.26).
fn valid_go_host(host: &str) -> bool {
    match host.rfind('[') {
        Some(0) => host.rfind(']').is_some_and(|close| {
            valid_port(&host[close + 1..]) && valid_ip_literal(&host[1..close])
        }),
        Some(_) => false,
        // The port starts at the last colon: Go's urlstrictcolons is off for a `go 1.25` module.
        None => {
            valid_port(host.rfind(':').map_or("", |i| &host[i..]))
                && unescape_host(host, false).is_some()
        }
    }
}

fn valid_port(port: &str) -> bool {
    port.is_empty()
        || port
            .strip_prefix(':')
            .is_some_and(|p| p.bytes().all(|b| b.is_ascii_digit()))
}

/// The inside of `[...]`: an IPv6 address, optionally with a `%25` zone, as Go's
/// `netip.ParseAddr` reads it once unescaped. IPv4 is refused.
fn valid_ip_literal(literal: &str) -> bool {
    let (addr, zone) = literal.split_at(literal.find("%25").unwrap_or(literal.len()));
    let Some(mut unescaped) = unescape_host(addr, false) else {
        return false;
    };
    match unescape_host(zone, true) {
        Some(zone) => unescaped.extend(zone),
        None => return false,
    }
    let Ok(unescaped) = String::from_utf8(unescaped) else {
        return false;
    };
    match unescaped.split_once('%') {
        Some((addr, zone)) => !zone.is_empty() && addr.parse::<Ipv6Addr>().is_ok(),
        None => unescaped.parse::<Ipv6Addr>().is_ok(),
    }
}

/// Go's `unescape` in host or zone mode: only host characters, and in a host `%XX` only for
/// non-ASCII bytes or `%25`; in a zone only for bytes a host could hold, or a space.
fn unescape_host(s: &str, zone: bool) -> Option<Vec<u8>> {
    let host_byte = |b: u8| b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:[]<>\"".contains(&b);
    let decoded = unescape(s)?;
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let ok = if b[i] == b'%' {
            let v = u8::from_str_radix(&s[i + 1..i + 3], 16).ok()?;
            i += 3;
            &s[i - 3..i] == "%25"
                || if zone {
                    v == b' ' || host_byte(v)
                } else {
                    v >= 0x80
                }
        } else {
            i += 1;
            b[i - 1] >= 0x80 || host_byte(b[i - 1])
        };
        if !ok {
            return None;
        }
    }
    Some(decoded)
}

/// Percent-decodes `s`; `None` on a `%` not followed by two hex digits, as Go rejects.
pub fn unescape(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = b.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Some(out)
}

const REDACTED: &str = "<redacted>";

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let base_url = go_url(&self.server_base_url)
            .map(|u| format!("{}://{}", u.scheme, u.host))
            .unwrap_or_default();
        f.debug_struct("Config")
            .field("listen_addr", &self.listen_addr)
            .field("mock_fleet", &self.mock_fleet)
            .field("server_base_url", &base_url)
            .field("server_read_token", &REDACTED)
            .field("server_tls", &self.server_tls.is_some())
            .field("triage_db_path", &self.triage_db_path)
            .field("admin_username", &self.admin_username)
            .field("admin_password_bcrypt", &REDACTED)
            .field("jwt_secret", &REDACTED)
            .field("jwt_ttl", &self.jwt_ttl)
            .field("fleet_poll_interval", &self.fleet_poll_interval)
            .field("fleet_cache_disabled", &self.fleet_cache_disabled)
            .field("fleet_cache_max_entries", &self.fleet_cache_max_entries)
            .field("oidc", &self.oidc)
            .field("trusted_proxies", &self.trusted_proxies)
            .field("enroll", &self.enroll)
            .finish()
    }
}

impl fmt::Debug for OidcConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OidcConfig")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("client_secret", &REDACTED)
            .field("redirect_url", &self.redirect_url)
            .field("allowed_subjects", &self.allowed_subjects)
            .finish()
    }
}

#[cfg(test)]
mod tests;
