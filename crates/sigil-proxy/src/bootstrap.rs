//! Local bootstrap (`proxy.yaml`). Contract: `contracts/README.md`
//! "Bootstrap 구성 후보" and `control-plane.md` §5.5 (origin binding).
//!
//! Remote config is never merged with this file. Secrets are referenced by
//! owner-only file; an environment-variable secret source is NOT supported in P1
//! (an `env`-style key is an unknown field and fails the load).

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sigil_proxy_api::Id;
use thiserror::Error;

use crate::limits::{Limits, LimitsError, LimitsOverrides};

/// OPEN: the contract fixes "loopback by default" but not the port. 8480 is a
/// placeholder; the server uses 8443/8444.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:8480";

#[derive(Debug, Error)]
pub enum BootstrapError {
    #[error("cannot read config {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("config parse error: {0}")]
    Parse(String),
    #[error("proxy_id does not match the id pattern ^[A-Za-z0-9][A-Za-z0-9_.-]{{0,127}}$")]
    ProxyId,
    #[error("listen: {0}")]
    Listen(String),
    #[error("control_plane_url: {0}")]
    ControlPlaneUrl(String),
    #[error("credentials.{reference}: {reason}")]
    Credential { reference: String, reason: String },
    #[error("{field}: {reason}")]
    File { field: String, reason: String },
    #[error("{0}")]
    Limits(#[from] LimitsError),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCredential {
    secret_file: PathBuf,
    #[serde(default)]
    upstream_origins: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBootstrap {
    proxy_id: String,
    #[serde(default)]
    listen: Option<String>,
    /// Listener TLS material (OPEN: the contract requires TLS for non-loopback
    /// listeners but does not name the keys).
    #[serde(default)]
    tls_cert_file: Option<PathBuf>,
    #[serde(default)]
    tls_key_file: Option<PathBuf>,
    control_plane_url: String,
    state_dir: PathBuf,
    client_cert_file: PathBuf,
    client_key_file: PathBuf,
    ca_file: PathBuf,
    #[serde(default)]
    limits: LimitsOverrides,
    #[serde(default)]
    credentials: BTreeMap<String, RawCredential>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    /// Absolute path. The secret itself is not read at load time.
    pub secret_file: PathBuf,
    /// Normalized `scheme://host[:port]` origins this ref may be sent to.
    pub upstream_origins: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ListenerTls {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
}

/// Validated bootstrap. All paths are absolute.
#[derive(Debug, Clone)]
pub struct Bootstrap {
    pub proxy_id: Id,
    pub listen: SocketAddr,
    pub listener_tls: Option<ListenerTls>,
    pub control_plane_url: String,
    pub state_dir: PathBuf,
    pub client_cert_file: PathBuf,
    pub client_key_file: PathBuf,
    pub ca_file: PathBuf,
    pub limits: Limits,
    pub credentials: BTreeMap<String, Credential>,
}

impl Bootstrap {
    /// Load, resolve relative paths against the config file's directory and
    /// validate everything. Any failure is a start error.
    pub fn load(config_path: &Path) -> Result<Bootstrap, BootstrapError> {
        let text = std::fs::read_to_string(config_path).map_err(|source| BootstrapError::Read {
            path: config_path.display().to_string(),
            source,
        })?;
        let abs = std::path::absolute(config_path).map_err(|source| BootstrapError::Read {
            path: config_path.display().to_string(),
            source,
        })?;
        let base = abs.parent().unwrap_or(Path::new("/")).to_path_buf();
        Self::from_yaml(&text, &base)
    }

    /// `base` is the directory relative paths resolve against.
    pub fn from_yaml(text: &str, base: &Path) -> Result<Bootstrap, BootstrapError> {
        // serde_yaml errors can quote input; the bootstrap holds no secret
        // values (only file paths), so passing the message through is fine.
        let raw: RawBootstrap =
            serde_yaml::from_str(text).map_err(|e| BootstrapError::Parse(e.to_string()))?;
        let resolve = |p: &Path| -> PathBuf {
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                base.join(p)
            }
        };

        let proxy_id = Id::new(raw.proxy_id).map_err(|_| BootstrapError::ProxyId)?;

        let listen: SocketAddr = raw
            .listen
            .as_deref()
            .unwrap_or(DEFAULT_LISTEN)
            .parse()
            .map_err(|_| BootstrapError::Listen("not a socket address".into()))?;
        let listener_tls = match (&raw.tls_cert_file, &raw.tls_key_file) {
            (Some(c), Some(k)) => Some(ListenerTls {
                cert_file: resolve(c),
                key_file: resolve(k),
            }),
            (None, None) => None,
            _ => {
                return Err(BootstrapError::Listen(
                    "tls_cert_file and tls_key_file must be set together".into(),
                ))
            }
        };
        if !is_loopback(listen.ip()) && listener_tls.is_none() {
            return Err(BootstrapError::Listen(
                "a non-loopback listen address requires tls_cert_file and tls_key_file".into(),
            ));
        }

        check_control_plane_url(&raw.control_plane_url)?;

        let client_cert_file = resolve(&raw.client_cert_file);
        let client_key_file = resolve(&raw.client_key_file);
        let ca_file = resolve(&raw.ca_file);
        // Keys and secrets are owner-only; certificates and the CA bundle are
        // public material (regular, non-symlink file is enough).
        check_public_file("client_cert_file", &client_cert_file)?;
        check_private_file("client_key_file", &client_key_file)?;
        check_public_file("ca_file", &ca_file)?;
        if let Some(t) = &listener_tls {
            check_public_file("tls_cert_file", &t.cert_file)?;
            check_private_file("tls_key_file", &t.key_file)?;
        }

        let mut credentials = BTreeMap::new();
        for (name, c) in raw.credentials {
            let cred_err = |reason: &str| BootstrapError::Credential {
                reference: name.clone(),
                reason: reason.to_string(),
            };
            if Id::new(name.clone()).is_err() {
                return Err(cred_err("credential ref does not match the id pattern"));
            }
            if c.upstream_origins.is_empty() {
                return Err(cred_err(
                    "upstream_origins is required and must not be empty (unbound ref is a start error)",
                ));
            }
            let mut origins = Vec::new();
            for o in &c.upstream_origins {
                let norm = normalize_origin(o).map_err(|r| cred_err(&r))?;
                if !origins.contains(&norm) {
                    origins.push(norm);
                }
            }
            let secret_file = resolve(&c.secret_file);
            check_private_file(&format!("credentials.{name}.secret_file"), &secret_file)?;
            credentials.insert(
                name,
                Credential {
                    secret_file,
                    upstream_origins: origins,
                },
            );
        }

        Ok(Bootstrap {
            proxy_id,
            listen,
            listener_tls,
            control_plane_url: raw.control_plane_url,
            state_dir: resolve(&raw.state_dir),
            client_cert_file,
            client_key_file,
            ca_file,
            limits: raw.limits.resolve()?,
            credentials,
        })
    }
}

fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v| v.is_loopback()),
    }
}

fn check_control_plane_url(url: &str) -> Result<(), BootstrapError> {
    let err = |m: &str| BootstrapError::ControlPlaneUrl(m.to_string());
    // OPEN: https only. Plain http to the control plane is refused even on
    // loopback; mTLS client auth is the only supported mechanism (D-02).
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| err("must be an https:// URL"))?;
    let (authority, tail) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    split_host_port(authority).map_err(|m| err(&m))?;
    if tail.contains(['?', '#']) {
        return Err(err("query and fragment are not allowed"));
    }
    if tail
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err(err("invalid character in path"));
    }
    Ok(())
}

/// Validate `host[:port]` (no userinfo). Returns lowercase host and optional port.
fn split_host_port(authority: &str) -> Result<(String, Option<u16>), String> {
    if authority.is_empty() {
        return Err("empty host".into());
    }
    if authority.contains('@') {
        return Err("userinfo is not allowed".into());
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']').ok_or("unterminated IPv6 literal")?;
        let host = &rest[..end];
        host.parse::<std::net::Ipv6Addr>()
            .map_err(|_| "invalid IPv6 literal")?;
        let after = &rest[end + 1..];
        let port = match after {
            "" => None,
            _ => Some(after.strip_prefix(':').ok_or("invalid authority")?),
        };
        (format!("[{}]", host.to_ascii_lowercase()), port)
    } else {
        let (h, p) = match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        };
        if h.is_empty()
            || !h
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            || h.starts_with(['.', '-'])
            || h.ends_with(['.', '-'])
        {
            return Err("invalid host".into());
        }
        (h.to_ascii_lowercase(), p)
    };
    let port = match port {
        None => None,
        Some(p) => {
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err("invalid port".into());
            }
            let n: u16 = p.parse().map_err(|_| "invalid port")?;
            if n == 0 {
                return Err("invalid port".into());
            }
            Some(n)
        }
    };
    Ok((host, port))
}

/// The single origin matcher for the proxy. Later tasks (route apply, per
/// request after DNS resolution) must compare origins only through this
/// function, never by ad-hoc string handling.
///
/// Accepts `scheme://host[:port]` with no path, query, fragment or userinfo.
/// Output is canonical: lowercase scheme and host, and the scheme's default port
/// (`http` 80, `https` 443) dropped, so `https://a:443` equals `https://a`.
/// `http://` is accepted only for loopback hosts (127.0.0.0/8, `::1`,
/// `localhost`); any other plain-http origin is an error.
pub fn normalize_origin(s: &str) -> Result<String, String> {
    let (scheme, rest) = s
        .split_once("://")
        .ok_or("origin must be scheme://host[:port]")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err("origin scheme must be http or https".into());
    }
    if rest.contains(['/', '?', '#']) {
        return Err("origin must not contain a path, query or fragment".into());
    }
    let (host, port) = split_host_port(rest)?;
    if scheme == "http" && !is_loopback_host(&host) {
        return Err("http:// origins are allowed only for loopback hosts".into());
    }
    let default_port = if scheme == "http" { 80 } else { 443 };
    Ok(match port {
        Some(p) if p != default_port => format!("{scheme}://{host}:{p}"),
        _ => format!("{scheme}://{host}"),
    })
}

fn is_loopback_host(host: &str) -> bool {
    if host == "localhost" {
        return true;
    }
    if let Some(v6) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return v6
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(|a| a.is_loopback());
    }
    host.parse::<std::net::Ipv4Addr>()
        .is_ok_and(|a| a.is_loopback())
}

fn file_err(field: &str, reason: impl Into<String>) -> BootstrapError {
    BootstrapError::File {
        field: field.to_string(),
        reason: reason.into(),
    }
}

/// Sensitive file (key, secret): `O_NOFOLLOW`, regular, owned by the current
/// user, no group/other bits, checked on the opened descriptor. Parent
/// directories are not walked (see [`crate::fsutil`]).
pub fn check_private_file(field: &str, path: &Path) -> Result<(), BootstrapError> {
    crate::fsutil::open_private_file(path)
        .map(drop)
        .map_err(|e| file_err(field, e.to_string()))
}

/// Public material (certificate, CA bundle): `O_NOFOLLOW`, regular file only.
pub fn check_public_file(field: &str, path: &Path) -> Result<(), BootstrapError> {
    crate::fsutil::open_public_file(path)
        .map(drop)
        .map_err(|e| file_err(field, e.to_string()))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    struct Fx {
        dir: tempfile::TempDir,
    }

    impl Fx {
        fn new() -> Fx {
            let dir = tempfile::tempdir().unwrap();
            for f in ["cert.pem", "key.pem", "secret.txt"] {
                Self::file(dir.path(), f, 0o600);
            }
            Self::file(dir.path(), "ca.pem", 0o644);
            Fx { dir }
        }
        fn file(dir: &Path, name: &str, mode: u32) {
            let p = dir.join(name);
            std::fs::write(&p, "x").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        fn yaml(&self, extra: &str) -> String {
            format!(
                "proxy_id: px-1\ncontrol_plane_url: https://server.example:8443\nstate_dir: state\n\
                 client_cert_file: cert.pem\nclient_key_file: key.pem\nca_file: ca.pem\n{extra}"
            )
        }
        fn load(&self, extra: &str) -> Result<Bootstrap, BootstrapError> {
            Bootstrap::from_yaml(&self.yaml(extra), self.dir.path())
        }
    }

    const CRED: &str = "credentials:\n  gh:\n    secret_file: secret.txt\n    upstream_origins: [\"https://api.example.com\"]\n";

    /// AC-14 / PX-001
    #[test]
    fn relative_paths_resolve_against_config_dir() {
        let fx = Fx::new();
        let b = fx.load(CRED).unwrap();
        let d = fx.dir.path();
        assert_eq!(b.state_dir, d.join("state"));
        assert_eq!(b.client_cert_file, d.join("cert.pem"));
        assert_eq!(b.client_key_file, d.join("key.pem"));
        assert_eq!(b.ca_file, d.join("ca.pem"));
        assert_eq!(b.credentials["gh"].secret_file, d.join("secret.txt"));
    }

    #[test]
    fn load_resolves_against_the_config_file_directory() {
        let fx = Fx::new();
        let cfg = fx.dir.path().join("proxy.yaml");
        std::fs::write(&cfg, fx.yaml(CRED)).unwrap();
        let b = Bootstrap::load(&cfg).unwrap();
        assert_eq!(b.ca_file, fx.dir.path().join("ca.pem"));
    }

    #[test]
    fn listen_defaults_to_loopback() {
        let fx = Fx::new();
        let b = fx.load(CRED).unwrap();
        assert!(b.listen.ip().is_loopback());
        assert!(b.listener_tls.is_none());
    }

    #[test]
    fn non_loopback_listen_requires_tls() {
        let fx = Fx::new();
        for l in ["0.0.0.0:8480", "192.0.2.1:8480", "[::]:8480"] {
            let e = fx.load(&format!("listen: \"{l}\"\n{CRED}")).unwrap_err();
            assert!(matches!(e, BootstrapError::Listen(_)), "{l}: {e}");
        }
        let ok = fx
            .load(&format!(
                "listen: \"0.0.0.0:8480\"\ntls_cert_file: cert.pem\ntls_key_file: key.pem\n{CRED}"
            ))
            .unwrap();
        assert!(ok.listener_tls.is_some());
        // half-configured TLS is an error even on loopback
        assert!(fx.load("tls_cert_file: cert.pem\n").is_err());
    }

    #[test]
    fn credential_without_upstream_origins_is_a_start_error() {
        let fx = Fx::new();
        let e = fx
            .load("credentials:\n  gh:\n    secret_file: secret.txt\n")
            .unwrap_err();
        assert!(matches!(e, BootstrapError::Credential { .. }));
        let e = fx
            .load("credentials:\n  gh:\n    secret_file: secret.txt\n    upstream_origins: []\n")
            .unwrap_err();
        assert!(matches!(e, BootstrapError::Credential { .. }));
    }

    #[test]
    fn upstream_origin_shape() {
        for ok in [
            "https://api.example.com",
            "http://127.0.0.1:9000",
            "https://[::1]:8443",
        ] {
            assert!(normalize_origin(ok).is_ok(), "{ok}");
        }
        // default ports are dropped, other ports kept, case folded
        for (input, want) in [
            ("HTTPS://API.Example.com:443", "https://api.example.com"),
            ("https://api.example.com", "https://api.example.com"),
            (
                "https://api.example.com:8443",
                "https://api.example.com:8443",
            ),
            ("http://127.0.0.1:80", "http://127.0.0.1"),
            ("http://localhost:8080", "http://localhost:8080"),
            ("http://LOCALHOST", "http://localhost"),
            ("http://[::1]:80", "http://[::1]"),
            ("https://[::1]:443", "https://[::1]"),
            ("http://127.5.5.5:9", "http://127.5.5.5:9"),
        ] {
            assert_eq!(normalize_origin(input).unwrap(), want, "{input}");
        }
        assert_eq!(
            normalize_origin("https://a.example:443"),
            normalize_origin("https://a.example")
        );
        // plain http only for loopback hosts
        for bad in [
            "http://api.example.com",
            "http://192.0.2.1",
            "http://10.0.0.1:80",
            "http://[2001:db8::1]",
            "http://localhost.example.com",
            "http://128.0.0.1",
        ] {
            assert!(normalize_origin(bad).is_err(), "{bad}");
        }
        for bad in [
            "https://api.example.com/",
            "https://api.example.com/path",
            "https://api.example.com?x=1",
            "https://api.example.com#f",
            "https://user:pw@api.example.com",
            "https://user@api.example.com",
            "ftp://api.example.com",
            "api.example.com",
            "https://",
            "https://api.example.com:",
            "https://api.example.com:0",
            "https://api.example.com:99999",
            "https://exa mple.com",
        ] {
            assert!(normalize_origin(bad).is_err(), "{bad}");
        }
        let fx = Fx::new();
        let e = fx
            .load("credentials:\n  gh:\n    secret_file: secret.txt\n    upstream_origins: [\"https://a.example/x\"]\n")
            .unwrap_err();
        assert!(matches!(e, BootstrapError::Credential { .. }));
    }

    #[test]
    fn secret_key_and_cert_files_are_checked() {
        // group/other permission bits
        for (name, field) in [("secret.txt", "secret"), ("key.pem", "key")] {
            let fx = Fx::new();
            let p = fx.dir.path().join(name);
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
            assert!(fx.load(CRED).is_err(), "{field} group-readable accepted");
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o604)).unwrap();
            assert!(fx.load(CRED).is_err(), "{field} other-readable accepted");
        }
        // certificates are public material: loose modes are accepted
        for name in ["cert.pem", "ca.pem"] {
            let fx = Fx::new();
            let p = fx.dir.path().join(name);
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(fx.load(CRED).is_ok(), "{name} 0644 must be accepted");
        }
        // a symlinked certificate is still refused
        let fx = Fx::new();
        std::fs::rename(fx.dir.path().join("cert.pem"), fx.dir.path().join("c2")).unwrap();
        symlink(fx.dir.path().join("c2"), fx.dir.path().join("cert.pem")).unwrap();
        assert!(fx.load(CRED).is_err());
        // symlink
        let fx = Fx::new();
        let real = fx.dir.path().join("real-secret");
        Fx::file(fx.dir.path(), "real-secret", 0o600);
        std::fs::remove_file(fx.dir.path().join("secret.txt")).unwrap();
        symlink(&real, fx.dir.path().join("secret.txt")).unwrap();
        let e = fx.load(CRED).unwrap_err();
        assert!(e.to_string().contains("symlink"), "{e}");
        // not a regular file
        let fx = Fx::new();
        std::fs::remove_file(fx.dir.path().join("key.pem")).unwrap();
        std::fs::create_dir(fx.dir.path().join("key.pem")).unwrap();
        assert!(fx.load(CRED).is_err());
        // missing
        let fx = Fx::new();
        std::fs::remove_file(fx.dir.path().join("ca.pem")).unwrap();
        assert!(fx.load(CRED).is_err());
    }

    #[test]
    fn proxy_id_must_match_contract_pattern() {
        let fx = Fx::new();
        for bad in ["", "-x", "a b", "a/b", "é"] {
            let y = fx
                .yaml(CRED)
                .replace("proxy_id: px-1", &format!("proxy_id: \"{bad}\""));
            let e = Bootstrap::from_yaml(&y, fx.dir.path()).unwrap_err();
            assert!(matches!(e, BootstrapError::ProxyId), "{bad}");
        }
        let long = "a".repeat(129);
        let y = fx
            .yaml(CRED)
            .replace("proxy_id: px-1", &format!("proxy_id: {long}"));
        assert!(Bootstrap::from_yaml(&y, fx.dir.path()).is_err());
    }

    #[test]
    fn env_secret_source_is_not_supported() {
        let fx = Fx::new();
        let e = fx
            .load("credentials:\n  gh:\n    secret_env: GH_TOKEN\n    upstream_origins: [\"https://a.example\"]\n")
            .unwrap_err();
        assert!(matches!(e, BootstrapError::Parse(_)));
    }

    #[test]
    fn unknown_top_level_field_is_rejected() {
        let fx = Fx::new();
        assert!(matches!(
            fx.load("bogus: 1\n").unwrap_err(),
            BootstrapError::Parse(_)
        ));
    }

    #[test]
    fn limits_in_bootstrap_can_only_lower() {
        let fx = Fx::new();
        let b = fx.load("limits:\n  max_concurrent_calls: 8\n").unwrap();
        assert_eq!(b.limits.max_concurrent_calls, 8);
        assert!(fx.load("limits:\n  max_concurrent_calls: 1000\n").is_err());
    }

    #[test]
    fn control_plane_url_must_be_https_without_userinfo() {
        let fx = Fx::new();
        for bad in [
            "http://s.example",
            "https://u:p@s.example",
            "https://s.example?x=1",
            "s.example",
        ] {
            let y = fx.yaml("").replace("https://server.example:8443", bad);
            assert!(Bootstrap::from_yaml(&y, fx.dir.path()).is_err(), "{bad}");
        }
    }
}
