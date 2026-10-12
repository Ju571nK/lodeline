//! Route table (T-12 slice A). Maps `route_id` to a fixed upstream, its
//! credential binding, the principals allowed on it and the downstream
//! `Origin` allowlist (PX-002, PX-008, PX-009, PX-014).
//!
//! The remote config fetch/apply is a later slice. It will call exactly one
//! constructor, [`RouteTable::build`], and install the result with
//! [`TableHandle::set`]. Nothing here reads the network.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use http::HeaderValue;
use sigil_proxy_api::Id;
use thiserror::Error;
use tokio::sync::Semaphore;

use crate::bootstrap::{normalize_origin, split_host_port, Credential};
use crate::limits::Limits;

/// One principal as the later config slice will describe it. The token itself
/// never appears here, only SHA-256 verifiers (control-plane.md §5.2).
#[derive(Debug, Clone)]
pub struct PrincipalSpec {
    pub principal_id: Id,
    /// Lowercase-hex SHA-256 verifiers (at most two for overlap).
    // OPEN: `not_after` of a verifier is not modelled in slice A; the config
    // slice must carry it and refuse expired verifiers at authenticate time.
    pub verifiers: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RouteSpec {
    pub route_id: Id,
    pub upstream_url: String,
    pub credential_ref: String,
    pub principals: Vec<PrincipalSpec>,
    /// Downstream `Origin` allowlist (control-plane.md §5.3). Normalized with
    /// [`normalize_origin`] at build.
    pub allowed_origins: Vec<String>,
    /// Explicit management flag for private destinations (control-plane.md
    /// §6.1 "private destinations need an explicit management flag").
    // OPEN: the DTO field name for this flag is not defined by the contract.
    pub allow_private_destination: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RouteError {
    #[error("route {route}: invalid upstream_url: {reason}")]
    UpstreamUrl { route: String, reason: String },
    #[error("route {route}: unknown credential_ref {reference}")]
    UnknownCredential { route: String, reference: String },
    #[error("route {route}: upstream origin is not bound to credential_ref {reference}")]
    CredentialOrigin { route: String, reference: String },
    #[error("credential_ref {reference}: cannot read the secret: {reason}")]
    Secret { reference: String, reason: String },
    #[error("route {route}: invalid allowed_origins entry: {reason}")]
    AllowedOrigin { route: String, reason: String },
    #[error("route {route}: verifier must be 64 lowercase hex characters")]
    Verifier { route: String },
    #[error("duplicate route_id {0}")]
    DuplicateRoute(String),
}

/// The fixed upstream of a route. Requests can never change it (AC-08).
#[derive(Debug, Clone)]
pub struct Upstream {
    pub https: bool,
    /// Lowercase host without IPv6 brackets.
    pub host: String,
    pub port: u16,
    /// Absolute path sent upstream. No query: the request's query is dropped.
    pub path: String,
    /// Set when the host is an IP literal (an "explicitly configured" address).
    pub host_literal: Option<IpAddr>,
    /// Value for the upstream `Host` header.
    pub host_header: String,
}

pub struct Principal {
    pub id: Id,
    verifiers: Vec<String>,
    /// Shared by every route that names the same principal id.
    pub(crate) sem: Arc<Semaphore>,
}

impl std::fmt::Debug for Principal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Principal")
            .field("id", &self.id)
            .field("verifiers", &self.verifiers.len())
            .finish()
    }
}

pub struct Route {
    pub id: Id,
    pub upstream: Upstream,
    /// `Bearer <secret>`, marked sensitive so a Debug print shows nothing.
    pub(crate) upstream_authorization: HeaderValue,
    principals: Vec<Principal>,
    pub(crate) allowed_origins: Vec<String>,
    pub(crate) allow_private: bool,
    pub(crate) sem: Arc<Semaphore>,
}

impl std::fmt::Debug for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Route")
            .field("id", &self.id)
            .field("upstream", &self.upstream)
            .field("principals", &self.principals)
            .field("allowed_origins", &self.allowed_origins)
            .finish_non_exhaustive()
    }
}

impl Route {
    /// Verify a bearer token against every verifier of every principal of this
    /// route (PX-008, AC-04). The work does not depend on which verifier
    /// matches or on whether any does: no early exit.
    pub fn authenticate(&self, token: &str) -> Option<&Principal> {
        let mut matched = 0u8;
        let mut idx = 0usize;
        for (i, p) in self.principals.iter().enumerate() {
            for v in &p.verifiers {
                let ok = sigil_proxy_api::verify(token, v) as u8;
                // Keep the first match without a secret-dependent branch.
                let take = ok & (1 ^ matched);
                let mask = 0usize.wrapping_sub(take as usize);
                idx = (idx & !mask) | (i & mask);
                matched |= ok;
            }
        }
        if matched == 1 {
            self.principals.get(idx)
        } else {
            None
        }
    }

    pub fn origin_allowed(&self, normalized_origin: &str) -> bool {
        self.allowed_origins.iter().any(|o| o == normalized_origin)
    }
}

#[derive(Debug)]
pub struct RouteTable {
    routes: HashMap<String, Route>,
    has_verifier: bool,
}

impl RouteTable {
    /// The single constructor the config-apply slice will call. Validates the
    /// whole input and fails as a whole (no partial table, control-plane.md
    /// §6.2 "Atomic apply"). Reads each referenced secret through the
    /// owner-only reader; secrets are never logged or put in errors.
    pub fn build(
        specs: &[RouteSpec],
        credentials: &BTreeMap<String, Credential>,
        limits: &Limits,
    ) -> Result<RouteTable, RouteError> {
        let mut secrets: HashMap<&str, Vec<u8>> = HashMap::new();
        let mut principal_sems: HashMap<String, Arc<Semaphore>> = HashMap::new();
        let mut routes = HashMap::new();
        let mut has_verifier = false;

        for spec in specs {
            let rid = spec.route_id.as_str().to_string();
            if routes.contains_key(&rid) {
                return Err(RouteError::DuplicateRoute(rid));
            }
            let (upstream, origin) =
                parse_upstream(&spec.upstream_url).map_err(|reason| RouteError::UpstreamUrl {
                    route: rid.clone(),
                    reason,
                })?;
            let cred = credentials.get(&spec.credential_ref).ok_or_else(|| {
                RouteError::UnknownCredential {
                    route: rid.clone(),
                    reference: spec.credential_ref.clone(),
                }
            })?;
            // N-1: the ref may only be sent to its bound origins.
            if !cred.upstream_origins.contains(&origin) {
                return Err(RouteError::CredentialOrigin {
                    route: rid,
                    reference: spec.credential_ref.clone(),
                });
            }
            if !secrets.contains_key(spec.credential_ref.as_str()) {
                let raw = crate::fsutil::read_private_file(&cred.secret_file).map_err(|e| {
                    RouteError::Secret {
                        reference: spec.credential_ref.clone(),
                        reason: e.kind().to_string(),
                    }
                })?;
                secrets.insert(spec.credential_ref.as_str(), raw);
            }
            let upstream_authorization = bearer_value(&secrets[spec.credential_ref.as_str()])
                .ok_or_else(|| RouteError::Secret {
                    reference: spec.credential_ref.clone(),
                    reason: "secret is empty or not a valid header value".into(),
                })?;

            let mut allowed_origins = Vec::new();
            for o in &spec.allowed_origins {
                let n = normalize_origin(o).map_err(|reason| RouteError::AllowedOrigin {
                    route: rid.clone(),
                    reason,
                })?;
                if !allowed_origins.contains(&n) {
                    allowed_origins.push(n);
                }
            }

            let mut principals = Vec::new();
            for p in &spec.principals {
                for v in &p.verifiers {
                    if v.len() != 64 || !v.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                        return Err(RouteError::Verifier { route: rid.clone() });
                    }
                }
                if !p.verifiers.is_empty() {
                    has_verifier = true;
                }
                let sem = principal_sems
                    .entry(p.principal_id.as_str().to_string())
                    .or_insert_with(|| {
                        Arc::new(Semaphore::new(limits.max_calls_per_principal as usize))
                    })
                    .clone();
                principals.push(Principal {
                    id: p.principal_id.clone(),
                    verifiers: p.verifiers.clone(),
                    sem,
                });
            }

            routes.insert(
                rid,
                Route {
                    id: spec.route_id.clone(),
                    upstream,
                    upstream_authorization,
                    principals,
                    allowed_origins,
                    allow_private: spec.allow_private_destination,
                    sem: Arc::new(Semaphore::new(limits.max_calls_per_route as usize)),
                },
            );
        }
        Ok(RouteTable {
            routes,
            has_verifier,
        })
    }

    pub fn route(&self, id: &str) -> Option<&Route> {
        self.routes.get(id)
    }

    /// True when at least one principal has a verifier. Until then the
    /// listener answers 401 to everything (decisions.md "P0 종료", T-12).
    pub fn has_verifier(&self) -> bool {
        self.has_verifier
    }
}

fn bearer_value(secret: &[u8]) -> Option<HeaderValue> {
    let s = std::str::from_utf8(secret).ok()?.trim();
    if s.is_empty() {
        return None;
    }
    let mut v = HeaderValue::from_str(&format!("Bearer {s}")).ok()?;
    v.set_sensitive(true);
    Some(v)
}

/// Parse `scheme://host[:port][/path]` with no userinfo, query or fragment.
/// Returns the upstream and its normalized origin (via [`normalize_origin`], so
/// a plain-http origin must be a loopback host).
fn parse_upstream(url: &str) -> Result<(Upstream, String), String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or("must be scheme://host[:port]/path")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err("scheme must be http or https".into());
    }
    if rest.contains(['?', '#', '@']) {
        return Err("userinfo, query and fragment are not allowed".into());
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if path
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || b == b'\\')
    {
        return Err("invalid character in path".into());
    }
    path.parse::<http::uri::PathAndQuery>()
        .map_err(|_| "invalid path".to_string())?;
    let origin = normalize_origin(&format!("{scheme}://{authority}"))?;
    let (host, port) = split_host_port(authority)?;
    let https = scheme == "https";
    let port = port.unwrap_or(if https { 443 } else { 80 });
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(&host)
        .to_string();
    let host_literal = bare.parse::<IpAddr>().ok();
    let default_port = if https { 443 } else { 80 };
    let host_header = if port == default_port {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    Ok((
        Upstream {
            https,
            host: bare,
            port,
            path: path.to_string(),
            host_literal,
            host_header,
        },
        origin,
    ))
}

/// Holder for the applied table. The config slice swaps it atomically; `None`
/// means no config has been applied, and every request is answered 401.
#[derive(Clone, Default)]
pub struct TableHandle(Arc<RwLock<Option<Arc<RouteTable>>>>);

impl TableHandle {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set(&self, table: Option<RouteTable>) {
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = table.map(Arc::new);
    }
    pub fn current(&self) -> Option<Arc<RouteTable>> {
        self.0.read().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn cred(dir: &std::path::Path, mode: u32, origins: &[&str]) -> BTreeMap<String, Credential> {
        let p = dir.join("secret");
        std::fs::write(&p, "UPSTREAM-SECRET-VALUE\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        BTreeMap::from([(
            "ref1".to_string(),
            Credential {
                secret_file: p,
                upstream_origins: origins.iter().map(|s| s.to_string()).collect(),
            },
        )])
    }

    fn spec(url: &str) -> RouteSpec {
        RouteSpec {
            route_id: Id::new("a").unwrap(),
            upstream_url: url.into(),
            credential_ref: "ref1".into(),
            principals: vec![PrincipalSpec {
                principal_id: Id::new("p1").unwrap(),
                verifiers: vec![sigil_proxy_api::verifier_for("tok-1")],
            }],
            allowed_origins: vec![],
            allow_private_destination: false,
        }
    }

    fn build(url: &str, origins: &[&str]) -> Result<RouteTable, RouteError> {
        let d = tempfile::tempdir().unwrap();
        RouteTable::build(
            &[spec(url)],
            &cred(d.path(), 0o600, origins),
            &Limits::default(),
        )
    }

    /// AC-08 / PX-014: the credential only goes to its bound origin.
    #[test]
    fn credential_origin_binding() {
        assert!(build("https://api.example.com/mcp", &["https://api.example.com"]).is_ok());
        // default port is normalized away on both sides
        assert!(build(
            "https://api.example.com:443/mcp",
            &["https://api.example.com"]
        )
        .is_ok());
        let e = build("https://evil.example.com/mcp", &["https://api.example.com"]).unwrap_err();
        assert!(matches!(e, RouteError::CredentialOrigin { .. }), "{e}");
        let e = build(
            "https://api.example.com:8443/mcp",
            &["https://api.example.com"],
        )
        .unwrap_err();
        assert!(matches!(e, RouteError::CredentialOrigin { .. }), "{e}");
    }

    /// AC-08: http only for loopback hosts, no userinfo/query/fragment.
    #[test]
    fn upstream_url_rules() {
        assert!(build("http://127.0.0.1:9000/mcp", &["http://127.0.0.1:9000"]).is_ok());
        assert!(build("http://localhost:9000/mcp", &["http://localhost:9000"]).is_ok());
        for bad in [
            "http://10.0.0.5:9000/mcp",
            "http://api.example.com/mcp",
            "https://u:p@api.example.com/mcp",
            "https://api.example.com/mcp?key=v",
            "https://api.example.com/mcp#f",
            "ftp://api.example.com/mcp",
            "api.example.com/mcp",
        ] {
            let e = build(bad, &["https://api.example.com"]).unwrap_err();
            assert!(matches!(e, RouteError::UpstreamUrl { .. }), "{bad}: {e}");
        }
    }

    /// PX-009: unknown ref, group-readable secret and bad verifier fail the build;
    /// no error text carries the secret.
    #[test]
    fn build_failures_do_not_leak_the_secret() {
        let d = tempfile::tempdir().unwrap();
        let c = cred(d.path(), 0o644, &["https://api.example.com"]);
        let e = RouteTable::build(&[spec("https://api.example.com/m")], &c, &Limits::default())
            .unwrap_err();
        assert!(matches!(e, RouteError::Secret { .. }));
        assert!(!format!("{e} {e:?}").contains("UPSTREAM-SECRET"));

        let d = tempfile::tempdir().unwrap();
        let c = cred(d.path(), 0o600, &["https://api.example.com"]);
        let mut s = spec("https://api.example.com/m");
        s.credential_ref = "missing".into();
        assert!(matches!(
            RouteTable::build(&[s], &c, &Limits::default()).unwrap_err(),
            RouteError::UnknownCredential { .. }
        ));
        let mut s = spec("https://api.example.com/m");
        s.principals[0].verifiers = vec!["ABC".into()];
        assert!(matches!(
            RouteTable::build(&[s], &c, &Limits::default()).unwrap_err(),
            RouteError::Verifier { .. }
        ));
        let t = RouteTable::build(&[spec("https://api.example.com/m")], &c, &Limits::default())
            .unwrap();
        assert!(!format!("{t:?}").contains("UPSTREAM-SECRET"));
    }

    #[test]
    fn allowed_origins_are_normalized() {
        let d = tempfile::tempdir().unwrap();
        let c = cred(d.path(), 0o600, &["https://api.example.com"]);
        let mut s = spec("https://api.example.com/m");
        s.allowed_origins = vec![
            "HTTPS://App.Example.com:443".into(),
            "http://localhost:80".into(),
        ];
        let t = RouteTable::build(&[s], &c, &Limits::default()).unwrap();
        let r = t.route("a").unwrap();
        assert!(r.origin_allowed("https://app.example.com"));
        assert!(r.origin_allowed("http://localhost"));
        assert!(!r.origin_allowed("https://other.example.com"));
        let mut s = spec("https://api.example.com/m");
        s.allowed_origins = vec!["http://app.example.com".into()];
        assert!(matches!(
            RouteTable::build(&[s], &c, &Limits::default()).unwrap_err(),
            RouteError::AllowedOrigin { .. }
        ));
    }

    /// AC-04: a token verifies only on its own route; a route without
    /// principals authenticates nobody.
    #[test]
    fn authenticate_is_per_route() {
        let t = build("https://api.example.com/m", &["https://api.example.com"]).unwrap();
        let r = t.route("a").unwrap();
        assert_eq!(r.authenticate("tok-1").unwrap().id.as_str(), "p1");
        assert!(r.authenticate("tok-2").is_none());
        assert!(r.authenticate("").is_none());
        assert!(t.has_verifier());
    }
}
