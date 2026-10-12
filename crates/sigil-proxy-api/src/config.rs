//! Proxy configuration DTO (control-plane.md §5.2 and §6.1) and the config hash.
//!
//! Two shapes:
//!
//! * [`ConfigSpec`] is what an operator submits inside [`PutConfigRequest`]. It
//!   carries no server-stamped or server-assigned field (revision, issue time,
//!   expiry, TTL, `credential_scope_id`), so an operator cannot choose them: a
//!   client-supplied value makes the closed parse fail (422 at the server).
//!   The server assigns `revision = expected_revision + 1`, stamps the times and
//!   derives the scope ids ([`credential_scope_id_for`]).
//! * [`ProxyConfig`] is the full document a proxy reads from
//!   `GET /v1/proxies/{id}/config`.
//!
//! Both are closed on parse (unknown fields rejected) and on emit. [`ProxyConfig`]
//! is closed on purpose even though the proxy reads it from the server: the
//! proxy reports a hash of what it applied, and a lenient parse would let a
//! proxy hash a different document than the server did.
//!
//! # `schema_version` and upgrade order
//!
//! Both shapes carry `schema_version` (the constant `1`; any other value fails
//! the parse). A change to the shape needs a new version. **Upgrade the proxy
//! first, then the server**: a proxy that does not know version N+1 rejects the
//! document (`last_update_error = validation_failed`) and keeps its previous
//! config, so a server that emits N+1 before the proxies understand it causes a
//! TTL expiry outage (fail closed). The reverse order is safe.
//!
//! # `config_hash`
//!
//! `config_hash` = lowercase-hex SHA-256 of the canonical JSON ([`canonical_json`]:
//! sorted keys, compact) of the [`ProxyConfig`] **without** `issued_at`,
//! `expires_at` and `ttl_seconds`. Those three change on every refresh
//! (control-plane §6.2 M-1: the same revision with the same hash only extends the
//! TTL), so including them would make a refresh look like a different config.
//! Everything else is included (`schema_version`, `revision`, `mode`, routes with
//! their `credential_scope_id` and limits, principals with verifiers), so a hash
//! identifies the content of one revision. It is the value of `config_hash` in
//! `proxy-status.schema.json` (`ConfigHash`). Key order and whitespace of the
//! received document do not matter; array order does.
//!
//! # Choices where control-plane §6.1 is silent
//!
//! * `limits` fields are `max_request_bytes`, `max_response_bytes` and
//!   `request_timeout_seconds`, each optional with a hard ceiling. A limit may
//!   only LOWER the proxy's own default: the proxy applies the minimum of its
//!   local value and the remote one, so remote config cannot raise a limit.
//! * `upstream_id` is unique per config (status reports key routes by it).
//! * `actor_kind` is `non_human` or `unknown` (README N3: `human` is not
//!   representable). Omitted means `unknown`.
//! * A verifier's `key_id` is an [`Id`] unique within its principal; a verifier
//!   value belongs to one principal in the whole config. At most two verifiers
//!   per principal (rotation overlap), at least one.
//! * `mode` is optional in the spec (default `observe`) and always present in
//!   the full document.

use std::collections::HashSet;

use sha2::{Digest, Sha256};

use crate::canonical::canonical_json;
use crate::error::ValidationError;
use crate::helpers::check_len;
use crate::origin::{normalize_origin, parse_upstream_url};
use crate::scalar::{ConfigHash, Id, NonNegativeI64, PositiveI64, SchemaVersion, Timestamp};
use crate::Validate;

/// Bounds of `ttl_seconds` (control-plane §6.3 proposal: 60-900 s, default 300 s).
pub const MIN_TTL_SECONDS: i64 = 60;
pub const MAX_TTL_SECONDS: i64 = 900;
pub const DEFAULT_TTL_SECONDS: i64 = 300;

/// Bounds and defaults of R (`max_offline_retry_age_seconds`), ledger L1.
pub const MIN_MAX_OFFLINE_RETRY_AGE_SECONDS: i64 = 3600;
pub const MAX_MAX_OFFLINE_RETRY_AGE_SECONDS: i64 = 7_776_000;
pub const DEFAULT_MAX_OFFLINE_RETRY_AGE_SECONDS: i64 = 2_592_000;

/// Bounds and defaults of E (`event_retention_seconds`), ledger L1. The lower
/// bound R + M depends on the server's `ack_loss_margin`; the server enforces it.
pub const MIN_EVENT_RETENTION_SECONDS: i64 = 3600;
pub const MAX_EVENT_RETENTION_SECONDS: i64 = 31_536_000;
pub const DEFAULT_EVENT_RETENTION_SECONDS: i64 = 7_776_000;

/// Count bounds.
pub const MAX_ROUTES: usize = 256;
pub const MAX_PRINCIPALS: usize = 1024;
pub const MAX_VERIFIERS_PER_PRINCIPAL: usize = 2;
pub const MAX_ALLOWED_ORIGINS: usize = 32;
const MAX_ORIGIN_LEN: usize = 256;

/// Hard ceilings of the `limits` fields (the proxy's own defaults are lower).
pub const MAX_LIMIT_REQUEST_BYTES: i64 = 16 * 1024 * 1024;
pub const MAX_LIMIT_RESPONSE_BYTES: i64 = 64 * 1024 * 1024;
pub const MAX_LIMIT_TIMEOUT_SECONDS: i64 = 600;

/// Fields excluded from the hash (they change on every refresh).
pub const HASH_EXCLUDED_FIELDS: [&str; 3] = ["issued_at", "expires_at", "ttl_seconds"];

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Operating mode. P1 has only `observe`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Observe,
}

/// The one supported upstream protocol revision in P1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum UpstreamProtocol {
    #[serde(rename = "2025-11-25")]
    V2025_11_25,
}

/// Declared kind of a principal. `human` is not representable (README N3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    NonHuman,
    Unknown,
}

/// The opaque scope id the server assigns to an (upstream endpoint, upstream
/// credential) binding: stable across revisions while the binding is unchanged,
/// different when `upstream_id`, `credential_ref` or the upstream URL changes,
/// never derived from a secret (the secret is not known to the server).
pub fn credential_scope_id_for(
    proxy_id: &str,
    upstream_id: &str,
    credential_ref: &str,
    origin: &str,
    path: &str,
) -> Id {
    let mut h = Sha256::new();
    h.update(b"sigil-credential-scope-v1");
    for part in [proxy_id, upstream_id, credential_ref, origin, path] {
        h.update([0u8]);
        h.update(part.as_bytes());
    }
    let d = h.finalize();
    Id::new(format!("cs-{}", hex(&d[..16])))
        .unwrap_or_else(|_| unreachable!("cs-<32 hex> is an Id"))
}

wire_struct! {
    /// Per-route limits. May only lower the proxy's own defaults.
    pub struct ConfigLimits {
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub max_request_bytes: Option<i64>,
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub max_response_bytes: Option<i64>,
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub request_timeout_seconds: Option<i64>,
    }
}

impl Validate for ConfigLimits {
    fn validate(&self) -> Result<(), ValidationError> {
        let check = |v: Option<i64>, max: i64, what: &str| match v {
            Some(n) if !(1..=max).contains(&n) => {
                Err(ValidationError::new(format!("{what} out of range")))
            }
            _ => Ok(()),
        };
        check(
            self.max_request_bytes,
            MAX_LIMIT_REQUEST_BYTES,
            "max_request_bytes",
        )?;
        check(
            self.max_response_bytes,
            MAX_LIMIT_RESPONSE_BYTES,
            "max_response_bytes",
        )?;
        check(
            self.request_timeout_seconds,
            MAX_LIMIT_TIMEOUT_SECONDS,
            "request_timeout_seconds",
        )
    }
}

wire_struct! {
    /// One verifier of a principal's bearer token ([`crate::verifier`]).
    /// The token itself never appears here.
    pub struct ConfigVerifier {
        pub key_id: Id,
        /// 64 lowercase hex digits.
        pub verifier: String,
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub not_after: Option<Timestamp>,
    }
}

impl Validate for ConfigVerifier {
    fn validate(&self) -> Result<(), ValidationError> {
        if !is_hex64(&self.verifier) {
            return Err(ValidationError::new(
                "verifier must be 64 lowercase hex digits",
            ));
        }
        Ok(())
    }
}

wire_struct! {
    /// A downstream principal (control-plane §5.2). `principal_id` becomes the
    /// `actor_id`; it is never taken from client input.
    pub struct ConfigPrincipal {
        pub principal_id: Id,
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub actor_kind: Option<ActorKind>,
        /// Permission owner, not evidence of the executor.
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub credential_owner_id: Option<Id>,
        /// 1..=2 entries (rotation overlap).
        pub verifiers: Vec<ConfigVerifier>,
        /// Route ids this principal may use; others are rejected.
        pub routes: Vec<Id>,
    }
}

impl Validate for ConfigPrincipal {
    fn validate(&self) -> Result<(), ValidationError> {
        check_len(
            "verifiers",
            self.verifiers.len(),
            1,
            MAX_VERIFIERS_PER_PRINCIPAL,
        )?;
        check_len("principal routes", self.routes.len(), 0, MAX_ROUTES)?;
        let mut keys = HashSet::new();
        for v in &self.verifiers {
            v.validate()?;
            if !keys.insert(v.key_id.as_str()) {
                return Err(ValidationError::new(
                    "key_id must be unique within a principal",
                ));
            }
        }
        if self.verifiers.len() == 2 && self.verifiers[0].verifier == self.verifiers[1].verifier {
            return Err(ValidationError::new(
                "the two verifiers of a principal must differ",
            ));
        }
        let mut routes = HashSet::new();
        if !self.routes.iter().all(|r| routes.insert(r.as_str())) {
            return Err(ValidationError::new("principal routes must be unique"));
        }
        Ok(())
    }
}

wire_struct! {
    /// Operator-supplied route.
    pub struct RouteSpec {
        pub route_id: Id,
        pub upstream_id: Id,
        /// https, or http to a loopback host; no userinfo, query or fragment.
        pub upstream_url: String,
        pub upstream_protocol: UpstreamProtocol,
        /// Name resolved on the proxy host (control-plane §5.5). Never a secret.
        pub credential_ref: Id,
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub limits: Option<ConfigLimits>,
    }
}

wire_struct! {
    /// One upstream route of the full document.
    pub struct ConfigRoute {
        pub route_id: Id,
        pub upstream_id: Id,
        pub upstream_url: String,
        pub upstream_protocol: UpstreamProtocol,
        pub credential_ref: Id,
        /// Server-assigned ([`credential_scope_id_for`]); opaque to everyone else.
        pub credential_scope_id: Id,
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub limits: Option<ConfigLimits>,
    }
}

fn validate_route_fields(
    upstream_url: &str,
    limits: Option<&ConfigLimits>,
) -> Result<(), ValidationError> {
    parse_upstream_url(upstream_url).map_err(ValidationError::new)?;
    if let Some(l) = limits {
        l.validate()?;
    }
    Ok(())
}

impl Validate for RouteSpec {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_route_fields(&self.upstream_url, self.limits.as_ref())
    }
}

impl Validate for ConfigRoute {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_route_fields(&self.upstream_url, self.limits.as_ref())
    }
}

/// Route fields the cross-checks need, for both route shapes.
struct RouteView<'a> {
    route_id: &'a Id,
    upstream_id: &'a Id,
}

/// Rules over the whole document, shared by [`ConfigSpec`] and [`ProxyConfig`].
fn validate_body(
    allowed_origins: &[String],
    routes: &[RouteView<'_>],
    principals: &[ConfigPrincipal],
    r: i64,
    e: i64,
) -> Result<(), ValidationError> {
    if !(MIN_MAX_OFFLINE_RETRY_AGE_SECONDS..=MAX_MAX_OFFLINE_RETRY_AGE_SECONDS).contains(&r) {
        return Err(ValidationError::new(
            "max_offline_retry_age_seconds out of range",
        ));
    }
    if !(MIN_EVENT_RETENTION_SECONDS..=MAX_EVENT_RETENTION_SECONDS).contains(&e) {
        return Err(ValidationError::new("event_retention_seconds out of range"));
    }
    if e < r {
        return Err(ValidationError::new(
            "event_retention_seconds must not be below max_offline_retry_age_seconds",
        ));
    }
    check_len(
        "allowed_origins",
        allowed_origins.len(),
        0,
        MAX_ALLOWED_ORIGINS,
    )?;
    let mut seen = HashSet::new();
    for o in allowed_origins {
        if o.len() > MAX_ORIGIN_LEN {
            return Err(ValidationError::limit("allowed_origins entry too long"));
        }
        let norm = normalize_origin(o).map_err(ValidationError::new)?;
        if !seen.insert(norm) {
            return Err(ValidationError::new("allowed_origins must be unique"));
        }
    }
    check_len("routes", routes.len(), 0, MAX_ROUTES)?;
    let mut route_ids = HashSet::new();
    let mut upstream_ids = HashSet::new();
    for route in routes {
        if !route_ids.insert(route.route_id.as_str()) {
            return Err(ValidationError::new("route_id must be unique"));
        }
        if !upstream_ids.insert(route.upstream_id.as_str()) {
            return Err(ValidationError::new("upstream_id must be unique"));
        }
    }
    check_len("principals", principals.len(), 0, MAX_PRINCIPALS)?;
    let mut ids = HashSet::new();
    let mut verifiers = HashSet::new();
    for p in principals {
        p.validate()?;
        if !ids.insert(p.principal_id.as_str()) {
            return Err(ValidationError::new("principal_id must be unique"));
        }
        for v in &p.verifiers {
            if !verifiers.insert(v.verifier.as_str()) {
                return Err(ValidationError::new(
                    "a verifier must belong to one principal",
                ));
            }
        }
        if p.routes.iter().any(|r| !route_ids.contains(r.as_str())) {
            return Err(ValidationError::new(
                "principal routes must name routes of this config",
            ));
        }
    }
    Ok(())
}

wire_struct! {
    /// Operator-supplied part of a configuration.
    pub struct ConfigSpec {
        pub schema_version: SchemaVersion,
        pub proxy_id: Id,
        /// Default `observe`.
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub mode: Option<Mode>,
        /// R. Server default 30 days when absent.
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub max_offline_retry_age_seconds: Option<i64>,
        /// E. Server default 90 days when absent.
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub event_retention_seconds: Option<i64>,
        /// Browser `Origin` values the downstream listener accepts (PX-014).
        pub allowed_origins: Vec<String>,
        pub routes: Vec<RouteSpec>,
        pub principals: Vec<ConfigPrincipal>,
    }
}

impl ConfigSpec {
    /// R with the default applied.
    pub fn max_offline_retry_age(&self) -> i64 {
        self.max_offline_retry_age_seconds
            .unwrap_or(DEFAULT_MAX_OFFLINE_RETRY_AGE_SECONDS)
    }

    /// E with the default applied.
    pub fn event_retention(&self) -> i64 {
        self.event_retention_seconds
            .unwrap_or(DEFAULT_EVENT_RETENTION_SECONDS)
    }

    /// The full document for `revision`, stamped by the caller (the server),
    /// with the `credential_scope_id` of every route assigned here.
    pub fn into_config(
        self,
        revision: PositiveI64,
        issued_at: Timestamp,
        expires_at: Timestamp,
        ttl_seconds: i64,
    ) -> Result<ProxyConfig, ValidationError> {
        self.validate()?;
        let routes = self
            .routes
            .iter()
            .map(|r| {
                let u = parse_upstream_url(&r.upstream_url).map_err(ValidationError::new)?;
                Ok(ConfigRoute {
                    credential_scope_id: credential_scope_id_for(
                        self.proxy_id.as_str(),
                        r.upstream_id.as_str(),
                        r.credential_ref.as_str(),
                        &u.origin,
                        &u.path,
                    ),
                    route_id: r.route_id.clone(),
                    upstream_id: r.upstream_id.clone(),
                    upstream_url: r.upstream_url.clone(),
                    upstream_protocol: r.upstream_protocol,
                    credential_ref: r.credential_ref.clone(),
                    limits: r.limits.clone(),
                })
            })
            .collect::<Result<Vec<_>, ValidationError>>()?;
        let cfg = ProxyConfig {
            schema_version: SchemaVersion,
            max_offline_retry_age_seconds: self.max_offline_retry_age(),
            event_retention_seconds: self.event_retention(),
            mode: self.mode.unwrap_or(Mode::Observe),
            proxy_id: self.proxy_id,
            revision,
            issued_at,
            expires_at,
            ttl_seconds,
            allowed_origins: self.allowed_origins,
            routes,
            principals: self.principals,
        };
        cfg.validate()?;
        Ok(cfg)
    }
}

impl Validate for ConfigSpec {
    fn validate(&self) -> Result<(), ValidationError> {
        for r in &self.routes {
            r.validate()?;
        }
        let views: Vec<_> = self
            .routes
            .iter()
            .map(|r| RouteView {
                route_id: &r.route_id,
                upstream_id: &r.upstream_id,
            })
            .collect();
        validate_body(
            &self.allowed_origins,
            &views,
            &self.principals,
            self.max_offline_retry_age(),
            self.event_retention(),
        )
    }
}

wire_struct! {
    /// The configuration a proxy fetches. Contains verifiers, so it is returned
    /// only to the proxy whose `proxy_id` it carries.
    pub struct ProxyConfig {
        pub schema_version: SchemaVersion,
        pub proxy_id: Id,
        /// Server-assigned, monotonic, `<= 2^63-1`.
        pub revision: PositiveI64,
        /// Server stamps, refreshed on every fetch.
        pub issued_at: Timestamp,
        pub expires_at: Timestamp,
        pub ttl_seconds: i64,
        pub mode: Mode,
        pub max_offline_retry_age_seconds: i64,
        pub event_retention_seconds: i64,
        pub allowed_origins: Vec<String>,
        pub routes: Vec<ConfigRoute>,
        pub principals: Vec<ConfigPrincipal>,
    }
}

impl Validate for ProxyConfig {
    fn validate(&self) -> Result<(), ValidationError> {
        if !(MIN_TTL_SECONDS..=MAX_TTL_SECONDS).contains(&self.ttl_seconds) {
            return Err(ValidationError::new("ttl_seconds out of range"));
        }
        for r in &self.routes {
            r.validate()?;
        }
        let views: Vec<_> = self
            .routes
            .iter()
            .map(|r| RouteView {
                route_id: &r.route_id,
                upstream_id: &r.upstream_id,
            })
            .collect();
        validate_body(
            &self.allowed_origins,
            &views,
            &self.principals,
            self.max_offline_retry_age_seconds,
            self.event_retention_seconds,
        )
    }
}

impl ProxyConfig {
    /// `config_hash` (see the module docs for what is excluded).
    pub fn config_hash(&self) -> ConfigHash {
        let mut value = serde_json::to_value(self).unwrap_or(serde_json::Value::Null);
        if let Some(map) = value.as_object_mut() {
            for k in HASH_EXCLUDED_FIELDS {
                map.remove(k);
            }
        }
        let digest = Sha256::digest(canonical_json(&value));
        // 64 lowercase hex digits by construction.
        ConfigHash::new(hex(&digest))
            .unwrap_or_else(|_| unreachable!("sha256 hex is a valid ConfigHash"))
    }

    /// The same configuration with fresh stamps (a refresh): `config_hash` is
    /// unchanged.
    pub fn restamped(
        &self,
        issued_at: Timestamp,
        expires_at: Timestamp,
        ttl_seconds: i64,
    ) -> ProxyConfig {
        ProxyConfig {
            issued_at,
            expires_at,
            ttl_seconds,
            ..self.clone()
        }
    }
}

wire_struct! {
    /// Body of `PUT /v1/proxies/{id}/config`.
    pub struct PutConfigRequest {
        /// The revision the caller last saw; `0` when no config exists yet.
        pub expected_revision: NonNegativeI64,
        pub config: ConfigSpec,
    }
}

no_rules!(PutConfigRequest);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{parse_config, parse_config_put};
    use serde_json::{json, Value};

    const V1: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const V2: &str = "cb7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const V3: &str = "db7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    fn route_spec(id: &str, url: &str) -> Value {
        json!({"route_id": id, "upstream_id": format!("up-{id}"), "upstream_url": url,
            "upstream_protocol": "2025-11-25", "credential_ref": "gh"})
    }

    fn principal(id: &str, verifier: &str, routes: Value) -> Value {
        json!({"principal_id": id,
            "verifiers": [{"key_id": "k1", "verifier": verifier}], "routes": routes})
    }

    fn spec() -> Value {
        json!({
            "schema_version": 1,
            "proxy_id": "px-1",
            "allowed_origins": ["https://app.example.com"],
            "routes": [route_spec("r1", "https://api.example.com/mcp")],
            "principals": [principal("claude", V1, json!(["r1"]))],
        })
    }

    fn full() -> Value {
        json!({
            "schema_version": 1,
            "proxy_id": "px-1", "revision": 3,
            "issued_at": "2026-10-11T00:00:00Z", "expires_at": "2026-10-11T00:05:00Z",
            "ttl_seconds": 300, "mode": "observe",
            "max_offline_retry_age_seconds": 2592000, "event_retention_seconds": 7776000,
            "allowed_origins": ["https://app.example.com"],
            "routes": [{"route_id": "r1", "upstream_id": "up-r1",
                "upstream_url": "https://api.example.com/mcp",
                "upstream_protocol": "2025-11-25", "credential_ref": "gh",
                "credential_scope_id": "cs-0123456789abcdef0123456789abcdef"}],
            "principals": [principal("claude", V1, json!(["r1"]))],
        })
    }

    fn bytes(v: &Value) -> Vec<u8> {
        serde_json::to_vec(v).unwrap()
    }

    fn put(v: Value) -> Vec<u8> {
        bytes(&json!({"expected_revision": 0, "config": v}))
    }

    fn rejects(v: Value) {
        assert!(parse_config_put(&put(v)).is_err());
    }

    #[test]
    fn spec_and_config_round_trip_and_are_closed() {
        let p = parse_config_put(&put(spec())).unwrap();
        assert_eq!(p.config.max_offline_retry_age(), 2_592_000);
        assert_eq!(p.config.event_retention(), 7_776_000);
        let out = serde_json::to_value(&p.config).unwrap();
        assert!(out.get("max_offline_retry_age_seconds").is_none());
        assert!(out.get("mode").is_none());
        let c = parse_config(&bytes(&full())).unwrap();
        assert_eq!(serde_json::to_value(&c).unwrap(), full());

        let mut with_extra = full();
        with_extra["surprise"] = json!(1);
        assert!(parse_config(&bytes(&with_extra)).is_err());
        let mut sp = spec();
        sp["revision"] = json!(5);
        rejects(sp);
        // server-assigned scope id cannot be supplied by the client
        let mut sp = spec();
        sp["routes"][0]["credential_scope_id"] = json!("cs-mine");
        rejects(sp);
        let mut r = spec();
        r["routes"][0]["surprise"] = json!(true);
        rejects(r);
        assert!(parse_config_put(br#"{"expected_revision":0}"#).is_err());
        assert!(parse_config_put(br#"{"expected_revision":-1,"config":{}}"#).is_err());
        assert!(parse_config(br#"{"proxy_id":"a","proxy_id":"b"}"#).is_err());
    }

    #[test]
    fn schema_version_is_required_and_exactly_one() {
        for bad in [json!(0), json!(2), json!("1"), json!(1.5)] {
            let mut s = spec();
            s["schema_version"] = bad.clone();
            rejects(s);
            let mut c = full();
            c["schema_version"] = bad;
            assert!(parse_config(&bytes(&c)).is_err());
        }
        let mut s = spec();
        s.as_object_mut().unwrap().remove("schema_version");
        rejects(s);
        let mut c = full();
        c.as_object_mut().unwrap().remove("schema_version");
        assert!(parse_config(&bytes(&c)).is_err());
    }

    #[test]
    fn revision_must_be_positive_and_integer() {
        for bad in [
            json!(0),
            json!(-1),
            json!(1.5),
            json!("1"),
            json!(1u64 << 63),
        ] {
            let mut c = full();
            c["revision"] = bad;
            assert!(parse_config(&bytes(&c)).is_err());
        }
        let mut c = full();
        c["revision"] = json!(i64::MAX);
        assert!(parse_config(&bytes(&c)).is_ok());
    }

    #[test]
    fn upstream_url_rules() {
        for bad in [
            "http://api.example.com/x",
            "https://user:pw@api.example.com/x",
            "https://api.example.com/x?k=1",
            "https://api.example.com/x#f",
            "https://169.254.169.254/",
            "https://10.0.0.5/",
            "ftp://api.example.com/",
            "",
        ] {
            let mut s = spec();
            s["routes"][0]["upstream_url"] = json!(bad);
            let e = parse_config_put(&put(s)).unwrap_err();
            assert_eq!(e.category(), crate::ErrorCategory::Semantic, "{bad}");
        }
        for ok in ["http://127.0.0.1:9000/mcp", "https://api.example.com"] {
            let mut s = spec();
            s["routes"][0]["upstream_url"] = json!(ok);
            assert!(parse_config_put(&put(s)).is_ok(), "{ok}");
        }
        let mut s = spec();
        s["routes"][0]["upstream_protocol"] = json!("2025-06-18");
        rejects(s);
    }

    #[test]
    fn route_and_principal_rules() {
        // duplicate route_id / upstream_id
        let mut s = spec();
        let r = s["routes"][0].clone();
        s["routes"] = json!([r.clone(), r]);
        rejects(s);
        let mut s = spec();
        let mut r2 = route_spec("r2", "https://b.example");
        r2["upstream_id"] = json!("up-r1");
        s["routes"] = json!([route_spec("r1", "https://a.example"), r2]);
        rejects(s);
        // duplicate principal_id
        let mut s = spec();
        s["principals"] = json!([principal("a", V1, json!([])), principal("a", V2, json!([]))]);
        rejects(s);
        // one verifier under two principals
        let mut s = spec();
        s["principals"] = json!([principal("a", V1, json!([])), principal("b", V1, json!([]))]);
        rejects(s);
        // principal naming an undefined route, duplicate route entry
        let mut s = spec();
        s["principals"] = json!([principal("a", V1, json!(["nope"]))]);
        rejects(s);
        let mut s = spec();
        s["principals"] = json!([principal("a", V1, json!(["r1", "r1"]))]);
        rejects(s);
        // verifier shape
        for bad in [&V1[..63], &V1.to_uppercase(), "", "zz"] {
            let mut s = spec();
            s["principals"][0]["verifiers"][0]["verifier"] = json!(bad);
            rejects(s);
        }
        // ids follow the Id pattern
        let mut s = spec();
        s["routes"][0]["route_id"] = json!("bad id");
        rejects(s);
        // actor_kind: human is not representable
        let mut s = spec();
        s["principals"][0]["actor_kind"] = json!("human");
        rejects(s);
        let mut s = spec();
        s["principals"][0]["actor_kind"] = json!("non_human");
        s["principals"][0]["credential_owner_id"] = json!("team-a");
        assert!(parse_config_put(&put(s)).is_ok());
        // mode: only observe
        let mut s = spec();
        s["mode"] = json!("enforce");
        rejects(s);
        let mut s = spec();
        s["mode"] = json!("observe");
        assert!(parse_config_put(&put(s)).is_ok());
    }

    #[test]
    fn verifier_overlap_for_rotation() {
        let two = |k2: &str, v2: &str| {
            let mut s = spec();
            s["principals"][0]["verifiers"] = json!([
                {"key_id": "k1", "verifier": V1, "not_after": "2027-01-01T00:00:00Z"},
                {"key_id": k2, "verifier": v2}]);
            s
        };
        assert!(parse_config_put(&put(two("k2", V2))).is_ok());
        rejects(two("k1", V2)); // key_id reused
        rejects(two("k2", V1)); // same verifier twice
        let mut s = spec();
        s["principals"][0]["verifiers"] = json!([
            {"key_id": "k1", "verifier": V1}, {"key_id": "k2", "verifier": V2},
            {"key_id": "k3", "verifier": V3}]);
        rejects(s);
        let mut s = spec();
        s["principals"][0]["verifiers"] = json!([]);
        rejects(s);
        let mut s = spec();
        s["principals"][0]["verifiers"][0]["not_after"] = json!("tomorrow");
        rejects(s);
        // the other principal cannot reuse the overlap verifier
        let mut s = two("k2", V2);
        s["principals"]
            .as_array_mut()
            .unwrap()
            .push(principal("b", V2, json!([])));
        rejects(s);
    }

    #[test]
    fn limits_may_be_set_within_ceilings() {
        let with = |l: Value| {
            let mut s = spec();
            s["routes"][0]["limits"] = l;
            s
        };
        assert!(parse_config_put(&put(with(json!({"max_request_bytes": 1024})))).is_ok());
        assert!(parse_config_put(&put(with(json!({})))).is_ok());
        for bad in [
            json!({"max_request_bytes": 0}),
            json!({"max_request_bytes": MAX_LIMIT_REQUEST_BYTES + 1}),
            json!({"max_response_bytes": MAX_LIMIT_RESPONSE_BYTES + 1}),
            json!({"request_timeout_seconds": 601}),
            json!({"request_timeout_seconds": -1}),
            json!({"unknown_limit": 1}),
        ] {
            rejects(with(bad));
        }
    }

    #[test]
    fn scope_ids_are_server_assigned_stable_and_binding_sensitive() {
        let t = |s: &str| Timestamp::new(s).unwrap();
        let build = |s: Value, rev: i64| {
            parse_config_put(&put(s))
                .unwrap()
                .config
                .into_config(
                    PositiveI64::new(rev).unwrap(),
                    t("2026-10-11T00:00:00Z"),
                    t("2026-10-11T00:05:00Z"),
                    300,
                )
                .unwrap()
        };
        let a = build(spec(), 1);
        let b = build(spec(), 2);
        let id = a.routes[0].credential_scope_id.as_str().to_string();
        assert!(id.starts_with("cs-") && id.len() == 35);
        assert_eq!(id, b.routes[0].credential_scope_id.as_str(), "stable");
        // changing any binding input re-mints
        for (field, val) in [
            ("upstream_url", json!("https://api.example.com/other")),
            ("credential_ref", json!("gh2")),
            ("upstream_id", json!("up-other")),
        ] {
            let mut s = spec();
            s["routes"][0][field] = val;
            assert_ne!(
                build(s, 1).routes[0].credential_scope_id.as_str(),
                id,
                "{field}"
            );
        }
        let mut s = spec();
        s["proxy_id"] = json!("px-2");
        assert_ne!(build(s, 1).routes[0].credential_scope_id.as_str(), id);
        // a limits edit does not re-mint
        let mut s = spec();
        s["routes"][0]["limits"] = json!({"request_timeout_seconds": 5});
        assert_eq!(build(s, 1).routes[0].credential_scope_id.as_str(), id);
        // the secret is not an input: nothing in the id depends on a verifier
        let mut s = spec();
        s["principals"][0]["verifiers"][0]["verifier"] = json!(V2);
        assert_eq!(build(s, 1).routes[0].credential_scope_id.as_str(), id);
    }

    #[test]
    fn count_and_value_bounds() {
        let many: Vec<Value> = (0..=MAX_ROUTES)
            .map(|i| route_spec(&format!("r{i}"), "https://a.example"))
            .collect();
        let mut s = spec();
        s["routes"] = json!(many);
        s["principals"] = json!([]);
        assert_eq!(
            parse_config_put(&put(s)).unwrap_err().category(),
            crate::ErrorCategory::Limit
        );
        let origins: Vec<String> = (0..=MAX_ALLOWED_ORIGINS)
            .map(|i| format!("https://o{i}.example"))
            .collect();
        let mut s = spec();
        s["allowed_origins"] = json!(origins);
        rejects(s);
        let ps: Vec<Value> = (0..=MAX_PRINCIPALS)
            .map(|i| principal(&format!("p{i}"), &format!("{i:064x}"), json!([])))
            .collect();
        let mut s = spec();
        s["principals"] = json!(ps);
        assert_eq!(
            parse_config_put(&put(s)).unwrap_err().category(),
            crate::ErrorCategory::Limit
        );
        for (field, bad) in [
            ("max_offline_retry_age_seconds", 3599),
            ("max_offline_retry_age_seconds", 7_776_001),
            ("event_retention_seconds", 3599),
            ("event_retention_seconds", 31_536_001),
        ] {
            let mut s = spec();
            s[field] = json!(bad);
            rejects(s);
        }
        let mut s = spec();
        s["max_offline_retry_age_seconds"] = json!(7_000_000);
        s["event_retention_seconds"] = json!(6_000_000);
        rejects(s);
        for ttl in [59, 901, 0, -1] {
            let mut c = full();
            c["ttl_seconds"] = json!(ttl);
            assert!(parse_config(&bytes(&c)).is_err(), "ttl {ttl}");
        }
    }

    #[test]
    fn allowed_origins_use_origin_rules() {
        for bad in [
            "https://app.example.com/",
            "https://app.example.com/x",
            "http://app.example.com",
            "https://u@app.example.com",
            "*",
            "null",
        ] {
            let mut s = spec();
            s["allowed_origins"] = json!([bad]);
            rejects(s);
        }
        let mut s = spec();
        s["allowed_origins"] = json!(["https://a.example", "https://A.example:443"]);
        rejects(s);
        let mut s = spec();
        s["allowed_origins"] = json!(["http://localhost:3000", "https://a.example"]);
        assert!(parse_config_put(&put(s)).is_ok());
    }

    #[test]
    fn error_text_does_not_echo_values() {
        let mut s = spec();
        s["routes"][0]["upstream_url"] = json!("https://u:SECRETPW@api.example.com/x");
        let e = parse_config_put(&put(s)).unwrap_err();
        assert!(!e.to_string().contains("SECRETPW"));
    }

    #[test]
    fn hash_is_stable_across_key_order_and_whitespace() {
        let a = parse_config(&bytes(&full())).unwrap();
        let mut m: Vec<(String, Value)> = full().as_object().unwrap().clone().into_iter().collect();
        m.reverse();
        let reordered = format!(
            "{{ {} }}",
            m.iter()
                .map(|(k, v)| format!("\"{k}\" :  {v}"))
                .collect::<Vec<_>>()
                .join(" ,\n ")
        );
        let b = parse_config(reordered.as_bytes()).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.config_hash(), b.config_hash());
        assert_eq!(a.config_hash().as_str().len(), 64);
    }

    #[test]
    fn hash_excludes_exactly_the_volatile_fields() {
        let a = parse_config(&bytes(&full())).unwrap();
        let t = |s: &str| Timestamp::new(s).unwrap();
        let r = a.restamped(t("2027-01-01T00:00:00Z"), t("2027-01-01T00:10:00Z"), 600);
        assert_eq!(a.config_hash(), r.config_hash());
        let mut c = a.clone();
        c.revision = PositiveI64::new(4).unwrap();
        assert_ne!(a.config_hash(), c.config_hash());
        let mut c = a.clone();
        c.principals[0].verifiers[0].verifier = V2.into();
        assert_ne!(a.config_hash(), c.config_hash());
        let mut c = a.clone();
        c.principals[0].actor_kind = Some(ActorKind::NonHuman);
        assert_ne!(a.config_hash(), c.config_hash());
        let mut c = a.clone();
        c.routes[0].credential_scope_id = Id::new("cs-other").unwrap();
        assert_ne!(a.config_hash(), c.config_hash());
        let mut c = a.clone();
        c.routes[0].limits = Some(ConfigLimits {
            max_request_bytes: Some(1),
            max_response_bytes: None,
            request_timeout_seconds: None,
        });
        assert_ne!(a.config_hash(), c.config_hash());
        let mut c = a.clone();
        c.allowed_origins.clear();
        assert_ne!(a.config_hash(), c.config_hash());
        let mut c = a.clone();
        c.event_retention_seconds += 1;
        assert_ne!(a.config_hash(), c.config_hash());
        // equals sha256 of canonical JSON without the excluded fields
        let mut v = serde_json::to_value(&a).unwrap();
        for k in HASH_EXCLUDED_FIELDS {
            v.as_object_mut().unwrap().remove(k);
        }
        let want = String::from_utf8(canonical_json(&v)).unwrap();
        assert!(!want.contains("issued_at") && want.starts_with("{\"allowed_origins\""));
        assert_eq!(
            a.config_hash().as_str(),
            hex(&Sha256::digest(want.as_bytes()))
        );
    }

    #[test]
    fn into_config_applies_defaults_and_validates() {
        let t = |s: &str| Timestamp::new(s).unwrap();
        let p = parse_config_put(&put(spec())).unwrap();
        let c = p
            .config
            .clone()
            .into_config(
                PositiveI64::new(1).unwrap(),
                t("2026-10-11T00:00:00Z"),
                t("2026-10-11T00:05:00Z"),
                300,
            )
            .unwrap();
        assert_eq!(c.max_offline_retry_age_seconds, 2_592_000);
        assert_eq!(c.event_retention_seconds, 7_776_000);
        assert_eq!(c.mode, Mode::Observe);
        assert!(c.validate().is_ok());
        assert!(p
            .config
            .into_config(
                PositiveI64::new(1).unwrap(),
                t("2026-10-11T00:00:00Z"),
                t("2026-10-11T00:05:00Z"),
                5,
            )
            .is_err());
    }
}
