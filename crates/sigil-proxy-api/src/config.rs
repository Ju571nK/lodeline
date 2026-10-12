//! Proxy configuration DTO (control-plane.md §6.1) and the config hash.
//!
//! Two shapes:
//!
//! * [`ConfigSpec`] is what an operator submits inside [`PutConfigRequest`]. It
//!   carries no server-stamped field (revision, issue time, expiry, TTL), so an
//!   operator cannot choose them. The server assigns `revision =
//!   expected_revision + 1` and stamps the times.
//! * [`ProxyConfig`] is the full document a proxy reads from
//!   `GET /v1/proxies/{id}/config`.
//!
//! Both are closed on parse (unknown fields rejected) and on emit. [`ProxyConfig`]
//! is closed on purpose even though the proxy reads it from the server: the
//! proxy reports a hash of what it applied, and a lenient parse would let a
//! proxy hash a different document than the server did. A new field therefore
//! needs a contract change that proxy and server adopt together.
//!
//! # `config_hash`
//!
//! `config_hash` = lowercase-hex SHA-256 of the canonical JSON ([`canonical_json`]:
//! sorted keys, compact) of the [`ProxyConfig`] **without** `issued_at`,
//! `expires_at` and `ttl_seconds`. Those three change on every refresh
//! (control-plane §6.2 M-1: the same revision with the same hash only extends the
//! TTL), so including them would make a refresh look like a different config.
//! Everything else is included, `revision` too, so a hash identifies the content
//! of one revision. It is the value of `config_hash` in `proxy-status.schema.json`
//! (`ConfigHash`). Key order and whitespace of the received document do not
//! matter; array order does (routes and principals are ordered lists).

use std::collections::{HashMap, HashSet};

use sha2::{Digest, Sha256};

use crate::canonical::canonical_json;
use crate::error::ValidationError;
use crate::helpers::check_len;
use crate::origin::{normalize_origin, parse_upstream_url};
use crate::scalar::{ConfigHash, Id, NonNegativeI64, PositiveI64, Timestamp};
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
pub const MAX_PRINCIPALS_PER_ROUTE: usize = 64;
pub const MAX_PRINCIPALS_TOTAL: usize = 1024;
pub const MAX_ALLOWED_ORIGINS: usize = 32;
const MAX_ORIGIN_LEN: usize = 256;

/// Fields excluded from the hash (they change on every refresh).
pub const HASH_EXCLUDED_FIELDS: [&str; 3] = ["issued_at", "expires_at", "ttl_seconds"];

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

wire_struct! {
    /// A downstream principal and the verifier of its bearer token
    /// ([`crate::verifier`]): 64 lowercase hex digits. The token itself never
    /// appears here.
    pub struct ConfigPrincipal {
        pub principal_id: Id,
        pub verifier: String,
    }
}

impl Validate for ConfigPrincipal {
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
    /// One upstream route.
    pub struct ConfigRoute {
        pub route_id: Id,
        /// https, or http to a loopback host; no userinfo, query or fragment.
        pub upstream_url: String,
        /// Name resolved on the proxy host (control-plane §5.5). Never a secret.
        pub credential_ref: Id,
        /// Principals that may use this route.
        pub principals: Vec<ConfigPrincipal>,
    }
}

impl Validate for ConfigRoute {
    fn validate(&self) -> Result<(), ValidationError> {
        parse_upstream_url(&self.upstream_url).map_err(ValidationError::new)?;
        check_len(
            "principals",
            self.principals.len(),
            0,
            MAX_PRINCIPALS_PER_ROUTE,
        )?;
        let mut ids = HashSet::new();
        let mut verifiers = HashSet::new();
        for p in &self.principals {
            p.validate()?;
            if !ids.insert(p.principal_id.as_str()) {
                return Err(ValidationError::new(
                    "principal_id must be unique within a route",
                ));
            }
            if !verifiers.insert(p.verifier.as_str()) {
                return Err(ValidationError::new(
                    "a verifier must be unique within a route",
                ));
            }
        }
        Ok(())
    }
}

/// Rules over the whole route list, shared by [`ConfigSpec`] and [`ProxyConfig`].
fn validate_body(
    allowed_origins: &[String],
    routes: &[ConfigRoute],
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
    let mut total = 0usize;
    // principal_id -> verifier and verifier -> principal_id must both be
    // functions over the whole config: a principal is one identity everywhere,
    // and a token resolves to exactly one principal.
    let mut by_id: HashMap<&str, &str> = HashMap::new();
    let mut by_verifier: HashMap<&str, &str> = HashMap::new();
    for route in routes {
        route.validate()?;
        if !route_ids.insert(route.route_id.as_str()) {
            return Err(ValidationError::new("route_id must be unique"));
        }
        total += route.principals.len();
        if total > MAX_PRINCIPALS_TOTAL {
            return Err(ValidationError::limit(
                "too many principals in total (max 1024)",
            ));
        }
        for p in &route.principals {
            let (id, v) = (p.principal_id.as_str(), p.verifier.as_str());
            if by_id.insert(id, v).is_some_and(|prev| prev != v) {
                return Err(ValidationError::new(
                    "a principal_id must have the same verifier on every route",
                ));
            }
            if by_verifier.insert(v, id).is_some_and(|prev| prev != id) {
                return Err(ValidationError::new(
                    "a verifier must belong to one principal_id",
                ));
            }
        }
    }
    Ok(())
}

wire_struct! {
    /// Operator-supplied part of a configuration.
    pub struct ConfigSpec {
        pub proxy_id: Id,
        /// R. Server default 30 days when absent.
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub max_offline_retry_age_seconds: Option<i64>,
        /// E. Server default 90 days when absent.
        #[serde(default, deserialize_with = "crate::helpers::present", skip_serializing_if = "Option::is_none")]
        pub event_retention_seconds: Option<i64>,
        /// Browser `Origin` values the downstream listener accepts (PX-014).
        pub allowed_origins: Vec<String>,
        pub routes: Vec<ConfigRoute>,
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

    /// The full document for `revision`, stamped by the caller (the server).
    pub fn into_config(
        self,
        revision: PositiveI64,
        issued_at: Timestamp,
        expires_at: Timestamp,
        ttl_seconds: i64,
    ) -> Result<ProxyConfig, ValidationError> {
        let cfg = ProxyConfig {
            max_offline_retry_age_seconds: self.max_offline_retry_age(),
            event_retention_seconds: self.event_retention(),
            proxy_id: self.proxy_id,
            revision,
            issued_at,
            expires_at,
            ttl_seconds,
            allowed_origins: self.allowed_origins,
            routes: self.routes,
        };
        cfg.validate()?;
        Ok(cfg)
    }
}

impl Validate for ConfigSpec {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_body(
            &self.allowed_origins,
            &self.routes,
            self.max_offline_retry_age(),
            self.event_retention(),
        )
    }
}

wire_struct! {
    /// The configuration a proxy fetches. Contains verifiers, so it is returned
    /// only to the proxy whose `proxy_id` it carries.
    pub struct ProxyConfig {
        pub proxy_id: Id,
        /// Server-assigned, monotonic, `<= 2^63-1`.
        pub revision: PositiveI64,
        /// Server stamps, refreshed on every fetch.
        pub issued_at: Timestamp,
        pub expires_at: Timestamp,
        pub ttl_seconds: i64,
        pub max_offline_retry_age_seconds: i64,
        pub event_retention_seconds: i64,
        pub allowed_origins: Vec<String>,
        pub routes: Vec<ConfigRoute>,
    }
}

impl Validate for ProxyConfig {
    fn validate(&self) -> Result<(), ValidationError> {
        if !(MIN_TTL_SECONDS..=MAX_TTL_SECONDS).contains(&self.ttl_seconds) {
            return Err(ValidationError::new("ttl_seconds out of range"));
        }
        validate_body(
            &self.allowed_origins,
            &self.routes,
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
        let hex = digest.iter().fold(String::with_capacity(64), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        });
        // 64 lowercase hex digits by construction.
        ConfigHash::new(hex).unwrap_or_else(|_| unreachable!("sha256 hex is a valid ConfigHash"))
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

    fn route(id: &str, url: &str, principals: Value) -> Value {
        json!({"route_id": id, "upstream_url": url, "credential_ref": "gh", "principals": principals})
    }

    fn spec() -> Value {
        json!({
            "proxy_id": "px-1",
            "allowed_origins": ["https://app.example.com"],
            "routes": [route("r1", "https://api.example.com/mcp",
                json!([{"principal_id": "claude", "verifier": V1}]))],
        })
    }

    fn full() -> Value {
        json!({
            "proxy_id": "px-1", "revision": 3,
            "issued_at": "2026-10-11T00:00:00Z", "expires_at": "2026-10-11T00:05:00Z",
            "ttl_seconds": 300,
            "max_offline_retry_age_seconds": 2592000, "event_retention_seconds": 7776000,
            "allowed_origins": ["https://app.example.com"],
            "routes": [route("r1", "https://api.example.com/mcp",
                json!([{"principal_id": "claude", "verifier": V1}]))],
        })
    }

    fn bytes(v: &Value) -> Vec<u8> {
        serde_json::to_vec(v).unwrap()
    }

    fn put(v: Value) -> Vec<u8> {
        bytes(&json!({"expected_revision": 0, "config": v}))
    }

    #[test]
    fn spec_and_config_round_trip_and_are_closed() {
        let p = parse_config_put(&put(spec())).unwrap();
        assert_eq!(p.config.max_offline_retry_age(), 2_592_000);
        assert_eq!(p.config.event_retention(), 7_776_000);
        // Emit is closed: no volatile or None fields leak.
        let out = serde_json::to_value(&p.config).unwrap();
        assert!(out.get("max_offline_retry_age_seconds").is_none());
        let c = parse_config(&bytes(&full())).unwrap();
        assert_eq!(serde_json::to_value(&c).unwrap(), full());

        let mut with_extra = full();
        with_extra["surprise"] = json!(1);
        assert!(parse_config(&bytes(&with_extra)).is_err());
        let mut sp = spec();
        sp["revision"] = json!(5);
        assert!(
            parse_config_put(&put(sp)).is_err(),
            "operator cannot choose server-stamped fields"
        );
        let mut r = spec();
        r["routes"][0]["surprise"] = json!(true);
        assert!(parse_config_put(&put(r)).is_err());
        assert!(parse_config_put(br#"{"expected_revision":0}"#).is_err());
        assert!(parse_config_put(br#"{"expected_revision":-1,"config":{}}"#).is_err());
        // Duplicate keys are rejected by the entry point.
        assert!(parse_config(br#"{"proxy_id":"a","proxy_id":"b"}"#).is_err());
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
    }

    #[test]
    fn uniqueness_and_verifier_rules() {
        // duplicate route_id
        let mut s = spec();
        let r = s["routes"][0].clone();
        s["routes"] = json!([r.clone(), r]);
        assert!(parse_config_put(&put(s)).is_err());
        // duplicate principal_id within a route
        let mut s = spec();
        s["routes"][0]["principals"] = json!([
            {"principal_id": "a", "verifier": V1}, {"principal_id": "a", "verifier": V2}]);
        assert!(parse_config_put(&put(s)).is_err());
        // duplicate verifier within a route
        let mut s = spec();
        s["routes"][0]["principals"] = json!([
            {"principal_id": "a", "verifier": V1}, {"principal_id": "b", "verifier": V1}]);
        assert!(parse_config_put(&put(s)).is_err());
        // same principal on two routes: same verifier ok, different verifier not
        let two = |v2: &str| {
            json!({"proxy_id": "px-1", "allowed_origins": [], "routes": [
                route("r1", "https://a.example", json!([{"principal_id": "a", "verifier": V1}])),
                route("r2", "https://b.example", json!([{"principal_id": "a", "verifier": v2}]))]})
        };
        assert!(parse_config_put(&put(two(V1))).is_ok());
        assert!(parse_config_put(&put(two(V2))).is_err());
        // one verifier under two principal_ids on different routes
        let s = json!({"proxy_id": "px-1", "allowed_origins": [], "routes": [
            route("r1", "https://a.example", json!([{"principal_id": "a", "verifier": V1}])),
            route("r2", "https://b.example", json!([{"principal_id": "b", "verifier": V1}]))]});
        assert!(parse_config_put(&put(s)).is_err());
        // verifier shape
        for bad in [&V1[..63], &V1.to_uppercase(), "", "zz"] {
            let mut s = spec();
            s["routes"][0]["principals"][0]["verifier"] = json!(bad);
            assert!(parse_config_put(&put(s)).is_err());
        }
        // ids follow the Id pattern
        let mut s = spec();
        s["routes"][0]["route_id"] = json!("bad id");
        assert!(parse_config_put(&put(s)).is_err());
    }

    #[test]
    fn count_and_value_bounds() {
        let many_routes: Vec<Value> = (0..=MAX_ROUTES)
            .map(|i| route(&format!("r{i}"), "https://a.example", json!([])))
            .collect();
        let s = json!({"proxy_id": "p", "allowed_origins": [], "routes": many_routes});
        assert_eq!(
            parse_config_put(&put(s)).unwrap_err().category(),
            crate::ErrorCategory::Limit
        );
        let origins: Vec<String> = (0..=MAX_ALLOWED_ORIGINS)
            .map(|i| format!("https://o{i}.example"))
            .collect();
        let s = json!({"proxy_id": "p", "allowed_origins": origins, "routes": []});
        assert!(parse_config_put(&put(s)).is_err());
        let ps: Vec<Value> = (0..=MAX_PRINCIPALS_PER_ROUTE)
            .map(|i| json!({"principal_id": format!("p{i}"), "verifier": format!("{i:064x}")}))
            .collect();
        let s = json!({"proxy_id": "p", "allowed_origins": [],
            "routes": [route("r", "https://a.example", json!(ps))]});
        assert!(parse_config_put(&put(s)).is_err());
        // 17 routes x 64 principals exceeds the total cap
        let routes: Vec<Value> = (0..17)
            .map(|r| {
                let ps: Vec<Value> = (0..64)
                    .map(|i| {
                        let n = r * 64 + i;
                        json!({"principal_id": format!("p{n}"), "verifier": format!("{n:064x}")})
                    })
                    .collect();
                route(&format!("r{r}"), "https://a.example", json!(ps))
            })
            .collect();
        let s = json!({"proxy_id": "p", "allowed_origins": [], "routes": routes});
        assert!(parse_config_put(&put(s)).is_err());

        for (field, bad) in [
            ("max_offline_retry_age_seconds", 3599),
            ("max_offline_retry_age_seconds", 7_776_001),
            ("event_retention_seconds", 3599),
            ("event_retention_seconds", 31_536_001),
        ] {
            let mut s = spec();
            s[field] = json!(bad);
            assert!(parse_config_put(&put(s)).is_err(), "{field}={bad}");
        }
        let mut s = spec();
        s["max_offline_retry_age_seconds"] = json!(7_000_000);
        s["event_retention_seconds"] = json!(6_000_000);
        assert!(parse_config_put(&put(s)).is_err(), "E below R");
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
            assert!(parse_config_put(&put(s)).is_err(), "{bad}");
        }
        let mut s = spec();
        s["allowed_origins"] = json!(["https://a.example", "https://A.example:443"]);
        assert!(
            parse_config_put(&put(s)).is_err(),
            "duplicates after normalisation"
        );
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
        let reordered = r#"{
            "routes": [ {"principals":[{"verifier":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","principal_id":"claude"}],
                         "credential_ref":"gh","upstream_url":"https://api.example.com/mcp","route_id":"r1"} ],
            "allowed_origins": ["https://app.example.com"],
            "event_retention_seconds": 7776000, "max_offline_retry_age_seconds": 2592000,
            "ttl_seconds": 300, "expires_at": "2026-10-11T00:05:00Z",
            "issued_at": "2026-10-11T00:00:00Z", "revision": 3, "proxy_id": "px-1"
        }"#;
        let b = parse_config(reordered.as_bytes()).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.config_hash(), b.config_hash());
        let h = a.config_hash();
        assert_eq!(h.as_str().len(), 64);
        assert!(h
            .as_str()
            .bytes()
            .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')));
    }

    #[test]
    fn hash_excludes_exactly_the_volatile_fields() {
        let a = parse_config(&bytes(&full())).unwrap();
        let t = |s: &str| Timestamp::new(s).unwrap();
        // refresh: new stamps and ttl, same hash
        let r = a.restamped(t("2027-01-01T00:00:00Z"), t("2027-01-01T00:10:00Z"), 600);
        assert_eq!(a.config_hash(), r.config_hash());
        // anything else changes the hash
        let mut c = a.clone();
        c.revision = PositiveI64::new(4).unwrap();
        assert_ne!(a.config_hash(), c.config_hash());
        let mut c = a.clone();
        c.routes[0].principals[0].verifier = V2.into();
        assert_ne!(a.config_hash(), c.config_hash());
        let mut c = a.clone();
        c.routes[0].credential_ref = Id::new("other").unwrap();
        assert_ne!(a.config_hash(), c.config_hash());
        let mut c = a.clone();
        c.allowed_origins.clear();
        assert_ne!(a.config_hash(), c.config_hash());
        let mut c = a.clone();
        c.event_retention_seconds += 1;
        assert_ne!(a.config_hash(), c.config_hash());
        // fixed vector: pins the exclusion list and the canonical form
        assert_eq!(
            a.config_hash().as_str(),
            expected_hash(&a),
            "hash equals sha256 of canonical JSON without the excluded fields"
        );
    }

    fn expected_hash(c: &ProxyConfig) -> String {
        let mut v = serde_json::to_value(c).unwrap();
        for k in ["issued_at", "expires_at", "ttl_seconds"] {
            v.as_object_mut().unwrap().remove(k);
        }
        let want = String::from_utf8(canonical_json(&v)).unwrap();
        assert!(!want.contains("issued_at") && want.starts_with("{\"allowed_origins\""));
        let d = Sha256::digest(want.as_bytes());
        d.iter().map(|b| format!("{b:02x}")).collect()
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
