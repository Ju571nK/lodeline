//! `server.yaml` schema + loader.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Default rolling window (days) for active-host counting.
pub const DEFAULT_ACTIVE_WINDOW_DAYS: u32 = 7;

/// DEPRECATED `license:` block from earlier releases. Parsed only so existing
/// configs keep loading: `active_window_days` is honored when the top-level
/// key is absent; `path` is ignored. Both log a deprecation warning at load.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct DeprecatedLicenseBlock {
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default)]
    pub active_window_days: Option<u32>,
}

/// `proxy:` section (T-11 S1). See `docs/specs/sigil-proxy` control-plane §0.1/§1.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProxyConfig {
    /// PEM of the proxy client CA. It must ALSO be present in `client_ca_path`
    /// (the listener has one client-CA bundle) and its subject DN must differ
    /// from every other CA in that bundle.
    pub ca_path: PathBuf,
    /// Durable proxy registry file (JSON, atomically written).
    // OPEN: moves to the S4 ledger DB.
    pub registry_path: PathBuf,
    /// Allow creating an empty registry when `registry_path` does not exist.
    /// Default false: a missing file is a boot error (a lost registry must not
    /// silently become an empty one).
    #[serde(default)]
    pub registry_init: bool,
    /// Management verifier file (JSON, owner-only 0600, not a symlink). Absent
    /// ⇒ the management routes and the audit read route are absent (404).
    /// Present ⇒ it must load at boot or the server refuses to start. See
    /// `proxy::verifiers` for the format and the fail-closed reload rule.
    #[serde(default)]
    pub management_verifiers: Option<PathBuf>,
    /// Durable proxy config/status store (JSON, owner-only, atomically
    /// written). Default: `proxy-state.json` next to `registry_path`. A missing
    /// file starts empty (warning); a corrupt, symlinked or group/world
    /// accessible one is a boot error.
    // OPEN: moves to the S4 ledger DB.
    #[serde(default)]
    pub state_path: Option<PathBuf>,
    /// Accept a state store that is behind the management audit (the audit
    /// records a `proxy.config_put` to a revision the store does not hold, e.g.
    /// the store file was lost or restored from a backup). Default false: boot
    /// refuses, because proxies would see a revision lower than the one they
    /// applied (`stale_revision`) and an operator must decide. Set it once, for
    /// the boot that accepts the loss, then remove it (mirrors `registry_init`).
    #[serde(default)]
    pub state_init: bool,
    /// TTL stamped on every served config (control-plane §6.3). Default 300 s,
    /// bounds 60-900 s. unmeasured: a proposal, not a promise.
    #[serde(default)]
    pub config_ttl_seconds: Option<u32>,
    /// `ack_loss_margin` M (ledger L1). A config PUT is refused (422) unless
    /// `event_retention_seconds >= max_offline_retry_age_seconds + M`.
    /// Default 7 days, bounds 1 hour - 30 days.
    #[serde(default)]
    pub ack_loss_margin_seconds: Option<u32>,
    /// Event ledger SQLite file (T-11 S4). Default `proxy-ledger.sqlite` next to
    /// the effective `state_path`. Created owner-only (0600); a symlink or a
    /// group/world accessible existing file is a boot error.
    #[serde(default)]
    pub ledger_path: Option<PathBuf>,
    /// `server.dedup_tombstone_retention` T (ledger L1): how long a dedup
    /// tombstone is kept after acceptance. Boot refuses unless
    /// `T >= max_offline_retry_age + ack_loss_margin` for every stored proxy
    /// config. Default 90 days (= the default E), bounds 1 hour - 730 days.
    /// unmeasured: an initial test value (D-04), not a retention guarantee.
    #[serde(default)]
    pub dedup_tombstone_retention_seconds: Option<u32>,
    /// Ledger storage caps. Exceeding one gives 503 `storage_limit` and stores
    /// nothing. Defaults are conservative, unmeasured test values (D-04).
    /// Rows: 1 - 1e9. Bytes: 1 MiB - 1 TiB. Per-proxy must not exceed total.
    #[serde(default)]
    pub ledger_max_rows_per_proxy: Option<u64>,
    #[serde(default)]
    pub ledger_max_bytes_per_proxy: Option<u64>,
    #[serde(default)]
    pub ledger_max_rows_total: Option<u64>,
    #[serde(default)]
    pub ledger_max_bytes_total: Option<u64>,
    /// Registry-entry store (SQLite, `POST /v1/proxy-metadata`). Default
    /// `proxy-metadata.sqlite` next to the effective `state_path`; same file
    /// rules as the ledger.
    #[serde(default)]
    pub metadata_path: Option<PathBuf>,
    /// Registry entries kept per proxy (1 - 10,000,000, default 20,000) and the
    /// total stored size of all entries including their definitions
    /// (1 MiB - 1 TiB, default 1 GiB). Exceeding either answers 503
    /// `storage_limit` and stores nothing. Unmeasured test values (D-04).
    #[serde(default)]
    pub metadata_max_entries_per_proxy: Option<u64>,
    #[serde(default)]
    pub metadata_max_bytes_total: Option<u64>,
    /// Per-proxy byte cap of stored entries (1 MiB - 1 TiB, default 128 MiB;
    /// must not exceed `metadata_max_bytes_total`).
    #[serde(default)]
    pub metadata_max_bytes_per_proxy: Option<u64>,
    /// Seconds allowed to read one ingest/upload body (1 - 300, default 20).
    /// A slower client is answered 429 `rate_limited` and frees its slot.
    #[serde(default)]
    pub ingest_body_timeout_seconds: Option<u32>,
    /// Concurrent ingest/upload requests (1 - 256, default 16). Above it the
    /// server answers 429 `rate_limited` without reading the body. One proxy
    /// may hold at most max(1, N/4) of them.
    #[serde(default)]
    pub ingest_max_concurrent: Option<u32>,
    /// Seconds between ledger retention sweeps (60 - 86400, default 3600).
    #[serde(default)]
    pub ledger_sweep_interval_seconds: Option<u32>,
}

impl ProxyConfig {
    pub const DEFAULT_TOMBSTONE_RETENTION_SECONDS: u32 = 90 * 24 * 3600;
    pub const MIN_TOMBSTONE_RETENTION_SECONDS: u32 = 3600;
    pub const MAX_TOMBSTONE_RETENTION_SECONDS: u32 = 730 * 24 * 3600;
    pub const DEFAULT_LEDGER_ROWS_PER_PROXY: u64 = 1_000_000;
    pub const DEFAULT_LEDGER_BYTES_PER_PROXY: u64 = 512 * 1024 * 1024;
    pub const DEFAULT_LEDGER_ROWS_TOTAL: u64 = 5_000_000;
    pub const DEFAULT_LEDGER_BYTES_TOTAL: u64 = 4 * 1024 * 1024 * 1024;
    pub const MAX_LEDGER_ROWS: u64 = 1_000_000_000;
    pub const MIN_LEDGER_BYTES: u64 = 1024 * 1024;
    pub const MAX_LEDGER_BYTES: u64 = 1 << 40;

    pub const DEFAULT_METADATA_ENTRIES_PER_PROXY: u64 = 10_000;
    pub const DEFAULT_METADATA_BYTES_PER_PROXY: u64 = 128 * 1024 * 1024;
    pub const DEFAULT_INGEST_BODY_TIMEOUT_SECONDS: u32 = 20;
    pub const MAX_METADATA_ENTRIES: u64 = 10_000_000;
    pub const DEFAULT_METADATA_BYTES_TOTAL: u64 = 1 << 30;
    pub const DEFAULT_INGEST_MAX_CONCURRENT: u32 = 16;
    pub const MAX_INGEST_MAX_CONCURRENT: u32 = 256;
    pub const DEFAULT_LEDGER_SWEEP_INTERVAL_SECONDS: u32 = 3600;

    pub const DEFAULT_CONFIG_TTL_SECONDS: u32 = 300;
    pub const DEFAULT_ACK_LOSS_MARGIN_SECONDS: u32 = 7 * 24 * 3600;

    pub fn config_ttl(&self) -> u32 {
        self.config_ttl_seconds
            .unwrap_or(Self::DEFAULT_CONFIG_TTL_SECONDS)
    }

    pub fn ack_loss_margin(&self) -> u32 {
        self.ack_loss_margin_seconds
            .unwrap_or(Self::DEFAULT_ACK_LOSS_MARGIN_SECONDS)
    }

    pub fn dedup_tombstone_retention(&self) -> u32 {
        self.dedup_tombstone_retention_seconds
            .unwrap_or(Self::DEFAULT_TOMBSTONE_RETENTION_SECONDS)
    }

    pub fn ledger_max_rows_per_proxy(&self) -> u64 {
        self.ledger_max_rows_per_proxy
            .unwrap_or(Self::DEFAULT_LEDGER_ROWS_PER_PROXY)
    }

    pub fn ledger_max_bytes_per_proxy(&self) -> u64 {
        self.ledger_max_bytes_per_proxy
            .unwrap_or(Self::DEFAULT_LEDGER_BYTES_PER_PROXY)
    }

    pub fn ledger_max_rows_total(&self) -> u64 {
        self.ledger_max_rows_total
            .unwrap_or(Self::DEFAULT_LEDGER_ROWS_TOTAL)
    }

    pub fn ledger_max_bytes_total(&self) -> u64 {
        self.ledger_max_bytes_total
            .unwrap_or(Self::DEFAULT_LEDGER_BYTES_TOTAL)
    }

    pub fn metadata_max_entries_per_proxy(&self) -> u64 {
        self.metadata_max_entries_per_proxy
            .unwrap_or(Self::DEFAULT_METADATA_ENTRIES_PER_PROXY)
    }

    pub fn metadata_max_bytes_total(&self) -> u64 {
        self.metadata_max_bytes_total
            .unwrap_or(Self::DEFAULT_METADATA_BYTES_TOTAL)
    }

    pub fn metadata_max_bytes_per_proxy(&self) -> u64 {
        self.metadata_max_bytes_per_proxy
            .unwrap_or(Self::DEFAULT_METADATA_BYTES_PER_PROXY)
    }

    pub fn ingest_body_timeout(&self) -> u32 {
        self.ingest_body_timeout_seconds
            .unwrap_or(Self::DEFAULT_INGEST_BODY_TIMEOUT_SECONDS)
    }

    pub fn ingest_max_concurrent(&self) -> u32 {
        self.ingest_max_concurrent
            .unwrap_or(Self::DEFAULT_INGEST_MAX_CONCURRENT)
    }

    pub fn ledger_sweep_interval(&self) -> u32 {
        self.ledger_sweep_interval_seconds
            .unwrap_or(Self::DEFAULT_LEDGER_SWEEP_INTERVAL_SECONDS)
    }

    /// Effective registry-entry store path.
    pub fn metadata_path(&self) -> PathBuf {
        self.metadata_path.clone().unwrap_or_else(|| {
            self.state_path()
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."))
                .join("proxy-metadata.sqlite")
        })
    }

    /// Effective ledger path.
    pub fn ledger_path(&self) -> PathBuf {
        self.ledger_path.clone().unwrap_or_else(|| {
            self.state_path()
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."))
                .join("proxy-ledger.sqlite")
        })
    }

    /// Effective store path.
    pub fn state_path(&self) -> PathBuf {
        self.state_path.clone().unwrap_or_else(|| {
            self.registry_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join("proxy-state.json")
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ServerConfig {
    /// Address to bind. e.g. `0.0.0.0:8443`.
    pub bind: SocketAddr,
    /// PEM server cert. If set (together with `tls_key_path`), the server
    /// runs mTLS; `client_ca_path` is then required.
    #[serde(default)]
    pub tls_cert_path: Option<PathBuf>,
    /// PEM server private key.
    #[serde(default)]
    pub tls_key_path: Option<PathBuf>,
    /// PEM bundle of CAs whose client certs are trusted (mTLS).
    #[serde(default)]
    pub client_ca_path: Option<PathBuf>,
    /// Directory where accepted events are written (per-host subdirs).
    pub events_out_dir: PathBuf,
    /// Path to the operator-signed policy bundle (`SignedPolicyResponse` JSON,
    /// produced by `sigil-sign`). Absent file ⇒ `GET /v1/policy` returns 404.
    pub policy_bundle_path: PathBuf,
    /// Path to the signed pack-set bundle (`SignedPolicyResponse`-shaped JSON,
    /// produced by `sigil-sign`). Absent ⇒ `GET /v1/rule-packs` returns 404.
    #[serde(default)]
    pub rule_packs_bundle_path: Option<std::path::PathBuf>,
    /// Directory of operator-populated, signed agent release artifacts
    /// (tarballs/zips, `.deb`/`.rpm`, `SHA256SUMS`, `build-manifest.json`).
    /// Absent ⇒ `GET /v1/artifacts*` returns 404 (feature off). #182
    #[serde(default)]
    pub artifacts_dir: Option<PathBuf>,
    /// #184 — operator-provided INTERMEDIATE CA cert (PEM). Returned in the
    /// enroll chain and used to sign host CSRs. Root stays offline. Absent ⇒
    /// enrollment off (404).
    #[serde(default)]
    pub enroll_ca_cert_path: Option<PathBuf>,
    /// #184 — intermediate CA private key (PEM, 0600). Online signing key.
    /// Absent ⇒ enrollment off.
    #[serde(default)]
    pub enroll_ca_key_path: Option<PathBuf>,
    /// #184 — enrollment token store (JSON, blake3-hashed tokens).
    /// Absent ⇒ enrollment off.
    #[serde(default)]
    pub enroll_tokens_path: Option<PathBuf>,
    /// #194.1 — optional allowlist of TLS client-cert fingerprints (blake3 hex
    /// of the leaf cert DER) permitted to call `POST /v1/enroll` (the
    /// PMS/issuer box). Absent ⇒ any mTLS fleet member may redeem an enroll
    /// token (pre-#194 behavior). Present-but-empty ⇒ deny-all.
    #[serde(default)]
    pub enroll_issuer_fingerprints: Option<Vec<String>>,
    /// #184 — issued client-cert validity in days (default 30; short by design,
    /// re-enroll replaces revocation in the MVP).
    #[serde(default)]
    pub enroll_cert_days: Option<u32>,
    /// Optional allowlist of `host_id`s. Absent ⇒ accept all authenticated hosts.
    /// REQUIRED for enrollment (#184): without it, auto-add is meaningless, so
    /// enrollment stays off (404) when this is unset.
    #[serde(default)]
    pub host_allowlist_path: Option<PathBuf>,
    /// #194.2 — when true, `POST /v1/events` additionally requires the TLS
    /// client cert to match the envelope `host_id` (subject CN == host_id, or
    /// host_id ∈ SAN DNS). Requires mTLS: the server refuses to start if this
    /// is set without the full TLS triple. Default false (pre-#194 behavior).
    #[serde(default)]
    pub events_require_cert_host_match: bool,
    /// T-11 — Sigil Proxy identity/registry. Absent ⇒ every proxy route is
    /// absent (404 like any unknown route) and host behaviour is unchanged.
    /// Requires mTLS (refuse-to-start otherwise).
    #[serde(default)]
    pub proxy: Option<ProxyConfig>,
    /// Path to the persisted per-host high-water-sequence map (for dedup
    /// across restarts). Defaults to `<events_out_dir>/.high-water.json`.
    #[serde(default)]
    pub high_water_path: Option<PathBuf>,
    /// Rolling window (days) for active-host counting, reported in
    /// `GET /v1/meta` under `fleet`. Read through [`Self::active_window_days`]:
    /// absent ⇒ deprecated `license.active_window_days`, else
    /// [`DEFAULT_ACTIVE_WINDOW_DAYS`]. An explicit top-level value always wins.
    #[serde(default)]
    pub active_window_days: Option<u32>,
    /// DEPRECATED — see [`DeprecatedLicenseBlock`]. Never serialized.
    #[serde(default, rename = "license", skip_serializing)]
    pub deprecated_license: Option<DeprecatedLicenseBlock>,
}

impl ServerConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let bytes = std::fs::read(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let cfg: Self = serde_yaml::from_slice(&bytes).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
        cfg.validate(path)?;
        cfg.warn_deprecated();
        Ok(cfg)
    }

    /// Effective active-host window: top-level `active_window_days`, else the
    /// deprecated `license.active_window_days`, else the default.
    pub fn active_window_days(&self) -> u32 {
        self.active_window_days
            .or_else(|| {
                self.deprecated_license
                    .as_ref()
                    .and_then(|l| l.active_window_days)
            })
            .unwrap_or(DEFAULT_ACTIVE_WINDOW_DAYS)
    }

    /// One `warn!` per deprecated `license:` key that is set.
    fn warn_deprecated(&self) {
        let Some(l) = &self.deprecated_license else {
            return;
        };
        if let Some(days) = l.active_window_days {
            if self.active_window_days.is_some() {
                tracing::warn!(
                    "config: `license.active_window_days` is deprecated and overridden \
                     by top-level `active_window_days`; remove the `license:` block"
                );
            } else {
                tracing::warn!(
                    active_window_days = days,
                    "config: `license.active_window_days` is deprecated; still honored, \
                     move it to top-level `active_window_days`"
                );
            }
        }
        if l.path.is_some() {
            tracing::warn!(
                "config: `license.path` is no longer used and is ignored; \
                 remove the `license:` block"
            );
        }
    }

    /// Cross-field boot validation. #194.2: `events_require_cert_host_match`
    /// is meaningless over plain HTTP (there is no client cert to match), so
    /// setting it without the full mTLS triple is a refuse-to-start error —
    /// never a silently-ignored gate.
    fn validate(&self, path: &Path) -> Result<(), ConfigError> {
        if self.events_require_cert_host_match && !self.mtls_enabled() {
            return Err(ConfigError::Invalid {
                path: path.to_path_buf(),
                reason: "events_require_cert_host_match requires mTLS \
                         (tls_cert_path + tls_key_path + client_ca_path)"
                    .to_string(),
            });
        }
        if self.proxy.is_some() && !self.mtls_enabled() {
            // control-plane §0.1: proxy routes are not served without mTLS.
            return Err(ConfigError::Invalid {
                path: path.to_path_buf(),
                reason: "proxy requires mTLS \
                         (tls_cert_path + tls_key_path + client_ca_path)"
                    .to_string(),
            });
        }
        if let Some(p) = &self.proxy {
            let bad = |reason: &str| ConfigError::Invalid {
                path: path.to_path_buf(),
                reason: reason.to_string(),
            };
            if !(60..=900).contains(&p.config_ttl()) {
                return Err(bad("proxy.config_ttl_seconds must be within 60..=900"));
            }
            if !(3600..=30 * 24 * 3600).contains(&p.ack_loss_margin()) {
                return Err(bad(
                    "proxy.ack_loss_margin_seconds must be within 3600..=2592000",
                ));
            }
            if !(ProxyConfig::MIN_TOMBSTONE_RETENTION_SECONDS
                ..=ProxyConfig::MAX_TOMBSTONE_RETENTION_SECONDS)
                .contains(&p.dedup_tombstone_retention())
            {
                return Err(bad(
                    "proxy.dedup_tombstone_retention_seconds must be within 3600..=63072000",
                ));
            }
            let rows = 1..=ProxyConfig::MAX_LEDGER_ROWS;
            let bytes = ProxyConfig::MIN_LEDGER_BYTES..=ProxyConfig::MAX_LEDGER_BYTES;
            if !rows.contains(&p.ledger_max_rows_per_proxy())
                || !rows.contains(&p.ledger_max_rows_total())
            {
                return Err(bad(
                    "proxy.ledger_max_rows_per_proxy and ledger_max_rows_total must be within 1..=1000000000",
                ));
            }
            if !bytes.contains(&p.ledger_max_bytes_per_proxy())
                || !bytes.contains(&p.ledger_max_bytes_total())
            {
                return Err(bad(
                    "proxy.ledger_max_bytes_per_proxy and ledger_max_bytes_total must be within 1048576..=1099511627776",
                ));
            }
            if p.ledger_max_rows_per_proxy() > p.ledger_max_rows_total()
                || p.ledger_max_bytes_per_proxy() > p.ledger_max_bytes_total()
            {
                return Err(bad(
                    "proxy.ledger_max_*_per_proxy must not exceed the matching ledger_max_*_total",
                ));
            }
            if !(1..=ProxyConfig::MAX_METADATA_ENTRIES)
                .contains(&p.metadata_max_entries_per_proxy())
                || !(ProxyConfig::MIN_LEDGER_BYTES..=ProxyConfig::MAX_LEDGER_BYTES)
                    .contains(&p.metadata_max_bytes_total())
            {
                return Err(bad(
                    "proxy.metadata_max_entries_per_proxy must be within 1..=10000000 and metadata_max_bytes_total within 1048576..=1099511627776",
                ));
            }
            if !(ProxyConfig::MIN_LEDGER_BYTES..=ProxyConfig::MAX_LEDGER_BYTES)
                .contains(&p.metadata_max_bytes_per_proxy())
                || p.metadata_max_bytes_per_proxy() > p.metadata_max_bytes_total()
            {
                return Err(bad(
                    "proxy.metadata_max_bytes_per_proxy must be within 1048576..=1099511627776 and not exceed metadata_max_bytes_total",
                ));
            }
            if !(1..=300).contains(&p.ingest_body_timeout()) {
                return Err(bad(
                    "proxy.ingest_body_timeout_seconds must be within 1..=300",
                ));
            }
            if !(1..=ProxyConfig::MAX_INGEST_MAX_CONCURRENT).contains(&p.ingest_max_concurrent()) {
                return Err(bad("proxy.ingest_max_concurrent must be within 1..=256"));
            }
            if !(60..=86_400).contains(&p.ledger_sweep_interval()) {
                return Err(bad(
                    "proxy.ledger_sweep_interval_seconds must be within 60..=86400",
                ));
            }
        }
        Ok(())
    }

    /// Effective high-water path: explicit, or `<events_out_dir>/.high-water.json`.
    pub fn high_water_path(&self) -> PathBuf {
        self.high_water_path
            .clone()
            .unwrap_or_else(|| self.events_out_dir.join(".high-water.json"))
    }

    /// True iff a full mTLS triple is configured.
    pub fn mtls_enabled(&self) -> bool {
        self.tls_cert_path.is_some() && self.tls_key_path.is_some() && self.client_ca_path.is_some()
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("yaml parse {path}: {source}")]
    Parse {
        path: PathBuf,
        source: serde_yaml::Error,
    },
    #[error("invalid config {path}: {reason}")]
    Invalid { path: PathBuf, reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// The shipped `config/server.example.yaml` must stay in sync with the
    /// `ServerConfig` schema: uncomment every documented setting and it must
    /// still deserialize (guards against a typo'd or renamed key in the docs).
    #[test]
    fn example_config_matches_schema() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../config/server.example.yaml"
        );
        let raw = std::fs::read_to_string(path).expect("read example yaml");
        let mut out = String::new();
        for line in raw.lines() {
            let t = line.trim_start();
            // Uncomment lines that document a setting (`# key:`, `#   - item`);
            // drop prose comments.
            let is_setting = t
                .strip_prefix('#')
                .map(|r| {
                    let r = r.trim_start();
                    r.starts_with("- ")
                        || r.split_once(':').is_some_and(|(k, _)| {
                            !k.is_empty() && k.chars().all(|c| c.is_ascii_lowercase() || c == '_')
                        })
                })
                .unwrap_or(false);
            if let Some(stripped) = line.strip_prefix("# ").or_else(|| line.strip_prefix('#')) {
                if is_setting {
                    out.push_str(stripped);
                    out.push('\n');
                }
                // else: prose comment — skip
            } else {
                out.push_str(line);
                out.push('\n');
            }
        }
        let cfg: ServerConfig = serde_yaml::from_str(&out).unwrap_or_else(|e| {
            panic!("example yaml (all keys uncommented) must parse: {e}\n---\n{out}")
        });
        // Spot-check the #184/#194 keys are present and typed as expected.
        assert!(cfg.enroll_ca_cert_path.is_some());
        assert!(cfg.enroll_issuer_fingerprints.is_some());
        assert!(cfg.events_require_cert_host_match);
        assert!(cfg.artifacts_dir.is_some());
        assert!(cfg.active_window_days.is_some());
        assert!(cfg.proxy.is_some());
        assert!(
            cfg.deprecated_license.is_none(),
            "example must not document `license:`"
        );
    }

    #[test]
    fn loads_minimal_config() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("server.yaml");
        std::fs::write(
            &p,
            r#"
bind: "127.0.0.1:8443"
events_out_dir: "/var/lib/sigil-server/events"
policy_bundle_path: "/var/lib/sigil-server/signed-policy.json"
"#,
        )
        .unwrap();
        let cfg = ServerConfig::load(&p).unwrap();
        assert_eq!(cfg.bind.port(), 8443);
        assert!(!cfg.mtls_enabled());
        assert!(cfg.host_allowlist_path.is_none());
        assert_eq!(
            cfg.high_water_path(),
            PathBuf::from("/var/lib/sigil-server/events/.high-water.json")
        );
    }

    #[test]
    fn mtls_enabled_when_full_triple_present() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("server.yaml");
        std::fs::write(
            &p,
            r#"
bind: "0.0.0.0:8443"
tls_cert_path: "/etc/sigil-server/server.crt"
tls_key_path: "/etc/sigil-server/server.key"
client_ca_path: "/etc/sigil-server/client-ca.pem"
events_out_dir: "/d/events"
policy_bundle_path: "/d/signed-policy.json"
host_allowlist_path: "/d/hosts.json"
"#,
        )
        .unwrap();
        let cfg = ServerConfig::load(&p).unwrap();
        assert!(cfg.mtls_enabled());
        assert!(cfg.host_allowlist_path.is_some());
    }

    /// #194.1 — enroll_issuer_fingerprints parses; absent stays None.
    #[test]
    fn parses_enroll_issuer_fingerprints() {
        let yaml = r#"
bind: "127.0.0.1:8443"
events_out_dir: "/d/events"
policy_bundle_path: "/d/signed-policy.json"
enroll_issuer_fingerprints:
  - "aabb01"
  - "ccdd02"
"#;
        let cfg: ServerConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            cfg.enroll_issuer_fingerprints,
            Some(vec!["aabb01".to_string(), "ccdd02".to_string()])
        );

        let yaml_absent = r#"
bind: "127.0.0.1:8443"
events_out_dir: "/d/events"
policy_bundle_path: "/d/signed-policy.json"
"#;
        let cfg: ServerConfig = serde_yaml::from_str(yaml_absent).unwrap();
        assert_eq!(cfg.enroll_issuer_fingerprints, None);
    }

    /// #194.2 — events_require_cert_host_match parses; default false.
    #[test]
    fn parses_events_require_cert_host_match() {
        let yaml = r#"
bind: "127.0.0.1:8443"
tls_cert_path: "/e/server.crt"
tls_key_path: "/e/server.key"
client_ca_path: "/e/client-ca.pem"
events_out_dir: "/d/events"
policy_bundle_path: "/d/signed-policy.json"
events_require_cert_host_match: true
"#;
        let cfg: ServerConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(cfg.events_require_cert_host_match);

        let yaml_absent = r#"
bind: "127.0.0.1:8443"
events_out_dir: "/d/events"
policy_bundle_path: "/d/signed-policy.json"
"#;
        let cfg: ServerConfig = serde_yaml::from_str(yaml_absent).unwrap();
        assert!(!cfg.events_require_cert_host_match, "default is false");
    }

    /// #194.2 — the flag without mTLS is a refuse-to-start config error; with
    /// the full mTLS triple the same config loads.
    #[test]
    fn cert_host_match_without_mtls_refuses_to_load() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("server.yaml");
        std::fs::write(
            &p,
            r#"
bind: "127.0.0.1:8443"
events_out_dir: "/d/events"
policy_bundle_path: "/d/signed-policy.json"
events_require_cert_host_match: true
"#,
        )
        .unwrap();
        let err = ServerConfig::load(&p).unwrap_err();
        assert!(
            matches!(err, ConfigError::Invalid { .. }),
            "flag without mTLS must refuse to start, got: {err}"
        );

        std::fs::write(
            &p,
            r#"
bind: "127.0.0.1:8443"
tls_cert_path: "/e/server.crt"
tls_key_path: "/e/server.key"
client_ca_path: "/e/client-ca.pem"
events_out_dir: "/d/events"
policy_bundle_path: "/d/signed-policy.json"
events_require_cert_host_match: true
"#,
        )
        .unwrap();
        let cfg = ServerConfig::load(&p).unwrap();
        assert!(cfg.events_require_cert_host_match && cfg.mtls_enabled());
    }

    /// T-11 — proxy section parses; absent ⇒ None; without mTLS it refuses.
    #[test]
    fn proxy_section_requires_mtls() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("server.yaml");
        let proxy = "proxy:\n  ca_path: /e/proxy-ca.pem\n  registry_path: /d/proxies.json\n";
        std::fs::write(&p, format!("{BASE}{proxy}")).unwrap();
        assert!(matches!(
            ServerConfig::load(&p).unwrap_err(),
            ConfigError::Invalid { .. }
        ));
        let mtls = "tls_cert_path: /e/s.crt\ntls_key_path: /e/s.key\nclient_ca_path: /e/ca.pem\n";
        std::fs::write(&p, format!("{BASE}{mtls}{proxy}")).unwrap();
        let cfg = ServerConfig::load(&p).unwrap();
        assert_eq!(
            cfg.proxy.unwrap().registry_path,
            PathBuf::from("/d/proxies.json")
        );
        std::fs::write(&p, format!("{BASE}{mtls}")).unwrap();
        assert!(ServerConfig::load(&p).unwrap().proxy.is_none());
    }

    #[test]
    fn missing_file_is_read_error() {
        let err = ServerConfig::load(Path::new("/nonexistent/server.yaml")).unwrap_err();
        assert!(matches!(err, ConfigError::Read { .. }));
    }

    const BASE: &str = r#"
bind: "127.0.0.1:8443"
events_out_dir: "/var/lib/sigil-server/events"
policy_bundle_path: "/var/lib/sigil-server/signed-policy.json"
"#;

    #[test]
    fn active_window_defaults_when_absent() {
        let cfg: ServerConfig = serde_yaml::from_str(BASE).unwrap();
        assert_eq!(cfg.active_window_days, None);
        assert!(cfg.deprecated_license.is_none());
        assert_eq!(cfg.active_window_days(), DEFAULT_ACTIVE_WINDOW_DAYS);
    }

    #[test]
    fn top_level_active_window_is_used() {
        let yaml = format!("{BASE}active_window_days: 30\n");
        let cfg: ServerConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(cfg.active_window_days(), 30);
    }

    /// Configs written for earlier releases (with a `license:` block holding
    /// both keys) must still load through `ServerConfig::load`.
    #[test]
    fn legacy_license_block_still_parses() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("server.yaml");
        std::fs::write(
            &p,
            format!(
                "{BASE}license:\n  path: /etc/sigil/license.bundle\n  active_window_days: 14\n"
            ),
        )
        .unwrap();
        let cfg = ServerConfig::load(&p).expect("legacy config loads");
        let l = cfg.deprecated_license.as_ref().expect("legacy block kept");
        assert_eq!(
            l.path.as_deref(),
            Some(Path::new("/etc/sigil/license.bundle"))
        );
        // A path-only legacy block also loads and falls back to the default.
        std::fs::write(
            &p,
            format!("{BASE}license:\n  path: /etc/sigil/license.bundle\n"),
        )
        .unwrap();
        let cfg = ServerConfig::load(&p).expect("path-only legacy config loads");
        assert_eq!(cfg.active_window_days(), DEFAULT_ACTIVE_WINDOW_DAYS);
    }

    #[test]
    fn legacy_active_window_is_honored_when_top_level_absent() {
        let yaml = format!("{BASE}license:\n  active_window_days: 14\n");
        let cfg: ServerConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(cfg.active_window_days, None);
        assert_eq!(cfg.active_window_days(), 14);
    }

    /// Top-level wins even when it equals the default (so the default value
    /// is not mistaken for "absent").
    #[test]
    fn top_level_active_window_wins_over_legacy() {
        let yaml = format!("{BASE}active_window_days: 30\nlicense:\n  active_window_days: 14\n");
        let cfg: ServerConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(cfg.active_window_days(), 30);

        let yaml = format!(
            "{BASE}active_window_days: {DEFAULT_ACTIVE_WINDOW_DAYS}\nlicense:\n  active_window_days: 14\n"
        );
        let cfg: ServerConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(cfg.active_window_days(), DEFAULT_ACTIVE_WINDOW_DAYS);
    }

    #[test]
    fn deprecated_block_is_not_serialized() {
        let yaml = format!("{BASE}license:\n  active_window_days: 14\n");
        let cfg: ServerConfig = serde_yaml::from_str(&yaml).unwrap();
        let out = serde_yaml::to_string(&cfg).unwrap();
        assert!(!out.contains("license"), "{out}");
    }
}
