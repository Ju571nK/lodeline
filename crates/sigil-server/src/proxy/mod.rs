//! T-11 — Sigil Proxy server side (identity, registry, guard, management).
//! Isolated from the host paths and OFF unless `proxy:` is configured.
//!
//! Spec: PX-008/009/012, AC-04, AC-13; control-plane.md §0.1, §1, §2. Slices
//! S1 (identity, registry, guard) and S2a (management auth, audit, lifecycle
//! routes, operator CLI). No config PUT (S3), no ingest/ledger (S4), no CSR
//! signing (S2b).

pub mod audit;
pub mod cli;
pub mod guard;
pub mod identity;
pub mod lifecycle;
pub mod mgmt;
pub mod registry;
pub mod verifiers;

use crate::config::ServerConfig;
use crate::tls_accept::PeerIdentity;
use anyhow::{bail, Context, Result};
use audit::MgmtAudit;
use identity::{PeerClass, ProxyCaInfo};
use registry::ProxyRegistry;
use verifiers::MgmtAuth;

/// Everything the proxy routes and the host-route guard need.
pub struct ProxyContext {
    pub ca: ProxyCaInfo,
    pub registry: ProxyRegistry,
    /// `Some` only when `proxy.management_verifiers` is configured. `None`
    /// means every management route and the audit read route are absent.
    pub mgmt: Option<MgmtAuth>,
    /// Signed management audit stream; present together with `mgmt`.
    pub audit: Option<MgmtAudit>,
}

impl ProxyContext {
    /// Boot-time construction. `Ok(None)` when no `proxy:` section is set.
    /// Refuses (Err) when the proxy CA is not in the client bundle, when
    /// another CA in the bundle shares the proxy CA's subject DN
    /// (control-plane §1.1: the DNs must differ so issuer => class is sound),
    /// or when the management verifier file is unusable.
    pub fn load(cfg: &ServerConfig) -> Result<Option<Self>> {
        let Some(pc) = cfg.proxy.as_ref() else {
            return Ok(None);
        };
        if !cfg.mtls_enabled() {
            bail!("proxy requires mTLS (tls_cert_path + tls_key_path + client_ca_path)");
        }
        let bundle_path = cfg.client_ca_path.as_ref().expect("mtls_enabled");
        let ca = ProxyCaInfo::from_files(&pc.ca_path, bundle_path)
            .with_context(|| format!("proxy CA {}", pc.ca_path.display()))?;
        let registry = ProxyRegistry::open(&pc.registry_path, pc.registry_init)
            .with_context(|| format!("proxy registry {}", pc.registry_path.display()))?;
        let (mgmt, audit) = match pc.management_verifiers.as_deref() {
            None => (None, None),
            Some(vp) => {
                let m = MgmtAuth::load(vp)?;
                if let Some(fp) = m
                    .caller_fingerprints()
                    .find(|f| registry.holds_fingerprint(f))
                {
                    bail!(
                        "management caller fingerprint {fp} is also a registered proxy fingerprint"
                    );
                }
                let hw = cfg.high_water_path();
                let dir = hw.parent().unwrap_or_else(|| std::path::Path::new("."));
                let key = crate::audit_key::AuditKey::load_or_create(dir).context(
                    "proxy management needs the audit signing key, which is unavailable",
                )?;
                (Some(m), Some(MgmtAudit::open(dir, key)?))
            }
        };
        tracing::info!(
            ca_subject = %ca.subject_dn,
            registry = %pc.registry_path.display(),
            management = mgmt.is_some(),
            "proxy routes enabled (GET /v1/proxy-config placeholder)"
        );
        Ok(Some(ProxyContext {
            ca,
            registry,
            mgmt,
            audit,
        }))
    }

    /// Class of a verified peer: the issuer-based class from the CA, plus the
    /// management-caller class (host-CA cert whose fingerprint is in the
    /// verifier file's caller list and is not a registered proxy fingerprint).
    pub fn peer_class(&self, peer: &PeerIdentity) -> PeerClass {
        match self.ca.classify(peer) {
            PeerClass::Host
                if self
                    .mgmt
                    .as_ref()
                    .is_some_and(|m| m.is_caller(&peer.fingerprint))
                    && !self.registry.holds_fingerprint(&peer.fingerprint) =>
            {
                PeerClass::Management
            }
            c => c,
        }
    }
}
