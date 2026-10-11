//! T-11 — Sigil Proxy server side (identity, registry, guard). Isolated from
//! the host paths and OFF unless `proxy:` is configured.
//!
//! Spec: PX-008/009, AC-04; control-plane.md §0.1, §1. Slice S1 only: no
//! management routes (S2), no ingest/ledger (S4).

pub mod guard;
pub mod identity;
pub mod registry;

use crate::config::ServerConfig;
use anyhow::{bail, Context, Result};
use identity::ProxyCaInfo;
use registry::ProxyRegistry;

/// Everything the proxy routes and the host-route guard need.
pub struct ProxyContext {
    pub ca: ProxyCaInfo,
    pub registry: ProxyRegistry,
}

impl ProxyContext {
    /// Boot-time construction. `Ok(None)` when no `proxy:` section is set.
    /// Refuses (Err) when the proxy CA is not in the client bundle, or when
    /// another CA in the bundle shares the proxy CA's subject DN
    /// (control-plane §1.1: the DNs must differ so issuer => class is sound).
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
        let registry = ProxyRegistry::open(&pc.registry_path)
            .with_context(|| format!("proxy registry {}", pc.registry_path.display()))?;
        tracing::info!(
            ca_subject = %ca.subject_dn,
            registry = %pc.registry_path.display(),
            "proxy routes enabled (GET /v1/proxy-config placeholder)"
        );
        Ok(Some(ProxyContext { ca, registry }))
    }
}
