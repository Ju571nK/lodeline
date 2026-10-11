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
use parking_lot::Mutex;
use registry::ProxyRegistry;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
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
    /// Last failed promotion attempt per proxy_id (retry at most once a minute).
    promote_backoff: Mutex<HashMap<String, Instant>>,
    /// Auth-denial audit coalescing, per (caller fingerprint, reason).
    deny_gate: Mutex<HashMap<(String, String), (Instant, u32)>>,
    /// Rate limiter for the "probe with a bearer" warning.
    probe_warn: Mutex<(Option<Instant>, u32)>,
}

/// One audited auth denial per caller and reason per window, with a count.
const DENY_AUDIT_WINDOW: Duration = Duration::from_secs(60);
const PROMOTE_RETRY: Duration = Duration::from_secs(60);
const PROBE_WARN_WINDOW: Duration = Duration::from_secs(60);

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
            promote_backoff: Mutex::new(HashMap::new()),
            deny_gate: Mutex::new(HashMap::new()),
            probe_warn: Mutex::new((None, 0)),
        }))
    }

    /// Decide whether an auth denial gets its own audit record now. `Some(n)`:
    /// write one record standing for `n` denials, then call
    /// [`Self::deny_audited`]. `None`: coalesced into the next record.
    pub fn deny_check(&self, caller_fp: &str, reason: &str) -> Option<u32> {
        let mut g = self.deny_gate.lock();
        let e = g.entry((caller_fp.to_string(), reason.to_string()));
        match e {
            std::collections::hash_map::Entry::Vacant(_) => Some(1),
            std::collections::hash_map::Entry::Occupied(mut o) => {
                let (last, suppressed) = o.get_mut();
                if last.elapsed() >= DENY_AUDIT_WINDOW {
                    Some(*suppressed + 1)
                } else {
                    *suppressed += 1;
                    None
                }
            }
        }
    }

    /// The record for `deny_check` was written: restart the window.
    pub fn deny_audited(&self, caller_fp: &str, reason: &str) {
        self.deny_gate.lock().insert(
            (caller_fp.to_string(), reason.to_string()),
            (Instant::now(), 0),
        );
    }

    /// A request with a bearer reached the management path without a usable
    /// management cert (or while the verifier file is broken). Not audited (no
    /// fsync per probe); one rate-limited warning with a count instead.
    pub fn note_probe(&self, why: &str) {
        let mut g = self.probe_warn.lock();
        g.1 += 1;
        if g.0.is_none_or(|t| t.elapsed() >= PROBE_WARN_WINDOW) {
            tracing::warn!(
                why,
                count = g.1,
                "management route probed with a bearer; answered 404"
            );
            *g = (Some(Instant::now()), 0);
        }
    }

    /// Rotation rule (control-plane §1.3): the first request authenticated with
    /// `fp_next` promotes it to `fp_current` and drops the old fingerprint.
    /// Same shape as a management write: begin, re-validate, audit, persist,
    /// swap. Blocking. If the audit or the persist fails nothing changes (the
    /// old fingerprint stays valid), the failure is logged at error level and
    /// the next attempt for this proxy waits at least a minute.
    pub fn promote_blocking(&self, proxy_id: &str, fp: &str) {
        use audit::AuditEntry;
        let Some(audit) = self.audit.as_ref() else {
            return;
        };
        if self
            .promote_backoff
            .lock()
            .get(proxy_id)
            .is_some_and(|t| t.elapsed() < PROMOTE_RETRY)
        {
            return;
        }
        let txn = self.registry.begin();
        let Some(cur) = txn.get(proxy_id) else {
            return;
        };
        if cur.state != registry::ProxyState::Active
            || cur.fp_next.as_deref() != Some(fp)
            || cur.fp_current.as_deref() == Some(fp)
        {
            return;
        }
        let now = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let mut new = cur.clone();
        new.fp_current = new.fp_next.take();
        new.updated_at = now;
        let entry = AuditEntry {
            request_id: uuid::Uuid::now_v7().to_string(),
            action: "proxy.fingerprint_promote".into(),
            proxy_id: proxy_id.into(),
            result: "ok".into(),
            http_status: 200,
            reason: Some("first_use_of_next".into()),
            from_state: Some("active".into()),
            to_state: Some("active".into()),
            subject_fingerprint: Some(fp.into()),
            replaced_fingerprint: cur.fp_current.clone(),
            caller_fingerprint: fp.into(),
            ..Default::default()
        };
        let backoff = || {
            self.promote_backoff
                .lock()
                .insert(proxy_id.to_string(), Instant::now());
        };
        if let Err(e) = audit.append(entry.clone()) {
            tracing::error!(error = %e, proxy_id, "ALERT fingerprint promotion skipped: audit append failed; old fingerprint stays valid");
            backoff();
            return;
        }
        match txn.commit(new) {
            Ok(()) => {
                self.promote_backoff.lock().remove(proxy_id);
            }
            Err(e) => {
                tracing::error!(error = %e, proxy_id, "ALERT fingerprint promotion failed to persist; old fingerprint stays valid");
                let _ = audit.append(AuditEntry {
                    result: "persist_failed".into(),
                    http_status: 500,
                    ..entry
                });
                backoff();
            }
        }
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

/// Re-read the management verifier file on SIGHUP (fail closed on error).
/// Call from inside the runtime.
#[cfg(unix)]
pub fn spawn_sighup_reload(ctx: Arc<ProxyContext>) -> Result<()> {
    let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .context("install SIGHUP handler")?;
    tokio::spawn(async move {
        while hup.recv().await.is_some() {
            let ctx = ctx.clone();
            let _ = tokio::task::spawn_blocking(move || {
                if let Some(m) = ctx.mgmt.as_ref() {
                    m.reload();
                }
            })
            .await;
        }
    });
    Ok(())
}
