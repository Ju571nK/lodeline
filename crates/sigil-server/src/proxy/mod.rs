//! T-11 — Sigil Proxy server side (identity, registry, guard, management).
//! Isolated from the host paths and OFF unless `proxy:` is configured.
//!
//! Spec: PX-008/009/012/016, AC-04, AC-12, AC-13; control-plane.md §0.1, §1, §2,
//! §6. Slices S1 (identity, registry, guard), S2a (management auth, audit,
//! lifecycle routes, operator CLI) and S3 (config DTO, config PUT/GET, status
//! ingest). No event ingest/ledger (S4), no CSR signing (S2b).

pub mod audit;
pub mod cli;
pub mod config_api;
pub mod guard;
pub mod identity;
pub mod ledger;
pub mod lifecycle;
pub mod mgmt;
pub mod registry;
pub mod status;
pub mod store;
pub mod verifiers;

use crate::config::ServerConfig;
use crate::tls_accept::PeerIdentity;
use anyhow::{bail, Context, Result};
use audit::MgmtAudit;
use identity::{PeerClass, ProxyCaInfo};
use parking_lot::Mutex;
use registry::ProxyRegistry;
use std::collections::HashMap;
#[cfg(unix)]
use std::sync::Arc;
use std::time::{Duration, Instant};
use store::ProxyStore;
use verifiers::MgmtAuth;

/// Everything the proxy routes and the host-route guard need.
pub struct ProxyContext {
    pub ca: ProxyCaInfo,
    pub registry: ProxyRegistry,
    /// Latest config, status snapshot and gap records per proxy.
    pub store: ProxyStore,
    /// Event ledger (T-11 S4 B1): storage only, no route yet. Blocking API;
    /// call from `spawn_blocking`.
    pub ledger: ledger::Ledger,
    /// TTL stamped on every served config (seconds).
    pub config_ttl: u32,
    /// `ack_loss_margin` M (seconds) for the E >= R + M check.
    pub ack_loss_margin: u32,
    /// `Some` only when `proxy.management_verifiers` is configured. `None`
    /// means every management route and the audit read route are absent.
    pub mgmt: Option<MgmtAuth>,
    /// Signed management audit stream; present together with `mgmt`.
    pub audit: Option<MgmtAudit>,
    /// Last failed promotion attempt per proxy_id (retry at most once a minute).
    promote_backoff: Mutex<HashMap<String, Instant>>,
    /// Auth-denial audit coalescing, per (caller fingerprint, reason).
    deny_gate: Mutex<HashMap<(String, String), (Instant, u32)>>,
    /// Proxies whose state the boot cross-check found behind the audit and that
    /// `state_init` let through: proxy_id -> audited revision. Their config is
    /// withheld (GET answers `config_unavailable`) and the next PUT must name the
    /// audited revision as `expected_revision`. Cleared by that PUT.
    pub withheld: Mutex<HashMap<String, u64>>,
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
        let store = ProxyStore::open(&pc.state_path())
            .with_context(|| format!("proxy state {}", pc.state_path().display()))?;
        // Ledger L1 startup invariant T >= R + M, checked against every stored
        // config before the ledger file is created or opened.
        ledger::check_tombstone_invariant(
            i64::from(pc.dedup_tombstone_retention()),
            pc.ack_loss_margin(),
            store
                .configs()
                .iter()
                .map(|(id, c)| (id.as_str(), c.config.max_offline_retry_age_seconds))
                .collect::<Vec<_>>(),
        )?;
        let ledger =
            ledger::Ledger::open(&pc.ledger_path(), ledger::LedgerOptions::from_config(pc))
                .with_context(|| format!("proxy ledger {}", pc.ledger_path().display()))?;
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
        let withheld = match audit.as_ref() {
            Some(a) => check_store_against_audit(&store, a, pc.state_init)?,
            None => HashMap::new(),
        };
        for id in stale_retention(&store, pc.ack_loss_margin()) {
            tracing::warn!(
                proxy_id = %id,
                "stored config has event_retention_seconds < max_offline_retry_age_seconds + ack_loss_margin under the current proxy.ack_loss_margin_seconds; PUT a new config to restore the ledger L1 invariant"
            );
        }
        tracing::info!(
            ca_subject = %ca.subject_dn,
            registry = %pc.registry_path.display(),
            management = mgmt.is_some(),
            "proxy routes enabled"
        );
        Ok(Some(ProxyContext {
            ca,
            registry,
            store,
            ledger,
            config_ttl: pc.config_ttl(),
            ack_loss_margin: pc.ack_loss_margin(),
            mgmt,
            audit,
            withheld: Mutex::new(withheld),
            promote_backoff: Mutex::new(HashMap::new()),
            deny_gate: Mutex::new(HashMap::new()),
            probe_warn: Mutex::new((None, 0)),
        }))
    }

    /// Run the ledger retention sweep at `now` (unix seconds). Each proxy's
    /// event retention E is its stored config value, or the default when none
    /// is stored. Not scheduled yet: slice B2 owns the periodic call.
    pub fn ledger_sweep(&self, now: i64) -> Result<ledger::SweepStats, ledger::LedgerError> {
        self.ledger.sweep(now, &|id| {
            self.store.config(id).map_or(
                sigil_proxy_api::config::DEFAULT_EVENT_RETENTION_SECONDS,
                |c| c.config.event_retention_seconds,
            )
        })
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

/// Boot cross-check (S3): the management audit is written BEFORE the store, so
/// it may be ahead of the store (a crash between the two, a lost or restored
/// store file) but never legitimately behind it. For every proxy with an `ok`
/// `proxy.config_put` to revision R in the audit, the store must hold a config
/// with revision >= R. Otherwise boot is refused unless `state_init` is set,
/// which downgrades it to a loud warning and returns the proxies whose config
/// must then be withheld, with their audited revisions.
pub fn check_store_against_audit(
    store: &ProxyStore,
    audit: &MgmtAudit,
    state_init: bool,
) -> Result<HashMap<String, u64>> {
    let (records, _) = audit
        .read(0, usize::MAX)
        .context("read the management audit for the proxy state cross-check")?;
    let mut latest: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    for r in records {
        let r = r.record;
        if r.action == "proxy.config_put" && r.result == "ok" {
            if let Some(to) = r.to_revision {
                let e = latest.entry(r.proxy_id).or_insert(0);
                *e = (*e).max(to);
            }
        }
    }
    let mut withheld = HashMap::new();
    for (id, audited) in latest {
        let held = store.entry(&id).map_or(0, |e| e.revision());
        if held < audited {
            if !state_init {
                bail!(
                    "proxy state for {id} holds revision {held} but the management audit records a config PUT to revision {audited}; \
                     the state store is behind (lost, restored or a crash between audit and write). \
                     Refusing to start; set proxy.state_init: true for one boot to accept it"
                );
            }
            tracing::error!(
                proxy_id = %id, held, audited,
                "ALERT proxy state is behind the management audit; accepted because proxy.state_init is set; its config is withheld until a config is PUT with expected_revision = the audited revision"
            );
            withheld.insert(id, audited);
        }
    }
    Ok(withheld)
}

/// Proxies whose stored config breaks `E >= R + M` under the CURRENT
/// `ack_loss_margin` (the margin may have been raised since the PUT).
pub fn stale_retention(store: &ProxyStore, margin_secs: u32) -> Vec<String> {
    store
        .configs()
        .into_iter()
        .filter(|(_, c)| {
            c.config.event_retention_seconds
                < c.config.max_offline_retry_age_seconds + i64::from(margin_secs)
        })
        .map(|(id, _)| id)
        .collect()
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
