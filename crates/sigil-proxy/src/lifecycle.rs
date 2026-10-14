//! Process lifecycle and the local status file.
//!
//! The config state is published here; the control-plane fetch and apply live in
//! [`crate::config_sync`]. A process that has not fetched a config from the
//! server is never `forwarding` (control-plane.md §6.3 "Restart", decision D-02
//! item 5).

use std::future::Future;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sigil_proxy_api::status::{ConfigState, LastUpdateError};

use crate::bootstrap::Bootstrap;
use crate::state_dir::{lock_is_held, StateDir, StateError, STATUS_FILE};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Starting,
    Running,
    Stopping,
    Stopped,
}

/// Local view for `health`. Not the wire `ProxyStatus` (that needs spool,
/// registry and route sections owned by later tasks).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalStatus {
    pub schema_version: u32,
    pub proxy_id: String,
    pub epoch_id: String,
    pub pid: u32,
    pub run_state: RunState,
    pub config_state: ConfigState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_update_error: Option<LastUpdateError>,
    pub forwarding: bool,
    /// F1: the status sequence looks stuck below the server's stored one, so
    /// status snapshots are being ignored (see `status_report::WEDGE_THRESHOLD`).
    /// Absent (false) in the normal case.
    #[serde(default, skip_serializing_if = "is_false")]
    pub status_sequence_wedged: bool,
    pub updated_at: String,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Forwarding requires a valid applied config and a running process. Nothing
/// else ever yields true.
pub fn forwarding_allowed(run_state: RunState, config_state: ConfigState) -> bool {
    run_state == RunState::Running && config_state == ConfigState::Valid
}

/// Config state at process start, given the previous status of the same epoch.
///
/// The monotonic deadline of an earlier run does not survive a restart, so a
/// previously valid config is `expired` and never `valid` until a fresh fetch
/// succeeds (fail closed). `disabled` stays `disabled`.
pub fn startup_config_state(previous: Option<&LocalStatus>) -> ConfigState {
    match previous.map(|p| p.config_state) {
        None | Some(ConfigState::None) => ConfigState::None,
        Some(ConfigState::Valid) | Some(ConfigState::Expired) => ConfigState::Expired,
        Some(ConfigState::Disabled) => ConfigState::Disabled,
    }
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .expect("rfc3339 formats")
}

pub fn read_status(dir: &Path) -> Option<LocalStatus> {
    let bytes = std::fs::read(dir.join(STATUS_FILE)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// A started proxy process: owns the state_dir lock and the status file.
pub struct Lifecycle {
    state: StateDir,
    status: LocalStatus,
    applied: Option<crate::state_dir::AppliedMark>,
    sequence_bound: Option<i64>,
    gap_queue: Option<crate::state_dir::GapQueueState>,
}

impl Lifecycle {
    pub fn start(b: &Bootstrap) -> Result<Lifecycle, StateError> {
        let state = StateDir::open(&b.state_dir, &b.proxy_id)?;
        let previous = if state.is_new_epoch() {
            None
        } else {
            read_status(state.dir())
        };
        // A corrupt or foreign mark refuses the start (fail closed).
        let applied = state.read_applied()?;
        // A corrupt sequence file refuses the start too.
        let sequence_bound = state.read_sequence_bound()?;
        // A corrupt, unsafe or inconsistent gap queue refuses the start too: it
        // would otherwise silently forget gaps the server never acknowledged.
        let gap_queue = state.read_gap_queue()?;
        let config_state = startup_config_state(previous.as_ref());
        let status = LocalStatus {
            schema_version: 1,
            proxy_id: b.proxy_id.as_str().to_string(),
            epoch_id: state.epoch_id().to_string(),
            pid: std::process::id(),
            run_state: RunState::Starting,
            config_state,
            last_update_error: None,
            forwarding: false,
            status_sequence_wedged: false,
            updated_at: now_rfc3339(),
        };
        let mut lc = Lifecycle {
            state,
            status,
            applied,
            sequence_bound,
            gap_queue,
        };
        lc.publish()?;
        Ok(lc)
    }

    /// The revision high-water mark loaded at start.
    pub fn applied_mark(&self) -> Option<&crate::state_dir::AppliedMark> {
        self.applied.as_ref()
    }

    /// Upper bound of the status sequences sent in this epoch, loaded at start.
    pub fn sequence_bound(&self) -> Option<i64> {
        self.sequence_bound
    }

    /// The gap queue loaded at start (once).
    pub fn take_gap_queue(&mut self) -> Option<crate::state_dir::GapQueueState> {
        self.gap_queue.take()
    }

    /// Persist the gap queue (called by the queue after each change).
    pub fn persist_gap_queue(
        &mut self,
        q: &crate::state_dir::GapQueueState,
    ) -> Result<(), StateError> {
        self.state.write_gap_queue(q)
    }

    /// F1: publish whether the status sequence looks stuck.
    pub fn set_sequence_wedged(&mut self, wedged: bool) -> Result<(), StateError> {
        self.status.status_sequence_wedged = wedged;
        self.publish()
    }

    /// Persist a new status-sequence bound before sequences up to it are used.
    pub fn persist_sequence_bound(&mut self, bound: i64) -> Result<(), StateError> {
        self.state.write_sequence_bound(bound)?;
        self.sequence_bound = Some(bound);
        Ok(())
    }

    /// Persist the high-water mark of a revision about to be applied.
    pub fn persist_applied(&mut self, revision: i64, config_hash: &str) -> Result<(), StateError> {
        self.state.write_applied(revision, config_hash)
    }

    pub fn status(&self) -> &LocalStatus {
        &self.status
    }

    pub fn epoch_id(&self) -> &str {
        self.state.epoch_id()
    }

    fn publish(&mut self) -> Result<(), StateError> {
        self.status.forwarding =
            forwarding_allowed(self.status.run_state, self.status.config_state);
        self.status.updated_at = now_rfc3339();
        let bytes = serde_json::to_vec_pretty(&self.status).expect("status serializes");
        self.state.write_atomic(STATUS_FILE, &bytes)
    }

    pub fn set_run_state(&mut self, s: RunState) -> Result<(), StateError> {
        self.status.run_state = s;
        self.publish()
    }

    /// Publish the config state and last update error reported by the config
    /// sync. `forwarding` is recomputed by `publish`.
    pub fn set_config(&mut self, s: crate::config_sync::SyncStatus) -> Result<(), StateError> {
        self.status.config_state = s.config_state;
        self.status.last_update_error = s.last_update_error;
        self.publish()
    }

    /// Model of "server unreachable": the config state is unchanged (never
    /// promoted to valid) and the failure is recorded.
    pub fn note_fetch_failed(&mut self) -> Result<(), StateError> {
        self.status.last_update_error = Some(LastUpdateError::FetchFailed);
        self.publish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainOutcome {
    Drained,
    /// Grace elapsed; remaining calls are outcome-unknown and must be recovered
    /// from the audit trail.
    GraceExpired,
}

/// Wait for in-flight work to finish, at most `grace`.
pub async fn drain<F: Future<Output = ()>>(grace: Duration, inflight: F) -> DrainOutcome {
    match tokio::time::timeout(grace, inflight).await {
        Ok(()) => DrainOutcome::Drained,
        Err(_) => DrainOutcome::GraceExpired,
    }
}

/// SIGTERM/SIGINT handlers. Installed eagerly (before `running` is published)
/// so a signal sent right after start is never lost to the default action.
#[cfg(unix)]
pub struct ShutdownSignal {
    term: tokio::signal::unix::Signal,
    int: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl ShutdownSignal {
    pub fn install() -> std::io::Result<Self> {
        use tokio::signal::unix::{signal, SignalKind};
        Ok(Self {
            term: signal(SignalKind::terminate())?,
            int: signal(SignalKind::interrupt())?,
        })
    }

    pub async fn wait(&mut self) {
        tokio::select! {
            _ = self.term.recv() => {}
            _ = self.int.recv() => {}
        }
    }
}

#[cfg(not(unix))]
pub struct ShutdownSignal;

#[cfg(not(unix))]
impl ShutdownSignal {
    pub fn install() -> std::io::Result<Self> {
        Ok(Self)
    }

    pub async fn wait(&mut self) {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// `run`: take the lock, publish status, bind the downstream listener, start the
/// config sync, serve until a signal, drain within the configured grace, stop.
///
/// Until the first config is fetched and applied there is no route table, so the
/// listener answers 401 to everything and the status never reports `forwarding`.
pub async fn run(b: &Bootstrap) -> anyhow::Result<()> {
    run_with_table(b, crate::route::TableHandle::new()).await
}

fn lock(lc: &std::sync::Mutex<Lifecycle>) -> std::sync::MutexGuard<'_, Lifecycle> {
    lc.lock().unwrap_or_else(|e| e.into_inner())
}

/// Like [`run`], with a caller-provided table holder.
pub async fn run_with_table(b: &Bootstrap, table: crate::route::TableHandle) -> anyhow::Result<()> {
    let mut sig = ShutdownSignal::install()?;
    run_with_shutdown(b, table, async move { sig.wait().await }).await
}

/// Like [`run_with_table`], stopping when `shutdown` completes instead of on a
/// process signal (embedding and tests).
pub async fn run_with_shutdown(
    b: &Bootstrap,
    table: crate::route::TableHandle,
    shutdown: impl Future<Output = ()>,
) -> anyhow::Result<()> {
    run_inner(
        b,
        table,
        shutdown,
        crate::config_sync::SyncParams::default(),
        crate::status_report::ReporterParams::default(),
        None,
    )
    .await
}

/// Pacing and an optional pre-bound listener. TEST-ONLY (feature `test-util`, or
/// this crate's own tests): production callers never see it, and nothing reads it
/// from the environment or from `proxy.yaml`. It lets an integration test against
/// a real server observe a revision change within seconds and avoid a
/// bind-then-release port race.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug, Default)]
pub struct RunTuning {
    pub sync: crate::config_sync::SyncParams,
    pub report: crate::status_report::ReporterParams,
    /// Used instead of binding `Bootstrap::listen` (which is then ignored).
    pub listener: Option<std::net::TcpListener>,
}

/// [`run_with_shutdown`] with explicit pacing. Tests only.
#[cfg(any(test, feature = "test-util"))]
pub async fn run_tuned(
    b: &Bootstrap,
    table: crate::route::TableHandle,
    shutdown: impl Future<Output = ()>,
    tuning: RunTuning,
) -> anyhow::Result<()> {
    run_inner(
        b,
        table,
        shutdown,
        tuning.sync,
        tuning.report,
        tuning.listener,
    )
    .await
}

async fn run_inner(
    b: &Bootstrap,
    table: crate::route::TableHandle,
    shutdown: impl Future<Output = ()>,
    sync_params: crate::config_sync::SyncParams,
    report_params: crate::status_report::ReporterParams,
    pre_bound: Option<std::net::TcpListener>,
) -> anyhow::Result<()> {
    let mut lc = Lifecycle::start(b)?;
    let initial = lc.status().config_state;
    let mark = lc.applied_mark().cloned();
    let seq_floor = lc.sequence_bound();
    let saved_gaps = lc.take_gap_queue();
    let lc = std::sync::Arc::new(std::sync::Mutex::new(lc));
    let acceptor = match &b.listener_tls {
        Some(t) => Some(crate::tls::load_acceptor(&t.cert_file, &t.key_file)?),
        None => None,
    };
    // Fail before publishing `running` if the address cannot be bound.
    let listener = match pre_bound {
        Some(l) => {
            l.set_nonblocking(true)?;
            tokio::net::TcpListener::from_std(l)?
        }
        None => tokio::net::TcpListener::bind(b.listen).await?,
    };
    tracing::info!(
        proxy_id = b.proxy_id.as_str(),
        epoch_id = lock(&lc).epoch_id(),
        config_state = ?initial,
        listen = %listener.local_addr()?,
        tls = acceptor.is_some(),
        "sigil-proxy listening (no applied config: every request is 401)"
    );
    lock(&lc).set_run_state(RunState::Running)?;

    // Config sync: fetch over mTLS, apply, keep the TTL deadline.
    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
    let mut report_task = None;
    let sync_task =
        match crate::config_sync::MtlsFetcher::from_bootstrap(b) {
            Some(fetcher) => {
                // One mTLS client serves the config fetch and the status report.
                let fetcher = std::sync::Arc::new(fetcher);
                let lc2 = lc.clone();
                let lc4 = lc.clone();
                let mut sync = crate::config_sync::ConfigSync::new(
                    b.proxy_id.as_str(),
                    b.credentials.clone(),
                    b.limits.clone(),
                    table.clone(),
                    initial,
                )
                .with_persister(Box::new(move |rev, hash| {
                    match lock(&lc4).persist_applied(rev, hash) {
                        Ok(()) => true,
                        Err(e) => {
                            tracing::error!(error = %e, "cannot persist the applied revision");
                            false
                        }
                    }
                }));
                if let Some(m) = mark {
                    sync = sync.with_high_water(m.revision, m.config_hash);
                }
                // Status report and heartbeat (T-12c2): follows the config view.
                let (sync, view_rx) = sync.with_view_channel();
                let lc5 = lc.clone();
                let epoch = lock(&lc).epoch_id().to_string();
                // Durable gap queue (L6b): reloaded from state_dir, written after
                // every change. No producer exists yet (relay events are
                // T-13/T-14), so it only holds what a previous run left.
                let lc6 = lc.clone();
                let gaps = saved_gaps
                    .map(crate::status_report::GapQueue::restore)
                    .unwrap_or_default()
                    .with_persister(Box::new(move |q| match lock(&lc6).persist_gap_queue(q) {
                        Ok(()) => true,
                        Err(e) => {
                            tracing::error!(error = %e, "cannot persist the gap queue");
                            false
                        }
                    }));
                let lc7 = lc.clone();
                let reporter = crate::status_report::Reporter::new(
                b.proxy_id.as_str(),
                &epoch,
                gaps,
                report_params,
            )
            .with_central(crate::status_report::CentralHealth::new())
            .with_wedge_hook(Box::new(move |w| {
                if let Err(e) = lock(&lc7).set_sequence_wedged(w) {
                    tracing::error!(error = %e, "cannot publish the sequence state");
                }
            }))
            .with_sequence_persistence(
                seq_floor,
                Box::new(move |bound| match lock(&lc5).persist_sequence_bound(bound) {
                    Ok(()) => true,
                    Err(e) => {
                        tracing::error!(error = %e, "cannot persist the status sequence bound");
                        false
                    }
                }),
            );
                let (report_fetcher, mut report_stop) = (fetcher.clone(), stop_rx.clone());
                report_task = Some(tokio::spawn(async move {
                    crate::status_report::run_status_reporter(
                        &*report_fetcher,
                        reporter,
                        view_rx,
                        async move {
                            let _ = report_stop.wait_for(|v| *v).await;
                        },
                    )
                    .await;
                }));
                Some(tokio::spawn(async move {
                    crate::config_sync::run_sync(
                        sync,
                        &*fetcher,
                        sync_params,
                        |s| {
                            if let Err(e) = lock(&lc2).set_config(s) {
                                tracing::error!(error = %e, "cannot publish config status");
                            }
                        },
                        async move {
                            let _ = stop_rx.wait_for(|v| *v).await;
                        },
                    )
                    .await;
                }))
            }
            None => {
                tracing::error!("control_plane_url unusable: no config will be fetched");
                None
            }
        };

    let proxy = crate::server::Proxy::new(
        b.limits.clone(),
        table,
        std::sync::Arc::new(crate::dest::SystemResolver),
    );
    let lc3 = lc.clone();
    let served = proxy
        .serve(listener, acceptor, async {
            shutdown.await;
            let _ = lock(&lc3).set_run_state(RunState::Stopping);
        })
        .await;
    // NOTE: Signal handlers stay installed during drain, so a second SIGTERM is
    // swallowed and only SIGKILL ends the process. Fine under systemd
    // (TimeoutStopSec); revisit if an operator needs a second signal to force exit.
    let _ = stop_tx.send(true);
    if let Some(t) = sync_task {
        let _ = t.await;
    }
    if let Some(t) = report_task {
        let _ = t.await;
    }
    let outcome = served?;
    tracing::info!(?outcome, "shutdown");
    lock(&lc).set_run_state(RunState::Stopped)?;
    Ok(())
}

/// Result of `health`: read-only, opens no listener and creates nothing.
#[derive(Debug, PartialEq, Eq)]
pub struct Health {
    pub alive: bool,
    pub status: Option<LocalStatus>,
}

pub fn health(state_dir: &Path) -> Health {
    let alive = lock_is_held(state_dir);
    Health {
        alive,
        status: read_status(state_dir).map(|mut s| {
            // Never trust a stored flag: recompute.
            s.forwarding = alive && forwarding_allowed(s.run_state, s.config_state);
            s
        }),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use sigil_proxy_api::Id;

    fn bootstrap(dir: &Path) -> Bootstrap {
        Bootstrap {
            proxy_id: Id::new("px-1").unwrap(),
            listen: "127.0.0.1:8480".parse().unwrap(),
            listener_tls: None,
            control_plane_url: "https://s.example".into(),
            state_dir: dir.join("st"),
            client_cert_file: dir.join("c"),
            client_key_file: dir.join("k"),
            ca_file: dir.join("ca"),
            limits: Default::default(),
            credentials: Default::default(),
        }
    }

    /// AC-12: restart with an unreachable server never reports forwarding;
    /// a previously valid config comes back as expired.
    #[test]
    fn restart_is_fail_closed() {
        let t = tempfile::tempdir().unwrap();
        let b = bootstrap(t.path());
        {
            let mut lc = Lifecycle::start(&b).unwrap();
            assert_eq!(lc.status().config_state, ConfigState::None);
            lc.set_run_state(RunState::Running).unwrap();
            // Simulate a prior run that had applied a valid config.
            lc.status.config_state = ConfigState::Valid;
            lc.publish().unwrap();
            assert!(lc.status().forwarding);
        }
        let mut lc = Lifecycle::start(&b).unwrap();
        assert_eq!(lc.status().config_state, ConfigState::Expired);
        assert!(!lc.status().forwarding);
        lc.set_run_state(RunState::Running).unwrap();
        lc.note_fetch_failed().unwrap();
        let s = read_status(&b.state_dir).unwrap();
        assert_eq!(s.config_state, ConfigState::Expired);
        assert_eq!(s.last_update_error, Some(LastUpdateError::FetchFailed));
        assert!(!s.forwarding);
        // another restart keeps expired, never valid
        drop(lc);
        let lc = Lifecycle::start(&b).unwrap();
        assert_eq!(lc.status().config_state, ConfigState::Expired);
    }

    #[test]
    fn startup_state_table() {
        let mk = |c| LocalStatus {
            schema_version: 1,
            proxy_id: "p".into(),
            epoch_id: "e".into(),
            pid: 1,
            run_state: RunState::Stopped,
            config_state: c,
            last_update_error: None,
            forwarding: false,
            status_sequence_wedged: false,
            updated_at: String::new(),
        };
        assert_eq!(startup_config_state(None), ConfigState::None);
        for (prev, want) in [
            (ConfigState::None, ConfigState::None),
            (ConfigState::Valid, ConfigState::Expired),
            (ConfigState::Expired, ConfigState::Expired),
            (ConfigState::Disabled, ConfigState::Disabled),
        ] {
            assert_eq!(startup_config_state(Some(&mk(prev))), want);
        }
        assert!(!forwarding_allowed(RunState::Running, ConfigState::None));
        assert!(!forwarding_allowed(RunState::Running, ConfigState::Expired));
        assert!(!forwarding_allowed(RunState::Stopping, ConfigState::Valid));
        assert!(forwarding_allowed(RunState::Running, ConfigState::Valid));
    }

    /// A lost state_dir means a new epoch and a clean `none` config state.
    #[test]
    fn new_epoch_ignores_old_status() {
        let t = tempfile::tempdir().unwrap();
        let b = bootstrap(t.path());
        {
            let mut lc = Lifecycle::start(&b).unwrap();
            lc.status.config_state = ConfigState::Valid;
            lc.publish().unwrap();
        }
        std::fs::remove_file(b.state_dir.join(crate::state_dir::BINDING_FILE)).unwrap();
        let lc = Lifecycle::start(&b).unwrap();
        assert_eq!(lc.status().config_state, ConfigState::None);
    }

    #[test]
    fn health_reads_status_without_creating_anything() {
        let t = tempfile::tempdir().unwrap();
        let b = bootstrap(t.path());
        // never started: nothing exists, health must not create it
        let h = health(&b.state_dir);
        assert!(!h.alive && h.status.is_none());
        assert!(!b.state_dir.exists());

        let mut lc = Lifecycle::start(&b).unwrap();
        lc.set_run_state(RunState::Running).unwrap();
        let h = health(&b.state_dir);
        assert!(h.alive);
        let s = h.status.unwrap();
        assert_eq!(s.run_state, RunState::Running);
        assert!(!s.forwarding);
        drop(lc);
        assert!(!health(&b.state_dir).alive);
    }

    /// PX-013: grace bounds the drain.
    #[tokio::test]
    async fn drain_respects_grace() {
        let o = drain(Duration::from_millis(500), async {}).await;
        assert_eq!(o, DrainOutcome::Drained);
        let o = drain(Duration::from_millis(30), std::future::pending::<()>()).await;
        assert_eq!(o, DrainOutcome::GraceExpired);
    }

    /// A corrupt revision mark refuses the start; a missing one is a first start.
    #[test]
    fn corrupt_applied_mark_refuses_start() {
        let t = tempfile::tempdir().unwrap();
        let b = bootstrap(t.path());
        {
            let lc = Lifecycle::start(&b).unwrap();
            assert!(lc.applied_mark().is_none(), "missing file is a first start");
        }
        let p = b.state_dir.join(crate::state_dir::APPLIED_FILE);
        std::fs::write(&p, "garbage").unwrap();
        std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        let e = Lifecycle::start(&b).err().expect("must refuse");
        assert!(matches!(e, StateError::BadAppliedRevision(_)), "{e}");
    }

    /// A corrupt sequence file refuses the start, like a corrupt applied mark.
    #[test]
    fn corrupt_sequence_file_refuses_start() {
        let t = tempfile::tempdir().unwrap();
        let b = bootstrap(t.path());
        {
            let lc = Lifecycle::start(&b).unwrap();
            assert!(lc.sequence_bound().is_none());
        }
        let p = b.state_dir.join(crate::state_dir::SEQUENCE_FILE);
        std::fs::write(&p, "garbage").unwrap();
        std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        let e = Lifecycle::start(&b).err().expect("must refuse");
        assert!(matches!(e, StateError::BadSequence(_)), "{e}");
    }

    fn lc_gap(n: u32) -> sigil_proxy_api::GapReport {
        serde_json::from_value(serde_json::json!({
            "kind": "event_quarantined",
            "gap_id": format!("00000000-0000-4000-8000-{n:012x}"),
            "detected_at": "2026-10-11T00:00:00Z",
            "event_ids": ["00000000-0000-4000-8000-000000000900"],
            "code": "semantic_invalid"}))
        .unwrap()
    }

    /// L6b: unacknowledged gaps (pending and quarantined) survive a restart.
    #[test]
    fn gap_queue_survives_a_restart() {
        use crate::status_report::{GapQueue, ReportOutcome};
        let t = tempfile::tempdir().unwrap();
        let b = bootstrap(t.path());
        let uid = |n: u32| format!("00000000-0000-4000-8000-{n:012x}");
        {
            let mut lc = Lifecycle::start(&b).unwrap();
            assert!(lc.take_gap_queue().is_none(), "first start");
            let lc = std::sync::Arc::new(std::sync::Mutex::new(lc));
            let lc2 = lc.clone();
            let q = GapQueue::new().with_persister(Box::new(move |s| {
                lc2.lock().unwrap().persist_gap_queue(s).is_ok()
            }));
            for n in 1..=3 {
                q.push(lc_gap(n)).unwrap();
            }
            q.settle(&ReportOutcome::Conflict { gaps: vec![uid(2)] });
        }
        let mut lc = Lifecycle::start(&b).unwrap();
        let q = GapQueue::restore(lc.take_gap_queue().expect("queue loaded"));
        assert_eq!(q.pending_ids(), vec![uid(1), uid(3)]);
        assert_eq!(q.quarantined_ids(), vec![uid(2)]);
    }

    /// A corrupt gap queue refuses the start, like a corrupt applied mark.
    #[test]
    fn corrupt_gap_queue_refuses_start() {
        let t = tempfile::tempdir().unwrap();
        let b = bootstrap(t.path());
        drop(Lifecycle::start(&b).unwrap());
        let p = b.state_dir.join(crate::state_dir::GAP_QUEUE_FILE);
        std::fs::write(&p, "garbage").unwrap();
        std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        let e = Lifecycle::start(&b).err().expect("must refuse");
        assert!(matches!(e, StateError::BadGapQueue(_)), "{e}");
        // unsafe permissions refuse too
        std::fs::write(&p, "{}").unwrap();
        std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o644)).unwrap();
        assert!(Lifecycle::start(&b).is_err());
    }

    /// F1: the wedge flag reaches the local status file and clears.
    #[test]
    fn sequence_wedge_is_shown_in_the_local_status() {
        let t = tempfile::tempdir().unwrap();
        let b = bootstrap(t.path());
        let mut lc = Lifecycle::start(&b).unwrap();
        assert!(!read_status(&b.state_dir).unwrap().status_sequence_wedged);
        lc.set_sequence_wedged(true).unwrap();
        assert!(read_status(&b.state_dir).unwrap().status_sequence_wedged);
        lc.set_sequence_wedged(false).unwrap();
        let s = std::fs::read_to_string(b.state_dir.join(STATUS_FILE)).unwrap();
        assert!(!s.contains("wedged"), "absent when false");
    }
}
