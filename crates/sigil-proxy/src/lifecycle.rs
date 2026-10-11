//! Process lifecycle and the local status file.
//!
//! No network exists yet (T-12). The config state is therefore only modelled:
//! a process that has not fetched a config from the server is never
//! `forwarding` (control-plane.md §6.3 "Restart", decision D-02 item 5).

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
    pub updated_at: String,
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
}

impl Lifecycle {
    pub fn start(b: &Bootstrap) -> Result<Lifecycle, StateError> {
        let state = StateDir::open(&b.state_dir, &b.proxy_id)?;
        let previous = if state.is_new_epoch() {
            None
        } else {
            read_status(state.dir())
        };
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
            updated_at: now_rfc3339(),
        };
        let mut lc = Lifecycle { state, status };
        lc.publish()?;
        Ok(lc)
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

/// `run` for T-10: no listener is opened (T-12 adds them). Take the lock,
/// publish status, wait for a signal, drain within the configured grace, stop.
pub async fn run(b: &Bootstrap) -> anyhow::Result<()> {
    let mut sig = ShutdownSignal::install()?;
    let mut lc = Lifecycle::start(b)?;
    tracing::info!(
        proxy_id = b.proxy_id.as_str(),
        epoch_id = lc.epoch_id(),
        config_state = ?lc.status().config_state,
        "sigil-proxy started (no listener in this build step; not forwarding)"
    );
    lc.set_run_state(RunState::Running)?;
    sig.wait().await;

    lc.set_run_state(RunState::Stopping)?;
    // NOTE: Signal handlers stay installed during drain, so a second SIGTERM is
    // swallowed and only SIGKILL ends the process. Fine under systemd
    // (TimeoutStopSec); revisit if an operator needs a second signal to force exit.
    // No in-flight calls exist yet; T-12 passes its drain future here.
    let outcome = drain(
        Duration::from_secs(b.limits.shutdown_grace_secs),
        std::future::ready(()),
    )
    .await;
    tracing::info!(?outcome, "shutdown");
    lc.set_run_state(RunState::Stopped)?;
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
}
