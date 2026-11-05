//! Phase 3b.1 — ai_guard_task orchestration.
//!
//! Trigger model:
//! - **Boot**: every parser runs once, force-emit even if score is 0.
//! - **File change**: hasher broadcasts each canonical path it just hashed;
//!   matching parser re-evaluates and emits if the reasons or controls hash
//!   changed. NOTE: the hasher only emits paths it processed, which means
//!   only paths covered by an active policy target. The baseline OSS policy
//!   (lodeline-rules-basic) includes `~/.claude/` and `~/.codex/`, so this
//!   trigger works out-of-box. If an operator removes those targets from
//!   their custom policy, this task falls back to heartbeat-only.
//! - **Heartbeat** (24h): every parser re-evaluates and force-emits. Provides
//!   liveness regardless of whether file-change events flow.
//!
//! A failed assessment sends `ai_guard_assess_failed`, never the last reading.
//! It is sent on the first failure, when the error kind or path changes, and
//! on each heartbeat while the source keeps failing (#333).

use crate::ai_guard::parser::{AiGuardParser, AssessError};
use crate::ai_guard::rubric;
use crate::state_task::CommittableEvent;
use lodeline_core::event::{
    AiGuardBucket, AiGuardScope, AiTool, Event, Evidence, Severity, SourceKind, Subject,
    AGENT_VERSION, SCHEMA_VERSION,
};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::{broadcast, mpsc, watch};

/// Shared state map keyed by `(tool, scope, pack_id, user)`. Persists between
/// calls so `eval_and_maybe_emit` can deduplicate identical reason sets across
/// triggers. The `pack_id` dimension ensures two parsers sharing the same
/// (tool, scope) but belonging to different rule packs never collide; `user`
/// does the same for one parser assessed against several homes (#329).
/// Read by the operator IPC handler (Task 7) for `lodeline show risk`.
pub type StateMap = HashMap<StateKey, SourceState>;
pub type StateKey = (AiTool, AiGuardScope, Option<String>, Option<String>);

/// A home a home-relative parser is assessed against. `user: None` is the
/// agent's own home (`TaskCtx::home_dir`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AssessHome {
    pub user: Option<String>,
    pub dir: PathBuf,
}

/// #333 — one spelling per home (`/home -> /var/home`), so a home is assessed,
/// and its external scripts attributed, under one path.
pub(crate) fn canonical_home(dir: &std::path::Path) -> PathBuf {
    dunce::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf())
}

/// One source in `StateMap`. An entry exists once the source was assessed or
/// failed, so at least one field is set.
#[derive(Clone, Debug, Default)]
pub struct SourceState {
    /// The last good reading, kept while the source fails.
    pub reading: Option<CachedAssessment>,
    /// Set while assessment fails; a good assessment clears it.
    pub failure: Option<AssessFailure>,
}

/// #333 — the failure last reported for a source.
#[derive(Clone, Debug)]
pub struct AssessFailure {
    /// The first failure since the agent started; stable until a good reading.
    pub since: OffsetDateTime,
    pub error_kind: &'static str,
    pub path: PathBuf,
}

/// One parser's last emitted state, kept in `StateMap` for change-detection
/// and IPC introspection. Both hashes participate in emission change detection.
#[derive(Clone, Debug)]
pub struct CachedAssessment {
    pub controls: Option<Vec<lodeline_core::event::AiGuardControl>>,
    pub controls_blake3: [u8; 32],
    pub score: f32,
    pub bucket: AiGuardBucket,
    pub reasons_blake3: [u8; 32],
    pub reasons_count: usize,
    pub last_assessed_ts: OffsetDateTime,
    /// #147 — the dangerous-toggle kinds present at this assessment. Compared
    /// against the next assessment's set to detect OFF→ON transitions (drift).
    pub dangerous_toggles: std::collections::BTreeSet<String>,
}

/// Bundle of shared dependencies the task needs at construction. Built once
/// in `runtime::run` and consumed by `ai_guard::task::run`.
pub struct TaskCtx {
    /// Storage is `Arc<dyn ..>` (not `Box<dyn ..>`) so the dispatcher can
    /// snapshot-clone the vec before dropping the read guard and entering
    /// an await — parking_lot RwLockReadGuard isn't Send across `.await`.
    /// Phase 3b.6.1 — policy_reload mutates this list to add/remove
    /// `ContinueDevProjectParser` instances as `continue_workspaces` changes.
    pub parsers: Arc<RwLock<Vec<Arc<dyn AiGuardParser>>>>,
    pub fc_rx: broadcast::Receiver<PathBuf>,
    pub event_tx: mpsc::Sender<CommittableEvent>,
    pub state: Arc<RwLock<StateMap>>,
    pub heartbeat_interval: Duration,
    pub home_dir: PathBuf,
    /// #329 — other users' homes a root agent also assesses. Empty when the
    /// agent runs as a normal user, which then sees only `home_dir`.
    pub user_homes: Vec<AssessHome>,
    /// #333 — the re-enumerated user set. Each new value replaces `user_homes`.
    pub users_rx: watch::Receiver<Vec<AssessHome>>,
    pub host_id: String,
    /// Phase 3b.3 — shared registry of external hook-script paths per parser
    /// (tool, scope). Populated by runtime/reload; read by the dispatch loop
    /// to route fsnotify events on script paths.
    pub ext_scripts: crate::ai_guard::ExtScriptRegistry,
    /// Phase 3b.5 — shared rubric (operator-tunable weights). Snapshot-
    /// cloned on each assess cycle before any await; rebuilt + swapped
    /// by policy_reload_task on envelope changes.
    pub rubric: crate::ai_guard::RubricHandle,
}

/// Main task loop. Boots, then selects between file-change broadcasts and
/// the heartbeat tick until the broadcast sender is dropped (shutdown).
pub async fn run(mut ctx: TaskCtx) {
    // #333 — so `homes_for` does not assess the agent's own home a second time
    // under a user's name.
    ctx.home_dir = canonical_home(&ctx.home_dir);
    for home in &mut ctx.user_homes {
        home.dir = canonical_home(&home.dir);
    }
    let mut users_open = true;
    // 1. Initial scan on boot. Snapshot-clone the parsers vec before any
    //    `.await` so the parking_lot RwLockReadGuard is dropped — guards are
    //    NOT Send across an await. Cloning a `Vec<Arc<dyn>>` just bumps each
    //    Arc refcount, so this is cheap.
    {
        let snapshot: Vec<Arc<dyn AiGuardParser>> = ctx.parsers.read().clone();
        for parser in &snapshot {
            for home in homes_for(parser.as_ref(), &ctx) {
                eval_and_maybe_emit(parser.as_ref(), &ctx, &home, true).await;
            }
        }
    }

    let mut heartbeat = tokio::time::interval(ctx.heartbeat_interval);
    heartbeat.tick().await; // skip the immediate first tick.

    loop {
        tokio::select! {
            recv = ctx.fc_rx.recv() => {
                match recv {
                    Ok(path) => {
                        // Snapshot per cycle so reload mutations between cycles take effect.
                        // Clone the ext-script HashMap once so the parking_lot read guard is
                        // dropped before any `.await` — guards are NOT Send across await.
                        let snapshot: Vec<Arc<dyn AiGuardParser>> = ctx.parsers.read().clone();
                        let ext_map = ctx.ext_scripts.read().clone();
                        for parser in &snapshot {
                            let scripts = ext_map.get(&(parser.tool(), parser.scope()));
                            for home in homes_for(parser.as_ref(), &ctx) {
                                let in_watched = parser
                                    .watched_paths(&home.dir)
                                    .iter()
                                    .any(|p| path_matches(&path, p));
                                let in_ext_script = scripts.is_some_and(|v| {
                                    v.iter().any(|(h, p)| *h == home.dir && path_matches(&path, p))
                                });
                                if in_watched || in_ext_script {
                                    eval_and_maybe_emit(parser.as_ref(), &ctx, &home, false).await;
                                }
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(skipped = n, "ai_guard fc_rx lagged");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        // Sender dropped — runtime shutting down.
                        return;
                    }
                }
            }
            _ = heartbeat.tick() => {
                let snapshot: Vec<Arc<dyn AiGuardParser>> = ctx.parsers.read().clone();
                for parser in &snapshot {
                    for home in homes_for(parser.as_ref(), &ctx) {
                        eval_and_maybe_emit(parser.as_ref(), &ctx, &home, true).await;
                    }
                }
            }
            changed = ctx.users_rx.changed(), if users_open => {
                if changed.is_err() {
                    users_open = false;
                    continue;
                }
                let next = ctx.users_rx.borrow_and_update().clone();
                set_user_homes(&mut ctx, next).await;
            }
        }
    }
}

/// #333 — swap in a re-enumerated user set. A removed user's readings leave the
/// state map, so no heartbeat re-sends them and the server's copy expires. An
/// added user is assessed now, not at the next heartbeat.
async fn set_user_homes(ctx: &mut TaskCtx, mut next: Vec<AssessHome>) {
    for home in &mut next {
        home.dir = canonical_home(&home.dir);
    }
    let old = std::mem::replace(&mut ctx.user_homes, next);
    ctx.state.write().retain(|key, _| {
        key.3
            .as_ref()
            .is_none_or(|user| ctx.user_homes.iter().any(|h| h.user.as_ref() == Some(user)))
    });
    let snapshot: Vec<Arc<dyn AiGuardParser>> = ctx.parsers.read().clone();
    for parser in &snapshot {
        for home in homes_for(parser.as_ref(), ctx) {
            if !old.contains(&home) && home.user.is_some() {
                eval_and_maybe_emit(parser.as_ref(), ctx, &home, true).await;
            }
        }
    }
}

/// Match an incoming change path against a watched path/dir. A watched dir
/// matches any path inside it; a watched file matches by exact equality.
///
/// Incoming paths are canonical. Resolve the watched prefix too, including
/// macOS /etc -> /private/etc and missing policy leaves under existing parents.
fn path_matches(incoming: &std::path::Path, watched: &std::path::Path) -> bool {
    if incoming.starts_with(watched) {
        return true;
    }
    let watched = crate::normalizer::canonicalize_glob_prefix(watched);
    if incoming == watched {
        return true;
    }
    incoming.starts_with(&watched)
}

/// The homes `parser` is assessed against: its project root needs only the
/// agent's own home, while user-level and application parsers also run once
/// per entry in `ctx.user_homes`.
fn homes_for(parser: &dyn AiGuardParser, ctx: &TaskCtx) -> Vec<AssessHome> {
    let own = AssessHome {
        user: None,
        dir: ctx.home_dir.clone(),
    };
    if matches!(parser.scope(), AiGuardScope::Project { .. }) {
        return vec![own];
    }
    std::iter::once(own)
        .chain(
            ctx.user_homes
                .iter()
                .filter(|h| h.dir != ctx.home_dir)
                .cloned(),
        )
        .collect()
}

async fn eval_and_maybe_emit(
    parser: &dyn AiGuardParser,
    ctx: &TaskCtx,
    home: &AssessHome,
    force_emit: bool,
) {
    let key = (
        parser.tool(),
        parser.scope(),
        parser.rule_pack_id().map(|s| s.to_string()),
        home.user.clone(),
    );
    let mut assessment = match parser.assess_posture(&home.dir) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = ?e, tool = ?parser.tool(), "ai_guard assess failed");
            report_failure(parser, ctx, &key, &e, force_emit).await;
            return;
        }
    };
    assessment.normalize();
    let controls_hash = assessment.controls_hash();
    let reasons = assessment.reasons;
    let controls = assessment.controls;
    // Phase 3b.5 — snapshot-clone the Rubric BEFORE any subsequent await.
    // Cheap: weights is a small HashMap.
    let rubric_snapshot = ctx.rubric.read().clone();
    let score = rubric_snapshot.score(&reasons);
    let bucket = rubric::bucket(score);
    let reasons_hash = rubric::canonical_hash(&reasons);
    let SourceState {
        reading: prev,
        failure,
    } = ctx.state.read().get(&key).cloned().unwrap_or_default();
    // A recovery always emits, so the server clears the unassessed mark now
    // and not at the next heartbeat.
    let changed = failure.is_some()
        || prev
            .as_ref()
            .map(|p| p.reasons_blake3 != reasons_hash || p.controls_blake3 != controls_hash)
            .unwrap_or(true);
    if !changed && !force_emit {
        return;
    }
    let now = OffsetDateTime::now_utc();
    // Reattestation iff this emit is force-driven AND reasons and controls are
    // unchanged from the previous one and no failure came between. Boot (no
    // prior state) is NOT a reattestation even though it's force-emitted.
    let is_reattestation = force_emit && prev.is_some() && !changed;

    // #147 — dangerous-toggle drift. A toggle is "dangerous" iff its reason
    // kind is in DANGEROUS_TOGGLE_KINDS. We compare the current set against the
    // previous cached set and emit a one-time event for each toggle that
    // appeared (OFF→ON). The standing state still rides the normal
    // AiGuardRiskAssessed reasons; this is an ADDITIONAL change event.
    //
    // MVP limitations (codex-review, all P2, none a current bug):
    //  1. Baseline is keyed by the full StateMap key (tool, scope, rule_pack_id),
    //     so a toggle first seen under a *renamed* rule pack id is baselined (no
    //     drift) — consistent with how every assessment is keyed. Built-in
    //     toggles (rule_pack_id = None) are unaffected.
    //  2. The prev-read / new-write below are not one atomic critical section.
    //     Safe today because the eval loop is serialized per key; if parser eval
    //     ever runs concurrently for the same key, fold read+compare+write into a
    //     single `state.write()` to avoid a double-fire.
    //  3. The cache advances before the drift send, so a send that fails during
    //     shutdown drops that one alert (at-most-once). The standing reason still
    //     re-establishes posture, so nothing about *state* is lost.
    let new_toggles: std::collections::BTreeSet<String> = rubric::dangerous_toggles(&reasons)
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    // Only fire when there is a PREVIOUS cached assessment for this key. The
    // first/boot assessment merely establishes the baseline, so a daemon
    // restart with a toggle already on never false-fires.
    let appeared: Vec<String> = match prev.as_ref() {
        Some(p) => new_toggles
            .difference(&p.dangerous_toggles)
            .cloned()
            .collect(),
        None => Vec::new(),
    };

    ctx.state.write().insert(
        key.clone(),
        SourceState {
            reading: Some(CachedAssessment {
                controls: controls.clone(),
                controls_blake3: controls_hash,
                score,
                bucket,
                reasons_blake3: reasons_hash,
                reasons_count: reasons.len(),
                last_assessed_ts: now,
                dangerous_toggles: new_toggles,
            }),
            failure: None,
        },
    );

    // One drift event per appeared toggle, sent before the reading.
    for toggle in appeared {
        send(
            ctx,
            Evidence::AiGuardToggleDrift {
                tool: key.0,
                scope: key.1.clone(),
                toggle,
                rule_pack_id: key.2.clone(),
                tool_label: parser.tool_label().map(|s| s.to_string()),
                user: key.3.clone(),
            },
        )
        .await;
    }

    send(
        ctx,
        Evidence::AiGuardRiskAssessed {
            controls,
            tool: key.0,
            scope: key.1.clone(),
            score,
            bucket,
            reasons,
            is_reattestation,
            rule_pack_id: key.2.clone(),
            tool_label: parser.tool_label().map(|s| s.to_string()),
            user: key.3.clone(),
        },
    )
    .await;
}

/// #333 — record a failed assessment and send `ai_guard_assess_failed` on the
/// first failure, when the error kind or path changes, and on a heartbeat.
/// The last good reading stays cached but is never re-sent.
async fn report_failure(
    parser: &dyn AiGuardParser,
    ctx: &TaskCtx,
    key: &StateKey,
    error: &AssessError,
    force_emit: bool,
) {
    // A size cap reached surfaces as `Parse` with only a message, so it maps
    // to `parse`; no message text goes on the wire.
    let (error_kind, path) = match error {
        AssessError::Io { path, .. } => ("unreadable", path),
        AssessError::Parse { path, .. } => ("parse", path),
    };
    let (since, unchanged, last_assessed_ts) = {
        let mut state = ctx.state.write();
        let entry = state.entry(key.clone()).or_default();
        let prev = entry.failure.take();
        let unchanged = prev
            .as_ref()
            .is_some_and(|f| f.error_kind == error_kind && f.path == *path);
        let since = prev.map_or_else(OffsetDateTime::now_utc, |f| f.since);
        entry.failure = Some(AssessFailure {
            since,
            error_kind,
            path: path.clone(),
        });
        (
            since,
            unchanged,
            entry.reading.as_ref().map(|r| r.last_assessed_ts),
        )
    };
    if unchanged && !force_emit {
        return;
    }
    send(
        ctx,
        Evidence::AiGuardAssessFailed {
            tool: key.0,
            scope: key.1.clone(),
            user: key.3.clone(),
            rule_pack_id: key.2.clone(),
            tool_label: parser.tool_label().map(|s| s.to_string()),
            error_kind: error_kind.to_string(),
            path: path.clone(),
            failing_since: since,
            last_assessed_ts,
            is_reattestation: unchanged,
        },
    )
    .await;
}

async fn send(ctx: &TaskCtx, evidence: Evidence) {
    let event = Event {
        schema_version: SCHEMA_VERSION,
        event_id: uuid::Uuid::now_v7(),
        ts: OffsetDateTime::now_utc(),
        host_id: ctx.host_id.clone(),
        agent_version: AGENT_VERSION.to_string(),
        severity: Severity::Warn,
        source: SourceKind::Agent,
        subject: Subject::Self_,
        evidence,
        target_id: None,
    };
    if ctx
        .event_tx
        .send(CommittableEvent {
            event,
            new_hash: None,
            path_for_db: PathBuf::new(),
            target_id: String::new(),
        })
        .await
        .is_err()
    {
        tracing::debug!("ai_guard event_tx send failed (sink closed during shutdown?)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn own_home(ctx: &TaskCtx) -> AssessHome {
        AssessHome {
            user: None,
            dir: ctx.home_dir.clone(),
        }
    }
    use crate::ai_guard::parser::AssessError;
    use lodeline_core::event::AiGuardReason;
    use std::sync::Mutex as StdMutex;
    use tokio::sync::{broadcast, mpsc};

    /// Test parser whose `assess()` returns scripted reason sets in order.
    struct ScriptedParser {
        tool: AiTool,
        scope: AiGuardScope,
        pack_id: Option<String>,
        tool_label: Option<String>,
        scripts: StdMutex<Vec<Vec<AiGuardReason>>>,
        watched: Vec<PathBuf>,
    }

    impl AiGuardParser for ScriptedParser {
        fn tool(&self) -> AiTool {
            self.tool
        }
        fn scope(&self) -> AiGuardScope {
            self.scope.clone()
        }
        fn rule_pack_id(&self) -> Option<&str> {
            self.pack_id.as_deref()
        }
        fn tool_label(&self) -> Option<&str> {
            self.tool_label.as_deref()
        }
        fn watched_paths(&self, _home: &std::path::Path) -> Vec<PathBuf> {
            self.watched.clone()
        }
        fn assess(&self, _home: &std::path::Path) -> Result<Vec<AiGuardReason>, AssessError> {
            let mut s = self.scripts.lock().unwrap();
            if s.is_empty() {
                Ok(Vec::new())
            } else {
                Ok(s.remove(0))
            }
        }
    }

    fn ctx_with(
        parser: impl AiGuardParser + 'static,
        fc_rx: broadcast::Receiver<PathBuf>,
        hb: Duration,
    ) -> (TaskCtx, mpsc::Receiver<CommittableEvent>) {
        let (tx, rx) = mpsc::channel(16);
        (
            TaskCtx {
                parsers: Arc::new(RwLock::new(
                    vec![Arc::new(parser) as Arc<dyn AiGuardParser>],
                )),
                fc_rx,
                event_tx: tx,
                state: Arc::new(RwLock::new(HashMap::new())),
                heartbeat_interval: hb,
                home_dir: PathBuf::from("/tmp/test-home"),
                user_homes: Vec::new(),
                users_rx: watch::channel(Vec::new()).1,
                host_id: "test-host".into(),
                ext_scripts: crate::ai_guard::empty_ext_script_registry(),
                rubric: crate::ai_guard::default_rubric_handle(),
            },
            rx,
        )
    }

    /// Test parser whose `assess()` returns scripted results in order.
    struct Flaky(StdMutex<Vec<Result<Vec<AiGuardReason>, AssessError>>>);

    impl AiGuardParser for Flaky {
        fn tool(&self) -> AiTool {
            AiTool::Codex
        }
        fn scope(&self) -> AiGuardScope {
            AiGuardScope::UserGlobal
        }
        fn tool_label(&self) -> Option<&str> {
            Some("codex-label")
        }
        fn watched_paths(&self, _home: &std::path::Path) -> Vec<PathBuf> {
            Vec::new()
        }
        fn assess(&self, _home: &std::path::Path) -> Result<Vec<AiGuardReason>, AssessError> {
            self.0.lock().unwrap().remove(0)
        }
    }

    fn unreadable(path: &str) -> Result<Vec<AiGuardReason>, AssessError> {
        Err(AssessError::Io {
            path: path.into(),
            source: std::io::Error::other("message that must stay local"),
        })
    }

    fn unparsable(path: &str) -> Result<Vec<AiGuardReason>, AssessError> {
        Err(AssessError::Parse {
            path: path.into(),
            message: "message that must stay local".into(),
        })
    }

    /// `(error_kind, path, failing_since, last_assessed_ts, is_reattestation)`
    /// of the one event the cycle sent, which must be `ai_guard_assess_failed`.
    type Failed = (
        String,
        PathBuf,
        OffsetDateTime,
        Option<OffsetDateTime>,
        bool,
    );

    fn only_failure(events: &mut mpsc::Receiver<CommittableEvent>) -> Failed {
        let ev = events.try_recv().expect("an event").event;
        assert!(events.try_recv().is_err(), "one event per cycle");
        assert_eq!(ev.severity, Severity::Warn);
        let text = serde_json::to_string(&ev).unwrap();
        assert!(!text.contains("must stay local"), "{text}");
        match ev.evidence {
            Evidence::AiGuardAssessFailed {
                error_kind,
                path,
                failing_since,
                last_assessed_ts,
                is_reattestation,
                ..
            } => (
                error_kind,
                path,
                failing_since,
                last_assessed_ts,
                is_reattestation,
            ),
            other => panic!("expected ai_guard_assess_failed, got {other:?}"),
        }
    }

    fn flaky_ctx(
        script: Vec<Result<Vec<AiGuardReason>, AssessError>>,
    ) -> (
        TaskCtx,
        Arc<dyn AiGuardParser>,
        mpsc::Receiver<CommittableEvent>,
    ) {
        let (_fc_tx, fc_rx) = broadcast::channel(8);
        let (ctx, events) = ctx_with(
            Flaky(StdMutex::new(script)),
            fc_rx,
            Duration::from_secs(3600),
        );
        let parser = ctx.parsers.read()[0].clone();
        (ctx, parser, events)
    }

    #[tokio::test(start_paused = true)]
    async fn a_failure_at_boot_reports_with_no_reading() {
        let (_fc_tx, fc_rx) = broadcast::channel(8);
        let (ctx, mut events) = ctx_with(
            Flaky(StdMutex::new(vec![unparsable(
                "/tmp/test-home/.codex/config.toml",
            )])),
            fc_rx,
            Duration::from_secs(24 * 3600),
        );
        let state = ctx.state.clone();
        let h = tokio::spawn(run(ctx));
        let ev = events.recv().await.expect("boot event").event;
        let j = serde_json::to_value(&ev).unwrap();
        assert_eq!(
            j["evidence"],
            serde_json::json!({
                "kind": "ai_guard_assess_failed",
                "tool": "codex",
                "scope": {"kind": "user_global"},
                "tool_label": "codex-label",
                "error_kind": "parse",
                "path": "/tmp/test-home/.codex/config.toml",
                "failing_since": j["evidence"]["failing_since"],
                "last_assessed_ts": null,
                "is_reattestation": false,
            })
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(5), events.recv())
                .await
                .is_err(),
            "one report per failure"
        );
        assert!(state.read().values().all(|s| s.reading.is_none()));
        h.abort();
    }

    #[tokio::test]
    async fn a_failure_after_a_reading_names_it_and_never_resends_it() {
        let (ctx, parser, mut events) = flaky_ctx(vec![
            Ok(vec![AiGuardReason::SandboxDisabled]),
            unreadable("/tmp/test-home/.codex/config.toml"),
            unreadable("/tmp/test-home/.codex/config.toml"),
        ]);
        let home = own_home(&ctx);
        eval_and_maybe_emit(parser.as_ref(), &ctx, &home, true).await;
        recv_next_risk_assessed(&mut events).await;
        let good = ctx.state.read().values().next().unwrap().reading.clone();
        let good_ts = good.unwrap().last_assessed_ts;

        eval_and_maybe_emit(parser.as_ref(), &ctx, &home, false).await;
        let (kind, path, since, last, reattest) = only_failure(&mut events);
        assert_eq!(kind, "unreadable");
        assert_eq!(path, PathBuf::from("/tmp/test-home/.codex/config.toml"));
        assert_eq!(last, Some(good_ts));
        assert!(!reattest);

        eval_and_maybe_emit(parser.as_ref(), &ctx, &home, true).await;
        let heartbeat = only_failure(&mut events);
        assert_eq!(
            heartbeat,
            (kind, path, since, Some(good_ts), true),
            "the heartbeat re-sends the failure, not the cached reading"
        );
    }

    #[tokio::test]
    async fn while_failing_only_heartbeats_and_new_errors_report() {
        let (ctx, parser, mut events) = flaky_ctx(vec![
            unreadable("/a"),
            unreadable("/a"),
            unreadable("/a"),
            unreadable("/b"),
            unparsable("/b"),
        ]);
        let home = own_home(&ctx);
        eval_and_maybe_emit(parser.as_ref(), &ctx, &home, false).await;
        let (_, _, since, last, reattest) = only_failure(&mut events);
        assert_eq!((last, reattest), (None, false));

        eval_and_maybe_emit(parser.as_ref(), &ctx, &home, false).await;
        assert!(
            events.try_recv().is_err(),
            "a repeat change-driven failure sends nothing"
        );

        eval_and_maybe_emit(parser.as_ref(), &ctx, &home, true).await;
        assert_eq!(
            only_failure(&mut events),
            ("unreadable".into(), "/a".into(), since, None, true)
        );

        eval_and_maybe_emit(parser.as_ref(), &ctx, &home, false).await;
        assert_eq!(
            only_failure(&mut events),
            ("unreadable".into(), "/b".into(), since, None, false),
            "a new path is a fresh report under the first failure time"
        );

        eval_and_maybe_emit(parser.as_ref(), &ctx, &home, false).await;
        assert_eq!(
            only_failure(&mut events),
            ("parse".into(), "/b".into(), since, None, false),
            "a new error kind is a fresh report"
        );
    }

    #[tokio::test]
    async fn recovery_emits_even_when_the_reading_matches_the_cache() {
        let reading = || Ok(vec![AiGuardReason::SandboxDisabled]);
        let (ctx, parser, mut events) =
            flaky_ctx(vec![reading(), unreadable("/a"), reading(), reading()]);
        let home = own_home(&ctx);
        eval_and_maybe_emit(parser.as_ref(), &ctx, &home, true).await;
        recv_next_risk_assessed(&mut events).await;
        eval_and_maybe_emit(parser.as_ref(), &ctx, &home, false).await;
        only_failure(&mut events);

        eval_and_maybe_emit(parser.as_ref(), &ctx, &home, false).await;
        let ev = events.try_recv().expect("recovery emits").event;
        assert!(
            matches!(
                ev.evidence,
                Evidence::AiGuardRiskAssessed {
                    is_reattestation: false,
                    ..
                }
            ),
            "{ev:?}"
        );
        assert!(events.try_recv().is_err(), "no drift on recovery");
        assert!(ctx.state.read().values().all(|s| s.failure.is_none()));

        eval_and_maybe_emit(parser.as_ref(), &ctx, &home, false).await;
        assert!(
            events.try_recv().is_err(),
            "after recovery an identical cycle is quiet again"
        );
    }

    #[tokio::test]
    async fn root_agent_assesses_each_user_home() {
        let homes = tempfile::tempdir().unwrap();
        let (alice, bob) = (homes.path().join("alice"), homes.path().join("bob"));
        std::fs::create_dir_all(alice.join(".claude")).unwrap();
        std::fs::create_dir_all(&bob).unwrap();
        std::fs::write(
            alice.join(".claude/settings.json"),
            r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"rm -rf ~/work"}]}]}}"#,
        )
        .unwrap();
        let (_fc_tx, fc_rx) = broadcast::channel(8);
        let (mut ctx, mut events) = ctx_with(
            crate::ai_guard::parser::claude_code::ClaudeCodeParser::default(),
            fc_rx,
            Duration::from_secs(3600),
        );
        ctx.home_dir = homes.path().join("root");
        ctx.user_homes = vec![
            AssessHome {
                user: Some("alice".into()),
                dir: alice,
            },
            AssessHome {
                user: Some("bob".into()),
                dir: bob,
            },
        ];
        let parser = ctx.parsers.read()[0].clone();
        for home in homes_for(parser.as_ref(), &ctx) {
            eval_and_maybe_emit(parser.as_ref(), &ctx, &home, true).await;
        }
        let mut seen = Vec::new();
        while let Ok(ev) = events.try_recv() {
            if let Evidence::AiGuardRiskAssessed { user, reasons, .. } = ev.event.evidence {
                seen.push((
                    user,
                    reasons
                        .iter()
                        .any(|r| matches!(r, AiGuardReason::DestructiveInInlineCommand { .. })),
                ));
            }
        }
        seen.sort();
        assert_eq!(
            seen,
            vec![
                (None, false),
                (Some("alice".into()), true),
                (Some("bob".into()), false)
            ]
        );
        assert_eq!(ctx.state.read().len(), 3);
    }

    #[tokio::test]
    async fn root_agent_reads_each_user_home_for_a_rule_pack() {
        use lodeline_core::policy::{Matcher, RuleEntry, RuleFormat, RulePack, RulePackScope};
        let homes = tempfile::tempdir().unwrap();
        let (root, alice, bob) = (
            homes.path().join("root"),
            homes.path().join("alice"),
            homes.path().join("bob"),
        );
        for (home, sandbox) in [(&root, true), (&alice, false), (&bob, true)] {
            std::fs::create_dir_all(home.join(".gemini")).unwrap();
            std::fs::write(
                home.join(".gemini/settings.json"),
                format!(r#"{{"sandbox":{sandbox}}}"#),
            )
            .unwrap();
        }
        let pack = crate::ai_guard::rule_pack::parser::RulePackParser::new(RulePack {
            id: "pack".into(),
            pack_version: 1,
            tool: AiTool::Gemini,
            scope: RulePackScope::UserGlobal,
            watched_paths: vec!["~/.gemini/settings.json".into()],
            platforms: None,
            tool_label: None,
            rules: vec![RuleEntry {
                id: "r1".into(),
                on_file: "~/.gemini/settings.json".into(),
                format: RuleFormat::Json,
                selector: "$.sandbox".into(),
                matcher: Matcher::Equals {
                    value: "false".into(),
                },
                emit: AiGuardReason::SandboxDisabled,
                when: vec![],
            }],
        })
        .unwrap();
        let (_fc_tx, fc_rx) = broadcast::channel(8);
        let (mut ctx, mut events) = ctx_with(pack, fc_rx, Duration::from_secs(3600));
        ctx.home_dir = root;
        ctx.user_homes = vec![
            AssessHome {
                user: Some("alice".into()),
                dir: alice.clone(),
            },
            AssessHome {
                user: Some("bob".into()),
                dir: bob,
            },
        ];
        let parser = ctx.parsers.read()[0].clone();
        assert!(parser
            .watched_paths(&alice)
            .contains(&alice.join(".gemini/settings.json")));
        for home in homes_for(parser.as_ref(), &ctx) {
            eval_and_maybe_emit(parser.as_ref(), &ctx, &home, true).await;
        }
        let mut seen = Vec::new();
        while let Ok(ev) = events.try_recv() {
            if let Evidence::AiGuardRiskAssessed {
                user,
                reasons,
                rule_pack_id,
                ..
            } = ev.event.evidence
            {
                assert_eq!(rule_pack_id.as_deref(), Some("pack"));
                seen.push((user, !reasons.is_empty()));
            }
        }
        seen.sort();
        assert_eq!(
            seen,
            vec![
                (None, false),
                (Some("alice".into()), true),
                (Some("bob".into()), false)
            ]
        );
    }

    /// Receive the next `AiGuardRiskAssessed` event, skipping any
    /// `AiGuardToggleDrift` events emitted earlier in the same cycle (#147).
    async fn recv_next_risk_assessed(
        events: &mut mpsc::Receiver<CommittableEvent>,
    ) -> CommittableEvent {
        loop {
            let ev = events.recv().await.expect("event");
            if matches!(ev.event.evidence, Evidence::AiGuardToggleDrift { .. }) {
                continue;
            }
            return ev;
        }
    }

    struct ControlsParser(
        StdMutex<Option<Vec<lodeline_core::event::AiGuardControl>>>,
        std::sync::atomic::AtomicBool,
    );

    impl AiGuardParser for ControlsParser {
        fn tool(&self) -> AiTool {
            AiTool::Codex
        }
        fn scope(&self) -> AiGuardScope {
            AiGuardScope::UserGlobal
        }
        fn watched_paths(&self, _: &std::path::Path) -> Vec<PathBuf> {
            vec![]
        }
        fn assess(&self, _: &std::path::Path) -> Result<Vec<AiGuardReason>, AssessError> {
            panic!("posture path must be used")
        }
        fn assess_posture(
            &self,
            _: &std::path::Path,
        ) -> Result<crate::ai_guard::parser::AiGuardAssessment, AssessError> {
            if self.1.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(AssessError::Io {
                    path: "fixture".into(),
                    source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
                });
            }
            Ok(crate::ai_guard::parser::AiGuardAssessment {
                reasons: vec![AiGuardReason::SandboxDisabled],
                controls: self.0.lock().unwrap().clone(),
            })
        }
    }

    #[tokio::test]
    async fn controls_changes_emit_without_changing_risk() {
        let (_tx, fc_rx) = broadcast::channel(8);
        let (ctx, mut events) = ctx_with(
            ControlsParser(StdMutex::new(None), false.into()),
            fc_rx,
            Duration::from_secs(60),
        );
        let parser = ControlsParser(StdMutex::new(None), false.into());
        let control = lodeline_core::event::AiGuardControl {
            id: "fixture.restricted".into(),
            source_path: "/fixture/settings".into(),
            setting: "restricted".into(),
            value: serde_json::json!(true),
        };
        let mut changed = control.clone();
        changed.value = serde_json::json!("managed");
        let mut moved = changed.clone();
        moved.source_path = "/fixture/managed".into();
        for controls in [
            None,
            Some(vec![]),
            Some(vec![control.clone()]),
            Some(vec![changed]),
            Some(vec![moved]),
            Some(vec![]),
            None,
        ] {
            *parser.0.lock().unwrap() = controls.clone();
            eval_and_maybe_emit(&parser, &ctx, &own_home(&ctx), false).await;
            let ev = events.try_recv().unwrap().event;
            match ev.evidence {
                Evidence::AiGuardRiskAssessed {
                    score,
                    controls: got,
                    is_reattestation,
                    ..
                } => {
                    assert_eq!(score, rubric::score(&[AiGuardReason::SandboxDisabled]));
                    assert_eq!(got, controls);
                    assert!(!is_reattestation);
                }
                other => panic!("unexpected event: {other:?}"),
            }
            assert!(events.try_recv().is_err());
        }
        *parser.0.lock().unwrap() = Some(vec![control.clone(), {
            let mut c = control.clone();
            c.id = "fixture.other".into();
            c
        }]);
        eval_and_maybe_emit(&parser, &ctx, &own_home(&ctx), false).await;
        events.try_recv().unwrap();
        {
            let mut lock = parser.0.lock().unwrap();
            let values = lock.as_mut().unwrap();
            values.reverse();
            values.push(control);
        }
        eval_and_maybe_emit(&parser, &ctx, &own_home(&ctx), false).await;
        assert!(
            events.try_recv().is_err(),
            "order and duplicates are not changes"
        );
        eval_and_maybe_emit(&parser, &ctx, &own_home(&ctx), true).await;
        assert!(matches!(
            events.try_recv().unwrap().event.evidence,
            Evidence::AiGuardRiskAssessed {
                is_reattestation: true,
                ..
            }
        ));
        let cached_controls = || {
            let state = ctx.state.read();
            state
                .values()
                .next()
                .unwrap()
                .reading
                .clone()
                .unwrap()
                .controls
        };
        let previous = cached_controls();
        *parser.0.lock().unwrap() = Some(vec![]);
        parser.1.store(true, std::sync::atomic::Ordering::Relaxed);
        eval_and_maybe_emit(&parser, &ctx, &own_home(&ctx), true).await;
        assert_eq!(
            only_failure(&mut events).0,
            "unreadable",
            "a failed heartbeat read reports the failure"
        );
        assert_eq!(cached_controls(), previous);
    }

    #[tokio::test(start_paused = true)]
    async fn boot_emits_initial_event_even_when_clean() {
        let (_tx, fc_rx) = broadcast::channel(8);
        let parser = ScriptedParser {
            tool: AiTool::ClaudeCode,
            scope: AiGuardScope::UserGlobal,
            pack_id: None,
            tool_label: None,
            scripts: StdMutex::new(vec![vec![]]),
            watched: vec![PathBuf::from("/tmp/test-home/.claude/settings.json")],
        };
        let (ctx, mut events) = ctx_with(parser, fc_rx, Duration::from_secs(24 * 3600));
        let h = tokio::spawn(run(ctx));
        // Allow the boot scan to fire.
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(10)).await;
        let ev = events.recv().await.expect("boot event");
        match ev.event.evidence {
            Evidence::AiGuardRiskAssessed {
                score,
                bucket,
                reasons,
                is_reattestation,
                ..
            } => {
                assert_eq!(score, 0.0);
                assert_eq!(bucket, AiGuardBucket::Low);
                assert!(reasons.is_empty());
                assert!(
                    !is_reattestation,
                    "boot scan with no prior state is not a re-attestation"
                );
            }
            other => panic!("expected AiGuardRiskAssessed, got {other:?}"),
        }
        h.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn unchanged_file_change_does_not_emit() {
        let (tx, fc_rx) = broadcast::channel(8);
        let watched = PathBuf::from("/tmp/test-home/.claude/settings.json");
        let parser = ScriptedParser {
            tool: AiTool::ClaudeCode,
            scope: AiGuardScope::UserGlobal,
            pack_id: None,
            tool_label: None,
            scripts: StdMutex::new(vec![
                vec![AiGuardReason::PermissionsDenyEmpty], // boot
                vec![AiGuardReason::PermissionsDenyEmpty], // identical → no emit
            ]),
            watched: vec![watched.clone()],
        };
        let (ctx, mut events) = ctx_with(parser, fc_rx, Duration::from_secs(24 * 3600));
        let h = tokio::spawn(run(ctx));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(10)).await;
        let _boot = events.recv().await.expect("boot event");
        tx.send(watched).unwrap();
        tokio::time::advance(Duration::from_millis(50)).await;
        // Should NOT receive a second event.
        let attempt = tokio::time::timeout(Duration::from_millis(100), events.recv()).await;
        assert!(attempt.is_err(), "expected no second emit, got {attempt:?}");
        h.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn changed_file_change_emits_with_is_reattestation_false() {
        let (tx, fc_rx) = broadcast::channel(8);
        let watched = PathBuf::from("/tmp/test-home/.claude/settings.json");
        let parser = ScriptedParser {
            tool: AiTool::ClaudeCode,
            scope: AiGuardScope::UserGlobal,
            pack_id: None,
            tool_label: None,
            scripts: StdMutex::new(vec![
                vec![AiGuardReason::PermissionsDenyEmpty],
                vec![AiGuardReason::SandboxDisabled],
            ]),
            watched: vec![watched.clone()],
        };
        let (ctx, mut events) = ctx_with(parser, fc_rx, Duration::from_secs(24 * 3600));
        let h = tokio::spawn(run(ctx));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(10)).await;
        let _boot = events.recv().await.expect("boot");
        tx.send(watched).unwrap();
        tokio::time::advance(Duration::from_millis(50)).await;
        // SandboxDisabled is also a dangerous toggle, so an OFF→ON drift event
        // precedes the risk event this cycle. Skip past it to the risk event.
        let ev = recv_next_risk_assessed(&mut events).await;
        match ev.event.evidence {
            Evidence::AiGuardRiskAssessed {
                is_reattestation, ..
            } => assert!(!is_reattestation),
            other => panic!("got {other:?}"),
        }
        h.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn heartbeat_force_emits_with_is_reattestation_true_when_unchanged() {
        let (_tx, fc_rx) = broadcast::channel(8);
        let parser = ScriptedParser {
            tool: AiTool::ClaudeCode,
            scope: AiGuardScope::UserGlobal,
            pack_id: None,
            tool_label: None,
            scripts: StdMutex::new(vec![
                vec![AiGuardReason::PermissionsDenyEmpty],
                vec![AiGuardReason::PermissionsDenyEmpty], // heartbeat — same
            ]),
            watched: vec![PathBuf::from("/tmp/test-home/.claude/settings.json")],
        };
        let (ctx, mut events) = ctx_with(parser, fc_rx, Duration::from_millis(100));
        let h = tokio::spawn(run(ctx));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(10)).await;
        let _boot = events.recv().await.expect("boot");
        tokio::time::advance(Duration::from_millis(150)).await;
        let ev = events.recv().await.expect("heartbeat event");
        match ev.event.evidence {
            Evidence::AiGuardRiskAssessed {
                is_reattestation, ..
            } => assert!(
                is_reattestation,
                "heartbeat with unchanged reasons must be re-attestation"
            ),
            other => panic!("got {other:?}"),
        }
        h.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn heartbeat_with_changed_reasons_emits_is_reattestation_false() {
        let (_tx, fc_rx) = broadcast::channel(8);
        let parser = ScriptedParser {
            tool: AiTool::ClaudeCode,
            scope: AiGuardScope::UserGlobal,
            pack_id: None,
            tool_label: None,
            scripts: StdMutex::new(vec![
                vec![AiGuardReason::PermissionsDenyEmpty], // boot
                vec![AiGuardReason::SandboxDisabled],      // heartbeat — different
            ]),
            watched: vec![PathBuf::from("/tmp/test-home/.claude/settings.json")],
        };
        let (ctx, mut events) = ctx_with(parser, fc_rx, Duration::from_millis(100));
        let h = tokio::spawn(run(ctx));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(10)).await;
        let _boot = events.recv().await.expect("boot event");
        tokio::time::advance(Duration::from_millis(150)).await;
        // SandboxDisabled (the changed reason) is also a dangerous toggle, so a
        // drift event precedes the risk event this cycle. Skip to the risk one.
        let ev = recv_next_risk_assessed(&mut events).await;
        match ev.event.evidence {
            Evidence::AiGuardRiskAssessed {
                is_reattestation, ..
            } => assert!(
                !is_reattestation,
                "heartbeat with CHANGED reasons must NOT be reattestation"
            ),
            other => panic!("got {other:?}"),
        }
        h.abort();
    }

    #[tokio::test]
    async fn emit_carries_tool_label_from_parser() {
        let (_fc_tx, fc_rx) = broadcast::channel(8);
        let (event_tx, mut events) = mpsc::channel(16);
        let state: Arc<RwLock<StateMap>> = Arc::new(RwLock::new(HashMap::new()));
        let ctx = TaskCtx {
            parsers: Arc::new(RwLock::new(vec![])),
            fc_rx,
            event_tx,
            state: state.clone(),
            heartbeat_interval: Duration::from_secs(24 * 3600),
            home_dir: PathBuf::from("/tmp/test-home"),
            user_homes: Vec::new(),
            users_rx: watch::channel(Vec::new()).1,
            host_id: "test-host".into(),
            ext_scripts: crate::ai_guard::empty_ext_script_registry(),
            rubric: crate::ai_guard::default_rubric_handle(),
        };
        let parser = ScriptedParser {
            tool: AiTool::Other,
            scope: AiGuardScope::UserGlobal,
            pack_id: Some("p".to_string()),
            tool_label: Some("acme-ai".to_string()),
            scripts: StdMutex::new(vec![vec![AiGuardReason::SandboxDisabled]]),
            watched: vec![],
        };
        eval_and_maybe_emit(&parser, &ctx, &own_home(&ctx), true).await;
        let ev = events.recv().await.expect("tool_label event");
        let j = serde_json::to_value(&ev.event).unwrap();
        assert_eq!(j["evidence"]["tool"], "other");
        assert_eq!(j["evidence"]["tool_label"], "acme-ai");
    }

    #[tokio::test]
    async fn distinct_pack_ids_do_not_collide_in_state() {
        let (_fc_tx, fc_rx) = broadcast::channel(8);
        let (event_tx, _events) = mpsc::channel(16);
        let state: Arc<RwLock<StateMap>> = Arc::new(RwLock::new(HashMap::new()));
        let ctx = TaskCtx {
            parsers: Arc::new(RwLock::new(vec![])),
            fc_rx,
            event_tx,
            state: state.clone(),
            heartbeat_interval: Duration::from_secs(24 * 3600),
            home_dir: PathBuf::from("/tmp/test-home"),
            user_homes: Vec::new(),
            users_rx: watch::channel(Vec::new()).1,
            host_id: "test-host".into(),
            ext_scripts: crate::ai_guard::empty_ext_script_registry(),
            rubric: crate::ai_guard::default_rubric_handle(),
        };
        // Parser A: tool=Gemini, scope=Project{path:"/r"}, pack_id=Some("pack-a"),
        //   scripts=[vec![AiGuardReason::SandboxDisabled]]
        let a = ScriptedParser {
            tool: AiTool::Gemini,
            scope: AiGuardScope::Project { path: "/r".into() },
            pack_id: Some("pack-a".to_string()),
            tool_label: None,
            scripts: StdMutex::new(vec![vec![AiGuardReason::SandboxDisabled]]),
            watched: vec![],
        };
        // Parser B: tool=Gemini, scope=Project{path:"/r"}, pack_id=Some("pack-b"),
        //   scripts=[vec![]]  (clean)
        let b = ScriptedParser {
            tool: AiTool::Gemini,
            scope: AiGuardScope::Project { path: "/r".into() },
            pack_id: Some("pack-b".to_string()),
            tool_label: None,
            scripts: StdMutex::new(vec![vec![]]),
            watched: vec![],
        };
        eval_and_maybe_emit(&a, &ctx, &own_home(&ctx), true).await;
        eval_and_maybe_emit(&b, &ctx, &own_home(&ctx), true).await;
        let scope = AiGuardScope::Project { path: "/r".into() };
        let s = ctx.state.read();
        assert!(s.contains_key(&(
            AiTool::Gemini,
            scope.clone(),
            Some("pack-a".to_string()),
            None
        )));
        assert!(s.contains_key(&(
            AiTool::Gemini,
            scope.clone(),
            Some("pack-b".to_string()),
            None
        )));
        assert_eq!(s.len(), 2);
    }

    // ---- #147 dangerous-toggle drift -------------------------------------

    /// Build a parsers-less ctx + a shared event channel for driving a single
    /// parser through `eval_and_maybe_emit` directly (mirrors
    /// `emit_carries_tool_label_from_parser`). Returns (ctx, event receiver).
    fn drift_ctx() -> (TaskCtx, mpsc::Receiver<CommittableEvent>) {
        let (_fc_tx, fc_rx) = broadcast::channel(8);
        let (event_tx, events) = mpsc::channel(32);
        let ctx = TaskCtx {
            parsers: Arc::new(RwLock::new(vec![])),
            fc_rx,
            event_tx,
            state: Arc::new(RwLock::new(HashMap::new())),
            heartbeat_interval: Duration::from_secs(24 * 3600),
            home_dir: PathBuf::from("/tmp/test-home"),
            user_homes: Vec::new(),
            users_rx: watch::channel(Vec::new()).1,
            host_id: "test-host".into(),
            ext_scripts: crate::ai_guard::empty_ext_script_registry(),
            rubric: crate::ai_guard::default_rubric_handle(),
        };
        (ctx, events)
    }

    #[tokio::test]
    async fn mcp_changes_reuse_toggle_events_and_repeat_edits_update_evidence() {
        let home = tempfile::tempdir().unwrap();
        let cache = home.path().join(".codex/cache/codex_apps_tools");
        std::fs::create_dir_all(&cache).unwrap();
        let write = |desc: &str| {
            std::fs::write(
                cache.join("a.json"),
                serde_json::json!({
                    "tools":[{"server_name":"third","tool":{"name":"read","description":desc}}]
                })
                .to_string(),
            )
            .unwrap()
        };
        let parser =
            crate::ai_guard::CodexToolCacheParser::with_baseline(home.path().join("baselines"));
        let (mut ctx, mut events) = drift_ctx();
        ctx.home_dir = home.path().into();
        write("original");
        eval_and_maybe_emit(&parser, &ctx, &own_home(&ctx), false).await;
        assert!(drain_drift_toggles(&mut events).is_empty());
        write("changed");
        eval_and_maybe_emit(&parser, &ctx, &own_home(&ctx), false).await;
        assert_eq!(
            drain_drift_toggles(&mut events),
            vec!["mcp_tool_surface_drift"]
        );
        write("changed again");
        eval_and_maybe_emit(&parser, &ctx, &own_home(&ctx), false).await;
        let event = events.try_recv().unwrap().event;
        assert!(matches!(
            event.evidence,
            Evidence::AiGuardRiskAssessed {
                is_reattestation: false,
                ..
            }
        ));
        assert!(events.try_recv().is_err());
        eval_and_maybe_emit(&parser, &ctx, &own_home(&ctx), false).await;
        assert!(events.try_recv().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn watched_policy_path_resolves_symlinked_parent() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let incoming = real.canonicalize().unwrap().join("requirements.toml");
        assert!(path_matches(&incoming, &link.join("requirements.toml")));
        assert!(!path_matches(&incoming, &link.join("other.toml")));
    }

    #[cfg(unix)]
    #[tokio::test(start_paused = true)]
    async fn a_symlinked_home_is_one_home_and_its_changes_match() {
        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("var/home");
        std::fs::create_dir_all(real.join("alice/.claude")).unwrap();
        std::os::unix::fs::symlink(&real, root.path().join("home")).unwrap();
        let settings = real
            .canonicalize()
            .unwrap()
            .join("alice/.claude/settings.json");
        std::fs::write(&settings, "{}").unwrap();
        let (tx, fc_rx) = broadcast::channel(8);
        let (mut ctx, mut events) = ctx_with(
            crate::ai_guard::parser::claude_code::ClaudeCodeParser::default(),
            fc_rx,
            Duration::from_secs(24 * 3600),
        );
        // A root agent that kept alice's HOME (`sudo` without -H), spelled
        // through `/home -> /var/home`, while passwd names the real path.
        ctx.home_dir = root.path().join("home/alice");
        ctx.user_homes = vec![AssessHome {
            user: Some("alice".into()),
            dir: real.join("alice"),
        }];
        let h = tokio::spawn(run(ctx));
        recv_next_risk_assessed(&mut events).await;
        assert!(
            tokio::time::timeout(Duration::from_secs(5), events.recv())
                .await
                .is_err(),
            "one reading per home, not one per spelling of it"
        );
        std::fs::write(
            &settings,
            r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"rm -rf ~/work"}]}]}}"#,
        )
        .unwrap();
        tx.send(settings).unwrap();
        let ev = tokio::time::timeout(Duration::from_secs(5), recv_next_risk_assessed(&mut events))
            .await
            .expect("a change in the symlinked home re-assesses it");
        assert!(matches!(
            ev.event.evidence,
            Evidence::AiGuardRiskAssessed { ref reasons, .. }
                if reasons.iter().any(|r| matches!(r, AiGuardReason::DestructiveInInlineCommand { .. }))
        ));
        h.abort();
    }

    async fn next_users(
        events: &mut mpsc::Receiver<CommittableEvent>,
        n: usize,
    ) -> Vec<Option<String>> {
        let mut users = Vec::new();
        for _ in 0..n {
            let ev = tokio::time::timeout(Duration::from_secs(5), recv_next_risk_assessed(events))
                .await
                .expect("a reading");
            let Evidence::AiGuardRiskAssessed { user, .. } = ev.event.evidence else {
                unreachable!()
            };
            users.push(user);
        }
        users.sort();
        users
    }

    #[tokio::test(start_paused = true)]
    async fn a_refreshed_user_set_assesses_added_users_and_drops_removed_ones() {
        let homes = tempfile::tempdir().unwrap();
        let home = |name: &str| {
            let dir = homes.path().join(name);
            std::fs::create_dir_all(&dir).unwrap();
            AssessHome {
                user: Some(name.into()),
                dir,
            }
        };
        let (alice, bob) = (home("alice"), home("bob"));
        let (_fc_tx, fc_rx) = broadcast::channel(8);
        let (mut ctx, mut events) = ctx_with(
            crate::ai_guard::parser::claude_code::ClaudeCodeParser::default(),
            fc_rx,
            Duration::from_secs(3600),
        );
        ctx.home_dir = homes.path().join("root");
        ctx.user_homes = vec![alice];
        let (users_tx, users_rx) = watch::channel(ctx.user_homes.clone());
        ctx.users_rx = users_rx;
        let state = ctx.state.clone();
        let h = tokio::spawn(run(ctx));
        assert_eq!(
            next_users(&mut events, 2).await,
            vec![None, Some("alice".into())]
        );

        users_tx.send(vec![bob]).unwrap();
        assert_eq!(
            next_users(&mut events, 1).await,
            vec![Some("bob".into())],
            "a user added after boot is assessed at the refresh"
        );
        let mut held: Vec<_> = state.read().keys().map(|k| k.3.clone()).collect();
        held.sort();
        assert_eq!(
            held,
            vec![None, Some("bob".into())],
            "alice's reading is dropped"
        );

        tokio::time::advance(Duration::from_secs(3600)).await;
        assert_eq!(
            next_users(&mut events, 2).await,
            vec![None, Some("bob".into())],
            "the heartbeat re-sends only the current users"
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(5), events.recv())
                .await
                .is_err(),
            "nothing more for alice"
        );
        h.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_change_to_another_users_external_script_reassesses_that_user() {
        let homes = tempfile::tempdir().unwrap();
        let (root, alice) = (homes.path().join("root"), homes.path().join("alice"));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(alice.join(".claude")).unwrap();
        std::fs::create_dir_all(alice.join("bin")).unwrap();
        let script = alice.join("bin/guard.sh");
        std::fs::write(&script, "#!/bin/sh\necho ok\n").unwrap();
        std::fs::write(
            alice.join(".claude/settings.json"),
            format!(
                r#"{{"hooks":{{"PreToolUse":[{{"hooks":[{{"type":"command","command":"{}"}}]}}]}}}}"#,
                script.display().to_string().replace('\\', "\\\\")
            ),
        )
        .unwrap();
        let (tx, fc_rx) = broadcast::channel(8);
        let (mut ctx, mut events) = ctx_with(
            crate::ai_guard::parser::claude_code::ClaudeCodeParser::default(),
            fc_rx,
            Duration::from_secs(24 * 3600),
        );
        ctx.home_dir = root.clone();
        ctx.user_homes = vec![AssessHome {
            user: Some("alice".into()),
            dir: alice.clone(),
        }];
        let mut effective = lodeline_core::policy::merge(
            lodeline_core::policy::defaults().unwrap(),
            None,
            None,
            lodeline_core::policy::current_platform(),
        )
        .unwrap();
        crate::runtime::register_ext_scripts(
            &ctx.parsers.read().clone(),
            &[root, alice],
            &ctx.ext_scripts,
            &mut effective,
        );
        let h = tokio::spawn(run(ctx));
        next_users(&mut events, 2).await;

        std::fs::write(&script, "#!/bin/sh\nrm -rf ~/work\n").unwrap();
        tx.send(dunce::canonicalize(&script).unwrap()).unwrap();
        let ev = tokio::time::timeout(Duration::from_secs(5), recv_next_risk_assessed(&mut events))
            .await
            .expect("the script change re-assesses the user whose settings run it");
        let Evidence::AiGuardRiskAssessed { user, reasons, .. } = ev.event.evidence else {
            unreachable!()
        };
        assert_eq!(user.as_deref(), Some("alice"));
        assert!(reasons
            .iter()
            .any(|r| matches!(r, AiGuardReason::DestructiveInHookScript { .. })));
        h.abort();
    }

    /// Drain the channel and return only the `AiGuardToggleDrift` toggles, in
    /// emission order. (Each `eval_and_maybe_emit` also emits an
    /// `AiGuardRiskAssessed`; we ignore those here.)
    fn drain_drift_toggles(events: &mut mpsc::Receiver<CommittableEvent>) -> Vec<String> {
        let mut out = Vec::new();
        while let Ok(ce) = events.try_recv() {
            if let Evidence::AiGuardToggleDrift { toggle, .. } = ce.event.evidence {
                out.push(toggle);
            }
        }
        out
    }

    fn one_shot_parser(reasons: Vec<AiGuardReason>) -> ScriptedParser {
        ScriptedParser {
            tool: AiTool::Gemini,
            scope: AiGuardScope::UserGlobal,
            pack_id: None,
            tool_label: None,
            scripts: StdMutex::new(vec![reasons]),
            watched: vec![],
        }
    }

    /// Baseline: first assessment with a dangerous toggle already present must
    /// NOT fire a drift event — boot establishes the baseline.
    #[tokio::test]
    async fn drift_baseline_does_not_fire() {
        let (ctx, mut events) = drift_ctx();
        let p = one_shot_parser(vec![AiGuardReason::AutoApprovalEnabled {
            mode: "auto_edit".into(),
        }]);
        eval_and_maybe_emit(&p, &ctx, &own_home(&ctx), true).await;
        assert!(
            drain_drift_toggles(&mut events).is_empty(),
            "boot assessment must not fire drift"
        );
        // Baseline was recorded.
        let key = (AiTool::Gemini, AiGuardScope::UserGlobal, None, None);
        assert!(ctx.state.read()[&key]
            .reading
            .as_ref()
            .unwrap()
            .dangerous_toggles
            .contains("auto_approval_enabled"));
    }

    /// #199 — the repository settings toggles that act before workspace trust
    /// baseline silently at boot and drift OFF→ON when added after boot.
    #[tokio::test]
    async fn project_settings_toggles_baseline_at_boot_and_drift_when_added() {
        let risky = serde_json::json!({
            "enabledPlugins": {"a@m": true},
            "apiKeyHelper": "./key.sh",
            "env": {"NODE_OPTIONS": "--require ./x.js"},
        });
        let run = |boot: &serde_json::Value, later: &serde_json::Value| {
            let (boot, later) = (boot.to_string(), later.to_string());
            async move {
                let repo = tempfile::tempdir().unwrap();
                let settings = repo.path().join(".claude/settings.json");
                std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
                let parser = crate::ai_guard::parser::claude_code::ClaudeCodeProjectParser {
                    repo_root: repo.path().into(),
                };
                let (ctx, mut events) = drift_ctx();
                std::fs::write(&settings, boot).unwrap();
                eval_and_maybe_emit(&parser, &ctx, &own_home(&ctx), true).await;
                let at_boot = drain_drift_toggles(&mut events);
                std::fs::write(&settings, later).unwrap();
                eval_and_maybe_emit(&parser, &ctx, &own_home(&ctx), false).await;
                (at_boot, drain_drift_toggles(&mut events))
            }
        };
        let (at_boot, after) = run(&risky, &risky).await;
        assert!(
            at_boot.is_empty() && after.is_empty(),
            "{at_boot:?} {after:?}"
        );
        let (at_boot, after) = run(&serde_json::json!({}), &risky).await;
        assert!(at_boot.is_empty(), "{at_boot:?}");
        assert_eq!(
            after,
            vec![
                "project_settings_env_override",
                "project_settings_helper_command",
                "project_settings_plugin_enabled",
            ]
        );
    }

    /// off→on: assess with toggle off, then flip it on → EXACTLY ONE drift
    /// event for that toggle kind.
    #[tokio::test]
    async fn drift_off_to_on_fires_once() {
        let (ctx, mut events) = drift_ctx();
        // First (baseline): toggle off — a non-dangerous reason so the reason
        // set is non-empty but carries no dangerous toggle.
        let off = one_shot_parser(vec![AiGuardReason::PermissionsDenyEmpty]);
        eval_and_maybe_emit(&off, &ctx, &own_home(&ctx), true).await;
        assert!(drain_drift_toggles(&mut events).is_empty());

        // Second: toggle on.
        let on = one_shot_parser(vec![AiGuardReason::SandboxDisabled]);
        eval_and_maybe_emit(&on, &ctx, &own_home(&ctx), false).await;
        assert_eq!(
            drain_drift_toggles(&mut events),
            vec!["sandbox_disabled".to_string()]
        );
    }

    /// already-on: toggle on across two assessments → no drift on the second.
    #[tokio::test]
    async fn drift_already_on_does_not_refire() {
        let (ctx, mut events) = drift_ctx();
        let on1 = one_shot_parser(vec![AiGuardReason::SandboxDisabled]);
        eval_and_maybe_emit(&on1, &ctx, &own_home(&ctx), true).await; // baseline (no drift)
        assert!(drain_drift_toggles(&mut events).is_empty());

        // Same toggle present again — force_emit so an AiGuardRiskAssessed is
        // produced, but the toggle was already in prev → no drift.
        let on2 = one_shot_parser(vec![AiGuardReason::SandboxDisabled]);
        eval_and_maybe_emit(&on2, &ctx, &own_home(&ctx), true).await;
        assert!(
            drain_drift_toggles(&mut events).is_empty(),
            "an already-on toggle must not re-fire"
        );
    }

    /// on→off: toggle removed → no drift (de-escalation is silent).
    #[tokio::test]
    async fn drift_on_to_off_does_not_fire() {
        let (ctx, mut events) = drift_ctx();
        let on = one_shot_parser(vec![AiGuardReason::SandboxDisabled]);
        eval_and_maybe_emit(&on, &ctx, &own_home(&ctx), true).await; // baseline
        let _ = drain_drift_toggles(&mut events);

        let off = one_shot_parser(vec![AiGuardReason::PermissionsDenyEmpty]);
        eval_and_maybe_emit(&off, &ctx, &own_home(&ctx), false).await;
        assert!(
            drain_drift_toggles(&mut events).is_empty(),
            "on→off must not fire drift"
        );
        // Cache reflects the toggle is gone.
        let key = (AiTool::Gemini, AiGuardScope::UserGlobal, None, None);
        assert!(ctx.state.read()[&key]
            .reading
            .as_ref()
            .unwrap()
            .dangerous_toggles
            .is_empty());
    }

    /// on→off→on: the toggle re-appearing fires drift again (each on-transition).
    #[tokio::test]
    async fn drift_on_off_on_fires_again() {
        let (ctx, mut events) = drift_ctx();
        eval_and_maybe_emit(
            &one_shot_parser(vec![AiGuardReason::SandboxDisabled]),
            &ctx,
            &own_home(&ctx),
            true,
        )
        .await; // baseline on
        let _ = drain_drift_toggles(&mut events);
        eval_and_maybe_emit(
            &one_shot_parser(vec![AiGuardReason::PermissionsDenyEmpty]),
            &ctx,
            &own_home(&ctx),
            false,
        )
        .await; // off
        let _ = drain_drift_toggles(&mut events);
        eval_and_maybe_emit(
            &one_shot_parser(vec![AiGuardReason::SandboxDisabled]),
            &ctx,
            &own_home(&ctx),
            false,
        )
        .await; // on again
        assert_eq!(
            drain_drift_toggles(&mut events),
            vec!["sandbox_disabled".to_string()]
        );
    }

    /// Multiple toggles appearing at once → one drift event per appeared toggle.
    #[tokio::test]
    async fn drift_multiple_toggles_one_event_each() {
        let (ctx, mut events) = drift_ctx();
        // Baseline: none.
        eval_and_maybe_emit(
            &one_shot_parser(vec![AiGuardReason::PermissionsDenyEmpty]),
            &ctx,
            &own_home(&ctx),
            true,
        )
        .await;
        let _ = drain_drift_toggles(&mut events);

        // Two dangerous toggles appear at once.
        let both = one_shot_parser(vec![
            AiGuardReason::SandboxDisabled,
            AiGuardReason::AutoApprovalEnabled {
                mode: "auto_edit".into(),
            },
        ]);
        eval_and_maybe_emit(&both, &ctx, &own_home(&ctx), false).await;
        let mut got = drain_drift_toggles(&mut events);
        got.sort();
        assert_eq!(
            got,
            vec![
                "auto_approval_enabled".to_string(),
                "sandbox_disabled".to_string()
            ]
        );
    }

    /// Full-loop off→on via the file-change trigger: drift event flows through
    /// `run()` exactly like the AiGuardRiskAssessed sibling.
    #[tokio::test(start_paused = true)]
    async fn drift_off_to_on_through_run_loop() {
        let (tx, fc_rx) = broadcast::channel(8);
        let watched = PathBuf::from("/tmp/test-home/.claude/settings.json");
        let parser = ScriptedParser {
            tool: AiTool::ClaudeCode,
            scope: AiGuardScope::UserGlobal,
            pack_id: None,
            tool_label: None,
            scripts: StdMutex::new(vec![
                vec![AiGuardReason::PermissionsDenyEmpty], // boot: toggle off
                vec![AiGuardReason::SandboxDisabled],      // change: toggle on
            ]),
            watched: vec![watched.clone()],
        };
        let (ctx, mut events) = ctx_with(parser, fc_rx, Duration::from_secs(24 * 3600));
        let h = tokio::spawn(run(ctx));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(10)).await;
        // Boot: AiGuardRiskAssessed only, no drift.
        let boot = events.recv().await.expect("boot");
        assert!(matches!(
            boot.event.evidence,
            Evidence::AiGuardRiskAssessed { .. }
        ));

        tx.send(watched).unwrap();
        tokio::time::advance(Duration::from_millis(50)).await;

        // The change cycle emits a drift event AND an AiGuardRiskAssessed.
        // Collect both (order: drift is sent before the risk event).
        let mut saw_drift = None;
        let mut saw_risk = false;
        for _ in 0..2 {
            let ev = tokio::time::timeout(Duration::from_millis(100), events.recv())
                .await
                .expect("event available")
                .expect("event");
            match ev.event.evidence {
                Evidence::AiGuardToggleDrift { toggle, .. } => saw_drift = Some(toggle),
                Evidence::AiGuardRiskAssessed { .. } => saw_risk = true,
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(saw_drift.as_deref(), Some("sandbox_disabled"));
        assert!(saw_risk, "drift is IN ADDITION to AiGuardRiskAssessed");
        h.abort();
    }
}
