//! Control IPC: UDS on Unix, Named Pipe on Windows.
//!
//! Phase 1 supports a single command: `{"cmd":"stats"}` returning the current
//! Heartbeat-equivalent payload as JSON.

use lodeline_core::stats::Stats;
use parking_lot::RwLock;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use crate::policy_apply::{apply, apply_rule_packs, ApplyContext, ApplyOutcome};

// The control-socket wire protocol now lives in `lodeline-core::control_proto`, so
// `lodeline-mcp` (local-mode client) can share the contract without depending on
// this crate. Re-exported here so existing `crate::control::{...}` paths keep
// working.
pub use lodeline_core::control_proto::{
    ApplyPolicyResult, AssessVerdict, DoctorAiGuardReport, ExtScriptSummary, FailedSource,
    ParserInfo, PerRepoSummary, PolicyStatusPayload, Request, Response, RiskPayload, RiskSummary,
    RubricEntry, RulePackInfo, TargetSummary, TargetsPayload,
};

/// Default control-socket path. As root, the system path `/var/run/lodeline`
/// (matches the systemd unit's `RuntimeDirectory=`). A non-root agent (macOS,
/// non-root Linux — e.g. the 2-machine test) can't write there, so fall back
/// to `$XDG_RUNTIME_DIR/lodeline` (else `$TMPDIR`/`/tmp/lodeline-<uid>`), keeping the
/// control plane usable without elevation. Override with `--control-socket`.
/// `lodeline run` binds it; `lodeline show stats` and `lodeline-sender` connect to it.
/// On Windows the named pipe is used instead and this value is ignored.
///
/// The pure branch logic lives in `lodeline_core::control_proto::resolve_control_socket`;
/// this wrapper supplies the euid/root/XDG/TMPDIR inputs.
pub fn default_control_socket() -> PathBuf {
    lodeline_core::control_proto::resolve_control_socket(
        is_root(),
        std::env::var("XDG_RUNTIME_DIR")
            .ok()
            .filter(|s| !s.is_empty()),
        std::env::var("TMPDIR").ok().filter(|s| !s.is_empty()),
        current_uid(),
    )
}

/// True when the process effective uid is 0 (root). Non-Unix: always false.
/// Also consulted by the keystore default in `runtime`.
#[cfg(unix)]
pub(crate) fn is_root() -> bool {
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}
#[cfg(not(unix))]
pub(crate) fn is_root() -> bool {
    false
}

/// True when this process assesses the other users' homes: root on Unix, the LocalSystem
/// account (`S-1-5-18`, a service) on Windows.
#[cfg(unix)]
pub(crate) fn assesses_other_users() -> bool {
    is_root()
}
#[cfg(windows)]
pub(crate) fn assesses_other_users() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, IsWellKnownSid, TokenUser, WinLocalSystemSid, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: `token` is a valid out pointer; the handle is closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return false;
    }
    let mut len = 0u32;
    // SAFETY: a null buffer with length 0 asks for the needed size.
    unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len) };
    // u64 words keep the buffer aligned for TOKEN_USER.
    let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
    // SAFETY: `buf` holds at least `len` bytes.
    let ok =
        unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) }
            != 0;
    let system = ok && {
        // SAFETY: on success the buffer starts with a TOKEN_USER whose SID points inside it.
        let user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
        let is_system = unsafe { IsWellKnownSid(user.User.Sid, WinLocalSystemSid) };
        is_system != 0
    };
    // SAFETY: `token` came from OpenProcessToken.
    unsafe { CloseHandle(token) };
    system
}
#[cfg(not(any(unix, windows)))]
pub(crate) fn assesses_other_users() -> bool {
    false
}

/// Process real uid — namespaces the fallback socket dir in shared `/tmp`.
/// Non-Unix: 0 (unused; Windows uses the named pipe).
#[cfg(unix)]
fn current_uid() -> u32 {
    // SAFETY: `getuid` has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}
#[cfg(not(unix))]
fn current_uid() -> u32 {
    0
}

/// Default control named-pipe name on Windows.
pub fn default_control_pipe_name() -> String {
    lodeline_core::control_proto::DEFAULT_CONTROL_PIPE.to_string()
}

/// Default hook-decide named-pipe name on Windows (#162) — the enforce IPC the
/// `lodeline-hook` client connects to, parallel to the control pipe. Mirrors the
/// Unix `<control-socket-dir>/hook-decide.sock` default.
#[cfg(windows)]
pub fn default_hook_decide_pipe_name() -> String {
    r"\\.\pipe\lodeline-hook-decide".to_string()
}

/// Shared context bundle passed to both platform `serve` functions.
pub struct ControlContext {
    pub stats: Arc<Stats>,
    pub apply_ctx: Arc<ApplyContext>,
    /// Used by `PolicyStatus` to read the active envelope's `valid_until`.
    /// Set by the `policy_expiry_task` (Task A6.4) on each successful apply.
    pub active_valid_until: Arc<RwLock<Option<time::OffsetDateTime>>>,
    /// Live snapshot of the active compiled-target set. Read by the `Targets`
    /// handler. Updated by `policy_reload_task` on each `apply_policy`.
    #[cfg(feature = "operator-cli")]
    pub targets_rx:
        tokio::sync::watch::Receiver<std::sync::Arc<Vec<crate::normalizer::CompiledTarget>>>,
    #[cfg(feature = "operator-cli")]
    pub ai_guard_state: std::sync::Arc<parking_lot::RwLock<crate::ai_guard::StateMap>>,
    /// Phase 3b.5 — needed by DoctorAiGuardReport handler.
    #[cfg(feature = "operator-cli")]
    pub parsers: std::sync::Arc<
        parking_lot::RwLock<Vec<std::sync::Arc<dyn crate::ai_guard::parser::AiGuardParser>>>,
    >,
    #[cfg(feature = "operator-cli")]
    pub ext_scripts: crate::ai_guard::ExtScriptRegistry,
    #[cfg(feature = "operator-cli")]
    pub rubric: crate::ai_guard::RubricHandle,
    /// Phase 3b.9 (#149) — hot-swappable deny evaluator for `Request::Assess`.
    /// Snapshot-cloned (inner `Arc`) per request, never held across await.
    #[cfg(feature = "operator-cli")]
    pub deny: crate::hook_deny::SharedEvaluator,
    /// The home the AI Guard parsers assess, as `run` resolved it (`--pin-user-home` first).
    #[cfg(feature = "operator-cli")]
    pub home_dir: std::path::PathBuf,
}

#[cfg(feature = "operator-cli")]
fn parser_infos(
    parsers: &[std::sync::Arc<dyn crate::ai_guard::parser::AiGuardParser>],
    home_dir: &std::path::Path,
) -> Vec<ParserInfo> {
    parsers
        .iter()
        .map(|p| ParserInfo {
            tool: p.tool(),
            scope: p.scope(),
            watched_path_count: p.watched_paths(home_dir).len(),
        })
        .collect()
}

#[cfg(feature = "operator-cli")]
fn rfc3339(ts: time::OffsetDateTime) -> String {
    ts.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

#[cfg(feature = "operator-cli")]
pub(crate) fn risk_summary(
    (tool, scope, _pid, user): &crate::ai_guard::task::StateKey,
    source: &crate::ai_guard::task::SourceState,
) -> Option<RiskSummary> {
    let cached = source.reading.as_ref()?;
    let last = rfc3339(cached.last_assessed_ts);
    Some(RiskSummary {
        controls: cached.controls.clone(),
        tool: tool.clone(),
        scope: scope.clone(),
        score: cached.score,
        bucket: cached.bucket.clone(),
        reasons_count: cached.reasons_count,
        last_assessed_ts: last,
        user: user.clone(),
        config_found: cached.config_found,
        reason_kinds: cached.reason_kinds.clone(),
    })
}

#[cfg(feature = "operator-cli")]
pub(crate) fn failed_source(
    (tool, scope, _pid, user): &crate::ai_guard::task::StateKey,
    source: &crate::ai_guard::task::SourceState,
) -> Option<FailedSource> {
    let failure = source.failure.as_ref()?;
    Some(FailedSource {
        tool: tool.clone(),
        scope: scope.clone(),
        user: user.clone(),
        error_kind: failure.error_kind.to_string(),
        path: failure.path.clone(),
        failing_since: rfc3339(failure.since),
        last_assessed_ts: source.reading.as_ref().map(|r| rfc3339(r.last_assessed_ts)),
    })
}

#[cfg(feature = "operator-cli")]
fn tool_key(tool: &lodeline_core::event::AiTool) -> String {
    serde_json::to_string(tool).unwrap_or_default()
}

#[cfg(feature = "operator-cli")]
pub(crate) fn risk_payload(
    state: &crate::ai_guard::task::StateMap,
    tool: Option<lodeline_core::event::AiTool>,
) -> RiskPayload {
    let mut assessments: Vec<RiskSummary> = state
        .iter()
        .filter(|((t, _scope, _pid, _user), _)| tool.as_ref().is_none_or(|filter| t == filter))
        .filter_map(|(key, source)| risk_summary(key, source))
        .collect();
    assessments.sort_by(|a, b| {
        serde_json::to_string(&a.tool)
            .unwrap_or_default()
            .cmp(&serde_json::to_string(&b.tool).unwrap_or_default())
    });
    let mut failed_sources: Vec<FailedSource> = state
        .iter()
        .filter(|((t, _scope, _pid, _user), _)| tool.as_ref().is_none_or(|filter| t == filter))
        .filter_map(|(key, source)| failed_source(key, source))
        .collect();
    failed_sources.sort_by(|a, b| {
        (tool_key(&a.tool), &a.user, &a.path).cmp(&(tool_key(&b.tool), &b.user, &b.path))
    });
    RiskPayload {
        assessments,
        failed_sources,
    }
}

/// Shared dispatch logic. Returns the `Response` for a given `Request`.
/// Both platform `serve` functions call this to avoid duplicating logic.
async fn handle(ctx: &ControlContext, req: Request) -> Response {
    match req {
        Request::Stats => Response {
            ok: true,
            stats: Some(ctx.stats.snapshot()),
            apply_policy: None,
            policy_status: None,
            targets: None,
            risk: None,
            doctor_ai_guard: None,
            assess_verdict: None,
            error: None,
        },
        Request::ApplyPolicy { response } => {
            let outcome = apply(&ctx.apply_ctx, &response).await;
            match outcome {
                ApplyOutcome::Accepted {
                    applied_policy_version,
                } => Response {
                    ok: true,
                    stats: None,
                    apply_policy: Some(ApplyPolicyResult::Accepted {
                        applied_policy_version,
                    }),
                    policy_status: None,
                    targets: None,
                    risk: None,
                    doctor_ai_guard: None,
                    assess_verdict: None,
                    error: None,
                },
                ApplyOutcome::Rejected { reason } => Response {
                    ok: false,
                    stats: None,
                    apply_policy: Some(ApplyPolicyResult::Rejected { reason }),
                    policy_status: None,
                    targets: None,
                    risk: None,
                    doctor_ai_guard: None,
                    assess_verdict: None,
                    error: None,
                },
                ApplyOutcome::Internal { detail } => Response {
                    ok: false,
                    stats: None,
                    apply_policy: None,
                    policy_status: None,
                    targets: None,
                    risk: None,
                    doctor_ai_guard: None,
                    assess_verdict: None,
                    error: Some(format!("internal: {detail}")),
                },
            }
        }
        Request::ApplyRulePacks { response } => {
            // Mirror the ApplyPolicy response shaping so the sender's `resp.ok`
            // check works identically. The rule-packs apply advances the
            // SEPARATE watermark; it never touches policy.yaml.
            let outcome = apply_rule_packs(&ctx.apply_ctx, &response).await;
            match outcome {
                ApplyOutcome::Accepted {
                    applied_policy_version,
                } => Response {
                    ok: true,
                    stats: None,
                    apply_policy: Some(ApplyPolicyResult::Accepted {
                        applied_policy_version,
                    }),
                    policy_status: None,
                    targets: None,
                    risk: None,
                    doctor_ai_guard: None,
                    assess_verdict: None,
                    error: None,
                },
                ApplyOutcome::Rejected { reason } => Response {
                    ok: false,
                    stats: None,
                    apply_policy: Some(ApplyPolicyResult::Rejected { reason }),
                    policy_status: None,
                    targets: None,
                    risk: None,
                    doctor_ai_guard: None,
                    assess_verdict: None,
                    error: None,
                },
                ApplyOutcome::Internal { detail } => Response {
                    ok: false,
                    stats: None,
                    apply_policy: None,
                    policy_status: None,
                    targets: None,
                    risk: None,
                    doctor_ai_guard: None,
                    assess_verdict: None,
                    error: Some(format!("internal: {detail}")),
                },
            }
        }
        Request::PolicyStatus => {
            let last_applied = ctx
                .apply_ctx
                .cache
                .lock()
                .host_meta_get()
                .map(|m| m.policy.version())
                .unwrap_or(0);
            let valid_until_snapshot = *ctx.active_valid_until.read();
            let valid_until_str = valid_until_snapshot.and_then(|t| {
                t.format(&time::format_description::well_known::Rfc3339)
                    .ok()
            });
            let expired = valid_until_snapshot
                .map(|t| time::OffsetDateTime::now_utc() >= t)
                .unwrap_or(false);
            Response {
                ok: true,
                stats: None,
                apply_policy: None,
                policy_status: Some(PolicyStatusPayload {
                    last_applied_policy_version: last_applied,
                    active_envelope_valid_until: valid_until_str,
                    policy_expired_active: expired,
                }),
                targets: None,
                risk: None,
                doctor_ai_guard: None,
                assess_verdict: None,
                error: None,
            }
        }
        #[cfg(feature = "operator-cli")]
        Request::Targets => {
            let snapshot = ctx.targets_rx.borrow().clone();
            let summaries = snapshot
                .iter()
                .map(|t| TargetSummary {
                    id: t.id.clone(),
                    tier: t.tier,
                    globs: t.globs.iter().map(|g| g.pattern().to_string()).collect(),
                })
                .collect();
            Response {
                ok: true,
                stats: None,
                apply_policy: None,
                policy_status: None,
                targets: Some(TargetsPayload { targets: summaries }),
                risk: None,
                doctor_ai_guard: None,
                assess_verdict: None,
                error: None,
            }
        }
        #[cfg(feature = "operator-cli")]
        Request::ReloadPolicy => {
            // send_modify always notifies receivers, even with no value change —
            // policy_reload_task wakes and re-reads policy.yaml from disk.
            ctx.apply_ctx.policy_version_tx.send_modify(|_| {});
            Response {
                ok: true,
                stats: None,
                apply_policy: None,
                policy_status: None,
                targets: None,
                risk: None,
                doctor_ai_guard: None,
                assess_verdict: None,
                error: None,
            }
        }
        #[cfg(feature = "operator-cli")]
        Request::Risk { tool } => {
            let payload = risk_payload(&ctx.ai_guard_state.read(), tool);
            Response {
                ok: true,
                stats: None,
                apply_policy: None,
                policy_status: None,
                targets: None,
                risk: Some(payload),
                doctor_ai_guard: None,
                assess_verdict: None,
                error: None,
            }
        }
        #[cfg(feature = "operator-cli")]
        Request::DoctorAiGuardReport => {
            // Parsers snapshot (clone the Arc list — small).
            let parsers_snapshot: Vec<std::sync::Arc<dyn crate::ai_guard::parser::AiGuardParser>> =
                ctx.parsers.read().clone();
            let parsers = parser_infos(&parsers_snapshot, &ctx.home_dir);

            // Per-repo summary — derive from parsers' scopes.
            let mut per_repo = PerRepoSummary::default();
            for p in &parsers_snapshot {
                if let lodeline_core::event::AiGuardScope::Project { .. } = p.scope() {
                    match p.tool() {
                        lodeline_core::event::AiTool::ContinueDev => per_repo.continue_dev += 1,
                        lodeline_core::event::AiTool::ClaudeCode => per_repo.claude_code += 1,
                        lodeline_core::event::AiTool::Codex => per_repo.codex += 1,
                        _ => {}
                    }
                }
            }

            // Rule packs — downcast via as_any() to identify RulePackParser.
            let mut rule_packs: Vec<RulePackInfo> = Vec::new();
            for p in &parsers_snapshot {
                if let Some(rpp) = p
                    .as_any()
                    .downcast_ref::<crate::ai_guard::rule_pack::parser::RulePackParser>()
                {
                    rule_packs.push(RulePackInfo {
                        id: rpp.pack.id.clone(),
                        loaded: true,
                        skip_reason: None,
                    });
                }
            }

            // Ext-script summary.
            let ext_map = ctx.ext_scripts.read();
            let mut unique: std::collections::BTreeSet<std::path::PathBuf> =
                std::collections::BTreeSet::new();
            let parser_entries = ext_map.len();
            for v in ext_map.values() {
                for (_, p) in v {
                    unique.insert(p.clone());
                }
            }
            drop(ext_map);
            let ext_scripts_summary = ExtScriptSummary {
                unique_paths: unique.len(),
                parser_entries,
            };

            // Latest risk — same shape as Risk handler.
            let snapshot = ctx.ai_guard_state.read();
            let mut latest_risk: Vec<RiskSummary> = snapshot
                .iter()
                .filter_map(|(key, source)| risk_summary(key, source))
                .collect();
            drop(snapshot);
            latest_risk.sort_by(|a, b| {
                serde_json::to_string(&a.tool)
                    .unwrap_or_default()
                    .cmp(&serde_json::to_string(&b.tool).unwrap_or_default())
            });

            // Effective rubric.
            let rubric_snapshot = ctx.rubric.read().clone();
            let mut effective_rubric: Vec<RubricEntry> = rubric_snapshot
                .weights
                .iter()
                .map(|(k, w)| RubricEntry {
                    kind_key: k.to_string(),
                    weight: *w,
                    overridden: rubric_snapshot.overridden.contains(k),
                })
                .collect();
            // Sort: weight DESC then kind_key alpha for stable display.
            effective_rubric.sort_by(|a, b| {
                b.weight
                    .partial_cmp(&a.weight)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| a.kind_key.cmp(&b.kind_key))
            });

            Response {
                ok: true,
                stats: None,
                apply_policy: None,
                policy_status: None,
                targets: None,
                risk: None,
                doctor_ai_guard: Some(DoctorAiGuardReport {
                    parsers,
                    per_repo,
                    rule_packs,
                    ext_scripts: ext_scripts_summary,
                    latest_risk,
                    effective_rubric,
                    unknown_override_keys: rubric_snapshot.unknown_override_keys.clone(),
                }),
                assess_verdict: None,
                error: None,
            }
        }
        // Phase 3b.9 (#149) — assess: evaluate a proposed command or MCP server
        // definition against the LIVE loaded policy.
        #[cfg(feature = "operator-cli")]
        Request::Assess { input } => {
            // Snapshot-clone the rubric and deny evaluator under short read
            // guards BEFORE any evaluation so a concurrent reload cannot change
            // the result mid-flight.
            let rubric_snapshot = ctx.rubric.read().clone();
            // Inner Arc clone — cheap, no deep copy of compiled regexes.
            let deny_snapshot = ctx.deny.read().clone();
            let enforce_bucket = lodeline_core::event::AiGuardBucket::High;
            let ctx_assess = crate::ai_guard::assess::AssessCtx {
                rubric: &rubric_snapshot,
                deny: &deny_snapshot,
                enforce_bucket,
            };
            let verdict = crate::ai_guard::assess::assess(&input, &ctx_assess);
            Response {
                ok: true,
                stats: None,
                apply_policy: None,
                policy_status: None,
                targets: None,
                risk: None,
                doctor_ai_guard: None,
                assess_verdict: Some(verdict),
                error: None,
            }
        }
        // The operator-cli request variants always exist on the wire (they live
        // in lodeline-core::control_proto), but their handlers compile only with
        // the `operator-cli` feature. In a hardened build without it, reject.
        #[cfg(not(feature = "operator-cli"))]
        Request::Targets
        | Request::ReloadPolicy
        | Request::Risk { .. }
        | Request::DoctorAiGuardReport
        | Request::Assess { .. } => Response {
            ok: false,
            stats: None,
            apply_policy: None,
            policy_status: None,
            targets: None,
            risk: None,
            doctor_ai_guard: None,
            assess_verdict: None,
            error: Some("operator-cli feature not enabled in this build".into()),
        },
    }
}

#[cfg(unix)]
pub async fn serve(socket_path: &Path, ctx: Arc<ControlContext>) -> std::io::Result<()> {
    serve_until(socket_path, ctx, tokio_util::sync::CancellationToken::new()).await
}

#[cfg(unix)]
pub async fn serve_until(
    socket_path: &Path,
    ctx: Arc<ControlContext>,
    shutdown: tokio_util::sync::CancellationToken,
) -> std::io::Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    if socket_path.exists() {
        let _ = std::fs::remove_file(socket_path);
    }
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(socket_path)?;
    let _socket_file = crate::ipc_lifecycle::SocketFile::new(socket_path)?;
    let mut connections = crate::ipc_lifecycle::Connections::default();
    // Lock the control socket to owner+group rw, no world access (issue #4). The
    // agent runs as root; group ownership (root by default; `lodeline` under the
    // future hardened install, epic #10) gates non-root control access. Set this
    // deterministically rather than relying on the process umask.
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))?;
    }
    tracing::info!(path = ?socket_path, "control IPC listening");
    loop {
        let Some(accepted) = connections.accept(listener.accept(), &shutdown).await else {
            break;
        };
        let (stream, _) = match accepted {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = ?e, "control IPC accept failed");
                continue;
            }
        };
        let ctx = ctx.clone();
        connections.spawn(async move {
            let (rd, mut wr) = stream.into_split();
            let mut reader = BufReader::new(rd);
            let mut line = String::new();
            if reader.read_line(&mut line).await.is_err() {
                return;
            }
            let resp = match serde_json::from_str::<Request>(line.trim()) {
                Ok(req) => handle(&ctx, req).await,
                Err(e) => Response {
                    ok: false,
                    stats: None,
                    apply_policy: None,
                    policy_status: None,
                    targets: None,
                    risk: None,
                    doctor_ai_guard: None,
                    assess_verdict: None,
                    error: Some(e.to_string()),
                },
            };
            if let Ok(json) = serde_json::to_string(&resp) {
                let _ = wr.write_all(json.as_bytes()).await;
                let _ = wr.write_all(b"\n").await;
            }
        });
    }
    drop(listener);
    connections.drain().await
}

#[cfg(windows)]
pub async fn serve(pipe_name: &str, ctx: Arc<ControlContext>) -> std::io::Result<()> {
    serve_until(pipe_name, ctx, tokio_util::sync::CancellationToken::new()).await
}

/// Windows control pipe. If another process still holds the name after the
/// retries, this returns an error that names the pipe and the agent exits,
/// because an agent without its control pipe would take no signed policy.
#[cfg(windows)]
pub async fn serve_until(
    pipe_name: &str,
    ctx: Arc<ControlContext>,
    shutdown: tokio_util::sync::CancellationToken,
) -> std::io::Result<()> {
    use crate::win_pipe::{claim, name_in_use, next_instance, CONTROL_SDDL};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let mut listening = match claim(pipe_name, CONTROL_SDDL, &shutdown).await {
        Ok(Some(server)) => server,
        Ok(None) => return Ok(()),
        Err(e) if name_in_use(&e) => {
            return Err(std::io::Error::new(
                e.kind(),
                format!("control pipe {pipe_name} is already in use by another process: {e}"),
            ))
        }
        Err(e) => return Err(e),
    };
    tracing::info!(pipe = %pipe_name, "control IPC listening");
    let mut connections = crate::ipc_lifecycle::Connections::default();
    loop {
        let Some(connected) = connections.accept(listening.connect(), &shutdown).await else {
            break;
        };
        connected?;
        // Open the next instance before handing this one off, so the name never lapses.
        let server = std::mem::replace(&mut listening, next_instance(pipe_name, CONTROL_SDDL)?);
        let ctx = ctx.clone();
        connections.spawn(async move {
            let (rd, mut wr) = tokio::io::split(server);
            let mut reader = BufReader::new(rd);
            let mut line = String::new();
            if reader.read_line(&mut line).await.is_err() {
                return;
            }
            let resp = match serde_json::from_str::<Request>(line.trim()) {
                Ok(req) => handle(&ctx, req).await,
                Err(e) => Response {
                    ok: false,
                    stats: None,
                    apply_policy: None,
                    policy_status: None,
                    targets: None,
                    risk: None,
                    doctor_ai_guard: None,
                    assess_verdict: None,
                    error: Some(e.to_string()),
                },
            };
            if let Ok(json) = serde_json::to_string(&resp) {
                let _ = wr.write_all(json.as_bytes()).await;
                let _ = wr.write_all(b"\n").await;
            }
        });
    }
    // Release the name before draining, so a restarting agent can claim it.
    drop(listening);
    connections.drain().await
}

#[cfg(all(test, feature = "operator-cli"))]
mod tests {
    use super::*;
    use crate::ai_guard::task::{CachedAssessment, SourceState};
    use lodeline_core::event::{AiGuardBucket, AiGuardScope, AiTool};

    fn source(config_found: Option<bool>) -> SourceState {
        SourceState {
            reading: Some(CachedAssessment {
                controls: None,
                controls_blake3: [0; 32],
                score: 0.0,
                bucket: AiGuardBucket::Low,
                reasons_blake3: [0; 32],
                reasons_count: 0,
                last_assessed_ts: time::OffsetDateTime::UNIX_EPOCH,
                dangerous_toggles: Default::default(),
                config_found,
                reason_kinds: Vec::new(),
            }),
            failure: None,
        }
    }

    fn found_in_reply(config_found: Option<bool>) -> Option<bool> {
        let key = (AiTool::Gemini, AiGuardScope::UserGlobal, None, None);
        risk_summary(&key, &source(config_found))
            .unwrap()
            .config_found
    }

    #[test]
    fn risk_reply_carries_the_cached_reason_kinds() {
        let mut state = source(None);
        state.reading.as_mut().unwrap().reason_kinds = vec!["no_sandbox".into(), "x".into()];
        let key = (AiTool::Gemini, AiGuardScope::UserGlobal, None, None);
        let reply = risk_summary(&key, &state).unwrap();
        assert_eq!(reply.reason_kinds, vec!["no_sandbox", "x"]);
    }

    #[test]
    fn risk_reply_carries_the_cached_config_found() {
        assert_eq!(found_in_reply(Some(false)), Some(false));
        assert_eq!(found_in_reply(Some(true)), Some(true));
        assert_eq!(found_in_reply(None), None);
    }

    #[cfg(feature = "operator-cli")]
    #[test]
    fn the_doctor_report_counts_each_parsers_paths_under_the_home_it_is_given() {
        use crate::ai_guard::parser::AiGuardParser;
        use lodeline_core::event::{AiGuardReason, AiGuardScope, AiTool};
        struct PerHome;
        impl AiGuardParser for PerHome {
            fn tool(&self) -> AiTool {
                AiTool::ClaudeCode
            }
            fn scope(&self) -> AiGuardScope {
                AiGuardScope::UserGlobal
            }
            fn watched_paths(&self, home: &std::path::Path) -> Vec<std::path::PathBuf> {
                home.components().map(|c| home.join(c)).collect()
            }
            fn assess(
                &self,
                _home: &std::path::Path,
            ) -> Result<Vec<AiGuardReason>, crate::ai_guard::parser::AssessError> {
                Ok(Vec::new())
            }
        }
        let parsers: Vec<std::sync::Arc<dyn AiGuardParser>> = vec![std::sync::Arc::new(PerHome)];
        let count = |home: &str| {
            super::parser_infos(&parsers, std::path::Path::new(home))[0].watched_path_count
        };
        assert_eq!(count("/pin"), 2);
        assert_eq!(count("/pin/deeper/home"), 4);
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    #[test]
    fn an_interactive_user_does_not_assess_other_users() {
        let account = std::env::var("USERNAME").unwrap_or_default();
        if account.ends_with('$') || account.eq_ignore_ascii_case("SYSTEM") {
            return;
        }
        assert!(!super::assesses_other_users());
    }
}
