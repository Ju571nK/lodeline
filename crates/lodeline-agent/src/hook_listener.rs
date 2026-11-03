//! Hook IPC listener (`hook.sock` on Unix, a named pipe on Windows). One-way: the agent reads `HookEnvelope`
//! JSON lines from AI hook emitters (lodeline-hook) and converts them to
//! `CommittableEvent` entries in the event sink. The emitter never reads a
//! response — `hook.sock` is write-only from the client's perspective.
//!
//! Security model (spec §9): DAC perms (0660) are the access gate.
//! `SO_PEERCRED` is read to stamp the kernel-verified peer uid onto the event
//! for attribution — it is NOT used to accept/reject connections.
//!
//! Concurrency: a `Semaphore` bounds inflight connections. When saturated the
//! connection is dropped BEFORE reading (never hold an fd open waiting on a
//! full sink). `try_send` is used so a full event channel never blocks the
//! listener loop.

use crate::hook_event::{enum_str, to_event};
use crate::state_task::CommittableEvent;
use lodeline_core::event::{
    Evidence, HookConfigDriftEvidence, Severity, SourceKind, Subject, AGENT_VERSION, SCHEMA_VERSION,
};
use lodeline_core::hook_proto::{
    HookConfigDriftReport, HookDriftEnvelope, HookEnvelope, HookMsgType,
};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::sync::{mpsc, Semaphore};

/// Maximum concurrent in-flight connections.
const MAX_INFLIGHT: usize = 32;

/// Maximum bytes read per connection before giving up (1 MiB).
const MAX_LINE: u64 = 1024 * 1024;

/// Bind `socket`, set 0o660 permissions, and start the accept loop.
///
/// Each accepted connection is handled in its own `tokio::spawn`ed task.
/// When `MAX_INFLIGHT` slots are all occupied the new connection is dropped
/// immediately without reading (a debug log records it). On parse success the
/// resulting `CommittableEvent` is sent with `try_send` — if the channel is
/// full the event is silently dropped rather than blocking.
///
/// This function runs until the tokio runtime shuts down (it does not return
/// under normal operation).
#[cfg(unix)]
pub async fn serve(
    socket: PathBuf,
    tx: mpsc::Sender<CommittableEvent>,
    host_id: String,
    activity_map: crate::hook_silence::ActivityMap,
) -> std::io::Result<()> {
    serve_until(
        socket,
        tx,
        host_id,
        activity_map,
        tokio_util::sync::CancellationToken::new(),
    )
    .await
}

#[cfg(unix)]
pub async fn serve_until(
    socket: PathBuf,
    tx: mpsc::Sender<CommittableEvent>,
    host_id: String,
    activity_map: crate::hook_silence::ActivityMap,
    shutdown: tokio_util::sync::CancellationToken,
) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    // Remove a stale socket file from a previous run.
    if socket.exists() {
        let _ = std::fs::remove_file(&socket);
    }
    // Ensure parent directory exists.
    if let Some(p) = socket.parent() {
        std::fs::create_dir_all(p)?;
    }

    let listener = UnixListener::bind(&socket)?;
    let _socket_file = crate::ipc_lifecycle::SocketFile::new(&socket)?;
    let mut connections = crate::ipc_lifecycle::Connections::default();
    // Set 0660 explicitly — do not rely on process umask.
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660))?;

    let sem = Arc::new(Semaphore::new(MAX_INFLIGHT));
    tracing::info!(path = ?socket, "hook IPC listening");

    loop {
        let Some(accepted) = connections.accept(listener.accept(), &shutdown).await else {
            break;
        };
        let (stream, _) = match accepted {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = ?e, "hook accept failed");
                continue;
            }
        };

        // Overload check: try to acquire a permit BEFORE reading anything.
        // If the semaphore is exhausted, drop the connection without reading.
        let permit = match sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::debug!("hook overload: dropping connection (MAX_INFLIGHT reached)");
                drop(stream);
                continue;
            }
        };

        // Read SO_PEERCRED now, while we still own the stream. On failure
        // (e.g., abstract-namespace socket on old kernels) fall back to u32::MAX
        // so the event is still recorded with an obviously-sentinel uid.
        let peer_uid = stream.peer_cred().map(|c| c.uid()).unwrap_or(u32::MAX);

        let tx = tx.clone();
        let host_id = host_id.clone();
        let activity_map = activity_map.clone();

        connections.spawn(async move {
            // Permit is held for the lifetime of this task.
            let _permit = permit;
            handle_hook_conn(stream, peer_uid, tx, host_id, activity_map).await;
        });
    }
    drop(listener);
    connections.drain().await
}

/// Windows hook listener over a named pipe. Mirrors the Unix listener above;
/// the per-connection logic is shared via `handle_hook_conn`. Windows named
/// pipes carry no peer uid, so the caller is recorded as `u32::MAX`.
///
/// If the pipe name stays taken through the retries this logs an error and
/// returns `Ok(())`: the agent keeps running without the hook pipe, and hooks
/// fail open.
#[cfg(windows)]
pub async fn serve_pipe_until(
    pipe_name: String,
    tx: mpsc::Sender<CommittableEvent>,
    host_id: String,
    activity_map: crate::hook_silence::ActivityMap,
    shutdown: tokio_util::sync::CancellationToken,
) -> std::io::Result<()> {
    let first = match crate::win_pipe::claim(&pipe_name, &shutdown).await {
        Ok(Some(server)) => server,
        Ok(None) => return Ok(()),
        Err(error) => {
            tracing::error!(pipe = %pipe_name, %error, "hook pipe unavailable; running without hook events");
            return Ok(());
        }
    };
    let sem = Arc::new(Semaphore::new(MAX_INFLIGHT));
    tracing::info!(pipe = %pipe_name, "hook IPC listening");
    let mut connections = crate::ipc_lifecycle::Connections::default();
    let open_next = || match crate::win_pipe::next_instance(&pipe_name) {
        Ok(server) => Some(server),
        Err(error) => {
            tracing::warn!(pipe = %pipe_name, %error, "hook pipe instance create failed; retrying");
            None
        }
    };
    let mut next = Some(first);
    loop {
        let Some(server) = next.take() else {
            if pipe_backoff(&shutdown).await {
                break;
            }
            next = open_next();
            continue;
        };
        let Some(connected) = connections.accept(server.connect(), &shutdown).await else {
            break;
        };
        // Open the next instance before handling this one, so a hook that
        // arrives meanwhile finds the pipe listening instead of busy.
        next = open_next();
        if let Err(error) = connected {
            tracing::warn!(%error, "hook pipe connect failed");
            if pipe_backoff(&shutdown).await {
                break;
            }
            continue;
        }
        let permit = match sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::debug!("hook overload: dropping connection (MAX_INFLIGHT reached)");
                continue;
            }
        };
        let tx = tx.clone();
        let host_id = host_id.clone();
        let activity_map = activity_map.clone();
        connections.spawn(async move {
            let _permit = permit;
            // A client that never writes must not hold its permit forever.
            let _ = tokio::time::timeout(
                PIPE_READ_TIMEOUT,
                handle_hook_conn(server, u32::MAX, tx, host_id, activity_map),
            )
            .await;
        });
    }
    drop(next);
    connections.drain().await
}

#[cfg(windows)]
const PIPE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Short pause after a pipe error so a persistent failure does not spin.
/// Returns true when shutdown was requested meanwhile.
#[cfg(windows)]
async fn pipe_backoff(shutdown: &tokio_util::sync::CancellationToken) -> bool {
    tokio::select! {
        _ = shutdown.cancelled() => true,
        _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => false,
    }
}

/// Transport-independent per-connection handler shared by the Unix-socket and
/// Windows-named-pipe listeners: read one bounded envelope line, record hook
/// activity, and queue the event. `peer_uid` is the caller's uid on Unix,
/// `u32::MAX` where the transport carries no peer credential.
async fn handle_hook_conn<S>(
    stream: S,
    peer_uid: u32,
    tx: mpsc::Sender<CommittableEvent>,
    host_id: String,
    activity_map: crate::hook_silence::ActivityMap,
) where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut line = String::new();
    // Limit bytes read to guard against a misbehaving / malicious sender
    // filling memory. `take` wraps the raw stream; BufReader sits on top.
    let mut rd = BufReader::new(stream.take(MAX_LINE));
    if rd.read_line(&mut line).await.is_err() {
        return;
    }

    let line = line.trim();
    let kind = serde_json::from_str::<MsgTypeHeader>(line)
        .ok()
        .map(|h| h.msg_type);
    let committable = match kind {
        Some(HookMsgType::DriftReport) => match serde_json::from_str::<HookDriftEnvelope>(line) {
            Ok(env) => CommittableEvent {
                event: to_drift_event(env, peer_uid, &host_id),
                new_hash: None,
                path_for_db: PathBuf::new(),
                target_id: String::new(),
            },
            Err(e) => {
                tracing::debug!(error = ?e, "hook: malformed drift report; dropping");
                return;
            }
        },
        Some(HookMsgType::HookInvocation) | None => {
            // observe (hook_invocation), and legacy senders with no msg_type field — existing path, unchanged.
            let env: HookEnvelope = match serde_json::from_str(line) {
                Ok(e) => e,
                Err(e) => {
                    tracing::debug!(error = ?e, "hook: malformed envelope; dropping");
                    return;
                }
            };
            // D6: record BEFORE try_send so a dropped-on-backpressure
            // observation never becomes false silence.
            crate::hook_silence::record_hook_event(
                &activity_map,
                env.payload.agent,
                peer_uid,
                time::OffsetDateTime::now_utc(),
            );
            CommittableEvent {
                event: to_event(env, peer_uid, &host_id),
                new_hash: None,
                path_for_db: PathBuf::new(),
                target_id: String::new(),
            }
        }
        Some(other) => {
            // DecisionRequest/DecisionResponse belong on hook-decide.sock, not here; any other type is unhandled on the observe socket.
            tracing::debug!(?other, "hook: unhandled msg_type on hook.sock; dropping");
            return;
        }
    };

    // try_send: if the channel is full (sink backpressure) we drop rather
    // than block. The listener must remain responsive to new connections.
    if tx.try_send(committable).is_err() {
        tracing::debug!("hook: event channel full; dropping hook event");
    }
}

#[derive(serde::Deserialize)]
struct MsgTypeHeader {
    msg_type: HookMsgType,
}

/// Convert a decoded `HookDriftEnvelope` + kernel-verified `peer_uid` into a
/// `HookConfigDrift` Event for the sink pipeline.
pub(crate) fn to_drift_event(
    env: HookDriftEnvelope,
    peer_uid: u32,
    host_id: &str,
) -> lodeline_core::event::Event {
    // envelope metadata (protocol_version/request_id/sent_at) is intentionally not threaded into the event, matching to_event.
    let r: HookConfigDriftReport = env.payload;
    lodeline_core::event::Event {
        schema_version: SCHEMA_VERSION,
        event_id: uuid::Uuid::now_v7(),
        ts: time::OffsetDateTime::now_utc(),
        host_id: host_id.to_string(),
        agent_version: AGENT_VERSION.to_string(),
        severity: Severity::Warn,
        source: SourceKind::AgentHook,
        subject: Subject::Self_,
        evidence: Evidence::HookConfigDrift(HookConfigDriftEvidence {
            agent: r.agent,
            peer_uid,
            drift_kind: enum_str(&r.drift_kind),
            settings_path: r.settings_path,
            expected_command_hash: r.expected_command_hash,
            observed_command_hash: r.observed_command_hash,
            expected_matcher: r.expected_matcher,
            observed_matcher: r.observed_matcher,
        }),
        target_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn handler_records_an_invocation_line_from_any_stream() {
        use lodeline_core::event::AiTool;
        use lodeline_core::hook_proto::{
            CaptureLevel, CaptureStatus, HookAction, HookInvocation, HOOK_PROTOCOL_VERSION,
        };
        let env = HookEnvelope {
            protocol_version: HOOK_PROTOCOL_VERSION,
            msg_type: HookMsgType::HookInvocation,
            request_id: uuid::Uuid::now_v7(),
            sent_at_unix_ms: 0,
            payload: HookInvocation {
                agent: AiTool::ClaudeCode,
                agent_session_id: None,
                tool_use_id: None,
                action: HookAction::Bash {
                    command_hash: "ab".repeat(32),
                    command_preview: Some("git status".into()),
                },
                capture_level: CaptureLevel::Redacted,
                capture_status: CaptureStatus::Ok,
                cwd: None,
            },
        };
        let line = format!("{}\n", serde_json::to_string(&env).unwrap());
        let (tx, mut rx) = mpsc::channel(4);
        let map = crate::hook_silence::new_map();

        handle_hook_conn(line.as_bytes(), 77, tx, "host-x".into(), map.clone()).await;

        let ev = rx.try_recv().expect("one event queued").event;
        assert_eq!(ev.host_id, "host-x");
        match ev.evidence {
            Evidence::HookInvocation(h) => {
                assert_eq!(h.peer_uid, 77);
                assert_eq!(h.action_kind, "bash");
            }
            other => panic!("expected HookInvocation, got {other:?}"),
        }
        assert!(
            map.lock().contains_key(&(AiTool::ClaudeCode, 77)),
            "silence tracking saw the hook"
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn hook_pipe_name_in_use_leaves_the_agent_running() {
        let name = format!(
            r"\\.\pipe\lodeline-hook-taken-{}",
            uuid::Uuid::new_v4().simple()
        );
        let _other = tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(true)
            .create(&name)
            .unwrap();
        let (tx, _rx) = mpsc::channel(1);
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            serve_pipe_until(
                name,
                tx,
                "host-x".into(),
                crate::hook_silence::new_map(),
                tokio_util::sync::CancellationToken::new(),
            ),
        )
        .await
        .expect("listener gives up on a taken name instead of waiting");
        // The supervisor stops the whole agent only when a tracked task returns Err.
        assert!(
            result.is_ok(),
            "a taken hook pipe name must not stop the agent: {result:?}"
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn hook_pipe_name_freed_during_retries_is_served() {
        use lodeline_core::hook_proto::PIPE_CLIENT_ACCESS;
        use std::os::windows::fs::OpenOptionsExt;
        let name = format!(
            r"\\.\pipe\lodeline-hook-freed-{}",
            uuid::Uuid::new_v4().simple()
        );
        let other = tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(true)
            .create(&name)
            .unwrap();
        let (tx, _rx) = mpsc::channel(1);
        let listener = tokio::spawn(serve_pipe_until(
            name.clone(),
            tx,
            "host-x".into(),
            crate::hook_silence::new_map(),
            tokio_util::sync::CancellationToken::new(),
        ));
        tokio::time::sleep(crate::win_pipe::NAME_IN_USE_WAIT).await;
        drop(other);
        tokio::task::spawn_blocking(move || {
            (0..500)
                .find_map(|_| {
                    let opened = std::fs::OpenOptions::new()
                        .access_mode(PIPE_CLIENT_ACCESS)
                        .open(&name);
                    if opened.is_err() {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    opened.ok()
                })
                .expect("hook opens the hook pipe with the client access mask")
        })
        .await
        .unwrap();
        assert!(
            !listener.is_finished(),
            "listener serves after the name frees"
        );
    }

    #[test]
    fn drift_report_becomes_hook_config_drift_event() {
        use lodeline_core::hook_proto::{
            DriftKind, HookConfigDriftReport, HookDriftEnvelope, HookMsgType, HOOK_PROTOCOL_VERSION,
        };
        let env = HookDriftEnvelope {
            protocol_version: HOOK_PROTOCOL_VERSION,
            msg_type: HookMsgType::DriftReport,
            request_id: uuid::Uuid::now_v7(),
            sent_at_unix_ms: 0,
            payload: HookConfigDriftReport {
                agent: lodeline_core::event::AiTool::ClaudeCode,
                drift_kind: DriftKind::MatcherDrift,
                settings_path: "/s".into(),
                expected_command_hash: "ab".repeat(32),
                observed_command_hash: Some("cd".repeat(32)),
                expected_matcher: Some("*".into()),
                observed_matcher: Some("Bash".into()),
            },
        };
        let ev = to_drift_event(env, 501, "host-x");
        match ev.evidence {
            Evidence::HookConfigDrift(d) => {
                assert_eq!(d.drift_kind, "matcher_drift");
                assert_eq!(d.peer_uid, 501);
                assert_eq!(d.observed_matcher.as_deref(), Some("Bash"));
            }
            other => panic!("expected HookConfigDrift, got {other:?}"),
        }
        assert!(matches!(ev.severity, Severity::Warn));
    }
}
