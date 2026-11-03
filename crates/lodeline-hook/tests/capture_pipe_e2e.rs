//! Windows: capture mode delivers the hook event to the agent's hook pipe.
#![cfg(windows)]

use lodeline_core::event::{AiTool, Evidence};
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

const PAYLOAD: &str = r#"{"hook_event_name":"PreToolUse","session_id":"s1","tool_use_id":"t1",
    "tool_name":"Bash","tool_input":{"command":"git status"}}"#;

fn run_hook(pipe: &str, home: &std::path::Path) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lodeline-hook"))
        .arg("claude-code")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("LODELINE_HOOK_SOCKET", pipe)
        .env_remove("LODELINE_HOOK_TEST_SEAM")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn lodeline-hook");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(PAYLOAD.as_bytes())
        .unwrap();
    child.wait_with_output().expect("wait for lodeline-hook")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capture_mode_reaches_the_agent_over_the_hook_pipe() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().to_path_buf();
    let pipe = format!(
        r"\\.\pipe\lodeline-hook-e2e-{}",
        uuid::Uuid::new_v4().simple()
    );
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let map = lodeline_agent::hook_silence::new_map();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let server = tokio::spawn(lodeline_agent::hook_listener::serve_pipe_until(
        pipe.clone(),
        tx,
        "host-w".into(),
        map.clone(),
        shutdown.clone(),
    ));

    // The hook drops its event silently while the pipe is not up yet, so retry.
    let mut received = None;
    for _ in 0..20 {
        let (p, h) = (pipe.clone(), home.clone());
        let out = tokio::task::spawn_blocking(move || run_hook(&p, &h))
            .await
            .unwrap();
        assert!(out.status.success(), "hook exits 0: {:?}", out.status);
        assert!(out.stdout.is_empty(), "capture mode writes no stdout");
        if let Ok(ev) = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
            received = ev;
            break;
        }
    }
    let ev = received.expect("agent recorded the hook event").event;

    match ev.evidence {
        Evidence::HookInvocation(h) => {
            assert_eq!(h.action_kind, "bash");
            assert_eq!(h.peer_uid, u32::MAX, "named pipes carry no peer uid");
        }
        other => panic!("expected HookInvocation, got {other:?}"),
    }
    assert!(
        map.lock().contains_key(&(AiTool::ClaudeCode, u32::MAX)),
        "silence tracking saw the hook"
    );

    shutdown.cancel();
    server.await.unwrap().expect("listener stops cleanly");
}
