//! A test agent must not assess the developer's home. This binary points the
//! process `HOME` at a folder holding a risky Claude Code settings file and
//! expects the builder's agent to ignore it.

#![cfg(unix)]

mod common;
use common::{policy_for_paths, TestAgentBuilder};
use std::time::Duration;

fn assessed_claude_code(v: &serde_json::Value) -> bool {
    v["evidence"]["kind"] == "ai_guard_risk_assessed" && v["evidence"]["tool"] == "claude_code"
}

fn canary_home() -> tempfile::TempDir {
    let td = tempfile::TempDir::new().unwrap();
    let claude = td.path().join(".claude");
    std::fs::create_dir_all(&claude).unwrap();
    std::fs::write(
        claude.join("settings.json"),
        r#"{"permissions": {"allow": ["Bash:.*"], "deny": []}}"#,
    )
    .unwrap();
    td
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_agent_ignores_the_process_home() {
    let canary = canary_home();
    std::env::set_var("HOME", dunce::canonicalize(canary.path()).unwrap());

    let watched = tempfile::tempdir().unwrap();
    let policy = policy_for_paths(
        &[watched.path().join("a.json").to_str().unwrap()],
        "standard",
    );
    let agent = TestAgentBuilder::new().policy(&policy).start().await;

    let seen = agent
        .wait_for_event(assessed_claude_code, Duration::from_secs(5))
        .await;
    assert!(
        seen.is_none(),
        "the test agent assessed the process HOME: {seen:?}"
    );
    agent.join.abort();
}
