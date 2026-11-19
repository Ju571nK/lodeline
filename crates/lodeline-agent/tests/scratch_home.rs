//! A test agent must not assess the developer's home. This binary points the
//! process `HOME` at a folder holding a risky Claude Code settings file and
//! expects the builder's agent to ignore it.

#![cfg(unix)]

mod common;
use common::{fs_event_timeout, policy_for_paths, TestAgentBuilder};
use std::time::Duration;

fn found_claude_code_settings(v: &serde_json::Value) -> bool {
    v["evidence"]["kind"] == "ai_guard_risk_assessed"
        && v["evidence"]["tool"] == "claude_code"
        && v["evidence"]["config_found"] == true
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
        .wait_for_event(found_claude_code_settings, Duration::from_secs(5))
        .await;
    assert!(
        seen.is_none(),
        "the test agent read the settings under the process HOME: {seen:?}"
    );
    agent.join.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_agent_reads_the_home_a_test_gives_it() {
    let canary = canary_home();
    let home = dunce::canonicalize(canary.path()).unwrap();

    let watched = tempfile::tempdir().unwrap();
    let policy = policy_for_paths(
        &[watched.path().join("a.json").to_str().unwrap()],
        "standard",
    );
    let agent = TestAgentBuilder::new()
        .policy(&policy)
        .home(&home)
        .start()
        .await;

    let seen = agent
        .wait_for_event(found_claude_code_settings, fs_event_timeout())
        .await;
    assert!(
        seen.is_some(),
        "the agent did not assess the home it was given"
    );
    agent.join.abort();
}

#[cfg(feature = "operator-cli")]
async fn target_ids(agent: &common::TestAgent) -> Vec<String> {
    let resp = agent.control(&serde_json::json!({"cmd": "targets"})).await;
    resp["targets"]["targets"]
        .as_array()
        .expect("targets payload")
        .iter()
        .map(|t| t["id"].as_str().unwrap().to_string())
        .collect()
}

#[cfg(feature = "operator-cli")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_agent_runs_only_its_own_targets_unless_defaults_are_asked_for() {
    let watched = tempfile::tempdir().unwrap();
    let policy = policy_for_paths(
        &[watched.path().join("a.json").to_str().unwrap()],
        "standard",
    );

    let isolated = TestAgentBuilder::new().policy(&policy).start().await;
    let ids = target_ids(&isolated).await;
    assert_eq!(ids.len(), 1, "unexpected targets: {ids:?}");
    assert!(ids[0].starts_with("test-target-"));
    isolated.join.abort();

    let with_defaults = TestAgentBuilder::new()
        .policy(&policy)
        .default_targets()
        .start()
        .await;
    let ids = target_ids(&with_defaults).await;
    assert!(ids.len() > 1, "default targets missing: {ids:?}");
    with_defaults.join.abort();
}
