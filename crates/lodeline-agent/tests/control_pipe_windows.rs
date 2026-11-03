//! Its own test binary: `runtime::run` installs the global tracing subscriber.
#![cfg(windows)]

use lodeline_agent::runtime::{run, PolicyPaths, RuntimeConfig};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_stops_when_another_process_holds_the_control_pipe() {
    let td = tempfile::TempDir::new().unwrap();
    let name = format!(r"\\.\pipe\lodeline-test-{}", uuid::Uuid::now_v7());
    let _other = tokio::net::windows::named_pipe::ServerOptions::new()
        .first_pipe_instance(true)
        .create(&name)
        .unwrap();
    let policy_file = td.path().join("policy.yaml");
    std::fs::write(&policy_file, "version: 1\n").unwrap();
    let cfg = RuntimeConfig {
        policy_paths: PolicyPaths::at(policy_file),
        state_db_path: td.path().join("state.db"),
        events_dir: td.path().join("events"),
        control_socket: td.path().join("control.sock"),
        control_pipe_name: name.clone(),
        hook_pipe_name: format!("{name}-hook"),
        poll_watcher: false,
        keystore_path: None,
    };
    let exit = tokio::time::timeout(std::time::Duration::from_secs(60), run(cfg)).await;
    assert!(
        matches!(exit, Ok(Ok(1))),
        "agent exits with an error: {exit:?}"
    );
}
