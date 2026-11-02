//! e2e: the CLI subcommands that talk to the daemon honour the global
//! `--control-socket` flag instead of the default socket path (#392).
#![cfg(all(unix, feature = "operator-cli"))]

mod common;
use common::{policy_for_paths, TestAgentBuilder};
use std::process::Command;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_clients_connect_to_the_control_socket_flag() {
    let dir = tempfile::tempdir().unwrap();
    let policy = policy_for_paths(&[dir.path().join("a.json").to_str().unwrap()], "standard");
    let agent = TestAgentBuilder::new().policy(&policy).start().await;
    // An empty runtime dir makes the default socket path unreachable.
    let empty_runtime_dir = tempfile::tempdir().unwrap();

    for (args, expect) in [
        (&["reload"][..], "reload requested"),
        (&["show", "stats"][..], ""),
        (&["show", "targets"][..], ""),
        (&["doctor"][..], "active parsers"),
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_lodeline"))
            .args(args)
            .arg("--control-socket")
            .arg(&agent.control_socket)
            .arg("--policy")
            .arg(&agent.policy_file)
            .env("XDG_RUNTIME_DIR", empty_runtime_dir.path())
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stdout.contains("not running") && !stderr.contains("cannot reach"),
            "`lodeline {}` missed --control-socket\nstdout: {stdout}\nstderr: {stderr}",
            args.join(" ")
        );
        assert!(
            stdout.contains(expect),
            "`lodeline {}` output lacks {expect:?}\nstdout: {stdout}\nstderr: {stderr}",
            args.join(" ")
        );
    }

    agent.join.abort();
}
