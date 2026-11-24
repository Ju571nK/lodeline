//! `lodeline run --pin-user-home`: one home for the watch targets, on the real binary for the
//! refused values and in process for the expansion. No real home is read.

#[cfg(all(unix, feature = "operator-cli"))]
mod common;
#[cfg(all(unix, feature = "operator-cli"))]
use common::{policy_for_paths, with_defaults_disabled, TestAgentBuilder};
use std::path::Path;
use std::process::{Command, Output};

fn run_pinned(home: &Path, pin: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lodeline"))
        .env("HOME", home)
        .env("USERPROFILE", home)
        .arg("--state-db")
        .arg(home.join("state.db"))
        .arg("--events-dir")
        .arg(home.join("events"))
        .arg("--control-socket")
        .arg(home.join("c.sock"))
        .args(["run", "--pin-user-home", pin])
        .output()
        .unwrap()
}

#[test]
fn a_relative_or_missing_pin_stops_the_command_before_the_agent_starts() {
    let home = tempfile::tempdir().unwrap();
    let missing = home.path().join("nowhere");
    for bad in ["relative/home", missing.to_str().unwrap()] {
        let out = run_pinned(home.path(), bad);
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{bad}: {err}");
        assert!(
            err.contains("--pin-user-home") && err.contains(bad),
            "{err}"
        );
        assert!(
            !home.path().join("state.db").exists(),
            "{bad}: agent started"
        );
    }
}

#[cfg(all(unix, feature = "operator-cli"))]
fn test_target_globs(resp: &serde_json::Value) -> Vec<String> {
    resp["targets"]["targets"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|t| {
            t["id"]
                .as_str()
                .is_some_and(|s| s.starts_with("test-target-"))
        })
        .flat_map(|t| t["globs"].as_array().unwrap())
        .map(|g| g.as_str().unwrap().to_string())
        .collect()
}

#[cfg(all(unix, feature = "operator-cli"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pinned_home_is_where_a_tilde_target_is_watched() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("pinned-home");
    let policy = policy_for_paths(&["~/.claude/settings.json"], "critical");
    let agent = TestAgentBuilder::new()
        .home(&home)
        .pin_home()
        .policy(&policy)
        .start()
        .await;

    let resp = agent.control(&serde_json::json!({"cmd": "targets"})).await;
    let globs = test_target_globs(&resp);
    assert_eq!(globs.len(), 1, "{globs:?}");
    assert!(
        globs[0].ends_with("pinned-home/.claude/settings.json"),
        "{globs:?}"
    );

    let edited = with_defaults_disabled(
        &policy_for_paths(&["~/.codex/config.toml"], "critical"),
        &dir.path().join("placeholder.json"),
    );
    std::fs::write(&agent.policy_file, edited).unwrap();
    let reloaded = agent
        .control(&serde_json::json!({"cmd": "reload_policy"}))
        .await;
    assert_eq!(reloaded["ok"], true);
    let deadline = std::time::Instant::now() + common::fs_event_timeout();
    let mut globs = Vec::new();
    while std::time::Instant::now() < deadline {
        let resp = agent.control(&serde_json::json!({"cmd": "targets"})).await;
        globs = test_target_globs(&resp);
        if globs.iter().any(|g| g.ends_with(".codex/config.toml")) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(globs.len(), 1, "{globs:?}");
    assert!(
        globs[0].ends_with("pinned-home/.codex/config.toml"),
        "{globs:?}"
    );

    agent.join.abort();
}

fn offline(home: &Path, args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_lodeline"))
        .env("HOME", home)
        .env("USERPROFILE", home)
        .arg("--state-db")
        .arg(home.join("state.db"))
        .arg("--control-socket")
        .arg(home.join("c.sock"))
        .args(args)
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn show_paths_with_a_pin_lists_only_that_home() {
    let dir = tempfile::tempdir().unwrap();
    let pin = dir.path().join("pinned-home");
    std::fs::create_dir(&pin).unwrap();
    let pin_str = pin.to_str().unwrap();
    let text = offline(dir.path(), &["show", "paths", "--pin-user-home", pin_str]);
    let listed: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("  /"))
        .map(str::trim)
        .collect();
    assert!(
        listed
            .iter()
            .any(|p| *p == format!("{pin_str}/.claude/settings.json")),
        "{text}"
    );
    let outside: Vec<_> = listed
        .iter()
        .filter(|p| p.contains("/.") && !p.starts_with(pin_str))
        .collect();
    assert!(
        outside.is_empty(),
        "paths outside the pinned home: {outside:?}"
    );
}

#[test]
fn doctor_with_a_pin_checks_that_home_only() {
    let dir = tempfile::tempdir().unwrap();
    let pin = dir.path().join("pinned-home");
    std::fs::create_dir(&pin).unwrap();
    let pin_str = pin.to_str().unwrap();
    let text = offline(dir.path(), &["doctor", "--pin-user-home", pin_str]);
    assert!(text.contains("enumerated users: 1\n"), "{text}");
    let absent: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("not present (no file at "))
        .collect();
    assert!(
        absent.iter().any(|l| l.contains(pin_str)),
        "no absent path under the pin: {text}"
    );
    let outside: Vec<_> = absent
        .iter()
        .filter(|l| l.contains("/.") && !l.contains(pin_str))
        .collect();
    assert!(
        outside.is_empty(),
        "paths outside the pinned home: {outside:?}"
    );
}
