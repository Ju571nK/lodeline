//! #382: what `lodeline-hook <agent> --enforce` leaves for the agent when a
//! panic or the watchdog ends the run. Spawns the real binary per adapter under
//! a temp HOME, with no decide daemon. The expected JSON below is the deny form
//! each product documents, written out here and not read from the adapters.
use serde_json::{json, Value};
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const REASON: &str =
    "Blocked by Lodeline rule fail_closed: decision unavailable; on_failure=closed";
const WATCHDOG: Duration = Duration::from_millis(800);
const BOUND: Duration = Duration::from_secs(10);

/// One payload that every adapter parses, so a run needs no per-agent fixture.
const PAYLOAD: &str = r#"{"hook_event_name":"beforeShellExecution","command":"rm -rf /x",
    "tool_name":"Bash","tool_input":{"command":"rm -rf /x"},
    "toolName":"run_terminal_command","toolInput":{"command":"rm -rf /x"},
    "toolCall":{"name":"run_command","args":{"CommandLine":"rm -rf /x"}}}"#;

fn documented_denies() -> [(&'static str, Value); 5] {
    let pretooluse = json!({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": REASON,
    }});
    [
        (
            "antigravity",
            json!({"allow_tool": false, "deny_reason": REASON}),
        ),
        ("claude-code", pretooluse.clone()),
        ("codex", pretooluse),
        (
            "cursor",
            json!({"permission": "deny", "agent_message": REASON, "user_message": REASON}),
        ),
        ("grok", json!({"decision": "deny", "reason": REASON})),
    ]
}

const AGENTS: [&str; 5] = ["antigravity", "claude-code", "codex", "cursor", "grok"];

enum Stdin {
    Payload,
    HeldOpen,
}

struct Run {
    stdout: String,
    stderr: String,
    code: i32,
    elapsed: Duration,
}

impl Run {
    #[track_caller]
    fn assert_only_line(&self, label: &str, expected: &Value) {
        assert_eq!(self.code, 0, "{label}: exit code");
        assert!(self.stderr.is_empty(), "{label}: stderr {:?}", self.stderr);
        assert!(self.stdout.ends_with('\n'), "{label}: {:?}", self.stdout);
        let lines: Vec<&str> = self.stdout.lines().collect();
        assert_eq!(lines.len(), 1, "{label}: one response, got {lines:?}");
        let got: Value = serde_json::from_str(lines[0]).expect("stdout is JSON");
        assert_eq!(&got, expected, "{label}: response");
    }

    #[track_caller]
    fn assert_silent_allow(&self, label: &str) {
        assert_eq!(self.code, 0, "{label}: exit code");
        assert!(self.stdout.is_empty(), "{label}: stdout {:?}", self.stdout);
        assert!(self.stderr.is_empty(), "{label}: stderr {:?}", self.stderr);
    }
}

/// Spawn the hook and fail, rather than hang, when it outlives `BOUND`.
fn drive(agent: &str, mode: &str, stdin: Stdin, seam: Option<&str>) -> Run {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir(&home).unwrap();
    let absent_socket = if cfg!(windows) {
        format!(r"\\.\pipe\lodeline-hook-absent-{}", std::process::id()).into()
    } else {
        dir.path().join("hook-decide.sock")
    };
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_lodeline-hook"));
    cmd.args([agent, "--enforce", "--on-failure", mode])
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("TMPDIR", dir.path())
        .env("XDG_RUNTIME_DIR", dir.path())
        .env("LODELINE_HOOK_SOCKET", dir.path().join("hook.sock"))
        .env("LODELINE_HOOK_DECIDE_SOCKET", absent_socket)
        .env_remove("LODELINE_HOOK_TEST_SEAM")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(point) = seam {
        cmd.env("LODELINE_HOOK_TEST_SEAM", point);
    }

    let started = Instant::now();
    let mut child = cmd.spawn().unwrap();
    let mut held = child.stdin.take();
    if matches!(stdin, Stdin::Payload) {
        // A seam can end the run before stdin is read, so a broken pipe is fine.
        let _ = held.take().unwrap().write_all(PAYLOAD.as_bytes());
    }
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > BOUND {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("{agent} {mode}: hook outlived {BOUND:?}");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let elapsed = started.elapsed();
    drop(held);
    let out = child.wait_with_output().unwrap();
    Run {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        code: out.status.code().unwrap_or(-1),
        elapsed,
    }
}

#[test]
fn no_verdict_closed_gives_each_documented_deny() {
    for (agent, deny) in documented_denies() {
        drive(agent, "closed", Stdin::Payload, None).assert_only_line(agent, &deny);
    }
}

#[test]
fn no_verdict_open_stays_a_deliberate_allow() {
    for agent in AGENTS {
        let run = drive(agent, "open", Stdin::Payload, None);
        if agent == "cursor" {
            run.assert_only_line(agent, &json!({"permission": "allow"}));
        } else {
            run.assert_silent_allow(agent);
        }
    }
}

#[test]
fn watchdog_closed_gives_each_documented_deny() {
    for (agent, deny) in documented_denies() {
        let run = drive(agent, "closed", Stdin::HeldOpen, None);
        run.assert_only_line(agent, &deny);
        assert!(run.elapsed >= WATCHDOG, "{agent}: {:?}", run.elapsed);
    }
}

#[test]
fn watchdog_open_stays_silent() {
    for agent in AGENTS {
        let run = drive(agent, "open", Stdin::HeldOpen, None);
        run.assert_silent_allow(agent);
        assert!(run.elapsed >= WATCHDOG, "{agent}: {:?}", run.elapsed);
    }
}

#[test]
fn an_unknown_agent_is_refused_before_any_hook_runs() {
    let out = Command::new(env!("CARGO_BIN_EXE_lodeline-hook"))
        .args(["bogus", "--enforce", "--on-failure", "closed"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
}

// The seam exists only in debug builds, so these skip under `cargo test --release`.
#[cfg(debug_assertions)]
mod seam {
    use super::*;

    #[test]
    fn panic_closed_gives_each_documented_deny() {
        for (agent, deny) in documented_denies() {
            drive(agent, "closed", Stdin::Payload, Some("panic")).assert_only_line(agent, &deny);
        }
    }

    #[test]
    fn panic_open_stays_silent() {
        for agent in AGENTS {
            drive(agent, "open", Stdin::Payload, Some("panic")).assert_silent_allow(agent);
        }
    }

    #[test]
    fn panic_before_the_adapter_is_known_has_no_deny_to_write() {
        for agent in AGENTS {
            let closed = drive(agent, "closed", Stdin::Payload, Some("before_adapter"));
            assert_eq!(closed.code, 2, "{agent}: closed exit code");
            assert!(closed.stdout.is_empty(), "{agent}: {:?}", closed.stdout);
            assert!(closed.stderr.is_empty(), "{agent}: {:?}", closed.stderr);

            drive(agent, "open", Stdin::Payload, Some("before_adapter")).assert_silent_allow(agent);
        }
    }

    /// The main thread never lets go of the stdout lock, so a watchdog that
    /// wrote through `std::io::stdout()` would block until `BOUND` fails it.
    #[test]
    fn watchdog_writes_while_the_stdout_lock_is_held() {
        for (agent, deny) in documented_denies() {
            let run = drive(agent, "closed", Stdin::Payload, Some("hold_stdout"));
            run.assert_only_line(agent, &deny);
        }
    }

    /// The main thread has written and stalls before it exits, so the watchdog
    /// fires with a response already out. Two responses would void the deny.
    #[test]
    fn a_second_failure_path_adds_no_second_response() {
        for (agent, deny) in documented_denies() {
            let run = drive(agent, "closed", Stdin::Payload, Some("stall_after_write"));
            run.assert_only_line(agent, &deny);
            assert!(run.elapsed >= WATCHDOG, "{agent}: {:?}", run.elapsed);
        }
    }
}
