//! The bounded-wait helpers fail by name, inside their bound, and leave no child running.
#![cfg(unix)]

mod common;

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn panic_text(result: std::thread::Result<()>) -> String {
    let payload = result.expect_err("the wait must fail");
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default()
}

fn alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success()
}

#[test]
fn a_child_that_never_exits_fails_by_name_and_is_killed() {
    let child = Command::new("sleep")
        .arg("600")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let started = Instant::now();

    let text = panic_text(catch_unwind(AssertUnwindSafe(|| {
        common::wait_bounded(child, Duration::from_millis(300), "the sleeping child");
    })));

    assert!(text.contains("the sleeping child"), "{text}");
    assert!(started.elapsed() < Duration::from_secs(30));
    assert!(!alive(pid), "the timed-out child must be gone");
}

#[test]
fn a_child_that_exits_returns_its_output() {
    let child = Command::new("echo")
        .arg("hello")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let out = common::wait_bounded(child, common::WAIT_BOUND, "echo");

    assert!(out.status.success());
    assert_eq!(out.stdout, b"hello\n");
}

#[test]
fn an_accept_nobody_answers_fails_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let listener = std::os::unix::net::UnixListener::bind(dir.path().join("s.sock")).unwrap();

    let text = panic_text(catch_unwind(AssertUnwindSafe(|| {
        common::accept_bounded(&listener, Duration::from_millis(300), "the silent peer");
    })));

    assert!(text.contains("the silent peer"), "{text}");
}
