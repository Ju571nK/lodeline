//! The bounded-wait helpers fail by name, inside their bound, and leave no child running.
#![cfg(unix)]

#[allow(unused_imports)]
mod common;

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn panic_text(payload: Box<dyn std::any::Any + Send>) -> String {
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

    let payload = catch_unwind(AssertUnwindSafe(|| {
        common::wait_bounded(child, Duration::from_millis(300), "the sleeping child");
    }))
    .expect_err("the wait must fail");

    let text = panic_text(payload);
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

#[tokio::test]
async fn an_event_that_never_comes_fails_by_name() {
    let (_tx, mut rx) = tokio::sync::mpsc::channel::<u8>(1);
    let started = Instant::now();

    let handle = tokio::spawn(async move {
        common::recv_bounded(&mut rx, Duration::from_millis(300), "the missing event").await
    });
    let payload = handle.await.expect_err("the wait must fail").into_panic();

    assert!(panic_text(payload).contains("the missing event"));
    assert!(started.elapsed() < Duration::from_secs(30));
}
