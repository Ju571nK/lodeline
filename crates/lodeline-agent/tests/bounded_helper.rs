#[allow(unused_imports)]
mod common;
use common::{policy_for_paths, run_bounded, start_bounded, stop_bounded, TestAgentBuilder};
use std::time::Duration;

#[test]
#[should_panic(expected = "pending step")]
fn a_future_that_never_completes_fails_by_step_name() {
    run_bounded("never", Duration::from_millis(300), |steps| async move {
        steps.at("pending step");
        steps.context(|| "3 file_change events".to_string());
        std::future::pending::<()>().await;
    });
}

#[test]
#[should_panic(expected = "3 file_change events")]
fn the_failure_message_carries_the_context() {
    run_bounded("never", Duration::from_millis(300), |steps| async move {
        steps.context(|| "3 file_change events".to_string());
        std::future::pending::<()>().await;
    });
}

#[test]
#[should_panic(expected = "blocked step")]
fn a_blocking_call_inside_the_body_is_cut_off() {
    run_bounded("blocked", Duration::from_millis(300), |steps| async move {
        steps.at("blocked step");
        std::thread::sleep(Duration::from_secs(5));
    });
}

#[test]
#[should_panic(expected = "runtime drop")]
fn a_runtime_that_cannot_shut_down_is_cut_off() {
    run_bounded("drop", Duration::from_millis(300), |steps| async move {
        steps.at("runtime drop");
        tokio::task::spawn_blocking(|| std::thread::sleep(Duration::from_secs(5)));
    });
}

#[test]
#[should_panic(expected = "body panic")]
fn a_panic_in_the_body_is_reported_as_is() {
    run_bounded("panics", Duration::from_secs(30), |_| async {
        panic!("body panic");
    });
}

#[test]
fn a_body_that_finishes_passes() {
    run_bounded("ok", Duration::from_secs(30), |_| async {});
}

const CHILD_ENV: &str = "BOUNDED_HELPER_CHILD";

fn panic_text(err: Box<dyn std::any::Any + Send>) -> String {
    err.downcast_ref::<String>()
        .cloned()
        .or_else(|| err.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default()
}

#[test]
fn a_runtime_drop_hang_after_stop_still_reports_the_events_seen() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("probe.json");
    let policy = policy_for_paths(&[target.to_str().unwrap()], "standard");

    let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_bounded("drop_hang", Duration::from_secs(4), |steps| async move {
            let mut agent = start_bounded(&steps, TestAgentBuilder::new().policy(&policy)).await;
            tokio::task::spawn_blocking(|| std::thread::sleep(Duration::from_secs(8)));
            stop_bounded(&steps, &mut agent).await;
            drop(agent);
        });
    }))
    .unwrap_err();

    let text = panic_text(err);
    assert!(
        text.contains("stuck at step \"drop the runtime\""),
        "{text}"
    );
    assert!(text.contains("events in all"), "{text}");
    assert!(
        !text.contains("last kinds []"),
        "the summary was read after the temp dir was gone: {text}"
    );
}

#[test]
fn inner_panic_child() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    run_bounded("child", Duration::from_secs(30), |steps| async move {
        steps.at("a distinctive step");
        panic!("inner failure");
    });
}

#[test]
fn an_inner_panic_prints_the_step_it_was_in() {
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "inner_panic_child", "--nocapture"])
        .env(CHILD_ENV, "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let out = common::wait_bounded(child, common::WAIT_BOUND, "the child test");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "the child test should fail");
    assert!(
        stderr.contains("stuck at step \"a distinctive step\""),
        "{stderr}"
    );
}
