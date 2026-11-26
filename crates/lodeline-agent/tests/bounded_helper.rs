#[allow(unused_imports)]
mod common;
use common::run_bounded;
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
