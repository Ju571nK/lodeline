use crate::adapters::HookOutput;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// How long a path that lost the race to finish waits for the winner, so a
/// stuck stdout cannot outlast the watchdog.
const FINISH_GRACE: Duration = Duration::from_millis(200);

/// The one way out of an enforce run. Agents accept one response, so the first
/// path to finish writes and every later path writes nothing. A panic hook may
/// run while the panicking code holds any lock, so stdout is duplicated up
/// front and written without `std::io::stdout()`.
pub struct Exit {
    stdout: Option<File>,
    claimed: AtomicBool,
}

impl Exit {
    pub fn new() -> Self {
        Self {
            stdout: duplicate_stdout(),
            claimed: AtomicBool::new(false),
        }
    }

    pub fn finish(&self, output: &HookOutput) -> ! {
        if self.claimed.swap(true, Ordering::SeqCst) {
            std::thread::sleep(FINISH_GRACE);
        } else if let (Some(mut file), Some(line)) = (self.stdout.as_ref(), &output.stdout) {
            // The agent reads the response as a line. Nothing can report a failed write.
            let _ = file
                .write_all(line.as_bytes())
                .and_then(|()| file.write_all(b"\n"));
            test_seam("stall_after_write");
        }
        std::process::exit(output.exit_code);
    }
}

fn duplicate_stdout() -> Option<File> {
    #[cfg(unix)]
    let duplicate = std::os::fd::AsFd::as_fd(&std::io::stdout()).try_clone_to_owned();
    #[cfg(windows)]
    let duplicate =
        std::os::windows::io::AsHandle::as_handle(&std::io::stdout()).try_clone_to_owned();
    duplicate.ok().map(File::from)
}

/// Best-effort one-line emit. NEVER returns Err for a normal failure (agent
/// down, reset, pipe broken) — those are success from the agent's POV.
///
/// `write_timeout` is applied via `set_write_timeout` on the stream.
/// NOTE: `UnixStream::connect()` itself is NOT separately bounded — the
/// caller's process watchdog (`arm_watchdog`) is the backstop for a stuck
/// connect.
#[cfg(unix)]
pub fn send_envelope(socket: &Path, line: &str, write_timeout: Duration) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    let stream = match UnixStream::connect(socket) {
        Ok(s) => s,
        Err(_) => return Ok(()), // agent down / socket missing → silent success
    };
    stream.set_write_timeout(Some(write_timeout)).ok();
    let mut stream = stream;
    let _ = stream.write_all(line.as_bytes());
    let _ = stream.write_all(b"\n");
    Ok(())
}

/// Non-unix stub. The agent's IPC on Windows is a named pipe (see `control.rs`'s
/// `#[cfg(windows)]` path); Stage 1 does not wire a named-pipe hook emit yet, so
/// the emit is a no-op here (fail-open, consistent with a down agent). Named-pipe
/// emit is a follow-up.
#[cfg(not(unix))]
pub fn send_envelope(_socket: &Path, _line: &str, _write_timeout: Duration) -> std::io::Result<()> {
    Ok(())
}

/// Spawn a watchdog that runs `on_expiry` after `budget`, so even a pathological
/// blocking stdin read cannot stall the agent's tool call.
pub fn arm_watchdog(budget: Duration, on_expiry: impl FnOnce() + Send + 'static) {
    std::thread::spawn(move || {
        std::thread::sleep(budget);
        on_expiry();
    });
}

/// Debug builds only: lets the e2e tests drive a failure path on the real
/// binary. No input reaches a panic, and release builds compile this out, so
/// the env var is never read there.
#[cfg(debug_assertions)]
pub fn test_seam(point: &str) {
    if std::env::var("LODELINE_HOOK_TEST_SEAM").as_deref() != Ok(point) {
        return;
    }
    match point {
        "hold_stdout" => {
            let _held = std::io::stdout().lock();
            loop {
                std::thread::park();
            }
        }
        "stall_after_write" => std::thread::sleep(Duration::from_secs(1)),
        _ => panic!("test seam: {point}"),
    }
}

#[cfg(not(debug_assertions))]
pub fn test_seam(_point: &str) {}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn emit_to_missing_socket_is_ok() {
        let path = std::path::Path::new("/nonexistent/lodeline/hook.sock");
        assert!(send_envelope(path, "{\"x\":1}", std::time::Duration::from_millis(150)).is_ok());
    }
}
