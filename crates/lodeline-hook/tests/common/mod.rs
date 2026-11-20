//! Bounded waits for the hook e2e tests. A hung child or a peer that never connects
//! fails the test by name inside `WAIT_BOUND`, and a timed-out child is killed first.

#![allow(dead_code)]

use std::io::Read;
use std::process::{Child, ExitStatus, Output};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub const WAIT_BOUND: Duration = Duration::from_secs(60);
const POLL: Duration = Duration::from_millis(5);

fn drain<R: Read + Send + 'static>(pipe: Option<R>) -> Option<JoinHandle<Vec<u8>>> {
    pipe.map(|mut pipe| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            buf
        })
    })
}

fn collect(reader: Option<JoinHandle<Vec<u8>>>) -> Vec<u8> {
    reader.map(|r| r.join().unwrap()).unwrap_or_default()
}

/// `wait_with_output` with a deadline. Closes the child's stdin first, as
/// `wait_with_output` does. On timeout the child is killed and reaped, then the
/// test panics naming `what`.
pub fn wait_bounded(mut child: Child, bound: Duration, what: &str) -> Output {
    drop(child.stdin.take());
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    let status = poll_exit(&mut child, bound, what);
    Output {
        status,
        stdout: collect(stdout),
        stderr: collect(stderr),
    }
}

fn poll_exit(child: &mut Child, bound: Duration, what: &str) -> ExitStatus {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if started.elapsed() > bound {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{what}: still running after {bound:?}, killed");
        }
        thread::sleep(POLL);
    }
}

/// `accept` with a deadline. The returned stream is blocking, with a read timeout of `bound`.
#[cfg(unix)]
pub fn accept_bounded(
    listener: &std::os::unix::net::UnixListener,
    bound: Duration,
    what: &str,
) -> std::os::unix::net::UnixStream {
    listener.set_nonblocking(true).unwrap();
    let started = Instant::now();
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                // macOS refuses these on a socket whose peer already exited; the data is
                // still readable then, so the errors are ignored.
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(bound));
                return stream;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    started.elapsed() <= bound,
                    "{what}: no connection within {bound:?}"
                );
                thread::sleep(POLL);
            }
            Err(e) => panic!("{what}: accept failed: {e}"),
        }
    }
}
