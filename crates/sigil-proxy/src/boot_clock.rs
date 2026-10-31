//! A per-boot clock that counts suspend and ignores wall-clock steps (#302
//! decision 4). The spool ages rows on it within one boot.
//!
//! | Platform | Boot id | Clock |
//! |---|---|---|
//! | Linux | `/proc/sys/kernel/random/boot_id` | `CLOCK_BOOTTIME` |
//! | macOS | `kern.bootsessionuuid` | `CLOCK_MONOTONIC_RAW` |
//! | others | none | none: the spool ages rows on the wall clock |
//!
//! `Instant` is not usable: it excludes suspend (`CLOCK_MONOTONIC` on Linux,
//! `CLOCK_UPTIME_RAW` on macOS). On macOS, `clock_gettime(2)` documents
//! `CLOCK_MONOTONIC_RAW` as counting sleep and as unaffected by time adjustments.

use std::sync::Arc;

/// One reading of the boot clock. `secs` compare only between readings with the
/// same `boot_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootInstant {
    pub boot_id: Arc<str>,
    pub secs: i64,
}

/// `None` means no boot clock is available: age falls back to the wall clock.
/// Injectable, like [`crate::spool::Clock`], so age rules are testable. The boot id
/// must not change during the life of one `Spool` (a real boot id cannot).
pub type BootClock = Arc<dyn Fn() -> Option<BootInstant> + Send + Sync>;

/// The boot clock of this host. The boot id is read once, here.
pub fn system_boot_clock() -> BootClock {
    match platform::boot_id() {
        Some(id) => {
            let boot_id: Arc<str> = id.into();
            Arc::new(move || {
                Some(BootInstant {
                    boot_id: boot_id.clone(),
                    secs: platform::boot_secs()?,
                })
            })
        }
        None => {
            tracing::warn!("no boot clock on this host; spool age uses the wall clock");
            Arc::new(|| None)
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod platform {
    #[cfg(target_os = "linux")]
    const CLOCK: libc::clockid_t = libc::CLOCK_BOOTTIME;
    #[cfg(target_os = "macos")]
    const CLOCK: libc::clockid_t = libc::CLOCK_MONOTONIC_RAW;

    pub(super) fn boot_secs() -> Option<i64> {
        let mut t = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let rc = unsafe { libc::clock_gettime(CLOCK, &mut t) };
        (rc == 0).then_some(t.tv_sec)
    }

    #[cfg(target_os = "linux")]
    pub(super) fn boot_id() -> Option<String> {
        let id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
        let id = id.trim();
        (!id.is_empty()).then(|| id.to_string())
    }

    #[cfg(target_os = "macos")]
    pub(super) fn boot_id() -> Option<String> {
        let mut buf = [0u8; 64];
        let mut len = buf.len();
        let rc = unsafe {
            libc::sysctlbyname(
                c"kern.bootsessionuuid".as_ptr(),
                buf.as_mut_ptr().cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            return None;
        }
        let id = std::ffi::CStr::from_bytes_until_nul(&buf).ok()?;
        let id = id.to_str().ok()?;
        (!id.is_empty()).then(|| id.to_string())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod platform {
    pub(super) fn boot_secs() -> Option<i64> {
        None
    }

    pub(super) fn boot_id() -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn the_host_boot_clock_reads_a_stable_id_and_a_running_clock() {
        let clock = system_boot_clock();
        let first = clock().expect("this platform has a boot clock");
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let second = clock().expect("this platform has a boot clock");
        assert!(first.boot_id.len() >= 32, "{}", first.boot_id);
        assert_eq!(first.boot_id, second.boot_id);
        assert!(first.secs > 0);
        assert!(second.secs > first.secs);
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn other_platforms_have_no_boot_clock() {
        assert_eq!(system_boot_clock()(), None);
    }
}
