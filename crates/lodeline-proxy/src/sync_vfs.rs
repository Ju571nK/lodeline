//! Test-only SQLite VFS: the platform default with every `xSync` counted per
//! file, and a copy of the file taken right after each `xSync`. That copy is
//! what a power loss keeps when the disk persists nothing that was not synced.
//! [`install`] makes it the default VFS of the process; it only observes, so
//! other tests' connections behave as before.

use std::collections::HashMap;
use std::ffi::{c_char, c_int, CStr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{LazyLock, Mutex, Once};

use rusqlite::ffi;

#[derive(Default)]
struct Synced {
    count: u64,
    image: Vec<u8>,
}

/// Open file (by address) -> its path and the real VFS's methods.
static OPEN: LazyLock<Mutex<HashMap<usize, (PathBuf, usize)>>> = LazyLock::new(Default::default);
/// Real methods table -> the copy with our `xSync` and `xClose` (leaked).
static TABLES: LazyLock<Mutex<HashMap<usize, usize>>> = LazyLock::new(Default::default);
static SYNCED: LazyLock<Mutex<HashMap<PathBuf, Synced>>> = LazyLock::new(Default::default);
static REAL: AtomicPtr<ffi::sqlite3_vfs> = AtomicPtr::new(std::ptr::null_mut());

/// Number of `xSync` calls on `path` so far.
pub fn syncs(path: &Path) -> u64 {
    SYNCED.lock().unwrap().get(path).map_or(0, |s| s.count)
}

/// The content of `path` as of its last `xSync` (empty if never synced).
pub fn synced_image(path: &Path) -> Vec<u8> {
    SYNCED
        .lock()
        .unwrap()
        .get(path)
        .map(|s| s.image.clone())
        .unwrap_or_default()
}

pub fn install() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| unsafe {
        let real = ffi::sqlite3_vfs_find(std::ptr::null());
        assert!(!real.is_null(), "no default VFS");
        REAL.store(real, Ordering::SeqCst);
        let mut ours = *real;
        ours.zName = c"lodeline-sync-count".as_ptr();
        ours.pNext = std::ptr::null_mut();
        ours.xOpen = Some(x_open);
        let ours = Box::leak(Box::new(ours));
        assert_eq!(ffi::sqlite3_vfs_register(ours, 1), ffi::SQLITE_OK);
    });
}

unsafe extern "C" fn x_open(
    _vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    file: *mut ffi::sqlite3_file,
    flags: c_int,
    out_flags: *mut c_int,
) -> c_int {
    let real = REAL.load(Ordering::SeqCst);
    let rc = unsafe { ((*real).xOpen.unwrap())(real, name, file, flags, out_flags) };
    let methods = unsafe { (*file).pMethods };
    if rc != ffi::SQLITE_OK || methods.is_null() || name.is_null() {
        return rc;
    }
    let path = PathBuf::from(
        unsafe { CStr::from_ptr(name) }
            .to_string_lossy()
            .into_owned(),
    );
    let ours = *TABLES
        .lock()
        .unwrap()
        .entry(methods as usize)
        .or_insert_with(|| {
            let mut t = unsafe { *methods };
            t.xSync = Some(x_sync);
            t.xClose = Some(x_close);
            Box::leak(Box::new(t)) as *const ffi::sqlite3_io_methods as usize
        });
    OPEN.lock()
        .unwrap()
        .insert(file as usize, (path, methods as usize));
    unsafe { (*file).pMethods = ours as *const ffi::sqlite3_io_methods };
    rc
}

fn real_methods(file: *mut ffi::sqlite3_file) -> (PathBuf, *const ffi::sqlite3_io_methods) {
    let (path, m) = OPEN.lock().unwrap()[&(file as usize)].clone();
    (path, m as *const ffi::sqlite3_io_methods)
}

unsafe extern "C" fn x_sync(file: *mut ffi::sqlite3_file, flags: c_int) -> c_int {
    let (path, real) = real_methods(file);
    let rc = unsafe { ((*real).xSync.unwrap())(file, flags) };
    if rc == ffi::SQLITE_OK {
        let image = std::fs::read(&path).unwrap_or_default();
        let mut all = SYNCED.lock().unwrap();
        let s = all.entry(path).or_default();
        s.count += 1;
        s.image = image;
    }
    rc
}

unsafe extern "C" fn x_close(file: *mut ffi::sqlite3_file) -> c_int {
    let (_, real) = real_methods(file);
    OPEN.lock().unwrap().remove(&(file as usize));
    unsafe { (*file).pMethods = real };
    unsafe { ((*real).xClose.unwrap())(file) }
}
