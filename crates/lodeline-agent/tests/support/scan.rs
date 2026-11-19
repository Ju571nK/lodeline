//! The workspace file walk shared by the test lints in this folder.

use std::path::{Path, PathBuf};

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Every `.rs` file under `crates/*/<subdir>`, sorted.
pub fn workspace_files(subdir: &str) -> Vec<PathBuf> {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    for krate in std::fs::read_dir(&crates).unwrap() {
        let dir = krate.unwrap().path().join(subdir);
        if dir.is_dir() {
            rust_sources(&dir, &mut files);
        }
    }
    files.sort();
    files
}
