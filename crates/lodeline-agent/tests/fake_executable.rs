//! A test that writes a fake executable must not leave a write fd open on it.
//!
//! A child forked by another test thread between our `open` and `close` holds
//! that fd until it execs, and running the script meanwhile fails with ETXTBSY
//! on Linux. The fix is a `write_executable` helper that copies the script in
//! through a `cp` child (see #699).
//!
//! The check is a file-level text heuristic. A file is flagged when it
//!
//! - has a script shebang (`#!/`),
//! - writes a file in-process (`fs::write(`, `File::create(` or `.write_all(`),
//! - sets an executable mode (`from_mode(0o7..` or `.mode(0o7..`), and
//! - never runs `Command::new("cp")`.
//!
//! The shebang keeps directory permissions (`0o700` on a tempdir) out. For
//! `crates/*/src`, only the text from the first `#[cfg(test)]` on counts.
//! Limits: it does not tie the write to the mode, so a file that has a helper
//! and one stray site is not flagged, and a script written without a shebang
//! is missed. A file the heuristic wrongly flags carries a line
//! `// fake-executable: exempt (<reason>)`.

use std::path::{Path, PathBuf};

mod support;
use support::scan::workspace_files;

const EXEMPT_PREFIX: &str = "// fake-executable: exempt (";
const WRITE_MARKERS: &[&str] = &["fs::write(", "File::create(", ".write_all("];
const EXEC_MODE_MARKERS: &[&str] = &["from_mode(0o7", ".mode(0o7"];
const CP_CHILD: &str = "Command::new(\"cp\")";

fn has_exemption(source: &str) -> bool {
    source.lines().any(|line| {
        line.trim()
            .strip_prefix(EXEMPT_PREFIX)
            .and_then(|rest| rest.strip_suffix(')'))
            .is_some_and(|reason| !reason.trim().is_empty())
    })
}

/// The part of a file the lint reads: all of an integration test, and the
/// `#[cfg(test)]` tail of a source file.
fn scanned_text<'a>(path: &Path, src: &'a str) -> &'a str {
    let in_src = path.components().any(|c| c.as_os_str() == "src");
    if !in_src {
        return src;
    }
    src.find("#[cfg(test)]").map_or("", |at| &src[at..])
}

fn writes_exec_in_process(text: &str) -> bool {
    text.contains("#!/")
        && WRITE_MARKERS.iter().any(|m| text.contains(m))
        && EXEC_MODE_MARKERS.iter().any(|m| text.contains(m))
        && !text.contains(CP_CHILD)
}

fn offending(files: &[(PathBuf, String)]) -> Vec<&Path> {
    files
        .iter()
        .filter(|(path, src)| writes_exec_in_process(scanned_text(path, src)))
        .filter(|(_, src)| !has_exemption(src))
        .map(|(path, _)| path.as_path())
        .collect()
}

fn read_all(paths: Vec<PathBuf>, skip: &std::ffi::OsStr) -> Vec<(PathBuf, String)> {
    paths
        .into_iter()
        .filter(|p| p.file_name() != Some(skip))
        .map(|p| {
            let src = std::fs::read_to_string(&p).unwrap();
            (p, src)
        })
        .collect()
}

#[test]
fn fake_executables_are_written_through_a_child_process() {
    let this = Path::new(file!()).file_name().unwrap().to_owned();
    let mut files = read_all(workspace_files("tests"), &this);
    files.extend(read_all(workspace_files("src"), &this));
    assert!(
        files
            .iter()
            .any(|(_, s)| s.contains("fn write_executable(")),
        "found no write_executable helper; the scan root is wrong"
    );
    let offenders = offending(&files);
    assert!(
        offenders.is_empty(),
        "these files write a fake executable in this process; copy it in through a `cp` child \
         like `write_executable` in lodeline-hook's install_antigravity_static.rs, or add \
         `{EXEMPT_PREFIX}<reason>)`: {offenders:#?}"
    );
}

#[test]
fn an_in_process_executable_write_is_flagged() {
    let write = "std::fs::write(&p, \"#!/bin/sh\\n\").unwrap();";
    let mode = "set_permissions(&p, Permissions::from_mode(0o755));";
    let cp = "Command::new(\"cp\")";
    let cases = [
        (format!("{write}\n{mode}"), "tests/t.rs", true),
        (format!("{write}\n{mode}\n{cp}"), "tests/t.rs", false),
        (
            format!("// fake-executable: exempt (never run)\n{write}\n{mode}"),
            "tests/t.rs",
            false,
        ),
        (
            format!("// fake-executable: exempt ()\n{write}\n{mode}"),
            "tests/t.rs",
            true,
        ),
        (
            "std::fs::write(&d, \"x\");\nfrom_mode(0o700)".to_string(),
            "tests/t.rs",
            false,
        ),
        (format!("{write}\n{mode}"), "src/lib.rs", false),
        (
            format!("fn prod() {{}}\n#[cfg(test)]\nmod tests {{\n{write}\n{mode}\n}}"),
            "src/lib.rs",
            true,
        ),
    ];
    for (src, path, flagged) in cases {
        let files = [(PathBuf::from(path), src.clone())];
        assert_eq!(!offending(&files).is_empty(), flagged, "{path}: {src}");
    }
}
