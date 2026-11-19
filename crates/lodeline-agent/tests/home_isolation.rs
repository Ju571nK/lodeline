//! An integration test that starts a workspace binary must point its home at a
//! scratch folder. Without that the binary reads the developer's real home.
//!
//! A file that spawns a binary has to set both `HOME` and `USERPROFILE`, or
//! carry a line `// home-isolation: exempt (<reason>)` that says why the
//! binaries it starts never read a home.

use std::path::{Path, PathBuf};

const SPAWN_MARKERS: &[&str] = &[
    "CARGO_BIN_EXE_",
    "assert_cmd",
    "cargo_bin",
    "Command::new(\"lodeline",
];
const EXEMPT_PREFIX: &str = "// home-isolation: exempt (";

fn test_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            test_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn workspace_test_files() -> Vec<PathBuf> {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    for krate in std::fs::read_dir(&crates).unwrap() {
        let tests = krate.unwrap().path().join("tests");
        if tests.is_dir() {
            test_sources(&tests, &mut files);
        }
    }
    files.sort();
    files
}

fn has_exemption(source: &str) -> bool {
    source.lines().any(|line| {
        line.trim()
            .strip_prefix(EXEMPT_PREFIX)
            .and_then(|rest| rest.strip_suffix(')'))
            .is_some_and(|reason| !reason.trim().is_empty())
    })
}

/// The files in `files` that spawn a binary and neither isolate the home nor
/// carry an exemption.
fn leaking(files: &[(PathBuf, String)]) -> Vec<&Path> {
    files
        .iter()
        .filter(|(_, src)| SPAWN_MARKERS.iter().any(|m| src.contains(m)))
        .filter(|(_, src)| !(src.contains("\"HOME\"") && src.contains("\"USERPROFILE\"")))
        .filter(|(_, src)| !has_exemption(src))
        .map(|(path, _)| path.as_path())
        .collect()
}

#[test]
fn binary_spawning_tests_isolate_the_home() {
    let this = Path::new(file!()).file_name().unwrap().to_owned();
    let files: Vec<_> = workspace_test_files()
        .into_iter()
        .filter(|p| p.file_name() != Some(&this))
        .map(|p| {
            let src = std::fs::read_to_string(&p).unwrap();
            (p, src)
        })
        .collect();
    assert!(
        files.iter().any(|(_, s)| s.contains("CARGO_BIN_EXE_")),
        "found no binary-spawning test; the scan root is wrong"
    );
    let offenders = leaking(&files);
    assert!(
        offenders.is_empty(),
        "these tests start a binary without setting HOME and USERPROFILE to a scratch folder \
         (set both with .env(), or add `{EXEMPT_PREFIX}<reason>)` when the binary never reads a home): {offenders:#?}"
    );
}

#[test]
fn a_file_that_spawns_without_a_scratch_home_is_flagged() {
    let spawn = "Command::new(env!(\"CARGO_BIN_EXE_lodeline\"))";
    let cases = [
        (spawn.to_string(), true),
        (format!("{spawn}.env(\"HOME\", h)"), true),
        (
            format!("{spawn}.env(\"HOME\", h).env(\"USERPROFILE\", h)"),
            false,
        ),
        (
            format!("// home-isolation: exempt (prints its version)\n{spawn}"),
            false,
        ),
        (format!("// home-isolation: exempt ()\n{spawn}"), true),
        ("fn no_spawn() {}".to_string(), false),
    ];
    for (src, flagged) in cases {
        let files = [(PathBuf::from("t.rs"), src.clone())];
        assert_eq!(!leaking(&files).is_empty(), flagged, "source: {src}");
    }
}
