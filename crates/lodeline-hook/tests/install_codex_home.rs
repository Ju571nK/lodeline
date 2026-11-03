//! `install --agent codex` writes the hooks file Codex reads: `$CODEX_HOME/hooks.json`
//! when `CODEX_HOME` is set, else `~/.codex/hooks.json` (`find_codex_home`,
//! codex-rs/utils/home-dir, rust-v0.166.0).
#![cfg(unix)]
use std::path::Path;
use std::process::Command;

fn hook(home: &Path, codex_home: Option<&Path>) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_lodeline-hook"));
    cmd.env("HOME", home)
        .env("XDG_STATE_HOME", home.join("state"))
        .env_remove("CODEX_HOME");
    if let Some(dir) = codex_home {
        cmd.env("CODEX_HOME", dir);
    }
    cmd
}

fn ok(cmd: &mut Command) -> String {
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{cmd:?} failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn run(home: &Path, codex_home: Option<&Path>, args: &[&str]) {
    ok(hook(home, codex_home).args(args));
}

fn lodeline_entries(hooks: &Path) -> usize {
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(hooks).unwrap()).unwrap();
    v["hooks"]["PreToolUse"]
        .as_array()
        .map_or(0, |groups| groups.len())
}

#[test]
fn install_and_uninstall_use_codex_home() {
    let (home, codex_home) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let hooks = codex_home.path().join("hooks.json");

    run(
        home.path(),
        Some(codex_home.path()),
        &["install", "--agent", "codex", "--write"],
    );
    assert_eq!(lodeline_entries(&hooks), 1);
    assert!(!home.path().join(".codex/hooks.json").exists());

    run(
        home.path(),
        Some(codex_home.path()),
        &["uninstall", "--agent", "codex", "--write"],
    );
    assert_eq!(lodeline_entries(&hooks), 0);
}

#[test]
fn install_without_codex_home_writes_dot_codex() {
    let home = tempfile::tempdir().unwrap();
    run(
        home.path(),
        None,
        &["install", "--agent", "codex", "--write"],
    );
    assert_eq!(lodeline_entries(&home.path().join(".codex/hooks.json")), 1);
}

#[test]
fn empty_codex_home_falls_back_to_dot_codex() {
    let home = tempfile::tempdir().unwrap();
    assert!(!home.path().join(".codex").exists());
    run(
        home.path(),
        Some(Path::new("")),
        &["install", "--agent", "codex", "--write"],
    );
    assert_eq!(lodeline_entries(&home.path().join(".codex/hooks.json")), 1);
}

#[test]
fn relative_codex_home_is_stored_absolute_and_verifies_from_elsewhere() {
    let (home, work) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    ok(hook(home.path(), Some(Path::new("rel-codex")))
        .current_dir(work.path())
        .args(["install", "--agent", "codex", "--write"]));
    let hooks = work.path().join("rel-codex/hooks.json");
    assert_eq!(lodeline_entries(&hooks), 1);

    let baseline: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            home.path()
                .join("state/lodeline/hook-registration-codex.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let stored = Path::new(baseline["settings_path"].as_str().unwrap());
    assert!(stored.is_absolute(), "baseline path {stored:?} is relative");
    assert_eq!(
        stored.canonicalize().unwrap(),
        hooks.canonicalize().unwrap()
    );

    let out = ok(hook(home.path(), None)
        .current_dir(home.path())
        .args(["verify", "--agent", "codex"]));
    assert!(out.contains("[OK]"), "verify output: {out}");
}
