//! `install --agent codex` writes the hooks file Codex reads: `$CODEX_HOME/hooks.json`
//! when `CODEX_HOME` is set, else `~/.codex/hooks.json` (`find_codex_home`,
//! codex-rs/utils/home-dir, rust-v0.166.0).
#![cfg(unix)]
use std::path::Path;
use std::process::Command;

fn run(home: &Path, codex_home: Option<&Path>, args: &[&str]) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_lodeline-hook"));
    cmd.args(args)
        .env("HOME", home)
        .env("XDG_STATE_HOME", home.join("state"))
        .env_remove("CODEX_HOME");
    if let Some(dir) = codex_home {
        cmd.env("CODEX_HOME", dir);
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
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
