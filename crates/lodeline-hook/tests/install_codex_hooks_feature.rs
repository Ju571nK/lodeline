//! `install` and `verify` for Codex warn, without failing, when Codex's
//! `[features] hooks` is off and so never runs the registered hook.
//! The binary reads the system config in `/etc/codex`, so each test skips on a
//! host that has that folder.
#![cfg(unix)]
use std::path::Path;
use std::process::{Command, Output};

fn hook(home: &Path, args: &[&str]) -> Output {
    let out = Command::new(env!("CARGO_BIN_EXE_lodeline-hook"))
        .env("HOME", home)
        .env("XDG_STATE_HOME", home.join("state"))
        .env("CODEX_HOME", home.join("codex"))
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "{args:?}: {out:?}");
    out
}

/// stderr of `install --write`, stdout of `verify`, with `config` as the user
/// config.toml. `None` when the host has a Codex system config.
fn install_and_verify(config: Option<&str>) -> Option<(tempfile::TempDir, String, String)> {
    if Path::new("/etc/codex").exists() {
        eprintln!("skipped: /etc/codex exists, so the result depends on this host's Codex config");
        return None;
    }
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("codex")).unwrap();
    if let Some(config) = config {
        std::fs::write(home.path().join("codex/config.toml"), config).unwrap();
    }
    let install = hook(home.path(), &["install", "--agent", "codex", "--write"]);
    let verify = hook(home.path(), &["verify", "--agent", "codex"]);
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    Some((home, text(&install.stderr), text(&verify.stdout)))
}

#[test]
fn hooks_false_warns_on_install_and_verify() {
    let Some((home, install, verify)) = install_and_verify(Some("[features]\nhooks = false\n"))
    else {
        return;
    };
    let file = home.path().join("codex/config.toml").display().to_string();
    assert!(
        install.contains("warning: Codex does not run hooks"),
        "{install}"
    );
    assert!(
        install.contains(&file) && install.contains("`hooks = false`"),
        "{install}"
    );
    assert!(
        install.contains("set `hooks = true` under [features]"),
        "{install}"
    );
    assert!(
        verify.contains("[WARN]") && verify.contains(&file),
        "{verify}"
    );
    assert!(
        verify.contains("[OK]    hook registration matches baseline"),
        "{verify}"
    );
}

#[test]
fn hooks_true_or_absent_does_not_warn() {
    for config in [
        Some("[features]\nhooks = true\n"),
        Some("model = \"o3\"\n"),
        None,
    ] {
        let Some((_home, install, verify)) = install_and_verify(config) else {
            return;
        };
        assert!(!install.contains("warning:"), "{config:?}: {install}");
        assert!(!verify.contains("[WARN]"), "{config:?}: {verify}");
    }
}

#[test]
fn malformed_config_warns_and_still_installs() {
    let Some((home, install, verify)) = install_and_verify(Some("[features\nhooks = false\n"))
    else {
        return;
    };
    assert!(install.contains("warning: cannot read "), "{install}");
    assert!(verify.contains("[WARN]  cannot read "), "{verify}");
    assert!(home.path().join("codex/hooks.json").exists());
}

#[test]
fn non_bool_hooks_warns_that_codex_does_not_load() {
    let Some((home, install, verify)) = install_and_verify(Some("[features]\nhooks = \"no\"\n"))
    else {
        return;
    };
    let file = home.path().join("codex/config.toml").display().to_string();
    let want = format!(
        "Codex does not load its config, so it runs no hooks: {file} sets `hooks` under \
         [features] to a value that is not true or false."
    );
    assert!(install.contains(&format!("warning: {want}")), "{install}");
    assert!(verify.contains(&want), "{verify}");
}
