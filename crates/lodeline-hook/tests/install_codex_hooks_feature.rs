//! `install` and `verify` for Codex warn, without failing, when Codex's
//! `[features] hooks` is off and so never runs the registered hook.
//! Assumes no `/etc/codex` config on the test host.
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

/// stderr of `install --write`, stdout of `verify`, with `config` as the user config.toml.
fn install_and_verify(config: Option<&str>) -> (tempfile::TempDir, String, String) {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("codex")).unwrap();
    if let Some(config) = config {
        std::fs::write(home.path().join("codex/config.toml"), config).unwrap();
    }
    let install = hook(home.path(), &["install", "--agent", "codex", "--write"]);
    let verify = hook(home.path(), &["verify", "--agent", "codex"]);
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (home, text(&install.stderr), text(&verify.stdout))
}

#[test]
fn hooks_false_warns_on_install_and_verify() {
    let (home, install, verify) = install_and_verify(Some("[features]\nhooks = false\n"));
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
        let (_home, install, verify) = install_and_verify(config);
        assert!(!install.contains("warning:"), "{config:?}: {install}");
        assert!(!verify.contains("[WARN]"), "{config:?}: {verify}");
    }
}

#[test]
fn malformed_config_warns_and_still_installs() {
    let (home, install, verify) = install_and_verify(Some("[features\nhooks = false\n"));
    assert!(install.contains("warning: cannot read "), "{install}");
    assert!(verify.contains("[WARN]  cannot read "), "{verify}");
    assert!(home.path().join("codex/hooks.json").exists());
}
