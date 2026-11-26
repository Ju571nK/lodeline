//! #717 — hooks that an enabled Codex plugin brings.

use lodeline_core::event::AiGuardFinding;
use std::path::{Path, PathBuf};
use toml::Value;

use super::codex::HookTrust;

/// One plugin hook declaration: a file in the plugin folder, or a block of
/// its manifest.
pub(super) struct PluginHookFile {
    pub(super) key_source: String,
    pub(super) file: PathBuf,
    pub(super) hooks: Value,
}

pub(super) struct EnabledPlugin {
    pub(super) id: String,
    pub(super) root: PathBuf,
    pub(super) files: Vec<PluginHookFile>,
}

pub(super) fn enabled_plugins(_codex_dir: &Path, _config: Option<&Value>) -> Vec<EnabledPlugin> {
    Vec::new()
}

pub(super) fn plugin_findings(
    _plugins: &[EnabledPlugin],
    _trust: &HookTrust,
    _home: Option<&Path>,
) -> Vec<AiGuardFinding> {
    Vec::new()
}

pub(super) fn content_hash(_root: &Path) -> std::io::Result<String> {
    Ok(String::new())
}

pub(super) fn watched_paths(_codex_dir: &Path, _config: Option<&Value>) -> Vec<PathBuf> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::super::codex::{assess_user_findings, CodexParser};
    use super::super::AiGuardParser;
    use super::*;
    use lodeline_core::event::{AiGuardReason, ConfigLayer, ConfigSource};
    use tempfile::tempdir;

    const DESTRUCTIVE: &str =
        r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"rm -rf /"}]}]}}"#;

    struct Fixture {
        _root: tempfile::TempDir,
        system: PathBuf,
        home: PathBuf,
        codex: PathBuf,
    }

    fn fixture() -> Fixture {
        let root = tempdir().unwrap();
        let system = root.path().join("etc-codex");
        let home = root.path().join("home");
        let codex = home.join(".codex");
        std::fs::create_dir_all(&system).unwrap();
        std::fs::create_dir_all(&codex).unwrap();
        Fixture {
            _root: root,
            system,
            home,
            codex,
        }
    }

    impl Fixture {
        fn plugin_dir(&self, version: &str) -> PathBuf {
            self.codex.join("plugins/cache/mk/demo").join(version)
        }

        fn write(&self, path: &Path, text: &str) {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }

        fn config(&self, text: &str) {
            self.write(&self.codex.join("config.toml"), text);
        }

        fn findings(&self) -> Vec<lodeline_core::event::AiGuardFinding> {
            assess_user_findings(&self.system, &self.codex, &self.home).unwrap()
        }

        fn destructive(&self) -> Vec<Option<ConfigSource>> {
            self.findings()
                .into_iter()
                .filter(|f| matches!(f.reason, AiGuardReason::DestructiveInInlineCommand { .. }))
                .map(|f| f.config_source)
                .collect()
        }
    }

    const ENABLED: &str = "[plugins.\"demo@mk\"]\nenabled = true\n";

    fn trusted(key: &str) -> String {
        format!("\n[hooks.state.'demo@mk:{key}']\ntrusted_hash = \"sha256:00\"\n")
    }

    fn user_source(file: &Path) -> Option<ConfigSource> {
        Some(ConfigSource {
            layer: ConfigLayer::User,
            file: file.to_string_lossy().into_owned(),
        })
    }

    #[test]
    fn an_enabled_trusted_plugin_hook_is_scored_and_names_its_file() {
        let fx = fixture();
        let file = fx.plugin_dir("1.0.0").join("hooks/hooks.json");
        fx.write(&file, DESTRUCTIVE);
        fx.config(&format!(
            "{ENABLED}{}",
            trusted("hooks/hooks.json:pre_tool_use:0:0")
        ));
        assert_eq!(fx.destructive(), vec![user_source(&file)]);
    }

    #[test]
    fn an_enabled_plugin_hook_without_a_trusted_hash_is_not_scored() {
        let fx = fixture();
        fx.write(
            &fx.plugin_dir("1.0.0").join("hooks/hooks.json"),
            DESTRUCTIVE,
        );
        fx.config(ENABLED);
        assert!(fx.destructive().is_empty());
    }

    #[test]
    fn a_disabled_or_unlisted_plugin_contributes_nothing() {
        let fx = fixture();
        fx.write(
            &fx.plugin_dir("1.0.0").join("hooks/hooks.json"),
            DESTRUCTIVE,
        );
        let state = trusted("hooks/hooks.json:pre_tool_use:0:0");
        fx.config(&format!("[plugins.\"demo@mk\"]\nenabled = false\n{state}"));
        assert!(fx.destructive().is_empty());
        fx.config(&state);
        assert!(fx.destructive().is_empty());
    }

    #[test]
    fn an_inline_manifest_hook_is_scored_and_names_the_manifest() {
        let fx = fixture();
        let manifest = fx.plugin_dir("1.0.0").join(".codex-plugin/plugin.json");
        fx.write(
            &manifest,
            &format!(r#"{{"name":"demo","hooks":{DESTRUCTIVE}}}"#),
        );
        fx.config(&format!(
            "{ENABLED}{}",
            trusted("plugin.json#hooks[0]:pre_tool_use:0:0")
        ));
        assert_eq!(fx.destructive(), vec![user_source(&manifest)]);
    }

    #[test]
    fn a_manifest_hooks_path_replaces_the_default_file() {
        let fx = fixture();
        let dir = fx.plugin_dir("1.0.0");
        fx.write(&dir.join("hooks/hooks.json"), DESTRUCTIVE);
        fx.write(
            &dir.join(".codex-plugin/plugin.json"),
            r#"{"name":"demo","hooks":"./extra.json"}"#,
        );
        fx.write(&dir.join("extra.json"), DESTRUCTIVE);
        fx.config(&format!(
            "{ENABLED}{}{}",
            trusted("hooks/hooks.json:pre_tool_use:0:0"),
            trusted("extra.json:pre_tool_use:0:0")
        ));
        assert_eq!(fx.destructive(), vec![user_source(&dir.join("extra.json"))]);
    }

    #[test]
    fn a_malformed_plugin_hooks_file_is_skipped_without_an_error() {
        let fx = fixture();
        fx.write(
            &fx.plugin_dir("1.0.0").join("hooks/hooks.json"),
            "{ not json",
        );
        fx.config(&format!(
            "{ENABLED}{}",
            trusted("hooks/hooks.json:pre_tool_use:0:0")
        ));
        assert!(fx.destructive().is_empty());
    }

    #[test]
    fn the_newest_version_folder_is_read_and_local_wins_over_it() {
        let fx = fixture();
        let state = trusted("hooks/hooks.json:pre_tool_use:0:0");
        fx.config(&format!("{ENABLED}{state}"));
        fx.write(
            &fx.plugin_dir("1.9.0").join("hooks/hooks.json"),
            DESTRUCTIVE,
        );
        let newest = fx.plugin_dir("1.10.0").join("hooks/hooks.json");
        fx.write(&newest, DESTRUCTIVE);
        assert_eq!(fx.destructive(), vec![user_source(&newest)]);
        let local = fx.plugin_dir("local").join("hooks/hooks.json");
        fx.write(&local, DESTRUCTIVE);
        assert_eq!(fx.destructive(), vec![user_source(&local)]);
    }

    #[test]
    fn a_content_hash_mismatch_means_the_hook_does_not_run() {
        let fx = fixture();
        let dir = fx.plugin_dir("1.0.0");
        fx.write(&dir.join("hooks/hooks.json"), DESTRUCTIVE);
        let hash = content_hash(&dir).unwrap();
        let state = |content: &str| {
            format!(
                "{ENABLED}\n[hooks.state.'demo@mk:hooks/hooks.json:pre_tool_use:0:0']\ntrusted_hash = \"sha256:00\"\ntrusted_content_hash = \"{content}\"\n"
            )
        };
        fx.config(&state(&hash));
        assert_eq!(fx.destructive().len(), 1);
        fx.config(&state("sha256:ff"));
        assert!(fx.destructive().is_empty());
    }

    #[test]
    fn the_content_hash_matches_the_codex_bundle_fingerprint() {
        let root = tempdir().unwrap();
        std::fs::write(root.path().join("a.txt"), "hi").unwrap();
        std::fs::create_dir_all(root.path().join("d")).unwrap();
        std::fs::write(root.path().join("d/b.txt"), "yo").unwrap();
        std::fs::create_dir_all(root.path().join("__pycache__")).unwrap();
        std::fs::write(root.path().join("__pycache__/c"), "x").unwrap();
        assert_eq!(
            content_hash(root.path()).unwrap(),
            "sha256:d59b660b0c174d266ea94cbc88c3be574c5268db0608e06f7b761b3be7792cef"
        );
    }

    #[test]
    fn the_user_parser_watches_the_files_of_an_enabled_plugin() {
        let fx = fixture();
        let dir = fx.plugin_dir("1.0.0");
        fx.write(&dir.join("hooks/hooks.json"), DESTRUCTIVE);
        fx.write(&dir.join(".codex-plugin/plugin.json"), r#"{"name":"demo"}"#);
        fx.config(ENABLED);
        let watched = CodexParser::with_codex_home(Some(fx.codex.clone())).watched_paths(&fx.home);
        assert!(
            watched.contains(&dir.join("hooks/hooks.json")),
            "{watched:?}"
        );
        assert!(
            watched.contains(&dir.join(".codex-plugin/plugin.json")),
            "{watched:?}"
        );
    }
}
