//! #717: hooks that an enabled Codex plugin brings, read as Codex 0.172.0
//! does (`core-plugins/src/loader.rs`, `hooks/src/engine/discovery.rs`,
//! `plugin_trust.rs` and `plugin_fingerprint.rs`, rust-v0.172.0).
//!
//! A plugin is active when `[plugins."<name>@<marketplace>"]` is in the
//! config and does not set `enabled = false`. Its folder is the newest
//! valid version folder under `plugins/cache/<marketplace>/<name>/`, or
//! `local` when that folder exists. Its hooks come from the manifest `hooks`
//! field (a path, a list of paths, an inline object or a list of them) and,
//! with no usable field, from `hooks/hooks.json`.
//!
//! A hook runs when the user config holds `[hooks.state."<plugin>:<file>:
//! <event>:<group>:<handler>"]` with a `trusted_hash`, no `enabled = false`,
//! and a `trusted_content_hash` (when present) equal to the hash of the
//! plugin folder. The `trusted_hash` itself is not compared with the hook,
//! for the reason given on `HookTrust`. A legacy approval, with no
//! `trusted_content_hash`, is read as trusted: its baseline file would be
//! created by Codex on first use, so a read cannot tell.

use lodeline_core::event::{AiGuardFinding, ConfigLayer};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use toml::Value;

use super::codex::{config_source, emit_hook_reasons, hook_event_key_label, stamp_all};

const MANIFEST_DIRS: [&str; 2] = [".codex-plugin", ".claude-plugin"];
/// The `key_source` of the default hooks file.
const DEFAULT_HOOKS_KEY: &str = "hooks/hooks.json";

fn default_hooks(root: &Path) -> PathBuf {
    root.join("hooks").join("hooks.json")
}

fn manifest_files(root: &Path) -> impl Iterator<Item = PathBuf> + '_ {
    MANIFEST_DIRS
        .iter()
        .map(|dir| root.join(dir).join("plugin.json"))
}
const LOCAL_VERSION: &str = "local";

/// One plugin hook declaration: a file in the plugin folder, or a block of
/// its manifest.
pub(super) struct PluginHookFile {
    /// The part of the `hooks.state` key after `<plugin>:`.
    key_source: String,
    pub(super) file: PathBuf,
    hooks: Value,
}

pub(super) struct EnabledPlugin {
    id: String,
    root: PathBuf,
    pub(super) files: Vec<PluginHookFile>,
}

fn safe_segment(segment: &str) -> bool {
    !segment.is_empty() && segment != "." && segment != ".." && !segment.contains(['/', '\\'])
}

fn valid_version(version: &str) -> bool {
    !version.is_empty()
        && version != "."
        && version != ".."
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+'))
}

/// `active_plugin_version`: `local` when present, else the highest version,
/// by semver when both parse and by text otherwise.
fn active_version(base: &Path) -> Option<String> {
    let mut versions: Vec<String> = std::fs::read_dir(base)
        .ok()?
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|v| valid_version(v))
        .collect();
    versions.sort_unstable_by(|a, b| {
        match (semver::Version::parse(a), semver::Version::parse(b)) {
            (Ok(a), Ok(b)) => a.cmp(&b),
            _ => a.cmp(b),
        }
    });
    if versions.iter().any(|v| v == LOCAL_VERSION) {
        return Some(LOCAL_VERSION.to_string());
    }
    versions.pop()
}

pub(super) fn enabled_plugins(codex_dir: &Path, config: Option<&Value>) -> Vec<EnabledPlugin> {
    let Some(plugins) = config
        .and_then(|c| c.get("plugins"))
        .and_then(Value::as_table)
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, entry) in plugins {
        let Some(entry) = entry.as_table() else {
            continue;
        };
        if entry.get("enabled").and_then(Value::as_bool) == Some(false) {
            continue;
        }
        let Some((name, marketplace)) = id.rsplit_once('@') else {
            continue;
        };
        if !safe_segment(name) || !safe_segment(marketplace) {
            continue;
        }
        let base = codex_dir
            .join("plugins")
            .join("cache")
            .join(marketplace)
            .join(name);
        let Some(version) = active_version(&base) else {
            continue;
        };
        let root = base.join(version);
        out.push(EnabledPlugin {
            id: id.clone(),
            files: plugin_hook_files(&root),
            root,
        });
    }
    out
}

fn json_to_toml(json: serde_json::Value) -> Option<Value> {
    Value::try_from(json).ok()
}

/// A manifest path: `./` then a relative path that stays in the plugin folder.
fn manifest_path(root: &Path, raw: &str) -> Option<(PathBuf, String)> {
    let relative = raw.strip_prefix("./")?;
    if relative.is_empty() || relative.starts_with(['/', '\\']) {
        return None;
    }
    let mut path = root.to_path_buf();
    for part in relative.split(['/', '\\']) {
        if part == ".." || part.contains(':') {
            return None;
        }
        if part.is_empty() || part == "." {
            continue;
        }
        path.push(part);
    }
    Some((path, relative.replace('\\', "/")))
}

enum ManifestHooks {
    Paths(Vec<(PathBuf, String)>),
    Inline(Vec<serde_json::Value>),
}

/// The manifest `hooks` field as Codex reads it. `None` means no usable
/// field, so the default file applies.
fn manifest_hooks(root: &Path, field: &serde_json::Value) -> Option<ManifestHooks> {
    use serde_json::Value as J;
    let is_hooks_file = |v: &J| {
        v.as_object()
            .is_some_and(|o| o.keys().all(|k| k == "hooks" || k == "description"))
    };
    match field {
        J::String(path) => manifest_path(root, path).map(|p| ManifestHooks::Paths(vec![p])),
        J::Array(items) if !items.is_empty() && items.iter().all(J::is_string) => {
            let paths: Vec<_> = items
                .iter()
                .filter_map(|v| manifest_path(root, v.as_str()?))
                .collect();
            (!paths.is_empty()).then_some(ManifestHooks::Paths(paths))
        }
        J::Object(_) if is_hooks_file(field) => Some(ManifestHooks::Inline(vec![field.clone()])),
        J::Array(items) if !items.is_empty() && items.iter().all(is_hooks_file) => {
            Some(ManifestHooks::Inline(items.clone()))
        }
        _ => None,
    }
}

fn plugin_hook_files(root: &Path) -> Vec<PluginHookFile> {
    let manifest = manifest_files(root).find(|p| p.is_file());
    let mut field = None;
    if let Some(path) = &manifest {
        let parsed = std::fs::read_to_string(path)
            .map_err(|e| e.to_string())
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).map_err(|e| e.to_string()));
        match parsed {
            Ok(json) => field = json.get("hooks").cloned(),
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "codex plugin manifest unreadable; skipped");
                return Vec::new();
            }
        }
    }
    let declared = field.as_ref().and_then(|f| manifest_hooks(root, f));
    let mut out = Vec::new();
    match declared {
        Some(ManifestHooks::Inline(blocks)) => {
            let Some(manifest) = manifest else {
                return out;
            };
            for (index, block) in blocks.into_iter().enumerate() {
                let hooks = json_to_toml(block);
                let has_hooks = hooks
                    .as_ref()
                    .and_then(|h| h.get("hooks"))
                    .and_then(Value::as_table)
                    .is_some_and(|t| !t.is_empty());
                if let (true, Some(hooks)) = (has_hooks, hooks) {
                    out.push(PluginHookFile {
                        key_source: format!("plugin.json#hooks[{index}]"),
                        file: manifest.clone(),
                        hooks,
                    });
                }
            }
        }
        Some(ManifestHooks::Paths(paths)) => {
            for (path, relative) in paths {
                out.extend(hook_file(path, relative));
            }
        }
        None => out.extend(hook_file(
            default_hooks(root),
            DEFAULT_HOOKS_KEY.to_string(),
        )),
    }
    out
}

fn hook_file(file: PathBuf, key_source: String) -> Option<PluginHookFile> {
    let hooks = super::codex::read_hooks_json(&file)?;
    Some(PluginHookFile {
        key_source,
        file,
        hooks,
    })
}

/// The hash Codex stores as `trusted_content_hash`: a SHA-256 over the
/// plugin folder (names, kinds, sizes and bytes in a fixed order), without
/// Python caches, `.venv` and `.egg-info` entries.
pub(super) fn content_hash(root: &Path) -> std::io::Result<String> {
    if !std::fs::symlink_metadata(root)?.is_dir() {
        return Err(std::io::Error::other("plugin root is not a directory"));
    }
    let mut hash = Sha256::new();
    hash.update(b"codex-plugin-bundle-v1");
    let mut pending = vec![root.to_path_buf()];
    let mut buffer = [0_u8; 64 * 1024];
    while let Some(path) = pending.pop() {
        let relative = path.strip_prefix(root).map_err(std::io::Error::other)?;
        let skipped = relative
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|n| {
                matches!(n, "__pycache__" | ".venv")
                    || n.ends_with(".pyc")
                    || n.ends_with(".egg-info")
            });
        if skipped {
            continue;
        }
        let name = relative.as_os_str().as_encoded_bytes();
        hash.update((name.len() as u64).to_le_bytes());
        hash.update(name);
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            hash.update(b"directory");
            let mut entries = std::fs::read_dir(&path)?.collect::<Result<Vec<_>, _>>()?;
            entries.sort_by_key(std::fs::DirEntry::file_name);
            pending.extend(entries.iter().rev().map(std::fs::DirEntry::path));
        } else if metadata.is_file() {
            hash.update(b"file");
            let length = metadata.len();
            hash.update(length.to_le_bytes());
            let mut file = std::fs::File::open(&path)?.take(length.saturating_add(1));
            let mut read = 0_u64;
            loop {
                let count = file.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                read += count as u64;
                hash.update(&buffer[..count]);
            }
            if read != length {
                return Err(std::io::Error::other("plugin file changed while hashing"));
            }
        } else {
            return Err(std::io::Error::other("unsupported plugin entry type"));
        }
    }
    Ok(format!("sha256:{:x}", hash.finalize()))
}

/// Findings of every hook that runs. `states` is the user config's
/// `[hooks.state]` table: Codex reads approvals from the user layer alone.
pub(super) fn plugin_findings(
    plugins: &[EnabledPlugin],
    states: Option<&toml::Table>,
    home: Option<&Path>,
) -> Vec<AiGuardFinding> {
    let mut out = Vec::new();
    for plugin in plugins {
        let content = std::cell::OnceCell::new();
        for file in &plugin.files {
            let mut reasons = Vec::new();
            emit_hook_reasons(
                &file.hooks,
                |event, group, handler| {
                    let key = format!(
                        "{}:{}:{}:{group}:{handler}",
                        plugin.id,
                        file.key_source,
                        hook_event_key_label(event)
                    );
                    let Some(state) = states
                        .and_then(|s| s.iter().find(|(k, _)| k.trim() == key).map(|(_, v)| v))
                    else {
                        return false;
                    };
                    if state.get("trusted_hash").and_then(Value::as_str).is_none()
                        || state.get("enabled").and_then(Value::as_bool) == Some(false)
                    {
                        return false;
                    }
                    match state.get("trusted_content_hash").and_then(Value::as_str) {
                        None => true,
                        Some(expected) => {
                            content
                                .get_or_init(|| content_hash(&plugin.root).ok())
                                .as_deref()
                                == Some(expected)
                        }
                    }
                },
                home,
                &mut reasons,
            );
            let source = config_source(&ConfigLayer::User, &file.file);
            out.extend(stamp_all(reasons, Some(source)));
        }
    }
    out
}

/// Files whose edit changes what the plugins of `config` run.
pub(super) fn watched_paths(codex_dir: &Path, config: Option<&Value>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for plugin in enabled_plugins(codex_dir, config) {
        out.push(default_hooks(&plugin.root));
        out.extend(manifest_files(&plugin.root));
        out.extend(plugin.files.into_iter().map(|f| f.file));
    }
    out.sort();
    out.dedup();
    out
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
            self.codex
                .join("plugins")
                .join("cache")
                .join("mk")
                .join("demo")
                .join(version)
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
        let file = fx.plugin_dir("1.0.0").join("hooks").join("hooks.json");
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
            &fx.plugin_dir("1.0.0").join("hooks").join("hooks.json"),
            DESTRUCTIVE,
        );
        fx.config(ENABLED);
        assert!(fx.destructive().is_empty());
    }

    #[test]
    fn a_disabled_or_unlisted_plugin_contributes_nothing() {
        let fx = fixture();
        fx.write(
            &fx.plugin_dir("1.0.0").join("hooks").join("hooks.json"),
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
        let manifest = fx
            .plugin_dir("1.0.0")
            .join(".codex-plugin")
            .join("plugin.json");
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
        fx.write(&dir.join("hooks").join("hooks.json"), DESTRUCTIVE);
        fx.write(
            &dir.join(".codex-plugin").join("plugin.json"),
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
            &fx.plugin_dir("1.0.0").join("hooks").join("hooks.json"),
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
            &fx.plugin_dir("1.9.0").join("hooks").join("hooks.json"),
            DESTRUCTIVE,
        );
        let newest = fx.plugin_dir("1.10.0").join("hooks").join("hooks.json");
        fx.write(&newest, DESTRUCTIVE);
        assert_eq!(fx.destructive(), vec![user_source(&newest)]);
        fx.write(
            &fx.plugin_dir("v9").join("hooks").join("hooks.json"),
            DESTRUCTIVE,
        );
        let local = fx.plugin_dir("local").join("hooks").join("hooks.json");
        fx.write(&local, DESTRUCTIVE);
        assert_eq!(fx.destructive(), vec![user_source(&local)]);
    }

    #[test]
    fn a_plugin_entry_without_enabled_counts_as_enabled() {
        let fx = fixture();
        let file = fx.plugin_dir("1.0.0").join("hooks").join("hooks.json");
        fx.write(&file, DESTRUCTIVE);
        fx.config(&format!(
            "[plugins.\"demo@mk\"]\n{}",
            trusted("hooks/hooks.json:pre_tool_use:0:0")
        ));
        assert_eq!(fx.destructive(), vec![user_source(&file)]);
    }

    #[test]
    fn a_plugin_name_that_leaves_the_cache_folder_is_ignored() {
        let fx = fixture();
        fx.write(
            &fx.codex
                .join("outside")
                .join("1.0.0")
                .join("hooks")
                .join("hooks.json"),
            DESTRUCTIVE,
        );
        std::fs::create_dir_all(fx.codex.join("plugins").join("cache").join("mk")).unwrap();
        fx.config(
            "[plugins.\"../../../outside@mk\"]\nenabled = true\n\
             [hooks.state.'../../../outside@mk:hooks/hooks.json:pre_tool_use:0:0']\ntrusted_hash = \"sha256:00\"\n",
        );
        assert!(fx.destructive().is_empty());
    }

    #[test]
    fn a_manifest_hooks_path_that_leaves_the_plugin_folder_is_ignored() {
        let fx = fixture();
        let dir = fx.plugin_dir("1.0.0");
        fx.write(&dir.join("..").join("outside.json"), DESTRUCTIVE);
        fx.write(
            &dir.join(".codex-plugin").join("plugin.json"),
            r#"{"name":"demo","hooks":"./../outside.json"}"#,
        );
        fx.config(&format!(
            "{ENABLED}{}",
            trusted("../outside.json:pre_tool_use:0:0")
        ));
        assert!(fx.destructive().is_empty());
    }

    #[test]
    fn a_malformed_manifest_means_the_plugin_adds_nothing() {
        let fx = fixture();
        let dir = fx.plugin_dir("1.0.0");
        fx.write(&dir.join("hooks").join("hooks.json"), DESTRUCTIVE);
        fx.write(&dir.join(".codex-plugin").join("plugin.json"), "{ not json");
        fx.config(&format!(
            "{ENABLED}{}",
            trusted("hooks/hooks.json:pre_tool_use:0:0")
        ));
        assert!(fx.destructive().is_empty());
    }

    #[test]
    fn a_state_without_a_trusted_hash_does_not_run_a_plugin_hook() {
        let fx = fixture();
        fx.write(
            &fx.plugin_dir("1.0.0").join("hooks").join("hooks.json"),
            DESTRUCTIVE,
        );
        fx.config(&format!(
            "{ENABLED}[hooks.state.'demo@mk:hooks/hooks.json:pre_tool_use:0:0']\nenabled = true\n"
        ));
        assert!(fx.destructive().is_empty());
    }

    #[test]
    fn a_state_that_sets_enabled_false_stops_a_plugin_hook() {
        let fx = fixture();
        fx.write(
            &fx.plugin_dir("1.0.0").join("hooks").join("hooks.json"),
            DESTRUCTIVE,
        );
        fx.config(&format!(
            "{ENABLED}{}enabled = false\n",
            trusted("hooks/hooks.json:pre_tool_use:0:0")
        ));
        assert!(fx.destructive().is_empty());
    }

    #[test]
    fn a_content_hash_mismatch_means_the_hook_does_not_run() {
        let fx = fixture();
        let dir = fx.plugin_dir("1.0.0");
        fx.write(&dir.join("hooks").join("hooks.json"), DESTRUCTIVE);
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
        std::fs::write(root.path().join("b.txt"), "yo").unwrap();
        std::fs::create_dir_all(root.path().join("__pycache__")).unwrap();
        std::fs::write(root.path().join("__pycache__").join("c"), "x").unwrap();
        assert_eq!(
            content_hash(root.path()).unwrap(),
            "sha256:4a206b41951ed24079c3fc6916ca6dc307beb5c7c17662c465b091e0225da9db"
        );
    }

    /// Codex hashes a nested path with the separator of its platform.
    #[cfg(unix)]
    #[test]
    fn the_content_hash_covers_a_nested_folder() {
        let root = tempdir().unwrap();
        std::fs::write(root.path().join("a.txt"), "hi").unwrap();
        std::fs::create_dir_all(root.path().join("d")).unwrap();
        std::fs::write(root.path().join("d").join("b.txt"), "yo").unwrap();
        assert_eq!(
            content_hash(root.path()).unwrap(),
            "sha256:d59b660b0c174d266ea94cbc88c3be574c5268db0608e06f7b761b3be7792cef"
        );
    }

    #[test]
    fn the_user_parser_watches_the_files_of_an_enabled_plugin() {
        let fx = fixture();
        let dir = fx.plugin_dir("1.0.0");
        fx.write(&dir.join("hooks").join("hooks.json"), DESTRUCTIVE);
        fx.write(
            &dir.join(".codex-plugin").join("plugin.json"),
            r#"{"name":"demo","hooks":"./extra/h.json"}"#,
        );
        fx.write(&dir.join("extra").join("h.json"), DESTRUCTIVE);
        fx.config(ENABLED);
        let watched = CodexParser::with_codex_home(Some(fx.codex.clone())).watched_paths(&fx.home);
        assert!(
            watched.contains(&dir.join("hooks").join("hooks.json")),
            "{watched:?}"
        );
        assert!(
            watched.contains(&dir.join(".codex-plugin").join("plugin.json")),
            "{watched:?}"
        );
        assert!(
            watched.contains(&dir.join("extra").join("h.json")),
            "{watched:?}"
        );
    }
}
