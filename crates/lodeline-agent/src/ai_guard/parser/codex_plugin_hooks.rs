//! #717: hooks that an enabled Codex plugin brings, read as Codex 0.172.0
//! does (`core-plugins/src/loader.rs` and `manifest.rs`, `hooks/src/engine/
//! discovery.rs`, `plugin_trust.rs` and `plugin_fingerprint.rs`, and
//! `utils/plugins/src/plugin_namespace.rs`, all at rust-v0.172.0). The
//! user-visible rules are in `docs/codex-coverage.md`.
//!
//! A plugin is read only when its `[plugins."<name>@<marketplace>"]` entry is
//! enabled, its id is valid, and the user config holds a `hooks.state` row
//! for it. Nothing in its folder is read before that. Every read stays
//! inside the Codex folder after links are resolved, takes regular files
//! only, and has a byte cap.

use lodeline_core::event::{AiGuardFinding, ConfigLayer};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use toml::Value;

use super::codex::{config_source, emit_hook_reasons, hook_event_key_label, stamp_all};

/// Largest manifest or hooks file that is read.
const MAX_JSON_BYTES: u64 = 1024 * 1024;
/// Largest legacy baseline file that is read.
const MAX_BASELINE_BYTES: u64 = 256;
/// Caps of the plugin folder hash: files, entries (files and folders) and bytes.
const MAX_BUNDLE_FILES: usize = 10_000;
const MAX_BUNDLE_ENTRIES: usize = 20_000;
const MAX_BUNDLE_BYTES: u64 = 256 * 1024 * 1024;

/// Manifest locations, in the order Codex looks (`DISCOVERABLE_PLUGIN_MANIFEST_PATHS`).
const MANIFEST_DIRS: [&str; 3] = [".codex-plugin", ".claude-plugin", ".cursor-plugin"];
const AGENT_MANIFEST: &str = "plugin.json";
const AGENT_SCHEMA_PREFIX: &str = "https://agent-plugins.org/schemas/";
const DEFAULT_HOOKS_KEY: &str = "hooks/hooks.json";
/// Most version folders of one plugin that are listed.
const MAX_VERSION_FOLDERS: usize = 1_000;
const LOCAL_VERSION: &str = "local";
const DEFAULT_OUTPUT_TOKEN_LIMIT: usize = 2_500;

// ---------------------------------------------------------------------------
// Typed hook files, as `codex-protocol/src/hooks.rs` and `config/src/hook_config.rs`.

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HooksFile {
    #[serde(default)]
    #[allow(dead_code)]
    description: Option<String>,
    #[serde(default)]
    hooks: Events,
}

macro_rules! events {
    ($($field:ident => $name:literal),* $(,)?) => {
        #[derive(Deserialize, Default)]
        struct Events {
            $(#[serde(rename = $name, default)] $field: Vec<Group>,)*
        }

        impl Events {
            fn all(&self) -> Vec<(&'static str, &Vec<Group>)> {
                vec![$(($name, &self.$field)),*]
            }
        }
    };
}

events! {
    pre_model_request => "PreModelRequest",
    post_model_request => "PostModelRequest",
    pre_tool_use => "PreToolUse",
    permission_request => "PermissionRequest",
    post_tool_use => "PostToolUse",
    pre_compact => "PreCompact",
    post_compact => "PostCompact",
    session_start => "SessionStart",
    session_end => "SessionEnd",
    user_prompt_submit => "UserPromptSubmit",
    subagent_start => "SubagentStart",
    subagent_stop => "SubagentStop",
    stop => "Stop",
    interrupt => "Interrupt",
}

impl Events {
    fn is_empty(&self) -> bool {
        self.all().iter().all(|(_, groups)| groups.is_empty())
    }

    fn group(&self, event: &str, group: usize) -> Option<&Group> {
        self.all()
            .into_iter()
            .find(|(name, _)| *name == event)
            .and_then(|(_, groups)| groups.get(group))
    }
}

#[derive(Deserialize)]
struct Group {
    #[serde(default)]
    matcher: Option<String>,
    #[serde(default)]
    hooks: Vec<Handler>,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum Handler {
    #[serde(rename = "command")]
    Command {
        command: String,
        #[serde(default, rename = "commandWindows", alias = "command_windows")]
        command_windows: Option<String>,
        #[serde(default, rename = "timeout")]
        timeout_sec: Option<u64>,
        #[serde(default)]
        r#async: bool,
        #[serde(default, rename = "statusMessage")]
        status_message: Option<String>,
        #[serde(default, rename = "additionalContextLimit")]
        additional_context_limit: Option<usize>,
    },
    #[serde(rename = "mcp_tool")]
    McpTool {
        server: String,
        tool: String,
        #[serde(default, deserialize_with = "mcp_input")]
        input: serde_json::Map<String, serde_json::Value>,
        #[serde(default, rename = "timeout")]
        timeout_sec: Option<u64>,
        #[serde(default, rename = "statusMessage")]
        status_message: Option<String>,
    },
    #[serde(rename = "prompt")]
    Prompt {},
    #[serde(rename = "agent")]
    Agent {},
}

fn mcp_input<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<serde_json::Map<String, serde_json::Value>, D::Error> {
    use serde_json::Value as J;
    fn representable(value: &J) -> bool {
        match value {
            J::Null => false,
            J::Number(n) => !n.is_u64() || n.as_i64().is_some(),
            J::Array(items) => items.iter().all(representable),
            J::Object(items) => items.values().all(representable),
            J::Bool(_) | J::String(_) => true,
        }
    }
    let input = serde_json::Map::deserialize(deserializer)?;
    if input.values().all(representable) {
        Ok(input)
    } else {
        Err(serde::de::Error::custom(
            "MCP hook input must be representable as TOML",
        ))
    }
}

fn takes_matcher(event: &str) -> bool {
    matches!(
        event,
        "PreToolUse"
            | "PermissionRequest"
            | "PostToolUse"
            | "SessionStart"
            | "SessionEnd"
            | "SubagentStart"
            | "SubagentStop"
            | "PreCompact"
            | "PostCompact"
    )
}

/// `HookMatcher::new`: an invalid regex skips the whole group.
fn matcher_compiles(pattern: &str) -> bool {
    pattern.is_empty()
        || pattern == "*"
        || pattern
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '|')
        || regex::Regex::new(pattern).is_ok()
}

fn sorted(value: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value as J;
    match value {
        J::Object(map) => {
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for key in keys {
                out.insert(key.clone(), sorted(&map[key]));
            }
            J::Object(out)
        }
        J::Array(items) => J::Array(items.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

/// The declaration hash Codex stores as `trusted_hash`, for the handler at
/// (`event`, `group`, `handler`), or `None` when Codex skips that handler
/// (`hook_hash`, `normalize_command_hook` and `append_matcher_groups` in
/// `discovery.rs`).
fn declaration_hash(events: &Events, event: &str, group: usize, handler: usize) -> Option<String> {
    use serde_json::{json, Value as J};
    let group = events.group(event, group)?;
    let matcher = group.matcher.as_deref().filter(|_| takes_matcher(event));
    if matcher.is_some_and(|m| !matcher_compiles(m)) {
        return None;
    }
    let timeout = |declared: Option<u64>| match event {
        "SessionEnd" | "Interrupt" => declared.unwrap_or(1).clamp(1, 3),
        _ => declared.unwrap_or(600).max(1),
    };
    let normalized = match group.hooks.get(handler)? {
        Handler::Command {
            command,
            command_windows,
            timeout_sec,
            r#async,
            status_message,
            additional_context_limit,
        } => {
            let command = if cfg!(windows) {
                command_windows.as_ref().unwrap_or(command)
            } else {
                command
            };
            if command.trim().is_empty() {
                return None;
            }
            let limit = matches!(
                event,
                "PreToolUse"
                    | "PostToolUse"
                    | "SessionStart"
                    | "UserPromptSubmit"
                    | "SubagentStart"
            )
            .then_some(*additional_context_limit)
            .flatten()
            .filter(|limit| *limit != DEFAULT_OUTPUT_TOKEN_LIMIT);
            let mut object = json!({
                "type": "command",
                "command": command,
                "timeout": timeout(*timeout_sec),
                "async": r#async,
            });
            if let Some(message) = status_message {
                object["statusMessage"] = J::from(message.as_str());
            }
            if let Some(limit) = limit {
                object["additionalContextLimit"] = J::from(limit);
            }
            object
        }
        Handler::McpTool {
            server,
            tool,
            input,
            timeout_sec,
            status_message,
        } => {
            if event == "SessionEnd" || server.trim().is_empty() || tool.trim().is_empty() {
                return None;
            }
            let mut object = json!({
                "type": "mcp_tool",
                "server": server,
                "tool": tool,
                "input": input,
                "timeout": timeout(*timeout_sec),
            });
            if let Some(message) = status_message {
                object["statusMessage"] = J::from(message.as_str());
            }
            object
        }
        Handler::Prompt {} | Handler::Agent {} => return None,
    };
    let mut identity = json!({
        "event_name": hook_event_key_label(event),
        "hooks": [normalized],
    });
    if let Some(matcher) = matcher {
        identity["matcher"] = J::from(matcher);
    }
    let bytes = serde_json::to_vec(&sorted(&identity)).ok()?;
    Some(format!("sha256:{:x}", Sha256::digest(bytes)))
}

// ---------------------------------------------------------------------------
// Plugin ids, folders and containment.

/// `validate_plugin_segment`: ASCII letters, digits, `-` and `_`; a plugin
/// name also takes dots that separate non-empty segments.
fn valid_segment(segment: &str, allow_dots: bool) -> bool {
    if segment.is_empty() {
        return false;
    }
    if allow_dots && (segment.starts_with('.') || segment.ends_with('.') || segment.contains(".."))
    {
        return false;
    }
    segment
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_') || allow_dots && c == '.')
}

fn parse_id(id: &str) -> Option<(&str, &str)> {
    let (name, marketplace) = id.rsplit_once('@')?;
    (valid_segment(name, true) && valid_segment(marketplace, false)).then_some((name, marketplace))
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
    let entries: Vec<_> = std::fs::read_dir(base)
        .ok()?
        .take(MAX_VERSION_FOLDERS + 1)
        .filter_map(Result::ok)
        .collect();
    if entries.len() > MAX_VERSION_FOLDERS {
        tracing::warn!(path = %base.display(), cap = MAX_VERSION_FOLDERS, "codex plugin has too many version folders; skipped");
        return None;
    }
    let mut versions: Vec<String> = entries
        .into_iter()
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

/// The Codex folder, resolved once; every path read must resolve under it.
struct Home(PathBuf);

impl Home {
    fn new(codex_dir: &Path) -> Option<Self> {
        dunce::canonicalize(codex_dir).ok().map(Self)
    }

    /// Whether `path` resolves, through every link on it, under the Codex folder.
    fn contains(&self, path: &Path) -> bool {
        let inside = dunce::canonicalize(path).is_ok_and(|real| real.starts_with(&self.0));
        if !inside && path.symlink_metadata().is_ok() {
            tracing::warn!(path = %path.display(), "codex plugin path leaves the Codex folder; skipped");
        }
        inside
    }

    /// The bytes of a regular file under the Codex folder, at most `cap`.
    fn read(&self, path: &Path, cap: u64) -> Option<Vec<u8>> {
        let metadata = std::fs::symlink_metadata(path).ok()?;
        if !metadata.file_type().is_file() {
            tracing::warn!(path = %path.display(), "codex plugin file is not a regular file; skipped");
            return None;
        }
        if !self.contains(path) {
            return None;
        }
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .ok()?
            .take(cap + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        if bytes.len() as u64 > cap {
            tracing::warn!(path = %path.display(), cap, "codex plugin file over the size cap; skipped");
            return None;
        }
        Some(bytes)
    }
}

// ---------------------------------------------------------------------------
// Manifest, as `find_plugin_manifest_path`, `ManifestCache::load` and `manifest.rs`.

fn is_file_not_link(path: &Path) -> Option<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(m) => Some(m.file_type().is_file()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => Some(false),
    }
}

/// The manifest JSON of a legacy-format plugin, or `None` when Codex loads
/// no manifest, loads an Agent Plugin manifest (which has no hooks here), or
/// fails to parse it.
fn load_manifest(home: &Home, root: &Path) -> Option<serde_json::Value> {
    let agent = root.join(AGENT_MANIFEST);
    match std::fs::symlink_metadata(&agent) {
        Ok(m) if !m.file_type().is_file() => return None,
        Ok(_) => {
            let text = home.read(&agent, MAX_JSON_BYTES)?;
            let schema = serde_json::from_slice::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| v.get("$schema").and_then(|s| s.as_str().map(str::to_owned)));
            if schema.is_some_and(|s| s.starts_with(AGENT_SCHEMA_PREFIX)) {
                return None;
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return None,
    }
    for dir in MANIFEST_DIRS {
        let parent = root.join(dir);
        match std::fs::symlink_metadata(&parent) {
            Ok(m) if !m.file_type().is_dir() => return None,
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return None,
        }
        let manifest = parent.join("plugin.json");
        match is_file_not_link(&manifest) {
            Some(true) => {
                let bytes = home.read(&manifest, MAX_JSON_BYTES)?;
                let json: serde_json::Value = match serde_json::from_slice(&bytes) {
                    Ok(json) => json,
                    Err(error) => {
                        tracing::warn!(path = %manifest.display(), %error, "codex plugin manifest invalid; plugin skipped");
                        return None;
                    }
                };
                if !manifest_is_valid(&json) {
                    tracing::warn!(path = %manifest.display(), "codex plugin manifest has a field of the wrong type; plugin skipped");
                    return None;
                }
                return Some(json);
            }
            Some(false) => return None,
            None => {}
        }
    }
    None
}

/// The typed fields of `RawPluginManifest` that a plain check can decide.
fn manifest_is_valid(json: &serde_json::Value) -> bool {
    use serde_json::Value as J;
    let Some(object) = json.as_object() else {
        return false;
    };
    let string_or_null = |key: &str| object.get(key).is_none_or(|v| v.is_string() || v.is_null());
    object.get("name").is_none_or(J::is_string)
        && string_or_null("version")
        && string_or_null("description")
        && string_or_null("apps")
        && object.get("keywords").is_none_or(|v| {
            v.as_array()
                .is_some_and(|items| items.iter().all(J::is_string))
        })
}

fn typed_hooks_file(value: &serde_json::Value) -> Option<HooksFile> {
    serde_json::from_value(value.clone()).ok()
}

enum Declared {
    Paths(Vec<(PathBuf, String)>),
    Inline(Vec<serde_json::Value>),
}

/// A manifest path: `./` then a relative path that stays in the plugin
/// folder. `key` is the path below the plugin folder with `/` separators.
fn resolve_path(root: &Path, raw: &str) -> Option<(PathBuf, String)> {
    let relative = raw.strip_prefix("./")?;
    if relative.is_empty() {
        return None;
    }
    let windows = cfg!(windows);
    let parts: Vec<&str> = if windows {
        relative.split(['/', '\\']).collect()
    } else {
        relative.split('/').collect()
    };
    if parts.contains(&"..") {
        return None;
    }
    if relative.starts_with('/')
        || windows
            && (relative.starts_with('\\')
                || matches!(relative.as_bytes(), [d, b':', ..] if d.is_ascii_alphabetic()))
    {
        return None;
    }
    let parts: Vec<&str> = parts
        .into_iter()
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
    if parts.is_empty() {
        return None;
    }
    let mut path = root.to_path_buf();
    path.extend(&parts);
    Some((path, parts.join("/").replace('\\', "/")))
}

/// `RawPluginManifestHooks`, tried in the order Codex declares: a path, a
/// list of paths, an inline file, a list of inline files. Anything else, and
/// a list of paths that all fail, means the default file.
fn declared_hooks(root: &Path, field: &serde_json::Value) -> Option<Declared> {
    use serde_json::Value as J;
    match field {
        J::String(path) => resolve_path(root, path).map(|p| Declared::Paths(vec![p])),
        J::Array(items) if items.iter().all(J::is_string) => {
            let paths: Vec<_> = items
                .iter()
                .filter_map(|v| resolve_path(root, v.as_str()?))
                .collect();
            let mut seen = std::collections::HashSet::new();
            let paths: Vec<_> = paths
                .into_iter()
                .filter(|(path, _)| seen.insert(path.clone()))
                .collect();
            (!paths.is_empty()).then_some(Declared::Paths(paths))
        }
        J::Object(_) if typed_hooks_file(field).is_some() => {
            Some(Declared::Inline(vec![field.clone()]))
        }
        J::Array(items) if items.iter().all(|v| typed_hooks_file(v).is_some()) => {
            (!items.is_empty()).then(|| Declared::Inline(items.clone()))
        }
        _ => None,
    }
}

/// JSON to TOML for the shared emitter; a null object value is dropped.
fn json_to_toml(json: &serde_json::Value) -> Option<Value> {
    use serde_json::Value as J;
    Some(match json {
        J::Null => return None,
        J::Bool(b) => Value::Boolean(*b),
        J::Number(n) => match n.as_i64() {
            Some(i) => Value::Integer(i),
            None => Value::Float(n.as_f64()?),
        },
        J::String(s) => Value::String(s.clone()),
        J::Array(items) => Value::Array(items.iter().filter_map(json_to_toml).collect()),
        J::Object(map) => Value::Table(
            map.iter()
                .filter_map(|(k, v)| Some((k.clone(), json_to_toml(v)?)))
                .collect(),
        ),
    })
}

/// One plugin hook declaration: a file in the plugin folder, or a block of
/// its manifest.
struct PluginHookFile {
    /// The part of the `hooks.state` key after `<plugin>:`.
    key_source: String,
    file: PathBuf,
    typed: Events,
    scored: Value,
}

fn hook_file(
    file: PathBuf,
    key_source: String,
    json: &serde_json::Value,
) -> Option<PluginHookFile> {
    let typed = match typed_hooks_file(json) {
        Some(file) => file.hooks,
        None => {
            tracing::warn!(path = %file.display(), "codex plugin hooks file invalid; skipped");
            return None;
        }
    };
    if typed.is_empty() {
        return None;
    }
    Some(PluginHookFile {
        key_source,
        file,
        typed,
        scored: json_to_toml(json)?,
    })
}

fn plugin_hook_files(home: &Home, root: &Path) -> Vec<PluginHookFile> {
    let Some(manifest) = load_manifest(home, root) else {
        return Vec::new();
    };
    let declared = manifest.get("hooks").and_then(|f| declared_hooks(root, f));
    let manifest_file = MANIFEST_DIRS
        .iter()
        .map(|d| root.join(d).join("plugin.json"))
        .find(|p| p.is_file());
    let read_json = |path: &Path| {
        let bytes = home.read(path, MAX_JSON_BYTES)?;
        match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(json) => Some(json),
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "codex plugin hooks file invalid; skipped");
                None
            }
        }
    };
    let mut out = Vec::new();
    match declared {
        Some(Declared::Inline(blocks)) => {
            let Some(manifest_file) = manifest_file else {
                return out;
            };
            for (index, block) in blocks.iter().enumerate() {
                out.extend(hook_file(
                    manifest_file.clone(),
                    format!("plugin.json#hooks[{index}]"),
                    block,
                ));
            }
        }
        Some(Declared::Paths(paths)) => {
            for (path, key) in paths {
                out.extend(read_json(&path).and_then(|json| hook_file(path, key, &json)));
            }
        }
        None => {
            let path = root.join("hooks").join("hooks.json");
            if path.is_file() {
                out.extend(
                    read_json(&path)
                        .and_then(|json| hook_file(path, DEFAULT_HOOKS_KEY.to_string(), &json)),
                );
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Which plugins, and what runs.

/// An enabled plugin with a valid id and a `hooks.state` row.
pub(super) struct Candidate {
    id: String,
    base: PathBuf,
}

pub(super) fn candidates(
    codex_dir: &Path,
    config: Option<&Value>,
    states: Option<&toml::Table>,
) -> Vec<Candidate> {
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
        let enabled = match entry.get("enabled") {
            None => true,
            Some(Value::Boolean(b)) => *b,
            Some(_) => false,
        };
        let Some((name, marketplace)) = parse_id(id) else {
            continue;
        };
        let prefix = format!("{id}:");
        if !enabled || !states.is_some_and(|s| s.keys().any(|k| k.starts_with(&prefix))) {
            continue;
        }
        out.push(Candidate {
            id: id.clone(),
            base: codex_dir
                .join("plugins")
                .join("cache")
                .join(marketplace)
                .join(name),
        });
    }
    out
}

pub(super) struct LoadedPlugin {
    id: String,
    root: PathBuf,
    files: Vec<PluginHookFile>,
}

pub(super) fn load(codex_dir: &Path, candidates: &[Candidate]) -> Vec<LoadedPlugin> {
    let Some(home) = Home::new(codex_dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for candidate in candidates {
        if !home.contains(&candidate.base) {
            continue;
        }
        let Some(version) = active_version(&candidate.base) else {
            continue;
        };
        let root = candidate.base.join(version);
        let is_dir = std::fs::symlink_metadata(&root).is_ok_and(|m| m.file_type().is_dir());
        if !is_dir || !home.contains(&root) {
            continue;
        }
        let files = plugin_hook_files(&home, &root);
        out.push(LoadedPlugin {
            id: candidate.id.clone(),
            root,
            files,
        });
    }
    out
}

/// The hash Codex stores as `trusted_content_hash`: a SHA-256 over the
/// plugin folder (names, kinds, sizes and bytes in a fixed order), without
/// Python caches, `.venv` and `.egg-info` entries. A link, any other entry
/// that is not a file or folder, or a folder past a cap, is an error.
pub(super) fn content_hash(root: &Path) -> std::io::Result<String> {
    content_hash_with(
        root,
        Caps {
            files: MAX_BUNDLE_FILES,
            entries: MAX_BUNDLE_ENTRIES,
            bytes: MAX_BUNDLE_BYTES,
        },
    )
}

struct Caps {
    files: usize,
    entries: usize,
    bytes: u64,
}

fn content_hash_with(root: &Path, caps: Caps) -> std::io::Result<String> {
    let too_big = |what: &str| std::io::Error::other(format!("plugin folder over the {what} cap"));
    if !std::fs::symlink_metadata(root)?.is_dir() {
        return Err(std::io::Error::other("plugin root is not a directory"));
    }
    let real_root = dunce::canonicalize(root)?;
    let mut hash = Sha256::new();
    hash.update(b"codex-plugin-bundle-v1");
    let mut pending = vec![root.to_path_buf()];
    let mut buffer = [0_u8; 64 * 1024];
    let (mut entries, mut files, mut bytes) = (0_usize, 0_usize, 0_u64);
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
        entries += 1;
        if entries > caps.entries {
            return Err(too_big("entry"));
        }
        let name = relative.as_os_str().as_encoded_bytes();
        hash.update((name.len() as u64).to_le_bytes());
        hash.update(name);
        let metadata = std::fs::symlink_metadata(&path)?;
        if !dunce::canonicalize(&path)?.starts_with(&real_root) {
            return Err(std::io::Error::other(
                "plugin entry resolves outside the plugin folder",
            ));
        }
        if metadata.is_dir() {
            hash.update(b"directory");
            let mut children = Vec::new();
            for entry in std::fs::read_dir(&path)? {
                children.push(entry?);
                if entries + children.len() > caps.entries {
                    return Err(too_big("entry"));
                }
            }
            children.sort_by_key(std::fs::DirEntry::file_name);
            pending.extend(children.iter().rev().map(std::fs::DirEntry::path));
        } else if metadata.is_file() {
            hash.update(b"file");
            files += 1;
            let length = metadata.len();
            bytes = bytes.saturating_add(length);
            if files > caps.files {
                return Err(too_big("file"));
            }
            if bytes > caps.bytes {
                return Err(too_big("byte"));
            }
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

/// `legacy_trust_path`: the baseline file of one plugin and user config path.
fn baseline_path(codex_dir: &Path, plugin_id: &str) -> PathBuf {
    let config_file = codex_dir.join("config.toml");
    let mut identity = Sha256::new();
    for part in [
        config_file.as_os_str().as_encoded_bytes(),
        plugin_id.as_bytes(),
    ] {
        identity.update((part.len() as u64).to_le_bytes());
        identity.update(part);
    }
    codex_dir
        .join(".hook-trust")
        .join(format!("{:x}", identity.finalize()))
}

/// Findings of every hook that runs. `states` is the user config's
/// `[hooks.state]` table: Codex reads approvals from the user layer alone.
pub(super) fn plugin_findings(
    codex_dir: &Path,
    plugins: &[LoadedPlugin],
    states: Option<&toml::Table>,
    home: Option<&Path>,
) -> Vec<AiGuardFinding> {
    let mut out = Vec::new();
    let Some(codex_home) = Home::new(codex_dir) else {
        return out;
    };
    for plugin in plugins {
        let content = std::cell::OnceCell::new();
        let current = || {
            content
                .get_or_init(|| match content_hash(&plugin.root) {
                    Ok(hash) => Some(hash),
                    Err(error) => {
                        tracing::warn!(plugin = %plugin.id, %error, "codex plugin folder hash failed; its hooks are not trusted");
                        None
                    }
                })
                .as_deref()
        };
        for file in &plugin.files {
            let mut reasons = Vec::new();
            emit_hook_reasons(
                &file.scored,
                |event, group, handler| {
                    let Some(declared) = declaration_hash(&file.typed, event, group, handler)
                    else {
                        return false;
                    };
                    let key = format!(
                        "{}:{}:{}:{group}:{handler}",
                        plugin.id,
                        file.key_source,
                        hook_event_key_label(event)
                    );
                    let Some(state) = states.and_then(|s| s.get(&key)).and_then(Value::as_table)
                    else {
                        return false;
                    };
                    let flag = |name: &str| match state.get(name) {
                        None => Some(None),
                        Some(Value::String(s)) => Some(Some(s.as_str())),
                        Some(_) => None,
                    };
                    let enabled = match state.get("enabled") {
                        None => true,
                        Some(Value::Boolean(b)) => *b,
                        Some(_) => false,
                    };
                    let (Some(Some(trusted)), Some(content_hash)) =
                        (flag("trusted_hash"), flag("trusted_content_hash"))
                    else {
                        return false;
                    };
                    if !enabled || trusted != declared {
                        return false;
                    }
                    let Some(now) = current() else {
                        return false;
                    };
                    match content_hash {
                        Some(approved) => approved == now,
                        None => {
                            let path = baseline_path(codex_dir, &plugin.id);
                            match std::fs::symlink_metadata(&path) {
                                Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
                                _ => codex_home
                                    .read(&path, MAX_BASELINE_BYTES)
                                    .is_some_and(|bytes| bytes == now.as_bytes()),
                            }
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

#[cfg(test)]
#[path = "codex_plugin_hooks_tests.rs"]
mod tests;
