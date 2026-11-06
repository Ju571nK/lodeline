// Consumed by install/uninstall subcommands. Registers/deregisters the
// lodeline-hook entry in each agent's config WITHOUT clobbering unrelated hooks.
//
// Agents differ in config path AND format (web-verified 2026-06):
//   - Claude Code / Codex: nested `hooks.PreToolUse[]` with
//     `{matcher, hooks:[{type:"command", command}]}`.
//       Claude Code: ~/.claude/settings.json
//       Codex:       $CODEX_HOME/hooks.json, else ~/.codex/hooks.json
//                    (runs only once the user trusts
//                    it in Codex — surfaced as CODEX_TRUST_NOTE)
//   - Cursor: ~/.cursor/hooks.json with `version:1` + per-event arrays
//     (`beforeShellExecution`, `beforeMCPExecution`) of `{command}`.
//
//   - Antigravity: ~/.gemini/config/hooks.json, same nested `PreToolUse` shape
//     as claude-code/codex. This is the SHARED hooks file agy's own `/hooks`
//     TUI writes, so registration merges and uninstall removes only our entry.
//     Hardware-verified on agy 1.1.7 (#202): the hook fires and an explicit
//     deny blocks the call. The earlier "hooks are not read from a settings
//     file" conclusion (#112) held for agy 1.0.4–1.0.8 and was fixed upstream.
//     The separate plugin-bundle path in `install_antigravity.rs` is a
//     different mechanism and has not been re-probed.

use lodeline_core::paths::{command_exe, is_hook_binary, SHELL_WS};
use serde_json::{json, Value};
use std::io;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum HookFormat {
    /// `root.hooks.PreToolUse[]` — Claude Code, Codex.
    NestedPreToolUse,
    /// `root.version` + `root.hooks.{beforeShellExecution,beforeMCPExecution}[]`.
    Cursor,
}

pub(crate) fn agent_format(agent: &str) -> Option<HookFormat> {
    match agent {
        // #208 — agy's shared hooks file uses the same nested shape as
        // claude-code/codex (hardware-verified on 1.1.7, #202: a bare
        // `{"PreToolUse":[…]}` at that path does not load).
        "claude-code" | "codex" | "antigravity" => Some(HookFormat::NestedPreToolUse),
        "cursor" => Some(HookFormat::Cursor),
        _ => None,
    }
}

pub(crate) const CURSOR_EVENTS: [&str; 2] = ["beforeShellExecution", "beforeMCPExecution"];

fn command_string(exe: &str, agent: &str, capture: &str) -> String {
    format!("{exe} {agent} --capture {capture}")
}

fn command_string_enforce(exe: &str, agent: &str, capture: &str, on_failure: &str) -> String {
    // Registrations dedupe by shape (see `is_our_command`): installing enforce over an
    // existing observe registration REPLACES it, so operators upgrading observe→enforce
    // get the observe entry overwritten, not a second entry.
    format!("{exe} {agent} --enforce --on-failure {on_failure} --capture {capture}")
}

/// The binary path as written into a hook command.
///
/// On Windows, `/` is the one separator that runs under Git Bash (Claude Code),
/// PowerShell (Codex) and `cmd /C`; Git Bash drops an unquoted `\`.
pub(crate) fn hook_exe(path: &str, windows: bool) -> String {
    let p = if windows {
        path.replace('\\', "/")
    } else {
        path.to_string()
    };
    // Quoted runs under Git Bash and cmd but not PowerShell, which needs `& "..."`
    // that the other two reject; no Windows API crate here for an 8.3 short path,
    // and release zips unpack anywhere, so install warns instead (see main.rs).
    if p.contains(SHELL_WS) {
        format!("\"{p}\"")
    } else {
        p
    }
}

/// Whether `cmd` runs `exe`, comparing in a form that ignores quoting, `\` vs
/// `/`, and the `\\?\` prefix lodeline-hook <= 0.12.2 wrote on Windows. Matching
/// a prefix rather than the first token also catches an old unquoted path that
/// contains a space.
fn invokes_exe(cmd: &str, exe: &str) -> bool {
    let key = |s: &str| {
        let s = s.trim_start_matches(SHELL_WS).replace('"', "");
        s.strip_prefix(r"\\?\").unwrap_or(&s).replace('\\', "/")
    };
    let (cmd, exe) = (key(cmd), key(exe));
    !exe.is_empty()
        && cmd
            .strip_prefix(&exe)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(SHELL_WS))
}

/// Whether `cmd` has the shape install writes for `agent` from any folder:
/// `<path>/lodeline-hook[.exe] <agent> ... --capture <mode>`. Release archives
/// unpack into a versioned folder, so an upgrade must find the old entry by
/// shape. Only the binary's own path may come before it, so a wrapper such as
/// `cmd.exe /c ...` or `bash -c ...` stays the user's.
fn is_our_command(cmd: &str, agent: &str) -> bool {
    let tokens = |s| str::split(s, SHELL_WS).filter(|t| !t.is_empty());
    let exe = command_exe(cmd);
    if is_hook_binary(exe.trim_matches('"')) {
        let rest = &cmd.trim_start_matches(SHELL_WS)[exe.len()..];
        return has_our_args(tokens(rest), agent);
    }
    // lodeline-hook <= 0.12.2 wrote a path with a space unquoted, so the binary
    // can be a later token. Every token before it must read as part of one path.
    let tokens: Vec<&str> = tokens(cmd).collect();
    let Some(bin) = tokens.iter().position(|t| is_hook_binary(t)) else {
        return false;
    };
    let path = &tokens[..=bin];
    starts_absolute(path[0])
        && path[1..]
            .iter()
            .all(|t| !t.starts_with(['/', '\\', '-', '.', '~']) && !starts_absolute(t))
        && path[bin].contains(['/', '\\'])
        && !path.iter().any(|t| t.contains(['"', '\'']))
        && !path[..bin].iter().any(|t| is_launcher(t))
        && has_our_args(tokens[bin + 1..].iter().copied(), agent)
}

/// Programs that run the rest of their command line.
const LAUNCHERS: [&str; 23] = [
    "cmd",
    "sh",
    "bash",
    "zsh",
    "dash",
    "pwsh",
    "powershell",
    "env",
    "wsl",
    "sudo",
    "doas",
    "nice",
    "nohup",
    "time",
    "timeout",
    "xargs",
    "stdbuf",
    "ionice",
    "chrt",
    "command",
    "exec",
    "setsid",
    "taskset",
];

/// A shell, wrapper, executable or script, which a folder name in an old
/// spaced path is not.
fn is_launcher(path: &str) -> bool {
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let name = name.to_ascii_lowercase();
    LAUNCHERS.contains(&name.as_str())
        || [".exe", ".cmd", ".bat", ".com", ".sh", ".ps1"]
            .iter()
            .any(|ext| name.ends_with(ext))
}

/// `/x`, `\x`, `\\?\C:...` or `C:...`.
fn starts_absolute(token: &str) -> bool {
    let b = token.as_bytes();
    token.starts_with(['/', '\\']) || (b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':')
}

fn has_our_args<'a>(mut args: impl Iterator<Item = &'a str>, agent: &str) -> bool {
    args.next() == Some(agent) && args.any(|t| t == "--capture")
}

/// Ours at any path, or any command that runs `exe` itself.
fn is_ours(cmd: &str, exe: &str, agent: &str) -> bool {
    is_our_command(cmd, agent) || invokes_exe(cmd, exe)
}

// --- Claude-style entry helpers ---

fn claude_entry(cmd: &str) -> Value {
    json!({ "matcher": "*", "hooks": [{ "type": "command", "command": cmd }] })
}

/// The command of a Claude-style entry's first inner hook, if any.
pub(crate) fn claude_entry_cmd(entry: &Value) -> Option<&str> {
    entry
        .get("hooks")
        .and_then(|h| h.as_array())
        .and_then(|hooks| hooks.first())
        .and_then(|h| h.get("command"))
        .and_then(|c| c.as_str())
}

fn group_hooks(group: &Value) -> &[Value] {
    group
        .get("hooks")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn hook_command(hook: &Value) -> Option<&str> {
    hook.get("command").and_then(Value::as_str)
}

/// Each inner hook command of ours, with the group that holds it. A group can
/// also hold the user's own hooks, so ours are counted and removed one by one.
pub(crate) fn nested_ours<'a>(
    groups: &'a [Value],
    exe: &'a str,
    agent: &'a str,
) -> impl Iterator<Item = (&'a Value, &'a str)> + 'a {
    groups.iter().flat_map(move |g| {
        group_hooks(g)
            .iter()
            .filter_map(hook_command)
            .filter(move |c| is_ours(c, exe, agent))
            .map(move |c| (g, c))
    })
}

/// Drop the inner hooks whose command matches, and a group only when that
/// empties it, so a user's hook sharing the group survives. Returns how many
/// hooks went.
pub(crate) fn strip_nested(groups: &mut Vec<Value>, is: impl Fn(&str) -> bool) -> usize {
    let mut removed = 0;
    groups.retain_mut(|group| {
        let Some(hooks) = group.get_mut("hooks").and_then(Value::as_array_mut) else {
            return true;
        };
        let before = hooks.len();
        hooks.retain(|h| !hook_command(h).is_some_and(&is));
        removed += before - hooks.len();
        hooks.len() == before || !hooks.is_empty()
    });
    removed
}

/// Get-or-create the nested `hooks.PreToolUse` array.
/// #208 — describe a shape conflict in an existing settings document, if the
/// merge would have to overwrite live data to proceed.
///
/// `pretooluse_array_mut` coerces: a `hooks` that is not an object, or a
/// `PreToolUse` that is not an array, is replaced outright. That is silent data
/// loss, and for antigravity the file is shared with agy's own `/hooks` TUI, so
/// what would be lost is the user's other hooks. Callers check this first and
/// refuse rather than coerce. Absent keys are not a conflict — there is nothing
/// there to lose.
pub fn conflicting_shape(root: &Value, agent: &str) -> Option<String> {
    if !root.is_null() && !root.is_object() {
        return Some("the document root is not a JSON object".to_string());
    }
    let hooks = root.get("hooks")?;
    if !hooks.is_object() {
        return Some("`hooks` exists but is not an object".to_string());
    }
    let events: &[&str] = match agent_format(agent) {
        Some(HookFormat::NestedPreToolUse) => &["PreToolUse"],
        Some(HookFormat::Cursor) => &CURSOR_EVENTS,
        None => return None,
    };
    for ev in events {
        match hooks.get(*ev) {
            Some(v) if !v.is_array() => {
                return Some(format!("`hooks.{ev}` exists but is not an array"));
            }
            _ => {}
        }
    }
    None
}

fn pretooluse_array_mut(root: &mut Value) -> &mut Vec<Value> {
    if !root.is_object() {
        *root = json!({});
    }
    if !root["hooks"].is_object() {
        root["hooks"] = json!({});
    }
    let h = &mut root["hooks"];
    if !h["PreToolUse"].is_array() {
        h["PreToolUse"] = json!([]);
    }
    h["PreToolUse"].as_array_mut().unwrap()
}

/// Remove each hook of ours and put `cmd` in a group of its own, where the
/// first group that held only ours was. A user's group is never written into.
fn merge_claude(arr: &mut Vec<Value>, exe: &str, agent: &str, cmd: &str) -> bool {
    let ours = |c: &str| is_ours(c, exe, agent);
    // Exactly the groups `strip_nested` drops.
    let only_ours = |g: &Value| {
        let hooks = group_hooks(g);
        !hooks.is_empty() && hooks.iter().all(|h| hook_command(h).is_some_and(ours))
    };
    let slot = arr.iter().position(only_ours);
    if slot.is_some_and(|i| claude_entry_cmd(&arr[i]) == Some(cmd))
        && nested_ours(arr, exe, agent).count() == 1
    {
        return false;
    }
    let at = slot.map_or(usize::MAX, |i| {
        arr[..i].iter().filter(|g| !only_ours(g)).count()
    });
    strip_nested(arr, ours);
    arr.insert(at.min(arr.len()), claude_entry(cmd));
    true
}

/// Replace every flat entry of ours with one `entry`, at the first one's position.
/// Returns false when `arr` already holds exactly one entry of ours and `same`
/// accepts it.
fn replace_ours(
    arr: &mut Vec<Value>,
    ours: impl Fn(&Value) -> bool,
    same: impl Fn(&Value) -> bool,
    entry: Value,
) -> bool {
    let first = arr.iter().position(&ours);
    if first.is_some_and(|i| same(&arr[i])) && arr.iter().filter(|e| ours(e)).count() == 1 {
        return false;
    }
    arr.retain(|e| !ours(e));
    arr.insert(first.unwrap_or(arr.len()), entry);
    true
}

// --- Cursor helpers ---

pub(crate) fn cursor_entry_is_ours(entry: &Value, exe: &str) -> bool {
    entry
        .get("command")
        .and_then(|c| c.as_str())
        .is_some_and(|c| is_ours(c, exe, "cursor"))
}

/// The `command` string of a Cursor settings entry, if present.
pub(crate) fn cursor_entry_command(entry: &Value) -> Option<&str> {
    entry.get("command").and_then(|c| c.as_str())
}

/// Effective `failClosed` of a Cursor entry — absent means false (Cursor default).
pub(crate) fn cursor_entry_fail_closed(entry: &Value) -> bool {
    entry
        .get("failClosed")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// The settings entry object for our hook on a Cursor event. Observe = bare
/// command; enforce-closed additionally carries `failClosed:true`, coupling our
/// `--on-failure closed` to Cursor's own fail-closed so a hook process that
/// crashes / times out / returns invalid JSON blocks the tool call instead of
/// failing open.
fn cursor_observe_entry(cmd: &str) -> Value {
    cursor_enforce_entry(cmd, "open")
}

fn cursor_enforce_entry(cmd: &str, on_failure: &str) -> Value {
    if on_failure == "closed" {
        json!({ "command": cmd, "failClosed": true })
    } else {
        json!({ "command": cmd })
    }
}

/// Upsert our prebuilt entry on BOTH Cursor gate events, replacing every entry of ours.
/// Replaces the whole entry object on change (so a stale `failClosed` from a prior
/// closed install is dropped on a later open install). Returns true if changed.
fn upsert_cursor_entry(root: &mut Value, exe: &str, entry: &Value) -> bool {
    if !root.is_object() {
        *root = json!({});
    }
    let mut changed = false;
    if root["version"].is_null() {
        root["version"] = json!(1);
        changed = true;
    }
    if !root["hooks"].is_object() {
        root["hooks"] = json!({});
    }
    for ev in CURSOR_EVENTS {
        let arr = {
            let h = &mut root["hooks"];
            if !h[ev].is_array() {
                h[ev] = json!([]);
            }
            h[ev].as_array_mut().unwrap()
        };
        changed |= replace_ours(
            arr,
            |e| cursor_entry_is_ours(e, exe),
            |e| e == entry,
            entry.clone(),
        );
    }
    changed
}

fn merge_cursor(root: &mut Value, exe: &str, cmd: &str) -> bool {
    upsert_cursor_entry(root, exe, &cursor_observe_entry(cmd))
}

fn merge_cursor_enforce(root: &mut Value, exe: &str, cmd: &str, on_failure: &str) -> bool {
    upsert_cursor_entry(root, exe, &cursor_enforce_entry(cmd, on_failure))
}

// ---------------------------------------------------------------------------
// Public API (dispatched by agent format)
// ---------------------------------------------------------------------------

/// Measured on codex-cli 0.164.0: an untrusted `~/.codex/hooks.json` entry is
/// skipped silently, and `hooks` is a stable, default-on feature. Codex source
/// keys trust to a hash of the entry, so a changed command needs trusting again.
pub const CODEX_TRUST_NOTE: &str = "note: Codex skips this hook, without a warning, until you \
    trust it. Run `codex`, open /hooks, and trust the lodeline-hook entry. Do this again after \
    any install that changes the hook command.";

/// Shared body for `render_block` / `render_block_enforce`: builds the
/// human-pasteable settings fragment + undo hint for a prebuilt command string.
/// `cursor_entry` is the pre-built Cursor entry object (observe or enforce with
/// optional `failClosed`) — used only for the Cursor format arm.
fn render_block_inner(cmd: &str, agent: &str, cursor_entry: &Value) -> String {
    let Some(fmt) = agent_format(agent) else {
        return format!("// unsupported agent '{agent}'\n");
    };
    let path = settings_path(agent)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "<settings>".into());
    let fragment = match fmt {
        HookFormat::NestedPreToolUse => json!({ "hooks": { "PreToolUse": [claude_entry(cmd)] } }),
        HookFormat::Cursor => json!({
            "version": 1,
            "hooks": {
                "beforeShellExecution": [cursor_entry],
                "beforeMCPExecution": [cursor_entry],
            }
        }),
    };
    let pretty = serde_json::to_string_pretty(&fragment).unwrap_or_default();
    let note = if agent == "codex" {
        format!("// {CODEX_TRUST_NOTE}\n")
    } else {
        String::new()
    };
    format!(
        "// Merge this into {path}:\n\
         {pretty}\n\
         {note}// remove with: lodeline-hook uninstall --agent {agent} --write\n"
    )
}

/// Human-pasteable block showing the settings fragment + undo hint.
pub fn render_block(exe: &str, agent: &str, capture: &str) -> String {
    let cmd = command_string(exe, agent, capture);
    render_block_inner(&cmd, agent, &cursor_observe_entry(&cmd))
}

/// Idempotently ensure the lodeline-hook entry is present. Returns `true` if the
/// document was modified.
pub fn merge_into(root: &mut Value, exe: &str, agent: &str, capture: &str) -> bool {
    let cmd = command_string(exe, agent, capture);
    let replaced = crate::legacy::strip_entries(root, agent) > 0;
    let merged = match agent_format(agent) {
        Some(HookFormat::NestedPreToolUse) => {
            merge_claude(pretooluse_array_mut(root), exe, agent, &cmd)
        }
        Some(HookFormat::Cursor) => merge_cursor(root, exe, &cmd),
        None => false,
    };
    replaced || merged
}

/// Like `render_block`, but the registered command runs the Stage 2 enforce
/// (deny-decision) path with the given on_failure mode.
pub fn render_block_enforce(exe: &str, agent: &str, capture: &str, on_failure: &str) -> String {
    let cmd = command_string_enforce(exe, agent, capture, on_failure);
    render_block_inner(&cmd, agent, &cursor_enforce_entry(&cmd, on_failure))
}

/// Merge an enforce-mode registration into the settings JSON.
/// For claude-code / codex (NestedPreToolUse): merges with the enforce command string.
/// For Cursor: upserts both gate-event entries; adds `failClosed:true` when
/// `on_failure == "closed"` to couple Cursor's own fail-closed behaviour to ours.
/// Returns `true` if the document was modified, `false` if already up-to-date.
pub fn merge_into_enforce(
    root: &mut Value,
    exe: &str,
    agent: &str,
    capture: &str,
    on_failure: &str,
) -> bool {
    let cmd = command_string_enforce(exe, agent, capture, on_failure);
    let replaced = crate::legacy::strip_entries(root, agent) > 0;
    let merged = match agent_format(agent) {
        Some(HookFormat::NestedPreToolUse) => {
            merge_claude(pretooluse_array_mut(root), exe, agent, &cmd)
        }
        Some(HookFormat::Cursor) => merge_cursor_enforce(root, exe, &cmd, on_failure),
        None => false,
    };
    replaced || merged
}

/// Remove every lodeline-hook entry for `agent`, at any path. Returns `true` if anything was
/// removed. Leaves unrelated hooks untouched.
pub fn remove_from(root: &mut Value, exe: &str, agent: &str) -> bool {
    let replaced = crate::legacy::strip_entries(root, agent) > 0;
    let removed = match agent_format(agent) {
        Some(HookFormat::NestedPreToolUse) => match root["hooks"]["PreToolUse"].as_array_mut() {
            Some(a) => strip_nested(a, |c| is_ours(c, exe, agent)) > 0,
            None => false,
        },
        Some(HookFormat::Cursor) => {
            let mut removed = false;
            for ev in CURSOR_EVENTS {
                if let Some(a) = root["hooks"][ev].as_array_mut() {
                    let before = a.len();
                    a.retain(|e| !cursor_entry_is_ours(e, exe));
                    removed |= a.len() < before;
                }
            }
            removed
        }
        None => false,
    };
    replaced || removed
}

/// Count lodeline-hook entries for `agent` at any path (across all relevant arrays), plus
/// entries from before the rename, which uninstall removes as well.
pub fn count_lodeline_entries(root: &Value, exe: &str, agent: &str) -> usize {
    let legacy = crate::legacy::count_entries(root, agent);
    legacy
        + match agent_format(agent) {
            Some(HookFormat::NestedPreToolUse) => root["hooks"]["PreToolUse"]
                .as_array()
                .map(|a| nested_ours(a, exe, agent).count())
                .unwrap_or(0),
            Some(HookFormat::Cursor) => CURSOR_EVENTS
                .iter()
                .map(|ev| {
                    root["hooks"][*ev]
                        .as_array()
                        .map(|a| a.iter().filter(|e| cursor_entry_is_ours(e, exe)).count())
                        .unwrap_or(0)
                })
                .sum(),
            None => 0,
        }
}

pub use lodeline_core::paths::{home_dir, hook_state_dir as state_dir};

/// Per-agent baseline path, only for agents with a known hook format (so a raw
/// `--agent` string can never be interpolated into a traversal path).
pub(crate) fn baseline_path_in(dir: &std::path::Path, agent: &str) -> Option<PathBuf> {
    agent_format(agent)?; // validate: known slug only
    Some(dir.join(format!("hook-registration-{agent}.json")))
}

pub(crate) fn baseline_path(agent: &str) -> Option<PathBuf> {
    baseline_path_in(&state_dir(), agent)
}

/// Map agent name → absolute path to its hook config file.
pub fn settings_path(agent: &str) -> Option<PathBuf> {
    let home = home_dir()?;
    let p = match agent {
        "claude-code" => home.join(".claude/settings.json"),
        // Codex reads `CODEX_HOME` with `env::var`, so an empty or non-UTF-8
        // value means `~/.codex` (`find_codex_home`, rust-v0.166.0). Codex
        // canonicalizes a relative value, so the baseline must store it absolute.
        "codex" => std::env::var("CODEX_HOME")
            .ok()
            .filter(|v| !v.is_empty())
            .map_or_else(
                || home.join(".codex"),
                |v| std::path::absolute(&v).unwrap_or_else(|_| v.into()),
            )
            .join("hooks.json"),
        "cursor" => home.join(".cursor/hooks.json"),
        // #208 — the SHARED hooks file, which agy's own `/hooks` TUI also
        // writes. Re-verified on agy 1.2.0: this path and workspace
        // `.agents/hooks.json` fire; `~/.gemini/antigravity-cli/hooks.json`
        // does not. Merged into, never overwritten.
        "antigravity" => home.join(".gemini/config/hooks.json"),
        _ => return None,
    };
    Some(p)
}

/// Write `state_dir()/hook-registration.json` + append to the discovery index.
#[allow(clippy::too_many_arguments)]
pub fn write_baseline(
    agent: &str,
    settings_path: &std::path::Path,
    exe: &str,
    agent_arg: &str,
    capture: &str,
    matcher: &str,
    enforce: bool,
    on_failure: &str,
) -> io::Result<()> {
    write_baseline_in(
        &state_dir(),
        agent,
        settings_path,
        exe,
        agent_arg,
        capture,
        matcher,
        enforce,
        on_failure,
    )
}

/// Directory-injectable core of [`write_baseline`]: writes
/// `dir/hook-registration-<agent>.json` + appends to `dir/hook-index.json`. Kept
/// separate so tests can supply a temp dir without touching the process-global
/// `XDG_STATE_HOME` env var (which would race other tests).
#[allow(clippy::too_many_arguments)]
fn write_baseline_in(
    dir: &std::path::Path,
    agent: &str,
    settings_path: &std::path::Path,
    exe: &str,
    agent_arg: &str,
    capture: &str,
    matcher: &str,
    enforce: bool,
    on_failure: &str,
) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;

    let cmd = if enforce {
        command_string_enforce(exe, agent_arg, capture, on_failure)
    } else {
        command_string(exe, agent_arg, capture)
    };
    let block_hash = blake3::hash(cmd.as_bytes()).to_hex().to_string();
    let written_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let settings_path_str = settings_path.to_string_lossy().to_string();

    let fail_closed: Option<bool> = (agent_format(agent) == Some(HookFormat::Cursor))
        .then(|| enforce && on_failure == "closed");

    let baseline = json!({
        "agent": agent,
        "settings_path": settings_path_str,
        "command": cmd,
        "capture": capture,
        "matcher": matcher,
        "block_hash": block_hash,
        "fail_closed": fail_closed,        // null for claude/codex; bool for cursor
        "written_at_unix": written_at_unix,
    });

    let reg_path = baseline_path_in(dir, agent)
        .ok_or_else(|| io::Error::other(format!("unknown agent for baseline: {agent}")))?;
    let pretty = serde_json::to_string_pretty(&baseline).map_err(io::Error::other)?;
    std::fs::write(&reg_path, pretty.as_bytes())?;

    let index_path = dir.join("hook-index.json");
    let mut entries: Vec<String> = if index_path.exists() {
        let raw = std::fs::read(&index_path)?;
        serde_json::from_slice::<Vec<String>>(&raw).unwrap_or_default()
    } else {
        Vec::new()
    };
    if !entries.contains(&settings_path_str) {
        entries.push(settings_path_str);
        let json = serde_json::to_string_pretty(&entries).map_err(io::Error::other)?;
        std::fs::write(&index_path, json.as_bytes())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_block_enforce_carries_flags() {
        let s = render_block_enforce("/abs/lodeline-hook", "claude-code", "redacted", "open");
        assert!(s.contains(
            "/abs/lodeline-hook claude-code --enforce --on-failure open --capture redacted"
        ));
        assert!(s.contains("PreToolUse"));
    }

    #[test]
    fn render_block_enforce_codex_carries_flags() {
        let s = render_block_enforce("/abs/lodeline-hook", "codex", "redacted", "open");
        assert!(
            s.contains("/abs/lodeline-hook codex --enforce --on-failure open --capture redacted")
        );
        assert!(s.contains("PreToolUse"));
    }

    // --- Claude Code (nested) ---
    #[test]
    fn render_block_has_abs_path_and_capture() {
        let s = render_block("/abs/lodeline-hook", "claude-code", "redacted");
        assert!(s.contains("/abs/lodeline-hook claude-code --capture redacted"));
        assert!(s.contains("PreToolUse"));
    }
    #[test]
    fn nested_merge_empty_idempotent_update() {
        let mut v = json!({});
        assert!(merge_into(
            &mut v,
            "/abs/lodeline-hook",
            "claude-code",
            "redacted"
        ));
        assert!(!merge_into(
            &mut v,
            "/abs/lodeline-hook",
            "claude-code",
            "redacted"
        ));
        assert_eq!(
            count_lodeline_entries(&v, "/abs/lodeline-hook", "claude-code"),
            1
        );
        // capture change updates in place
        assert!(merge_into(
            &mut v,
            "/abs/lodeline-hook",
            "claude-code",
            "raw"
        ));
        assert_eq!(
            count_lodeline_entries(&v, "/abs/lodeline-hook", "claude-code"),
            1
        );
        let s = serde_json::to_string(&v).unwrap();
        assert!(s.contains("--capture raw") && !s.contains("--capture redacted"));
    }
    #[test]
    fn nested_remove_preserves_foreign() {
        let mut v = json!({"hooks":{"PreToolUse":[
            {"matcher":"*","hooks":[{"type":"command","command":"/other/tool run"}]}
        ]}});
        merge_into(&mut v, "/abs/lodeline-hook", "claude-code", "redacted");
        assert!(remove_from(&mut v, "/abs/lodeline-hook", "claude-code"));
        assert_eq!(
            count_lodeline_entries(&v, "/abs/lodeline-hook", "claude-code"),
            0
        );
        assert!(serde_json::to_string(&v)
            .unwrap()
            .contains("/other/tool run"));
    }

    fn pretooluse_commands(v: &Value) -> Vec<&str> {
        v["hooks"]["PreToolUse"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(claude_entry_cmd)
            .collect()
    }

    // Registered by lodeline-hook <= 0.12.2 on Windows: canonicalize() kept the `\\?\` prefix.
    const VERBATIM_OLD: &str =
        r"\\?\C:\Users\alice\x\lodeline-hook.exe claude-code --capture redacted";

    #[test]
    fn hook_exe_per_platform() {
        assert_eq!(
            hook_exe("/usr/local/bin/lodeline-hook", false),
            "/usr/local/bin/lodeline-hook"
        );
        assert_eq!(
            hook_exe("/Users/a b/lodeline-hook", false),
            r#""/Users/a b/lodeline-hook""#
        );
        assert_eq!(
            hook_exe(r"C:\Users\alice\tools\x\lodeline-hook.exe", true),
            "C:/Users/alice/tools/x/lodeline-hook.exe"
        );
        assert_eq!(
            hook_exe(
                "C:\\Users\\alice\\新しい\u{3000}フォルダー\\lodeline-hook.exe",
                true
            ),
            "C:/Users/alice/新しい\u{3000}フォルダー/lodeline-hook.exe"
        );
        assert_eq!(
            hook_exe("/home/alice/a\u{a0}b\u{85}c/lodeline-hook", false),
            "/home/alice/a\u{a0}b\u{85}c/lodeline-hook"
        );
        assert_eq!(
            hook_exe(r"C:\Program Files\Lodeline 한글\lodeline-hook.exe", true),
            r#""C:/Program Files/Lodeline 한글/lodeline-hook.exe""#
        );
    }

    #[test]
    fn windows_commands_use_forward_slashes_for_every_agent() {
        let exe = hook_exe(r"C:\Users\alice\x\lodeline-hook.exe", true);
        for agent in ["claude-code", "codex"] {
            let mut v = json!({});
            assert!(merge_into(&mut v, &exe, agent, "redacted"));
            assert_eq!(
                pretooluse_commands(&v),
                [format!(
                    "C:/Users/alice/x/lodeline-hook.exe {agent} --capture redacted"
                )]
            );
        }
    }

    #[test]
    fn codex_upgrade_replaces_old_backslash_registration() {
        let exe = hook_exe(r"C:\Users\alice\x\lodeline-hook.exe", true);
        for old in [
            r"C:\Users\alice\x\lodeline-hook.exe codex --capture redacted",
            r"\\?\C:\Users\alice\x\lodeline-hook.exe codex --capture redacted",
        ] {
            let mut v = json!({"hooks":{"PreToolUse":[
                {"matcher":"*","hooks":[{"type":"command","command":old}]}
            ]}});
            assert_eq!(count_lodeline_entries(&v, &exe, "codex"), 1, "{old}");
            assert!(merge_into(&mut v, &exe, "codex", "redacted"));
            assert_eq!(
                pretooluse_commands(&v),
                ["C:/Users/alice/x/lodeline-hook.exe codex --capture redacted"]
            );
        }
    }

    #[test]
    fn command_exe_reads_quoted_and_bare_paths() {
        assert_eq!(
            command_exe(r#""C:/Program Files/x.exe" claude-code --capture redacted"#),
            r#""C:/Program Files/x.exe""#
        );
        assert_eq!(
            command_exe("/usr/bin/lodeline-hook claude-code --capture redacted"),
            "/usr/bin/lodeline-hook"
        );
        assert!(!invokes_exe(
            "/usr/bin/lodeline-hook.bak claude-code",
            "/usr/bin/lodeline-hook"
        ));
        assert!(invokes_exe(
            "/usr/bin/lodeline-hook\tclaude-code --capture redacted",
            "/usr/bin/lodeline-hook"
        ));
        let wide = "C:/Users/alice/新しい\u{3000}フォルダー/lodeline-hook.exe";
        let cmd = format!("{wide} codex --capture redacted");
        assert_eq!(command_exe(&cmd), wide);
        assert!(invokes_exe(&cmd, wide));
        assert!(!invokes_exe(
            &format!("{wide}\u{3000}codex --capture redacted"),
            wide
        ));
    }

    #[test]
    fn upgrade_replaces_verbatim_windows_registration() {
        let exe = "C:/Users/alice/x/lodeline-hook.exe";
        let mut v = json!({"hooks":{"PreToolUse":[
            {"matcher":"*","hooks":[{"type":"command","command":VERBATIM_OLD}]}
        ]}});
        assert_eq!(count_lodeline_entries(&v, exe, "claude-code"), 1);
        assert!(merge_into(&mut v, exe, "claude-code", "redacted"));
        assert_eq!(
            pretooluse_commands(&v),
            ["C:/Users/alice/x/lodeline-hook.exe claude-code --capture redacted"]
        );

        let mut old = json!({"hooks":{"PreToolUse":[
            {"matcher":"*","hooks":[{"type":"command","command":VERBATIM_OLD}]}
        ]}});
        assert!(remove_from(&mut old, exe, "claude-code"));
        assert!(pretooluse_commands(&old).is_empty());
    }

    #[test]
    fn quoted_path_with_spaces_dedupes_and_spares_foreign() {
        let exe = r#""C:/Program Files/Lodeline 한글/lodeline-hook.exe""#;
        let foreign = r#""C:/Program Files/Other/tool.exe" run"#;
        let mut v = json!({"hooks":{"PreToolUse":[
            {"matcher":"*","hooks":[{"type":"command","command":foreign}]}
        ]}});
        assert!(merge_into(&mut v, exe, "claude-code", "redacted"));
        assert!(!merge_into(&mut v, exe, "claude-code", "redacted"));
        assert_eq!(count_lodeline_entries(&v, exe, "claude-code"), 1);
        assert!(remove_from(&mut v, exe, "claude-code"));
        assert_eq!(pretooluse_commands(&v), [foreign]);
    }

    #[test]
    fn upgrade_replaces_old_unquoted_path_with_spaces() {
        let old = r"C:\Program Files\Lodeline\lodeline-hook.exe codex --capture redacted";
        let exe = r#""C:/Program Files/Lodeline/lodeline-hook.exe""#;
        let mut v = json!({"hooks":{"PreToolUse":[
            {"matcher":"*","hooks":[{"type":"command","command":old}]}
        ]}});
        assert!(merge_into(&mut v, exe, "codex", "redacted"));
        assert_eq!(
            pretooluse_commands(&v),
            [r#""C:/Program Files/Lodeline/lodeline-hook.exe" codex --capture redacted"#]
        );
    }

    #[test]
    fn cursor_upgrade_replaces_verbatim_windows_registration() {
        let old = r"\\?\C:\Users\alice\x\lodeline-hook.exe cursor --capture redacted";
        let exe = "C:/Users/alice/x/lodeline-hook.exe";
        let mut v = json!({"version":1,"hooks":{
            "beforeShellExecution":[{"command":old}],
            "beforeMCPExecution":[{"command":old}],
        }});
        assert!(merge_into(&mut v, exe, "cursor", "redacted"));
        assert_eq!(count_lodeline_entries(&v, exe, "cursor"), 2);
        assert_eq!(
            v["hooks"]["beforeMCPExecution"][0]["command"],
            json!("C:/Users/alice/x/lodeline-hook.exe cursor --capture redacted")
        );
    }

    // Release archives unpack into a versioned folder, so an upgrade installs
    // from a new path while the old entry still names the old folder.
    const OLD_DIR: &str = r"C:\Users\alice\lodeline-0.12.2-x86_64-pc-windows-msvc";
    const NEW_EXE: &str = "C:/Users/alice/lodeline-0.12.3-x86_64-pc-windows-msvc/lodeline-hook.exe";
    const FOREIGN: &str = "/other/tool run";

    fn old_commands(agent: &str) -> [String; 2] {
        [
            format!(r"\\?\{OLD_DIR}\lodeline-hook.exe {agent} --capture redacted"),
            format!(
                "{}/lodeline-hook.exe {agent} --enforce --on-failure open --capture raw",
                OLD_DIR.replace('\\', "/")
            ),
        ]
    }

    fn wrapper(agent: &str) -> String {
        format!("cmd.exe /c {NEW_EXE} {agent} --capture redacted")
    }

    fn nested_settings(cmds: &[&str]) -> Value {
        json!({"hooks":{"PreToolUse": cmds.iter()
            .map(|c| json!({"matcher":"*","hooks":[{"type":"command","command":c}]}))
            .collect::<Vec<_>>()}})
    }

    #[test]
    fn upgrade_from_another_folder_leaves_one_entry() {
        for agent in ["claude-code", "codex", "antigravity"] {
            let [verbatim, slash] = old_commands(agent);
            let wrap = wrapper(agent);
            let mut v = nested_settings(&[FOREIGN, &verbatim, &wrap, &slash]);
            assert!(merge_into(&mut v, NEW_EXE, agent, "redacted"));
            let new = format!("{NEW_EXE} {agent} --capture redacted");
            assert_eq!(pretooluse_commands(&v), [FOREIGN, &new, &wrap], "{agent}");
            assert_eq!(count_lodeline_entries(&v, NEW_EXE, agent), 1, "{agent}");
            assert!(!merge_into(&mut v, NEW_EXE, agent, "redacted"), "{agent}");
        }
    }

    #[test]
    fn enforce_upgrade_from_another_folder_leaves_one_entry() {
        let [verbatim, slash] = old_commands("codex");
        let mut v = nested_settings(&[&verbatim, &slash]);
        assert!(merge_into_enforce(
            &mut v, NEW_EXE, "codex", "redacted", "closed"
        ));
        assert_eq!(
            pretooluse_commands(&v),
            [format!(
                "{NEW_EXE} codex --enforce --on-failure closed --capture redacted"
            )]
        );
    }

    #[test]
    fn cursor_upgrade_from_another_folder_leaves_one_entry_per_event() {
        let [verbatim, slash] = old_commands("cursor");
        let wrap = wrapper("cursor");
        let event =
            json!([{"command":FOREIGN},{"command":verbatim},{"command":wrap},{"command":slash}]);
        let mut v = json!({"version":1,"hooks":{
            "beforeShellExecution": event.clone(),
            "beforeMCPExecution": event,
        }});
        assert!(merge_into(&mut v, NEW_EXE, "cursor", "redacted"));
        let new = format!("{NEW_EXE} cursor --capture redacted");
        for ev in CURSOR_EVENTS {
            assert_eq!(
                v["hooks"][ev],
                json!([{"command":FOREIGN},{"command":new},{"command":wrap}]),
                "{ev}"
            );
        }
        assert_eq!(count_lodeline_entries(&v, NEW_EXE, "cursor"), 2);
    }

    #[test]
    fn tarball_to_package_upgrade_replaces_the_tarball_entry() {
        let old = "/home/alice/lodeline-0.12.2-x86_64-unknown-linux-gnu/lodeline-hook claude-code --capture redacted";
        let mut v = nested_settings(&[old]);
        assert!(merge_into(
            &mut v,
            "/usr/bin/lodeline-hook",
            "claude-code",
            "redacted"
        ));
        assert_eq!(
            pretooluse_commands(&v),
            ["/usr/bin/lodeline-hook claude-code --capture redacted"]
        );
    }

    #[test]
    fn uninstall_removes_our_entries_at_any_path() {
        for agent in ["claude-code", "codex"] {
            let [verbatim, slash] = old_commands(agent);
            let wrap = wrapper(agent);
            let mut v = nested_settings(&[FOREIGN, &verbatim, &wrap, &slash]);
            assert_eq!(count_lodeline_entries(&v, NEW_EXE, agent), 2, "{agent}");
            assert!(remove_from(&mut v, NEW_EXE, agent));
            assert_eq!(pretooluse_commands(&v), [FOREIGN, &wrap], "{agent}");
        }
        let [verbatim, slash] = old_commands("cursor");
        let mut v = json!({"version":1,"hooks":{
            "beforeShellExecution":[{"command":verbatim},{"command":FOREIGN}],
            "beforeMCPExecution":[{"command":slash}],
        }});
        assert_eq!(count_lodeline_entries(&v, NEW_EXE, "cursor"), 2);
        assert!(remove_from(&mut v, NEW_EXE, "cursor"));
        assert_eq!(
            v["hooks"],
            json!({"beforeShellExecution":[{"command":FOREIGN}],"beforeMCPExecution":[]})
        );
    }

    #[test]
    fn commands_that_only_mention_our_binary_are_not_ours() {
        let agent = "claude-code";
        for cmd in [
            wrapper(agent),
            format!("bash -c '{NEW_EXE} {agent} --capture redacted'"),
            format!("/bin/sh -c \"{NEW_EXE} {agent} --capture redacted\""),
            "/opt/x/lodeline-hook.bak claude-code --capture redacted".to_string(),
            "/opt/x/my-lodeline-hook claude-code --capture redacted".to_string(),
            "/opt/x/lodeline-hook claude-code --verbose".to_string(),
            "/opt/x/lodeline-hook codex --capture redacted".to_string(),
        ] {
            let mut v = nested_settings(&[&cmd]);
            assert_eq!(count_lodeline_entries(&v, NEW_EXE, agent), 0, "{cmd}");
            assert!(merge_into(&mut v, NEW_EXE, agent, "redacted"));
            assert_eq!(pretooluse_commands(&v)[0], cmd);
            assert_eq!(pretooluse_commands(&v).len(), 2, "{cmd}");
        }
    }

    fn group(matcher: &str, cmds: &[&str]) -> Value {
        json!({"matcher": matcher, "hooks": cmds.iter()
            .map(|c| json!({"type":"command","command":c}))
            .collect::<Vec<_>>()})
    }

    #[test]
    fn a_user_hook_sharing_our_group_survives_install_and_uninstall() {
        let mine = "/u/mine.sh";
        for agent in ["claude-code", "codex", "antigravity"] {
            let old = format!("/old/lodeline-hook {agent} --capture redacted");
            let only_ours = format!("/older/lodeline-hook {agent} --capture raw");
            let start = json!({"hooks":{"PreToolUse":[
                group("Bash", &[mine, &old]),
                group("*", &[&only_ours]),
            ]}});
            let new = format!("{NEW_EXE} {agent} --capture redacted");

            let mut v = start.clone();
            assert!(merge_into(&mut v, NEW_EXE, agent, "redacted"));
            assert_eq!(
                v["hooks"]["PreToolUse"],
                json!([group("Bash", &[mine]), group("*", &[&new])]),
                "{agent}"
            );
            assert!(!merge_into(&mut v, NEW_EXE, agent, "redacted"), "{agent}");
            assert_eq!(count_lodeline_entries(&v, NEW_EXE, agent), 1, "{agent}");

            let mut v = start.clone();
            assert_eq!(count_lodeline_entries(&v, NEW_EXE, agent), 2, "{agent}");
            assert!(remove_from(&mut v, NEW_EXE, agent));
            assert_eq!(
                v["hooks"]["PreToolUse"],
                json!([group("Bash", &[mine])]),
                "{agent}"
            );
        }

        let mut v = json!({"hooks":{"PreToolUse":[
            group("Bash", &[mine, "/old/lodeline-hook codex --capture redacted"]),
        ]}});
        assert!(merge_into_enforce(
            &mut v, NEW_EXE, "codex", "redacted", "closed"
        ));
        let new = format!("{NEW_EXE} codex --enforce --on-failure closed --capture redacted");
        assert_eq!(
            v["hooks"]["PreToolUse"],
            json!([group("Bash", &[mine]), group("*", &[&new])])
        );
        assert!(!merge_into_enforce(
            &mut v, NEW_EXE, "codex", "redacted", "closed"
        ));
    }

    #[test]
    fn install_never_writes_into_a_user_group() {
        let mut v = json!({"hooks":{"PreToolUse":[group("*", &["/u/mine.sh"])]}});
        assert!(merge_into(&mut v, NEW_EXE, "claude-code", "redacted"));
        let new = format!("{NEW_EXE} claude-code --capture redacted");
        assert_eq!(
            v["hooks"]["PreToolUse"],
            json!([group("*", &["/u/mine.sh"]), group("*", &[&new])])
        );
    }

    #[test]
    fn old_unquoted_path_with_a_space_from_another_folder_is_ours() {
        let old = r"\\?\C:\Users\Jane Doe\lodeline-0.12.2\lodeline-hook.exe claude-code --capture redacted";
        let mut v = nested_settings(&[FOREIGN, old]);
        assert_eq!(count_lodeline_entries(&v, NEW_EXE, "claude-code"), 1);
        assert!(merge_into(&mut v, NEW_EXE, "claude-code", "redacted"));
        assert_eq!(
            pretooluse_commands(&v),
            [
                FOREIGN,
                &format!("{NEW_EXE} claude-code --capture redacted")
            ]
        );
        for cmd in [
            r"C:\Program Files\Lodeline\LODELINE-HOOK.EXE claude-code --capture raw",
            "C:/x/Lodeline-Hook.exe claude-code --capture raw",
            "/Users/Jane Doe/lodeline-0.12.2/lodeline-hook claude-code --capture redacted",
            "/home/a b c/lodeline-hook claude-code --capture redacted",
        ] {
            assert_eq!(
                count_lodeline_entries(&nested_settings(&[cmd]), NEW_EXE, "claude-code"),
                1,
                "{cmd}"
            );
        }
    }

    #[test]
    fn a_wrapper_around_a_spaced_path_stays_foreign() {
        let claimed: Vec<&str> = [
            r"cmd.exe /c C:\x y\lodeline-hook.exe claude-code --capture redacted",
            r"C:\Windows\System32\cmd.exe /c C:\x y\lodeline-hook.exe claude-code --capture redacted",
            r"C:\Program Files\Git\bin\bash.exe -c C:/x/lodeline-hook.exe claude-code --capture redacted",
            "/bin/bash x y/lodeline-hook claude-code --capture redacted",
            "/usr/bin/env /opt/x/lodeline-hook claude-code --capture redacted",
            "/usr/bin/env lodeline-hook claude-code --capture redacted",
            r"C:\x y\lodeline-hook.exe codex --capture redacted",
            r"C:\x y\lodeline-hook.exe claude-code --verbose",
            "/usr/bin/sudo x y/lodeline-hook claude-code --capture redacted",
            "/usr/bin/nice ./lodeline-hook claude-code --capture redacted",
            "/usr/bin/time ../bin/lodeline-hook claude-code --capture redacted",
            "/usr/bin/nohup bin/lodeline-hook claude-code --capture redacted",
            "/usr/bin/timeout 5 bin/lodeline-hook claude-code --capture redacted",
            "/opt/wrap.sh bin/lodeline-hook claude-code --capture redacted",
            "C:/tools/run.exe a/lodeline-hook.exe claude-code --capture redacted",
            "/opt/x ~/lodeline-hook claude-code --capture redacted",
        ]
        .into_iter()
        .filter(|cmd| {
            let mut v = nested_settings(&[cmd]);
            count_lodeline_entries(&v, NEW_EXE, "claude-code") != 0
                || remove_from(&mut v, NEW_EXE, "claude-code")
        })
        .collect();
        assert!(claimed.is_empty(), "claimed as ours: {claimed:#?}");
    }

    // --- Codex (nested, ~/.codex/hooks.json) ---
    #[test]
    fn codex_uses_nested_and_notes_hook_trust() {
        let s = render_block("/abs/lodeline-hook", "codex", "redacted");
        assert!(s.contains("/abs/lodeline-hook codex --capture redacted"));
        // Path-separator-agnostic: PathBuf renders `\` on Windows.
        assert!(s.contains("codex") && s.contains("hooks.json"));
        assert!(s.contains("/hooks") && s.contains("trust"));
        assert!(!s.contains("config.toml"));
        let mut v = json!({});
        assert!(merge_into(
            &mut v,
            "/abs/lodeline-hook",
            "codex",
            "redacted"
        ));
        assert_eq!(count_lodeline_entries(&v, "/abs/lodeline-hook", "codex"), 1);
        assert!(v["hooks"]["PreToolUse"].is_array());
    }

    // #208 — Antigravity IS a settings-merge agent now. Its file is shared
    // with agy's own `/hooks` TUI, so the merge must be additive and uninstall
    // must take only our entry.
    #[test]
    fn antigravity_registers_in_nested_pretooluse_shape() {
        let mut v = json!({});
        assert!(merge_into(
            &mut v,
            "/abs/lodeline-hook",
            "antigravity",
            "redacted"
        ));
        assert_eq!(
            count_lodeline_entries(&v, "/abs/lodeline-hook", "antigravity"),
            1
        );
        // The nested wrapper is required: a bare top-level `PreToolUse` does
        // not load on agy (#202).
        assert!(v["hooks"]["PreToolUse"].is_array(), "got {v}");
        assert!(
            v["PreToolUse"].is_null(),
            "must not write the bare shape: {v}"
        );
    }

    #[test]
    fn antigravity_settings_path_is_the_shared_file() {
        let p = settings_path("antigravity").expect("antigravity has a settings path");
        assert!(
            p.ends_with(".gemini/config/hooks.json"),
            "got {}",
            p.display()
        );
    }

    /// The file belongs to agy too — registering must not drop a hook the user
    /// or the `/hooks` TUI put there, and uninstall must leave it behind.
    #[test]
    fn antigravity_merge_preserves_foreign_hooks_and_uninstall_leaves_them() {
        let mut v = json!({
            "hooks": {"PreToolUse": [
                {"matcher": "*", "hooks": [{"type": "command", "command": "/other/tool --x"}]}
            ]}
        });
        assert!(merge_into(
            &mut v,
            "/abs/lodeline-hook",
            "antigravity",
            "redacted"
        ));
        assert_eq!(v["hooks"]["PreToolUse"].as_array().unwrap().len(), 2);

        assert!(remove_from(&mut v, "/abs/lodeline-hook", "antigravity"));
        let left = v["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(left.len(), 1, "foreign hook must survive: {v}");
        assert_eq!(left[0]["hooks"][0]["command"], "/other/tool --x");
        assert_eq!(
            count_lodeline_entries(&v, "/abs/lodeline-hook", "antigravity"),
            0
        );
    }

    // --- Cursor (version + two event arrays) ---
    #[test]
    fn cursor_registers_both_events_with_version() {
        let mut v = json!({});
        assert!(merge_into(
            &mut v,
            "/abs/lodeline-hook",
            "cursor",
            "redacted"
        ));
        assert_eq!(v["version"], json!(1));
        assert!(v["hooks"]["beforeShellExecution"].is_array());
        assert!(v["hooks"]["beforeMCPExecution"].is_array());
        // one entry per event = 2 total
        assert_eq!(
            count_lodeline_entries(&v, "/abs/lodeline-hook", "cursor"),
            2
        );
        assert!(!merge_into(
            &mut v,
            "/abs/lodeline-hook",
            "cursor",
            "redacted"
        ));
        let s = render_block("/abs/lodeline-hook", "cursor", "redacted");
        assert!(s.contains("beforeShellExecution") && s.contains("beforeMCPExecution"));
    }
    #[test]
    fn cursor_remove_preserves_foreign() {
        let mut v = json!({"version":1,"hooks":{"beforeShellExecution":[
            {"command":"/other/guard.sh"}
        ]}});
        merge_into(&mut v, "/abs/lodeline-hook", "cursor", "redacted");
        assert!(remove_from(&mut v, "/abs/lodeline-hook", "cursor"));
        assert_eq!(
            count_lodeline_entries(&v, "/abs/lodeline-hook", "cursor"),
            0
        );
        assert!(serde_json::to_string(&v)
            .unwrap()
            .contains("/other/guard.sh"));
    }

    #[test]
    fn unsupported_agent_paths() {
        assert!(settings_path("nope").is_none());
        assert_eq!(count_lodeline_entries(&json!({}), "/x", "nope"), 0);
    }

    // --- Cursor enforce ---

    #[test]
    fn cursor_enforce_registers_both_events_with_failclosed() {
        let mut v = json!({});
        assert!(merge_into_enforce(
            &mut v,
            "/abs/lodeline-hook",
            "cursor",
            "redacted",
            "closed"
        ));
        for ev in CURSOR_EVENTS {
            let arr = v["hooks"][ev].as_array().unwrap();
            assert_eq!(arr.len(), 1, "{ev} has exactly one entry");
            assert_eq!(arr[0]["failClosed"], json!(true));
            let cmd = arr[0]["command"].as_str().unwrap();
            assert!(cmd.contains("--enforce"), "got: {cmd}");
            assert!(cmd.contains("--on-failure closed"), "got: {cmd}");
        }
        // idempotent
        assert!(!merge_into_enforce(
            &mut v,
            "/abs/lodeline-hook",
            "cursor",
            "redacted",
            "closed"
        ));
        assert_eq!(
            count_lodeline_entries(&v, "/abs/lodeline-hook", "cursor"),
            2
        );
    }

    #[test]
    fn cursor_enforce_open_has_no_failclosed() {
        let mut v = json!({});
        merge_into_enforce(&mut v, "/abs/lodeline-hook", "cursor", "redacted", "open");
        let arr = v["hooks"]["beforeShellExecution"].as_array().unwrap();
        assert!(arr[0].get("failClosed").is_none());
    }

    #[test]
    fn cursor_closed_to_open_strips_failclosed() {
        let mut v = json!({});
        merge_into_enforce(&mut v, "/abs/lodeline-hook", "cursor", "redacted", "closed");
        assert!(merge_into_enforce(
            &mut v,
            "/abs/lodeline-hook",
            "cursor",
            "redacted",
            "open"
        ));
        let arr = v["hooks"]["beforeShellExecution"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert!(
            arr[0].get("failClosed").is_none(),
            "stale failClosed must be removed"
        );
        assert_eq!(
            arr[0].as_object().unwrap().len(),
            1,
            "entry is exactly {{command}}"
        );
    }

    #[test]
    fn cursor_observe_to_enforce_replaces_in_place() {
        let mut v = json!({});
        merge_into(&mut v, "/abs/lodeline-hook", "cursor", "redacted");
        assert!(merge_into_enforce(
            &mut v,
            "/abs/lodeline-hook",
            "cursor",
            "redacted",
            "open"
        ));
        // replaced, not stacked: still one per event (2 total)
        assert_eq!(
            count_lodeline_entries(&v, "/abs/lodeline-hook", "cursor"),
            2
        );
        let arr = v["hooks"]["beforeShellExecution"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert!(arr[0]["command"].as_str().unwrap().contains("--enforce"));
    }

    #[test]
    fn cursor_entry_accessors() {
        let e = json!({ "command": "/x/lodeline-hook cursor --enforce", "failClosed": true });
        assert_eq!(
            cursor_entry_command(&e),
            Some("/x/lodeline-hook cursor --enforce")
        );
        assert!(cursor_entry_fail_closed(&e));
        let no_fc = json!({ "command": "/x/lodeline-hook cursor" });
        assert!(!cursor_entry_fail_closed(&no_fc)); // absent = false (Cursor default)
        assert_eq!(cursor_entry_command(&json!({})), None); // command absent → None
        assert!(!cursor_entry_fail_closed(&json!({ "failClosed": "yes" }))); // non-bool → false
    }

    #[test]
    fn cursor_enforce_to_observe_strips_enforce() {
        let mut v = json!({});
        merge_into_enforce(&mut v, "/abs/lodeline-hook", "cursor", "redacted", "closed");
        assert!(merge_into(
            &mut v,
            "/abs/lodeline-hook",
            "cursor",
            "redacted"
        ));
        let arr = v["hooks"]["beforeShellExecution"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        let entry = arr[0].as_object().unwrap();
        assert_eq!(entry.len(), 1, "downgrade leaves exactly {{command}}");
        assert!(!entry["command"].as_str().unwrap().contains("--enforce"));
        assert!(
            entry.get("failClosed").is_none(),
            "stale failClosed stripped on downgrade"
        );
    }

    #[test]
    fn cursor_enforce_preview_closed_shows_failclosed() {
        let s = render_block_enforce("/abs/lodeline-hook", "cursor", "redacted", "closed");
        assert!(
            s.contains("\"failClosed\": true"),
            "closed preview must show failClosed:\n{s}"
        );
        let open = render_block_enforce("/abs/lodeline-hook", "cursor", "redacted", "open");
        assert!(
            !open.contains("failClosed"),
            "open preview must NOT show failClosed:\n{open}"
        );
    }

    // --- write_baseline records the actual installed command ---

    /// Helper: call the directory-injectable `write_baseline_in` with `dir` and
    /// return the parsed JSON from `dir/hook-registration.json`. Race-free: no
    /// process-global env var (`XDG_STATE_HOME`) is touched, so these tests are
    /// safe to run in parallel with any other state_dir()-dependent test.
    fn baseline_json_in(
        dir: &std::path::Path,
        enforce: bool,
        on_failure: &str,
    ) -> serde_json::Value {
        let settings = dir.join("settings.json");
        write_baseline_in(
            dir,
            "claude-code",
            &settings,
            "/usr/bin/lodeline-hook",
            "claude-code",
            "redacted",
            "*",
            enforce,
            on_failure,
        )
        .unwrap();
        let raw = std::fs::read(baseline_path_in(dir, "claude-code").unwrap()).unwrap();
        serde_json::from_slice(&raw).unwrap()
    }

    /// `command_string_enforce` produces the right flag sequence (pure, race-free).
    #[test]
    fn command_string_enforce_contains_enforce_flags() {
        let cmd =
            command_string_enforce("/usr/bin/lodeline-hook", "claude-code", "redacted", "open");
        assert!(
            cmd.contains("--enforce --on-failure open"),
            "command_string_enforce must include enforce flags, got: {cmd}"
        );
        assert!(
            cmd.contains("--capture redacted"),
            "command_string_enforce must include --capture, got: {cmd}"
        );
    }

    /// write_baseline(enforce=true) records the enforce command and a matching hash.
    #[test]
    fn write_baseline_records_enforce_command_when_enforce() {
        let tmp = tempfile::tempdir().unwrap();
        let v = baseline_json_in(tmp.path(), true, "open");
        let cmd = v["command"].as_str().unwrap();
        assert!(
            cmd.contains("--enforce --on-failure open"),
            "baseline must record the enforce command, got: {cmd}"
        );
        let expected_hash = blake3::hash(cmd.as_bytes()).to_hex().to_string();
        assert_eq!(
            v["block_hash"].as_str().unwrap(),
            expected_hash,
            "block_hash must be blake3 of the enforce command"
        );
    }

    /// write_baseline(enforce=false) records the observe command (regression guard).
    #[test]
    fn write_baseline_records_observe_command_when_not_enforce() {
        let tmp = tempfile::tempdir().unwrap();
        let v = baseline_json_in(tmp.path(), false, "open");
        let cmd = v["command"].as_str().unwrap();
        assert!(
            !cmd.contains("--enforce"),
            "non-enforce baseline must NOT contain --enforce, got: {cmd}"
        );
        assert!(
            cmd.contains("--capture redacted"),
            "non-enforce baseline must contain --capture, got: {cmd}"
        );
    }

    #[test]
    fn baseline_path_is_per_agent_and_validated() {
        let dir = std::path::Path::new("/state");
        assert_eq!(
            baseline_path_in(dir, "cursor").unwrap(),
            dir.join("hook-registration-cursor.json")
        );
        assert!(baseline_path_in(dir, "../evil").is_none()); // unknown slug → no path
    }

    #[test]
    fn write_baseline_per_agent_no_clobber_and_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        // claude (observe) then cursor (enforce closed) → two distinct files
        write_baseline_in(
            dir.path(),
            "claude-code",
            std::path::Path::new("/h/.claude/settings.json"),
            "/x/lodeline-hook",
            "claude-code",
            "redacted",
            "*",
            false,
            "open",
        )
        .unwrap();
        write_baseline_in(
            dir.path(),
            "cursor",
            std::path::Path::new("/h/.cursor/hooks.json"),
            "/x/lodeline-hook",
            "cursor",
            "redacted",
            "*",
            true,
            "closed",
        )
        .unwrap();

        let claude: serde_json::Value = serde_json::from_slice(
            &std::fs::read(dir.path().join("hook-registration-claude-code.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(claude["agent"], "claude-code");
        assert!(claude["matcher"].is_string());
        assert!(claude["fail_closed"].is_null()); // claude → no fail_closed

        let cursor: serde_json::Value = serde_json::from_slice(
            &std::fs::read(dir.path().join("hook-registration-cursor.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(cursor["agent"], "cursor");
        assert_eq!(cursor["fail_closed"], serde_json::json!(true)); // enforce + closed
        assert!(cursor["matcher"].is_string()); // matcher kept for wire continuity
    }
}
