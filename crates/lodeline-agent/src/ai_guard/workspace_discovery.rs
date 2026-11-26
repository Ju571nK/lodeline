//! Phase 3b.6.2 — generic per-repo discovery shared by Continue.dev,
//! Claude Code, and Codex per-repo parsers. Extracted from the
//! per-tool `continue_discovery` module shipped in 3b.6.1.

use std::path::{Path, PathBuf};

use super::parser::claude_components::{
    MAX_NESTED_DEPTH, MAX_NESTED_WALK_DIRS, MAX_WATCHED_COMPONENT_DIRS, NESTED_WALK_SKIPPED,
};

const DISCOVERY_WARN_THRESHOLD: usize = 50;

/// Most nested `.claude/settings.json` rows one repository adds.
const MAX_NESTED_ROWS: usize = MAX_WATCHED_COMPONENT_DIRS;
/// Most folders the nested walk reads below one repository.
const MAX_NESTED_REPO_DIRS: usize = 2_000;

/// Bounds on the nested walk. `total_dirs` is shared by every repository one
/// discovery call walks, so a workspace of many repositories stays cheap.
#[derive(Clone, Copy)]
struct NestedLimits {
    depth: usize,
    rows: usize,
    repo_dirs: usize,
    total_dirs: usize,
}

const NESTED_LIMITS: NestedLimits = NestedLimits {
    depth: MAX_NESTED_DEPTH,
    rows: MAX_NESTED_ROWS,
    repo_dirs: MAX_NESTED_REPO_DIRS,
    total_dirs: MAX_NESTED_WALK_DIRS,
};

/// Scan each operator-supplied workspace root 1-level deep and return
/// canonical paths of direct subdirs that contain `marker_subpath`
/// as an existing file.
///
/// - `roots`: raw policy.yaml strings (one root per element). Each is
///   ~/$VAR-expanded via `lodeline_core::policy::expand::expand` then
///   canonicalized via `dunce::canonicalize`.
/// - `marker_subpath`: relative path under each candidate repo that
///   must exist as a file for the repo to count
///   (e.g. `".continue/config.json"`, `".claude/settings.json"`,
///   `".codex/config.toml"`).
///
/// Errors / edge cases are tolerated:
/// - Roots that fail to expand / canonicalize → warn-log, skip.
/// - Non-dir entries → silent skip.
/// - Output deduplicated via BTreeSet.
/// - Info-log once when total > `DISCOVERY_WARN_THRESHOLD`.
pub fn discover_per_repo(roots: &[String], marker_subpath: &str) -> Vec<PathBuf> {
    let mut out = std::collections::BTreeSet::new();
    for raw in roots {
        let Some(root) = expand_and_canonicalize(raw) else {
            continue;
        };
        let entries = match std::fs::read_dir(&root) {
            Ok(it) => it,
            Err(e) => {
                tracing::warn!(root = %root.display(), error = %e,
                    "workspace_discovery: read_dir failed; skipping root");
                continue;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let marker = path.join(marker_subpath);
            if marker.is_file() {
                match dunce::canonicalize(&path) {
                    Ok(canonical) => {
                        out.insert(canonical);
                    }
                    Err(e) => {
                        tracing::warn!(path = %path.display(), error = %e,
                            "workspace_discovery: canonicalize failed; skipping repo");
                    }
                }
            }
        }
    }
    if out.len() > DISCOVERY_WARN_THRESHOLD {
        tracing::info!(count = out.len(), marker = %marker_subpath,
            "workspace_discovery: many repos discovered (operator may want narrower roots)");
    }
    out.into_iter().collect()
}

/// #145 — Claude Code repos are discovered by EITHER marker: the per-tool
/// settings file (`.claude/settings.json`) OR a committed project MCP payload
/// at the repo root (`.mcp.json`). A repo with only `.mcp.json` is still a
/// TrustFall surface, so it must be discovered (and watched) too. Union,
/// deduplicated by canonical path.
pub fn discover_claude_repos(roots: &[String]) -> Vec<PathBuf> {
    let mut set: std::collections::BTreeSet<PathBuf> =
        discover_per_repo(roots, ".claude/settings.json")
            .into_iter()
            .collect();
    set.extend(discover_per_repo(roots, ".mcp.json"));
    set.extend(discover_per_repo(roots, "CLAUDE.md"));
    set.extend(discover_per_repo(roots, "AGENTS.md"));
    // #199: "Yes, and don't ask again" writes allow rules to the local file,
    // so it is often the only one a repo has; a loop prompt runs unattended.
    set.extend(discover_per_repo(roots, ".claude/settings.local.json"));
    set.extend(discover_per_repo(roots, ".claude/loop.md"));
    // #199 — a repo that ships only skills or subagents can still carry hooks.
    set.extend(discover_per_repo_dir(roots, ".claude/skills"));
    set.extend(discover_per_repo_dir(roots, ".claude/agents"));
    set.extend(discover_per_repo_dir(roots, ".claude/commands"));
    let repos: Vec<PathBuf> = set.iter().cloned().collect();
    set.extend(nested_rows_for_repos(&repos, NESTED_LIMITS));
    set.into_iter().collect()
}

/// The nested rows of every repo in `repos`, walked in the order given (the
/// caller passes them sorted, so the caps pick the same folders on every run).
/// Logs one warning when any cap stopped a walk.
fn nested_rows_for_repos(repos: &[PathBuf], limits: NestedLimits) -> Vec<PathBuf> {
    let mut budget = limits.total_dirs;
    let mut out = Vec::new();
    let mut capped = false;
    for repo in repos {
        let (rows, stopped) = nested_claude_settings_dirs(repo, limits, &mut budget);
        out.extend(rows);
        capped |= stopped;
    }
    if capped {
        tracing::warn!(
            total_dirs = limits.total_dirs,
            repo_dirs = limits.repo_dirs,
            rows = limits.rows,
            "workspace_discovery: nested .claude/settings.json walk hit a cap; some folders get no row"
        );
    }
    out
}

/// #539. The folders strictly below `repo` that hold their own
/// `.claude/settings.json`. Claude Code reads that file for a session started
/// in the folder, so each one is a project row of its own. The walk is
/// breadth first and sorted by name, so the caps pick the same folders on every
/// run. It goes `limits.depth` levels down, reads at most `limits.repo_dirs`
/// folders and what is left of `budget`, returns at most `limits.rows`, and
/// skips hidden folders, `node_modules` and `target`. A link is not followed.
/// The bool is true when a cap stopped the walk.
fn nested_claude_settings_dirs(
    repo: &Path,
    limits: NestedLimits,
    budget: &mut usize,
) -> (Vec<PathBuf>, bool) {
    let mut found = Vec::new();
    let mut queue = std::collections::VecDeque::from([(repo.to_path_buf(), 0usize)]);
    let mut visited = 0usize;
    while let Some((dir, depth)) = queue.pop_front() {
        if visited == usize::MAX {
            return (found, true);
        }
        visited += 1;
        *budget = budget.saturating_sub(1);
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut subdirs = Vec::new();
        let mut has_dot_claude = false;
        for entry in entries.flatten() {
            if !entry.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == ".claude" {
                has_dot_claude = true;
            } else if !name.starts_with('.') && !NESTED_WALK_SKIPPED.contains(&name.as_ref()) {
                subdirs.push(entry.path());
            }
        }
        if depth > 0 && has_dot_claude && dir.join(".claude").join("settings.json").is_file() {
            if found.len() == limits.rows {
                return (found, true);
            }
            found.push(dir);
        }
        if depth < limits.depth {
            subdirs.sort();
            queue.extend(subdirs.into_iter().map(|sub| (sub, depth + 1)));
        }
    }
    (found, false)
}

/// #146. Codex repos by `.codex/config.toml`, `.codex/hooks.json` (#200), a
/// root `.codex/rules/` folder, or a committed `AGENTS.md` (Codex's first-class
/// instruction file). Union, deduped by canonical path.
pub fn discover_codex_repos(roots: &[String]) -> Vec<PathBuf> {
    let mut set: std::collections::BTreeSet<PathBuf> =
        discover_per_repo(roots, ".codex/config.toml")
            .into_iter()
            .collect();
    set.extend(discover_per_repo(roots, ".codex/hooks.json"));
    set.extend(discover_per_repo_dir(roots, ".codex/rules"));
    set.extend(discover_per_repo(roots, "AGENTS.md"));
    let subfolder_only = discover_git_repos_with_subfolder_codex(roots, &set);
    set.extend(subfolder_only);
    set.into_iter().collect()
}

/// A repository whose only Codex files sit in a subfolder `.codex/`. Only a
/// direct subdirectory with a `.git` entry that is not already `found` is
/// walked, so a plain folder of projects costs one `stat` each.
fn discover_git_repos_with_subfolder_codex(
    roots: &[String],
    found: &std::collections::BTreeSet<PathBuf>,
) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for raw in roots {
        let Some(root) = expand_and_canonicalize(raw) else {
            continue;
        };
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() || !path.join(".git").exists() {
                continue;
            }
            let Ok(repo) = dunce::canonicalize(&path) else {
                continue;
            };
            if !found.contains(&repo) && !codex_subfolder_dirs(&repo).is_empty() {
                out.push(repo);
            }
        }
    }
    out
}

const SUBFOLDER_WALK_MAX_DEPTH: usize = 5;
const SUBFOLDER_WALK_MAX_DIRS: usize = 2_000;
const SUBFOLDER_WALK_SKIP: [&str; 3] = ["node_modules", "target", "vendor"];

#[cfg(test)]
pub(crate) mod walk_probe {
    use std::cell::RefCell;

    thread_local! {
        static HOOK: RefCell<Option<Box<dyn Fn()>>> = const { RefCell::new(None) };
    }

    pub(crate) fn set(hook: impl Fn() + 'static) {
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }

    pub(crate) fn clear() {
        HOOK.with(|h| *h.borrow_mut() = None);
    }

    pub(crate) fn fire() {
        HOOK.with(|h| {
            if let Some(hook) = h.borrow().as_ref() {
                hook();
            }
        });
    }
}

/// #200. The `.codex/` folders strictly below `repo_root` that hold a
/// `config.toml`, a `hooks.json` or a `rules` folder. Codex layers every
/// `.codex/` from the project root down to the folder a session starts in, and
/// a daemon cannot know that folder, so every one is returned. The walk is
/// bounded in depth and in folders visited, skips hidden folders,
/// `node_modules`, `target` and `vendor`, and follows no symlink. A folder with
/// its own `.git` entry is a nested repository or submodule, which Codex takes
/// as its own project root, so the walk does not enter it.
pub fn codex_subfolder_dirs(repo_root: &Path) -> Vec<PathBuf> {
    #[cfg(test)]
    walk_probe::fire();
    let mut found = Vec::new();
    let mut queue = std::collections::VecDeque::from([(repo_root.to_path_buf(), 0usize)]);
    let mut visited = 0usize;
    while let Some((dir, depth)) = queue.pop_front() {
        if visited == SUBFOLDER_WALK_MAX_DIRS {
            tracing::warn!(
                visited,
                "workspace_discovery: subfolder .codex walk stopped at the folder cap"
            );
            break;
        }
        visited += 1;
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let entries: Vec<_> = entries.flatten().collect();
        if depth > 0 && entries.iter().any(|e| e.file_name() == ".git") {
            continue;
        }
        for entry in entries {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if !kind.is_dir() {
                continue;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == ".codex" {
                if depth > 0 && holds_codex_layer(&entry.path()) {
                    found.push(entry.path());
                }
                continue;
            }
            if depth < SUBFOLDER_WALK_MAX_DEPTH
                && !name.starts_with('.')
                && !SUBFOLDER_WALK_SKIP.contains(&name.as_ref())
            {
                queue.push_back((entry.path(), depth + 1));
            }
        }
    }
    found.sort();
    found
}

fn holds_codex_layer(dot_codex: &Path) -> bool {
    dot_codex.join("config.toml").is_file()
        || dot_codex.join("hooks.json").is_file()
        || dot_codex.join("rules").is_dir()
}

/// #146 — Cursor repos by `.cursor/mcp.json`, `.cursor/hooks.json` (#203) OR
/// `.cursorrules` (files) OR a `.cursor/rules` directory. Union, deduped by
/// canonical path.
pub fn discover_cursor_repos(roots: &[String]) -> Vec<PathBuf> {
    let mut set: std::collections::BTreeSet<PathBuf> = discover_per_repo(roots, ".cursor/mcp.json")
        .into_iter()
        .collect();
    set.extend(discover_per_repo(roots, ".cursor/hooks.json"));
    set.extend(discover_per_repo(roots, ".cursorrules"));
    set.extend(discover_per_repo_dir(roots, ".cursor/rules"));
    set.into_iter().collect()
}

/// #203: Grok repos by a `.grok/hooks` folder or a `.grok/config.toml`,
/// the two project sources `GrokProjectParser` reads. Union, deduped by
/// canonical path.
pub fn discover_grok_repos(roots: &[String]) -> Vec<PathBuf> {
    let mut set: std::collections::BTreeSet<PathBuf> = discover_per_repo_dir(roots, ".grok/hooks")
        .into_iter()
        .collect();
    set.extend(discover_per_repo(roots, ".grok/config.toml"));
    set.into_iter().collect()
}

/// Like [`discover_per_repo`], but the marker is a directory.
fn discover_per_repo_dir(roots: &[String], marker_subpath: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for raw in roots {
        let Some(root) = expand_and_canonicalize(raw) else {
            continue;
        };
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && path.join(marker_subpath).is_dir() {
                if let Ok(c) = dunce::canonicalize(&path) {
                    out.push(c);
                }
            }
        }
    }
    out
}

fn expand_and_canonicalize(raw: &str) -> Option<PathBuf> {
    let expanded =
        match lodeline_core::policy::expand::expand(raw, &lodeline_core::policy::expand::EnvLookup)
        {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(raw, error = ?e, "workspace_discovery: expand failed; skipping");
                return None;
            }
        };
    match dunce::canonicalize(&expanded) {
        Ok(p) => Some(p),
        Err(e) => {
            tracing::warn!(raw, expanded = %expanded.display(), error = %e,
                "workspace_discovery: canonicalize failed; skipping");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const CONTINUE_MARKER: &str = ".continue/config.json";
    const CLAUDE_MARKER: &str = ".claude/settings.json";
    const CODEX_MARKER: &str = ".codex/config.toml";

    fn make_repo_with(dir: &std::path::Path, name: &str, marker: &str) {
        let repo = dir.join(name);
        let (sub, file) = marker.split_once('/').unwrap();
        std::fs::create_dir_all(repo.join(sub)).unwrap();
        std::fs::write(repo.join(sub).join(file), "{}").unwrap();
    }

    #[test]
    fn discover_empty_roots() {
        let out = discover_per_repo(&[], CONTINUE_MARKER);
        assert!(out.is_empty());
    }

    #[test]
    fn discover_skips_nonexistent_root() {
        let out = discover_per_repo(
            &["/this/path/does/not/exist/lodeline-3b6.2".to_string()],
            CONTINUE_MARKER,
        );
        assert!(out.is_empty());
    }

    #[test]
    fn discover_finds_one_level_subdir_with_marker_continue() {
        let dir = tempdir().unwrap();
        make_repo_with(dir.path(), "repoA", CONTINUE_MARKER);
        let out = discover_per_repo(&[dir.path().to_string_lossy().into()], CONTINUE_MARKER);
        let canonical = dunce::canonicalize(dir.path().join("repoA")).unwrap();
        assert_eq!(out, vec![canonical]);
    }

    #[test]
    fn discover_finds_one_level_subdir_with_marker_claude() {
        let dir = tempdir().unwrap();
        make_repo_with(dir.path(), "repoA", CLAUDE_MARKER);
        let out = discover_per_repo(&[dir.path().to_string_lossy().into()], CLAUDE_MARKER);
        let canonical = dunce::canonicalize(dir.path().join("repoA")).unwrap();
        assert_eq!(out, vec![canonical]);
    }

    #[test]
    fn discover_finds_one_level_subdir_with_marker_codex() {
        let dir = tempdir().unwrap();
        make_repo_with(dir.path(), "repoA", CODEX_MARKER);
        let out = discover_per_repo(&[dir.path().to_string_lossy().into()], CODEX_MARKER);
        let canonical = dunce::canonicalize(dir.path().join("repoA")).unwrap();
        assert_eq!(out, vec![canonical]);
    }

    #[test]
    fn discover_ignores_subdir_without_marker() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("emptyRepo")).unwrap();
        let out = discover_per_repo(&[dir.path().to_string_lossy().into()], CONTINUE_MARKER);
        assert!(out.is_empty());
    }

    #[test]
    fn discover_does_not_recurse_two_levels() {
        let dir = tempdir().unwrap();
        let workspace = dir.path().join("ws");
        let group = workspace.join("group");
        std::fs::create_dir_all(&group).unwrap();
        make_repo_with(&group, "repoC", CONTINUE_MARKER);
        let out = discover_per_repo(&[workspace.to_string_lossy().into()], CONTINUE_MARKER);
        assert!(
            out.is_empty(),
            "1-level scan must not match group/repoC; got {out:?}"
        );
    }

    #[test]
    fn discover_multiple_repos_under_one_root() {
        let dir = tempdir().unwrap();
        make_repo_with(dir.path(), "repoA", CONTINUE_MARKER);
        make_repo_with(dir.path(), "repoB", CONTINUE_MARKER);
        let out = discover_per_repo(&[dir.path().to_string_lossy().into()], CONTINUE_MARKER);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn discover_dedups_across_roots() {
        let dir = tempdir().unwrap();
        make_repo_with(dir.path(), "repoA", CONTINUE_MARKER);
        let root = dir.path().to_string_lossy().to_string();
        let out = discover_per_repo(&[root.clone(), root], CONTINUE_MARKER);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn discover_claude_repos_finds_mcp_json_only_repo() {
        let root = tempdir().unwrap();
        let repo = root.path().join("only-mcp");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join(".mcp.json"), "{}").unwrap();
        let roots = vec![root.path().to_string_lossy().to_string()];
        let found = discover_claude_repos(&roots);
        let canon = dunce::canonicalize(&repo).unwrap();
        assert!(found.contains(&canon), "got {found:?}");
    }

    #[test]
    fn discover_claude_repos_finds_skills_or_subagents_only_repo() {
        let root = tempdir().unwrap();
        let skills = root.path().join("only-skills");
        let agents = root.path().join("only-subagents");
        std::fs::create_dir_all(skills.join(".claude/skills/x")).unwrap();
        std::fs::create_dir_all(agents.join(".claude/agents")).unwrap();
        let roots = vec![root.path().to_string_lossy().to_string()];
        let found = discover_claude_repos(&roots);
        assert!(
            found.contains(&dunce::canonicalize(&skills).unwrap()),
            "got {found:?}"
        );
        assert!(
            found.contains(&dunce::canonicalize(&agents).unwrap()),
            "got {found:?}"
        );
    }

    #[test]
    fn discover_claude_repos_finds_commands_only_repo() {
        let root = tempdir().unwrap();
        let repo = root.path().join("only-commands");
        std::fs::create_dir_all(repo.join(".claude/commands")).unwrap();
        std::fs::write(repo.join(".claude/commands/x.md"), "x").unwrap();
        let roots = vec![root.path().to_string_lossy().to_string()];
        let found = discover_claude_repos(&roots);
        assert!(
            found.contains(&dunce::canonicalize(&repo).unwrap()),
            "got {found:?}"
        );
    }

    fn write_settings(dir: &std::path::Path) {
        std::fs::create_dir_all(dir.join(".claude")).unwrap();
        std::fs::write(dir.join(".claude").join("settings.json"), "{}").unwrap();
    }

    fn nested_found(root: &std::path::Path) -> Vec<PathBuf> {
        discover_claude_repos(&[root.to_string_lossy().to_string()])
    }

    #[test]
    fn nested_claude_settings_below_a_repo_get_a_project_row() {
        let root = tempdir().unwrap();
        let repo = root.path().join("repo");
        write_settings(&repo);
        write_settings(&repo.join("pkg"));
        write_settings(&repo.join("apps").join("web"));
        let found = nested_found(root.path());
        for dir in [
            repo.clone(),
            repo.join("pkg"),
            repo.join("apps").join("web"),
        ] {
            assert!(
                found.contains(&dunce::canonicalize(&dir).unwrap()),
                "{dir:?} missing from {found:?}"
            );
        }
        assert!(
            !found.contains(&dunce::canonicalize(repo.join("apps")).unwrap()),
            "a folder with no settings of its own gets no row: {found:?}"
        );
    }

    #[test]
    fn nested_walk_stops_below_the_depth_cap() {
        let root = tempdir().unwrap();
        let repo = root.path().join("repo");
        write_settings(&repo);
        let mut deep = repo.clone();
        let mut at_cap = repo.clone();
        for i in 1..=(MAX_NESTED_DEPTH + 1) {
            deep = deep.join(format!("d{i}"));
            if i == MAX_NESTED_DEPTH {
                at_cap = deep.clone();
            }
        }
        write_settings(&at_cap);
        write_settings(&deep);
        let found = nested_found(root.path());
        assert!(found.contains(&dunce::canonicalize(&at_cap).unwrap()));
        assert!(!found.contains(&dunce::canonicalize(&deep).unwrap()));
    }

    #[test]
    fn nested_walk_skips_hidden_node_modules_and_target_folders() {
        let root = tempdir().unwrap();
        let repo = root.path().join("repo");
        write_settings(&repo);
        for skipped in [".hidden", "node_modules", "target"] {
            write_settings(&repo.join(skipped).join("pkg"));
            write_settings(&repo.join(skipped));
        }
        write_settings(&repo.join("kept"));
        let found = nested_found(root.path());
        assert_eq!(found.len(), 2, "got {found:?}");
        assert!(found.contains(&dunce::canonicalize(repo.join("kept")).unwrap()));
    }

    #[cfg(unix)]
    #[test]
    fn nested_walk_follows_no_link() {
        let root = tempdir().unwrap();
        let repo = root.path().join("repo");
        let outside = root.path().join("elsewhere");
        write_settings(&repo);
        write_settings(&outside.join("pkg"));
        std::os::unix::fs::symlink(&outside, repo.join("linked")).unwrap();
        let found = nested_found(root.path());
        assert!(
            !found.iter().any(|p| p.ends_with("pkg")),
            "a linked folder was walked: {found:?}"
        );
    }

    #[test]
    fn nested_rows_stop_at_the_row_cap() {
        let root = tempdir().unwrap();
        let repo = dunce::canonicalize(root.path()).unwrap().join("repo");
        write_settings(&repo);
        for i in 0..10 {
            write_settings(&repo.join(format!("p{i:02}")));
        }
        let small = NestedLimits {
            rows: 3,
            ..NESTED_LIMITS
        };
        let rows = nested_rows_for_repos(std::slice::from_ref(&repo), small);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0], repo.join("p00"));
        let all = nested_rows_for_repos(std::slice::from_ref(&repo), NESTED_LIMITS);
        assert_eq!(all.len(), 10);
    }

    #[test]
    fn nested_rows_hold_a_cap_of_64_per_repo() {
        let root = tempdir().unwrap();
        let repo = root.path().join("repo");
        write_settings(&repo);
        for i in 0..(MAX_NESTED_ROWS + 6) {
            write_settings(&repo.join(format!("p{i:03}")));
        }
        assert_eq!(nested_found(root.path()).len(), 1 + MAX_NESTED_ROWS);
    }

    #[test]
    fn nested_walk_budget_is_shared_across_repos() {
        let root = tempdir().unwrap();
        let base = dunce::canonicalize(root.path()).unwrap();
        let repos: Vec<PathBuf> = (0..3).map(|r| base.join(format!("repo{r}"))).collect();
        for repo in &repos {
            write_settings(repo);
            for i in 0..5 {
                write_settings(&repo.join(format!("p{i}")));
            }
        }
        let limits = NestedLimits {
            total_dirs: 8,
            ..NESTED_LIMITS
        };
        let rows = nested_rows_for_repos(&repos, limits);
        let per_repo: Vec<usize> = repos
            .iter()
            .map(|r| rows.iter().filter(|p| p.starts_with(r)).count())
            .collect();
        assert_eq!(per_repo, vec![5, 1, 0], "got {rows:?}");
    }

    #[test]
    fn nested_walk_holds_a_cap_of_2000_folders_per_repo() {
        assert_eq!(MAX_NESTED_REPO_DIRS, 2_000);
        let root = tempdir().unwrap();
        let big = root.path().join("big");
        let after = root.path().join("zafter");
        write_settings(&big);
        write_settings(&after);
        for i in 0..(MAX_NESTED_REPO_DIRS + 100) {
            std::fs::create_dir_all(big.join(format!("d{i:04}"))).unwrap();
        }
        write_settings(&big.join("d0000"));
        write_settings(&big.join(format!("d{:04}", MAX_NESTED_REPO_DIRS + 99)));
        write_settings(&after.join("pkg"));
        let found = nested_found(root.path());
        let has = |p: PathBuf| found.contains(&dunce::canonicalize(p).unwrap());
        assert!(has(big.join("d0000")));
        assert!(!has(big.join(format!("d{:04}", MAX_NESTED_REPO_DIRS + 99))));
        assert!(
            has(after.join("pkg")),
            "a capped repo used the whole budget"
        );
    }

    #[test]
    fn nested_folder_reachable_from_two_roots_is_listed_once() {
        let root = tempdir().unwrap();
        let repo = root.path().join("repo");
        write_settings(&repo);
        write_settings(&repo.join("pkg"));
        let r = root.path().to_string_lossy().to_string();
        let found = discover_claude_repos(&[r.clone(), r]);
        assert_eq!(found.len(), 2, "got {found:?}");
    }

    #[test]
    fn discover_claude_repos_finds_agents_md_only() {
        let root = tempdir().unwrap();
        let repo = root.path().join("only-agents");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("AGENTS.md"), "x").unwrap();
        let roots = vec![root.path().to_string_lossy().to_string()];
        assert!(discover_claude_repos(&roots).contains(&dunce::canonicalize(&repo).unwrap()));
    }
    #[test]
    fn discover_claude_repos_finds_local_settings_or_loop_prompt_only() {
        let root = tempdir().unwrap();
        make_repo_with(root.path(), "only-local", ".claude/settings.local.json");
        make_repo_with(root.path(), "only-loop", ".claude/loop.md");
        let roots = vec![root.path().to_string_lossy().to_string()];
        let found = discover_claude_repos(&roots);
        for name in ["only-local", "only-loop"] {
            let repo = dunce::canonicalize(root.path().join(name)).unwrap();
            assert!(found.contains(&repo), "{name}: got {found:?}");
        }
    }

    #[test]
    fn discover_codex_repos_finds_hooks_json_only() {
        let root = tempdir().unwrap();
        let repo = root.path().join("only-hooks");
        std::fs::create_dir_all(repo.join(".codex")).unwrap();
        std::fs::write(repo.join(".codex/hooks.json"), "{}").unwrap();
        let roots = vec![root.path().to_string_lossy().to_string()];
        assert!(discover_codex_repos(&roots).contains(&dunce::canonicalize(&repo).unwrap()));
    }

    #[test]
    fn discover_codex_repos_finds_a_git_repo_with_only_a_subfolder_codex() {
        let dir = tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::create_dir_all(repo.join("services/api/.codex")).unwrap();
        std::fs::write(repo.join("services/api/.codex/hooks.json"), "{}").unwrap();
        let plain = dir.path().join("plain");
        std::fs::create_dir_all(plain.join("services/api/.codex")).unwrap();
        std::fs::write(plain.join("services/api/.codex/hooks.json"), "{}").unwrap();
        let roots = [dir.path().to_string_lossy().into_owned()];
        let found = discover_codex_repos(&roots);
        assert!(found.contains(&dunce::canonicalize(&repo).unwrap()));
        assert!(!found.contains(&dunce::canonicalize(&plain).unwrap()));
    }

    #[test]
    fn codex_subfolder_dirs_stop_at_a_nested_repo() {
        let dir = tempdir().unwrap();
        let repo = dir.path().join("repo");
        let own = repo.join("services/api/.codex");
        let inner = repo.join("libs/inner");
        for layer in [&own, &inner.join(".codex"), &inner.join("tools/.codex")] {
            std::fs::create_dir_all(layer).unwrap();
            std::fs::write(layer.join("hooks.json"), "{}").unwrap();
        }
        std::fs::write(inner.join(".git"), "gitdir: ../../.git/modules/inner\n").unwrap();
        assert_eq!(codex_subfolder_dirs(&repo), vec![own]);
    }

    #[test]
    fn discover_codex_repos_finds_a_root_rules_folder_only() {
        let root = tempdir().unwrap();
        let repo = root.path().join("only-rules");
        std::fs::create_dir_all(repo.join(".codex/rules")).unwrap();
        std::fs::write(
            repo.join(".codex/rules/default.rules"),
            "prefix_rule(pattern=[\"git\", \"push\"], decision=\"allow\")\n",
        )
        .unwrap();
        let roots = vec![root.path().to_string_lossy().to_string()];
        assert!(discover_codex_repos(&roots).contains(&dunce::canonicalize(&repo).unwrap()));
    }

    #[test]
    fn discover_codex_repos_finds_an_empty_root_rules_folder() {
        let root = tempdir().unwrap();
        let repo = root.path().join("empty-rules");
        std::fs::create_dir_all(repo.join(".codex/rules")).unwrap();
        let roots = vec![root.path().to_string_lossy().to_string()];
        assert!(discover_codex_repos(&roots).contains(&dunce::canonicalize(&repo).unwrap()));
    }

    #[test]
    fn discover_codex_repos_ignores_a_rules_file() {
        let root = tempdir().unwrap();
        let repo = root.path().join("rules-file");
        std::fs::create_dir_all(repo.join(".codex")).unwrap();
        std::fs::write(repo.join(".codex/rules"), "x").unwrap();
        let roots = vec![root.path().to_string_lossy().to_string()];
        assert!(!discover_codex_repos(&roots).contains(&dunce::canonicalize(&repo).unwrap()));
    }

    #[test]
    fn discover_codex_repos_finds_agents_md_only() {
        let root = tempdir().unwrap();
        let repo = root.path().join("only-agents");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("AGENTS.md"), "x").unwrap();
        let roots = vec![root.path().to_string_lossy().to_string()];
        assert!(discover_codex_repos(&roots).contains(&dunce::canonicalize(&repo).unwrap()));
    }
    #[test]
    fn discover_cursor_repos_finds_cursorrules_and_rules_dir() {
        let root = tempdir().unwrap();
        let r1 = root.path().join("a");
        std::fs::create_dir_all(&r1).unwrap();
        std::fs::write(r1.join(".cursorrules"), "x").unwrap();
        let r2 = root.path().join("b");
        std::fs::create_dir_all(r2.join(".cursor").join("rules")).unwrap();
        let r3 = root.path().join("c");
        std::fs::create_dir_all(r3.join(".cursor")).unwrap();
        std::fs::write(r3.join(".cursor").join("hooks.json"), "{}").unwrap();
        let roots = vec![root.path().to_string_lossy().to_string()];
        let found = discover_cursor_repos(&roots);
        assert!(found.contains(&dunce::canonicalize(&r1).unwrap()));
        assert!(found.contains(&dunce::canonicalize(&r2).unwrap()));
        assert!(found.contains(&dunce::canonicalize(&r3).unwrap()));
    }

    #[test]
    fn discover_grok_repos_finds_hooks_dir_or_config_toml_only() {
        let root = tempdir().unwrap();
        let hooks = root.path().join("hooks");
        std::fs::create_dir_all(hooks.join(".grok").join("hooks")).unwrap();
        let config = root.path().join("config");
        std::fs::create_dir_all(config.join(".grok")).unwrap();
        std::fs::write(config.join(".grok").join("config.toml"), "").unwrap();
        let bare = root.path().join("bare");
        std::fs::create_dir_all(bare.join(".grok")).unwrap();
        let roots = vec![root.path().to_string_lossy().to_string()];
        let found = discover_grok_repos(&roots);
        assert_eq!(
            found,
            vec![
                dunce::canonicalize(&config).unwrap(),
                dunce::canonicalize(&hooks).unwrap()
            ]
        );
    }

    #[test]
    fn discover_skips_when_marker_is_dir_not_file() {
        let dir = tempdir().unwrap();
        let repo = dir.path().join("badRepo");
        // Create `.continue/config.json` as a DIRECTORY, not a file
        std::fs::create_dir_all(repo.join(".continue").join("config.json")).unwrap();
        let out = discover_per_repo(&[dir.path().to_string_lossy().into()], CONTINUE_MARKER);
        assert!(out.is_empty(), "marker must be a file, not a dir");
    }
}
