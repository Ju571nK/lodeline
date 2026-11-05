//! #199: where Claude Code reads a project's local settings file.
//!
//! Since v2.1.211 Claude Code keeps `.claude/settings.local.json` (the file
//! "Yes, and don't ask again" writes its allow rules to) at the git
//! repository root, and in a linked worktree at the main checkout's root, not
//! in the directory a session starts in. It still reads a copy an older
//! version left in the start directory.

use std::path::{Path, PathBuf};

/// The directory whose `.claude/settings.local.json` Claude Code reads for a
/// session started at `start`, when that is not `start` itself.
///
/// `None` keeps the start directory's file, which is what Claude Code does
/// outside a git repository, on Windows, and when the root, its `.git` or its
/// `.claude` is owned by a different user. The other documented exception, a
/// root that is the user's home directory, needs the home and is left to the
/// caller.
pub(crate) fn local_settings_root(start: &Path) -> Option<PathBuf> {
    if cfg!(windows) {
        return None;
    }
    let (top, dot_git) = start.ancestors().find_map(|dir| {
        let dot_git = dir.join(".git");
        dot_git.symlink_metadata().ok().map(|_| (dir, dot_git))
    })?;
    let root = if dot_git.is_dir() {
        top.to_path_buf()
    } else {
        main_checkout_root(top, &dot_git)?
    };
    (root != start && same_owner(start, &root)).then_some(root)
}

/// The checkout a `.git` file belongs to: the main checkout for a linked
/// worktree, `top` itself for a submodule, whose git dir has no `commondir`.
fn main_checkout_root(top: &Path, dot_git: &Path) -> Option<PathBuf> {
    let text = std::fs::read_to_string(dot_git).ok()?;
    let git_dir = top.join(text.trim().strip_prefix("gitdir:")?.trim());
    let Ok(common) = std::fs::read_to_string(git_dir.join("commondir")) else {
        return Some(top.to_path_buf());
    };
    let common = dunce::canonicalize(git_dir.join(common.trim())).ok()?;
    // shortcut: a worktree of a bare repository has no main checkout, so its
    // own file is kept; read the bare layout's rule if one turns up.
    if common.file_name()? != ".git" {
        return None;
    }
    common.parent().map(Path::to_path_buf)
}

#[cfg(unix)]
fn same_owner(start: &Path, root: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    // The owner of the start directory stands in for the user running Claude
    // Code: the agent may run as another account.
    let Ok(owner) = start.metadata().map(|m| m.uid()) else {
        return false;
    };
    [root.to_path_buf(), root.join(".git"), root.join(".claude")]
        .iter()
        .all(|p| p.symlink_metadata().map_or(true, |m| m.uid() == owner))
}

#[cfg(not(unix))]
fn same_owner(_start: &Path, _root: &Path) -> bool {
    true
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn canon(p: &Path) -> PathBuf {
        dunce::canonicalize(p).unwrap()
    }

    #[test]
    fn repo_root_keeps_its_own_file() {
        let dir = tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        assert_eq!(local_settings_root(&canon(dir.path())), None);
    }

    #[test]
    fn outside_a_repository_keeps_the_start_file() {
        let dir = tempdir().unwrap();
        assert_eq!(local_settings_root(&canon(dir.path())), None);
    }

    #[test]
    fn subdirectory_reads_the_repository_root_file() {
        let dir = tempdir().unwrap();
        let root = canon(dir.path());
        std::fs::create_dir(root.join(".git")).unwrap();
        let sub = root.join("packages/web");
        std::fs::create_dir_all(&sub).unwrap();
        assert_eq!(local_settings_root(&sub), Some(root));
    }

    /// The layout `git worktree add` writes: a `.git` file naming the
    /// worktree's git dir, whose `commondir` points back at the main `.git`.
    #[test]
    fn linked_worktree_reads_the_main_checkout_file() {
        let dir = tempdir().unwrap();
        let main = canon(dir.path()).join("main");
        let git_dir = main.join(".git/worktrees/wt");
        std::fs::create_dir_all(&git_dir).unwrap();
        std::fs::write(git_dir.join("commondir"), "../..\n").unwrap();
        let wt = canon(dir.path()).join("wt");
        std::fs::create_dir_all(&wt).unwrap();
        std::fs::write(wt.join(".git"), format!("gitdir: {}\n", git_dir.display())).unwrap();
        assert_eq!(local_settings_root(&wt), Some(main.clone()));
        let sub = wt.join("src");
        std::fs::create_dir(&sub).unwrap();
        assert_eq!(local_settings_root(&sub), Some(main));
    }

    #[test]
    fn submodule_is_its_own_repository() {
        let dir = tempdir().unwrap();
        let outer = canon(dir.path());
        std::fs::create_dir_all(outer.join(".git/modules/lib")).unwrap();
        let sub = outer.join("lib");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join(".git"), "gitdir: ../.git/modules/lib\n").unwrap();
        assert_eq!(local_settings_root(&sub), None);
    }
}
