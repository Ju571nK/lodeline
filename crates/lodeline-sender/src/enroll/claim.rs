//! Give the host its host_id through the agent: `lodeline [--state-db P] init-host-id <id>`.
//!
//! The agent owns the `state.db` default and its schema, so enroll runs the agent
//! binary instead of opening the database itself.

use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, PartialEq, Eq)]
pub enum Claim {
    /// The host has this host_id now (or already had it).
    Done,
    /// The host already has another host_id (exit 3).
    Conflict,
    /// The agent does not know `init-host-id` (clap exit 2).
    OldAgent,
    Failed(String),
}

fn agent_name() -> String {
    format!("lodeline{}", std::env::consts::EXE_SUFFIX)
}

/// The agent binary: next to this one, then `/usr/bin/lodeline`. A non-root run also
/// looks on `PATH`; root never does, because a `PATH` entry can be user-writable.
pub fn locate_agent(root: bool) -> Result<PathBuf, String> {
    let name = agent_name();
    let sibling = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.join(&name)));
    let mut candidates: Vec<PathBuf> = sibling.into_iter().collect();
    if root {
        candidates.push(PathBuf::from("/usr/bin/lodeline"));
    } else if let Some(p) = std::env::var_os("PATH") {
        candidates.extend(std::env::split_paths(&p).map(|d| d.join(&name)));
    }
    candidates.into_iter().find(|c| c.is_file()).ok_or_else(|| {
        "install the Lodeline agent first; enroll stores the host_id the agent will use".into()
    })
}

/// Run `init-host-id`, with the agent's output going straight to this terminal.
pub fn init_host_id(agent: &Path, state_db: Option<&Path>, host_id: &str) -> Claim {
    let mut cmd = Command::new(agent);
    if let Some(db) = state_db {
        cmd.arg("--state-db").arg(db);
    }
    match cmd.arg("init-host-id").arg(host_id).status() {
        Err(e) => Claim::Failed(format!("cannot run {}: {e}", agent.display())),
        Ok(s) => match s.code() {
            Some(0) => Claim::Done,
            Some(3) => Claim::Conflict,
            Some(2) => Claim::OldAgent,
            _ => Claim::Failed("see the message above".into()),
        },
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn fake(dir: &Path, code: i32) -> PathBuf {
        let p = dir.join("lodeline");
        std::fs::write(
            &p,
            format!(
                "#!/bin/sh\necho \"$@\" > '{}/args'\nexit {code}\n",
                dir.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[test]
    fn exit_codes_map_and_the_state_db_is_forwarded() {
        let d = tempfile::tempdir().unwrap();
        for (code, want) in [
            (0, Claim::Done),
            (3, Claim::Conflict),
            (2, Claim::OldAgent),
            (1, Claim::Failed("see the message above".into())),
            (7, Claim::Failed("see the message above".into())),
        ] {
            let agent = fake(d.path(), code);
            let got = init_host_id(&agent, Some(Path::new("/s/state.db")), "ID");
            assert_eq!(got, want, "exit {code}");
            let args = std::fs::read_to_string(d.path().join("args")).unwrap();
            assert_eq!(args.trim(), "--state-db /s/state.db init-host-id ID");
        }
        let agent = fake(d.path(), 0);
        init_host_id(&agent, None, "ID");
        let args = std::fs::read_to_string(d.path().join("args")).unwrap();
        assert_eq!(args.trim(), "init-host-id ID");
    }

    #[test]
    fn a_missing_binary_is_a_failure() {
        let r = init_host_id(Path::new("/nonexistent/lodeline"), None, "ID");
        assert!(matches!(r, Claim::Failed(m) if m.contains("cannot run")));
    }
}
