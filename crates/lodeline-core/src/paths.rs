//! Default on-disk locations shared by binaries that do not link each other.

use std::path::PathBuf;

/// Where `lodeline-sender` reads its config when `--config` is not given.
pub fn default_sender_config() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/etc/lodeline/sender.yaml")
    }
    #[cfg(windows)]
    {
        PathBuf::from(r"C:\ProgramData\Lodeline\sender.yaml")
    }
}

/// Where `lodeline-sender` keeps its read offset when `offset_path` is omitted.
pub fn default_sender_offset() -> PathBuf {
    PathBuf::from("/var/lib/lodeline-sender/sender-offset.json")
}

/// The user's home directory, cross-platform: `HOME` (Unix) or `USERPROFILE`
/// (Windows, where `HOME` is usually unset).
pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var_os("USERPROFILE").filter(|s| !s.is_empty()))
        .map(PathBuf::from)
}

/// Where `lodeline-hook install` records its registrations:
/// `$XDG_STATE_HOME/lodeline` or `<home>/.local/state/lodeline`.
pub fn hook_state_dir() -> PathBuf {
    if let Ok(base) = std::env::var("XDG_STATE_HOME") {
        PathBuf::from(base).join("lodeline")
    } else {
        home_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join(".local/state/lodeline")
    }
}
