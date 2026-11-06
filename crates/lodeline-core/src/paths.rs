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

/// Whitespace a shell splits a command on. Not Unicode whitespace: a path with
/// U+3000 or U+00A0 is one token to a shell and must stay unquoted.
pub const SHELL_WS: [char; 4] = [' ', '\t', '\r', '\n'];

/// The binary path at the start of a hook command: a leading double-quoted
/// string with its quotes, else the first whitespace token.
pub fn command_exe(cmd: &str) -> &str {
    let cmd = cmd.trim_start_matches(SHELL_WS);
    match cmd.strip_prefix('"').and_then(|rest| rest.find('"')) {
        Some(end) => &cmd[..end + 2],
        None => cmd.split(SHELL_WS).next().unwrap_or(""),
    }
}

/// The last path component is `lodeline-hook`. Windows file names ignore case.
pub fn is_hook_binary(path: &str) -> bool {
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    ["lodeline-hook", "lodeline-hook.exe"]
        .iter()
        .any(|n| name.eq_ignore_ascii_case(n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_exe_reads_quoted_bare_and_unterminated() {
        assert_eq!(
            command_exe(r#""C:/Program Files/x.exe" claude-code --capture redacted"#),
            r#""C:/Program Files/x.exe""#
        );
        assert_eq!(
            command_exe("\t/usr/bin/lodeline-hook claude-code --capture redacted"),
            "/usr/bin/lodeline-hook"
        );
        let wide = "C:/Users/alice/新しい\u{3000}フォルダー/lodeline-hook.exe";
        assert_eq!(command_exe(&format!("{wide} codex")), wide);
        assert_eq!(
            command_exe(r#""C:/Program Files/lodeline-hook.exe codex --capture redacted"#),
            r#""C:/Program"#
        );
    }

    #[test]
    fn is_hook_binary_needs_our_file_name() {
        assert!(is_hook_binary("/usr/bin/lodeline-hook"));
        assert!(is_hook_binary(r"C:\Lodeline\Lodeline-Hook.EXE"));
        assert!(!is_hook_binary("/usr/bin/lodeline-hook.bak"));
        assert!(!is_hook_binary("C:/x/lodeline-hook.cmd"));
        assert!(!is_hook_binary("/tmp/steer.sh"));
    }
}
