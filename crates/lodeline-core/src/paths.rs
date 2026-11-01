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
