//! Crash-safe writer for one signed artifact file and its recorded version.
//!
//! Spec §4.4. A file and a state.db row cannot change together, so state.db records
//! the apply before the file moves. A stop at any step leaves a state that the next
//! boot resolves from what is on disk, with [`settle_pending`].

use super::deployment::ArtifactKind;
use crate::host_meta::PendingEnvelope;
use crate::state::{HashCache, StateError};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;
use time::OffsetDateTime;

/// Errors produced by the atomic writer.
#[derive(Debug, Error)]
pub enum AtomicWriteError {
    /// I/O failure during write/rename/fsync.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// state.db refused or failed the apply before the file moved, so the file
    /// and the applied version are unchanged. A lower version lands here.
    #[error("state.db update failed before disk write: {0}")]
    StateBeforeDisk(StateError),
    /// The file may be ahead of the applied version, and the next boot settles it.
    #[error("state.db update failed AFTER disk write: {0}")]
    StateAfterDisk(StateError),
}

/// Atomically write `bytes` to `target` and advance the applied version of `kind`
/// to `version`. Steps:
///   1. Record the version, the blake3 of `bytes`, and `valid_until` as pending.
///   2. Write `bytes` to a temp file, fsync it, rename it over `target`, fsync the
///      parent directory.
///   3. Promote pending to applied.
pub fn atomic_write(
    kind: ArtifactKind,
    target: &Path,
    bytes: &[u8],
    cache: &HashCache,
    version: i64,
    valid_until: OffsetDateTime,
) -> Result<(), AtomicWriteError> {
    let pending = PendingEnvelope {
        version,
        hash_hex: blake3::hash(bytes).to_hex().to_string(),
        valid_until,
    };
    cache
        .record_pending(kind, &pending)
        .map_err(AtomicWriteError::StateBeforeDisk)?;
    write_file_durably(target, bytes)?;
    cache
        .promote_pending(kind)
        .map_err(AtomicWriteError::StateAfterDisk)
}

/// Resolve an apply that stopped partway. Run it at boot, before any new apply.
/// `target` holding the pending bytes means the rename happened, so the apply is
/// finished, and its version is returned. Otherwise the rename never happened, or an
/// older agent has since gone past this version, and the pending record is dropped.
/// Safe to run again after a stop at any point.
pub fn settle_pending(
    kind: ArtifactKind,
    target: &Path,
    cache: &HashCache,
) -> Result<Option<i64>, AtomicWriteError> {
    let Some(pending) = cache
        .pending(kind)
        .map_err(AtomicWriteError::StateAfterDisk)?
    else {
        return Ok(None);
    };
    let on_disk = match std::fs::read(target) {
        Ok(bytes) => Some(blake3::hash(&bytes).to_hex().to_string()),
        Err(e) if e.kind() == ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    if on_disk.as_deref() == Some(pending.hash_hex.as_str()) {
        match cache.promote_pending(kind) {
            Ok(()) => return Ok(Some(pending.version)),
            Err(StateError::WouldLowerVersion { .. }) => {}
            Err(e) => return Err(AtomicWriteError::StateAfterDisk(e)),
        }
    }
    cache
        .clear_pending(kind)
        .map_err(AtomicWriteError::StateAfterDisk)?;
    Ok(None)
}

/// Crash-safe file write: write `bytes` to a pid-scoped temp file, fsync it, rename
/// it over `target`, then fsync the parent directory (POSIX only). Does NOT touch
/// state.db.
fn write_file_durably(target: &Path, bytes: &[u8]) -> Result<(), AtomicWriteError> {
    let parent = target
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&parent)?;

    let pid = std::process::id();
    let tmp = parent.join(format!(
        ".{}.{}.tmp",
        target
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("policy.yaml"),
        pid
    ));

    // 1. Write + fsync the file.
    {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }

    // 2. Rename atomically.
    std::fs::rename(&tmp, target)?;

    // 3. fsync parent directory (POSIX only — no-op on Windows where
    //    rename's durability semantics differ).
    #[cfg(unix)]
    {
        let dir = std::fs::OpenOptions::new().read(true).open(&parent)?;
        dir.sync_all()?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use time::macros::datetime;
    use ArtifactKind::{Policy, RulePacks};

    const UNTIL: OffsetDateTime = datetime!(2030-01-01 0:00 UTC);

    fn fresh_cache(dir: &tempfile::TempDir) -> HashCache {
        HashCache::open(&dir.path().join("state.db")).unwrap()
    }

    fn write(
        kind: ArtifactKind,
        target: &Path,
        bytes: &[u8],
        cache: &HashCache,
        version: i64,
    ) -> Result<(), AtomicWriteError> {
        atomic_write(kind, target, bytes, cache, version, UNTIL)
    }

    fn applied(cache: &HashCache, kind: ArtifactKind) -> i64 {
        let meta = cache.host_meta_get().unwrap();
        match kind {
            Policy => meta.policy.version(),
            RulePacks => meta.rule_packs.version(),
        }
    }

    fn record_pending(cache: &HashCache, kind: ArtifactKind, bytes: &[u8], version: i64) {
        let pending = PendingEnvelope {
            version,
            hash_hex: blake3::hash(bytes).to_hex().to_string(),
            valid_until: UNTIL,
        };
        cache.record_pending(kind, &pending).unwrap();
    }

    #[test]
    fn writes_policy_and_advances_version() {
        let dir = tempdir().unwrap();
        let cache = fresh_cache(&dir);
        let target = dir.path().join("policy.yaml");
        write(Policy, &target, b"version: 5\nrules: []\n", &cache, 5).unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"version: 5\nrules: []\n");
        assert_eq!(applied(&cache, Policy), 5);
        assert_eq!(
            cache.host_meta_get().unwrap().policy.valid_until(),
            Some(UNTIL)
        );
    }

    #[test]
    fn writes_rule_packs_and_advances_rule_packs_version() {
        let dir = tempdir().unwrap();
        let cache = fresh_cache(&dir);
        let target = dir.path().join("rule_packs.yaml");
        write(
            RulePacks,
            &target,
            b"version: 1\nrule_packs: []\n",
            &cache,
            3,
        )
        .unwrap();

        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"version: 1\nrule_packs: []\n"
        );
        assert_eq!(applied(&cache, RulePacks), 3);
        // The policy watermark is untouched by a rule-packs write.
        assert_eq!(applied(&cache, Policy), 0);
    }

    #[test]
    fn second_write_overwrites_atomically() {
        let dir = tempdir().unwrap();
        let cache = fresh_cache(&dir);
        let target = dir.path().join("policy.yaml");
        write(Policy, &target, b"version: 1\n", &cache, 1).unwrap();
        write(Policy, &target, b"version: 2\n", &cache, 2).unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"version: 2\n");
        assert_eq!(applied(&cache, Policy), 2);
    }

    #[test]
    fn a_refused_version_leaves_the_file_and_the_record_alone() {
        let dir = tempdir().unwrap();
        let cache = fresh_cache(&dir);
        let target = dir.path().join("policy.yaml");
        write(Policy, &target, b"two\n", &cache, 2).unwrap();

        let refused = write(Policy, &target, b"one\n", &cache, 1);

        assert!(matches!(
            refused,
            Err(AtomicWriteError::StateBeforeDisk(
                StateError::WouldLowerVersion { requested: 1 }
            ))
        ));
        assert_eq!(std::fs::read(&target).unwrap(), b"two\n");
        assert_eq!(applied(&cache, Policy), 2);
    }

    #[test]
    fn settling_finishes_an_apply_whose_rename_happened_and_twice_changes_nothing() {
        for kind in [Policy, RulePacks] {
            let dir = tempdir().unwrap();
            let cache = fresh_cache(&dir);
            let target = dir.path().join("artifact.yaml");
            record_pending(&cache, kind, b"five\n", 5);
            std::fs::write(&target, b"five\n").unwrap();

            assert_eq!(settle_pending(kind, &target, &cache).unwrap(), Some(5));
            assert_eq!(settle_pending(kind, &target, &cache).unwrap(), None);

            assert_eq!(applied(&cache, kind), 5);
            assert_eq!(cache.pending(kind).unwrap(), None);
        }
    }

    #[test]
    fn settling_drops_an_apply_whose_rename_never_happened() {
        for kind in [Policy, RulePacks] {
            let dir = tempdir().unwrap();
            let cache = fresh_cache(&dir);
            let target = dir.path().join("artifact.yaml");
            write(kind, &target, b"two\n", &cache, 2).unwrap();
            record_pending(&cache, kind, b"five\n", 5);

            assert_eq!(settle_pending(kind, &target, &cache).unwrap(), None);

            assert_eq!(applied(&cache, kind), 2);
            assert_eq!(cache.pending(kind).unwrap(), None);
            assert_eq!(std::fs::read(&target).unwrap(), b"two\n");
        }
    }

    #[test]
    fn settling_drops_an_apply_when_the_file_does_not_exist() {
        let dir = tempdir().unwrap();
        let cache = fresh_cache(&dir);
        record_pending(&cache, Policy, b"one\n", 1);

        let settled = settle_pending(Policy, &dir.path().join("missing.yaml"), &cache);

        assert_eq!(settled.unwrap(), None);
        assert_eq!(applied(&cache, Policy), 0);
        assert_eq!(cache.pending(Policy).unwrap(), None);
    }

    #[test]
    fn settling_never_lowers_a_version_an_older_agent_went_past() {
        let dir = tempdir().unwrap();
        let cache = fresh_cache(&dir);
        let target = dir.path().join("policy.yaml");
        record_pending(&cache, Policy, b"same\n", 5);
        std::fs::write(&target, b"same\n").unwrap();
        cache
            .conn
            .execute("UPDATE host_meta SET last_applied_policy_version = 9", [])
            .unwrap();

        assert_eq!(settle_pending(Policy, &target, &cache).unwrap(), None);

        assert_eq!(applied(&cache, Policy), 9);
        assert_eq!(cache.pending(Policy).unwrap(), None);
    }

    #[test]
    fn settling_keeps_the_pending_record_when_the_file_cannot_be_read() {
        let dir = tempdir().unwrap();
        let cache = fresh_cache(&dir);
        record_pending(&cache, Policy, b"five\n", 5);

        // A directory is one error that is not "not found" on every platform.
        let settled = settle_pending(Policy, dir.path(), &cache);

        assert!(matches!(settled, Err(AtomicWriteError::Io(_))));
        assert!(cache.pending(Policy).unwrap().is_some());
    }

    #[test]
    fn temp_file_is_cleaned_after_rename() {
        let dir = tempdir().unwrap();
        let cache = fresh_cache(&dir);
        let target = dir.path().join("policy.yaml");
        write(Policy, &target, b"x", &cache, 1).unwrap();

        let leftover: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(
            leftover.is_empty(),
            "no .tmp files should remain after successful rename"
        );
    }

    #[test]
    fn creates_parent_directory_if_missing() {
        let dir = tempdir().unwrap();
        let cache = fresh_cache(&dir);
        let target = dir.path().join("nested/sub/policy.yaml");
        write(Policy, &target, b"version: 1\n", &cache, 1).unwrap();
        assert!(target.exists());
    }
}
