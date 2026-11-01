//! Host-side dead-letter / audit spool writer.
//!
//! Spec §3.8.3 — best-effort, at-least-once. Caller writes BEFORE the
//! offset advance fsync. Failure to write here logs once and proceeds
//! (the host audit is a debugging aid, not source-of-truth).

use lodeline_core::event::Event;
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;
use time::OffsetDateTime;

#[derive(Debug, Error)]
pub enum DeadLetterError {
    #[error("io {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("serialize: {0}")]
    Serialize(serde_json::Error),
}

/// Most dead-letter files kept. There is one file a day.
pub const MAX_FILES: usize = 30;

/// Append one event line to today's `sender-dead-letter-YYYY-MM-DD.jsonl`
/// in `dir`. Creates the file if missing, and then prunes old files; one fsync per line.
pub fn append(dir: &Path, event: &Event) -> Result<(), DeadLetterError> {
    std::fs::create_dir_all(dir).map_err(|source| DeadLetterError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    let now = OffsetDateTime::now_utc();
    let basename = format!(
        "sender-dead-letter-{:04}-{:02}-{:02}.jsonl",
        now.year(),
        u8::from(now.month()),
        now.day()
    );
    let path = dir.join(basename);
    let mut bytes = serde_json::to_vec(event).map_err(DeadLetterError::Serialize)?;
    bytes.push(b'\n');
    let new_file = !path.exists();
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|source| DeadLetterError::Io {
            path: path.clone(),
            source,
        })?;
    f.write_all(&bytes).map_err(|source| DeadLetterError::Io {
        path: path.clone(),
        source,
    })?;
    f.sync_all().map_err(|source| DeadLetterError::Io {
        path: path.clone(),
        source,
    })?;
    // The count only grows when a file is created, so one scan per file is enough.
    if new_file {
        prune(dir, &path);
    }
    Ok(())
}

/// Removes the oldest dead-letter files past [`MAX_FILES`], counting `keep`. Names carry
/// the date, so name order is age order, unless the clock was set back. Then files
/// dated in the future sort last, and `keep`, the file just written, is never one that
/// goes. A failure is ignored: this directory is a debugging aid.
fn prune(dir: &Path, keep: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p != keep
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("sender-dead-letter-") && n.ends_with(".jsonl"))
        })
        .collect();
    files.sort();
    let mut removed = 0;
    for old in &files[..files.len().saturating_sub(MAX_FILES - 1)] {
        removed += usize::from(std::fs::remove_file(old).is_ok());
    }
    if removed > 0 {
        tracing::info!(removed, "pruned old dead-letter files");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lodeline_core::event::{
        Evidence, Severity, SourceKind, Subject, AGENT_VERSION, SCHEMA_VERSION,
    };
    use tempfile::tempdir;

    fn sample_event() -> Event {
        Event {
            schema_version: SCHEMA_VERSION,
            event_id: uuid::Uuid::nil(),
            ts: OffsetDateTime::now_utc(),
            host_id: "h".into(),
            agent_version: AGENT_VERSION.to_string(),
            severity: Severity::Warn,
            source: SourceKind::Agent,
            subject: Subject::Self_,
            evidence: Evidence::EventUnprocessableLocal {
                original_event_id: uuid::Uuid::nil(),
                server_reason: "schema_mismatch".into(),
            },
            target_id: None,
        }
    }

    #[test]
    fn append_creates_file_with_one_jsonl_line() {
        let dir = tempdir().unwrap();
        append(dir.path(), &sample_event()).unwrap();
        // Find the file (filename has date suffix).
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("sender-dead-letter-")
            })
            .collect();
        assert_eq!(entries.len(), 1);
        let body = std::fs::read_to_string(entries[0].path()).unwrap();
        assert!(body.ends_with('\n'));
        assert_eq!(body.matches('\n').count(), 1);
    }

    #[test]
    fn the_oldest_files_go_when_there_are_too_many() {
        let dir = tempdir().unwrap();
        for day in 1..=MAX_FILES + 5 {
            let name = format!("sender-dead-letter-2020-01-{day:02}.jsonl");
            std::fs::write(dir.path().join(name), b"{}\n").unwrap();
        }
        std::fs::write(dir.path().join("notes.txt"), b"keep").unwrap();
        append(dir.path(), &sample_event()).unwrap();
        let mut names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("sender-dead-letter-"))
            .collect();
        names.sort();
        assert_eq!(names.len(), MAX_FILES);
        assert!(names.last().unwrap() > &"sender-dead-letter-2021".to_owned());
        assert!(!names.contains(&"sender-dead-letter-2020-01-01.jsonl".to_owned()));
        assert!(dir.path().join("notes.txt").exists());
    }

    #[test]
    fn files_are_scanned_when_a_file_is_created_and_not_on_every_append() {
        let dir = tempdir().unwrap();
        append(dir.path(), &sample_event()).unwrap();
        for day in 1..=MAX_FILES {
            let name = format!("sender-dead-letter-2020-01-{day:02}.jsonl");
            std::fs::write(dir.path().join(name), b"{}\n").unwrap();
        }
        append(dir.path(), &sample_event()).unwrap();
        let count = || std::fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(count(), MAX_FILES + 1, "today's file already existed");
    }

    #[test]
    fn the_file_just_written_survives_when_the_clock_was_set_back() {
        let dir = tempdir().unwrap();
        for day in 1..=MAX_FILES {
            let name = format!("sender-dead-letter-2099-01-{day:02}.jsonl");
            std::fs::write(dir.path().join(name), b"{}\n").unwrap();
        }
        append(dir.path(), &sample_event()).unwrap();
        let today: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| !p.to_string_lossy().contains("2099"))
            .collect();
        assert_eq!(today.len(), 1, "today's file was pruned");
        assert_eq!(
            std::fs::read_to_string(&today[0]).unwrap().lines().count(),
            1
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), MAX_FILES);
    }

    #[test]
    fn two_appends_produce_two_lines() {
        let dir = tempdir().unwrap();
        append(dir.path(), &sample_event()).unwrap();
        append(dir.path(), &sample_event()).unwrap();
        let entry = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .find(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("sender-dead-letter-")
            })
            .unwrap();
        let body = std::fs::read_to_string(entry.path()).unwrap();
        assert_eq!(body.matches('\n').count(), 2);
    }
}
