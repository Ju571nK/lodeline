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
/// in `dir`. Creates the file if missing; one fsync per line.
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
    prune(dir);
    Ok(())
}

/// Removes the oldest dead-letter files past [`MAX_FILES`]. Names carry the date, so
/// name order is age order. A failure is ignored: this directory is a debugging aid.
fn prune(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("sender-dead-letter-") && n.ends_with(".jsonl"))
        })
        .collect();
    files.sort();
    for old in &files[..files.len().saturating_sub(MAX_FILES)] {
        let _ = std::fs::remove_file(old);
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
