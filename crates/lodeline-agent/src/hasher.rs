//! Hasher pool task. Performs blake3 hashing on `spawn_blocking` workers.

use crate::normalizer::NormalizedEvent;
use lodeline_core::debounce::PendingEvent;
use lodeline_core::event::{EvidenceQuality, FileChangeKind};
use lodeline_core::hashing::{hash_path, HashOutcome};
use lodeline_core::stats::Stats;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct HashedEvent {
    pub norm: NormalizedEvent,
    pub after_hash: Option<String>,
    pub size_after: Option<u64>,
    pub recheck_hash: Option<String>,
    pub quality: EvidenceQuality,
    pub debounced_from: Option<PendingEvent>, // present when sourced via debouncer
}

pub async fn run(
    mut rx: mpsc::Receiver<PendingEvent>,
    tx: mpsc::Sender<HashedEvent>,
    target_lookup: Arc<dyn TargetLookup + Send + Sync>,
    stats: Arc<Stats>,
    ai_guard_tx: Option<tokio::sync::broadcast::Sender<std::path::PathBuf>>,
) {
    while let Some(first) = rx.recv().await {
        let mut batch = vec![first];
        while let Ok(next) = rx.try_recv() {
            batch.push(next);
        }
        for pending in coalesce_adjacent(batch) {
            let path = pending.path.clone();
            let started = Instant::now();
            let outcome = tokio::task::spawn_blocking(move || hash_path(&path)).await;
            let elapsed_us = started.elapsed().as_micros() as u64;
            stats.record_hash_us(elapsed_us);

            let mut norm = match target_lookup.find_for_path(&pending.path, pending.kind) {
                Some(n) => n,
                None => continue,
            };
            // The lookup re-derives target/tier from the path; the rename pairing
            // (done once in the normalizer) rides downstream on the PendingEvent.
            norm.rename_from = pending.rename_from.clone();

            let (after_hash, size_after, mut quality) = match outcome {
                Ok(Ok(HashOutcome::Hashed { hex, size })) => {
                    (Some(hex), Some(size), pending.evidence_quality())
                }
                Ok(Ok(HashOutcome::TooLarge { size })) => {
                    (None, Some(size), EvidenceQuality::Incomplete)
                }
                Ok(Ok(HashOutcome::NotFound)) => (None, None, EvidenceQuality::Incomplete),
                _ => (None, None, EvidenceQuality::Incomplete),
            };

            if started.elapsed() > Duration::from_millis(1000)
                && quality == EvidenceQuality::Definitive
            {
                quality = EvidenceQuality::Delayed;
            }

            let recheck_hash = if pending.critical && pending.kind != FileChangeKind::Removed {
                // Schedule a 100ms recheck inline.
                tokio::time::sleep(Duration::from_millis(100)).await;
                let p = pending.path.clone();
                match tokio::task::spawn_blocking(move || hash_path(&p)).await {
                    Ok(Ok(HashOutcome::Hashed { hex, .. })) => Some(hex),
                    _ => None,
                }
            } else {
                None
            };

            let ag_path = ai_guard_tx.as_ref().map(|_| pending.path.clone());
            let _ = tx
                .send(HashedEvent {
                    norm,
                    after_hash,
                    size_after,
                    recheck_hash,
                    quality,
                    debounced_from: Some(pending),
                })
                .await;
            if let (Some(ag_tx), Some(p)) = (&ai_guard_tx, ag_path) {
                // Broadcast best-effort; lagged receivers will catch up via heartbeat.
                let _ = ag_tx.send(p);
            }
        }
    }
}

/// Merges runs of already-queued events for one path and kind into the last of
/// the run. Hashing reads the file as it is now, so each event of a run would
/// read the same bytes; one hash and one recheck cover them all.
fn coalesce_adjacent(batch: Vec<PendingEvent>) -> Vec<PendingEvent> {
    let mut out: Vec<PendingEvent> = Vec::with_capacity(batch.len());
    for next in batch {
        match out.last_mut() {
            Some(last)
                if last.path == next.path
                    && last.kind == next.kind
                    && last.critical == next.critical =>
            {
                last.last_seen_ms = next.last_seen_ms;
                last.coalesced_count = last.coalesced_count.saturating_add(next.coalesced_count);
                if next.rename_from.is_some() {
                    last.rename_from = next.rename_from;
                }
            }
            _ => out.push(next),
        }
    }
    out
}

/// Recovers a `PendingEvent`'s target/tier metadata from its (canonical) path.
/// The runtime implements this by re-matching against the same compiled globs
/// the normalizer uses (see `GlobTargetLookup`). The rename pairing is *not*
/// reconstructed here — it travels separately on `PendingEvent::rename_from`.
pub trait TargetLookup {
    fn find_for_path(
        &self,
        path: &std::path::Path,
        kind: FileChangeKind,
    ) -> Option<NormalizedEvent>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::normalizer::NormalizedEvent;
    use lodeline_core::policy::Tier;
    use std::path::{Path, PathBuf};

    struct AllCritical;

    impl TargetLookup for AllCritical {
        fn find_for_path(&self, path: &Path, kind: FileChangeKind) -> Option<NormalizedEvent> {
            Some(NormalizedEvent {
                path: path.to_path_buf(),
                kind,
                rename_from: None,
                target_id: "t".into(),
                tier: Tier::Critical,
            })
        }
    }

    fn pending(path: &Path, kind: FileChangeKind, ms: u64) -> PendingEvent {
        PendingEvent {
            path: path.to_path_buf(),
            kind,
            first_seen_ms: ms,
            last_seen_ms: ms,
            coalesced_count: 1,
            critical: true,
            rename_from: None,
        }
    }

    async fn run_to_end(events: Vec<PendingEvent>) -> (Vec<HashedEvent>, Duration) {
        let (tx_pending, rx_pending) = mpsc::channel(events.len().max(1));
        let (tx_hashed, mut rx_hashed) = mpsc::channel(events.len().max(1));
        for event in events {
            tx_pending.send(event).await.unwrap();
        }
        drop(tx_pending);
        let started = tokio::time::Instant::now();
        run(
            rx_pending,
            tx_hashed,
            Arc::new(AllCritical),
            Arc::new(Stats::default()),
            None,
        )
        .await;
        let elapsed = started.elapsed();
        let mut out = Vec::new();
        while let Ok(event) = rx_hashed.try_recv() {
            out.push(event);
        }
        (out, elapsed)
    }

    #[tokio::test(start_paused = true)]
    async fn queued_burst_for_one_path_drains_within_the_shutdown_limit() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("settings.json");
        std::fs::write(&file, b"last content").unwrap();
        let burst: Vec<_> = (0..330)
            .map(|i| pending(&file, FileChangeKind::Modified, i))
            .collect();

        let (out, elapsed) = run_to_end(burst).await;

        assert!(elapsed < Duration::from_secs(5), "drain took {elapsed:?}");
        let last = out.last().expect("the burst is recorded");
        let expected = hash_path(&file).unwrap();
        let HashOutcome::Hashed { hex, .. } = expected else {
            panic!("hash failed")
        };
        assert_eq!(last.after_hash.as_deref(), Some(hex.as_str()));
        assert_eq!(last.recheck_hash.as_deref(), Some(hex.as_str()));
    }

    #[tokio::test(start_paused = true)]
    async fn events_for_different_paths_and_kinds_are_not_merged() {
        let dir = tempfile::tempdir().unwrap();
        let a: PathBuf = dir.path().join("a.json");
        let b: PathBuf = dir.path().join("b.json");
        std::fs::write(&a, b"a").unwrap();
        std::fs::write(&b, b"b").unwrap();
        let events = vec![
            pending(&a, FileChangeKind::Modified, 0),
            pending(&b, FileChangeKind::Modified, 1),
            pending(&a, FileChangeKind::Modified, 2),
            pending(&a, FileChangeKind::Created, 3),
        ];

        let (out, _) = run_to_end(events).await;

        let seen: Vec<_> = out
            .iter()
            .map(|e| (e.norm.path.clone(), e.norm.kind))
            .collect();
        assert_eq!(
            seen,
            vec![
                (a.clone(), FileChangeKind::Modified),
                (b, FileChangeKind::Modified),
                (a.clone(), FileChangeKind::Modified),
                (a, FileChangeKind::Created),
            ]
        );
    }
}
