//! Sink task. Owns the `JsonlSink`; calls `commit_baseline` after each write.

use crate::state_task::{commit_baseline, CommittableEvent};
use lodeline_core::sink::EventSink;
use lodeline_core::state::HashCache;
use lodeline_core::stats::Stats;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

pub async fn run(
    mut sink: impl EventSink,
    mut rx: mpsc::Receiver<CommittableEvent>,
    cache: Arc<Mutex<HashCache>>,
    stats: Arc<Stats>,
) -> std::io::Result<()> {
    let mut fsync_tick = tokio::time::interval(Duration::from_secs(1));
    fsync_tick.tick().await;
    loop {
        tokio::select! {
            biased;
            maybe = rx.recv() => {
                let Some(committable) = maybe else { break; };
                if is_unchanged_write(&cache, &committable) {
                    continue;
                }
                sink.write(&committable.event).map_err(std::io::Error::other)?;
                stats.record_emit(evidence_kind_str(&committable.event.evidence));
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                commit_baseline(&cache, &committable, now_ms);
            }
            _ = fsync_tick.tick() => {
                sink.flush_durable().map_err(std::io::Error::other)?;
            }
        }
    }
    sink.shutdown().map_err(std::io::Error::other)
}

/// True when the write left the bytes at the baseline, so recording it adds nothing.
fn is_unchanged_write(cache: &Mutex<HashCache>, committable: &CommittableEvent) -> bool {
    use lodeline_core::event::{Evidence, EvidenceQuality, FileChangeKind};
    let Evidence::FileChange {
        change_kind,
        after_hash: Some(after),
        recheck_hash,
        evidence_quality,
        ..
    } = &committable.event.evidence
    else {
        return false;
    };
    *change_kind != FileChangeKind::Removed
        && *evidence_quality != EvidenceQuality::Incomplete
        && recheck_hash.as_ref().is_none_or(|r| r == after)
        && cache
            .lock()
            .get(&committable.path_for_db)
            .ok()
            .flatten()
            .as_ref()
            == Some(after)
}

fn evidence_kind_str(e: &lodeline_core::event::Evidence) -> &'static str {
    use lodeline_core::event::Evidence::*;
    match e {
        FileChange { .. } => "file_change",
        Heartbeat { .. } => "heartbeat",
        PermissionMissing { .. } => "permission_missing",
        ChannelStall { .. } => "channel_stall",
        WatcherDegraded { .. } => "watcher_degraded",
        AgentDying { .. } => "agent_dying",
        RateLimitExceeded { .. } => "rate_limit_exceeded",
        HostIdFingerprintDrift { .. } => "host_id_fingerprint_drift",
        PolicySignatureInvalid { .. } => "policy_signature_invalid",
        PolicyReloaded { .. } => "policy_reloaded",
        RulePackBundleApplied { .. } => "rule_pack_bundle_applied",
        PolicyExpiredActive { .. } => "policy_expired_active",
        AgentJsonlForceGc { .. } => "agent_jsonl_force_gc",
        SenderSkippedSegment { .. } => "sender_skipped_segment",
        HostIdConflict { .. } => "host_id_conflict",
        AgentTooOld { .. } => "agent_too_old",
        CertExpired { .. } => "cert_expired",
        TlsFailure { .. } => "tls_failure",
        EventUnprocessableLocal { .. } => "event_unprocessable_local",
        ServerProtocolViolation { .. } => "server_protocol_violation",
        SenderLagCritical { .. } => "sender_lag_critical",
        AiGuardRiskAssessed { .. } => "ai_guard_risk_assessed",
        AiGuardToggleDrift { .. } => "ai_guard_toggle_drift",
        AiGuardAssessFailed { .. } => "ai_guard_assess_failed",
        HostMetaSnapshot { .. } => "host_meta_snapshot",
        HookInvocation(_) => "hook_invocation",
        HookDecision(_) => "hook_decision",
        HookConfigDrift(_) => "hook_config_drift",
        PossibleHookActivitySilent(_) => "possible_hook_activity_silent",
        Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn final_durable_flush_failure_is_returned() {
        struct FailingFlush;
        impl EventSink for FailingFlush {
            fn write(
                &mut self,
                _: &lodeline_core::event::Event,
            ) -> Result<(), lodeline_core::sink::SinkError> {
                Ok(())
            }
            fn flush_durable(&mut self) -> Result<(), lodeline_core::sink::SinkError> {
                Err(std::io::Error::other("test fsync failure").into())
            }
            fn shutdown(&mut self) -> Result<(), lodeline_core::sink::SinkError> {
                self.flush_durable()
            }
        }
        let td = tempfile::tempdir().unwrap();
        let cache = Arc::new(Mutex::new(
            HashCache::open(&td.path().join("state.db")).unwrap(),
        ));
        let (tx, rx) = mpsc::channel(1);
        drop(tx);
        let error = run(FailingFlush, rx, cache, Arc::new(Stats::default()))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("test fsync failure"));
    }

    #[test]
    fn possible_hook_activity_silent_has_sink_label() {
        use lodeline_core::event::{
            AiTool, Confidence, Evidence, PossibleHookActivitySilentEvidence,
        };
        let ev = Evidence::PossibleHookActivitySilent(PossibleHookActivitySilentEvidence {
            agent: AiTool::Codex,
            uid: None,
            last_hook_seen_at: time::OffsetDateTime::UNIX_EPOCH,
            last_session_activity_at: None,
            window_secs: 0,
            probe_kind: "codex_sessions".into(),
            path_hash: None,
            probe_error: None,
            scan_truncated: false,
            confidence: Confidence::Low,
        });
        assert_eq!(evidence_kind_str(&ev), "possible_hook_activity_silent");
    }

    #[tokio::test]
    async fn one_file_change_is_counted_once() {
        use crate::hasher::HashedEvent;
        use crate::normalizer::NormalizedEvent;
        use lodeline_core::event::{EvidenceQuality, FileChangeKind};
        use lodeline_core::policy::Tier;

        struct NullSink;
        impl EventSink for NullSink {
            fn write(
                &mut self,
                _: &lodeline_core::event::Event,
            ) -> Result<(), lodeline_core::sink::SinkError> {
                Ok(())
            }
            fn flush_durable(&mut self) -> Result<(), lodeline_core::sink::SinkError> {
                Ok(())
            }
            fn shutdown(&mut self) -> Result<(), lodeline_core::sink::SinkError> {
                Ok(())
            }
        }
        let td = tempfile::tempdir().unwrap();
        let cache = Arc::new(Mutex::new(
            HashCache::open(&td.path().join("state.db")).unwrap(),
        ));
        let stats = Arc::new(Stats::default());
        let (tx_hashed, rx_hashed) = mpsc::channel(1);
        let (tx_sink, rx_sink) = mpsc::channel(1);
        let state = tokio::spawn(crate::state_task::run(
            rx_hashed,
            tx_sink,
            cache.clone(),
            "host".into(),
        ));
        let sink = tokio::spawn(run(NullSink, rx_sink, cache, stats.clone()));
        tx_hashed
            .send(HashedEvent {
                norm: NormalizedEvent {
                    path: td.path().join("watched.json"),
                    kind: FileChangeKind::Modified,
                    rename_from: None,
                    target_id: "t".into(),
                    tier: Tier::Standard,
                },
                after_hash: Some("h".into()),
                size_after: Some(1),
                recheck_hash: None,
                quality: EvidenceQuality::Definitive,
                debounced_from: None,
            })
            .await
            .unwrap();
        drop(tx_hashed);
        state.await.unwrap();
        sink.await.unwrap().unwrap();

        let snap = stats.snapshot();
        assert_eq!(snap.events_emitted_total, 1);
        assert_eq!(snap.events_by_kind["file_change"], 1);
    }

    struct NullSink;
    impl EventSink for NullSink {
        fn write(
            &mut self,
            _: &lodeline_core::event::Event,
        ) -> Result<(), lodeline_core::sink::SinkError> {
            Ok(())
        }
        fn flush_durable(&mut self) -> Result<(), lodeline_core::sink::SinkError> {
            Ok(())
        }
        fn shutdown(&mut self) -> Result<(), lodeline_core::sink::SinkError> {
            Ok(())
        }
    }

    fn hashed(
        path: &std::path::Path,
        kind: lodeline_core::event::FileChangeKind,
        after: Option<&str>,
    ) -> crate::hasher::HashedEvent {
        use crate::normalizer::NormalizedEvent;
        use lodeline_core::event::EvidenceQuality;
        crate::hasher::HashedEvent {
            norm: NormalizedEvent {
                path: path.to_path_buf(),
                kind,
                rename_from: None,
                target_id: "t".into(),
                tier: lodeline_core::policy::Tier::Standard,
            },
            after_hash: after.map(str::to_string),
            size_after: after.map(|_| 1),
            recheck_hash: None,
            quality: EvidenceQuality::Definitive,
            debounced_from: None,
        }
    }

    /// Runs `events` through the state and sink tasks over a baseline seeded
    /// with `seed`, and returns the emitted count and the cache.
    async fn emitted_after(
        seed: &[(&std::path::Path, &str)],
        events: Vec<crate::hasher::HashedEvent>,
    ) -> (u64, Arc<Mutex<HashCache>>) {
        let td = tempfile::tempdir().unwrap();
        let cache = Arc::new(Mutex::new(
            HashCache::open(&td.path().join("state.db")).unwrap(),
        ));
        for (path, hash) in seed {
            cache.lock().put(path, hash, 1, "t", 0).unwrap();
        }
        let stats = Arc::new(Stats::default());
        let (tx_hashed, rx_hashed) = mpsc::channel(1);
        let (tx_sink, rx_sink) = mpsc::channel(1);
        let state = tokio::spawn(crate::state_task::run(
            rx_hashed,
            tx_sink,
            cache.clone(),
            "host".into(),
        ));
        let sink = tokio::spawn(run(NullSink, rx_sink, cache.clone(), stats.clone()));
        for event in events {
            tx_hashed.send(event).await.unwrap();
        }
        drop(tx_hashed);
        state.await.unwrap();
        sink.await.unwrap().unwrap();
        (stats.snapshot().events_emitted_total, cache)
    }

    #[tokio::test]
    async fn a_write_that_leaves_the_baseline_unchanged_is_dropped() {
        use lodeline_core::event::FileChangeKind::Modified;
        let p = std::path::Path::new("/w/a.json");
        let (n, _) = emitted_after(&[(p, "h")], vec![hashed(p, Modified, Some("h"))]).await;
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn a_write_that_changes_the_bytes_is_recorded() {
        use lodeline_core::event::FileChangeKind::Modified;
        let p = std::path::Path::new("/w/a.json");
        let (n, cache) = emitted_after(&[(p, "h")], vec![hashed(p, Modified, Some("h2"))]).await;
        assert_eq!(n, 1);
        assert_eq!(cache.lock().get(p).unwrap().as_deref(), Some("h2"));
    }

    #[tokio::test]
    async fn recreating_a_removed_file_with_the_same_bytes_is_recorded() {
        use lodeline_core::event::FileChangeKind::{Created, Removed};
        let p = std::path::Path::new("/w/a.json");
        let (n, _) = emitted_after(
            &[(p, "h")],
            vec![hashed(p, Removed, None), hashed(p, Created, Some("h"))],
        )
        .await;
        assert_eq!(n, 2);
    }

    #[tokio::test]
    async fn an_event_without_an_after_hash_is_recorded() {
        use lodeline_core::event::FileChangeKind::Modified;
        let p = std::path::Path::new("/w/a.json");
        let (n, _) = emitted_after(&[(p, "h")], vec![hashed(p, Modified, None)]).await;
        assert_eq!(n, 1);
    }

    #[tokio::test]
    async fn an_incomplete_event_is_recorded() {
        use lodeline_core::event::EvidenceQuality::Incomplete;
        use lodeline_core::event::FileChangeKind::Modified;
        let p = std::path::Path::new("/w/a.json");
        let mut ev = hashed(p, Modified, Some("h"));
        ev.quality = Incomplete;
        let (n, _) = emitted_after(&[(p, "h")], vec![ev]).await;
        assert_eq!(n, 1);
    }

    #[tokio::test]
    async fn a_recheck_that_differs_is_recorded() {
        use lodeline_core::event::FileChangeKind::Modified;
        let p = std::path::Path::new("/w/a.json");
        let mut ev = hashed(p, Modified, Some("h"));
        ev.recheck_hash = Some("h2".into());
        let (n, _) = emitted_after(&[(p, "h")], vec![ev]).await;
        assert_eq!(n, 1);
    }

    #[tokio::test]
    async fn a_file_with_no_baseline_is_recorded() {
        use lodeline_core::event::FileChangeKind::Modified;
        let p = std::path::Path::new("/w/a.json");
        let (n, _) = emitted_after(&[], vec![hashed(p, Modified, Some("h"))]).await;
        assert_eq!(n, 1);
    }

    #[tokio::test]
    async fn a_file_that_vanished_is_recorded_when_it_comes_back_with_the_same_bytes() {
        use lodeline_core::event::FileChangeKind::{Created, Modified};
        let p = std::path::Path::new("/w/a.json");
        let (n, _) = emitted_after(
            &[(p, "h")],
            vec![hashed(p, Modified, None), hashed(p, Created, Some("h"))],
        )
        .await;
        assert_eq!(n, 2);
    }

    #[tokio::test]
    async fn a_rename_deletes_the_baseline_of_the_old_path() {
        use lodeline_core::event::FileChangeKind::Renamed;
        let old = std::path::Path::new("/w/old.json");
        let new = std::path::Path::new("/w/new.json");
        let mut ev = hashed(new, Renamed, Some("h2"));
        ev.norm.rename_from = Some(old.to_path_buf());
        let (_, cache) = emitted_after(&[(old, "h")], vec![ev]).await;
        assert_eq!(cache.lock().get(old).unwrap(), None);
        assert_eq!(cache.lock().get(new).unwrap().as_deref(), Some("h2"));
    }
}
