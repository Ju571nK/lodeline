//! `host_meta` accessor over the singleton `state.db` row.
//!
//! Spec §1.4 host_id persistence + §3.8.2 last_applied_policy_version.

use crate::policy::deployment::ArtifactKind;
use crate::state::{HashCache, StateError};
use rusqlite::types::Type;
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use std::num::NonZeroI64;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Snapshot of the host_meta row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostMeta {
    /// UUIDv4 string, generated on first run, stable across restarts.
    pub host_id: Option<String>,
    /// blake3 hex of (platform_uuid || stable_mac || cpu_brand).
    pub hw_fingerprint: Option<String>,
    /// The envelope behind `policy.yaml`.
    pub policy: AppliedEnvelope,
    /// The envelope behind `rule-packs.yaml`.
    pub rule_packs: AppliedEnvelope,
}

/// The envelope a host recorded for one artifact file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppliedEnvelope {
    /// No envelope was applied. The file on disk, if any, is local.
    NotApplied,
    Applied {
        /// Per-customer monotonic counter.
        version: NonZeroI64,
        /// `None`: an agent that did not record expiry applied this version.
        valid_until: Option<OffsetDateTime>,
    },
}

impl AppliedEnvelope {
    /// The version to verify against and to report. 0 means no envelope.
    pub fn version(self) -> i64 {
        match self {
            Self::NotApplied => 0,
            Self::Applied { version, .. } => version.get(),
        }
    }

    pub fn valid_until(self) -> Option<OffsetDateTime> {
        match self {
            Self::NotApplied => None,
            Self::Applied { valid_until, .. } => valid_until,
        }
    }

    fn read(recorded: i64, valid_until: Option<OffsetDateTime>) -> Self {
        match NonZeroI64::new(recorded) {
            Some(version) => Self::Applied {
                version,
                valid_until,
            },
            None => Self::NotApplied,
        }
    }
}

/// An apply that recorded its intent and has not finished.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingEnvelope {
    pub version: i64,
    /// Plain blake3 of the bytes bound for the file. Nothing signs this hash.
    pub hash_hex: String,
    pub valid_until: OffsetDateTime,
}

impl HashCache {
    /// Read the current host_meta row.
    pub fn host_meta_get(&self) -> Result<HostMeta, StateError> {
        let row = self.conn.query_row(
            "SELECT h.host_id, h.hw_fingerprint,
                    h.last_applied_policy_version, p.valid_until,
                    h.last_applied_rule_packs_version, r.valid_until
             FROM host_meta h
             LEFT JOIN applied_envelope p
               ON p.kind = 'policy' AND p.version = h.last_applied_policy_version
             LEFT JOIN applied_envelope r
               ON r.kind = 'rule_packs' AND r.version = h.last_applied_rule_packs_version
             WHERE h.id = 1",
            [],
            |r| {
                let policy_version: i64 = r.get(2)?;
                let policy_valid_until = optional_time(r.get(3)?)?;
                // Older agents recorded 1 at boot for any local policy.yaml. No
                // envelope is lower than v1, so reading this as "none" lowers nothing.
                let policy = if policy_version == 1 && policy_valid_until.is_none() {
                    AppliedEnvelope::NotApplied
                } else {
                    AppliedEnvelope::read(policy_version, policy_valid_until)
                };
                Ok(HostMeta {
                    host_id: r.get(0)?,
                    hw_fingerprint: r.get(1)?,
                    policy,
                    rule_packs: AppliedEnvelope::read(r.get(4)?, optional_time(r.get(5)?)?),
                })
            },
        )?;
        Ok(row)
    }

    /// Set `host_id` (idempotent).
    pub fn host_meta_set_host_id(&self, host_id: &str) -> Result<(), StateError> {
        self.conn.execute(
            "UPDATE host_meta SET host_id = ?1 WHERE id = 1",
            rusqlite::params![host_id],
        )?;
        Ok(())
    }

    /// Set `hw_fingerprint` (idempotent).
    pub fn host_meta_set_hw_fingerprint(&self, fp: &str) -> Result<(), StateError> {
        self.conn.execute(
            "UPDATE host_meta SET hw_fingerprint = ?1 WHERE id = 1",
            rusqlite::params![fp],
        )?;
        Ok(())
    }

    /// Record an apply before its file moves, so that a boot can finish it. A
    /// version below the recorded one leaves everything alone and returns
    /// [`StateError::WouldLowerVersion`].
    pub fn record_pending(
        &self,
        kind: ArtifactKind,
        pending: &PendingEnvelope,
    ) -> Result<(), StateError> {
        let (key, column) = names(kind);
        // At NORMAL a power cut can lose this commit after the rename has reached disk.
        self.conn.pragma_update(None, "synchronous", "FULL")?;
        let inserted = self.conn.execute(
            &format!(
                "INSERT OR REPLACE INTO pending_envelope (kind, version, hash_hex, valid_until)
                 SELECT ?1, ?2, ?3, ?4 FROM host_meta WHERE id = 1 AND {column} <= ?2"
            ),
            params![
                key,
                pending.version,
                pending.hash_hex,
                format_time(pending.valid_until)?
            ],
        );
        self.conn.pragma_update(None, "synchronous", "NORMAL")?;
        require_advanced(inserted?, pending.version)
    }

    /// The apply in progress for `kind`, if any.
    pub fn pending(&self, kind: ArtifactKind) -> Result<Option<PendingEnvelope>, StateError> {
        let row = self
            .conn
            .query_row(
                "SELECT version, hash_hex, valid_until FROM pending_envelope WHERE kind = ?1",
                [names(kind).0],
                |r| {
                    Ok(PendingEnvelope {
                        version: r.get(0)?,
                        hash_hex: r.get(1)?,
                        valid_until: parse_time(&r.get::<_, String>(2)?)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// Finish the apply in progress: its version and expiry become the applied
    /// ones, in one transaction. A version below the recorded one changes nothing
    /// and returns [`StateError::WouldLowerVersion`].
    pub fn promote_pending(&self, kind: ArtifactKind) -> Result<(), StateError> {
        let (key, column) = names(kind);
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let version: i64 = tx.query_row(
            "SELECT version FROM pending_envelope WHERE kind = ?1",
            [key],
            |r| r.get(0),
        )?;
        let updated = tx.execute(
            &format!("UPDATE host_meta SET {column} = ?1 WHERE id = 1 AND {column} <= ?1"),
            [version],
        )?;
        require_advanced(updated, version)?;
        tx.execute(
            "INSERT OR REPLACE INTO applied_envelope (kind, version, valid_until)
             SELECT kind, version, valid_until FROM pending_envelope WHERE kind = ?1",
            [key],
        )?;
        tx.execute("DELETE FROM pending_envelope WHERE kind = ?1", [key])?;
        tx.commit()?;
        Ok(())
    }

    /// Drop the apply in progress. The applied version stays as it was.
    pub fn clear_pending(&self, kind: ArtifactKind) -> Result<(), StateError> {
        self.conn.execute(
            "DELETE FROM pending_envelope WHERE kind = ?1",
            [names(kind).0],
        )?;
        Ok(())
    }
}

/// The `kind` value in the envelope tables, and the `host_meta` version column.
fn names(kind: ArtifactKind) -> (&'static str, &'static str) {
    match kind {
        ArtifactKind::Policy => ("policy", "last_applied_policy_version"),
        ArtifactKind::RulePacks => ("rule_packs", "last_applied_rule_packs_version"),
    }
}

fn format_time(t: OffsetDateTime) -> rusqlite::Result<String> {
    t.format(&Rfc3339)
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
}

fn parse_time(text: &str) -> rusqlite::Result<OffsetDateTime> {
    OffsetDateTime::parse(text, &Rfc3339)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, Type::Text, Box::new(e)))
}

fn optional_time(text: Option<String>) -> rusqlite::Result<Option<OffsetDateTime>> {
    text.as_deref().map(parse_time).transpose()
}

fn require_advanced(updated: usize, requested: i64) -> Result<(), StateError> {
    if updated == 0 {
        return Err(StateError::WouldLowerVersion { requested });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use time::macros::datetime;
    use ArtifactKind::{Policy, RulePacks};

    const UNTIL: OffsetDateTime = datetime!(2030-01-02 03:04:05.123456789 UTC);

    fn fresh_cache() -> (tempfile::TempDir, HashCache) {
        let dir = tempdir().unwrap();
        let db = dir.path().join("state.db");
        let cache = HashCache::open(&db).unwrap();
        (dir, cache)
    }

    fn pending(version: i64) -> PendingEnvelope {
        PendingEnvelope {
            version,
            hash_hex: format!("hash-{version}"),
            valid_until: UNTIL,
        }
    }

    fn apply(c: &HashCache, kind: ArtifactKind, version: i64) {
        c.record_pending(kind, &pending(version)).unwrap();
        c.promote_pending(kind).unwrap();
    }

    fn applied(version: i64, valid_until: Option<OffsetDateTime>) -> AppliedEnvelope {
        AppliedEnvelope::Applied {
            version: NonZeroI64::new(version).unwrap(),
            valid_until,
        }
    }

    fn set_recorded(c: &HashCache, policy: i64, rule_packs: i64) {
        c.conn
            .execute(
                "UPDATE host_meta SET last_applied_policy_version = ?1,
                 last_applied_rule_packs_version = ?2",
                [policy, rule_packs],
            )
            .unwrap();
    }

    #[test]
    fn fresh_state_returns_empty_meta() {
        let (_dir, cache) = fresh_cache();
        let m = cache.host_meta_get().unwrap();
        assert_eq!(m.host_id, None);
        assert_eq!(m.hw_fingerprint, None);
        assert_eq!(m.policy, AppliedEnvelope::NotApplied);
        assert_eq!(m.rule_packs, AppliedEnvelope::NotApplied);
        assert_eq!(m.policy.version(), 0);
    }

    #[test]
    fn set_and_get_host_id() {
        let (_dir, cache) = fresh_cache();
        cache
            .host_meta_set_host_id("5a7c3e91-aaaa-bbbb-cccc-dddddddddddd")
            .unwrap();
        let m = cache.host_meta_get().unwrap();
        assert_eq!(
            m.host_id.as_deref(),
            Some("5a7c3e91-aaaa-bbbb-cccc-dddddddddddd")
        );
    }

    #[test]
    fn set_and_get_hw_fingerprint() {
        let (_dir, cache) = fresh_cache();
        cache.host_meta_set_hw_fingerprint("deadbeef").unwrap();
        let m = cache.host_meta_get().unwrap();
        assert_eq!(m.hw_fingerprint.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn promote_records_the_version_and_expiry_of_each_kind_apart() {
        let (_dir, c) = fresh_cache();

        apply(&c, Policy, 42);
        apply(&c, RulePacks, 7);

        let m = c.host_meta_get().unwrap();
        assert_eq!(m.policy, applied(42, Some(UNTIL)));
        assert_eq!(m.rule_packs, applied(7, Some(UNTIL)));
        assert_eq!(c.pending(Policy).unwrap(), None);
        assert_eq!(c.pending(RulePacks).unwrap(), None);
    }

    #[test]
    fn a_pending_apply_changes_no_applied_state_until_promoted() {
        let (_dir, c) = fresh_cache();
        apply(&c, Policy, 2);

        c.record_pending(Policy, &pending(5)).unwrap();

        assert_eq!(c.host_meta_get().unwrap().policy.version(), 2);
        assert_eq!(c.pending(Policy).unwrap(), Some(pending(5)));
        c.clear_pending(Policy).unwrap();
        assert_eq!(c.pending(Policy).unwrap(), None);
        assert_eq!(c.host_meta_get().unwrap().policy.version(), 2);
    }

    #[test]
    fn versions_refuse_to_move_backward() {
        for kind in [Policy, RulePacks] {
            let (_dir, c) = fresh_cache();
            apply(&c, kind, 5);

            let refused = c.record_pending(kind, &pending(4));

            assert!(matches!(
                refused,
                Err(StateError::WouldLowerVersion { requested: 4 })
            ));
            assert_eq!(c.pending(kind).unwrap(), None);
            apply(&c, kind, 5);
        }
    }

    #[test]
    fn promote_refuses_to_move_past_a_higher_record_and_keeps_the_pending_row() {
        let (_dir, c) = fresh_cache();
        c.record_pending(Policy, &pending(4)).unwrap();
        set_recorded(&c, 5, 0);

        let refused = c.promote_pending(Policy);

        assert!(matches!(
            refused,
            Err(StateError::WouldLowerVersion { requested: 4 })
        ));
        assert_eq!(c.host_meta_get().unwrap().policy.version(), 5);
        assert_eq!(c.pending(Policy).unwrap(), Some(pending(4)));
    }

    #[test]
    fn a_recorded_version_with_no_row_has_unknown_expiry() {
        let (_dir, c) = fresh_cache();
        set_recorded(&c, 7, 3);

        let m = c.host_meta_get().unwrap();

        assert_eq!(m.policy, applied(7, None));
        assert_eq!(m.rule_packs, applied(3, None));
    }

    #[test]
    fn an_expiry_row_for_another_version_is_not_used() {
        let (_dir, c) = fresh_cache();
        apply(&c, Policy, 5);

        // An older agent moved the record and did not know about the row.
        set_recorded(&c, 9, 0);

        assert_eq!(c.host_meta_get().unwrap().policy, applied(9, None));
    }

    #[test]
    fn a_policy_record_of_one_with_no_row_reads_as_no_envelope() {
        let (_dir, c) = fresh_cache();
        set_recorded(&c, 1, 1);

        let m = c.host_meta_get().unwrap();

        assert_eq!(m.policy, AppliedEnvelope::NotApplied);
        assert_eq!(
            m.rule_packs,
            applied(1, None),
            "only policy was misrecorded"
        );
        apply(&c, Policy, 1);
        assert_eq!(c.host_meta_get().unwrap().policy, applied(1, Some(UNTIL)));
    }

    #[test]
    fn updates_persist_across_reopen() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("state.db");
        {
            let cache = HashCache::open(&db).unwrap();
            cache.host_meta_set_host_id("persist-me").unwrap();
            apply(&cache, Policy, 7);
            cache.record_pending(RulePacks, &pending(3)).unwrap();
        }
        let cache = HashCache::open(&db).unwrap();
        let m = cache.host_meta_get().unwrap();
        assert_eq!(m.host_id.as_deref(), Some("persist-me"));
        assert_eq!(m.policy, applied(7, Some(UNTIL)));
        assert_eq!(cache.pending(RulePacks).unwrap(), Some(pending(3)));
    }

    /// The statements of `HashCache::open` before the rule-packs column, and the
    /// row an agent of that time left behind.
    const FIRST_SCHEMA: &str = "
        CREATE TABLE baseline (
            path TEXT PRIMARY KEY,
            hash_hex TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            target_id TEXT NOT NULL,
            updated_at_ms INTEGER NOT NULL
        );
        CREATE TABLE host_meta (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            host_id TEXT,
            hw_fingerprint TEXT,
            last_applied_policy_version INTEGER NOT NULL DEFAULT 0
        );
        INSERT INTO baseline VALUES ('/x', 'H1', 1, 't1', 0);
        INSERT INTO host_meta VALUES (1, 'host', 'fp', 9);";

    #[test]
    fn opening_an_old_schema_keeps_its_rows_and_twice_changes_nothing() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("state.db");
        rusqlite::Connection::open(&db)
            .unwrap()
            .execute_batch(FIRST_SCHEMA)
            .unwrap();

        for _ in 0..2 {
            let c = HashCache::open(&db).unwrap();
            let m = c.host_meta_get().unwrap();
            assert_eq!(m.host_id.as_deref(), Some("host"));
            assert_eq!(m.policy, applied(9, None));
            assert_eq!(m.rule_packs, AppliedEnvelope::NotApplied);
            assert_eq!(c.get(std::path::Path::new("/x")).unwrap().unwrap(), "H1");
        }
    }
}
