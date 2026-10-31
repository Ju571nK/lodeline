//! T-11 S4 slice B1 — storage tests for the proxy event ledger (L1, L4, L5 SV-1,
//! N2/M1/M2a; PX-010/011, AC-05/06). No HTTP here.

use lodeline_proxy_api::{parse_event, ProxyEvent};
use lodeline_server::config::ProxyConfig;
use lodeline_server::proxy::ledger::{
    check_tombstone_invariant, config_retention_ok, ConflictKind, GapKind, Ledger, LedgerCaps,
    LedgerError, LedgerOptions,
};
use serde_json::json;
use std::path::Path;
use std::sync::Arc;

const EP1: &str = "11111111-1111-4111-8111-111111111111";
const EP2: &str = "22222222-2222-4222-8222-222222222222";
const DAY: i64 = 86_400;

fn uuid(n: u32) -> String {
    format!("00000000-0000-4000-8000-{n:012}")
}

fn ev_with(
    proxy: &str,
    epoch: &str,
    seq: i64,
    event_n: u32,
    inv_n: u32,
    extra: &str,
) -> ProxyEvent {
    let v = json!({
        "schema_version": 1,
        "event_id": uuid(event_n),
        "proxy_id": proxy,
        "epoch_id": epoch,
        "sequence": seq,
        "occurred_at": "2026-10-10T00:00:00Z",
        "event_type": "invocation.started",
        "payload": {
            "invocation_id": uuid(inv_n),
            "upstream_id": format!("up{extra}"),
            "route_revision": 1,
            "protocol_version": "unknown",
            "method": "ping",
            "actor": {
                "actor_id": "actor-1",
                "actor_kind": "non_human",
                "authentication_method": "bearer",
                "evidence_source": "proxy_credential_mapping"
            }
        }
    });
    parse_event(v.to_string().as_bytes()).unwrap()
}

/// Event whose ids all derive from `seq` in EP1.
fn ev(proxy: &str, seq: i64) -> ProxyEvent {
    ev_with(proxy, EP1, seq, seq as u32, seq as u32 + 5000, "")
}

fn open(dir: &Path) -> Ledger {
    Ledger::open(&dir.join("l.sqlite"), LedgerOptions::default()).unwrap()
}

fn open_with(dir: &Path, opts: LedgerOptions) -> Ledger {
    Ledger::open(&dir.join("l.sqlite"), opts).unwrap()
}

fn ids(v: &[lodeline_proxy_api::Uuid]) -> Vec<String> {
    v.iter().map(|u| u.as_str().to_string()).collect()
}

#[test]
fn accepts_then_survives_reopen() {
    let d = tempfile::tempdir().unwrap();
    {
        let l = open(d.path());
        let out = l
            .insert_batch("px", &[ev("px", 1), ev("px", 2)], 1000)
            .unwrap();
        assert_eq!(ids(&out.accepted), vec![uuid(1), uuid(2)]);
        assert!(out.duplicate.is_empty());
    }
    let l = open(d.path());
    // S5 fields survive: creation seq, received_at, canonical event.
    let s = l.stored_event("px", &uuid(2)).unwrap().unwrap();
    assert_eq!((s.received_at, s.sequence), (1000, 2));
    assert!(s.created_seq > l.stored_event("px", &uuid(1)).unwrap().unwrap().created_seq);
    assert!(!s.canonical.is_empty());
    // and dedup still works after reopen
    let out = l.insert_batch("px", &[ev("px", 1)], 2000).unwrap();
    assert!(out.accepted.is_empty());
    assert_eq!(ids(&out.duplicate), vec![uuid(1)]);
}

#[cfg(unix)]
#[test]
fn ledger_file_is_owner_only_and_unsafe_files_are_refused() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("l.sqlite");
    let l = Ledger::open(&p, LedgerOptions::default()).unwrap();
    l.insert_batch("px", &[ev("px", 1)], 1).unwrap();
    assert_eq!(
        std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
        0o600
    );
    drop(l);
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Ledger::open(&p, LedgerOptions::default()).is_err());
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = d.path().join("link.sqlite");
    std::os::unix::fs::symlink(&p, &link).unwrap();
    assert!(Ledger::open(&link, LedgerOptions::default()).is_err());
}

#[test]
fn equal_event_is_duplicate_and_different_is_conflict() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    l.insert_batch("px", &[ev("px", 1)], 10).unwrap();
    // same event_id, one payload field differs
    let changed = ev_with("px", EP1, 1, 1, 5001, "-other");
    let err = l
        .insert_batch("px", &[ev("px", 2), changed], 11)
        .unwrap_err();
    match err {
        LedgerError::Conflicts(items) => {
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].index, 1);
            assert_eq!(items[0].kind, ConflictKind::Conflict);
            assert_eq!(items[0].event_id.as_str(), uuid(1));
        }
        e => panic!("{e:?}"),
    }
    // event 2 was rolled back with the batch
    assert!(l.stored_event("px", &uuid(2)).unwrap().is_none());
    // same event_id in a different epoch is a conflict too (M1)
    let other_epoch = ev_with("px", EP2, 1, 1, 5001, "");
    assert!(matches!(
        l.insert_batch("px", &[other_epoch], 12),
        Err(LedgerError::Conflicts(_))
    ));
}

#[test]
fn same_epoch_sequence_with_other_event_id_is_sequence_conflict() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    l.insert_batch("px", &[ev("px", 1)], 10).unwrap();
    let reuse = ev_with("px", EP1, 1, 99, 5099, "");
    match l.insert_batch("px", &[reuse], 11).unwrap_err() {
        LedgerError::Conflicts(items) => {
            assert_eq!(items[0].kind, ConflictKind::SequenceConflict);
            assert_eq!(items[0].event_id.as_str(), uuid(99));
        }
        e => panic!("{e:?}"),
    }
    // the same sequence in another epoch is fine
    let ok = ev_with("px", EP2, 1, 98, 5098, "");
    assert_eq!(l.insert_batch("px", &[ok], 12).unwrap().accepted.len(), 1);
    // two events in ONE batch reusing a sequence: second is the conflict
    let a = ev_with("px", EP1, 7, 70, 5070, "");
    let b = ev_with("px", EP1, 7, 71, 5071, "");
    match l.insert_batch("px", &[a, b], 13).unwrap_err() {
        LedgerError::Conflicts(items) => {
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].index, 1);
            assert_eq!(items[0].kind, ConflictKind::SequenceConflict);
        }
        e => panic!("{e:?}"),
    }
}

#[test]
fn invocation_owner_is_bound_to_the_first_proxy() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    l.insert_batch("pa", &[ev_with("pa", EP1, 1, 1, 777, "")], 10)
        .unwrap();
    let theirs = ev_with("pb", EP1, 1, 2, 777, "");
    match l.insert_batch("pb", &[theirs], 11).unwrap_err() {
        LedgerError::Conflicts(items) => {
            assert_eq!(items[0].kind, ConflictKind::InvocationOwnerConflict);
            assert_eq!(items[0].index, 0);
        }
        e => panic!("{e:?}"),
    }
    // the owner may add more events of its invocation
    let more = ev_with("pa", EP1, 2, 3, 777, "");
    assert_eq!(l.insert_batch("pa", &[more], 12).unwrap().accepted.len(), 1);
    // and a proxy mismatch between caller and event is refused outright
    assert_eq!(
        l.insert_batch("pa", &[ev("pb", 9)], 13).unwrap_err(),
        LedgerError::ProxyMismatch
    );
}

#[test]
fn failing_batch_is_atomic() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    l.insert_batch("px", &[ev("px", 1)], 10).unwrap();
    let bad = ev_with("px", EP1, 1, 50, 5050, ""); // sequence conflict
    let err = l
        .insert_batch("px", &[ev("px", 2), ev("px", 3), bad], 11)
        .unwrap_err();
    assert!(matches!(err, LedgerError::Conflicts(_)));
    for n in [2, 3] {
        assert!(l.stored_event("px", &uuid(n)).unwrap().is_none());
    }
    assert_eq!(l.usage("px").unwrap().event_rows, 1);
    assert_eq!(l.gaps("px").unwrap().len(), 0, "rolled-back gap derivation");
    // a retry without the bad item succeeds as a normal batch
    let out = l
        .insert_batch("px", &[ev("px", 2), ev("px", 3)], 12)
        .unwrap();
    assert_eq!(out.accepted.len(), 2);
}

#[test]
fn intra_batch_repeat_is_a_duplicate() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    let out = l
        .insert_batch("px", &[ev("px", 1), ev("px", 1)], 10)
        .unwrap();
    assert_eq!(ids(&out.accepted), vec![uuid(1)]);
    assert_eq!(ids(&out.duplicate), vec![uuid(1)]);
    assert_eq!(l.usage("px").unwrap().event_rows, 1);
}

#[test]
fn concurrent_batches_are_all_or_nothing_and_unique() {
    let d = tempfile::tempdir().unwrap();
    let l = Arc::new(open(d.path()));
    let mut hs = vec![];
    for t in 0..8u32 {
        let l = l.clone();
        hs.push(std::thread::spawn(move || {
            // every thread submits the SAME shared batch (1..=20) plus a private tail
            let mut batch: Vec<ProxyEvent> = (1..=20).map(|s| ev("px", s)).collect();
            batch.push(ev_with("px", EP1, 100 + t as i64, 900 + t, 6000 + t, ""));
            l.insert_batch("px", &batch, 50).unwrap()
        }));
    }
    let outs: Vec<_> = hs.into_iter().map(|h| h.join().unwrap()).collect();
    let accepted: usize = outs.iter().map(|o| o.accepted.len()).sum();
    // 20 shared events are accepted exactly once overall, plus 8 private events
    assert_eq!(accepted, 20 + 8);
    // exactly one thread won the shared batch; the rest saw 20 duplicates
    assert_eq!(outs.iter().filter(|o| o.duplicate.len() == 20).count(), 7);
    assert_eq!(l.usage("px").unwrap().event_rows, 28);
}

#[test]
fn retention_boundary_and_tombstone_dedup() {
    let d = tempfile::tempdir().unwrap();
    let t = 10 * DAY;
    let opts = LedgerOptions {
        tombstone_retention_secs: t,
        caps: LedgerCaps::default(),
    };
    let l = open_with(d.path(), opts);
    l.insert_batch("px", &[ev("px", 1)], 1_000).unwrap();
    let e = |_: &str| 5 * DAY; // E < T
                               // exactly at received_at + E: still kept
    let s = l.sweep(1_000 + 5 * DAY, &e).unwrap();
    assert_eq!(s.events, 0);
    assert!(l.stored_event("px", &uuid(1)).unwrap().is_some());
    // one second later: the body goes, the tombstone stays
    let s = l.sweep(1_000 + 5 * DAY + 1, &e).unwrap();
    assert_eq!((s.events, s.tombstones), (1, 0));
    assert!(l.stored_event("px", &uuid(1)).unwrap().is_none());
    let u = l.usage("px").unwrap();
    assert_eq!((u.event_rows, u.event_bytes, u.tombstone_rows), (0, 0, 1));
    // dedup still answers from the tombstone (equal => duplicate)
    let now = 1_000 + 6 * DAY;
    let out = l.insert_batch("px", &[ev("px", 1)], now).unwrap();
    assert_eq!(ids(&out.duplicate), vec![uuid(1)]);
    // different content => conflict; reused sequence => sequence_conflict
    let changed = ev_with("px", EP1, 1, 1, 5001, "-x");
    assert!(matches!(
        l.insert_batch("px", &[changed], now),
        Err(LedgerError::Conflicts(v)) if v[0].kind == ConflictKind::Conflict
    ));
    let reuse = ev_with("px", EP1, 1, 77, 5077, "");
    assert!(matches!(
        l.insert_batch("px", &[reuse], now),
        Err(LedgerError::Conflicts(v)) if v[0].kind == ConflictKind::SequenceConflict
    ));
    // at received_at + T the tombstone is still there; after it, it is gone
    l.sweep(1_000 + t, &e).unwrap();
    assert_eq!(l.usage("px").unwrap().tombstone_rows, 1);
    let s = l.sweep(1_000 + t + 1, &e).unwrap();
    assert_eq!(s.tombstones, 1);
    // resubmission after expiry is accepted as new (L1 cases)
    let out = l.insert_batch("px", &[ev("px", 1)], 1_000 + t + 2).unwrap();
    assert_eq!(out.accepted.len(), 1);
}

#[test]
fn retention_uses_received_at_not_occurred_at() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    // occurred_at is 2026-10-10 in the fixture; received_at is what matters
    l.insert_batch("px", &[ev("px", 1)], 10_000_000).unwrap();
    let e = |_: &str| 100;
    assert_eq!(l.sweep(10_000_050, &e).unwrap().events, 0);
    assert_eq!(l.sweep(10_000_101, &e).unwrap().events, 1);
}

#[test]
fn gaps_open_close_and_stay_listed() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    l.insert_batch("px", &[ev("px", 1), ev("px", 2)], 10)
        .unwrap();
    assert!(l.gaps("px").unwrap().is_empty(), "first epoch, contiguous");
    // 3,4 missing
    l.insert_batch("px", &[ev("px", 5)], 20).unwrap();
    let g = l.gaps("px").unwrap();
    assert_eq!(g.len(), 1);
    assert_eq!(g[0].kind, GapKind::SequenceGap);
    assert_eq!((g[0].from_sequence, g[0].to_sequence), (Some(3), Some(4)));
    assert!(g[0].open);
    // fill one: still open
    l.insert_batch("px", &[ev("px", 3)], 30).unwrap();
    assert!(l.gaps("px").unwrap()[0].open);
    // fill the other: closed, still listed, closed_at recorded
    l.insert_batch("px", &[ev("px", 4)], 40).unwrap();
    let g = l.gaps("px").unwrap();
    assert_eq!(g.len(), 1);
    assert!(!g[0].open);
    assert_eq!(g[0].closed_at, Some(40));
    // a duplicate retransmission neither reopens nor adds a gap
    l.insert_batch("px", &[ev("px", 4)], 50).unwrap();
    assert_eq!(l.gaps("px").unwrap().len(), 1);
    // a new epoch records the change; its missing head starts at sequence 1
    let first = ev_with("px", EP2, 3, 300, 5300, "");
    l.insert_batch("px", &[first], 60).unwrap();
    let g = l.gaps("px").unwrap();
    assert_eq!(g.len(), 3);
    assert_eq!(g[1].kind, GapKind::ProducerEpochChange);
    assert_eq!(g[1].previous_epoch_id.as_deref(), Some(EP1));
    assert_eq!(g[1].epoch_id, EP2);
    assert_eq!((g[2].from_sequence, g[2].to_sequence), (Some(1), Some(2)));
    // events for the older epoch are still accepted normally
    let late = ev_with("px", EP1, 6, 600, 5600, "");
    assert_eq!(l.insert_batch("px", &[late], 70).unwrap().accepted.len(), 1);
}

#[test]
fn gap_derivation_does_not_depend_on_order_inside_a_batch() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    l.insert_batch("px", &[ev("px", 3), ev("px", 1), ev("px", 2)], 10)
        .unwrap();
    assert!(l.gaps("px").unwrap().is_empty());
}

#[test]
fn storage_caps_refuse_without_effect() {
    let d = tempfile::tempdir().unwrap();
    let caps = LedgerCaps::new(3, u64::MAX / 16, 4, u64::MAX / 16);
    let l = open_with(
        d.path(),
        LedgerOptions {
            tombstone_retention_secs: 90 * DAY,
            caps,
        },
    );
    l.insert_batch("pa", &[ev("pa", 1), ev("pa", 2), ev("pa", 3)], 1)
        .unwrap();
    // per-proxy rows: a fourth row is refused, nothing stored
    assert_eq!(
        l.insert_batch("pa", &[ev("pa", 4)], 2).unwrap_err(),
        LedgerError::StorageLimit
    );
    assert!(l.stored_event("pa", &uuid(4)).unwrap().is_none());
    assert_eq!(l.usage("pa").unwrap().event_rows, 3);
    // a pure duplicate batch is never refused by a cap
    assert_eq!(
        l.insert_batch("pa", &[ev("pa", 1)], 3)
            .unwrap()
            .duplicate
            .len(),
        1
    );
    // global rows: another proxy gets 1 more, then the total (4) is hit
    l.insert_batch("pb", &[ev_with("pb", EP1, 1, 600, 6600, "")], 4)
        .unwrap();
    assert_eq!(
        l.insert_batch("pb", &[ev_with("pb", EP1, 2, 601, 6601, "")], 5)
            .unwrap_err(),
        LedgerError::StorageLimit
    );
    // a cap hit does not hide a conflict (409 first)
    assert!(matches!(
        l.insert_batch("pa", &[ev_with("pa", EP1, 1, 99, 5099, "")], 6),
        Err(LedgerError::Conflicts(_))
    ));
}

#[test]
fn byte_cap_is_enforced() {
    let d = tempfile::tempdir().unwrap();
    let l = open_with(
        d.path(),
        LedgerOptions {
            tombstone_retention_secs: 90 * DAY,
            caps: LedgerCaps {
                file_bytes: u64::MAX / 4,
                ..LedgerCaps::new(1000, 700, 1000, 10_000)
            },
        },
    );
    // one canonical event is a few hundred bytes: one fits under 700, two do not
    assert!(l.insert_batch("px", &[ev("px", 1)], 1).is_ok());
    let used = l.usage("px").unwrap().event_bytes;
    assert!(used > 350 && used < 700, "fixture size assumption: {used}");
    assert_eq!(
        l.insert_batch("px", &[ev("px", 2)], 2).unwrap_err(),
        LedgerError::StorageLimit
    );
}

#[test]
fn tombstone_invariant_t_ge_r_plus_m() {
    let r = 30 * DAY;
    let m = (7 * DAY) as u32;
    assert!(check_tombstone_invariant(37 * DAY, m, [("px", r)]).is_ok());
    let err = check_tombstone_invariant(37 * DAY - 1, m, [("px", r), ("py", 1)])
        .unwrap_err()
        .to_string();
    assert!(err.contains("px") && err.contains("T >= R + M"), "{err}");
    // no stored config => nothing to violate
    assert!(check_tombstone_invariant(3600, m, std::iter::empty::<(&str, i64)>()).is_ok());
}

#[test]
fn server_config_bounds_for_the_new_keys() {
    let base = |extra: &str| {
        format!(
            "bind: \"127.0.0.1:8443\"\ntls_cert_path: /a\ntls_key_path: /b\nclient_ca_path: /c\n\
             events_out_dir: /d\npolicy_bundle_path: /e\nproxy:\n  ca_path: /f\n  registry_path: /g/r.json\n{extra}"
        )
    };
    let load = |extra: &str| {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("s.yaml");
        std::fs::write(&p, base(extra)).unwrap();
        lodeline_server::config::ServerConfig::load(&p)
    };
    let ok = load("").unwrap();
    let pc = ok.proxy.unwrap();
    assert_eq!(
        pc.ledger_path(),
        std::path::PathBuf::from("/g/proxy-ledger.sqlite")
    );
    assert_eq!(
        pc.dedup_tombstone_retention(),
        ProxyConfig::DEFAULT_TOMBSTONE_RETENTION_SECONDS
    );
    assert!(load("  dedup_tombstone_retention_seconds: 3599\n").is_err());
    assert!(load("  dedup_tombstone_retention_seconds: 63072001\n").is_err());
    assert!(load("  ledger_max_rows_per_proxy: 0\n").is_err());
    assert!(load("  ledger_max_bytes_total: 1024\n").is_err());
    assert!(load("  ledger_max_rows_per_proxy: 10\n  ledger_max_rows_total: 5\n").is_err());
    assert!(load("  ledger_max_rows_per_proxy: 10\n  ledger_max_rows_total: 10\n").is_ok());
}

#[test]
fn errors_echo_no_input_value() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    l.insert_batch("px-CANARY", &[ev("px-CANARY", 1)], 1)
        .unwrap();
    let changed = ev_with("px-CANARY", EP1, 1, 1, 5001, "-CANARY-value");
    let e = l.insert_batch("px-CANARY", &[changed], 2).unwrap_err();
    // Display is fixed text; Debug carries only index, event id and a code.
    let shown = format!("{e} {e:?}");
    assert!(!shown.contains("CANARY"), "{shown}");
    let mm = l
        .insert_batch("px-CANARY", &[ev("other-CANARY", 1)], 3)
        .unwrap_err();
    assert!(!format!("{mm} {mm:?}").contains("CANARY"));
    // code mapping used by the handler
    assert_eq!(
        LedgerError::StorageLimit.error_code().unwrap().as_str(),
        "storage_limit"
    );
    assert_eq!(
        LedgerError::StorageUnavailable
            .error_code()
            .unwrap()
            .as_str(),
        "storage_unavailable"
    );
    assert_eq!(
        ConflictKind::SequenceConflict.error_code().as_str(),
        "sequence_conflict"
    );
    assert_eq!(
        ConflictKind::InvocationOwnerConflict.error_code().as_str(),
        "invocation_owner_conflict"
    );
}

#[test]
fn storage_failure_maps_to_unavailable_without_effect() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("l.sqlite");
    {
        let l = Ledger::open(&p, LedgerOptions::default()).unwrap();
        l.insert_batch("px", &[ev("px", 1)], 1).unwrap();
    }
    {
        let c = rusqlite::Connection::open(&p).unwrap();
        c.execute_batch("DROP TABLE tombstones").unwrap();
    }
    // user_version is still 1, so it reopens; the missing table fails the insert
    let l = Ledger::open(&p, LedgerOptions::default()).unwrap();
    assert_eq!(
        l.insert_batch("px", &[ev("px", 2)], 2).unwrap_err(),
        LedgerError::StorageUnavailable
    );
    assert!(l.stored_event("px", &uuid(2)).unwrap().is_none());
}

#[test]
fn foreign_or_newer_schema_is_refused() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("l.sqlite");
    {
        let l = Ledger::open(&p, LedgerOptions::default()).unwrap();
        drop(l);
        let c = rusqlite::Connection::open(&p).unwrap();
        c.pragma_update(None, "user_version", 99).unwrap();
    }
    assert!(Ledger::open(&p, LedgerOptions::default()).is_err());
}

fn db_live_bytes(path: &Path) -> u64 {
    let c = rusqlite::Connection::open(path).unwrap();
    let n = |p: &str| {
        c.pragma_query_value(None, p, |r| r.get::<_, i64>(0))
            .unwrap()
    };
    ((n("page_count") - n("freelist_count")) * n("page_size")) as u64
}

#[test]
fn config_put_retention_rule_includes_t() {
    let (r, m) = (30 * DAY, (7 * DAY) as u32);
    assert!(config_retention_ok(90 * DAY, r, m, 90 * DAY));
    assert!(config_retention_ok(37 * DAY, r, m, 37 * DAY));
    assert!(!config_retention_ok(37 * DAY - 1, r, m, 90 * DAY), "E");
    assert!(!config_retention_ok(90 * DAY, r, m, 37 * DAY - 1), "T");
}

#[test]
fn huge_sequence_jump_then_fills_is_fast_and_correct() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    l.insert_batch("px", &[ev("px", 1)], 10).unwrap();
    l.insert_batch("px", &[ev("px", 1_000_000_000)], 11)
        .unwrap();
    let g = l.gaps("px").unwrap();
    assert_eq!(g.len(), 1);
    assert_eq!(
        (g[0].from_sequence, g[0].to_sequence),
        (Some(2), Some(999_999_999))
    );
    let t0 = std::time::Instant::now();
    for chunk in (2..=1500i64).collect::<Vec<_>>().chunks(100) {
        let batch: Vec<_> = chunk.iter().map(|s| ev("px", *s)).collect();
        l.insert_batch("px", &batch, 12).unwrap();
    }
    assert!(t0.elapsed().as_secs() < 20, "fills must not scan the range");
    assert!(l.gaps("px").unwrap()[0].open, "range is nowhere near full");
}

#[test]
fn small_gap_closes_exactly_when_full_even_in_one_batch() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    l.insert_batch("px", &[ev("px", 1), ev("px", 6)], 10)
        .unwrap(); // gap 2..5
    l.insert_batch("px", &[ev("px", 4), ev("px", 2), ev("px", 5)], 11)
        .unwrap();
    assert!(l.gaps("px").unwrap()[0].open);
    l.insert_batch("px", &[ev("px", 3)], 12).unwrap();
    assert!(!l.gaps("px").unwrap()[0].open);
}

#[test]
fn open_gap_cap_counts_open_gaps_only() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    // sequences 2,4,..,20000: 10_000 events, each opening a one-sequence gap
    for start in (0..10_000i64).step_by(100) {
        let batch: Vec<_> = (start..start + 100)
            .map(|i| ev("px", 2 * (i + 1)))
            .collect();
        l.insert_batch("px", &batch, 10).unwrap();
    }
    assert_eq!(l.gaps("px").unwrap().len(), 10_000);
    assert_eq!(
        l.insert_batch("px", &[ev("px", 20_002)], 11).unwrap_err(),
        LedgerError::StorageLimit
    );
    // close one gap (sequence 1 fills [1,1]); closed gaps stay listed but no
    // longer count, so the refused event now fits
    l.insert_batch("px", &[ev("px", 1)], 12).unwrap();
    assert_eq!(
        l.insert_batch("px", &[ev("px", 20_002)], 13)
            .unwrap()
            .accepted
            .len(),
        1
    );
    assert_eq!(l.gaps("px").unwrap().len(), 10_001);
}

#[test]
fn file_size_backstop_and_tombstone_bound_are_separate() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("l.sqlite");
    let f0 = {
        let _l = Ledger::open(&p, LedgerOptions::default()).unwrap();
        db_live_bytes(&p)
    };
    let caps = LedgerCaps {
        file_bytes: f0,
        ..LedgerCaps::default()
    };
    let l = Ledger::open(
        &p,
        LedgerOptions {
            tombstone_retention_secs: 90 * DAY,
            caps,
        },
    )
    .unwrap();
    let batch: Vec<_> = (1..=100).map(|s| ev("px", s)).collect();
    assert_eq!(
        l.insert_batch("px", &batch, 1).unwrap_err(),
        LedgerError::StorageLimit
    );
    assert_eq!(l.usage("px").unwrap().event_rows, 0);

    // tombstones do not consume the event rows cap: 3 events fit rows=3 even
    // though events and tombstones together are 6
    let d2 = tempfile::tempdir().unwrap();
    let mut caps = LedgerCaps::new(3, 1 << 30, 100, 1 << 30);
    let l2 = open_with(
        d2.path(),
        LedgerOptions {
            tombstone_retention_secs: 90 * DAY,
            caps,
        },
    );
    l2.insert_batch("px", &[ev("px", 1), ev("px", 2), ev("px", 3)], 1)
        .unwrap();
    // own tombstone bound
    caps.tombstones_per_proxy = 2;
    let d3 = tempfile::tempdir().unwrap();
    let l3 = open_with(
        d3.path(),
        LedgerOptions {
            tombstone_retention_secs: 90 * DAY,
            caps,
        },
    );
    assert_eq!(
        l3.insert_batch("px", &[ev("px", 1), ev("px", 2), ev("px", 3)], 1)
            .unwrap_err(),
        LedgerError::StorageLimit
    );
}

#[cfg(unix)]
#[test]
fn wal_and_shm_files_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    l.insert_batch("px", &[ev("px", 1)], 1).unwrap();
    for suffix in ["-wal", "-shm"] {
        let f = d.path().join(format!("l.sqlite{suffix}"));
        let mode = std::fs::metadata(&f).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "{suffix}: {mode:o}");
    }
}

#[test]
fn sweep_truncates_the_wal() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    let batch: Vec<_> = (1..=50).map(|s| ev("px", s)).collect();
    l.insert_batch("px", &batch, 1).unwrap();
    let wal = d.path().join("l.sqlite-wal");
    assert!(std::fs::metadata(&wal).unwrap().len() > 0);
    l.sweep(1 + DAY, &|_| 100).unwrap();
    assert_eq!(std::fs::metadata(&wal).unwrap().len(), 0);
}

#[test]
fn old_epoch_event_after_a_newer_epoch_adds_no_gap() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    l.insert_batch("px", &[ev_with("px", EP1, 1, 1, 5001, "")], 1)
        .unwrap();
    l.insert_batch("px", &[ev_with("px", EP2, 1, 2, 5002, "")], 2)
        .unwrap();
    l.insert_batch("px", &[ev_with("px", EP1, 2, 3, 5003, "")], 3)
        .unwrap();
    let g = l.gaps("px").unwrap();
    assert_eq!(g.len(), 1, "only the single epoch change: {g:?}");
    assert_eq!(g[0].kind, GapKind::ProducerEpochChange);
}

#[test]
fn gap_stays_open_when_its_evidence_expired_and_sweep_cleans_up() {
    let d = tempfile::tempdir().unwrap();
    let t = 10 * DAY;
    let l = open_with(
        d.path(),
        LedgerOptions {
            tombstone_retention_secs: t,
            caps: LedgerCaps::default(),
        },
    );
    let e = |_: &str| 100 * DAY;
    l.insert_batch("px", &[ev("px", 1), ev("px", 2), ev("px", 5)], 0)
        .unwrap(); // gap A: 3..4
    l.insert_batch("px", &[ev_with("px", EP2, 1, 200, 5200, "")], 1000)
        .unwrap();
    // tombstones and the idle EP1 epoch row expire (T), gap A is kept (E)
    let s = l.sweep(20 * DAY, &e).unwrap();
    assert!(s.tombstones >= 4 && s.epochs == 1, "{s:?}");
    // EP1 reappears (outside the invariant): a new epoch row, new head gap B.
    l.insert_batch("px", &[ev("px", 7)], 20 * DAY).unwrap();
    let gaps = l.gaps("px").unwrap();
    let a = &gaps[0];
    assert_eq!((a.from_sequence, a.to_sequence), (Some(3), Some(4)));
    // replay 1..=6: 1, 2 and 5 are still stored as event rows (E > T), so they
    // are duplicates and not counted; neither gap may close wrongly
    let batch: Vec<_> = (1..=6).map(|s| ev("px", s)).collect();
    let out = l.insert_batch("px", &batch, 20 * DAY + 1).unwrap();
    assert_eq!((out.accepted.len(), out.duplicate.len()), (3, 3));
    let gaps = l.gaps("px").unwrap();
    assert!(gaps[0].open, "stale gap must not close on a replay");
    let b = gaps
        .iter()
        .find(|g| (g.from_sequence, g.to_sequence) == (Some(1), Some(6)))
        .unwrap();
    assert!(b.open, "3 of 6 sequences counted");

    // a full sweep long after: gaps, owners, epochs and usage all go
    let s = l.sweep(500 * DAY, &|_| 1).unwrap();
    assert!(s.gaps >= 3 && s.invocations >= 1, "{s:?}");
    assert!(l.gaps("px").unwrap().is_empty());
    assert_eq!(l.usage("px").unwrap(), Default::default());
    // the invocation binding was released: another proxy can use that id
    let other = ev_with("pb", EP1, 1, 900, 5001, "");
    assert_eq!(
        l.insert_batch("pb", &[other], 500 * DAY + 1)
            .unwrap()
            .accepted
            .len(),
        1
    );
}

#[test]
fn ledger_sweep_helper_uses_default_retention_without_stored_config() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    let store =
        lodeline_server::proxy::store::ProxyStore::open(&d.path().join("state.json")).unwrap();
    l.insert_batch("px", &[ev("px", 1)], 1_000).unwrap();
    let e = lodeline_proxy_api::config::DEFAULT_EVENT_RETENTION_SECONDS;
    let s = lodeline_server::proxy::sweep_ledger(&l, &store, 1_000 + e).unwrap();
    assert_eq!(s.events, 0);
    let s = lodeline_server::proxy::sweep_ledger(&l, &store, 1_000 + e + 1).unwrap();
    assert_eq!(s.events, 1);
}

#[test]
fn with_many_open_gaps_only_the_containing_gap_advances() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    // sequences 1,4,7,...: gaps [2,3],[5,6],[8,9],...
    let batch: Vec<_> = (0..300i64).map(|i| ev("px", 1 + 3 * i)).collect();
    for c in batch.chunks(100) {
        l.insert_batch("px", c, 10).unwrap();
    }
    assert_eq!(l.gaps("px").unwrap().len(), 299);
    // 5 is in gap [5,6]: it stays open (1 of 2), and so do all the others
    l.insert_batch("px", &[ev("px", 5)], 11).unwrap();
    assert!(l.gaps("px").unwrap().iter().all(|g| g.open));
    // 6 completes exactly that gap
    l.insert_batch("px", &[ev("px", 6)], 12).unwrap();
    let closed: Vec<_> = l
        .gaps("px")
        .unwrap()
        .into_iter()
        .filter(|g| !g.open)
        .collect();
    assert_eq!(closed.len(), 1);
    assert_eq!(
        (closed[0].from_sequence, closed[0].to_sequence),
        (Some(5), Some(6))
    );
    // a sequence in the next gap closes only after both of its sequences
    l.insert_batch("px", &[ev("px", 3)], 13).unwrap();
    assert_eq!(l.gaps("px").unwrap().iter().filter(|g| !g.open).count(), 1);
    l.insert_batch("px", &[ev("px", 2)], 14).unwrap();
    assert_eq!(l.gaps("px").unwrap().iter().filter(|g| !g.open).count(), 2);
}
