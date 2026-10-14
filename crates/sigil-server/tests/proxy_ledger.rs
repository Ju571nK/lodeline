//! T-11 S4 slice B1 — storage tests for the proxy event ledger (L1, L4, L5 SV-1,
//! N2/M1/M2a; PX-010/011, AC-05/06). No HTTP here.

use serde_json::json;
use sigil_proxy_api::{parse_event, ProxyEvent};
use sigil_server::config::ProxyConfig;
use sigil_server::proxy::ledger::{
    check_tombstone_invariant, ConflictKind, GapKind, Ledger, LedgerCaps, LedgerError,
    LedgerOptions,
};
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

fn ids(v: &[sigil_proxy_api::Uuid]) -> Vec<String> {
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
    let caps = LedgerCaps {
        rows_per_proxy: 3,
        bytes_per_proxy: u64::MAX / 4,
        rows_total: 4,
        bytes_total: u64::MAX / 4,
    };
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
                rows_per_proxy: 1000,
                bytes_per_proxy: 700,
                rows_total: 1000,
                bytes_total: 10_000,
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
        sigil_server::config::ServerConfig::load(&p)
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
