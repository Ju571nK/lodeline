//! Go's `internal/triage/repo_test.go`, plus checks against the database the Go build wrote.

use std::cell::Cell;
use std::path::PathBuf;

use super::*;

const HOST1: &str = "5a7c3e91-aaaa-bbbb-cccc-111111111111";
const HOST2: &str = "5a7c3e91-aaaa-bbbb-cccc-222222222222";
const EV1: &str = "019e0cea-0001-7000-8000-000000000001";
const EV2: &str = "019e0cea-0001-7000-8000-000000000002";
const EV3: &str = "019e0cea-0001-7000-8000-000000000003";

/// Go's test clock: 2026-05-19T12:00:00Z, one millisecond later on every read.
struct Clock(Cell<u32>);

impl Clock {
    fn new() -> Self {
        Self(Cell::new(0))
    }

    fn now(&self) -> GoTime {
        let tick = self.0.replace(self.0.get() + 1);
        GoTime {
            unix: 1_779_192_000 + i64::from(tick / 1000),
            nanos: tick % 1000 * 1_000_000,
            offset: 0,
        }
    }
}

fn store() -> Store {
    Store::open(":memory:").unwrap()
}

fn snap(extra: &str) -> String {
    format!(
        r#"{{"kind":"ai_guard_risk_assessed","tool":"claude_code","score":7.2,"bucket":"critical","extra":"{extra}"}}"#
    )
}

fn extra(snapshot: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(snapshot).unwrap();
    v["extra"].as_str().unwrap().to_owned()
}

fn input(host: &str, event: &str) -> Upsert {
    Upsert {
        host_id: host.into(),
        event_id: event.into(),
        actor: "admin".into(),
        ..Upsert::default()
    }
}

fn insert(s: &Store, clock: &Clock, host: &str, event: &str, snapshot: String) -> Row {
    let row = Upsert {
        evidence_snapshot: Some(snapshot),
        ..input(host, event)
    };
    s.upsert(row, clock.now()).unwrap()
}

#[test]
fn open_runs_schema_idempotently() {
    let s = store();
    s.lock().execute_batch(SCHEMA).unwrap();
}

#[test]
fn upsert_insert_defaults_to_open() {
    let (s, clock) = (store(), Clock::new());
    let row = insert(&s, &clock, HOST1, EV1, snap("hello"));
    assert_eq!(row.status, "open");
    assert_eq!(row.assignee, None);
    assert_eq!(extra(&row.evidence_snapshot), "hello");
    assert!(!row.created_at.is_zero());
    assert_eq!(row.created_at, row.updated_at);
}

#[test]
fn upsert_requires_identity_and_actor() {
    let (s, clock) = (store(), Clock::new());
    let full = Upsert {
        evidence_snapshot: Some(snap("x")),
        ..input(HOST1, EV1)
    };
    for missing in [
        Upsert {
            host_id: String::new(),
            ..full.clone()
        },
        Upsert {
            event_id: String::new(),
            ..full.clone()
        },
        Upsert {
            actor: String::new(),
            ..full.clone()
        },
    ] {
        assert_eq!(
            s.upsert(missing, clock.now()),
            Err(Error::MissingFields("HostID/EventID/Actor"))
        );
    }
}

#[test]
fn upsert_insert_requires_evidence_snapshot() {
    let (s, clock) = (store(), Clock::new());
    let err = s.upsert(input(HOST1, EV1), clock.now()).unwrap_err();
    assert_eq!(
        err.to_string(),
        "triage: missing required fields: EvidenceSnapshot required on insert"
    );
}

#[test]
fn upsert_rejects_bad_status() {
    let (s, clock) = (store(), Clock::new());
    let row = Upsert {
        status: "bogus".into(),
        evidence_snapshot: Some(snap("x")),
        ..input(HOST1, EV1)
    };
    assert_eq!(
        s.upsert(row, clock.now()),
        Err(Error::InvalidStatus("bogus".into()))
    );
}

#[test]
fn upsert_update_bumps_updated_at_and_appends_log() {
    let (s, clock) = (store(), Clock::new());
    let created = insert(&s, &clock, HOST1, EV1, snap("x")).created_at;
    let update = Upsert {
        status: "acknowledged".into(),
        assignee: Some("alice".into()),
        ..input(HOST1, EV1)
    };
    let updated = s.upsert(update, clock.now()).unwrap();
    assert_eq!(updated.status, "acknowledged");
    assert_eq!(updated.assignee.as_deref(), Some("alice"));
    assert!(updated.updated_at > created, "updated_at must advance");
    assert_eq!(updated.created_at, created, "created_at must not change");

    let log = s.get(HOST1, EV1).unwrap().log;
    assert_eq!(log.len(), 2, "initial open + status change");
    assert_eq!(log[0].from_status, None);
    assert_eq!(log[0].to_status.as_deref(), Some("open"));
    assert_eq!(log[1].from_status.as_deref(), Some("open"));
    assert_eq!(log[1].to_status.as_deref(), Some("acknowledged"));
}

#[test]
fn upsert_without_status_change_adds_no_log_row() {
    let (s, clock) = (store(), Clock::new());
    insert(&s, &clock, HOST1, EV1, snap("x"));
    let assign = Upsert {
        assignee: Some("bob".into()),
        ..input(HOST1, EV1)
    };
    s.upsert(assign, clock.now()).unwrap();
    assert_eq!(s.get(HOST1, EV1).unwrap().log.len(), 1);
}

#[test]
fn upsert_clear_assignee() {
    let (s, clock) = (store(), Clock::new());
    let first = Upsert {
        assignee: Some("alice".into()),
        evidence_snapshot: Some(snap("x")),
        ..input(HOST1, EV1)
    };
    s.upsert(first, clock.now()).unwrap();
    let clear = Upsert {
        clear_assignee: true,
        ..input(HOST1, EV1)
    };
    s.upsert(clear, clock.now()).unwrap();
    assert_eq!(s.get(HOST1, EV1).unwrap().row.assignee, None);
}

#[test]
fn evidence_snapshot_immutable_on_update() {
    let (s, clock) = (store(), Clock::new());
    insert(&s, &clock, HOST1, EV1, snap("first"));
    let update = Upsert {
        status: "resolved".into(),
        evidence_snapshot: Some(snap("second")),
        ..input(HOST1, EV1)
    };
    s.upsert(update, clock.now()).unwrap();
    let row = s.get(HOST1, EV1).unwrap().row;
    assert_eq!(extra(&row.evidence_snapshot), "first");
}

#[test]
fn get_not_found() {
    assert_eq!(store().get("missing", "missing"), Err(Error::NotFound));
}

#[test]
fn notes_append_and_list_chronological() {
    let (s, clock) = (store(), Clock::new());
    insert(&s, &clock, HOST1, EV1, snap("x"));
    s.append_note(HOST1, EV1, "alice", "first", clock.now())
        .unwrap();
    s.append_note(HOST1, EV1, "bob", "second", clock.now())
        .unwrap();
    let notes = s.get(HOST1, EV1).unwrap().notes;
    let bodies: Vec<_> = notes.iter().map(|n| n.body.as_str()).collect();
    assert_eq!(bodies, ["first", "second"]);
}

#[test]
fn notes_require_existing_triage_row() {
    let (s, clock) = (store(), Clock::new());
    assert_eq!(
        s.append_note(HOST1, EV1, "alice", "hi", clock.now()),
        Err(Error::NotFound)
    );
}

#[test]
fn notes_list_is_empty_for_no_notes() {
    let (s, clock) = (store(), Clock::new());
    insert(&s, &clock, HOST1, EV1, snap("x"));
    assert!(s.get(HOST1, EV1).unwrap().notes.is_empty());
}

/// Go's `TestEvidenceSnapshot_RoundTripsRawJSON`, kept to the byte: the stored text is what the
/// client sent, and the encoded form is Go's compacted, HTML-escaped one.
#[test]
fn evidence_snapshot_round_trips_raw_json() {
    let (s, clock) = (store(), Clock::new());
    let raw = "{ \"n\" : 1.0, \"e\": 1e2, \"big\": 123456789012345678901234567890,\n \"s\": \"<b>&amp;\\u0041\\n\u{2028}\" }";
    insert(&s, &clock, HOST1, EV1, raw.into());
    let row = s.get(HOST1, EV1).unwrap().row;
    assert_eq!(row.evidence_snapshot, raw);
    let body = serde_json::to_value(&row).unwrap();
    assert_eq!(
        serde_json::to_string(&row).unwrap(),
        format!(
            r#"{{"host_id":"{HOST1}","event_id":"{EV1}","status":"open","assignee":null,"evidence_snapshot":{{"n":1.0,"e":1e2,"big":123456789012345678901234567890,"s":"\u003cb\u003e\u0026amp;\u0041\n\u2028"}},"created_at":"2026-05-19T12:00:00.000000000Z","updated_at":"2026-05-19T12:00:00.000000000Z"}}"#
        )
    );
    assert_eq!(body["evidence_snapshot"]["s"], "<b>&amp;A\n\u{2028}");
}

#[test]
fn timestamps_use_go_fixed_width_layout() {
    let at = |unix, nanos| GoTime {
        unix,
        nanos,
        offset: 0,
    };
    assert_eq!(
        format_ts(&at(1_779_192_000, 0)),
        "2026-05-19T12:00:00.000000000Z"
    );
    assert_eq!(
        format_ts(&at(1_779_192_000, 1_000_000)),
        "2026-05-19T12:00:00.001000000Z"
    );
    assert_eq!(
        format_ts(&GoTime::default()),
        "0001-01-01T00:00:00.000000000Z"
    );
    // Go's parseTS reads any RFC 3339 form and returns UTC; text it cannot read is year 1.
    assert_eq!(
        parse_ts("2026-05-19T14:00:00.5+02:00"),
        at(1_779_192_000, 500_000_000)
    );
    assert!(parse_ts("yesterday").is_zero());
}

#[test]
fn dsn_pragmas_follow_modernc() {
    assert_eq!(
        dsn_pragmas("file:/x/t.sqlite?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"),
        Ok(vec!["busy_timeout(5000)".into(), "foreign_keys(1)".into(), "journal_mode(WAL)".into()])
    );
    // A `?` in the path starts the query early, and the first pragma's key no longer matches.
    assert_eq!(
        dsn_pragmas("file:/x/q?x.sqlite?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"),
        Ok(vec!["busy_timeout(5000)".into()])
    );
    assert!(dsn_pragmas("file:/x/q?a;b&_pragma=x").is_err());
    assert_eq!(dsn_pragmas(":memory:"), Ok(vec![]));
}

/// A plain path is opened as Go opens it: WAL with foreign keys on, no directory created.
#[test]
fn open_matches_go_file_handling() {
    let dir = temp_dir("open");
    let path = dir.join("t.sqlite");
    let s = Store::open(path.to_str().unwrap()).unwrap();
    let conn = s.lock();
    let mode: String = conn
        .query_row("pragma journal_mode", [], |r| r.get(0))
        .unwrap();
    let fk: i64 = conn
        .query_row("pragma foreign_keys", [], |r| r.get(0))
        .unwrap();
    let busy: i64 = conn
        .query_row("pragma busy_timeout", [], |r| r.get(0))
        .unwrap();
    assert_eq!((mode.as_str(), fk, busy), ("wal", 1, 5000));
    drop(conn);

    let missing = dir.join("no/such/dir/t.sqlite");
    let err = Store::open(missing.to_str().unwrap()).err().unwrap();
    assert_eq!(
        err.to_string(),
        "triage: apply schema: unable to open database file (14)"
    );
    assert!(!dir.join("no").exists());
    // SQLite reads the path as a URI: `%41` is `A`.
    Store::open(dir.join("p%41.sqlite").to_str().unwrap()).unwrap();
    assert!(dir.join("pA.sqlite").exists());
    std::fs::remove_dir_all(dir).unwrap();
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "lodeline-manager-triage-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const TESTDATA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata");

/// A copy of the Go-written database, so the committed file stays as it is.
fn go_database(name: &str) -> (Store, PathBuf) {
    let dir = temp_dir(name);
    let path = dir.join("triage.sqlite");
    std::fs::copy(format!("{TESTDATA}/triage.sqlite"), &path).unwrap();
    (Store::open(path.to_str().unwrap()).unwrap(), dir)
}

fn json_file(path: &str) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// Checks `body` against a golden body: `EVT#n` stands for `event_id`, and each `<now@case
/// .9Z>` time for one fixed-width time, the same one wherever the golden repeats it, and later
/// for each later case.
fn assert_golden(mut body: serde_json::Value, golden: &str, event_id: &str, evt: &str) {
    fn walk(
        v: &mut serde_json::Value,
        g: &serde_json::Value,
        event_id: &str,
        evt: &str,
        times: &mut Vec<(String, String)>,
    ) {
        match (v, g) {
            (serde_json::Value::Object(m), serde_json::Value::Object(gm)) => {
                for (k, v) in m.iter_mut() {
                    if let Some(g) = gm.get(k) {
                        walk(v, g, event_id, evt, times);
                    }
                }
            }
            (serde_json::Value::Array(a), serde_json::Value::Array(ga)) => {
                for (v, g) in a.iter_mut().zip(ga) {
                    walk(v, g, event_id, evt, times);
                }
            }
            (v @ serde_json::Value::String(_), serde_json::Value::String(g)) => {
                let s = v.as_str().unwrap().to_owned();
                if s == event_id {
                    *v = evt.into();
                } else if g.starts_with("<now@") && g.ends_with(" .9Z>") {
                    assert_eq!(format_ts(&parse_ts(&s)), s, "fixed-width time {s}");
                    match times.iter().find(|(p, _)| p == g) {
                        Some((_, seen)) => assert_eq!(seen, &s, "{g}"),
                        None => times.push((g.clone(), s)),
                    }
                    *v = g.as_str().into();
                }
            }
            _ => {}
        }
    }
    let golden = json_file(&format!(
        "{}/web/tests/parity/goldens/{golden}.json",
        env!("CARGO_MANIFEST_DIR")
    ))["body"]
        .clone();
    let mut times = Vec::new();
    walk(&mut body, &golden, event_id, evt, &mut times);
    assert_eq!(body, golden, "{golden}");
    // The cases named in the placeholders ran in table order, so their times are in that order.
    let cases = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/web/tests/parity/cases.ts"
    ))
    .unwrap();
    let position = |placeholder: &str| {
        let case = placeholder
            .trim_start_matches("<now@")
            .trim_end_matches(" .9Z>");
        cases.find(&format!("'{case}'")).expect(case)
    };
    times.sort_by_key(|(p, _)| position(p));
    assert!(times.windows(2).all(|w| w[0].1 < w[1].1), "{times:?}");
}

/// The Go-written rows read back as the `triage-get` and `triage-get-bob` goldens.
#[test]
fn reads_the_go_database_as_the_goldens() {
    let recording = json_file(&format!("{TESTDATA}/recording.json"));
    let row = &recording["triage_row"];
    let (host, event) = (
        row["host_id"].as_str().unwrap(),
        row["event_id"].as_str().unwrap(),
    );
    let (s, dir) = go_database("golden");
    let body = serde_json::to_value(s.get(host, event).unwrap()).unwrap();
    assert_golden(body, row["golden"].as_str().unwrap(), event, "EVT#3");

    let (bob_host, bob_event): (String, String) = s
        .lock()
        .query_row(
            "SELECT host_id, event_id FROM triage WHERE host_id <> ?",
            [host],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let bob = s.get(&bob_host, &bob_event).unwrap();
    assert_eq!(
        bob.row.evidence_snapshot, "null",
        "Go stores a null snapshot as text"
    );
    assert_golden(
        serde_json::to_value(bob).unwrap(),
        "triage-get-bob",
        &bob_event,
        "EVT#6",
    );
    let views = s.views(&[(host.into(), event.into()), (host.into(), "missing".into())]);
    assert_eq!(views[0].as_ref().unwrap().status, "investigating");
    assert_eq!(views[1], None);
    std::fs::remove_dir_all(dir).unwrap();
}

/// Rows the Rust port writes sort among Go's rows by time, also where one time has no fraction
/// and the other has: the case Go's fixed-width layout exists for.
#[test]
fn go_and_rust_rows_sort_together_by_updated_at() {
    let (s, dir) = go_database("mixed");
    let go_rows: Vec<(String, String, String)> = {
        let conn = s.lock();
        let mut stmt = conn
            .prepare("SELECT host_id, event_id, updated_at FROM triage")
            .unwrap();
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    assert_eq!(go_rows.len(), 2);
    let (go_host, go_event, go_updated) = &go_rows[0];
    let t = parse_ts(go_updated);
    assert!(t.nanos > 0, "the Go row's time has a fraction");
    let shifted = |secs: i64, nanos: u32| GoTime {
        unix: t.unix + secs,
        nanos,
        offset: 0,
    };
    // A whole second just before and just after the Go row, and one nanosecond after it.
    for (event, at) in [
        ("rust-before", shifted(0, 0)),
        ("rust-after", shifted(1, 0)),
        (
            "rust-just-after",
            GoTime {
                nanos: t.nanos + 1,
                ..t
            },
        ),
    ] {
        insert_at(&s, go_host, event, at);
    }
    // A Rust update and notes on the Go row, before and after its Go notes.
    let update = Upsert {
        status: "resolved".into(),
        ..input(go_host, go_event)
    };
    let go_notes = s.get(go_host, go_event).unwrap().notes;
    s.append_note(go_host, go_event, "admin", "rust-first", shifted(-3600, 0))
        .unwrap();
    s.upsert(update, shifted(2, 0)).unwrap();
    s.append_note(go_host, go_event, "admin", "rust-last", shifted(2, 0))
        .unwrap();

    let conn = s.lock();
    let mut stmt = conn
        .prepare(
            "SELECT updated_at FROM triage ORDER BY updated_at DESC, host_id ASC, event_id ASC",
        )
        .unwrap();
    let sorted: Vec<String> = stmt
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    drop(stmt);
    drop(conn);
    let times: Vec<GoTime> = sorted.iter().map(|s| parse_ts(s)).collect();
    assert_eq!(times.len(), 5);
    assert!(times.windows(2).all(|w| w[0] >= w[1]), "{sorted:?}");

    let detail = s.get(go_host, go_event).unwrap();
    let bodies: Vec<&str> = detail.notes.iter().map(|n| n.body.as_str()).collect();
    let mut want = vec!["rust-first"];
    want.extend(go_notes.iter().map(|n| n.body.as_str()));
    want.push("rust-last");
    assert_eq!(bodies, want);
    assert_eq!(
        detail.log.last().unwrap().to_status.as_deref(),
        Some("resolved")
    );
    assert!(detail.log.windows(2).all(|w| w[0].at <= w[1].at));
    std::fs::remove_dir_all(dir).unwrap();
}

fn insert_at(s: &Store, host: &str, event: &str, at: GoTime) {
    let row = Upsert {
        evidence_snapshot: Some("{}".into()),
        ..input(host, event)
    };
    s.upsert(row, at).unwrap();
}

/// Go's `TestListByStatus_OrderedByUpdatedAtDesc`, on the query the schema's index serves:
/// Go's list call is not ported, as no handler used it.
#[test]
fn rows_order_by_updated_at_desc() {
    let (s, clock) = (store(), Clock::new());
    insert(&s, &clock, HOST1, EV1, snap("a"));
    insert(&s, &clock, HOST1, EV2, snap("b"));
    insert(&s, &clock, HOST2, EV3, snap("c"));
    let conn = s.lock();
    let mut stmt = conn
        .prepare("SELECT event_id FROM triage WHERE status IN ('open') ORDER BY updated_at DESC")
        .unwrap();
    let events: Vec<String> = stmt
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(events, [EV3, EV2, EV1]);
}
