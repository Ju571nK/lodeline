//! The console's own SQLite store of alert triage state, Go's `internal/triage`: one row per
//! `(host_id, event_id)` with its status, assignee and the event as it was when triage began,
//! plus notes and a log of status changes. `lodeline-server` never reads or writes it.
//!
//! The file format is Go's: the same schema, pragmas and timestamp text, so a database written
//! by the Go build opens here and the two builds' rows sort together.

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Transaction};
use serde::ser::Error as _;
use serde::{Serialize, Serializer};
use serde_json::value::RawValue;

use crate::config;
use crate::fleet::GoTime;

/// Go's `schemaSQL`, verbatim. It runs on every open; there is no version table.
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS triage (
  host_id           TEXT NOT NULL,
  event_id          TEXT NOT NULL,
  status            TEXT NOT NULL CHECK(status IN
                    ('open','acknowledged','investigating','resolved')),
  assignee          TEXT,
  evidence_snapshot TEXT NOT NULL,
  created_at        TEXT NOT NULL,
  updated_at        TEXT NOT NULL,
  PRIMARY KEY (host_id, event_id)
);

CREATE INDEX IF NOT EXISTS triage_status_idx
  ON triage(status, updated_at DESC);

CREATE TABLE IF NOT EXISTS triage_notes (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  host_id    TEXT NOT NULL,
  event_id   TEXT NOT NULL,
  author     TEXT NOT NULL,
  body       TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (host_id, event_id) REFERENCES triage(host_id, event_id)
);

CREATE INDEX IF NOT EXISTS triage_notes_event_idx
  ON triage_notes(host_id, event_id, created_at);

CREATE TABLE IF NOT EXISTS triage_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  host_id     TEXT NOT NULL,
  event_id    TEXT NOT NULL,
  actor       TEXT NOT NULL,
  from_status TEXT,
  to_status   TEXT,
  at          TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS triage_log_event_idx
  ON triage_log(host_id, event_id, at);
";

/// The values the schema's CHECK accepts.
pub const STATUSES: [&str; 4] = ["open", "acknowledged", "investigating", "resolved"];

const ROW_COLUMNS: &str =
    "host_id, event_id, status, assignee, evidence_snapshot, created_at, updated_at";

#[derive(Debug, PartialEq)]
pub enum Error {
    NotFound,
    InvalidStatus(String),
    MissingFields(&'static str),
    /// A database failure, with Go's `triage: <step>:` prefix.
    Db(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NotFound => f.write_str("triage: not found"),
            Error::InvalidStatus(s) => write!(f, "triage: invalid status: {s:?}"),
            Error::MissingFields(which) => write!(f, "triage: missing required fields: {which}"),
            Error::Db(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for Error {}

fn db(step: &'static str) -> impl Fn(rusqlite::Error) -> Error {
    move |e| Error::Db(format!("triage: {step}: {}", sqlite_text(&e)))
}

/// SQLite's message with the result code after it, as modernc.org/sqlite words its errors.
///
/// shortcut: where SQLite's message differs from the code's generic text, Go puts the generic
/// text first (`constraint failed: FOREIGN KEY constraint failed (787)`); this keeps only the
/// message. Only 500 bodies and startup errors show it.
fn sqlite_text(e: &rusqlite::Error) -> String {
    let rusqlite::Error::SqliteFailure(f, msg) = e else {
        return e.to_string();
    };
    let msg = msg.as_deref().unwrap_or_default();
    // rusqlite appends the path to an open failure; Go's text has none.
    let msg = msg.split_once(": file:").map_or(msg, |(m, _)| m);
    let busy = if f.extended_code == rusqlite::ffi::SQLITE_BUSY {
        " (SQLITE_BUSY)"
    } else {
        ""
    };
    format!("{msg} ({}){busy}", f.extended_code)
}

/// One `triage` row. The snapshot is the JSON text exactly as the client sent it.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Row {
    pub host_id: String,
    pub event_id: String,
    pub status: String,
    pub assignee: Option<String>,
    #[serde(serialize_with = "go_raw")]
    pub evidence_snapshot: String,
    #[serde(serialize_with = "fixed_width")]
    pub created_at: GoTime,
    #[serde(serialize_with = "fixed_width")]
    pub updated_at: GoTime,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Note {
    pub id: i64,
    pub host_id: String,
    pub event_id: String,
    pub author: String,
    pub body: String,
    #[serde(serialize_with = "fixed_width")]
    pub created_at: GoTime,
}

/// One status change. `from_status` is `None` for the insert.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct LogEntry {
    pub id: i64,
    pub actor: String,
    pub from_status: Option<String>,
    pub to_status: Option<String>,
    #[serde(serialize_with = "fixed_width")]
    pub at: GoTime,
}

/// A row with its notes and log, oldest first: `GET /api/v1/triage/{host_id}/{event_id}`.
#[derive(Debug, PartialEq, Serialize)]
pub struct Detail {
    pub row: Row,
    pub notes: Vec<Note>,
    pub log: Vec<LogEntry>,
}

/// The triage state the alerts queue shows beside each event. Unlike the triage routes, Go
/// encodes this time as a plain `time.Time`, which drops trailing fraction zeros.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct View {
    pub status: String,
    pub assignee: Option<String>,
    pub updated_at: GoTime,
}

/// What `upsert` changes. On insert the snapshot is required and an empty status means `open`.
/// On update an empty status, `None` assignee and `None` snapshot leave the row as it is, and
/// the snapshot is never changed.
#[derive(Clone, Debug, Default)]
pub struct Upsert {
    pub host_id: String,
    pub event_id: String,
    pub status: String,
    pub assignee: Option<String>,
    pub clear_assignee: bool,
    pub evidence_snapshot: Option<String>,
    /// The session subject, recorded in the log.
    pub actor: String,
}

/// One connection, as Go's pool of one: SQLite has a single writer.
pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    /// Go's `triage.Open`. A plain path becomes the same `file:` URI with the same pragmas, so
    /// SQLite reads `%`, `?` and `#` in it the same way. The parent directory is not created,
    /// and a new file gets SQLite's default mode, as in Go.
    pub fn open(path: &str) -> Result<Self, Error> {
        let dsn = if path.starts_with("file:") || path == ":memory:" {
            path.to_owned()
        } else {
            format!("file:{path}?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
        };
        // Go opens lazily, so any failure here surfaces when it applies the schema.
        let fail = |e: String| Error::Db(format!("triage: apply schema: {e}"));
        let sqlite = |e: rusqlite::Error| fail(sqlite_text(&e));
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_FULL_MUTEX
            | OpenFlags::SQLITE_OPEN_URI;
        let conn = Connection::open_with_flags(&dsn, flags).map_err(sqlite)?;
        for pragma in dsn_pragmas(&dsn).map_err(fail)? {
            let mut stmt = conn.prepare(&format!("pragma {pragma}")).map_err(sqlite)?;
            let mut rows = stmt.query([]).map_err(sqlite)?;
            while rows.next().map_err(sqlite)?.is_some() {}
        }
        conn.execute_batch(SCHEMA).map_err(sqlite)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        // A panic mid-transaction rolled it back when the transaction dropped.
        self.conn.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Go's `Repo.Upsert`: inserts or updates the row and logs a status change, in one
    /// transaction. `updated_at` moves on every update, also when nothing else changes.
    pub fn upsert(&self, input: Upsert, now: GoTime) -> Result<Row, Error> {
        if input.host_id.is_empty() || input.event_id.is_empty() || input.actor.is_empty() {
            return Err(Error::MissingFields("HostID/EventID/Actor"));
        }
        if !input.status.is_empty() && !STATUSES.contains(&input.status.as_str()) {
            return Err(Error::InvalidStatus(input.status));
        }
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(db("begin"))?;
        let row = match get_row(&tx, &input.host_id, &input.event_id)? {
            None => {
                let snapshot = input
                    .evidence_snapshot
                    .filter(|s| !s.is_empty())
                    .ok_or(Error::MissingFields("EvidenceSnapshot required on insert"))?;
                let status = if input.status.is_empty() {
                    STATUSES[0].to_owned()
                } else {
                    input.status
                };
                let row = Row {
                    host_id: input.host_id,
                    event_id: input.event_id,
                    status,
                    assignee: input.assignee,
                    evidence_snapshot: snapshot,
                    created_at: now,
                    updated_at: now,
                };
                tx.execute(
                    "INSERT INTO triage (host_id, event_id, status, assignee, evidence_snapshot, created_at, updated_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?)",
                    params![
                        row.host_id,
                        row.event_id,
                        row.status,
                        row.assignee,
                        row.evidence_snapshot,
                        format_ts(&now),
                        format_ts(&now)
                    ],
                )
                .map_err(db("insert"))?;
                append_log(&tx, &row, &input.actor, None, now)?;
                row
            }
            Some(mut row) => {
                let from = (!input.status.is_empty() && input.status != row.status)
                    .then(|| std::mem::replace(&mut row.status, input.status));
                if input.clear_assignee {
                    row.assignee = None;
                } else if input.assignee.is_some() {
                    row.assignee = input.assignee;
                }
                row.updated_at = now;
                tx.execute(
                    "UPDATE triage SET status = ?, assignee = ?, updated_at = ?
                     WHERE host_id = ? AND event_id = ?",
                    params![
                        row.status,
                        row.assignee,
                        format_ts(&now),
                        row.host_id,
                        row.event_id
                    ],
                )
                .map_err(db("update"))?;
                if let Some(from) = from {
                    append_log(&tx, &row, &input.actor, Some(&from), now)?;
                }
                row
            }
        };
        tx.commit().map_err(db("commit"))?;
        Ok(row)
    }

    /// Go's `Repo.AppendNote`: a note on an existing row.
    pub fn append_note(
        &self,
        host_id: &str,
        event_id: &str,
        author: &str,
        body: &str,
        now: GoTime,
    ) -> Result<Note, Error> {
        if [host_id, event_id, author, body]
            .iter()
            .any(|s| s.is_empty())
        {
            return Err(Error::MissingFields("hostID/eventID/author/body"));
        }
        let conn = self.lock();
        get_row(&conn, host_id, event_id)?.ok_or(Error::NotFound)?;
        conn.execute(
            "INSERT INTO triage_notes (host_id, event_id, author, body, created_at)
             VALUES (?, ?, ?, ?, ?)",
            params![host_id, event_id, author, body, format_ts(&now)],
        )
        .map_err(db("insert note"))?;
        Ok(Note {
            id: conn.last_insert_rowid(),
            host_id: host_id.to_owned(),
            event_id: event_id.to_owned(),
            author: author.to_owned(),
            body: body.to_owned(),
            created_at: now,
        })
    }

    /// The row with its notes and log, Go's `GetByEventKey`, `ListNotes` and `ListLog`.
    pub fn get(&self, host_id: &str, event_id: &str) -> Result<Detail, Error> {
        let conn = self.lock();
        let row = get_row(&conn, host_id, event_id)?.ok_or(Error::NotFound)?;
        let key = params![host_id, event_id];
        let notes = conn
            .prepare(
                "SELECT id, host_id, event_id, author, body, created_at
                 FROM triage_notes
                 WHERE host_id = ? AND event_id = ?
                 ORDER BY created_at ASC, id ASC",
            )
            .and_then(|mut stmt| {
                stmt.query_map(key, |r| {
                    Ok(Note {
                        id: r.get(0)?,
                        host_id: r.get(1)?,
                        event_id: r.get(2)?,
                        author: r.get(3)?,
                        body: r.get(4)?,
                        created_at: parse_ts(&r.get::<_, String>(5)?),
                    })
                })?
                .collect()
            })
            .map_err(db("list notes"))?;
        let log = conn
            .prepare(
                "SELECT id, actor, from_status, to_status, at
                 FROM triage_log
                 WHERE host_id = ? AND event_id = ?
                 ORDER BY at ASC, id ASC",
            )
            .and_then(|mut stmt| {
                stmt.query_map(key, |r| {
                    Ok(LogEntry {
                        id: r.get(0)?,
                        actor: r.get(1)?,
                        from_status: r.get(2)?,
                        to_status: r.get(3)?,
                        at: parse_ts(&r.get::<_, String>(4)?),
                    })
                })?
                .collect()
            })
            .map_err(db("list log"))?;
        Ok(Detail { row, notes, log })
    }

    /// The view of each `(host_id, event_id)`. A missing row or a read error gives `None`, as Go
    /// drops lookup errors so that the queue still loads.
    pub fn views(&self, keys: &[(String, String)]) -> Vec<Option<View>> {
        let conn = self.lock();
        keys.iter()
            .map(|(host, event)| {
                let row = get_row(&conn, host, event).ok().flatten()?;
                Some(View {
                    status: row.status,
                    assignee: row.assignee,
                    updated_at: row.updated_at,
                })
            })
            .collect()
    }
}

fn get_row(conn: &Connection, host_id: &str, event_id: &str) -> Result<Option<Row>, Error> {
    conn.query_row(
        &format!("SELECT {ROW_COLUMNS} FROM triage WHERE host_id = ? AND event_id = ?"),
        params![host_id, event_id],
        |r| {
            Ok(Row {
                host_id: r.get(0)?,
                event_id: r.get(1)?,
                status: r.get(2)?,
                assignee: r.get(3)?,
                evidence_snapshot: r.get(4)?,
                created_at: parse_ts(&r.get::<_, String>(5)?),
                updated_at: parse_ts(&r.get::<_, String>(6)?),
            })
        },
    )
    .optional()
    .map_err(db("scan"))
}

fn append_log(
    tx: &Transaction,
    row: &Row,
    actor: &str,
    from: Option<&str>,
    at: GoTime,
) -> Result<(), Error> {
    tx.execute(
        "INSERT INTO triage_log (host_id, event_id, actor, from_status, to_status, at)
         VALUES (?, ?, ?, ?, ?, ?)",
        params![
            row.host_id,
            row.event_id,
            actor,
            from,
            row.status,
            format_ts(&at)
        ],
    )
    .map_err(db("insert log"))?;
    Ok(())
}

/// The `_pragma` values modernc.org/sqlite runs from the query of a DSN: `busy_timeout` first,
/// then the rest sorted without regard to case. A query `url.ParseQuery` refuses fails the open.
fn dsn_pragmas(dsn: &str) -> Result<Vec<String>, String> {
    let Some((_, query)) = dsn.split_once('?').filter(|(name, _)| !name.is_empty()) else {
        return Ok(Vec::new());
    };
    let decode = |s: &str| {
        config::unescape(&s.replace('+', " "))
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .ok_or_else(|| format!("invalid URL escape in {s:?}"))
    };
    let mut pragmas = Vec::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        if pair.contains(';') {
            return Err("invalid semicolon separator in query".into());
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let (key, value) = (decode(key)?, decode(value)?);
        if key == "_pragma" {
            pragmas.push(value);
        }
    }
    pragmas.sort_by_key(|p| {
        let p = p.trim().to_lowercase();
        (!p.starts_with("busy_timeout"), p)
    });
    Ok(pragmas)
}

pub fn now() -> GoTime {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    GoTime {
        unix: d.as_secs() as i64,
        nanos: d.subsec_nanos(),
        offset: 0,
    }
}

/// Go's `tsLayout`, `2006-01-02T15:04:05.000000000Z07:00` in UTC. The fixed width makes text
/// order match time order; with trailing zeros dropped, `12:00:00Z` sorts after
/// `12:00:00.001Z`.
pub fn format_ts(t: &GoTime) -> String {
    let secs = t.format_utc_seconds();
    format!("{}.{:09}Z", &secs[..secs.len() - 1], t.nanos)
}

/// Go's `parseTS`: any RFC 3339 form, in UTC; text that does not parse reads as year 1.
pub fn parse_ts(s: &str) -> GoTime {
    GoTime::parse(s)
        .map(|t| GoTime { offset: 0, ..t })
        .unwrap_or_default()
}

fn fixed_width<S: Serializer>(t: &GoTime, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&format_ts(t))
}

/// Go encodes a `json.RawMessage` compacted, with `<`, `>`, `&`, U+2028 and U+2029 escaped, and
/// fails the whole body when the text is not JSON.
fn go_raw<S: Serializer>(text: &str, s: S) -> Result<S::Ok, S::Error> {
    RawValue::from_string(go_compact(text))
        .map_err(S::Error::custom)?
        .serialize(s)
}

/// Go's `appendCompact` with HTML escaping: whitespace outside strings is dropped, and number
/// spelling and string escapes are kept as written.
pub fn go_compact(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let (mut in_string, mut escaped) = (false, false);
    for c in text.chars() {
        match c {
            '<' | '>' | '&' | '\u{2028}' | '\u{2029}' => {
                out += &format!("\\u{:04x}", c as u32);
                continue;
            }
            ' ' | '\t' | '\n' | '\r' if !in_string => continue,
            _ => out.push(c),
        }
        if in_string {
            match (escaped, c) {
                (true, _) => escaped = false,
                (false, '\\') => escaped = true,
                (false, '"') => in_string = false,
                _ => {}
            }
        } else if c == '"' {
            in_string = true;
        }
    }
    out
}

#[cfg(test)]
mod tests;
