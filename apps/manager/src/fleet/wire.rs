//! The fleet bodies as the console reads and relays them: Go's `internal/fleet/client.go` types.
//!
//! Go decodes each upstream body into these structs and encodes the struct again, so the SPA
//! gets Go's shape whatever the server sent: unknown fields are dropped, a missing or `null`
//! field becomes its zero value (`""`, `0`, `false`, year 1), times are re-formatted, and the
//! open-ended parts (event source, subject and evidence, AI guard scope, reasons and control
//! values) pass through as raw JSON. `lodeline-fleet-api` holds the server's own, stricter types;
//! the contract test ties the two together.

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Datelike, NaiveDate, Timelike};
use serde::de::{DeserializeOwned, Error as _};
use serde::ser::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

/// Raw JSON, Go's `json.RawMessage`: `null` when the key is missing.
pub type Raw = Value;

/// Keys whose values Go keeps as `json.RawMessage`; their contents are never normalized.
const RAW_KEYS: [&str; 6] = ["source", "subject", "evidence", "scope", "reasons", "value"];

/// Decodes `v` with Go's rules for typed fields. Go treats `null` and a missing key alike for
/// every typed field (a pointer stays nil, any other field keeps its zero value), so `null`
/// members are removed and `#[serde(default)]` fills the rest.
///
/// shortcut: a `null` element inside a typed array fails to decode, where Go stores the zero
/// value; upgrade if a server ever sends one.
pub fn go_decode<T: DeserializeOwned>(v: Value) -> serde_json::Result<T> {
    serde_json::from_value(strip_nulls(v))
}

fn strip_nulls(v: Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.into_iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| {
                    let v = if RAW_KEYS.contains(&k.as_str()) {
                        v
                    } else {
                        strip_nulls(v)
                    };
                    (k, v)
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.into_iter().map(strip_nulls).collect()),
        v => v,
    }
}

/// A Go `time.Time`: an instant plus the UTC offset it was written with, which Go keeps when it
/// encodes the value again. The default is Go's zero time, `0001-01-01T00:00:00Z`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GoTime {
    pub unix: i64,
    pub nanos: u32,
    pub offset: i32,
}

const ZERO_UNIX: i64 = -62_135_596_800;

impl Default for GoTime {
    fn default() -> Self {
        Self::from_unix(ZERO_UNIX)
    }
}

impl PartialOrd for GoTime {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Instants compare by time alone, as Go's `Before` and `After`.
impl Ord for GoTime {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.unix, self.nanos).cmp(&(other.unix, other.nanos))
    }
}

impl GoTime {
    pub fn from_unix(unix: i64) -> Self {
        Self {
            unix,
            nanos: 0,
            offset: 0,
        }
    }

    /// Go's `IsZero`: the instant of year 1, whatever the offset.
    pub fn is_zero(&self) -> bool {
        self.unix == ZERO_UNIX && self.nanos == 0
    }

    pub fn unix_millis(&self) -> i64 {
        self.unix * 1000 + i64::from(self.nanos / 1_000_000)
    }

    /// Go's `time.Parse(time.RFC3339, s)`, which also decodes JSON times (Go 1.26 turns its
    /// stricter checks off). It is laxer than RFC 3339: a one-digit hour, a `,` before the
    /// fraction, and zone offsets up to `24:60` pass; a leap second and a bad day do not.
    pub fn parse(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        let digits = |at: usize, n: usize| -> Option<u32> {
            let d = b.get(at..at + n)?;
            d.iter()
                .all(u8::is_ascii_digit)
                .then(|| d.iter().fold(0, |acc, c| acc * 10 + u32::from(c - b'0')))
        };
        let lit = |at: usize, c: u8| (b.get(at) == Some(&c)).then_some(());

        let year = digits(0, 4)?;
        lit(4, b'-')?;
        let month = digits(5, 2)?;
        lit(7, b'-')?;
        let day = digits(8, 2)?;
        lit(10, b'T')?;
        let hour_len = if b.get(12).is_some_and(u8::is_ascii_digit) {
            2
        } else {
            1
        };
        let hour = digits(11, hour_len)?;
        let mut i = 11 + hour_len;
        lit(i, b':')?;
        let min = digits(i + 1, 2)?;
        lit(i + 3, b':')?;
        let sec = digits(i + 4, 2)?;
        i += 6;
        if !(1..=12).contains(&month) || hour >= 24 || min >= 60 || sec >= 60 {
            return None;
        }

        let mut nanos = 0;
        if matches!(b.get(i), Some(b'.' | b',')) && b.get(i + 1).is_some_and(u8::is_ascii_digit) {
            let n = b[i + 1..].iter().take_while(|c| c.is_ascii_digit()).count();
            let kept = n.min(9);
            nanos = digits(i + 1, kept)? * 10u32.pow((9 - kept) as u32);
            i += 1 + n;
        }

        let offset = if lit(i, b'Z').is_some() {
            i += 1;
            0
        } else {
            let sign = match b.get(i)? {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            lit(i + 3, b':')?;
            let (hh, mm) = (digits(i + 1, 2)?, digits(i + 4, 2)?);
            if hh > 24 || mm > 60 {
                return None;
            }
            i += 6;
            sign * (hh as i32 * 3600 + mm as i32 * 60)
        };
        if i != b.len() {
            return None;
        }

        let local = NaiveDate::from_ymd_opt(year as i32, month, day)?
            .and_hms_opt(hour, min, sec)?
            .and_utc()
            .timestamp();
        Some(Self {
            unix: local - i64::from(offset),
            nanos,
            offset,
        })
    }

    fn civil(&self, offset: i32) -> chrono::NaiveDateTime {
        DateTime::from_timestamp(self.unix + i64::from(offset), self.nanos)
            .expect("in chrono's range")
            .naive_utc()
    }

    /// Go's `t.UTC().Format(time.RFC3339)`: whole seconds, `Z`.
    pub fn format_utc_seconds(&self) -> String {
        let t = self.civil(0);
        let year = t.year();
        let year = if year < 0 {
            format!("-{:04}", -year)
        } else {
            format!("{year:04}")
        };
        format!(
            "{year}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            t.month(),
            t.day(),
            t.hour(),
            t.minute(),
            t.second()
        )
    }

    /// Go's `MarshalJSON`: RFC 3339 with trailing fraction zeros dropped, in the offset the time
    /// was written with. Go refuses a year outside 0 to 9999 and an offset of 24 hours or more.
    fn marshal(&self) -> Result<String, &'static str> {
        let t = self.civil(self.offset);
        let minutes = self.offset / 60;
        if !(0..=9999).contains(&t.year()) || minutes.abs() / 60 >= 24 {
            return Err("Time.MarshalJSON: time outside the range RFC 3339 can write");
        }
        let mut s = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
            t.year(),
            t.month(),
            t.day(),
            t.hour(),
            t.minute(),
            t.second()
        );
        if self.nanos > 0 {
            s += format!(".{:09}", self.nanos).trim_end_matches('0');
        }
        if minutes == 0 {
            s.push('Z');
        } else {
            let sign = if minutes < 0 { '-' } else { '+' };
            let m = minutes.abs();
            s += &format!("{sign}{:02}:{:02}", m / 60, m % 60);
        }
        Ok(s)
    }
}

impl fmt::Display for GoTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.marshal().unwrap_or_else(|e| e.to_owned()))
    }
}

impl Serialize for GoTime {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.marshal().map_err(S::Error::custom)?)
    }
}

impl<'de> Deserialize<'de> for GoTime {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).ok_or_else(|| D::Error::custom(format!("not an RFC 3339 time: {s:?}")))
    }
}

/// `GET /v1/healthz`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Healthz {
    pub status: String,
    pub ts: GoTime,
}

/// `GET /v1/meta`. `fleet` and `audit_head` are left out when absent, as Go's `omitempty`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Meta {
    pub server_version: String,
    pub schema_version: i64,
    pub ts: GoTime,
    pub alerts_definition_default: AlertsDefinitionDefault,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fleet: Option<ActiveHosts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_head: Option<AuditHead>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ActiveHosts {
    pub active_host_count: i64,
    pub active_window_days: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditHead {
    pub seq: i64,
    pub hash: String,
    pub sig: String,
    pub pubkey_id: String,
    pub pubkey: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertsDefinitionDefault {
    pub evidence_kinds: Option<Vec<String>>,
    pub ai_guard_buckets: Option<Vec<String>>,
    pub additional_kinds: Option<Vec<String>>,
}

/// One row of `GET /v1/fleet/hosts`, and the top of `GET /v1/fleet/hosts/{host_id}`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HostSummary {
    pub host_id: String,
    pub hostname: Option<String>,
    pub agent_version: String,
    pub last_seen_ts: GoTime,
    pub status: String,
    pub current_risk: Option<CurrentRisk>,
    /// Keyed by severity, with only the keys the server sent.
    pub open_event_counts_24h: Option<BTreeMap<String, i64>>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CurrentRisk {
    pub max_score: f64,
    pub max_bucket: String,
    pub by_tool: Option<BTreeMap<String, ToolRisk>>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ToolRisk {
    pub score: f64,
    pub bucket: String,
    pub assessed_ts: GoTime,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HostsPage {
    pub hosts: Option<Vec<HostSummary>>,
    pub next_cursor: Option<String>,
    pub total_estimated: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HostDetail {
    #[serde(flatten)]
    pub summary: HostSummary,
    pub host_meta: Option<HostMeta>,
    pub policy_state: Option<PolicyState>,
    pub agent_health: Option<AgentHealth>,
    pub ai_guard: Option<AiGuard>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HostMeta {
    pub os_name: String,
    pub os_version: String,
    pub kernel_version: String,
    pub architecture: String,
    pub interfaces: Option<Vec<NetInterface>>,
    pub default_gateway_v4: Option<String>,
    pub default_gateway_v6: Option<String>,
    pub dns_servers: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetInterface {
    pub name: String,
    pub mac: String,
    pub ipv4: Option<Vec<String>>,
    pub ipv6: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicyState {
    pub last_applied_policy_version: i64,
    pub policy_expired_active: bool,
    pub last_policy_reload_ts: Option<GoTime>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentHealth {
    pub recent_channel_stalls_24h: i64,
    pub recent_watcher_degraded_24h: i64,
    pub recent_sender_lag_critical_24h: i64,
    pub last_heartbeat_ts: Option<GoTime>,
    pub hash_p99_ms_latest: Option<i64>,
    pub jsonl_above_soft_floor_latest: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AiGuard {
    pub by_tool: Option<BTreeMap<String, ToolAiGuard>>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AiGuardControl {
    pub id: String,
    pub source_path: String,
    pub setting: String,
    pub value: Raw,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ToolAiGuard {
    /// Left out when unreported; an empty list means the agent looked and found none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controls: Option<Vec<AiGuardControl>>,
    pub score: f64,
    pub bucket: String,
    pub assessed_ts: GoTime,
    pub is_reattestation: bool,
    pub scope: Raw,
    pub reasons: Option<Vec<Raw>>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RiskPage {
    pub rows: Option<Vec<RiskRow>>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RiskRow {
    pub host_id: String,
    pub hostname: Option<String>,
    pub score: f64,
    pub bucket: String,
    pub top_tool: String,
    pub reasons_count: i64,
    pub assessed_ts: GoTime,
    pub open_alert_count_24h: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CompliancePage {
    pub rows: Option<Vec<ComplianceRow>>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ComplianceRow {
    pub host_id: String,
    pub hostname: Option<String>,
    pub last_applied_policy_version: i64,
    pub server_current_policy_version: i64,
    pub version_drift: i64,
    pub policy_expired_active: bool,
    pub last_policy_reload_ts: Option<GoTime>,
    pub signature_failures_24h: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct EventsPage {
    pub events: Option<Vec<Event>>,
    pub next_cursor: Option<String>,
}

/// One stored event. Its top-level fields are typed as Go's `fleet.Event`; the open-ended parts
/// stay raw, so an evidence kind the console does not know keeps its payload.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Event {
    pub schema_version: i64,
    pub event_id: String,
    pub ts: GoTime,
    pub host_id: String,
    pub agent_version: String,
    pub severity: String,
    pub source: Raw,
    pub subject: Raw,
    #[serde(deserialize_with = "evidence")]
    pub evidence: Raw,
    pub target_id: Option<String>,
}

impl Event {
    /// `evidence.kind`, or `""`.
    pub fn evidence_kind(&self) -> &str {
        self.evidence["kind"].as_str().unwrap_or_default()
    }
}

/// Go's `Evidence.UnmarshalJSON`: an object whose `kind`, if present, is a string.
fn evidence<'de, D: Deserializer<'de>>(d: D) -> Result<Raw, D::Error> {
    let v = Value::deserialize(d)?;
    match &v {
        Value::Object(m) if matches!(m.get("kind"), None | Some(Value::String(_))) => Ok(v),
        _ => Err(D::Error::custom(
            "fleet: evidence: not an object with a string kind",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_and_refuses_what_go_time_parse_does() {
        for (s, want) in [
            ("2026-01-01T00:00:00Z", Some("2026-01-01T00:00:00Z")),
            ("2026-01-01T00:00:00,5Z", Some("2026-01-01T00:00:00.5Z")),
            (
                "2026-01-01T00:00:00.123456789123Z",
                Some("2026-01-01T00:00:00.123456789Z"),
            ),
            ("2026-01-01T00:00:00-00:00", Some("2026-01-01T00:00:00Z")),
            (
                "2026-01-02T00:00:00+09:00",
                Some("2026-01-02T00:00:00+09:00"),
            ),
            ("2026-01-01T1:00:00Z", Some("2026-01-01T01:00:00Z")),
            ("2024-02-29T00:00:00Z", Some("2024-02-29T00:00:00Z")),
            ("2026-01-01t00:00:00Z", None),
            ("2026-01-01T00:00:00z", None),
            ("2026-01-01T00:00:00+0900", None),
            ("2026-01-01 00:00:00Z", None),
            ("2026-01-01T23:59:60Z", None),
            ("2026-01-01T00:00Z", None),
            ("2026-02-30T00:00:00Z", None),
            ("2026-13-01T00:00:00Z", None),
            ("2026-01-01T00:00:00+25:00", None),
            ("2026-01-01T00:00:00.Z", None),
            ("2026-01-01T00:00:00Zjunk", None),
            ("yesterday", None),
            ("2026-01-01", None),
        ] {
            assert_eq!(
                GoTime::parse(s).map(|t| t.to_string()),
                want.map(String::from),
                "{s}"
            );
        }
        let day = GoTime::parse("2026-01-01T00:00:00,5+24:00").unwrap();
        assert_eq!(day.format_utc_seconds(), "2025-12-31T00:00:00Z");
        assert!(day.marshal().is_err(), "Go cannot encode a 24 h offset");
        assert!(GoTime::default().is_zero());
        assert_eq!(GoTime::default().to_string(), "0001-01-01T00:00:00Z");
    }

    #[test]
    fn decoding_follows_go_for_missing_null_and_unknown_fields() {
        let page: HostsPage = go_decode(serde_json::json!({
            "hosts": [{"host_id": "h", "hostname": null, "status": null, "extra": 1,
                "open_event_counts_24h": {"warn": 2}}],
            "added_later": true
        }))
        .unwrap();
        let out = serde_json::to_value(&page).unwrap();
        assert_eq!(
            out,
            serde_json::json!({"hosts": [{"agent_version": "", "current_risk": null,
                "host_id": "h", "hostname": null, "last_seen_ts": "0001-01-01T00:00:00Z",
                "open_event_counts_24h": {"warn": 2}, "status": ""}],
                "next_cursor": null, "total_estimated": 0})
        );

        let ev: Event = go_decode(serde_json::json!({
            "event_id": "e", "evidence": {"kind": "x", "inner": null}, "subject": null
        }))
        .unwrap();
        assert_eq!(ev.evidence, serde_json::json!({"kind": "x", "inner": null}));
        assert_eq!(ev.subject, Value::Null);
        for bad in [
            serde_json::json!({"evidence": "text"}),
            serde_json::json!({"evidence": {"kind": 5}}),
            serde_json::json!({"schema_version": 1.5}),
            serde_json::json!({"ts": 5}),
        ] {
            assert!(go_decode::<Event>(bad.clone()).is_err(), "{bad}");
        }
    }
}
