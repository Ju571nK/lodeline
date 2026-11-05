//! The fleet bodies as the console reads and relays them: Go's `internal/fleet/client.go` types.
//!
//! Go decodes each upstream body into these structs and encodes the struct again, so the SPA
//! gets Go's shape whatever the server sent: unknown fields are dropped, a missing or `null`
//! field becomes its zero value (`""`, `0`, `false`, year 1), times are re-formatted, and the
//! open-ended parts (event source, subject and evidence, AI guard scope, score source, reasons
//! and control values) pass through as raw JSON. `lodeline-fleet-api` holds the server's own,
//! stricter types; the contract test ties the two together.

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Datelike, NaiveDate, Timelike};
use serde::de::{DeserializeOwned, Error as _};
use serde::ser::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::value::RawValue;

/// Raw JSON, Go's `json.RawMessage`: the server's text, relayed as written, so key order and
/// number spelling survive and a number past `f64` does not fail the decode. `null` when the key
/// is missing.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Raw(Box<RawValue>);

impl Default for Raw {
    fn default() -> Self {
        Self(RawValue::NULL.to_owned())
    }
}

impl PartialEq for Raw {
    fn eq(&self, other: &Self) -> bool {
        self.0.get() == other.0.get()
    }
}

impl Raw {
    /// The string member `key` of an object, or `""`.
    pub fn member_str(&self, key: &str) -> String {
        members(self.0.get())
            .ok()
            .and_then(|m| serde_json::from_str(m.get(key)?.get()).ok())
            .unwrap_or_default()
    }
}

/// An object's members, the last of repeated keys kept, as Go and `serde_json::Value` read them.
/// The values stay text, so their numbers are never parsed.
fn members(text: &str) -> serde_json::Result<BTreeMap<String, Box<RawValue>>> {
    serde_json::from_str(text)
}

/// Keys whose values Go keeps as `json.RawMessage`; their contents are never normalized.
const RAW_KEYS: [&str; 6] = ["source", "subject", "evidence", "scope", "reasons", "value"];

/// Float fields. Every other number the console decodes is an integer.
const FLOAT_KEYS: [&str; 2] = ["score", "max_score"];

/// The most levels a body may nest, raw values included: one more than its deepest array or
/// object, empty or not. That is the 127 nested arrays and objects `serde_json::Value` allows,
/// the bound this decode had when it parsed the whole body into one.
const MAX_DEPTH: usize = 128;

/// Decodes `json` with Go's rules for typed fields. Go treats `null` and a missing key alike for
/// every typed field (a pointer stays nil, any other field keeps its zero value), so `null`
/// members are removed and `#[serde(default)]` fills the rest. A `null` map entry is kept as the
/// value type's zero value, as Go stores it. Go reads `-0` into an integer as 0, where serde
/// reads it as a float, so `-0` outside a float field becomes 0. A number past `f64` in a typed
/// field fails the decode, as in Go. A body nested past `MAX_DEPTH`, raw values included, fails
/// the decode.
///
/// shortcut: a `null` element inside a typed array fails to decode, where Go stores the zero
/// value; and `-0.0` or `-0e0` in an integer field decodes as 0, where Go refuses it. Upgrade if
/// a server ever sends one.
pub fn go_decode<T: DeserializeOwned>(json: &RawValue) -> serde_json::Result<T> {
    serde_json::from_str(&normalize(json, false, MAX_DEPTH)?)
}

fn normalize(v: &RawValue, float: bool, depth: usize) -> serde_json::Result<String> {
    let text = v.get();
    let first = text.as_bytes().first();
    // As in `levels`, an array or object takes a level below it even when it is empty.
    if depth < 1 + usize::from(matches!(first, Some(b'{' | b'['))) {
        return Err(too_deep());
    }
    let depth = depth - 1;
    Ok(match first {
        Some(b'{') => object(text, None, |k, v| {
            if RAW_KEYS.contains(&k) {
                if levels(v.get()) > depth {
                    return Err(too_deep());
                }
                Ok(v.get().to_owned())
            } else if let Some(zero) = map_zero(k) {
                normalize_map(v, zero, depth)
            } else {
                normalize(v, FLOAT_KEYS.contains(&k), depth)
            }
        })?,
        Some(b'[') => {
            let items: Vec<Box<RawValue>> = serde_json::from_str(text)?;
            let items: Vec<String> = items
                .iter()
                .map(|v| normalize(v, false, depth))
                .collect::<serde_json::Result<_>>()?;
            format!("[{}]", items.join(","))
        }
        Some(b'-') if !float && text.parse::<f64>().is_ok_and(|f| f == 0.0) => "0".to_owned(),
        _ => text.to_owned(),
    })
}

fn too_deep() -> serde_json::Error {
    <serde_json::Error as serde::de::Error>::custom("recursion limit exceeded")
}

/// The levels `normalize` would count in `text`, which is valid JSON, as `serde_json::Value`
/// bounds them: one more than the deepest array or object, empty or not. A single pass with no
/// recursion, so it measures any nesting safely.
fn levels(text: &str) -> usize {
    let (mut depth, mut max) = (0, 0);
    let mut bytes = text.bytes();
    while let Some(b) = bytes.next() {
        match b {
            b'{' | b'[' => {
                depth += 1;
                max = max.max(depth);
            }
            b'}' | b']' => depth -= 1,
            b'"' => {
                while let Some(b) = bytes.next() {
                    match b {
                        b'\\' => _ = bytes.next(),
                        b'"' => break,
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    max + 1
}

/// The object `text` written again with each member's value mapped by `f`. A `null` member is
/// dropped, or written as `null_as` when one is given.
fn object(
    text: &str,
    null_as: Option<&str>,
    f: impl Fn(&str, &RawValue) -> serde_json::Result<String>,
) -> serde_json::Result<String> {
    let mut out = Vec::new();
    for (k, v) in members(text)? {
        let v = match (v.get(), null_as) {
            ("null", None) => continue,
            ("null", Some(zero)) => zero.to_owned(),
            _ => f(&k, &v)?,
        };
        out.push(format!("{}:{v}", serde_json::to_string(&k)?));
    }
    Ok(format!("{{{}}}", out.join(",")))
}

/// The zero value Go stores for a `null` entry of each map field.
fn map_zero(key: &str) -> Option<&'static str> {
    match key {
        "open_event_counts_24h" => Some("0"),
        "by_tool" => Some("{}"),
        _ => None,
    }
}

fn normalize_map(v: &RawValue, zero: &str, depth: usize) -> serde_json::Result<String> {
    if v.get().starts_with('{') {
        object(v.get(), Some(zero), |_, v| normalize(v, false, depth))
    } else {
        normalize(v, false, depth)
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
        let err = "Time.MarshalJSON: time outside the range RFC 3339 can write";
        // Past chrono's range is past year 9999 too.
        let t =
            DateTime::from_timestamp(self.unix.saturating_add(i64::from(self.offset)), self.nanos)
                .ok_or(err)?
                .naive_utc();
        let minutes = self.offset / 60;
        if !(0..=9999).contains(&t.year()) || minutes.abs() / 60 >= 24 {
            return Err(err);
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
    /// Failing AI Guard sources per tool. Left out when none fails or the server predates it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_guard_unassessed: Option<BTreeMap<String, ToolUnassessed>>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ToolUnassessed {
    pub since: GoTime,
    pub last_assessed_ts: Option<GoTime>,
    pub sources: Vec<UnassessedSource>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct UnassessedSource {
    pub scope: Raw,
    pub user: Option<String>,
    pub rule_pack_id: Option<String>,
    pub error_kind: String,
    pub path: String,
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
    /// Relayed as written, so a missing `source` (an older server) stays distinct from one with
    /// `user: null`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<Raw>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unassessed_since: Option<GoTime>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HostsPage {
    pub hosts: Option<Vec<HostSummary>>,
    pub next_cursor: Option<String>,
    pub total_estimated: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct HostDetail {
    #[serde(flatten)]
    pub summary: HostSummary,
    pub host_meta: Option<HostMeta>,
    pub policy_state: Option<PolicyState>,
    pub agent_health: Option<AgentHealth>,
    pub ai_guard: Option<AiGuard>,
}

/// The detail blocks of a host body. `HostDetail` reads them and the summary from the same text,
/// because `flatten` would buffer the summary's members in a form a `Raw` cannot be read from.
#[derive(Deserialize)]
struct DetailBlocks {
    host_meta: Option<HostMeta>,
    policy_state: Option<PolicyState>,
    agent_health: Option<AgentHealth>,
    ai_guard: Option<AiGuard>,
}

impl<'de> Deserialize<'de> for HostDetail {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = Raw::deserialize(d)?;
        let DetailBlocks {
            host_meta,
            policy_state,
            agent_health,
            ai_guard,
        } = serde_json::from_str(text.0.get()).map_err(D::Error::custom)?;
        Ok(Self {
            summary: serde_json::from_str(text.0.get()).map_err(D::Error::custom)?,
            host_meta,
            policy_state,
            agent_health,
            ai_guard,
        })
    }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<Raw>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unassessed_since: Option<GoTime>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<Raw>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unassessed_since: Option<GoTime>,
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
    pub fn evidence_kind(&self) -> String {
        self.evidence.member_str("kind")
    }
}

/// Go's `Evidence.UnmarshalJSON`: an object whose `kind`, if present, is a string or `null`.
fn evidence<'de, D: Deserializer<'de>>(d: D) -> Result<Raw, D::Error> {
    let raw = Raw::deserialize(d)?;
    let kind_ok = |m: BTreeMap<String, Box<RawValue>>| {
        m.get("kind")
            .is_none_or(|k| serde_json::from_str::<Option<String>>(k.get()).is_ok())
    };
    if members(raw.0.get()).is_ok_and(kind_ok) {
        Ok(raw)
    } else {
        Err(D::Error::custom(
            "fleet: evidence: not an object with a string kind",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode<T: DeserializeOwned>(json: impl ToString) -> serde_json::Result<T> {
        go_decode(&serde_json::from_str::<Box<RawValue>>(&json.to_string()).unwrap())
    }

    fn text(raw: &Raw) -> &str {
        raw.0.get()
    }

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
        let page: HostsPage = decode(serde_json::json!({
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

        let ev: Event = decode(
            r#"{"event_id": "e", "evidence": {"kind": "x", "inner": null, "n": 1e400}, "subject": null}"#,
        )
        .unwrap();
        assert_eq!(
            text(&ev.evidence),
            r#"{"kind": "x", "inner": null, "n": 1e400}"#
        );
        assert_eq!(text(&ev.subject), "null");
        assert_eq!(ev.evidence_kind(), "x");
        let ev: Event = decode(r#"{"evidence": {"kind": null}}"#).unwrap();
        assert_eq!(text(&ev.evidence), r#"{"kind": null}"#);
        assert_eq!(ev.evidence_kind(), "");
        for bad in [
            r#"{"evidence": "text"}"#,
            r#"{"evidence": {"kind": 5}}"#,
            r#"{"schema_version": 1.5}"#,
            r#"{"ts": 5}"#,
            // Typed fields are parsed: a number past f64 fails the body, as in Go.
            r#"{"schema_version": 1e400}"#,
        ] {
            assert!(decode::<Event>(bad).is_err(), "{bad}");
        }
        assert!(decode::<HostDetail>(r#"{"current_risk": {"max_score": 1e400}}"#).is_err());
    }

    /// A missing `source` stays missing and one with `user: null` keeps it, so the SPA can tell an
    /// older server from the agent's own home. Unassessed times are read as times.
    #[test]
    fn score_source_and_unassessed_fields_pass_through() {
        let body = r#"{"current_risk": {"max_score": 2, "max_bucket": "medium", "by_tool": {
                "codex": {"score": 2, "bucket": "medium", "assessed_ts": "2026-01-01T00:00:00Z",
                    "source": {"scope": {"kind": "user_global"}, "user": null,
                        "rule_pack_id": null, "tool_label": null},
                    "unassessed_since": "2026-01-01T00:05:00.500+09:00"},
                "gemini": {"score": 1, "bucket": "medium", "assessed_ts": "2026-01-01T00:00:00Z"}}},
            "ai_guard_unassessed": {"cursor": {"since": "2026-01-01T00:01:00Z",
                "last_assessed_ts": null, "sources": [{"scope": {"kind": "user_global"},
                    "user": "bob", "rule_pack_id": null, "error_kind": "parse",
                    "path": "/home/bob/.cursor/mcp.json"}]}}}"#;
        let host: HostSummary = decode(body).unwrap();
        let out = serde_json::to_value(&host).unwrap();
        let by_tool = &out["current_risk"]["by_tool"];
        let codex = host
            .current_risk
            .as_ref()
            .unwrap()
            .by_tool
            .as_ref()
            .unwrap()["codex"]
            .clone();
        assert_eq!(
            text(codex.source.as_ref().unwrap()),
            r#"{"scope": {"kind": "user_global"}, "user": null,
                        "rule_pack_id": null, "tool_label": null}"#
        );
        assert_eq!(
            by_tool["codex"]["unassessed_since"],
            "2026-01-01T00:05:00.5+09:00"
        );
        assert!(by_tool["gemini"].get("source").is_none());
        assert!(by_tool["gemini"].get("unassessed_since").is_none());
        assert_eq!(
            out["ai_guard_unassessed"]["cursor"],
            serde_json::json!({"since": "2026-01-01T00:01:00Z", "last_assessed_ts": null,
                "sources": [{"scope": {"kind": "user_global"}, "user": "bob",
                    "rule_pack_id": null, "error_kind": "parse",
                    "path": "/home/bob/.cursor/mcp.json"}]})
        );
        let older: HostSummary = decode(r#"{"ai_guard_unassessed": null}"#).unwrap();
        assert!(serde_json::to_value(&older)
            .unwrap()
            .get("ai_guard_unassessed")
            .is_none());
    }

    /// Raw and typed values share one nesting limit: the one `serde_json::Value` set when this
    /// decode parsed the whole body into it.
    #[test]
    fn nesting_is_bounded_under_raw_and_typed_keys() {
        // `n` arrays and objects under `x`, the deepest holding a scalar or nothing.
        let body = |key: &str, n: usize, end: &str| {
            let n = if end == "1" { n } else { n - 1 };
            let (open, close) = ("[".repeat(n), "]".repeat(n));
            format!(r#"{{"{key}":{{"kind":"k","x":{open}{end}{close}}}}}"#)
        };
        for key in ["evidence", "unknown"] {
            for end in ["1", "[]", "{}"] {
                for (n, ok) in [(125, true), (126, false), (100_000, false)] {
                    let body = body(key, n, end);
                    let as_value = serde_json::from_str::<serde_json::Value>(&body);
                    assert_eq!(as_value.is_ok(), ok, "{key} {end} at {n} as Value");
                    assert_eq!(decode::<Event>(body).is_ok(), ok, "{key} {end} at {n}");
                }
            }
        }
        // Brackets inside strings, escaped quotes included, are text, not nesting.
        let brackets = format!(
            r#"{{"evidence":{{"kind":"\"{}","x":[]}}}}"#,
            "[{".repeat(200)
        );
        assert!(decode::<Event>(brackets).is_ok());
    }

    /// A `null` map entry is the value type's zero value, and `-0` is 0 in an integer field and
    /// stays `-0` in a float field, as Go decodes them.
    #[test]
    fn decoding_follows_go_for_null_map_entries_and_minus_zero() {
        let body = r#"{"schema_version": -0, "open_event_counts_24h": {"warn": null, "info": -0},
            "current_risk": {"max_score": -0, "by_tool": {"codex": null}},
            "ai_guard": {"by_tool": {"gemini": null}},
            "agent_health": {"hash_p99_ms_latest": -0, "recent_channel_stalls_24h": -0}}"#;
        let host: HostDetail = decode(body).unwrap();
        let out = serde_json::to_value(&host).unwrap();
        assert_eq!(
            out["open_event_counts_24h"],
            serde_json::json!({"info": 0, "warn": 0})
        );
        let zero_time = "0001-01-01T00:00:00Z";
        assert_eq!(
            out["current_risk"]["by_tool"],
            serde_json::json!({"codex": {"score": 0.0, "bucket": "", "assessed_ts": zero_time}})
        );
        assert!(host
            .summary
            .current_risk
            .unwrap()
            .max_score
            .is_sign_negative());
        assert_eq!(
            out["ai_guard"]["by_tool"],
            serde_json::json!({"gemini": {"score": 0.0, "bucket": "", "assessed_ts": zero_time,
                "is_reattestation": false, "scope": null, "reasons": null}})
        );
        assert_eq!(out["agent_health"]["hash_p99_ms_latest"], 0);
        assert_eq!(out["agent_health"]["recent_channel_stalls_24h"], 0);
        let ev: Event = decode(r#"{"schema_version": -0}"#).unwrap();
        assert_eq!(ev.schema_version, 0);
    }
}
