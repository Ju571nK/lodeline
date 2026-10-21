//! Request classification (T-12b1; PX-003/004/006, support-matrix §1/§2/§5).
//!
//! One bounded pass over the request body COPY. The forwarded bytes are the very
//! same buffer and are never altered. Nothing from `arguments`, `_meta` values
//! or other params is retained: unknown content is skipped by the parser, and
//! only the method vocabulary, the JSON-RPC id, a validated tool name, the
//! cancel target and presence flags leave this module.

use std::borrow::Cow;
use std::fmt;

use serde::de::{self, Deserializer, IgnoredAny, MapAccess, Visitor};
use serde::Deserialize;
use serde_json::value::RawValue;

/// The only revision P1 supports (support-matrix §1).
pub const PROTOCOL_VERSION: &str = "2025-11-25";

/// Revisions that are known but unsupported. A header with one of these is not
/// a "modern" request (decisions.md "2025-06-18 downstream 입력").
const LEGACY_VERSIONS: [&str; 3] = ["2024-11-05", "2025-03-26", "2025-06-18"];

/// A request id longer than this is malformed. Ids are echoed and matched, so
/// they must be small. // OPEN: not in D-04.
pub const MAX_ID_BYTES: usize = 256;

/// Tool name bounds. // OPEN: the contract only says "unparseable name".
pub const MAX_TOOL_NAME_BYTES: usize = 256;

// ---------------------------------------------------------------- request id

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
enum IdKey {
    Str(String),
    Num(String),
}

/// A JSON-RPC request id (string or number). Equality is exact JSON value
/// equality as the cancel contract needs it: `"4"` != `4`, `4` != `4.0`, and a
/// string compares by its decoded value (`"a"` == `"a"`).
#[derive(Clone, Debug)]
pub struct RequestId {
    key: IdKey,
    raw: String,
}

impl PartialEq for RequestId {
    fn eq(&self, o: &Self) -> bool {
        self.key == o.key
    }
}
impl Eq for RequestId {}
impl std::hash::Hash for RequestId {
    fn hash<H: std::hash::Hasher>(&self, h: &mut H) {
        self.key.hash(h)
    }
}

impl RequestId {
    /// From the id exactly as written in the message. `None` for anything that
    /// is not a short string or number (null, bool, object, oversize).
    pub fn from_raw(raw: &str) -> Option<RequestId> {
        let raw = raw.trim();
        if raw.is_empty() || raw.len() > MAX_ID_BYTES {
            return None;
        }
        let key = match raw.as_bytes()[0] {
            b'"' => IdKey::Str(serde_json::from_str::<String>(raw).ok()?),
            b'-' | b'0'..=b'9' => {
                // RawValue already guarantees valid JSON; this guards direct
                // callers.
                serde_json::from_str::<serde_json::Number>(raw).ok()?;
                IdKey::Num(raw.to_string())
            }
            _ => return None,
        };
        Some(RequestId {
            key,
            raw: raw.to_string(),
        })
    }

    /// The id as written, valid JSON, for echoing in a JSON-RPC error.
    pub fn raw(&self) -> &str {
        &self.raw
    }
}

// ------------------------------------------------------------------- vocabulary

/// The audit method vocabulary (contracts/README.md R1). Anything else,
/// including resources/prompts, is `Unknown` and the original is never kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Method {
    Initialize,
    Ping,
    ToolsList,
    ToolsCall,
    Unknown,
}

impl Method {
    fn from_wire(m: &str) -> Method {
        match m {
            "initialize" => Method::Initialize,
            "ping" => Method::Ping,
            "tools/list" => Method::ToolsList,
            "tools/call" => Method::ToolsCall,
            _ => Method::Unknown,
        }
    }
}

/// A validated tool name. It is untrusted content: `Debug` and `Display` never
/// print it, so an accidental `{:?}` of an observation cannot log it.
#[derive(Clone, PartialEq, Eq)]
pub struct ToolName(String);

impl ToolName {
    pub fn parse(s: &str) -> Option<ToolName> {
        if s.is_empty() || s.len() > MAX_TOOL_NAME_BYTES || s.chars().any(|c| c.is_control()) {
            return None;
        }
        Some(ToolName(s.to_string()))
    }
    /// For the single consumer that resolves it locally against the inventory
    /// (T-13). Must not be logged or emitted.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ToolName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ToolName(<redacted>)")
    }
}

/// The `tool` facet of a call (contracts/README.md "Tool identity").
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToolField {
    /// Methods other than `tools/call`.
    NotApplicable,
    Name(ToolName),
    /// `tools/call` whose name cannot be parsed.
    Malformed,
}

// ------------------------------------------------------------------- results

/// Why a message is not forwarded (or is answered by the proxy).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalKind {
    /// Body is not JSON.
    Parse,
    /// Valid JSON, not a JSON-RPC message.
    InvalidRequest,
    /// Top-level array (removed in 2025-11-25).
    Batch,
    /// D-01 B1: `server/discover`, `_meta` protocol key, unknown version header.
    ModernRequest,
    /// `MCP-Protocol-Version` is a known legacy revision on a non-initialize
    /// message.
    VersionHeader,
    /// `tasks/*`.
    TasksMethod,
    /// `resources/subscribe` and `resources/unsubscribe`.
    ResourcesSubscription,
    /// `tools/call` with an unparseable name.
    ToolNameMalformed,
    /// Request body over the limit.
    RequestTooLarge,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub kind: RefusalKind,
    /// The request id when one could be read (an error can echo it).
    pub id: Option<RequestId>,
    /// Audit method (`Unknown` unless the method is in the vocabulary).
    pub method: Method,
    pub tool: ToolField,
}

impl Refusal {
    fn bare(kind: RefusalKind) -> Refusal {
        Refusal {
            kind,
            id: None,
            method: Method::Unknown,
            tool: ToolField::NotApplicable,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestInfo {
    pub id: RequestId,
    pub method: Method,
    pub tool: ToolField,
    /// `tools/list` only: a cursor was sent (the value is never kept).
    pub list_cursor: bool,
    /// `tools/call` only: `params.task` was present. Forwarded unchanged.
    pub task_augmented: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NotificationInfo {
    /// `notifications/cancelled` for a client-initiated request id.
    Cancelled { target: RequestId },
    /// Any other notification: relayed, no event.
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Request(RequestInfo),
    Notification(NotificationInfo),
    /// A client JSON-RPC response to a server request: relayed, no event.
    ClientResponse,
    Refused(Refusal),
}

/// The `MCP-Protocol-Version` header, classified without session state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderVersion {
    Absent,
    /// The supported revision.
    Current,
    /// A known legacy revision.
    Legacy,
    /// Anything else (duplicates, non-ASCII, unknown revisions): modern.
    Modern,
}

impl HeaderVersion {
    pub fn from_headers(h: &http::HeaderMap) -> HeaderVersion {
        let mut it = h.get_all("mcp-protocol-version").iter();
        let Some(v) = it.next() else {
            return HeaderVersion::Absent;
        };
        if it.next().is_some() {
            return HeaderVersion::Modern;
        }
        match v.to_str().map(str::trim) {
            Ok(PROTOCOL_VERSION) => HeaderVersion::Current,
            Ok(s) if LEGACY_VERSIONS.contains(&s) => HeaderVersion::Legacy,
            _ => HeaderVersion::Modern,
        }
    }
}

// ----------------------------------------------------------------- wire probes

/// A field whose value is irrelevant but whose presence matters (a JSON `null`
/// counts as present).
#[derive(Default)]
struct Present(bool);

impl<'de> Deserialize<'de> for Present {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        IgnoredAny::deserialize(d)?;
        Ok(Present(true))
    }
}

/// `_meta`: only whether it carries the modern protocol key.
#[derive(Default)]
struct MetaProbe {
    modern: bool,
}

impl<'de> Deserialize<'de> for MetaProbe {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = MetaProbe;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<MetaProbe, A::Error> {
                let mut modern = false;
                while let Some(k) = m.next_key::<Cow<str>>()? {
                    if k == "io.modelcontextprotocol/protocolVersion" {
                        modern = true;
                    }
                    m.next_value::<IgnoredAny>()?;
                }
                Ok(MetaProbe { modern })
            }
            fn visit_unit<E: de::Error>(self) -> Result<MetaProbe, E> {
                Ok(MetaProbe::default())
            }
        }
        d.deserialize_any(V)
    }
}

/// A raw value that tells an absent key from an explicit `null`.
#[derive(Default)]
struct RawField<'a>(Option<&'a RawValue>);

impl<'de: 'a, 'a> Deserialize<'de> for RawField<'a> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        <&'a RawValue>::deserialize(d).map(|r| RawField(Some(r)))
    }
}

#[derive(Deserialize)]
struct Envelope<'a> {
    #[serde(borrow, default)]
    jsonrpc: Option<Cow<'a, str>>,
    #[serde(borrow, default)]
    method: Option<Cow<'a, str>>,
    #[serde(borrow, default)]
    id: RawField<'a>,
    #[serde(borrow, default)]
    params: Option<&'a RawValue>,
    #[serde(default)]
    result: Present,
    #[serde(default)]
    error: Present,
}

/// `name` of any JSON type: a non-string is a malformed tool name (-32602), not
/// an unprobeable body.
#[derive(Deserialize)]
#[serde(untagged)]
enum NameField<'a> {
    Str(#[serde(borrow)] Cow<'a, str>),
    Other(IgnoredAny),
}

/// The params fields this module looks at. Everything else, `arguments`
/// included, is skipped and dropped by the parser.
#[derive(Deserialize, Default)]
struct ParamsProbe<'a> {
    #[serde(borrow, default)]
    name: Option<NameField<'a>>,
    #[serde(default)]
    cursor: Present,
    #[serde(default)]
    task: Present,
    #[serde(rename = "_meta", default)]
    meta: MetaProbe,
    #[serde(rename = "requestId", borrow, default)]
    request_id: Option<&'a RawValue>,
}

fn first_non_ws(b: &[u8]) -> Option<u8> {
    b.iter().copied().find(|c| !c.is_ascii_whitespace())
}

/// Classify one request body. `header` is the `MCP-Protocol-Version` header.
///
/// Order: modern header, batch, syntax/shape, modern body markers, legacy
/// header on a non-initialize message, `tasks/*` and subscriptions, tool name.
pub fn classify(body: &[u8], header: HeaderVersion) -> Message {
    let refuse = |kind| Message::Refused(Refusal::bare(kind));
    if header == HeaderVersion::Modern {
        return refuse(RefusalKind::ModernRequest);
    }
    match first_non_ws(body) {
        Some(b'[') => return refuse(RefusalKind::Batch),
        Some(_) => {}
        None => return refuse(RefusalKind::Parse),
    }
    let env: Envelope = match serde_json::from_slice(body) {
        Ok(e) => e,
        Err(e) => {
            return refuse(if e.is_data() {
                RefusalKind::InvalidRequest
            } else {
                RefusalKind::Parse
            })
        }
    };
    if env.jsonrpc.as_deref() != Some("2.0") {
        return refuse(RefusalKind::InvalidRequest);
    }

    // id: absent, or a short string/number. `null` and other types are invalid.
    let id = match env.id.0 {
        None => None,
        Some(raw) => match RequestId::from_raw(raw.get()) {
            Some(i) => Some(i),
            None => return refuse(RefusalKind::InvalidRequest),
        },
    };

    let Some(method) = env.method.as_deref() else {
        // No method: only a response (result or error with an id) is valid.
        let is_response = id.is_some() && (env.result.0 || env.error.0);
        if !is_response {
            return refuse(RefusalKind::InvalidRequest);
        }
        if header == HeaderVersion::Legacy {
            return Message::Refused(Refusal::bare(RefusalKind::VersionHeader));
        }
        return Message::ClientResponse;
    };
    let audit = Method::from_wire(method);

    // The params probe. A failure only matters for the methods that need params.
    let probe: Option<ParamsProbe> = match env.params {
        // params must be an object (a positional array would parse as a struct)
        Some(p) if p.get().starts_with('{') => serde_json::from_str(p.get()).ok(),
        Some(_) => None,
        None => Some(ParamsProbe::default()),
    };

    let with = |kind, tool| {
        Message::Refused(Refusal {
            kind,
            id: id.clone(),
            method: audit,
            tool,
        })
    };

    if probe.is_none() {
        // Params that are present but do not parse (duplicate keys, wrong
        // shape): a probe that cannot see `_meta` must not be read as "not
        // modern".
        return with(RefusalKind::InvalidRequest, ToolField::NotApplicable);
    }
    if method == "server/discover" || probe.as_ref().is_some_and(|p| p.meta.modern) {
        // B1 audit: method and version are both literal `unknown`.
        return Message::Refused(Refusal {
            kind: RefusalKind::ModernRequest,
            id: id.clone(),
            method: Method::Unknown,
            tool: ToolField::NotApplicable,
        });
    }
    if header == HeaderVersion::Legacy && audit != Method::Initialize {
        return with(RefusalKind::VersionHeader, ToolField::NotApplicable);
    }
    if method.starts_with("tasks/") {
        return with(RefusalKind::TasksMethod, ToolField::NotApplicable);
    }
    if method == "resources/subscribe" || method == "resources/unsubscribe" {
        return with(RefusalKind::ResourcesSubscription, ToolField::NotApplicable);
    }

    let Some(id) = id.clone() else {
        // Only `notifications/*` may omit the id; any other id-less method
        // would otherwise be relayed unobserved.
        if !method.starts_with("notifications/") {
            return with(RefusalKind::InvalidRequest, ToolField::NotApplicable);
        }
        if method == "notifications/cancelled" {
            let target = probe
                .as_ref()
                .and_then(|p| p.request_id)
                .and_then(|r| RequestId::from_raw(r.get()));
            return match target {
                Some(target) => Message::Notification(NotificationInfo::Cancelled { target }),
                None => refuse(RefusalKind::InvalidRequest),
            };
        }
        return Message::Notification(NotificationInfo::Other);
    };

    let mut info = RequestInfo {
        id,
        method: audit,
        tool: ToolField::NotApplicable,
        list_cursor: false,
        task_augmented: false,
    };
    match audit {
        Method::ToolsCall => {
            let name = probe
                .as_ref()
                .and_then(|p| match p.name.as_ref() {
                    Some(NameField::Str(s)) => Some(s.as_ref()),
                    _ => None,
                })
                .and_then(ToolName::parse);
            match name {
                Some(n) => info.tool = ToolField::Name(n),
                None => return with(RefusalKind::ToolNameMalformed, ToolField::Malformed),
            }
            info.task_augmented = probe.as_ref().is_some_and(|p| p.task.0);
        }
        Method::ToolsList => {
            info.list_cursor = probe.as_ref().is_some_and(|p| p.cursor.0);
        }
        _ => {}
    }
    Message::Request(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(body: &str) -> Message {
        classify(body.as_bytes(), HeaderVersion::Absent)
    }
    fn refused(m: Message) -> Refusal {
        match m {
            Message::Refused(r) => r,
            o => panic!("expected refusal, got {o:?}"),
        }
    }
    fn req(m: Message) -> RequestInfo {
        match m {
            Message::Request(r) => r,
            o => panic!("expected request, got {o:?}"),
        }
    }

    #[test]
    fn tools_call_has_method_id_and_tool() {
        let r = req(c(
            r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"echo","arguments":{"k":"CANARY"}}}"#,
        ));
        assert_eq!(r.method, Method::ToolsCall);
        assert_eq!(r.id.raw(), "7");
        assert_eq!(r.tool, ToolField::Name(ToolName::parse("echo").unwrap()));
        assert!(!r.task_augmented && !r.list_cursor);
    }

    #[test]
    fn method_vocabulary_and_unknown() {
        for (m, want) in [
            ("initialize", Method::Initialize),
            ("ping", Method::Ping),
            ("tools/list", Method::ToolsList),
            ("resources/read", Method::Unknown),
            ("prompts/get", Method::Unknown),
            ("completion/complete", Method::Unknown),
        ] {
            let r = req(c(&format!(
                r#"{{"jsonrpc":"2.0","id":"a","method":"{m}"}}"#
            )));
            assert_eq!(r.method, want, "{m}");
        }
    }

    #[test]
    fn tools_list_cursor_presence_only() {
        let r = req(c(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"cursor":"SECRET-CURSOR"}}"#,
        ));
        assert!(r.list_cursor);
        let r = req(c(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#));
        assert!(!r.list_cursor);
        let r = req(c(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#,
        ));
        assert!(!r.list_cursor);
    }

    #[test]
    fn task_augmentation_is_flagged_not_refused() {
        let r = req(c(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","task":{"ttl":1}}}"#,
        ));
        assert!(r.task_augmented);
    }

    #[test]
    fn ids_compare_by_json_value() {
        let id = |s: &str| RequestId::from_raw(s).unwrap();
        assert_eq!(id("4"), id("4"));
        assert_ne!(id("4"), id("\"4\""));
        assert_ne!(id("4"), id("4.0"));
        assert_eq!(id("\"a\""), id(r#""\u0061""#));
        assert_eq!(id(r#""a\u00e9""#), id("\"aé\""));
        assert_eq!(
            id("12345678901234567890123456789").raw(),
            "12345678901234567890123456789"
        );
        for bad in ["null", "true", "{}", "[1]", "", "\"", "1 2"] {
            assert!(RequestId::from_raw(bad).is_none(), "{bad}");
        }
        let long = format!("\"{}\"", "x".repeat(MAX_ID_BYTES));
        assert!(RequestId::from_raw(&long).is_none());
    }

    #[test]
    fn invalid_ids_are_malformed() {
        for body in [
            r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":true,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":{"a":1},"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}"#,
        ] {
            assert_eq!(refused(c(body)).kind, RefusalKind::InvalidRequest, "{body}");
        }
    }

    #[test]
    fn malformed_bodies() {
        for (body, want) in [
            ("", RefusalKind::Parse),
            ("   ", RefusalKind::Parse),
            ("not json", RefusalKind::Parse),
            ("{", RefusalKind::Parse),
            (
                r#"{"jsonrpc":"2.0","method":"ping"}trailing"#,
                RefusalKind::Parse,
            ),
            ("{}", RefusalKind::InvalidRequest),
            ("null", RefusalKind::InvalidRequest),
            ("42", RefusalKind::InvalidRequest),
            ("\"x\"", RefusalKind::InvalidRequest),
            (r#"{"id":1,"method":"ping"}"#, RefusalKind::InvalidRequest),
            (
                r#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#,
                RefusalKind::InvalidRequest,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":5}"#,
                RefusalKind::InvalidRequest,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"ping","method":"ping"}"#,
                RefusalKind::InvalidRequest,
            ),
            // no method and not a response
            (r#"{"jsonrpc":"2.0","id":1}"#, RefusalKind::InvalidRequest),
            (r#"{"jsonrpc":"2.0"}"#, RefusalKind::InvalidRequest),
        ] {
            let r = refused(c(body));
            assert_eq!(r.kind, want, "{body:?}");
            assert_eq!(r.method, Method::Unknown);
        }
    }

    #[test]
    fn deeply_nested_input_is_malformed_not_a_crash() {
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"ping","params":{}1{}}}"#,
            "[".repeat(5000),
            "]".repeat(5000)
        );
        // Must not overflow the stack; the params probe fails (depth), the
        // outer envelope is rejected by the parser's recursion limit.
        let m = c(&body);
        assert!(matches!(m, Message::Refused(_) | Message::Request(_)));
    }

    #[test]
    fn batches_are_refused() {
        for body in [
            r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#,
            "  \n[]",
            "[",
            "[1,2",
        ] {
            assert_eq!(refused(c(body)).kind, RefusalKind::Batch, "{body}");
        }
    }

    #[test]
    fn tasks_methods_are_refused_with_the_id() {
        for m in [
            "tasks/get",
            "tasks/result",
            "tasks/list",
            "tasks/cancel",
            "tasks/x",
        ] {
            let r = refused(c(&format!(r#"{{"jsonrpc":"2.0","id":9,"method":"{m}"}}"#)));
            assert_eq!(r.kind, RefusalKind::TasksMethod, "{m}");
            assert_eq!(r.id.unwrap().raw(), "9");
            // the original method is never kept
            assert_eq!(r.method, Method::Unknown);
        }
        // a notification with a tasks method has no id to answer
        let r = refused(c(r#"{"jsonrpc":"2.0","method":"tasks/get"}"#));
        assert_eq!(r.kind, RefusalKind::TasksMethod);
        assert!(r.id.is_none());
        // not a prefix match on the substring
        assert!(matches!(
            c(r#"{"jsonrpc":"2.0","id":1,"method":"mytasks/get"}"#),
            Message::Request(_)
        ));
    }

    #[test]
    fn resources_subscribe_is_refused() {
        for m in ["resources/subscribe", "resources/unsubscribe"] {
            let r = refused(c(&format!(
                r#"{{"jsonrpc":"2.0","id":2,"method":"{m}","params":{{"uri":"x"}}}}"#
            )));
            assert_eq!(r.kind, RefusalKind::ResourcesSubscription);
        }
        // read/list are relayed
        for m in [
            "resources/read",
            "resources/list",
            "resources/templates/list",
        ] {
            assert!(matches!(
                c(&format!(r#"{{"jsonrpc":"2.0","id":2,"method":"{m}"}}"#)),
                Message::Request(_)
            ));
        }
    }

    #[test]
    fn tool_name_must_be_a_valid_string() {
        for params in [
            r#"{}"#,
            r#"{"name":5}"#,
            r#"{"name":null}"#,
            r#"{"name":""}"#,
            r#"{"name":"a\u0000b"}"#,
            r#"{"name":"a\nb"}"#,
        ] {
            let body =
                format!(r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{params}}}"#);
            let r = refused(c(&body));
            assert_eq!(r.kind, RefusalKind::ToolNameMalformed, "{params}");
            assert_eq!(r.tool, ToolField::Malformed);
            assert_eq!(r.method, Method::ToolsCall);
            assert_eq!(r.id.unwrap().raw(), "1");
        }
        let r = refused(c(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#));
        assert_eq!(r.kind, RefusalKind::ToolNameMalformed);
        let long = "n".repeat(MAX_TOOL_NAME_BYTES + 1);
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"{long}"}}}}"#
        );
        assert_eq!(refused(c(&body)).kind, RefusalKind::ToolNameMalformed);
    }

    #[test]
    fn modern_markers() {
        for body in [
            r#"{"jsonrpc":"2.0","id":1,"method":"server/discover"}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"x"}}}"#,
        ] {
            let r = refused(c(body));
            assert_eq!(r.kind, RefusalKind::ModernRequest, "{body}");
            // the raw method and `_meta` are echoed nowhere; method is `unknown`
            assert_eq!(r.method, Method::Unknown);
            assert_eq!(r.tool, ToolField::NotApplicable);
        }
        // other _meta keys are fine
        assert!(matches!(
            c(r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":{"progressToken":1}}}"#),
            Message::Request(_)
        ));
    }

    #[test]
    fn version_header_rules() {
        let ping = br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
        let init = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#;
        // current and absent are fine
        assert!(matches!(
            classify(ping, HeaderVersion::Current),
            Message::Request(_)
        ));
        assert!(matches!(
            classify(ping, HeaderVersion::Absent),
            Message::Request(_)
        ));
        // legacy value: refused after initialize, tolerated on initialize itself
        assert_eq!(
            refused(classify(ping, HeaderVersion::Legacy)).kind,
            RefusalKind::VersionHeader
        );
        assert!(matches!(
            classify(init, HeaderVersion::Legacy),
            Message::Request(_)
        ));
        // any unknown value is modern, even on initialize and even for junk bodies
        for b in [&ping[..], init, b"not json", b"[1]"] {
            assert_eq!(
                refused(classify(b, HeaderVersion::Modern)).kind,
                RefusalKind::ModernRequest
            );
        }
        // legacy applies to notifications and client responses too
        assert_eq!(
            refused(classify(
                br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
                HeaderVersion::Legacy
            ))
            .kind,
            RefusalKind::VersionHeader
        );
        assert_eq!(
            refused(classify(
                br#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
                HeaderVersion::Legacy
            ))
            .kind,
            RefusalKind::VersionHeader
        );
    }

    #[test]
    fn header_value_classes() {
        use http::{HeaderMap, HeaderValue};
        let h = |vals: &[&str]| {
            let mut m = HeaderMap::new();
            for v in vals {
                m.append("mcp-protocol-version", HeaderValue::from_str(v).unwrap());
            }
            HeaderVersion::from_headers(&m)
        };
        assert_eq!(h(&[]), HeaderVersion::Absent);
        assert_eq!(h(&["2025-11-25"]), HeaderVersion::Current);
        assert_eq!(h(&[" 2025-11-25 "]), HeaderVersion::Current);
        for l in ["2024-11-05", "2025-03-26", "2025-06-18"] {
            assert_eq!(h(&[l]), HeaderVersion::Legacy);
        }
        for m in ["2026-07-28", "garbage", "", "2025-11-26"] {
            assert_eq!(h(&[m]), HeaderVersion::Modern, "{m:?}");
        }
        assert_eq!(h(&["2025-11-25", "2025-11-25"]), HeaderVersion::Modern);
    }

    #[test]
    fn cancel_notifications() {
        let n = c(
            r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"4","reason":"SECRET"}}"#,
        );
        assert_eq!(
            n,
            Message::Notification(NotificationInfo::Cancelled {
                target: RequestId::from_raw("\"4\"").unwrap()
            })
        );
        let n =
            c(r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":4}}"#);
        match n {
            Message::Notification(NotificationInfo::Cancelled { target }) => {
                assert_ne!(target, RequestId::from_raw("\"4\"").unwrap());
                assert_eq!(target, RequestId::from_raw("4").unwrap());
            }
            o => panic!("{o:?}"),
        }
        for bad in [
            r#"{"jsonrpc":"2.0","method":"notifications/cancelled"}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":null}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":{"a":1}}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":[1]}"#,
        ] {
            assert_eq!(refused(c(bad)).kind, RefusalKind::InvalidRequest, "{bad}");
        }
    }

    #[test]
    fn other_notifications_and_client_responses() {
        assert_eq!(
            c(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#),
            Message::Notification(NotificationInfo::Other)
        );
        assert_eq!(
            c(r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}"#),
            Message::Notification(NotificationInfo::Other)
        );
        // client answers to sampling/elicitation/roots are not malformed
        for body in [
            r#"{"jsonrpc":"2.0","id":"s1","result":{"role":"assistant"}}"#,
            r#"{"jsonrpc":"2.0","id":3,"error":{"code":-32601,"message":"x"}}"#,
        ] {
            assert_eq!(c(body), Message::ClientResponse, "{body}");
        }
    }

    /// M1: only `notifications/*` may omit the id. Anything else would be
    /// relayed as an unobserved "notification".
    #[test]
    fn id_less_requests_are_refused() {
        for body in [
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x"}}"#,
            r#"{"jsonrpc":"2.0","method":"tools/list"}"#,
            r#"{"jsonrpc":"2.0","method":"initialize","params":{}}"#,
            r#"{"jsonrpc":"2.0","method":"ping"}"#,
            r#"{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"u"}}"#,
        ] {
            let r = refused(c(body));
            assert_eq!(r.kind, RefusalKind::InvalidRequest, "{body}");
            assert!(r.id.is_none());
        }
        assert_eq!(
            c(r#"{"jsonrpc":"2.0","method":"notifications/anything"}"#),
            Message::Notification(NotificationInfo::Other)
        );
    }

    /// M2: params that are present but cannot be probed (duplicate keys, wrong
    /// shape) must not be read as "not modern".
    #[test]
    fn unprobeable_params_are_refused() {
        for body in [
            // duplicate `_meta`: the second one carries the modern marker
            r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#,
            // duplicate `name`
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","name":"b"}}"#,
            // duplicate `cursor`, `task`
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"cursor":"a","cursor":"b"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","task":{},"task":{}}}"#,
            // wrong shapes
            r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":[1,2]}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":"x"}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":5}}"#,
            // notifications too
            r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{"_meta":{},"_meta":{}}}"#,
        ] {
            let r = refused(c(body));
            assert_eq!(r.kind, RefusalKind::InvalidRequest, "{body}");
        }
        // the id is kept so the error can echo it
        let r = refused(c(
            r#"{"jsonrpc":"2.0","id":"q","method":"ping","params":{"_meta":{},"_meta":{}}}"#,
        ));
        assert_eq!(r.id.unwrap().raw(), "\"q\"");
        // absent and null params are fine
        assert!(matches!(
            c(r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":null}"#),
            Message::Request(_)
        ));
        assert!(matches!(
            c(r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}"#),
            Message::Request(_)
        ));
    }

    #[test]
    fn debug_never_prints_the_tool_name() {
        let r = req(c(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"CANARY-TOOL"}}"#,
        ));
        assert!(!format!("{r:?}").contains("CANARY"));
    }
}
