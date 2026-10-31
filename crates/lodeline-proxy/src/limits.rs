//! D-04 limits. Defaults are the P1 initial values of `validation.md`
//! ("D-04: 첫 배포와 수치 한도"). They are test targets, not performance
//! guarantees. Local config may only LOWER a value, within `[min, default]`.

use serde::Deserialize;
use thiserror::Error;

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const GIB: u64 = 1024 * MIB;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub max_request_body_bytes: u64,
    pub max_header_bytes: u64,
    pub max_json_response_bytes: u64,
    pub max_sse_event_bytes: u64,
    pub max_call_response_bytes: u64,
    pub call_bandwidth_bytes_per_sec: u64,
    pub process_bandwidth_bytes_per_sec: u64,
    pub max_concurrent_calls: u64,
    pub max_calls_per_route: u64,
    pub max_calls_per_principal: u64,
    pub max_sessions: u64,
    pub max_sessions_per_principal: u64,
    pub session_idle_secs: u64,
    /// Default 0: overload is rejected at once, no hidden unbounded wait.
    pub queue_depth: u64,
    pub connect_timeout_secs: u64,
    pub response_idle_timeout_secs: u64,
    pub call_timeout_secs: u64,
    pub shutdown_grace_secs: u64,
    pub inventory_max_pages: u64,
    pub inventory_max_tools: u64,
    pub inventory_max_bytes: u64,
    pub event_max_bytes: u64,
    pub spool_max_bytes: u64,
    pub spool_gap_reserve_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_request_body_bytes: MIB,
            max_header_bytes: 32 * KIB,
            max_json_response_bytes: 8 * MIB,
            max_sse_event_bytes: MIB,
            max_call_response_bytes: 64 * MIB,
            call_bandwidth_bytes_per_sec: 4 * MIB,
            process_bandwidth_bytes_per_sec: 32 * MIB,
            max_concurrent_calls: 64,
            max_calls_per_route: 16,
            max_calls_per_principal: 8,
            max_sessions: 256,
            max_sessions_per_principal: 32,
            session_idle_secs: 15 * 60,
            queue_depth: 0,
            connect_timeout_secs: 5,
            response_idle_timeout_secs: 30,
            call_timeout_secs: 120,
            shutdown_grace_secs: 30,
            inventory_max_pages: 100,
            inventory_max_tools: 10_000,
            inventory_max_bytes: 16 * MIB,
            event_max_bytes: 16 * KIB,
            spool_max_bytes: GIB,
            spool_gap_reserve_bytes: 16 * MIB,
        }
    }
}

/// Per-route limits from the remote config (`ConfigLimits`), already validated
/// as positive by the parser. They can only LOWER the local values.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RemoteLimits {
    pub max_request_bytes: Option<u64>,
    pub max_response_bytes: Option<u64>,
    pub request_timeout_seconds: Option<u64>,
}

impl Limits {
    /// Effective limits of a route: `min(local, remote)` per field (#260). A
    /// remote value above the local one has no effect, and a missing remote value
    /// leaves the local one. The response cap applies to the JSON body, the
    /// accumulated call and (so it cannot be a larger window than the call) the
    /// SSE event; the timeout applies to the whole call.
    pub fn lowered_by(&self, remote: &RemoteLimits) -> Limits {
        let mut out = self.clone();
        let low = |local: &mut u64, r: Option<u64>| {
            if let Some(r) = r {
                *local = (*local).min(r);
            }
        };
        low(&mut out.max_request_body_bytes, remote.max_request_bytes);
        low(&mut out.max_json_response_bytes, remote.max_response_bytes);
        low(&mut out.max_call_response_bytes, remote.max_response_bytes);
        low(&mut out.max_sse_event_bytes, remote.max_response_bytes);
        low(&mut out.call_timeout_secs, remote.request_timeout_seconds);
        out
    }
}

// NOTE: no cross-field check yet. Each value is only bounded by its own default,
// so a config may lower a total below a sub-limit (for example
// max_concurrent_calls below max_calls_per_route, or spool_max_bytes below
// spool_gap_reserve_bytes). Cross-field validation is deliberately deferred.

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LimitsError {
    #[error("limits.{field} = {value} is out of bounds ({min}..={max}); config may only lower the default")]
    OutOfBounds {
        field: &'static str,
        value: u64,
        min: u64,
        max: u64,
    },
}

macro_rules! limits_overrides {
    ($($field:ident : $min:expr),* $(,)?) => {
        /// The `limits:` bootstrap section: every key optional, unknown keys rejected.
        #[derive(Debug, Clone, Default, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct LimitsOverrides {
            $(pub $field: Option<u64>,)*
        }

        impl LimitsOverrides {
            /// Apply on top of the defaults. A value above its default or below
            /// its minimum is an error (never clamped silently).
            pub fn resolve(&self) -> Result<Limits, LimitsError> {
                let mut out = Limits::default();
                $(
                    if let Some(v) = self.$field {
                        let (min, max) = ($min, out.$field);
                        if v < min || v > max {
                            return Err(LimitsError::OutOfBounds {
                                field: stringify!($field), value: v, min, max,
                            });
                        }
                        out.$field = v;
                    }
                )*
                Ok(out)
            }
        }
    };
}

// Minimum 1 everywhere except queue_depth (0 is the default and the only
// allowed value: it may not be raised).
limits_overrides! {
    max_request_body_bytes: 1,
    max_header_bytes: 1,
    max_json_response_bytes: 1,
    max_sse_event_bytes: 1,
    max_call_response_bytes: 1,
    call_bandwidth_bytes_per_sec: 1,
    process_bandwidth_bytes_per_sec: 1,
    max_concurrent_calls: 1,
    max_calls_per_route: 1,
    max_calls_per_principal: 1,
    max_sessions: 1,
    max_sessions_per_principal: 1,
    session_idle_secs: 1,
    queue_depth: 0,
    connect_timeout_secs: 1,
    response_idle_timeout_secs: 1,
    call_timeout_secs: 1,
    shutdown_grace_secs: 1,
    inventory_max_pages: 1,
    inventory_max_tools: 1,
    inventory_max_bytes: 1,
    event_max_bytes: 1,
    spool_max_bytes: 1,
    spool_gap_reserve_bytes: 1,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AC-07/AC-12 (PX-013): defaults equal the validation.md D-04 table.
    #[test]
    fn defaults_equal_validation_md_d04_table() {
        let l = Limits::default();
        // HTTP request body / header: 1 MiB / 32 KiB
        assert_eq!(l.max_request_body_bytes, 1_048_576);
        assert_eq!(l.max_header_bytes, 32_768);
        // single JSON response / SSE event: 8 MiB / 1 MiB
        assert_eq!(l.max_json_response_bytes, 8 * 1_048_576);
        assert_eq!(l.max_sse_event_bytes, 1_048_576);
        // per-call accumulated response / bandwidth: 64 MiB / 4 MiB/s
        assert_eq!(l.max_call_response_bytes, 64 * 1_048_576);
        assert_eq!(l.call_bandwidth_bytes_per_sec, 4 * 1_048_576);
        // process response bandwidth: 32 MiB/s
        assert_eq!(l.process_bandwidth_bytes_per_sec, 32 * 1_048_576);
        // concurrent calls: total 64, route 16, principal 8
        assert_eq!(
            (
                l.max_concurrent_calls,
                l.max_calls_per_route,
                l.max_calls_per_principal
            ),
            (64, 16, 8)
        );
        // sessions: total 256, principal 32; idle 15 min
        assert_eq!((l.max_sessions, l.max_sessions_per_principal), (256, 32));
        assert_eq!(l.session_idle_secs, 900);
        // queue: default 0
        assert_eq!(l.queue_depth, 0);
        // connect / response idle / whole call: 5 s / 30 s / 120 s
        assert_eq!(
            (
                l.connect_timeout_secs,
                l.response_idle_timeout_secs,
                l.call_timeout_secs
            ),
            (5, 30, 120)
        );
        // shutdown grace: 30 s
        assert_eq!(l.shutdown_grace_secs, 30);
        // inventory: 100 pages, 10,000 tools, 16 MiB
        assert_eq!(
            (
                l.inventory_max_pages,
                l.inventory_max_tools,
                l.inventory_max_bytes
            ),
            (100, 10_000, 16 * 1_048_576)
        );
        // audit event 16 KiB; spool 1 GiB + 16 MiB gap reserve
        assert_eq!(l.event_max_bytes, 16 * 1024);
        assert_eq!(l.spool_max_bytes, 1_073_741_824);
        assert_eq!(l.spool_gap_reserve_bytes, 16 * 1_048_576);
    }

    #[test]
    fn config_may_lower_but_not_raise() {
        let lowered = LimitsOverrides {
            max_concurrent_calls: Some(10),
            ..Default::default()
        }
        .resolve()
        .unwrap();
        assert_eq!(lowered.max_concurrent_calls, 10);
        assert_eq!(lowered.max_calls_per_route, 16);

        let raised = LimitsOverrides {
            max_concurrent_calls: Some(65),
            ..Default::default()
        }
        .resolve();
        assert!(matches!(raised, Err(LimitsError::OutOfBounds { .. })));
        let zero = LimitsOverrides {
            call_timeout_secs: Some(0),
            ..Default::default()
        }
        .resolve();
        assert!(zero.is_err());
        let queue = LimitsOverrides {
            queue_depth: Some(1),
            ..Default::default()
        }
        .resolve();
        assert!(queue.is_err(), "queue depth may not be raised above 0");
    }

    #[test]
    fn unknown_limit_key_is_rejected() {
        assert!(serde_yaml::from_str::<LimitsOverrides>("bogus: 1").is_err());
    }

    /// #260: remote limits only lower the local values (min per field).
    #[test]
    fn remote_limits_only_lower() {
        let local = Limits {
            max_request_body_bytes: 1000,
            max_json_response_bytes: 2000,
            max_call_response_bytes: 3000,
            max_sse_event_bytes: 500,
            call_timeout_secs: 60,
            ..Limits::default()
        };
        // lower: wins
        let low = RemoteLimits {
            max_request_bytes: Some(10),
            max_response_bytes: Some(100),
            request_timeout_seconds: Some(5),
        };
        let e = local.lowered_by(&low);
        assert_eq!(e.max_request_body_bytes, 10);
        assert_eq!(e.max_json_response_bytes, 100);
        assert_eq!(e.max_call_response_bytes, 100);
        assert_eq!(e.max_sse_event_bytes, 100);
        assert_eq!(e.call_timeout_secs, 5);
        // higher: ignored
        let high = RemoteLimits {
            max_request_bytes: Some(1_000_000),
            max_response_bytes: Some(1_000_000),
            request_timeout_seconds: Some(600),
        };
        assert_eq!(local.lowered_by(&high), local);
        // absent: unchanged
        assert_eq!(local.lowered_by(&RemoteLimits::default()), local);
        // fields the remote cannot name stay local
        assert_eq!(e.max_header_bytes, local.max_header_bytes);
    }
}
