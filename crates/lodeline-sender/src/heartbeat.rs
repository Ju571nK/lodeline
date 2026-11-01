//! What the sender knows about its link to `lodeline-server`, and the task that
//! leaves it on disk for readers on this host.

use crate::state;
use lodeline_core::sender_status::{
    Contact, LinkFailure, SenderReport, REPORT_INTERVAL, REPORT_SCHEMA_VERSION,
};
use parking_lot::RwLock;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// How soon a change of state reaches the file.
const CHANGE_CHECK: Duration = Duration::from_secs(1);

/// The two requests the sender repeats. Each fails on its own: a server can serve
/// policy and refuse events, so success on one must not clear the other.
#[derive(Clone, Copy, Debug)]
pub enum Plane {
    Events,
    Policy,
}

#[derive(Clone, Copy, Debug)]
struct Failure {
    since: OffsetDateTime,
    failure: LinkFailure,
}

#[derive(Clone, Debug, Default)]
pub struct SenderStats {
    last_ok_at: Option<OffsetDateTime>,
    events: Option<Failure>,
    policy: Option<Failure>,
    pub client_cert_expires_at: Option<OffsetDateTime>,
}

impl SenderStats {
    pub fn record(&mut self, plane: Plane, result: Result<(), LinkFailure>, now: OffsetDateTime) {
        let current = match plane {
            Plane::Events => &mut self.events,
            Plane::Policy => &mut self.policy,
        };
        match result {
            Ok(()) => {
                *current = None;
                self.last_ok_at = Some(now);
            }
            Err(failure) => {
                let since = current.map_or(now, |f| f.since);
                *current = Some(Failure { since, failure });
            }
        }
    }

    pub fn contact(&self) -> Contact {
        let oldest = [self.events, self.policy]
            .into_iter()
            .flatten()
            .min_by_key(|f| f.since);
        match (oldest, self.last_ok_at) {
            (Some(Failure { since, failure }), last_ok_at) => Contact::Failing {
                since,
                failure,
                last_ok_at,
            },
            (None, Some(last_ok_at)) => Contact::Reached { last_ok_at },
            (None, None) => Contact::NoAnswerYet,
        }
    }
}

pub type SharedStats = Arc<RwLock<SenderStats>>;

pub fn shared() -> SharedStats {
    Arc::new(RwLock::new(SenderStats::default()))
}

fn same_state(a: &Contact, b: &Contact) -> bool {
    match (a, b) {
        (Contact::Failing { failure: a, .. }, Contact::Failing { failure: b, .. }) => a == b,
        _ => std::mem::discriminant(a) == std::mem::discriminant(b),
    }
}

/// Writes the report at start, on a change of state, and every [`REPORT_INTERVAL`]. A
/// failed write is only logged, because the report must never stop events shipping.
pub async fn write_status(stats: SharedStats, path: PathBuf, shutdown: CancellationToken) {
    let mut tick = tokio::time::interval(CHANGE_CHECK);
    let mut last: Option<(Contact, Instant)> = None;
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            _ = tick.tick() => {
                let (contact, client_cert_expires_at) = {
                    let s = stats.read();
                    (s.contact(), s.client_cert_expires_at)
                };
                let due = last.is_none_or(|(written, at)| {
                    !same_state(&written, &contact) || at.elapsed() >= REPORT_INTERVAL
                });
                if due {
                    let report = SenderReport {
                        schema_version: REPORT_SCHEMA_VERSION,
                        written_at: OffsetDateTime::now_utc(),
                        contact,
                        client_cert_expires_at,
                    };
                    if let Err(e) = state::store_report(&path, &report) {
                        tracing::warn!(error = ?e, "writing the status file failed");
                    }
                    last = Some((contact, Instant::now()));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    const T1: OffsetDateTime = datetime!(2026-05-15 0:00 UTC);
    const T2: OffsetDateTime = datetime!(2026-05-15 0:01 UTC);
    const T3: OffsetDateTime = datetime!(2026-05-15 0:02 UTC);

    #[test]
    fn starts_with_no_answer_and_claims_nothing() {
        assert_eq!(SenderStats::default().contact(), Contact::NoAnswerYet);
    }

    #[test]
    fn success_is_reached_with_its_time() {
        let mut s = SenderStats::default();
        s.record(Plane::Events, Ok(()), T1);
        assert_eq!(s.contact(), Contact::Reached { last_ok_at: T1 });
    }

    #[test]
    fn repeated_failure_keeps_its_start_and_reports_the_latest_cause() {
        let mut s = SenderStats::default();
        s.record(Plane::Events, Ok(()), T1);
        s.record(Plane::Events, Err(LinkFailure::Network), T2);
        s.record(
            Plane::Events,
            Err(LinkFailure::Response {
                last_response_code: 503,
            }),
            T3,
        );
        assert_eq!(
            s.contact(),
            Contact::Failing {
                since: T2,
                failure: LinkFailure::Response {
                    last_response_code: 503
                },
                last_ok_at: Some(T1),
            }
        );
    }

    #[test]
    fn success_on_one_plane_does_not_clear_a_failure_on_the_other() {
        let mut s = SenderStats::default();
        s.record(Plane::Events, Err(LinkFailure::Tls), T1);
        s.record(Plane::Policy, Ok(()), T2);
        assert!(matches!(
            s.contact(),
            Contact::Failing {
                failure: LinkFailure::Tls,
                ..
            }
        ));
        s.record(Plane::Events, Ok(()), T3);
        assert_eq!(s.contact(), Contact::Reached { last_ok_at: T3 });
    }

    #[test]
    fn a_new_cause_is_a_change_of_state_but_a_new_timestamp_is_not() {
        let reached = |last_ok_at| Contact::Reached { last_ok_at };
        let failing = |failure| Contact::Failing {
            since: T1,
            failure,
            last_ok_at: None,
        };
        assert!(same_state(&reached(T1), &reached(T2)));
        assert!(!same_state(&reached(T1), &Contact::NoAnswerYet));
        assert!(!same_state(
            &failing(LinkFailure::Network),
            &failing(LinkFailure::Tls)
        ));
    }
}
