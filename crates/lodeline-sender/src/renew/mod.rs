//! The sender renews its own client certificate and key before they expire (#553).
//!
//! Everything comes from the certificate on disk: it names its own validity, and
//! renewal is due between 60% and 75% of it, at a point that depends on the host_id so
//! a fleet does not renew at once. There is no setting. [`Renewer::step`] does one
//! wake: settle the files ([`pair::settle`]), pick up a pair that appeared on disk,
//! and renew when due. The task calls it, then sleeps for what it returns.

pub mod net;
pub mod pair;

use crate::heartbeat::SharedStats;
use crate::transport::{build_client, ClientHandle};
use net::Answer;
use pair::Paths;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Duration;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

/// The longest sleep: the files are read again at least this often.
const WAKE: Duration = Duration::from_secs(300);
/// One log line of each kind per this long.
const LOG_EVERY: i64 = 3600;

/// `[0, 1)` from the host_id, fixed for a host.
fn spread(host_id: &str) -> f64 {
    let h = Sha256::digest(host_id.as_bytes());
    u64::from_be_bytes(h[..8].try_into().expect("8 bytes")) as f64 / 2f64.powi(64)
}

/// The moment renewal is due, in Unix seconds: 60% to 75% into the validity.
pub fn target(not_before: i64, not_after: i64, host_id: &str) -> i64 {
    let v = (not_after - not_before).max(0) as f64;
    not_before + (v * (0.60 + 0.15 * spread(host_id))) as i64
}

/// The wait after the `fails`-th failure in a row: a fiftieth of the validity (1 to 60 s),
/// doubling, up to a tenth of it but at most 1 h, so a 15 s certificate retries every
/// second and a 30 day one backs off from a minute to an hour. Spread by 20% per host.
pub fn backoff(not_before: i64, not_after: i64, host_id: &str, fails: u32) -> Duration {
    let v = (not_after - not_before).max(1) as u64;
    let first = (v / 50).clamp(1, 60);
    let cap = (v / 10).clamp(first, 3600);
    let wait = (first << fails.saturating_sub(1).min(20)).min(cap);
    Duration::from_secs_f64(wait as f64 * (0.8 + 0.4 * spread(host_id)))
}

/// A refusal is not retried quickly: a tenth of the validity, 1 min to 6 h.
fn refused_wait(not_before: i64, not_after: i64) -> Duration {
    Duration::from_secs(((not_after - not_before).max(0) as u64 / 10).clamp(60, 21600))
}

#[derive(Default)]
struct Limiter(HashMap<&'static str, i64>);

impl Limiter {
    /// True when the line `key` may be logged at `now`; then it is quiet for `LOG_EVERY`.
    fn due(&mut self, key: &'static str, now: i64) -> bool {
        match self.0.get(key) {
            Some(&t) if now - t < LOG_EVERY => false,
            _ => {
                self.0.insert(key, now);
                true
            }
        }
    }
}

/// The files renewal works on, when the config names a whole mutual TLS identity and the
/// CA that signs the new certificate. Not on Windows, where renewal is off.
pub fn paths(c: &crate::config::SenderConfig) -> Option<Paths> {
    match (&c.client_cert_path, &c.client_key_path, &c.server_ca_path) {
        (Some(_), Some(_), Some(_)) if cfg!(windows) => {
            tracing::info!("certificate renewal is not supported on Windows yet");
            None
        }
        (Some(crt), Some(key), Some(ca)) => Some(Paths::new(crt, key, ca)),
        _ => None,
    }
}

/// Settle the files before the first client is built: a pair split by a crash cannot
/// build one. Anything it cannot repair is left for the caller's own error.
pub fn settle_at_start(p: &Paths, host_id: &str) {
    match pair::settle(p, host_id, OffsetDateTime::now_utc()) {
        Ok(None) => {}
        Ok(Some(why)) => tracing::error!("{why}"),
        Err(e) => tracing::error!(error = %e, "cannot settle the renewal files"),
    }
}

pub struct RenewCtx {
    pub client: ClientHandle,
    pub stats: SharedStats,
    pub server_base_url: String,
    pub host_id: String,
    pub paths: Paths,
    pub shutdown: CancellationToken,
}

pub struct Renewer {
    ctx: RenewCtx,
    /// False when this account cannot create files beside the live pair.
    enabled: bool,
    /// The pair the current client was built from.
    loaded: Option<(Vec<u8>, Vec<u8>)>,
    fails: u32,
    retry_at: Option<i64>,
    log: Limiter,
}

fn when(t: i64) -> String {
    OffsetDateTime::from_unix_timestamp(t)
        .map(|t| t.to_string())
        .unwrap_or_default()
}

impl Renewer {
    pub fn new(ctx: RenewCtx) -> Self {
        let owned = match pair::key_owner_problem(&ctx.paths) {
            None => true,
            Some(why) => {
                tracing::error!("{why}");
                false
            }
        };
        let writable = match pair::writable(&ctx.paths) {
            Ok(()) => true,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "certificate renewal is off: this account cannot create files in the \
                     directory of client.key or of client.crt. Give the directory to the \
                     sender account (an `enroll` run as root leaves it root-owned) and \
                     restart the sender"
                );
                false
            }
        };
        let enabled = owned && writable;
        let loaded = disk(&ctx.paths);
        Self {
            ctx,
            enabled,
            loaded,
            fails: 0,
            retry_at: None,
            log: Limiter::default(),
        }
    }

    /// One wake. Returns how long to sleep.
    pub async fn step(&mut self, now: OffsetDateTime) -> Duration {
        let t = now.unix_timestamp();
        if self.enabled {
            let (p, host) = (&self.ctx.paths, &self.ctx.host_id);
            // Not clean: no request and no rename until the next wake. A live pair that
            // was replaced on disk is still picked up, when it matches.
            match pair::settle(p, host, now) {
                Ok(None) => {}
                Ok(Some(why)) => {
                    if self.log.due("mismatch", t) {
                        tracing::error!("{why}");
                    }
                    return WAKE;
                }
                Err(e) => {
                    if self.log.due("settle", t) {
                        tracing::error!(error = %e, "cannot settle the renewal files");
                    }
                    self.reload_if_matching(t);
                    return WAKE;
                }
            }
        }
        self.reload(t);
        let Some(live) = self.loaded.as_ref().and_then(|(c, _)| pair::leaf(c)) else {
            return WAKE;
        };
        let (not_before, not_after) = (live.not_before, live.not_after);
        if t >= not_after {
            if self.log.due("expired", t) {
                tracing::error!(
                    "client certificate expired at {}. This host must enroll again: get a new \
                     token, move client.crt and client.key aside, run `lodeline-sender enroll \
                     <file>`. The sender picks the new pair up without a restart",
                    when(not_after)
                );
            }
            return WAKE;
        }
        let due = target(not_before, not_after, &self.ctx.host_id);
        let until = |at: i64| {
            Duration::from_secs((at - t).max(0) as u64).clamp(Duration::from_millis(500), WAKE)
        };
        if t < due {
            return until(due);
        }
        if !self.enabled {
            if self.log.due("off", t) {
                tracing::error!(
                    "client certificate expires at {} and renewal is off (see the start of \
                     this log); enroll this host again before then",
                    when(not_after)
                );
            }
            return WAKE;
        }
        if let Some(at) = self.retry_at.filter(|&at| t < at) {
            return until(at);
        }
        let near = (not_after - t) * 10 < not_after - not_before;
        let wait = match self.attempt(now, not_after).await {
            Ok(()) => {
                // The swap, at once: the next request already uses the new pair.
                self.reload(t);
                return Duration::from_millis(500);
            }
            Err(Answer::TooEarly(wait)) => wait,
            Err(Answer::Refused(status)) => {
                if self.log.due("refused", t) {
                    tracing::error!(
                        status,
                        "the server refused to renew this host's certificate, which expires at \
                         {}. {}",
                        when(not_after),
                        if status == 404 {
                            "It does not offer renewal: enrollment is off there, its audit file \
                             is unreadable, or it is older than this sender. Fix the server, or \
                             enroll this host again with a new token before the certificate expires"
                        } else {
                            "Either this certificate is no longer the newest one issued for the \
                             host (the host was enrolled again, or a copy of its key renewed \
                             first), or the server already issued three certificates for it, or \
                             the host is not on the allowlist. Check the server's audit file for \
                             this host: if the certificate was replaced, enroll this host again \
                             with a new token (move client.crt and client.key aside first). \
                             Otherwise check the allowlist"
                        }
                    );
                }
                refused_wait(not_before, not_after)
            }
            Err(Answer::Failed(cause)) => {
                self.fails += 1;
                if self.log.due("failed", t) {
                    if near {
                        tracing::error!(%cause, "certificate renewal failed and the certificate expires at {}", when(not_after));
                    } else {
                        tracing::warn!(%cause, "certificate renewal failed; trying again later");
                    }
                }
                backoff(not_before, not_after, &self.ctx.host_id, self.fails)
            }
            Err(Answer::Issued(_)) => unreachable!("attempt returns Ok for an issued answer"),
        };
        self.retry_at = Some(t + wait.as_secs().max(1) as i64);
        wait.clamp(Duration::from_millis(500), WAKE)
    }

    /// One renewal: request, check, store, build a client from the new pair, commit.
    /// `Err` carries what to do next; the next files stay for a repeat with the same CSR.
    async fn attempt(&mut self, now: OffsetDateTime, live_not_after: i64) -> Result<(), Answer> {
        let fail = |e: &dyn std::fmt::Display| Answer::Failed(e.to_string());
        let ctx = &self.ctx;
        let (key, csr) = pair::prepare(&ctx.paths, &ctx.host_id).map_err(|e| fail(&e))?;
        let answer = net::request(&ctx.client.get(), &ctx.server_base_url, &csr).await;
        let Answer::Issued(issued) = answer else {
            return Err(answer);
        };
        let mut bundle = issued.client_cert_pem;
        if !bundle.ends_with('\n') {
            bundle.push('\n');
        }
        bundle.push_str(&issued.ca_chain_pem);
        let ca = pair::ca_pem(&ctx.paths).map_err(|e| fail(&e))?;
        match pair::judge(live_not_after, &key, &bundle, &ctx.host_id, &ca, now) {
            pair::Verdict::Usable => {}
            pair::Verdict::Stale(why) | pair::Verdict::Unfit(why) => {
                return Err(fail(&format!("the server's answer cannot be used: {why}")));
            }
        }
        pair::store_cert(&ctx.paths, &bundle).map_err(|e| fail(&e))?;
        let built = build_client(
            Some(&ctx.paths.crt_next),
            Some(&ctx.paths.key_next),
            Some(&ctx.paths.ca),
        );
        if let Err(e) = built {
            let _ = std::fs::remove_file(&ctx.paths.crt_next);
            return Err(fail(&format!(
                "cannot build a client from the new pair: {e}"
            )));
        }
        pair::commit(&ctx.paths).map_err(|e| fail(&e))?;
        tracing::info!(serial = %issued.serial, not_after = %issued.not_after, "renewed the client certificate and key");
        Ok(())
    }

    fn reload_if_matching(&mut self, t: i64) {
        if pair::live_fits(&self.ctx.paths) {
            self.reload(t);
        }
    }

    /// Build a client from the live files when they differ from what the current one was
    /// built from: a renewal, a repaired commit, or an `enroll` run by hand.
    fn reload(&mut self, t: i64) {
        let Some(now_on_disk) = disk(&self.ctx.paths) else {
            return;
        };
        if self.loaded.as_ref() == Some(&now_on_disk) {
            return;
        }
        let p = &self.ctx.paths;
        match build_client(Some(&p.crt), Some(&p.key), Some(&p.ca)) {
            Ok(client) => {
                self.ctx.client.set(client);
                self.fails = 0;
                self.retry_at = None;
                if let Some(l) = pair::leaf(&now_on_disk.0) {
                    self.ctx.stats.write().client_cert_expires_at =
                        OffsetDateTime::from_unix_timestamp(l.not_after).ok();
                }
                self.loaded = Some(now_on_disk);
            }
            Err(e) if self.log.due("reload", t) => {
                tracing::error!(error = %e, "the key and certificate on disk cannot be used; keeping the current client");
            }
            Err(_) => {}
        }
    }
}

fn disk(p: &Paths) -> Option<(Vec<u8>, Vec<u8>)> {
    Some((std::fs::read(&p.crt).ok()?, std::fs::read(&p.key).ok()?))
}

pub async fn run(ctx: RenewCtx) {
    let shutdown = ctx.shutdown.clone();
    let mut renewer = Renewer::new(ctx);
    loop {
        let wait = renewer.step(OffsetDateTime::now_utc()).await;
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(wait) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOSTS: [&str; 4] = [
        "3f2c6a1e-8b4d-4c2a-9e7f-1a2b3c4d5e6f",
        "018f9c1a-0000-7000-8000-00000000aa01",
        "018f9c1a-0000-7000-8000-00000000aa02",
        "5a1c6a1e-8b4d-4c2a-9e7f-1a2b3c4d5e70",
    ];

    #[test]
    fn the_target_lies_between_sixty_and_seventy_five_percent_of_any_validity() {
        for v in [15, 3600, 86_400, 30 * 86_400, 365 * 86_400] {
            for h in HOSTS {
                let t = target(1_000_000, 1_000_000 + v, h) - 1_000_000;
                assert!(
                    t as f64 >= v as f64 * 0.60 - 1.0 && t as f64 <= v as f64 * 0.75,
                    "{v} s, {h}: {t}"
                );
            }
        }
    }

    #[test]
    fn hosts_get_different_targets_and_one_host_always_the_same() {
        let t = |h| target(0, 30 * 86_400, h);
        let all: std::collections::HashSet<_> = HOSTS.iter().map(|h| t(h)).collect();
        assert_eq!(all.len(), HOSTS.len(), "the offset comes from the host_id");
        assert_eq!(t(HOSTS[0]), t(HOSTS[0]));
    }

    #[test]
    fn a_fifteen_second_certificate_retries_before_it_expires() {
        // Due at 9 s at the earliest, so 6 s remain for the retries.
        let first = backoff(0, 15, HOSTS[0], 1);
        assert!(first <= Duration::from_secs(2), "{first:?}");
        let sum: f64 = (1..=3)
            .map(|n| backoff(0, 15, HOSTS[0], n).as_secs_f64())
            .sum();
        assert!(sum < 6.0, "three attempts fit before expiry: {sum}");
    }

    #[test]
    fn backoff_grows_and_stops_at_an_hour_for_a_month_long_certificate() {
        let month = 30 * 86_400;
        let w = |n| backoff(0, month, HOSTS[0], n).as_secs_f64();
        assert!((48.0..=72.0).contains(&w(1)), "{}", w(1));
        assert!(w(2) > w(1) * 1.9 && w(2) < w(1) * 2.1);
        assert!((2880.0..=4320.0).contains(&w(30)), "{}", w(30));
    }

    #[test]
    fn a_refusal_waits_a_tenth_of_the_validity_between_a_minute_and_six_hours() {
        assert_eq!(refused_wait(0, 15), Duration::from_secs(60));
        assert_eq!(refused_wait(0, 30 * 86_400), Duration::from_secs(21_600));
    }

    #[test]
    fn a_log_line_is_due_once_per_period() {
        let mut l = Limiter::default();
        assert!(l.due("a", 0));
        assert!(!l.due("a", LOG_EVERY - 1));
        assert!(l.due("b", 1), "another line has its own period");
        assert!(l.due("a", LOG_EVERY));
    }
}
