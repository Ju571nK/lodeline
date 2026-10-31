//! Pure lifecycle transitions of a registry entry (control-plane §1.3).
//!
//! ```text
//! pending --fingerprint--> active <--enable-- disabled
//!    |                       |  \--disable-->    |
//!    +-------- retire -------+-------------------+--> retired (terminal)
//! ```
//!
//! - `fingerprint` on `pending`: becomes `fp_current`, state `active`.
//! - `fingerprint` on `active`: sets `fp_next` (replacing an older next). The
//!   proxy's first request authenticated with `fp_next` promotes it to
//!   `fp_current` and drops the old one (`ProxyRegistry::promote_next`).
//! - `fingerprint` on `disabled`: REPLACES the entry's fingerprints (current =
//!   new, next = none) and keeps the state, so an operator can swap out a
//!   suspect cert before `enable` without a window where it works again.
//! - `disable`: `active` only. `enable`: `disabled` only. `retire`: any state
//!   but `retired`; terminal, the `proxy_id` is never reused.
//! - A fingerprint already held by any entry (including this one) is refused.

use super::registry::{ProxyRecord, ProxyState};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denied {
    /// Transition not allowed from the current state (409 `invalid_state`).
    InvalidState,
    /// Fingerprint already held (409 `already_exists`).
    FingerprintInUse,
}

pub fn new_pending(proxy_id: &str, display_name: &str, now: &str) -> ProxyRecord {
    ProxyRecord {
        proxy_id: proxy_id.to_string(),
        display_name: display_name.to_string(),
        state: ProxyState::Pending,
        fp_current: None,
        fp_next: None,
        created_at: now.to_string(),
        updated_at: now.to_string(),
    }
}

fn touched(rec: &ProxyRecord, now: &str) -> ProxyRecord {
    let mut n = rec.clone();
    n.updated_at = now.to_string();
    n
}

/// `fp_owner` is who currently holds `fp` anywhere in the registry.
pub fn add_fingerprint(
    rec: &ProxyRecord,
    fp: &str,
    fp_owner: Option<&str>,
    now: &str,
) -> Result<ProxyRecord, Denied> {
    if rec.state == ProxyState::Retired {
        return Err(Denied::InvalidState);
    }
    if fp_owner.is_some() {
        return Err(Denied::FingerprintInUse);
    }
    let mut n = touched(rec, now);
    match rec.state {
        ProxyState::Pending => {
            n.fp_current = Some(fp.to_string());
            n.fp_next = None;
            n.state = ProxyState::Active;
        }
        ProxyState::Active => n.fp_next = Some(fp.to_string()),
        ProxyState::Disabled => {
            n.fp_current = Some(fp.to_string());
            n.fp_next = None;
        }
        ProxyState::Retired => unreachable!(),
    }
    Ok(n)
}

pub fn disable(rec: &ProxyRecord, now: &str) -> Result<ProxyRecord, Denied> {
    if rec.state != ProxyState::Active {
        return Err(Denied::InvalidState);
    }
    let mut n = touched(rec, now);
    n.state = ProxyState::Disabled;
    Ok(n)
}

pub fn enable(rec: &ProxyRecord, now: &str) -> Result<ProxyRecord, Denied> {
    if rec.state != ProxyState::Disabled {
        return Err(Denied::InvalidState);
    }
    let mut n = touched(rec, now);
    n.state = ProxyState::Active;
    Ok(n)
}

pub fn retire(rec: &ProxyRecord, now: &str) -> Result<ProxyRecord, Denied> {
    if rec.state == ProxyState::Retired {
        return Err(Denied::InvalidState);
    }
    let mut n = touched(rec, now);
    n.state = ProxyState::Retired;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: &str = "2026-10-11T00:00:00Z";

    fn rec(state: ProxyState) -> ProxyRecord {
        let mut r = new_pending("px", "px", T);
        r.state = state;
        r.fp_current = Some("cur".into());
        r.fp_next = None;
        r
    }

    #[test]
    fn fingerprint_rules() {
        let p = new_pending("px", "px", T);
        let a = add_fingerprint(&p, "f1", None, T).unwrap();
        assert_eq!(
            (a.state, a.fp_current.as_deref()),
            (ProxyState::Active, Some("f1"))
        );
        let b = add_fingerprint(&a, "f2", None, T).unwrap();
        assert_eq!(
            (b.fp_current.as_deref(), b.fp_next.as_deref()),
            (Some("f1"), Some("f2"))
        );
        let c = add_fingerprint(&b, "f3", None, T).unwrap();
        assert_eq!(
            c.fp_next.as_deref(),
            Some("f3"),
            "newer next replaces older next"
        );
        assert_eq!(
            add_fingerprint(&a, "f", Some("other"), T),
            Err(Denied::FingerprintInUse)
        );
        let d = add_fingerprint(&rec(ProxyState::Disabled), "fresh", None, T).unwrap();
        assert_eq!(
            (d.state, d.fp_current.as_deref(), d.fp_next),
            (ProxyState::Disabled, Some("fresh"), None)
        );
        assert_eq!(
            add_fingerprint(&rec(ProxyState::Retired), "x", None, T),
            Err(Denied::InvalidState)
        );
    }

    #[test]
    fn transitions_matrix() {
        use ProxyState::*;
        for (from, dis, ena, ret) in [
            (Pending, false, false, true),
            (Active, true, false, true),
            (Disabled, false, true, true),
            (Retired, false, false, false),
        ] {
            let r = rec(from);
            assert_eq!(disable(&r, T).is_ok(), dis, "disable from {from:?}");
            assert_eq!(enable(&r, T).is_ok(), ena, "enable from {from:?}");
            assert_eq!(retire(&r, T).is_ok(), ret, "retire from {from:?}");
        }
        assert_eq!(disable(&rec(Active), T).unwrap().state, Disabled);
        assert_eq!(enable(&rec(Disabled), T).unwrap().state, Active);
        assert_eq!(retire(&rec(Active), T).unwrap().state, Retired);
    }
}
