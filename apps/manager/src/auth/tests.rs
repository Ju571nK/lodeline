//! The session forms of the parity table and Go's `jwt_test.go` verify cases, as unit tests.

use super::*;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde_json::json;
use std::time::Duration;

const SECRET: &str = "0123456789abcdefghijklmnopqrstuv";
const NOW: u64 = 1_779_192_000; // 2026-05-19T12:00:00Z, the clock of Go's jwt_test.go

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn token(alg: Algorithm, claims: &Value, secret: &str) -> String {
    encode(
        &Header::new(alg),
        claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap()
}

fn valid_claims() -> Value {
    json!({"iss": ISSUER, "sub": "admin", "iat": NOW, "nbf": NOW, "exp": NOW + 12 * 3600})
}

fn with(changes: Value) -> Value {
    let mut claims = valid_claims();
    for (k, v) in changes.as_object().unwrap() {
        if v.is_null() {
            claims.as_object_mut().unwrap().remove(k);
        } else {
            claims[k] = v.clone();
        }
    }
    claims
}

fn signer() -> Signer {
    Signer::new(SECRET.as_bytes(), Duration::from_secs(12 * 3600)).unwrap()
}

fn verify(token: &str, now: u64) -> Result<String, VerifyError> {
    signer()
        .verify_at(token, at(now))
        .map(|(subject, _)| subject)
}

fn b64(s: &str) -> String {
    base64url(s.as_bytes())
}

#[test]
fn accepts_a_valid_token() {
    let t = token(Algorithm::HS256, &valid_claims(), SECRET);
    assert_eq!(verify(&t, NOW), Ok("admin".to_owned()));
}

#[test]
fn session_forms_match_go() {
    use VerifyError::{Expired, Invalid};
    let past = NOW - 1000;
    let cases: Vec<(&str, Value, Result<&str, VerifyError>)> = vec![
        ("expired", json!({"exp": past}), Err(Expired)),
        ("expired at this second", json!({"exp": NOW}), Err(Expired)),
        ("expires next second", json!({"exp": NOW + 1}), Ok("admin")),
        ("expired-5s", json!({"exp": NOW - 5}), Err(Expired)),
        (
            "expired-wrong-issuer",
            json!({"exp": past, "iss": "someone-else"}),
            Err(Expired),
        ),
        (
            "expired-empty-subject",
            json!({"exp": past, "sub": ""}),
            Err(Expired),
        ),
        (
            "expired-not-yet-valid",
            json!({"exp": past, "nbf": NOW + 60}),
            Err(Expired),
        ),
        ("wrong-issuer", json!({"iss": "someone-else"}), Err(Invalid)),
        ("missing issuer", json!({"iss": null}), Err(Invalid)),
        ("empty-subject", json!({"sub": ""}), Err(Invalid)),
        ("missing subject", json!({"sub": null}), Err(Invalid)),
        ("not-yet-valid-5s", json!({"nbf": NOW + 5}), Err(Invalid)),
        ("valid from this second", json!({"nbf": NOW}), Ok("admin")),
        ("no-exp", json!({"exp": null}), Ok("admin")),
        ("no nbf", json!({"nbf": null}), Ok("admin")),
        ("issued-in-5s", json!({"iat": NOW + 5}), Ok("admin")),
        (
            "other-subject",
            json!({"sub": "someone-else"}),
            Ok("someone-else"),
        ),
        (
            "fractional-exp",
            json!({"exp": NOW as f64 + 60.75}),
            Ok("admin"),
        ),
        (
            "fractional exp floors to the second",
            json!({"exp": NOW as f64 + 0.75}),
            Err(Expired),
        ),
        (
            "with-audience",
            json!({"aud": "some-other-service"}),
            Ok("admin"),
        ),
        ("audience list", json!({"aud": ["a", "b"]}), Ok("admin")),
        (
            "exp as a numeric string",
            json!({"exp": (NOW + 60).to_string()}),
            Ok("admin"),
        ),
        (
            "exp as a non-numeric string",
            json!({"exp": "soon"}),
            Err(Invalid),
        ),
        (
            "exp as a padded string",
            json!({"exp": format!(" {}", NOW + 60)}),
            Err(Invalid),
        ),
        ("subject as a number", json!({"sub": 7}), Err(Invalid)),
        ("audience as a number", json!({"aud": 7}), Err(Invalid)),
        (
            "audience list with a number",
            json!({"aud": ["a", 7]}),
            Err(Invalid),
        ),
        ("iat as an object", json!({"iat": {}}), Err(Invalid)),
    ];
    for (name, changes, want) in cases {
        let t = token(Algorithm::HS256, &with(changes), SECRET);
        assert_eq!(verify(&t, NOW), want.map(str::to_owned), "{name}");
    }
}

fn signed_raw(claims: &str) -> String {
    let message = format!("{}.{}", b64(r#"{"alg":"HS256","typ":"JWT"}"#), b64(claims));
    let key = EncodingKey::from_secret(SECRET.as_bytes());
    let signature = jsonwebtoken::crypto::sign(message.as_bytes(), &key, Algorithm::HS256).unwrap();
    format!("{message}.{signature}")
}

#[test]
fn refuses_claim_keys_that_differ_only_by_case_and_repeated_claims() {
    let (exp, past) = (NOW + 60, NOW - 60);
    let cases = [
        (
            "upper-case issuer",
            format!(r#"{{"ISS":"{ISSUER}","sub":"admin","exp":{exp}}}"#),
        ),
        (
            "subject, then a mixed-case subject",
            format!(r#"{{"iss":"{ISSUER}","sub":"admin","Sub":"","exp":{exp}}}"#),
        ),
        (
            "long s folds to s",
            format!(r#"{{"iss":"{ISSUER}","sub":"admin","ſub":"","exp":{exp}}}"#),
        ),
        (
            "mistyped upper-case audience",
            format!(r#"{{"iss":"{ISSUER}","sub":"admin","AUD":5,"exp":{exp}}}"#),
        ),
        (
            "exp twice",
            format!(r#"{{"iss":"{ISSUER}","sub":"admin","exp":{past},"exp":{exp}}}"#),
        ),
    ];
    for (name, claims) in cases {
        assert_eq!(
            verify(&signed_raw(&claims), NOW),
            Err(VerifyError::Invalid),
            "{name}"
        );
    }
    let other_keys = format!(r#"{{"iss":"{ISSUER}","sub":"admin","exp":{exp},"x":1,"X":2,"x":3}}"#);
    assert_eq!(
        verify(&signed_raw(&other_keys), NOW),
        Ok("admin".to_owned())
    );
}

// Go's time.Unix wraps past its range, so such an expiry lies in the past.
#[test]
fn an_expiry_past_gos_time_range_is_expired() {
    let last_go_second = 9_223_371_974_719_178_752.0; // the largest f64 at or below i64::MAX - 62135596800
    for exp in [json!(last_go_second), json!(9.2e18)] {
        let t = token(Algorithm::HS256, &with(json!({ "exp": exp })), SECRET);
        assert_eq!(verify(&t, NOW), Ok("admin".to_owned()), "{exp}");
    }
    for exp in [
        json!(9_223_371_974_719_179_776.0),
        json!(9.3e18),
        json!(2f64.powi(63)),
        json!(u64::MAX),
        json!(1e30),
        json!("1e30"),
    ] {
        let t = token(Algorithm::HS256, &with(json!({ "exp": exp })), SECRET);
        assert_eq!(verify(&t, NOW), Err(VerifyError::Expired), "{exp}");
    }
    let big = format!(r#"{{"iss":"{ISSUER}","sub":"admin","exp":99999999999999999999999}}"#);
    assert_eq!(verify(&signed_raw(&big), NOW), Err(VerifyError::Expired));
}

// Go limits the subject length when signing, not when verifying.
#[test]
fn accepts_a_long_subject() {
    let long = "a".repeat(300);
    let t = token(Algorithm::HS256, &with(json!({ "sub": long })), SECRET);
    assert_eq!(verify(&t, NOW), Ok(long));
}

#[test]
fn rejects_other_algorithms_and_keys() {
    let claims = valid_claims();
    let hs512 = token(Algorithm::HS512, &claims, SECRET);
    let wrong_key = token(
        Algorithm::HS256,
        &claims,
        "differentdifferentdifferentXXXXX",
    );
    let alg_none = format!(
        "{}.{}.",
        b64(r#"{"alg":"none","typ":"JWT"}"#),
        b64(&claims.to_string())
    );
    for (name, t) in [
        ("hs512", hs512),
        ("wrong key", wrong_key),
        ("alg none", alg_none),
    ] {
        assert_eq!(verify(&t, NOW), Err(VerifyError::Invalid), "{name}");
    }
}

#[test]
fn an_expired_token_with_a_bad_signature_is_invalid() {
    let t = token(
        Algorithm::HS256,
        &with(json!({"exp": NOW - 1000})),
        "differentdifferentdifferentXXXXX",
    );
    assert_eq!(verify(&t, NOW), Err(VerifyError::Invalid));
}

#[test]
fn rejects_tampered_and_malformed_tokens() {
    let t = token(Algorithm::HS256, &valid_claims(), SECRET);
    let parts: Vec<&str> = t.split('.').collect();
    let tampered = format!(
        "{}.{}.{}",
        parts[0],
        b64(&with(json!({"sub": "other-user"})).to_string()),
        parts[2]
    );
    let not_object = format!("{}.{}.", parts[0], b64("[]"));
    for (name, t) in [
        ("empty", String::new()),
        ("garbage", "not-a-token".to_owned()),
        ("tampered", tampered),
        ("claims not an object", not_object),
        ("two parts", format!("{}.{}", parts[0], parts[1])),
    ] {
        assert_eq!(verify(&t, NOW), Err(VerifyError::Invalid), "{name}");
    }
}

#[test]
fn accepts_the_go_minted_session_token() {
    // The parity suite's throwaway JWT_SECRET (web/tests/parity/env.ts).
    let secret = "parity-jwt-29d7b42591a19bb0ac7e84f4b0b4169b38028f60";
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/session-token.txt");
    let token = std::fs::read_to_string(path).unwrap();
    let signer = Signer::new(secret.as_bytes(), Duration::from_secs(3600)).unwrap();
    assert_eq!(signer.verify(token.trim()), Ok("admin".to_owned()));
}

#[test]
fn reads_the_session_cookie_as_go_does() {
    let cookie = |lines: &[&str]| {
        let mut headers = HeaderMap::new();
        for line in lines {
            headers.append(header::COOKIE, line.parse().unwrap());
        }
        request_cookie(&headers, COOKIE_NAME).map(str::to_owned)
    };
    let cases: [(&[&str], Option<&str>); 9] = [
        (&[], None),
        (&["other=1"], None),
        (&["lodeline_session=a.b.c"], Some("a.b.c")),
        (&["other=1; lodeline_session=a.b.c"], Some("a.b.c")),
        (
            &["lodeline_session=first; lodeline_session=second"],
            Some("first"),
        ),
        (
            &["lodeline_session=first", "lodeline_session=second"],
            Some("first"),
        ),
        (&["lodeline_session="], Some("")),
        (&["lodeline_session=\"quoted\""], Some("quoted")),
        (
            &["lodeline_session=bad\\value; lodeline_session=good"],
            Some("good"),
        ),
    ];
    for (lines, want) in cases {
        assert_eq!(cookie(lines).as_deref(), want, "{lines:?}");
    }
}

// Go's jwt_test.go constructor and Sign cases, and oidc_test.go's TestSignUntilCapsSession.
#[test]
fn new_signer_checks_secret_and_ttl() {
    let err = Signer::new(b"tooshort", Duration::from_secs(3600))
        .err()
        .unwrap();
    assert!(err.contains("32 bytes"), "{err}");
    assert!(Signer::new(SECRET.as_bytes(), Duration::ZERO).is_err());
    assert!(Signer::new(SECRET.as_bytes(), Duration::from_secs(3600)).is_ok());
}

#[test]
fn sign_round_trips_the_subject_with_golang_jwt_claims() {
    let s = signer();
    let now = at(NOW) + Duration::from_millis(400);
    let (token, exp) = s.sign_at("admin", None, now).unwrap();
    assert_eq!(exp, now + Duration::from_secs(12 * 3600));
    assert_eq!(
        s.verify_at(&token, at(NOW)),
        Ok(("admin".to_owned(), Some((NOW + 12 * 3600) as i64)))
    );
    let payload = token.split('.').nth(1).unwrap();
    assert_eq!(
        payload,
        b64(&format!(
            r#"{{"iss":"lodeline-manager","sub":"admin","exp":{},"nbf":{NOW},"iat":{NOW}}}"#,
            NOW + 12 * 3600
        ))
    );
}

#[test]
fn sign_refuses_empty_and_long_subjects() {
    let s = signer();
    assert!(s.sign_at("", None, at(NOW)).is_none());
    assert!(s.sign_at(&"a".repeat(257), None, at(NOW)).is_none());
    assert!(s.sign_at(&"a".repeat(256), None, at(NOW)).is_some());
}

#[test]
fn sign_until_caps_the_session() {
    let s = signer();
    let deadline = at(NOW + 60);
    let (token, exp) = s.sign_at("oidc:subject", Some(deadline), at(NOW)).unwrap();
    assert_eq!(exp, deadline);
    assert_eq!(
        s.verify_at(&token, at(NOW)),
        Ok(("oidc:subject".to_owned(), Some((NOW + 60) as i64)))
    );
    assert!(s
        .sign_at("oidc:subject", Some(at(NOW - 1)), at(NOW))
        .is_none());
    assert!(s.sign_at("oidc:subject", Some(at(NOW)), at(NOW)).is_none());
}

// Go's password_test.go.
#[test]
fn password_matches_as_go_does() {
    let (password, hash) = (
        "change-me-on-first-boot",
        "$2a$10$55LlvKwbVdEZOVEdFBFshuFyd1fqHDSKTTXgK5L890cxNNZxATtg2",
    );
    assert!(password_matches(password, hash));
    for (p, h) in [
        ("wrong-password", hash),
        ("change-me-on-first-bootx", hash),
        ("", hash),
        (password, ""),
        ("", ""),
        (password, "not-a-bcrypt-hash"),
        (password, "$2a$10$tooshort"),
    ] {
        assert!(!password_matches(p, h), "{p} {h}");
    }
    let fresh = bcrypt::hash("a-fresh-password", 4).unwrap();
    assert!(password_matches("a-fresh-password", &fresh));
    assert!(!password_matches("not-the-password", &fresh));
}

/// The same password under each prefix Go and the config accept; the parity suite's `$2y$` hash.
#[test]
fn password_matches_every_accepted_prefix() {
    let hash = bcrypt::hash("pw", 4).unwrap();
    for prefix in ["$2a$", "$2b$", "$2y$"] {
        assert!(
            password_matches("pw", &format!("{prefix}{}", &hash[4..])),
            "{prefix}"
        );
    }
    let parity = "$2y$10$qZuItXlc/MfSA/5vLEKM9uK1tXFuGeLTf6QTheNacl.CkQHYW.AbK";
    assert!(password_matches("parity-9866c8cb59b2029c", parity));
}

/// bcrypt reads 72 bytes, NUL bytes included, as Go's x/crypto does.
#[test]
fn password_bytes_past_72_are_ignored() {
    let long = "x".repeat(72);
    let hash = bcrypt::hash(&long, 4).unwrap();
    assert!(password_matches(&format!("{long}tail"), &hash));
    let with_nul = bcrypt::hash("a\0b", 4).unwrap();
    assert!(password_matches("a\0b", &with_nul));
    assert!(!password_matches("a\0c", &with_nul));
}

#[test]
fn base64url_matches_go_raw_url_encoding() {
    for (input, want) in [
        (&b""[..], ""),
        (b"f", "Zg"),
        (b"fo", "Zm8"),
        (b"foo", "Zm9v"),
        (&[0xfb, 0xff], "-_8"),
    ] {
        assert_eq!(base64url(input), want);
    }
}

/// The algorithm comes from the verifier, never from the token: an RS256 header over an HMAC
/// made with the session secret is refused.
#[test]
fn rejects_an_rs256_header_over_an_hmac_signature() {
    let message = format!(
        "{}.{}",
        b64(r#"{"alg":"RS256","typ":"JWT"}"#),
        b64(&valid_claims().to_string())
    );
    let key = EncodingKey::from_secret(SECRET.as_bytes());
    let signature = jsonwebtoken::crypto::sign(message.as_bytes(), &key, Algorithm::HS256).unwrap();
    assert_eq!(
        verify(&format!("{message}.{signature}"), NOW),
        Err(VerifyError::Invalid)
    );
}
