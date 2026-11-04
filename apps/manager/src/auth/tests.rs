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

fn verify(token: &str, now: u64) -> Result<String, VerifyError> {
    Signer::new(SECRET.as_bytes()).verify_at(token, at(now))
}

fn b64(s: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let bytes = s.as_bytes();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | (b as u32) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
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
    let signer = Signer::new(secret.as_bytes());
    assert_eq!(signer.verify(token.trim()), Ok("admin".to_owned()));
}

#[test]
fn reads_the_session_cookie_as_go_does() {
    let cookie = |lines: &[&str]| {
        let mut headers = HeaderMap::new();
        for line in lines {
            headers.append(header::COOKIE, line.parse().unwrap());
        }
        session_cookie(&headers).map(str::to_owned)
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
