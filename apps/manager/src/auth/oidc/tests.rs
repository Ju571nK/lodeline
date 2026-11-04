//! Go's `internal/auth/oidc_test.go` against the ported fake provider, plus the go-oidc and
//! x/oauth2 rules the Go tests do not reach. Expected strings marked "Go" were printed by Go
//! 1.26 with go-oidc v3.21.0 and x/oauth2 v0.36.0.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::json;
use sha2::{Digest, Sha256};

use super::*;
use crate::config::OidcConfig;
use crate::testutil::{authorize_redirect, Mutate, OidcProvider};

fn config(p: &OidcProvider) -> OidcConfig {
    OidcConfig {
        issuer: p.url.clone(),
        client_id: "console".into(),
        client_secret: "test-secret".into(),
        redirect_url: "https://console.example/api/v1/auth/oidc/callback".into(),
        allowed_subjects: vec!["employee-1".into()],
    }
}

fn param(url: &reqwest::Url, key: &str) -> String {
    url.query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Starts a login and follows the provider's redirect: the state, the binding and the code.
async fn start_login(o: &Oidc, p: &OidcProvider) -> (String, String, String) {
    let (location, binding) = o.begin().unwrap();
    let callback = authorize_redirect(&p.client(), &location).await;
    (param(&callback, "state"), binding, param(&callback, "code"))
}

#[tokio::test]
async fn oidc_flow_matches_go() {
    let at_hash_ok: Mutate = |c| {
        c.insert(
            "at_hash".into(),
            json!(base64url(&Sha256::digest(b"opaque")[..16])),
        );
    };
    let cases: Vec<(&str, Option<Mutate>, bool)> = vec![
        ("standard provider", None, false),
        (
            "unknown subject",
            Some(|c| {
                c.insert("sub".into(), json!("outsider"));
            }),
            true,
        ),
        (
            "wrong nonce",
            Some(|c| {
                c.insert("nonce".into(), json!("wrong"));
            }),
            true,
        ),
        (
            "wrong issuer",
            Some(|c| {
                c.insert("iss".into(), json!("https://other.example"));
            }),
            true,
        ),
        (
            "wrong audience",
            Some(|c| {
                c.insert("aud".into(), json!("other"));
            }),
            true,
        ),
        (
            "expired",
            Some(|c| {
                c.insert("exp".into(), json!(now() - 3600));
            }),
            true,
        ),
        (
            "wrong authorized party",
            Some(|c| {
                c.insert("azp".into(), json!("other"));
            }),
            true,
        ),
        (
            "multiple audiences without azp",
            Some(|c| {
                c.insert("aud".into(), json!(["console", "other"]));
            }),
            true,
        ),
        (
            "multiple audiences with azp",
            Some(|c| {
                c.insert("aud".into(), json!(["console", "other"]));
                c.insert("azp".into(), json!("console"));
            }),
            false,
        ),
        // Beyond Go's table.
        ("matching at_hash", Some(at_hash_ok), false),
        (
            "wrong at_hash",
            Some(|c| {
                c.insert("at_hash".into(), json!("AAAAAAAAAAAAAAAAAAAAAA"));
            }),
            true,
        ),
        (
            "subject differs in case only",
            Some(|c| {
                c.insert("sub".into(), json!("Employee-1"));
            }),
            true,
        ),
        (
            "no exp",
            Some(|c| {
                c.remove("exp");
            }),
            true,
        ),
        (
            "iat null",
            Some(|c| {
                c.insert("iat".into(), json!(null));
            }),
            true,
        ),
        (
            "nbf inside the 5 minute allowance",
            Some(|c| {
                c.insert("nbf".into(), json!(now() + 240));
            }),
            false,
        ),
        (
            "nbf past the 5 minute allowance",
            Some(|c| {
                c.insert("nbf".into(), json!(now() + 400));
            }),
            true,
        ),
        (
            "azp equal to the client with one audience",
            Some(|c| {
                c.insert("azp".into(), json!("console"));
            }),
            false,
        ),
        (
            "nonce missing",
            Some(|c| {
                c.remove("nonce");
            }),
            true,
        ),
    ];
    let p = OidcProvider::start(false).await;
    let o = Oidc::discover(&config(&p), p.client()).await.unwrap();
    for (name, mutate, denied) in cases {
        p.mutate(mutate);
        let (state, binding, code) = start_login(&o, &p).await;
        assert!(
            o.complete(&state, "wrong-browser", &code).await.is_none(),
            "{name}: wrong binding"
        );
        let got = o.complete(&state, &binding, &code).await;
        if denied {
            assert!(got.is_none(), "{name}");
        } else {
            let (subject, exp) = got.unwrap_or_else(|| panic!("{name}"));
            assert_eq!(subject, identity(&p.url, "employee-1"), "{name}");
            assert!(subject.starts_with("oidc:"), "{name}");
            assert!(exp.abs_diff(now() as i64 + 3600) <= 3, "{name}: {exp}");
        }
        assert!(
            o.complete(&state, &binding, &code).await.is_none(),
            "{name}: a second use must fail"
        );
    }
}

#[tokio::test]
async fn attempts_expire_and_are_capped() {
    let p = OidcProvider::start(false).await;
    let mut o = Oidc::discover(&config(&p), p.client()).await.unwrap();
    let (location, binding) = o.begin().unwrap();
    let state = param(&reqwest::Url::parse(&location).unwrap(), "state");
    let base = Instant::now();
    o.now = Box::new(move || base + LOGIN_ATTEMPT_TTL + Duration::from_secs(1));
    assert!(o.consume(&state, &binding).is_none());
    for _ in 0..MAX_LOGIN_ATTEMPTS {
        assert!(o.begin().is_some());
    }
    assert!(o.begin().is_none());
    o.now = Box::new(move || base + 2 * LOGIN_ATTEMPT_TTL + Duration::from_secs(60));
    assert!(o.begin().is_some());
}

/// A matched binding uses the attempt up even when the rest fails; an error answer from the
/// provider (no code) still consumes it.
#[tokio::test]
async fn a_matched_attempt_is_used_once_even_on_failure() {
    let p = OidcProvider::start(false).await;
    let o = Oidc::discover(&config(&p), p.client()).await.unwrap();
    let (state, binding, code) = start_login(&o, &p).await;
    assert!(o.complete(&state, &binding, "").await.is_none());
    assert!(o.complete(&state, &binding, &code).await.is_none());
    assert!(o.complete(&state, "", &code).await.is_none());
    assert!(o.complete("", &binding, &code).await.is_none());
}

#[tokio::test]
async fn rejects_an_invalid_signature() {
    let p = OidcProvider::start(true).await;
    let o = Oidc::discover(&config(&p), p.client()).await.unwrap();
    let (state, binding, code) = start_login(&o, &p).await;
    assert!(o.complete(&state, &binding, &code).await.is_none());
}

#[test]
fn rejects_cleartext_and_credentialed_endpoints() {
    assert!(https("http://identity.example/keys").is_none());
    assert!(https("https://user:pass@identity.example/keys").is_none());
    assert!(https("https://identity.example/keys").is_some());
}

#[tokio::test]
async fn discovery_requires_the_issuer_and_https_endpoints() {
    let p = OidcProvider::start(false).await;
    let changes: [(Mutate, &str); 6] = [
        (
            |d| {
                d.insert("issuer".into(), json!("https://other.example"));
            },
            "discovery failed",
        ),
        (
            |d| {
                let url = d["token_endpoint"]
                    .as_str()
                    .unwrap()
                    .replace("https", "http");
                d.insert("token_endpoint".into(), json!(url));
            },
            "HTTPS authorization and token endpoints",
        ),
        (
            |d| {
                d.insert("authorization_endpoint".into(), json!("/authorize"));
            },
            "HTTPS authorization and token endpoints",
        ),
        (
            |d| {
                d.insert(
                    "authorization_endpoint".into(),
                    json!("https://id.example/authorize#f"),
                );
            },
            "HTTPS authorization and token endpoints",
        ),
        (
            |d| {
                d.insert("userinfo_endpoint".into(), json!(5));
            },
            "discovery failed",
        ),
        (
            |d| {
                d.insert(
                    "id_token_signing_alg_values_supported".into(),
                    json!("RS256"),
                );
            },
            "discovery failed",
        ),
    ];
    for (change, want) in changes {
        p.mutate_discovery(Some(change));
        let err = Oidc::discover(&config(&p), p.client()).await.err().unwrap();
        assert!(err.contains(want), "{err}");
    }
    // An http issuer never leaves the process.
    let mut c = config(&p);
    c.issuer = c.issuer.replace("https", "http");
    assert!(Oidc::discover(&c, p.client()).await.is_err());
}

/// The provider lists only algorithms the console does not accept, so its RS256 tokens fail.
#[tokio::test]
async fn the_discovered_algorithms_bind_the_id_token() {
    let p = OidcProvider::start(false).await;
    p.mutate_discovery(Some(|d| {
        d.insert(
            "id_token_signing_alg_values_supported".into(),
            json!(["ES256", "HS256"]),
        );
    }));
    let o = Oidc::discover(&config(&p), p.client()).await.unwrap();
    assert_eq!(o.algorithms, ["ES256"]);
    let (state, binding, code) = start_login(&o, &p).await;
    assert!(o.complete(&state, &binding, &code).await.is_none());

    p.mutate_discovery(Some(|d| {
        d.remove("id_token_signing_alg_values_supported");
    }));
    let o = Oidc::discover(&config(&p), p.client()).await.unwrap();
    assert_eq!(o.algorithms, ["RS256"]);
}

/// x/oauth2 tries the client secret in a basic auth header first, then in the form, and keeps
/// the style that worked.
#[tokio::test]
async fn the_token_request_falls_back_to_form_credentials() {
    let p = OidcProvider::start(false).await;
    p.form_auth_only(true);
    let o = Oidc::discover(&config(&p), p.client()).await.unwrap();
    let (state, binding, code) = start_login(&o, &p).await;
    assert!(o.complete(&state, &binding, &code).await.is_some());
    assert_eq!(p.token_requests(), 2);
    let (state, binding, code) = start_login(&o, &p).await;
    assert!(o.complete(&state, &binding, &code).await.is_some());
    assert_eq!(p.token_requests(), 3);
}

#[tokio::test]
async fn the_authorization_url_matches_go() {
    let p = OidcProvider::start(false).await;
    let mut o = Oidc::discover(&config(&p), p.client()).await.unwrap();
    o.client_id = "console id".into();
    o.auth_url = "https://id.example/authorize?tenant=a b".into();
    // Go.
    let want = "https://id.example/authorize?tenant=a b&client_id=console+id&code_challenge=a1Y-Z7sHPycP84FUZMgqhDyqVo6DdP5EUEXrLaTUge0&code_challenge_method=S256&nonce=NONCE&redirect_uri=https%3A%2F%2Fconsole.example%2Fapi%2Fv1%2Fauth%2Foidc%2Fcallback&response_mode=query&response_type=code&scope=openid&state=STATE";
    assert_eq!(o.authorization_url("STATE", "NONCE", "VERIFIER"), want);

    // Each value is 32 random bytes, base64url.
    let (location, binding) = o.begin().unwrap();
    let url = reqwest::Url::parse(&location).unwrap();
    let state = param(&url, "state");
    let attempts = o.attempts.lock().unwrap();
    let a = &attempts[&state];
    for v in [&state, &binding, &a.nonce, &a.verifier] {
        assert_eq!(v.len(), 43, "{v}");
    }
    assert_eq!(a.nonce, param(&url, "nonce"));
    assert_eq!(
        param(&url, "code_challenge"),
        base64url(&Sha256::digest(a.verifier.as_bytes()))
    );
    assert_ne!(a.binding, state);
}

#[test]
fn form_encoding_matches_go() {
    // Go: url.Values{"a b": {"x&y=z+"}, "c": {"~-._"}, "é": {"/?#%"}}.Encode()
    assert_eq!(
        encode_form(vec![("é", "/?#%"), ("c", "~-._"), ("a b", "x&y=z+")]),
        "a+b=x%26y%3Dz%2B&c=~-._&%C3%A9=%2F%3F%23%25"
    );
    assert_eq!(
        format!("{}:{}", query_escape("console id"), query_escape("s&cret")),
        "console+id:s%26cret"
    );
    assert_eq!(
        parse_form("a=1&b=x+y&a=2&c=%41"),
        Some(vec![
            ("a".into(), "1".into()),
            ("b".into(), "x y".into()),
            ("a".into(), "2".into()),
            ("c".into(), "A".into()),
        ])
    );
    assert_eq!(parse_form("a=1;b=2"), None);
    assert_eq!(parse_form("a=%zz"), None);
}

/// Vectors printed by Go's `json.Marshal([]string{iss, sub})` and SHA-256.
#[test]
fn identity_matches_go() {
    let cases = [
        (
            "https://id.example",
            "employee-1",
            "oidc:e0fc34e7701636200f4f3d75949b3552552d2cc9e7d1ede68344a4ccf80847b4",
        ),
        (
            "https://id.example/realm",
            "a<&>b",
            "oidc:712d734405bbaec2dc53208ae9b909b49fc460759f093fca91a7d151df398322",
        ),
        (
            "https://id.example/?a=1&b=<2>",
            "\"quoted\" \\ back",
            "oidc:fbce5ec2d2c5e07e031e7656d39d5af6583dbf11f67dca72bc2e8f14e01daa3e",
        ),
        (
            "https://id.example",
            "ctl\u{8}\u{c}\n\r\t\u{1}\u{1f}\u{7f} end",
            "oidc:f1eede1f27e7605f9069e28c830869432f9e996a03b5cf5994f15340b9bf94b5",
        ),
        (
            "https://id.example",
            "line\u{2028}para\u{2029} é 漢字 😀",
            "oidc:86eb7f9a4735111e22454d2872997c1aa68b190f49f70a0625ce8deb39e00b8a",
        ),
    ];
    for (iss, sub, want) in cases {
        assert_eq!(identity(iss, sub), want, "{sub:?}");
    }
}

#[test]
fn at_hash_matches_go() {
    // Go: base64.RawURLEncoding of the first half of sha256("opaque").
    assert_eq!(
        at_hash(Algorithm::RS256, "opaque").as_deref(),
        Some("bSKYhMEmi7CrMtjaMV0P5Q")
    );
    assert_eq!(at_hash(Algorithm::RS384, "opaque").unwrap().len(), 32);
    assert_eq!(at_hash(Algorithm::EdDSA, "opaque").unwrap().len(), 43);
    assert_eq!(at_hash(Algorithm::HS256, "opaque"), None);
}

#[test]
fn id_token_claims_decode_as_go_does() {
    let ok = |p: &str| id_claims(p.as_bytes());
    let c = ok(r#"{"ISS":"i","Sub":"s","aud":"a","exp":"100","iat":1.9,"nbf":null,"NONCE":"n","azp":null}"#).unwrap();
    assert_eq!(
        (c.iss.as_str(), c.sub.as_str(), c.nonce.as_str()),
        ("i", "s", "n")
    );
    assert_eq!(
        (c.aud, c.exp, c.nbf),
        (vec!["a".to_owned()], Some(100), None)
    );
    assert_eq!(ok(r#"{"exp":1e3}"#).unwrap().exp, Some(1000));
    assert_eq!(ok(r#"{"exp":-1.5}"#).unwrap().exp, Some(-1));
    assert_eq!(ok(r#"{"aud":null}"#).unwrap().aud, [""]);
    assert_eq!(ok(r#"{"aud":["a",null]}"#).unwrap().aud, ["a", ""]);
    assert_eq!(ok(r#"{"sub":"a","sub":"b"}"#).unwrap().sub, "b");
    assert!(ok("null").is_some());
    assert!(ok(r#"{"_claim_names":{"x":"s"},"_claim_sources":{"s":{"endpoint":"e"}}}"#).is_some());
    for bad in [
        "[]",
        r#"{"sub":1}"#,
        r#"{"aud":5}"#,
        r#"{"aud":[1]}"#,
        r#"{"exp":null}"#,
        r#"{"iat":null}"#,
        r#"{"exp":"soon"}"#,
        r#"{"exp":" 1"}"#,
        r#"{"exp":true}"#,
        r#"{"exp":1e999}"#,
        r#"{"azp":7}"#,
        r#"{"_claim_names":{"x":"s"}}"#,
        r#"{"_claim_names":{"x":""},"_claim_sources":{"":{}}}"#,
        r#"{"_claim_sources":{"s":{"endpoint":1}}}"#,
        r#"{} x"#,
    ] {
        assert!(ok(bad).is_none(), "{bad}");
    }
}

#[test]
fn token_responses_decode_as_x_oauth2_does() {
    let t = token_json(br#"{"access_token":"a","id_token":"x","expires_in":"3600"}"#).unwrap();
    assert_eq!(
        (t.access_token.as_str(), t.id_token.as_deref()),
        ("a", Some("x"))
    );
    // The raw map's keys match exactly; the struct's fold case.
    let t = token_json(br#"{"ACCESS_TOKEN":"a","ID_TOKEN":"x"}"#).unwrap();
    assert_eq!((t.access_token.as_str(), t.id_token), ("a", None));
    assert_eq!(
        token_json(br#"{"error":"denied"}"#).unwrap().error,
        "denied"
    );
    assert_eq!(token_json(br#"{"id_token":5}"#).unwrap().id_token, None);
    for bad in [
        r#"{"expires_in":3600.5}"#,
        r#"{"expires_in":"x"}"#,
        r#"{"access_token":1}"#,
        "[]",
    ] {
        assert!(token_json(bad.as_bytes()).is_none(), "{bad}");
    }
}

/// An HMAC ID token is never accepted, whatever secret signed it: the provider's algorithms
/// are asymmetric only.
#[tokio::test]
async fn rejects_an_hmac_id_token() {
    let p = OidcProvider::start(false).await;
    let o = Oidc::discover(&config(&p), p.client()).await.unwrap();
    let claims = json!({"iss": p.url, "sub": "employee-1", "aud": "console", "exp": now() + 60});
    for secret in [&b"test-secret"[..], p.url.as_bytes()] {
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(Algorithm::HS256),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(secret),
        )
        .unwrap();
        assert!(o.verify_signature(&token).await.is_none());
    }
}
