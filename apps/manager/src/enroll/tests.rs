//! The settings, the template and the host id. The route is tested in `api/enrollment/tests.rs`
//! and the mint against a real server in `tests/live.rs`.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use super::*;
use crate::testutil::Pki;

mod live;

const MARK: &str = "SECRETMARK-9f3a";
const TOKEN: &str = "mint-bearer-SECRETMARK-9f3a";
const KEY_B64: &str = "xKVQIC12z2nEWqPizVT8sAuQLaXtfPgZURnVS0+pcU8=";

type Env = HashMap<&'static str, String>;

fn keystore(b64: &str, from: &str, until: &str) -> String {
    format!(
        r#"{{"pubkeys":[{{"id":"k1","ed25519_pubkey_b64":"{b64}","valid_from":"{from}","valid_until":"{until}"}}]}}"#
    )
}

fn good_keystore() -> String {
    keystore(KEY_B64, "2020-01-01T00:00:00Z", "2099-01-01T00:00:00Z")
}

fn write(path: &Path, text: &str) -> PathBuf {
    std::fs::write(path, text).unwrap();
    path.to_owned()
}

fn chmod(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

/// A full, valid environment over files in `pki`'s directory. The read identity is the
/// `client` pair, the mint identity is `mint`.
fn env(pki: &Pki) -> Env {
    pki.leaf("mint", "extendedKeyUsage=clientAuth\n");
    chmod(&pki.path("mint.key"), 0o600);
    write(&pki.path("keystore.json"), &good_keystore());
    let p = |n: &str| pki.path(n).to_string_lossy().into_owned();
    [
        (MINT_TOKEN, TOKEN.to_owned()),
        (MINT_CERT, p("mint.crt")),
        (MINT_KEY, p("mint.key")),
        (FILE_SERVER_URL, "https://lodeline.example.com:8443".into()),
        (FILE_ENROLL_URL, "https://lodeline.example.com:8444".into()),
        (FILE_CA, p("ca.crt")),
        (FILE_KEYSTORE, p("keystore.json")),
        (PUBLIC_ORIGIN, "https://console.example.com".into()),
        ("LODELINE_SERVER_CLIENT_CERT_PATH", p("client.crt")),
    ]
    .into_iter()
    .collect()
}

fn load(env: &Env, subjects: &str, mock: bool) -> Result<Enroll, ConfigError> {
    let read = |k: &str| env.get(k).cloned().unwrap_or_default();
    Enroll::load(
        &read,
        subjects,
        ("https://fleet.example.com:8443", None),
        mock,
    )
}

fn load_err(env: &Env) -> String {
    load(env, "", false).unwrap_err().to_string()
}

#[test]
fn a_full_environment_turns_the_route_on() {
    let pki = Pki::new("enroll-on");
    let e = env(&pki);
    let Enroll::On(on) = load(&e, r#"["alice"]"#, false).unwrap() else {
        panic!("off");
    };
    assert_eq!(on.public_origin, "https://console.example.com");
    assert!(on.may_enroll("alice") && !on.may_enroll("bob"));
    assert!(on.template.load().is_ok());
}

#[test]
fn none_of_the_eight_set_is_off_and_names_all_of_them() {
    let Ok(Enroll::Off(names)) = load(&Env::new(), "", false) else {
        panic!("not off");
    };
    assert_eq!(names, REQUIRED);
}

#[test]
fn each_variable_removed_alone_stops_the_start_and_names_it() {
    let pki = Pki::new("enroll-missing");
    let full = env(&pki);
    for name in REQUIRED {
        let mut e = full.clone();
        e.remove(name);
        let msg = load_err(&e);
        assert!(msg.contains(name), "{name}: {msg}");
        assert!(
            REQUIRED.iter().filter(|n| msg.contains(*n)).count() == 1,
            "{msg}"
        );
    }
}

#[test]
fn several_missing_are_all_named_and_a_setting_never_prints_a_value() {
    let pki = Pki::new("enroll-several");
    let mut e = env(&pki);
    e.remove(MINT_KEY);
    e.remove(FILE_CA);
    let msg = load_err(&e);
    assert!(msg.contains(MINT_KEY) && msg.contains(FILE_CA), "{msg}");
    assert!(!msg.contains(MARK));
}

#[test]
fn mock_mode_needs_only_the_public_origin_from_the_environment() {
    let off = load(&Env::new(), "", true).unwrap();
    assert!(matches!(off, Enroll::Off(n) if n == [PUBLIC_ORIGIN]));
    let e: Env = [(PUBLIC_ORIGIN, "http://127.0.0.1:8080".to_owned())].into();
    let Enroll::On(on) = load(&e, "", true).unwrap() else {
        panic!("off");
    };
    assert!(on.template.load().is_ok());
    let bad: Env = [(PUBLIC_ORIGIN, "http://127.0.0.1:8080/".to_owned())].into();
    assert!(load(&bad, "", true).is_err());
}

#[test]
fn the_public_origin_is_one_origin() {
    for ok in [
        "https://console.example.com",
        "http://127.0.0.1:8080",
        "HTTPS://Console.Example.COM:443",
    ] {
        assert!(origin_of(ok).is_some(), "{ok}");
    }
    assert_eq!(
        origin_of("HTTPS://Console.Example.COM:443").unwrap(),
        "https://console.example.com"
    );
    for bad in [
        "https://console.example.com/",
        "https://console.example.com/app",
        "https://console.example.com?x=1",
        "https://console.example.com#f",
        "https://alice@console.example.com",
        "ftp://console.example.com",
        "null",
        "console.example.com",
        "",
    ] {
        assert!(origin_of(bad).is_none(), "{bad}");
    }
    let pki = Pki::new("enroll-origin");
    for bad in [
        "https://console.example.com/",
        "https://console.example.com/x",
    ] {
        let mut e = env(&pki);
        e.insert(PUBLIC_ORIGIN, bad.into());
        assert!(load_err(&e).contains(PUBLIC_ORIGIN), "{bad}");
    }
}

#[test]
fn the_two_file_urls_are_https_origins() {
    let pki = Pki::new("enroll-urls");
    for name in [FILE_SERVER_URL, FILE_ENROLL_URL] {
        for bad in [
            "http://lodeline.example.com:8443",
            "https://lodeline.example.com/x",
            "lodeline.example.com",
        ] {
            let mut e = env(&pki);
            e.insert(name, bad.into());
            assert!(load_err(&e).contains(name), "{name} {bad}");
        }
    }
}

#[test]
fn the_server_url_of_the_console_must_be_https() {
    let pki = Pki::new("enroll-https");
    let e = env(&pki);
    let read = |k: &str| e.get(k).cloned().unwrap_or_default();
    let err = Enroll::load(&read, "", ("http://fleet.example.com", None), false).unwrap_err();
    assert!(err.to_string().contains("https"), "{err}");
}

#[test]
fn the_mint_certificate_must_differ_from_the_read_identity() {
    let pki = Pki::new("enroll-same");
    let mut e = env(&pki);
    e.insert(
        MINT_CERT,
        pki.path("client.crt").to_string_lossy().into_owned(),
    );
    e.insert(
        MINT_KEY,
        pki.path("client.key").to_string_lossy().into_owned(),
    );
    chmod(&pki.path("client.key"), 0o600);
    let msg = load_err(&e);
    assert!(msg.contains(MINT_CERT) && msg.contains("differ"), "{msg}");
}

#[cfg(unix)]
#[test]
fn a_mint_key_that_group_or_others_can_reach_stops_the_start() {
    let pki = Pki::new("enroll-mode");
    let e = env(&pki);
    for mode in [0o644, 0o640, 0o604] {
        chmod(&pki.path("mint.key"), mode);
        let msg = load_err(&e);
        assert!(
            msg.contains(MINT_KEY) && msg.contains("chmod 600"),
            "{mode:o} {msg}"
        );
    }
    chmod(&pki.path("mint.key"), 0o600);
    assert!(load(&e, "", false).is_ok());
}

#[test]
fn a_ca_file_must_hold_only_certificates_and_at_least_one() {
    let pki = Pki::new("enroll-ca");
    let ca = std::fs::read_to_string(pki.path("ca.crt")).unwrap();
    let key = std::fs::read_to_string(pki.path("server.key")).unwrap();
    for (what, body) in [
        ("a private key block", format!("{ca}{key}")),
        ("no block", "nothing here\n".to_owned()),
        (
            "a bad block",
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".to_owned(),
        ),
        (
            "another label",
            ca.replace("CERTIFICATE", "TRUSTED CERTIFICATE"),
        ),
    ] {
        let mut e = env(&pki);
        e.insert(
            FILE_CA,
            write(&pki.path("bad-ca.pem"), &body)
                .to_string_lossy()
                .into_owned(),
        );
        let msg = load_err(&e);
        assert!(msg.contains(FILE_CA), "{what}: {msg}");
    }
}

#[test]
fn a_keystore_must_hold_a_32_byte_key_and_a_forward_window() {
    let pki = Pki::new("enroll-ks");
    let b64_31 = "xKVQIC12z2nEWqPizVT8sAuQLaXtfPgZURnVS0+pcQ==";
    for (what, body) in [
        (
            "31 bytes",
            keystore(b64_31, "2020-01-01T00:00:00Z", "2099-01-01T00:00:00Z"),
        ),
        (
            "not base64",
            keystore("!!!", "2020-01-01T00:00:00Z", "2099-01-01T00:00:00Z"),
        ),
        (
            "backward window",
            keystore(KEY_B64, "2099-01-01T00:00:00Z", "2020-01-01T00:00:00Z"),
        ),
        (
            "equal window",
            keystore(KEY_B64, "2020-01-01T00:00:00Z", "2020-01-01T00:00:00Z"),
        ),
        (
            "bad time",
            keystore(KEY_B64, "yesterday", "2099-01-01T00:00:00Z"),
        ),
        ("no keys", r#"{"pubkeys":[]}"#.to_owned()),
    ] {
        let mut e = env(&pki);
        e.insert(
            FILE_KEYSTORE,
            write(&pki.path("bad-ks.json"), &body)
                .to_string_lossy()
                .into_owned(),
        );
        assert!(load_err(&e).contains(FILE_KEYSTORE), "{what}");
    }
}

#[test]
fn a_keystore_syntax_error_gives_a_position_and_none_of_the_content() {
    let pki = Pki::new("enroll-ks-syntax");
    let mut e = env(&pki);
    let body = format!(r#"{{"pubkeys":[{{"id":"{MARK}" "oops"}}]}}"#);
    e.insert(
        FILE_KEYSTORE,
        write(&pki.path("syntax.json"), &body)
            .to_string_lossy()
            .into_owned(),
    );
    let msg = load_err(&e);
    assert!(
        msg.contains(FILE_KEYSTORE) && msg.contains("line 1, column"),
        "{msg}"
    );
    assert!(!msg.contains(MARK), "{msg}");
    let typed = r#"{"pubkeys":[{"id":"SECRETMARK-9f3a","ed25519_pubkey_b64":7}]}"#;
    e.insert(
        FILE_KEYSTORE,
        write(&pki.path("typed.json"), typed)
            .to_string_lossy()
            .into_owned(),
    );
    assert!(!load_err(&e).contains(MARK));
}

#[test]
fn the_subject_list_is_a_nonempty_json_array() {
    let pki = Pki::new("enroll-subjects");
    let e = env(&pki);
    for bad in ["alice", "[]", r#"[""]"#, "[1]", "{}"] {
        let msg = load(&e, bad, false).unwrap_err().to_string();
        assert!(msg.contains(SUBJECTS), "{bad}: {msg}");
    }
    assert!(load(&e, r#"["alice","oidc:abc"]"#, false).is_ok());
}

#[test]
fn nothing_prints_the_bearer() {
    let pki = Pki::new("enroll-debug");
    let e = env(&pki);
    let on = load(&e, "", false).unwrap();
    for shown in [
        format!("{on:?}"),
        format!("{on:#?}"),
        format!("{:?}", Bearer(TOKEN.into())),
    ] {
        assert!(!shown.contains(MARK), "{shown}");
    }
    assert_eq!(format!("{:?}", Bearer(TOKEN.into())), "<redacted>");
}

#[test]
fn the_files_are_read_again_on_each_call() {
    let pki = Pki::new("enroll-reread");
    let mut e = env(&pki);
    let ks = pki.path("rotating.json");
    e.insert(
        FILE_KEYSTORE,
        write(&ks, &good_keystore()).to_string_lossy().into_owned(),
    );
    let Enroll::On(on) = load(&e, "", false).unwrap() else {
        panic!("off");
    };
    let first = on.template.load().unwrap();
    assert!(first
        .render("h", "t", "k")
        .unwrap()
        .windows(KEY_B64.len())
        .any(|w| w == KEY_B64.as_bytes()));
    let other = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    write(
        &ks,
        &keystore(other, "2020-01-01T00:00:00Z", "2099-01-01T00:00:00Z"),
    );
    let second = on.template.load().unwrap();
    let file = String::from_utf8(second.render("h", "t", "k").unwrap()).unwrap();
    assert!(file.contains(other) && !file.contains(KEY_B64));
    assert_ne!(first.keys[0].sha256, second.keys[0].sha256);
}

#[test]
fn a_file_that_became_unreadable_or_invalid_names_its_variable() {
    let pki = Pki::new("enroll-gone");
    let mut e = env(&pki);
    let (ca, ks) = (pki.path("gone-ca.pem"), pki.path("gone-ks.json"));
    std::fs::copy(pki.path("ca.crt"), &ca).unwrap();
    write(&ks, &good_keystore());
    e.insert(FILE_CA, ca.to_string_lossy().into_owned());
    e.insert(FILE_KEYSTORE, ks.to_string_lossy().into_owned());
    let Enroll::On(on) = load(&e, "", false).unwrap() else {
        panic!("off");
    };
    std::fs::remove_file(&ks).unwrap();
    let msg = on.template.load().err().unwrap().to_string();
    assert!(msg.starts_with(FILE_KEYSTORE), "{msg}");
    write(&ks, &good_keystore());
    write(&ca, "garbage");
    assert!(on
        .template
        .load()
        .err()
        .unwrap()
        .to_string()
        .starts_with(FILE_CA));
    std::fs::remove_file(&ca).unwrap();
    assert!(on
        .template
        .load()
        .err()
        .unwrap()
        .to_string()
        .starts_with(FILE_CA));
}

#[test]
fn a_file_over_the_readers_limit_is_refused_with_the_variable_named() {
    let pki = Pki::new("enroll-big");
    let mut e = env(&pki);
    let one = std::fs::read_to_string(pki.path("ca.crt")).unwrap();
    let big = one.repeat(MAX_ENROLLMENT_FILE_BYTES as usize / one.len() + 1);
    e.insert(
        FILE_CA,
        write(&pki.path("big.pem"), &big)
            .to_string_lossy()
            .into_owned(),
    );
    let msg = load_err(&e);
    assert!(msg.contains(FILE_CA) && msg.contains("64 KiB"), "{msg}");
}

#[test]
fn the_ca_and_keystore_fingerprints_have_the_form_the_sender_prints() {
    let pki = Pki::new("enroll-fp");
    let e = env(&pki);
    let Enroll::On(on) = load(&e, "", false).unwrap() else {
        panic!("off");
    };
    let l = on.template.load().unwrap();
    assert!(
        l.cas[0].subject.contains("test-ca-enroll-fp"),
        "{}",
        l.cas[0].subject
    );
    for fp in [&l.cas[0].sha256, &l.keys[0].sha256] {
        let parts: Vec<_> = fp.split(':').collect();
        assert_eq!(parts.len(), 32);
        assert!(parts.iter().all(|p| p.len() == 2
            && p.bytes()
                .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))));
    }
    // The sender prints the same SHA-256 over the 32 raw key bytes.
    assert_eq!(l.keys[0].sha256, fingerprint(&b64_decode(KEY_B64).unwrap()));
}

#[test]
fn base64_is_standard_padded_and_exact() {
    assert_eq!(b64_decode(KEY_B64).unwrap().len(), 32);
    assert_eq!(b64_decode("TWFu").unwrap(), b"Man");
    assert_eq!(b64_decode("TWE=").unwrap(), b"Ma");
    assert_eq!(b64_decode("TQ==").unwrap(), b"M");
    for bad in [
        "TQ=", "TWE", "T===", "TQ=A", "TR==", "TW-u", "TWFu ", "TWF=u",
    ] {
        assert!(b64_decode(bad).is_none(), "{bad}");
    }
}

#[test]
fn host_ids_are_canonical_version_4_and_all_different() {
    let mut seen = HashSet::new();
    for _ in 0..5000 {
        let id = new_host_id().unwrap();
        assert!(is_canonical_v4(&id), "{id}");
        assert_eq!(id.len(), 36);
        assert!(seen.insert(id));
    }
}

#[test]
fn only_the_canonical_spelling_is_a_host_id() {
    let v4 = "3f2c6a1e-8b4d-4c2a-9e7f-1a2b3c4d5e6f";
    assert!(is_canonical_v4(v4));
    for bad in [
        "3F2C6A1E-8B4D-4C2A-9E7F-1A2B3C4D5E6F",
        "3f2c6a1e8b4d4c2a9e7f1a2b3c4d5e6f",
        "018f9c1a-0000-7000-8000-0000000000aa",
        "3f2c6a1e-8b4d-4c2a-7e7f-1a2b3c4d5e6f",
        "3f2c6a1e-8b4d-4c2a-9e7f-1a2b3c4d5e6",
        "3f2c6a1e-8b4d-4c2a-9e7f-1a2b3c4d5e6fa",
        "{3f2c6a1e-8b4d-4c2a-9e7f-1a2b3c4d5e6f}",
        "3f2c6a1e-8b4d-4c2a-9e7f-1a2b3c4d5e6g",
        "",
    ] {
        assert!(!is_canonical_v4(bad), "{bad}");
    }
}
