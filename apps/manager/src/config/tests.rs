//! A 1:1 port of Go's `internal/config/config_test.go`, one test per Go test function and the
//! same subtests, plus the Go `TestOIDCConfig` cases and the redacted `Debug`.

use super::*;
use std::collections::HashMap;
use std::path::Path;

const VALID_BCRYPT_HASH: &str = "$2a$04$abcdefghijklmnopqrstuuFooBarBazQuuxCorgePloghTes12tHashXY";
const VALID_JWT_SECRET: &str = "abcdefghijklmnopqrstuvwxyzABCDEF";

type Env = HashMap<&'static str, String>;

fn full_valid_env() -> Env {
    [
        ("LISTEN_ADDR", ":9999"),
        ("LODELINE_SERVER_BASE_URL", "http://localhost:9090"),
        ("LODELINE_SERVER_READ_TOKEN", "secret-token"),
        ("MOCK_FLEET", ""),
        ("TRIAGE_DB_PATH", "/tmp/test-triage.sqlite"),
        ("ADMIN_USERNAME", "admin"),
        ("ADMIN_PASSWORD_BCRYPT", VALID_BCRYPT_HASH),
        ("JWT_SECRET", VALID_JWT_SECRET),
        ("JWT_TTL_HOURS", "24"),
        ("FLEET_POLL_INTERVAL_SECONDS", "10"),
        ("LODELINE_SERVER_CA_PATH", ""),
        ("LODELINE_SERVER_CLIENT_CERT_PATH", ""),
        ("LODELINE_SERVER_CLIENT_KEY_PATH", ""),
    ]
    .into_iter()
    .map(|(k, v)| (k, v.to_owned()))
    .collect()
}

fn load(env: &Env) -> Result<Config, ConfigError> {
    Config::load(|k| env.get(k).cloned())
}

fn load_err(env: &Env) -> ConfigError {
    match load(env) {
        Ok(_) => panic!("load succeeded"),
        Err(e) => e,
    }
}

fn set(env: &mut Env, key: &'static str, value: impl Into<String>) {
    env.insert(key, value.into());
}

/// A directory under the system temp dir, removed on drop.
struct TempDir(std::path::PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl std::ops::Deref for TempDir {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

fn temp_dir(name: &str) -> TempDir {
    let dir = std::env::temp_dir().join(format!("lodeline-manager-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    TempDir(dir)
}

fn path_str(p: &Path) -> String {
    p.to_str().unwrap().to_owned()
}

#[test]
fn load_valid_full_config() {
    let c = load(&full_valid_env()).unwrap();
    assert_eq!(c.listen_addr, ":9999");
    assert_eq!(c.server_base_url, "http://localhost:9090");
    assert_eq!(c.server_read_token, "secret-token");
    assert!(!c.mock_fleet);
    assert_eq!(c.triage_db_path, "/tmp/test-triage.sqlite");
    assert_eq!(c.admin_username, "admin");
    assert_eq!(c.admin_password_bcrypt, VALID_BCRYPT_HASH);
    assert_eq!(c.jwt_secret, VALID_JWT_SECRET);
    assert_eq!(c.jwt_ttl, Duration::from_secs(24 * 3600));
    assert_eq!(c.fleet_poll_interval, Duration::from_secs(10));
}

#[test]
fn load_defaults_applied_when_optional_unset() {
    let mut env = full_valid_env();
    for key in [
        "LISTEN_ADDR",
        "TRIAGE_DB_PATH",
        "JWT_TTL_HOURS",
        "FLEET_POLL_INTERVAL_SECONDS",
    ] {
        set(&mut env, key, "");
    }
    let c = load(&env).unwrap();
    assert_eq!(c.listen_addr, ":8080");
    assert_eq!(c.triage_db_path, "./var/triage.sqlite");
    assert_eq!(c.jwt_ttl, Duration::from_secs(12 * 3600));
    assert_eq!(c.fleet_poll_interval, Duration::from_secs(5));
}

#[test]
fn load_mock_fleet_relaxes_lodeline_url_and_token() {
    let mut env = full_valid_env();
    set(&mut env, "MOCK_FLEET", "1");
    set(&mut env, "LODELINE_SERVER_BASE_URL", "");
    set(&mut env, "LODELINE_SERVER_READ_TOKEN", "");
    let c = load(&env).unwrap();
    assert!(c.mock_fleet);
    assert!(c.server_base_url.is_empty());
    assert!(c.server_read_token.is_empty());
}

#[test]
fn load_missing_required_non_mock_mode() {
    for key in [
        "LODELINE_SERVER_BASE_URL",
        "LODELINE_SERVER_READ_TOKEN",
        "ADMIN_USERNAME",
        "ADMIN_PASSWORD_BCRYPT",
        "JWT_SECRET",
    ] {
        let mut env = full_valid_env();
        set(&mut env, key, "");
        let err = load_err(&env);
        assert!(
            matches!(err, ConfigError::MissingRequired(_)),
            "{key}: expected MissingRequired, got {err}"
        );
        assert!(err.to_string().contains(key), "{key}: {err}");
    }
}

#[test]
fn load_missing_required_mock_mode_still_needs_auth() {
    let mut env = full_valid_env();
    set(&mut env, "MOCK_FLEET", "1");
    set(&mut env, "LODELINE_SERVER_BASE_URL", "");
    set(&mut env, "LODELINE_SERVER_READ_TOKEN", "");
    set(&mut env, "ADMIN_USERNAME", "");
    let err = load_err(&env);
    assert!(matches!(err, ConfigError::MissingRequired(_)));
    assert!(err.to_string().contains("ADMIN_USERNAME"));
}

#[test]
fn load_short_jwt_secret() {
    let mut env = full_valid_env();
    set(&mut env, "JWT_SECRET", "tooshort");
    let err = load_err(&env);
    assert!(err
        .to_string()
        .contains("JWT_SECRET must be at least 32 bytes"));
    assert!(!matches!(err, ConfigError::MissingRequired(_)));
}

#[test]
fn load_refuses_example_values() {
    for (key, value) in [
        ("LODELINE_SERVER_READ_TOKEN", EXAMPLE_READ_TOKEN),
        ("ADMIN_PASSWORD_BCRYPT", EXAMPLE_ADMIN_HASH),
        ("JWT_SECRET", EXAMPLE_JWT_SECRET),
    ] {
        let mut env = full_valid_env();
        set(&mut env, key, format!(" {value} "));
        let err = load_err(&env).to_string();
        assert!(
            err.starts_with(&format!("config: {key} is the public example value")),
            "{err}"
        );
    }
    assert!(crate::auth::password_matches(
        "change-me-on-first-boot",
        EXAMPLE_ADMIN_HASH
    ));
}

#[test]
fn load_mock_fleet_ignores_example_read_token() {
    let mut env = full_valid_env();
    set(&mut env, "MOCK_FLEET", "1");
    set(&mut env, "LODELINE_SERVER_READ_TOKEN", EXAMPLE_READ_TOKEN);
    assert!(load(&env).is_ok());
}

#[test]
fn load_invalid_bcrypt_hash() {
    for hash in [
        "plain",
        "hunter2hunter2hunter2hunter2hunter2hunter2hunter2hunter2hunter2",
        "$5$rounds=1000$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
        "$2a$04$short",
    ] {
        let mut env = full_valid_env();
        set(&mut env, "ADMIN_PASSWORD_BCRYPT", hash);
        assert!(
            load_err(&env).to_string().contains("ADMIN_PASSWORD_BCRYPT"),
            "{hash}"
        );
    }
}

#[test]
fn load_accepts_all_bcrypt_prefixes() {
    for prefix in ["$2a$", "$2b$", "$2y$"] {
        let mut env = full_valid_env();
        set(
            &mut env,
            "ADMIN_PASSWORD_BCRYPT",
            format!("{prefix}{}", &VALID_BCRYPT_HASH[4..]),
        );
        let c = load(&env).unwrap();
        assert!(c.admin_password_bcrypt.starts_with(prefix));
    }
}

#[test]
fn load_non_integer_jwt_ttl() {
    let mut env = full_valid_env();
    set(&mut env, "JWT_TTL_HOURS", "not-a-number");
    assert!(load_err(&env).to_string().contains("JWT_TTL_HOURS"));
}

#[test]
fn load_zero_jwt_ttl() {
    let mut env = full_valid_env();
    set(&mut env, "JWT_TTL_HOURS", "0");
    assert!(load_err(&env).to_string().contains("JWT_TTL_HOURS"));
}

#[test]
fn load_negative_fleet_poll_interval() {
    let mut env = full_valid_env();
    set(&mut env, "FLEET_POLL_INTERVAL_SECONDS", "-5");
    assert!(load_err(&env)
        .to_string()
        .contains("FLEET_POLL_INTERVAL_SECONDS"));
}

#[test]
fn load_multiple_missing_reported_together() {
    let mut env = full_valid_env();
    set(&mut env, "LODELINE_SERVER_BASE_URL", "");
    set(&mut env, "ADMIN_USERNAME", "");
    set(&mut env, "JWT_SECRET", "");
    let msg = load_err(&env).to_string();
    for key in ["LODELINE_SERVER_BASE_URL", "ADMIN_USERNAME", "JWT_SECRET"] {
        assert!(msg.contains(key), "{key} in {msg}");
    }
}

#[test]
fn load_whitespace_trimmed_from_strings() {
    let mut env = full_valid_env();
    set(
        &mut env,
        "LODELINE_SERVER_BASE_URL",
        "  http://localhost:9090  ",
    );
    set(&mut env, "ADMIN_USERNAME", "  admin\t");
    let c = load(&env).unwrap();
    assert_eq!(c.server_base_url, "http://localhost:9090");
    assert_eq!(c.admin_username, "admin");
}

#[test]
fn oidc_environment() {
    let mut env: Env = [
        ("OIDC_ISSUER_URL", "https://identity.example/realm"),
        ("OIDC_CLIENT_ID", "console"),
        ("OIDC_CLIENT_SECRET", "secret"),
        (
            "OIDC_REDIRECT_URL",
            "https://console.example/api/v1/auth/oidc/callback",
        ),
        ("OIDC_ALLOWED_SUBJECTS", r#"["employee-1"]"#),
        ("MOCK_FLEET", "1"),
        ("ADMIN_USERNAME", "admin"),
        ("ADMIN_PASSWORD_BCRYPT", VALID_BCRYPT_HASH),
        ("JWT_SECRET", VALID_JWT_SECRET),
    ]
    .into_iter()
    .map(|(k, v)| (k, v.to_owned()))
    .collect();
    let c = load(&env).unwrap();
    assert_eq!(c.oidc.unwrap().allowed_subjects, ["employee-1"]);
    set(&mut env, "OIDC_ALLOWED_SUBJECTS", "employee-1");
    assert!(load_err(&env).to_string().contains("JSON array"));
    set(&mut env, "OIDC_ALLOWED_SUBJECTS", "[]");
    assert!(load_err(&env).to_string().contains("OIDC_ALLOWED_SUBJECTS"));
}

#[test]
fn load_server_tls_unset_leaves_default_transport() {
    assert!(load(&full_valid_env()).unwrap().server_tls.is_none());
}

#[test]
fn load_server_tls_errors() {
    let dir = temp_dir("tls-errors");
    let not_pem = path_str(&dir.join("not-pem"));
    std::fs::write(&not_pem, "hello").unwrap();
    let absent = path_str(&dir.join("absent.crt"));
    type Vars<'a> = &'a [(&'static str, &'a str)];
    let cases: [(&str, Vars, &str); 5] = [
        (
            "cert without key",
            &[("LODELINE_SERVER_CLIENT_CERT_PATH", &not_pem)],
            "must be set together",
        ),
        (
            "key without cert",
            &[("LODELINE_SERVER_CLIENT_KEY_PATH", &not_pem)],
            "must be set together",
        ),
        (
            "missing CA file",
            &[("LODELINE_SERVER_CA_PATH", &absent)],
            "LODELINE_SERVER_CA_PATH",
        ),
        (
            "CA file without a certificate",
            &[("LODELINE_SERVER_CA_PATH", &not_pem)],
            "no PEM certificate",
        ),
        (
            "unreadable key pair",
            &[
                ("LODELINE_SERVER_CLIENT_CERT_PATH", &not_pem),
                ("LODELINE_SERVER_CLIENT_KEY_PATH", &not_pem),
            ],
            "LODELINE_SERVER_CLIENT_CERT_PATH",
        ),
    ];
    for (name, vars, want) in cases {
        let mut env = full_valid_env();
        set(
            &mut env,
            "LODELINE_SERVER_BASE_URL",
            "https://lodeline.example:8443",
        );
        for (k, v) in vars {
            set(&mut env, k, *v);
        }
        let err = load_err(&env).to_string();
        assert!(err.contains(want), "{name}: {err}");
    }
}

#[test]
fn load_server_tls_needs_https() {
    let dir = temp_dir("tls-https");
    let ca = path_str(&dir.join("ca.crt"));
    std::fs::write(&ca, TEST_CA_PEM).unwrap();
    let mut env = full_valid_env();
    set(&mut env, "LODELINE_SERVER_CA_PATH", ca);
    assert!(load_err(&env).to_string().contains("https://"));

    set(
        &mut env,
        "LODELINE_SERVER_BASE_URL",
        "HTTPS://lodeline.example:8443",
    );
    let tls = load(&env).unwrap().server_tls.unwrap();
    assert!(!tls.roots.is_empty());

    // Go's url.Parse refuses these, so they are not https URLs either.
    for bad in [
        "https://a%41.example",
        "https://[192.0.2.1]:8443",
        "https://us er@lodeline.example",
        "https://us%zzer@lodeline.example",
    ] {
        set(&mut env, "LODELINE_SERVER_BASE_URL", bad);
        assert!(load_err(&env).to_string().contains("https://"), "{bad}");
    }
}

/// Go's `AppendCertsFromPEM` skips a block it cannot read and keeps the rest; it fails only
/// when no certificate parses. The error names the variable and the path, never the contents.
#[test]
fn load_server_tls_skips_unreadable_ca_entries() {
    let dir = temp_dir("tls-bundle");
    let bad_der = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    let bad_base64 = "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n";
    let crl = "-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n";
    let mut env = full_valid_env();
    set(
        &mut env,
        "LODELINE_SERVER_BASE_URL",
        "https://lodeline.example:8443",
    );

    let ca = path_str(&dir.join("mixed.crt"));
    std::fs::write(&ca, format!("{bad_der}{TEST_CA_PEM}{bad_base64}{crl}")).unwrap();
    set(&mut env, "LODELINE_SERVER_CA_PATH", &ca);
    let cfg = load(&env).unwrap();
    assert_eq!(cfg.server_tls.as_ref().unwrap().roots.len(), 1);
    assert!(crate::fleet::from_config(&cfg).is_ok());

    let ca = path_str(&dir.join("bad.crt"));
    std::fs::write(&ca, format!("{bad_der}{bad_base64}{crl}")).unwrap();
    set(&mut env, "LODELINE_SERVER_CA_PATH", &ca);
    let err = load_err(&env).to_string();
    assert_eq!(
        err,
        format!("config: LODELINE_SERVER_CA_PATH: no PEM certificate in {ca}")
    );
}

#[test]
fn load_mock_fleet_ignores_server_tls() {
    let dir = temp_dir("tls-mock");
    let mut env = full_valid_env();
    set(&mut env, "MOCK_FLEET", "1");
    set(&mut env, "LODELINE_SERVER_BASE_URL", "");
    set(
        &mut env,
        "LODELINE_SERVER_CA_PATH",
        path_str(&dir.join("absent.crt")),
    );
    assert!(load(&env).unwrap().server_tls.is_none());
}

// A throwaway self-signed certificate; only its PEM shape matters.
const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBVzCB/qADAgECAhRBNVQze3ZuzYO01kKjJ9HeL7h4wjAKBggqhkjOPQQDAjAS
MRAwDgYDVQQDDAd0ZXN0LWNhMB4XDTI2MTAzMDA2NDQzNFoXDTM2MTAyNzA2NDQz
NFowEjEQMA4GA1UEAwwHdGVzdC1jYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA
BLutJyHS7hk0f9fFfQHcHwMx28zLWa7+2a+p0oY8ZJiGzobaUIv1B3RxLvtO5QX9
uR1fDYqpcXbLXRkzeklQPE2jMjAwMB0GA1UdDgQWBBT0z9lg5s2qGEurn1se56Od
f7hQxDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQDXTkFv4+Q2
QxY1BNHTcGHgwp5imTTHlf75AOKJjQkN0QIgJel6p0vI44UHLKFaJhBtMZ7D39mS
UU27/7V3jmgz164=
-----END CERTIFICATE-----
";

#[test]
fn legacy_env_names_reports_names_not_values() {
    let got =
        legacy_env_names(["SIGIL_INSECURE_COOKIE", "LODELINE_X", "NOT_SIGIL_Y"].map(String::from));
    assert_eq!(got, ["SIGIL_INSECURE_COOKIE"]);
}

// Go's TestOIDCConfig in internal/auth: the Rust port validates OIDC inside config.
#[test]
fn oidc_config_validation() {
    let valid = || OidcConfig {
        issuer: "https://id.example/realm".into(),
        client_id: "console".into(),
        client_secret: "secret".into(),
        redirect_url: "https://console.example/api/v1/auth/oidc/callback".into(),
        allowed_subjects: vec!["subject".into()],
    };
    assert!(valid().validate().unwrap().is_some());
    let empty = OidcConfig {
        issuer: String::new(),
        client_id: String::new(),
        client_secret: String::new(),
        redirect_url: String::new(),
        allowed_subjects: Vec::new(),
    };
    assert!(empty.validate().unwrap().is_none());
    let changes: [fn(&mut OidcConfig); 6] = [
        |c| c.issuer = "http://id.example".into(),
        |c| c.allowed_subjects.clear(),
        |c| c.allowed_subjects = vec![String::new()],
        |c| c.redirect_url = "https://console.example/other".into(),
        |c| c.issuer = "https://user:pass@id.example".into(),
        |c| c.client_secret.clear(),
    ];
    for (i, change) in changes.iter().enumerate() {
        let mut c = valid();
        change(&mut c);
        assert!(c.validate().is_err(), "change {i}");
    }
}

// Where Go's url.Parse differs from a WHATWG parser, validation follows Go.
#[test]
fn oidc_urls_follow_go_parsing() {
    let with_redirect = |redirect: &str| OidcConfig {
        issuer: "https://id.example".into(),
        client_id: "console".into(),
        client_secret: "secret".into(),
        redirect_url: redirect.into(),
        allowed_subjects: vec!["subject".into()],
    };
    for ok in [
        "https://console.example/api/v1/auth/oidc/%63allback",
        "HTTPS://console.example:8443/api/v1/auth/oidc/callback",
        "https://console.example/api/v1/auth/oidc/callback?",
        "https://console.example/api/v1/auth/oidc/callback#",
        "https://[::1]:8443/api/v1/auth/oidc/callback",
        "https://[::ffff:192.0.2.1]/api/v1/auth/oidc/callback",
        "https://[fe80::1%25en0]/api/v1/auth/oidc/callback",
        "https://b%C3%BCcher.example/api/v1/auth/oidc/callback",
        "https://console.example:80:443/api/v1/auth/oidc/callback",
    ] {
        assert!(with_redirect(ok).validate().is_ok(), "{ok}");
    }
    for bad in [
        "https:///api/v1/auth/oidc/callback",
        "https://@console.example/api/v1/auth/oidc/callback",
        "https://console.example/api/v1/x/../auth/oidc/callback",
        "https://console.example/api/v1/auth/oidc/callback?a=1",
        "https://console.example/api/v1/auth/oidc/callback#top",
        "https://console.example:port/api/v1/auth/oidc/callback",
        "https://console.example/api/v1/auth/oidc/%zzallback",
        "https://console example/api/v1/auth/oidc/callback",
        // Go 1.25+ host rules: escapes of ASCII bytes, and brackets around anything but IPv6.
        "https://console%2Eexample/api/v1/auth/oidc/callback",
        "https://ex%20ample/api/v1/auth/oidc/callback",
        "https://[192.0.2.1]/api/v1/auth/oidc/callback",
        "https://[console.example]/api/v1/auth/oidc/callback",
        "https://x[::1]/api/v1/auth/oidc/callback",
        "https://[fe80::1%25]/api/v1/auth/oidc/callback",
        "https://[fe80::1%25en%2F0]/api/v1/auth/oidc/callback",
        "https://[fe80::1%en0]/api/v1/auth/oidc/callback",
    ] {
        assert!(with_redirect(bad).validate().is_err(), "{bad}");
    }
}

#[test]
fn debug_redacts_secrets() {
    let mut env = full_valid_env();
    set(
        &mut env,
        "LODELINE_SERVER_BASE_URL",
        "https://user:pw@lodeline.example:8443/x?k=v",
    );
    set(&mut env, "OIDC_ISSUER_URL", "https://id.example");
    set(&mut env, "OIDC_CLIENT_ID", "console");
    set(&mut env, "OIDC_CLIENT_SECRET", "oidc-client-secret-value");
    set(
        &mut env,
        "OIDC_REDIRECT_URL",
        "https://console.example/api/v1/auth/oidc/callback",
    );
    set(&mut env, "OIDC_ALLOWED_SUBJECTS", r#"["subject"]"#);
    let shown = format!("{:?}", load(&env).unwrap());
    for secret in [
        "secret-token",
        VALID_JWT_SECRET,
        VALID_BCRYPT_HASH,
        "oidc-client-secret-value",
        "pw",
        "k=v",
    ] {
        assert!(!shown.contains(secret), "{secret} in {shown}");
    }
    assert!(shown.contains("https://lodeline.example:8443"), "{shown}");
    assert!(shown.contains("admin"), "{shown}");
}

#[test]
fn trusted_proxies_are_addresses_and_networks() {
    let mut env = full_valid_env();
    assert!(load(&env).unwrap().trusted_proxies.is_empty());
    set(
        &mut env,
        "TRUSTED_PROXIES",
        " 192.0.2.1, 198.51.100.0/24 ,,2001:db8::/32",
    );
    let nets: Vec<String> = load(&env)
        .unwrap()
        .trusted_proxies
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(nets, ["192.0.2.1/32", "198.51.100.0/24", "2001:db8::/32"]);
    for bad in ["proxy.example", "198.51.100.0/33", "192.0.2.1:80"] {
        set(&mut env, "TRUSTED_PROXIES", bad);
        assert_eq!(
            load_err(&env),
            ConfigError::Invalid(format!(
                "config: TRUSTED_PROXIES: {bad:?} is not an IP address or CIDR network"
            ))
        );
    }
}
