//! Read and validate the enrollment file.
//!
//! The file carries a token, so no message here quotes a value from it. A JSON error
//! prints its position, a field error prints the field's name.

use lodeline_core::host_meta::is_canonical_v4;
use lodeline_core::policy::pubkeys::{Keystore, KeystoreEntry};
use lodeline_fleet_api::enrollment::{
    EnrollmentFile, PolicyKey, PolicyKeystore, ENROLLMENT_FORMAT, MAX_ENROLLMENT_FILE_BYTES,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const TOP_FIELDS: [&str; 8] = [
    "enroll_url",
    "expires_at",
    "host_id",
    "lodeline_enrollment",
    "policy_keystore",
    "server_ca_pem",
    "server_url",
    "token",
];
const KEYSTORE_FIELDS: [&str; 1] = ["pubkeys"];
const KEY_FIELDS: [&str; 4] = ["ed25519_pubkey_b64", "id", "valid_from", "valid_until"];
const MAX_TOKEN_BYTES: usize = 256;

/// One CA certificate the file makes the host trust.
pub struct CaInfo {
    pub subject: String,
    pub sha256: String,
}

/// One policy key the file makes the agent trust.
pub struct KeyInfo {
    pub id: String,
    pub b64: String,
    pub sha256: String,
    pub valid_from: String,
    pub valid_until: String,
}

/// A validated enrollment file.
pub struct Parsed {
    pub file: EnrollmentFile,
    /// `server_url` and `enroll_url` as origins with no trailing slash.
    pub server_origin: String,
    pub enroll_origin: String,
    pub cas: Vec<CaInfo>,
    pub keys: Vec<KeyInfo>,
    pub keystore_json: Vec<u8>,
    pub warnings: Vec<String>,
}

/// Read, bound, parse and validate the file at `path`. The error is the message to
/// print after the path.
pub fn read(path: &Path, now: OffsetDateTime) -> Result<Parsed, String> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut opts, libc::O_NONBLOCK);
    let f = opts
        .open(path)
        .map_err(|e| format!("cannot open it: {e}"))?;
    let md = f.metadata().map_err(|e| format!("cannot stat it: {e}"))?;
    if !md.is_file() {
        return Err("it is not a regular file".into());
    }
    if md.len() > MAX_ENROLLMENT_FILE_BYTES {
        return Err(format!(
            "it is larger than {} KiB",
            MAX_ENROLLMENT_FILE_BYTES / 1024
        ));
    }
    let warnings: Vec<String> = mode_warning(&md)?.into_iter().collect();
    let mut bytes = Vec::new();
    f.take(MAX_ENROLLMENT_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read it: {e}"))?;
    if bytes.len() as u64 > MAX_ENROLLMENT_FILE_BYTES {
        return Err("it is larger than 64 KiB".into());
    }
    parse(&bytes, now, warnings)
}

/// Refuse a file that group or others can write, and warn when they can read it.
#[cfg(unix)]
fn mode_warning(md: &std::fs::Metadata) -> Result<Option<String>, String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = md.permissions().mode();
    if mode & 0o022 != 0 {
        return Err("it is writable by group or others; run `chmod 600` on it".into());
    }
    Ok((mode & 0o004 != 0).then(|| {
        "the enrollment file is readable by every account on this host and holds a single-use \
         token; run `chmod 600` on it"
            .to_string()
    }))
}

#[cfg(not(unix))]
fn mode_warning(_: &std::fs::Metadata) -> Result<Option<String>, String> {
    Ok(None)
}

fn parse(bytes: &[u8], now: OffsetDateTime, mut warnings: Vec<String>) -> Result<Parsed, String> {
    // A serde message can quote a value, so only the position is printed.
    let v: Value = serde_json::from_slice(bytes).map_err(|e| {
        format!(
            "it is not valid JSON (line {}, column {})",
            e.line(),
            e.column()
        )
    })?;
    let obj = v.as_object().ok_or("it must be a JSON object")?;
    let version = match obj.get("lodeline_enrollment") {
        None => return Err(missing("lodeline_enrollment")),
        Some(n) => n
            .as_u64()
            .ok_or("field `lodeline_enrollment` must be a number")?,
    };
    if version != u64::from(ENROLLMENT_FORMAT) {
        return Err(format!(
            "this file is format {version}; this lodeline-sender reads format \
             {ENROLLMENT_FORMAT}; upgrade lodeline-sender"
        ));
    }
    unknown(obj, &TOP_FIELDS, "", &mut warnings);

    let host_id = string(obj, "host_id")?;
    if !is_canonical_v4(&host_id) {
        return Err(format!(
            "field `host_id` must be a lowercase, hyphenated version 4 UUID, got {host_id:?}"
        ));
    }
    let token = string(obj, "token")?;
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES || token.chars().any(char::is_whitespace) {
        return Err("field `token` must be 1 to 256 characters with no whitespace".into());
    }
    let (enroll_origin, enroll_host) = origin(&string(obj, "enroll_url")?, "enroll_url")?;
    let (server_origin, server_host) = origin(&string(obj, "server_url")?, "server_url")?;
    if enroll_host != server_host {
        warnings.push(format!(
            "enroll_url ({enroll_host}) and server_url ({server_host}) name different hosts"
        ));
    }
    let expires = match obj.get("expires_at") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(
            OffsetDateTime::parse(s, &Rfc3339)
                .map_err(|_| "field `expires_at` must be an RFC 3339 time")?,
        ),
        Some(_) => return Err("field `expires_at` must be a string".into()),
    };
    if expires.is_some_and(|t| t < now) {
        warnings.push(
            "expires_at is in the past; enroll still tries, because this host's clock may be \
             wrong"
                .into(),
        );
    }
    let server_ca_pem = string(obj, "server_ca_pem")?;
    let cas = ca_info(&server_ca_pem)?;
    let (keys, ks, ks_file) = keystore(obj, now, &mut warnings)?;
    let mut keystore_json = serde_json::to_vec_pretty(&ks).map_err(|e| e.to_string())?;
    keystore_json.push(b'\n');

    Ok(Parsed {
        file: EnrollmentFile {
            enroll_url: enroll_origin.clone(),
            expires_at: obj
                .get("expires_at")
                .and_then(Value::as_str)
                .map(str::to_owned),
            host_id,
            lodeline_enrollment: ENROLLMENT_FORMAT,
            policy_keystore: ks_file,
            server_ca_pem,
            server_url: server_origin.clone(),
            token,
        },
        server_origin,
        enroll_origin,
        cas,
        keys,
        keystore_json,
        warnings,
    })
}

fn missing(field: &str) -> String {
    format!("missing field `{field}`")
}

fn string(obj: &Map<String, Value>, field: &str) -> Result<String, String> {
    match obj.get(field) {
        None => Err(missing(field)),
        Some(Value::String(s)) => Ok(s.clone()),
        Some(_) => Err(format!("field `{field}` must be a string")),
    }
}

/// Warn about each field this build does not know, by name and never by value: a
/// trust file that silently drops a field it does not understand is not safe.
fn unknown(obj: &Map<String, Value>, known: &[&str], within: &str, warnings: &mut Vec<String>) {
    for k in obj.keys().filter(|k| !known.contains(&k.as_str())) {
        let k: String = k.chars().take(64).collect();
        warnings.push(format!(
            "ignoring unknown field {within}{k:?}; this lodeline-sender may be older than the \
             tool that made the file"
        ));
    }
}

/// An `https` origin with nothing after the host and port, as `(origin, host)`.
fn origin(s: &str, field: &str) -> Result<(String, String), String> {
    let bad = |why: &str| {
        format!("field `{field}` must be an https origin such as https://lodeline.example.com:8443 ({why})")
    };
    let u = reqwest::Url::parse(s).map_err(|_| bad("not a URL"))?;
    if u.scheme() != "https" {
        return Err(bad("the scheme must be https"));
    }
    let host = u.host_str().ok_or_else(|| bad("no host"))?.to_owned();
    if !u.username().is_empty() || u.password().is_some() {
        return Err(bad("no user name or password"));
    }
    if u.query().is_some() || u.fragment().is_some() || u.path() != "/" {
        return Err(bad("no path, query or fragment"));
    }
    Ok((u.origin().ascii_serialization(), host))
}

/// The PEM labels must all be `CERTIFICATE`, which keeps a private key out of the file.
fn ca_info(pem: &str) -> Result<Vec<CaInfo>, String> {
    // A private key block anywhere in the field, however it is indented or prefixed.
    if pem.to_ascii_uppercase().contains("PRIVATE KEY") {
        return Err(
            "field `server_ca_pem` holds a private key; this file must never carry one".into(),
        );
    }
    for line in pem.lines().filter(|l| l.starts_with("-----BEGIN ")) {
        if line.trim_end() != "-----BEGIN CERTIFICATE-----" {
            return Err("field `server_ca_pem` may hold only CERTIFICATE blocks; this file must never carry a private key".into());
        }
    }
    let ders = rustls_pemfile::certs(&mut pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "field `server_ca_pem` is not valid PEM")?;
    if ders.is_empty() {
        return Err("field `server_ca_pem` holds no certificate".into());
    }
    ders.iter()
        .map(|der| {
            let (_, c) = x509_parser::parse_x509_certificate(der).map_err(|_| {
                "field `server_ca_pem` holds a block that is not an X.509 certificate"
            })?;
            Ok(CaInfo {
                subject: c.subject().to_string(),
                sha256: fingerprint(der),
            })
        })
        .collect()
}

/// SHA-256 as upper-case hex pairs separated by colons, the form `openssl x509 -fingerprint -sha256` prints.
pub fn fingerprint(bytes: &[u8]) -> String {
    let d = Sha256::digest(bytes);
    d.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

type KeystoreParts = (Vec<KeyInfo>, Keystore, PolicyKeystore);

fn keystore(
    obj: &Map<String, Value>,
    now: OffsetDateTime,
    warnings: &mut Vec<String>,
) -> Result<KeystoreParts, String> {
    let ks = obj
        .get("policy_keystore")
        .ok_or_else(|| missing("policy_keystore"))?
        .as_object()
        .ok_or("field `policy_keystore` must be an object")?;
    unknown(ks, &KEYSTORE_FIELDS, "in policy_keystore: ", warnings);
    let list = ks
        .get("pubkeys")
        .ok_or_else(|| missing("policy_keystore.pubkeys"))?
        .as_array()
        .ok_or("field `policy_keystore.pubkeys` must be a list")?;
    if list.is_empty() {
        return Err("field `policy_keystore.pubkeys` needs at least one key; without one the agent rejects every signed policy".into());
    }
    let (mut infos, mut entries, mut file_keys) = (Vec::new(), Vec::new(), Vec::new());
    for (i, e) in list.iter().enumerate() {
        let e = e
            .as_object()
            .ok_or_else(|| format!("policy_keystore.pubkeys[{i}] must be an object"))?;
        unknown(e, &KEY_FIELDS, "in a policy key: ", warnings);
        let field =
            |name: &str| string(e, name).map_err(|m| format!("policy_keystore.pubkeys[{i}]: {m}"));
        let (id, b64) = (field("id")?, field("ed25519_pubkey_b64")?);
        let (from_s, until_s) = (field("valid_from")?, field("valid_until")?);
        let raw = data_encoding::BASE64.decode(b64.as_bytes()).map_err(|_| {
            format!("policy_keystore.pubkeys[{i}]: ed25519_pubkey_b64 is not base64")
        })?;
        if raw.len() != 32 {
            return Err(format!(
                "policy_keystore.pubkeys[{i}]: ed25519_pubkey_b64 must decode to 32 bytes, got {}",
                raw.len()
            ));
        }
        let time = |name: &str, s: &str| {
            OffsetDateTime::parse(s, &Rfc3339).map_err(|_| {
                format!("policy_keystore.pubkeys[{i}]: {name} must be an RFC 3339 time")
            })
        };
        let (valid_from, valid_until) =
            (time("valid_from", &from_s)?, time("valid_until", &until_s)?);
        if valid_from >= valid_until {
            return Err(format!(
                "policy_keystore.pubkeys[{i}]: valid_from must be before valid_until"
            ));
        }
        infos.push(KeyInfo {
            id: id.clone(),
            b64: b64.clone(),
            sha256: fingerprint(&raw),
            valid_from: from_s.clone(),
            valid_until: until_s.clone(),
        });
        entries.push(KeystoreEntry {
            id: id.clone(),
            ed25519_pubkey_b64: b64.clone(),
            valid_from,
            valid_until,
        });
        file_keys.push(PolicyKey {
            ed25519_pubkey_b64: b64,
            id,
            valid_from: from_s,
            valid_until: until_s,
        });
    }
    if !entries
        .iter()
        .any(|k| k.valid_from <= now && now < k.valid_until)
    {
        warnings.push(
            "no policy key in the file is valid now; the agent rejects signed policy until one is"
                .into(),
        );
    }
    Ok((
        infos,
        Keystore { pubkeys: entries },
        PolicyKeystore { pubkeys: file_keys },
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    pub const HOST: &str = "3f2c6a1e-8b4d-4c2a-9e7f-1a2b3c4d5e6f";

    pub fn ca_pem() -> String {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut p = rcgen::CertificateParams::new(vec![]).unwrap();
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.distinguished_name
            .push(rcgen::DnType::CommonName, "test-root");
        p.self_signed(&key).unwrap().pem()
    }

    pub fn doc() -> Value {
        json!({
            "lodeline_enrollment": 1,
            "host_id": HOST,
            "token": "tok-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
            "enroll_url": "https://lodeline.example.com:8444",
            "server_url": "https://lodeline.example.com:8443",
            "server_ca_pem": ca_pem(),
            "policy_keystore": {"pubkeys": [{
                "id": "prod-key-1",
                "ed25519_pubkey_b64": data_encoding::BASE64.encode(&[7u8; 32]),
                "valid_from": "2020-01-01T00:00:00Z",
                "valid_until": "2099-01-01T00:00:00Z",
            }]}
        })
    }

    fn try_parse(v: &Value) -> Result<Parsed, String> {
        parse(
            &serde_json::to_vec(v).unwrap(),
            OffsetDateTime::now_utc(),
            vec![],
        )
    }

    fn err_of(v: &Value) -> String {
        try_parse(v).map(|_| ()).unwrap_err()
    }

    #[test]
    fn a_valid_file_parses_and_shows_what_it_trusts() {
        let p = try_parse(&doc()).unwrap();
        assert_eq!(p.file.host_id, HOST);
        assert_eq!(p.server_origin, "https://lodeline.example.com:8443");
        assert_eq!(p.cas.len(), 1);
        assert!(p.cas[0].subject.contains("test-root"));
        assert_eq!(p.cas[0].sha256.split(':').count(), 32);
        assert_eq!(p.keys[0].id, "prod-key-1");
        assert!(p.warnings.is_empty(), "{:?}", p.warnings);
        let ks: Keystore = serde_json::from_slice(&p.keystore_json).unwrap();
        assert_eq!(ks.pubkeys.len(), 1);
    }

    #[test]
    fn an_unknown_field_warns_by_name_and_never_by_value() {
        let mut d = doc();
        d["pin_server_cert"] = json!("hunter2-secret");
        d["policy_keystore"]["pubkeys"][0]["role"] = json!("hunter2-secret");
        let p = try_parse(&d).unwrap();
        assert_eq!(p.warnings.len(), 2, "{:?}", p.warnings);
        assert!(p.warnings.iter().any(|w| w.contains("pin_server_cert")));
        assert!(p.warnings.iter().all(|w| !w.contains("hunter2")));
    }

    #[test]
    fn another_format_version_is_refused() {
        for v in [json!(2), json!(0)] {
            let mut d = doc();
            d["lodeline_enrollment"] = v;
            assert!(err_of(&d).contains("upgrade lodeline-sender"));
        }
        let mut d = doc();
        d.as_object_mut().unwrap().remove("lodeline_enrollment");
        assert!(err_of(&d).contains("lodeline_enrollment"));
    }

    #[test]
    fn each_missing_field_names_itself() {
        for f in [
            "host_id",
            "token",
            "enroll_url",
            "server_url",
            "server_ca_pem",
            "policy_keystore",
        ] {
            let mut d = doc();
            d.as_object_mut().unwrap().remove(f);
            assert!(err_of(&d).contains(f), "{f}");
        }
    }

    #[test]
    fn a_wrong_typed_token_prints_no_value() {
        let mut d = doc();
        d["token"] = json!(12345678);
        let e = err_of(&d);
        assert!(e.contains("`token`") && !e.contains("12345678"), "{e}");
        let e = parse(
            b"{\"token\": \"tok-secret-value\" oops}",
            OffsetDateTime::now_utc(),
            vec![],
        )
        .map(|_| ())
        .unwrap_err();
        assert!(e.contains("line 1") && !e.contains("secret"), "{e}");
    }

    #[test]
    fn host_id_must_be_a_canonical_v4() {
        for bad in [
            "3F2C6A1E-8B4D-4C2A-9E7F-1A2B3C4D5E6F",
            "{3f2c6a1e-8b4d-4c2a-9e7f-1a2b3c4d5e6f}",
            "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
            "host-a",
        ] {
            let mut d = doc();
            d["host_id"] = json!(bad);
            assert!(err_of(&d).contains("host_id"), "{bad}");
        }
    }

    #[test]
    fn urls_must_be_bare_https_origins() {
        for bad in [
            "http://lodeline.example.com",
            "https://lodeline.example.com/v1",
            "https://lodeline.example.com/?a=1",
            "https://alice:pw@lodeline.example.com",
            "https://lodeline.example.com/#x",
            "lodeline.example.com",
        ] {
            let mut d = doc();
            d["server_url"] = json!(bad);
            let e = err_of(&d);
            assert!(e.contains("server_url") && !e.contains("pw"), "{bad}: {e}");
        }
        let mut d = doc();
        d["enroll_url"] = json!("https://other.example.com:8444/");
        let p = try_parse(&d).unwrap();
        assert_eq!(p.enroll_origin, "https://other.example.com:8444");
        assert!(p.warnings.iter().any(|w| w.contains("different hosts")));
    }

    #[test]
    fn the_ca_must_be_certificates_only() {
        for bad in [
            "",
            "not pem",
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n",
        ] {
            let mut d = doc();
            d["server_ca_pem"] = json!(bad);
            assert!(err_of(&d).contains("server_ca_pem"), "{bad:?}");
        }
        let mut d = doc();
        let mixed = format!(
            "{}-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n",
            ca_pem()
        );
        d["server_ca_pem"] = json!(mixed);
        assert!(err_of(&d).contains("private key"));
    }

    #[test]
    fn a_private_key_is_refused_wherever_it_sits_in_the_field() {
        for lead in ["  ", "\t", "x ", "# "] {
            let mut d = doc();
            d["server_ca_pem"] = json!(format!(
                "{}{lead}-----BEGIN PRIVATE KEY-----\nAAAA\n{lead}-----END PRIVATE KEY-----\n",
                ca_pem()
            ));
            assert!(err_of(&d).contains("private key"), "{lead:?}");
        }
    }

    #[test]
    fn policy_keys_are_checked() {
        let key = |m: fn(&mut Value)| {
            let mut d = doc();
            m(&mut d["policy_keystore"]["pubkeys"][0]);
            err_of(&d)
        };
        assert!(
            key(|k| k["ed25519_pubkey_b64"] = json!(data_encoding::BASE64.encode(&[1u8; 31])))
                .contains("32 bytes")
        );
        assert!(key(|k| k["ed25519_pubkey_b64"] = json!("!!!")).contains("base64"));
        assert!(key(|k| k["valid_until"] = json!("2019-01-01T00:00:00Z")).contains("before"));
        assert!(key(|k| k["valid_from"] = json!("yesterday")).contains("RFC 3339"));
        let mut d = doc();
        d["policy_keystore"]["pubkeys"] = json!([]);
        assert!(err_of(&d).contains("at least one"));
        let mut d = doc();
        d["policy_keystore"]["pubkeys"][0]["valid_until"] = json!("2021-01-01T00:00:00Z");
        let p = try_parse(&d).unwrap();
        assert!(p.warnings.iter().any(|w| w.contains("no policy key")));
    }

    #[test]
    fn a_past_expiry_warns() {
        let mut d = doc();
        d["expires_at"] = json!("2020-01-01T00:00:00Z");
        assert!(try_parse(&d)
            .unwrap()
            .warnings
            .iter()
            .any(|w| w.contains("expires_at")));
        d["expires_at"] = json!("soon");
        assert!(err_of(&d).contains("expires_at"));
    }

    #[cfg(unix)]
    #[test]
    fn reading_checks_size_kind_and_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("host.json");
        let write = |body: &[u8], mode: u32| {
            std::fs::write(&p, body).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        let now = OffsetDateTime::now_utc();
        let body = serde_json::to_vec(&doc()).unwrap();
        write(&body, 0o600);
        assert!(read(&p, now).unwrap().warnings.is_empty());
        write(&body, 0o644);
        assert!(read(&p, now)
            .unwrap()
            .warnings
            .iter()
            .any(|w| w.contains("readable by every")));
        write(&body, 0o666);
        assert!(read(&p, now).map(|_| ()).unwrap_err().contains("writable"));
        write(&vec![b' '; MAX_ENROLLMENT_FILE_BYTES as usize + 1], 0o600);
        assert!(read(&p, now).map(|_| ()).unwrap_err().contains("larger"));
        assert!(read(dir.path(), now)
            .map(|_| ())
            .unwrap_err()
            .contains("regular"));
    }
}
