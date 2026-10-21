//! The per-proxy registry key K and the derivations built on it (README "D-05
//! metadata registry (N9)", `contracts/registry.md` R3).
//!
//! * `K` is 256 random bits, kept owner-only (0600) in the state directory,
//!   never transmitted, logged or backed up. [`Key`] has no `Clone`, prints
//!   nothing and overwrites its bytes when dropped.
//! * `key_id = "kid-" + hex24(SHA-256("sigil-key-id-v1\0" || K))`. A fresh random
//!   K therefore always has a fresh `key_id` and it is never reused.
//! * `fingerprint = HMAC-SHA-256(K, "sigil-tooldef-fp-v1\0" || JCS(tool))`.
//! * `metadata_ref` = first 16 bytes of
//!   `HMAC-SHA-256(K, "sigil-metadata-ref-v1\0" || JCS(scope key + canon + key_id + fingerprint))`
//!   as an RFC 9562 version-8 UUID.
//!
//! `check_schema.py` carries the reference model of these derivations with a
//! fixture key; the tests below reproduce its vectors. HMAC is implemented here
//! on top of `sha2` (RFC 2104) instead of adding a crate; it is checked against
//! the RFC 4231 vectors.

use std::fmt;
use std::path::Path;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::jcs::{self, JcsError};
use crate::registry_store::RegistryError;

/// The only canon version of the contract (`registry-entry.schema.json`).
pub const CANON_V1: &str = "sigil-tooldef-fp-v1";
/// File name of the key inside the state directory.
pub const KEY_FILE: &str = "registry_key.json";

const FP_DOMAIN: &[u8] = b"sigil-tooldef-fp-v1\0";
const REF_DOMAIN: &[u8] = b"sigil-metadata-ref-v1\0";
const KID_DOMAIN: &[u8] = b"sigil-key-id-v1\0";

/// The scope key of a registry entry: `(proxy_id, upstream_id,
/// credential_scope_id, protocol_version, observation_source)`. `route_revision`
/// is deliberately absent.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScopeKey {
    pub proxy_id: String,
    pub upstream_id: String,
    pub credential_scope_id: String,
    pub protocol_version: String,
    pub observation_source: String,
}

impl ScopeKey {
    /// The scope key of the contract's only protocol revision and source.
    pub fn live(proxy_id: &str, upstream_id: &str, credential_scope_id: &str) -> ScopeKey {
        ScopeKey {
            proxy_id: proxy_id.to_string(),
            upstream_id: upstream_id.to_string(),
            credential_scope_id: credential_scope_id.to_string(),
            protocol_version: "2025-11-25".to_string(),
            observation_source: "proxy_live".to_string(),
        }
    }

    fn material(&self, canon: &str, key_id: &str, fingerprint: &str) -> Value {
        json!({
            "proxy_id": self.proxy_id,
            "upstream_id": self.upstream_id,
            "credential_scope_id": self.credential_scope_id,
            "protocol_version": self.protocol_version,
            "observation_source": self.observation_source,
            "canon": canon,
            "key_id": key_id,
            "fingerprint": fingerprint,
        })
    }
}

/// What a tool definition is minted to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Derived {
    pub key_id: String,
    pub fingerprint: String,
    pub metadata_ref: String,
}

/// K. 32 bytes.
pub struct Key {
    bytes: [u8; 32],
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        // Best effort: volatile writes the optimiser may not remove.
        for b in self.bytes.iter_mut() {
            // SAFETY: `b` is a valid, aligned, exclusive reference.
            unsafe { std::ptr::write_volatile(b, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl Key {
    /// A fresh random K.
    pub fn generate() -> Result<Key, RegistryError> {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|_| RegistryError::Random)?;
        Ok(Key { bytes })
    }

    /// Build from raw bytes (tests and fixtures only use fixed keys).
    pub fn from_bytes(bytes: [u8; 32]) -> Key {
        Key { bytes }
    }

    pub fn key_id(&self) -> String {
        let mut h = Sha256::new();
        h.update(KID_DOMAIN);
        h.update(self.bytes);
        format!("kid-{}", &hex(&h.finalize())[..24])
    }

    /// `HMAC-SHA-256(K, canon-domain || JCS(definition))`, lower-case hex.
    pub fn fingerprint(&self, definition: &Value) -> Result<String, JcsError> {
        let mut msg = FP_DOMAIN.to_vec();
        msg.extend_from_slice(&jcs::canonicalize(definition)?);
        Ok(hex(&hmac_sha256(&self.bytes, &msg)))
    }

    /// The reference of a definition under this key in `scope`.
    pub fn derive(&self, scope: &ScopeKey, definition: &Value) -> Result<Derived, JcsError> {
        let key_id = self.key_id();
        let fingerprint = self.fingerprint(definition)?;
        let metadata_ref = self.metadata_ref(scope, &key_id, &fingerprint)?;
        Ok(Derived {
            key_id,
            fingerprint,
            metadata_ref,
        })
    }

    fn metadata_ref(
        &self,
        scope: &ScopeKey,
        key_id: &str,
        fingerprint: &str,
    ) -> Result<String, JcsError> {
        let mut msg = REF_DOMAIN.to_vec();
        msg.extend_from_slice(&jcs::canonicalize(&scope.material(
            CANON_V1,
            key_id,
            fingerprint,
        ))?);
        let mac = hmac_sha256(&self.bytes, &msg);
        let mut b = [0u8; 16];
        b.copy_from_slice(&mac[..16]);
        b[6] = (b[6] & 0x0f) | 0x80; // version 8
        b[8] = (b[8] & 0x3f) | 0x80; // RFC 9562 variant
        Ok(uuid::Uuid::from_bytes(b).hyphenated().to_string())
    }

    // ------------------------------------------------------------ persistence

    /// Read the key file of `dir`: `Ok(None)` when it does not exist. The file
    /// must be a regular file owned by this user with mode 0600 and its stored
    /// `key_id` must match the key (a corrupt or edited file is an error, not a
    /// silently new key).
    pub(crate) fn load(dir: &Path) -> Result<Option<Key>, RegistryError> {
        let path = dir.join(KEY_FILE);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(RegistryError::Io(e.kind())),
        }
        let raw =
            crate::fsutil::read_private_file(&path).map_err(|e| RegistryError::Io(e.kind()))?;
        let v: Value = serde_json::from_slice(&raw).map_err(|_| RegistryError::KeyCorrupt)?;
        let (Some(kid), Some(hexkey), Some(1)) = (
            v.get("key_id").and_then(Value::as_str),
            v.get("key").and_then(Value::as_str),
            v.get("schema_version").and_then(Value::as_u64),
        ) else {
            return Err(RegistryError::KeyCorrupt);
        };
        let bytes = unhex32(hexkey).ok_or(RegistryError::KeyCorrupt)?;
        let key = Key { bytes };
        if key.key_id() != kid {
            return Err(RegistryError::KeyCorrupt);
        }
        Ok(Some(key))
    }

    /// Atomically replace the key file (tmp 0600 + fsync + rename + directory
    /// fsync). Replacing is what destroys a previous K.
    pub(crate) fn store(&self, dir: &Path) -> Result<(), RegistryError> {
        let body = serde_json::to_vec(&json!({
            "schema_version": 1,
            "key_id": self.key_id(),
            "key": hex(&self.bytes),
        }))
        .map_err(|_| RegistryError::KeyCorrupt)?;
        write_private_atomic(dir, KEY_FILE, &body)
    }
}

/// tmp file (0600, `O_NOFOLLOW`) + fsync + rename + directory fsync.
#[cfg(unix)]
pub(crate) fn write_private_atomic(
    dir: &Path,
    name: &str,
    bytes: &[u8],
) -> Result<(), RegistryError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let io = |e: std::io::Error| RegistryError::Io(e.kind());
    let tmp = dir.join(format!(".{name}.tmp"));
    let dest = dir.join(name);
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)
        .map_err(io)?;
    f.write_all(bytes).map_err(io)?;
    f.sync_all().map_err(io)?;
    drop(f);
    std::fs::rename(&tmp, &dest).map_err(io)?;
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(io)?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn write_private_atomic(_: &Path, _: &str, _: &[u8]) -> Result<(), RegistryError> {
    Err(RegistryError::Unsupported)
}

// ------------------------------------------------------------------ primitives

pub(crate) fn hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 15) as usize] as char);
    }
    s
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// SHA-256 of `data`, lower-case hex.
pub(crate) fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// HMAC-SHA-256 (RFC 2104).
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixture keys of check_schema.py (never real keys).
    fn test_key() -> Key {
        Key::from_bytes(*b"fixture-only-key-not-a-secret-00")
    }
    fn other_key() -> Key {
        Key::from_bytes(*b"fixture-only-key-not-a-secret-01")
    }
    fn scope() -> ScopeKey {
        ScopeKey::live("proxy-demo", "fixture", "scope-1")
    }
    fn tool() -> Value {
        json!({"name": "json_ok", "description": "fixture tool",
               "inputSchema": {"type": "object", "properties": {}}})
    }

    #[test]
    fn hmac_rfc4231_vectors() {
        // Test case 1 and 2, and 6 (key longer than the block size).
        assert_eq!(
            hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_eq!(
            hex(&hmac_sha256(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn hmac_rfc4231_case_7_and_block_size_boundaries() {
        // Case 7: key and data both longer than the block size.
        let data = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
        assert_eq!(
            hex(&hmac_sha256(&[0xaa; 131], data)),
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
        );
        // Keys of 63, 64 (exactly the block) and 65 (hashed first) bytes, from
        // Python's hmac module.
        for (n, want) in [
            (
                63u8,
                "a3f5e50452b8f20e018bbad3eec760142f58e8b943446fb154eea58679c63036",
            ),
            (
                64,
                "a5347accf12c5c3edf87ddb44e5b3a1c6957591c7092e527c2e63a5e48f8ebc5",
            ),
            (
                65,
                "0b4330970a8c3347598324cd9a56100c0c95ad46a30ae4de0011a39cc6c31dfe",
            ),
        ] {
            let key: Vec<u8> = (0..n).collect();
            assert_eq!(hex(&hmac_sha256(&key, b"msg")), want, "{n}-byte key");
        }
    }

    /// Vectors computed by the reference model of `check_schema.py`
    /// (`key_id_for`, `fingerprint`, `metadata_ref`).
    #[test]
    fn reproduces_check_schema_model_vectors() {
        let (k, k2, s, t) = (test_key(), other_key(), scope(), tool());
        assert_eq!(k.key_id(), "kid-515d9db90ad81a45ddf59866");
        assert_eq!(k2.key_id(), "kid-8170d36c20a959f16bd92c64");
        let d = k.derive(&s, &t).unwrap();
        assert_eq!(d.key_id, k.key_id());
        assert_eq!(
            d.fingerprint,
            "26416eba2692d8282b881c4ef5f013bd03c64168c83dbeefd9afdaa8a15cd4af"
        );
        assert_eq!(d.metadata_ref, "3f4720a0-484d-8103-a955-96953753827d");
        // Same value as the schema example `invocation-started.example.json`.
        let changed = json!({"name": "json_ok", "description": "changed",
               "inputSchema": {"type": "object", "properties": {}}});
        let dc = k.derive(&s, &changed).unwrap();
        assert_eq!(
            dc.fingerprint,
            "355ff86fe115c1d0f324c429552e059c88d8ed99b70fd2b44438efde03a03b89"
        );
        assert_eq!(dc.metadata_ref, "92ae6aff-c697-88fc-a386-f3d472a83cc8");
        assert_eq!(
            k2.derive(&s, &t).unwrap().metadata_ref,
            "2e96fcd9-1150-83be-a4bb-d9fb5c74ce8c"
        );
        let mut s2 = s.clone();
        s2.credential_scope_id = "scope-2".into();
        assert_eq!(
            k.derive(&s2, &t).unwrap().metadata_ref,
            "e80dd0f0-bfec-8a04-8ab0-7bb1e1018291"
        );
        let mut s3 = s.clone();
        s3.proxy_id = "proxy-b".into();
        assert_eq!(
            k.derive(&s3, &t).unwrap().metadata_ref,
            "747b99d4-9522-89b0-a453-90e705f7464a"
        );
    }

    #[test]
    fn non_ascii_definition_matches_the_model() {
        // Python model: jcs_subset on {"name":"t","é":1,"z":"日本","a😀":true}.
        let v = json!({"name": "t", "é": 1, "z": "日本", "a😀": true});
        assert_eq!(
            test_key().fingerprint(&v).unwrap(),
            "d2f712c7ccaebb3da3f2666e75aac3272a072a4b45e3e3b6f1f0710ddbbb7dbe"
        );
    }

    #[test]
    fn ref_is_a_version_8_uuid_and_deterministic() {
        let r = test_key().derive(&scope(), &tool()).unwrap().metadata_ref;
        let u = uuid::Uuid::parse_str(&r).unwrap();
        assert_eq!(u.get_version_num(), 8);
        assert_eq!(
            r,
            test_key().derive(&scope(), &tool()).unwrap().metadata_ref
        );
        assert!(!r.contains("json_ok"));
        // Key order of the definition does not matter; its content does.
        let reordered: Value = serde_json::from_str(
            r#"{"inputSchema":{"properties":{},"type":"object"},"name":"json_ok","description":"fixture tool"}"#,
        )
        .unwrap();
        assert_eq!(
            test_key().derive(&scope(), &reordered).unwrap(),
            test_key().derive(&scope(), &tool()).unwrap()
        );
    }

    #[test]
    fn generated_keys_differ_and_debug_is_redacted() {
        let (a, b) = (Key::generate().unwrap(), Key::generate().unwrap());
        assert_ne!(a.key_id(), b.key_id());
        let shown = format!("{a:?}");
        assert!(!shown.contains(&hex(&a.bytes)));
        assert_eq!(shown, "Key(<redacted>)");
    }

    #[cfg(unix)]
    #[test]
    fn key_file_round_trip_mode_and_corruption() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        assert!(Key::load(d.path()).unwrap().is_none());
        let k = Key::generate().unwrap();
        k.store(d.path()).unwrap();
        let mode = std::fs::metadata(d.path().join(KEY_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let back = Key::load(d.path()).unwrap().unwrap();
        assert_eq!(back.key_id(), k.key_id());
        // Replacing destroys the old key: only the new one can be read back.
        let k2 = Key::generate().unwrap();
        k2.store(d.path()).unwrap();
        assert_eq!(Key::load(d.path()).unwrap().unwrap().key_id(), k2.key_id());
        // A loose mode, a wrong key_id and garbage are all errors.
        std::fs::set_permissions(
            d.path().join(KEY_FILE),
            std::fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        assert!(matches!(Key::load(d.path()), Err(RegistryError::Io(_))));
        std::fs::set_permissions(
            d.path().join(KEY_FILE),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let mut v: Value =
            serde_json::from_slice(&std::fs::read(d.path().join(KEY_FILE)).unwrap()).unwrap();
        v["key_id"] = json!("kid-000000000000000000000000");
        std::fs::write(d.path().join(KEY_FILE), serde_json::to_vec(&v).unwrap()).unwrap();
        assert!(matches!(
            Key::load(d.path()),
            Err(RegistryError::KeyCorrupt)
        ));
        std::fs::write(d.path().join(KEY_FILE), b"garbage").unwrap();
        assert!(matches!(
            Key::load(d.path()),
            Err(RegistryError::KeyCorrupt)
        ));
    }
}
