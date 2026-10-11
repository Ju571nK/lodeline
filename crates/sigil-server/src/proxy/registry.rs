//! Proxy registry: `proxy_id` to fingerprints + state (control-plane §1.2/§1.3).
//!
//! Storage: one JSON file, loaded into memory at boot and rewritten
//! atomically (tmp in same dir + fsync + rename) on every mutation. Mutations
//! are persist-first-then-swap: a failed write leaves memory unchanged.
// OPEN: moves to the S4 ledger DB.

use anyhow::{bail, Context, Result};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyState {
    Pending,
    Active,
    Disabled,
    Retired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyRecord {
    pub proxy_id: String,
    pub display_name: String,
    pub state: ProxyState,
    /// blake3 hex of the current leaf DER.
    pub fp_current: Option<String>,
    /// blake3 hex of the renewal leaf (accepted alongside `fp_current`).
    pub fp_next: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl ProxyRecord {
    /// True when `fp` equals the current or next fingerprint.
    pub fn matches_fingerprint(&self, fp: &str) -> bool {
        [&self.fp_current, &self.fp_next]
            .into_iter()
            .flatten()
            .any(|f| f == fp)
    }
}

#[derive(Default, Serialize, Deserialize)]
struct FileFormat {
    proxies: Vec<ProxyRecord>,
}

pub struct ProxyRegistry {
    path: PathBuf,
    inner: RwLock<BTreeMap<String, ProxyRecord>>,
}

impl ProxyRegistry {
    /// Load the registry (boot). Fail closed:
    /// - a missing file is an error unless `init` (config `registry_init`),
    ///   which creates an empty registry;
    /// - a symlink, or a file writable by group/others, is refused;
    /// - duplicate `proxy_id`s, or one fingerprint held by two ids, are refused.
    pub fn open(path: &Path, init: bool) -> Result<Self> {
        let meta = match std::fs::symlink_metadata(path) {
            Ok(m) => Some(m),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e).context("stat proxy registry"),
        };
        let Some(meta) = meta else {
            if !init {
                bail!(
                    "proxy registry {} does not exist (set proxy.registry_init: true to create it)",
                    path.display()
                );
            }
            let reg = Self {
                path: path.to_path_buf(),
                inner: RwLock::new(BTreeMap::new()),
            };
            write_atomic(path, &serde_json::to_vec_pretty(&FileFormat::default())?)?;
            return Ok(reg);
        };
        if meta.file_type().is_symlink() {
            bail!("proxy registry must not be a symlink");
        }
        if !meta.is_file() {
            bail!("proxy registry is not a regular file");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o022 != 0 {
                bail!("proxy registry must not be group- or world-writable");
            }
        }
        let b = std::fs::read(path).context("read proxy registry")?;
        let f: FileFormat = serde_json::from_slice(&b).context("parse proxy registry JSON")?;
        let mut map = BTreeMap::new();
        for r in f.proxies {
            if map.insert(r.proxy_id.clone(), r).is_some() {
                bail!("duplicate proxy_id in registry");
            }
        }
        // One fingerprint must identify one proxy_id (the same fp twice inside
        // one record is harmless).
        let mut owner: BTreeMap<&str, &str> = BTreeMap::new();
        for r in map.values() {
            for fp in [&r.fp_current, &r.fp_next].into_iter().flatten() {
                if let Some(prev) = owner.insert(fp.as_str(), r.proxy_id.as_str()) {
                    if prev != r.proxy_id {
                        bail!("fingerprint held by more than one proxy_id");
                    }
                }
            }
        }
        Ok(Self {
            path: path.to_path_buf(),
            inner: RwLock::new(map),
        })
    }

    pub fn get(&self, proxy_id: &str) -> Option<ProxyRecord> {
        self.inner.read().get(proxy_id).cloned()
    }

    /// True if any entry (any state) holds `fp` as current or next. Used to
    /// keep registered proxy leaves off host routes.
    pub fn holds_fingerprint(&self, fp: &str) -> bool {
        self.inner
            .read()
            .values()
            .any(|r| r.matches_fingerprint(fp))
    }

    /// Start a write transaction. Holds the registry write lock until the
    /// returned value is committed or dropped, so the management handlers can
    /// validate, append the audit record and commit atomically.
    pub fn begin(&self) -> RegistryTxn<'_> {
        RegistryTxn {
            guard: self.inner.write(),
            path: &self.path,
        }
    }

    /// Promote `fp_next` to `fp_current` when `fp` is the (distinct) next
    /// fingerprint of an active entry. Returns whether anything changed.
    /// Persist-first-then-swap. This is the rotation rule: the old
    /// fingerprint is dropped at the first request authenticated with `next`.
    pub fn promote_next(&self, proxy_id: &str, fp: &str, now: &str) -> Result<bool> {
        let txn = self.begin();
        let Some(rec) = txn.get(proxy_id) else {
            return Ok(false);
        };
        if rec.state != ProxyState::Active
            || rec.fp_next.as_deref() != Some(fp)
            || rec.fp_current.as_deref() == Some(fp)
        {
            return Ok(false);
        }
        let mut next = rec;
        next.fp_current = next.fp_next.take();
        next.updated_at = now.to_string();
        txn.commit(next)?;
        Ok(true)
    }

    /// Insert or replace a record. Persists to disk first, then swaps the
    /// in-memory map, so a failed write leaves memory unchanged.
    ///
    /// Test-only seeding helper (state setups the management routes cannot
    /// reach). Compiled only for unit tests or with the `test-support` feature.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn seed_for_test(&self, record: ProxyRecord) -> Result<()> {
        let mut g = self.inner.write();
        let mut next = g.clone();
        next.insert(record.proxy_id.clone(), record);
        let file = FileFormat {
            proxies: next.values().cloned().collect(),
        };
        write_atomic(&self.path, &serde_json::to_vec_pretty(&file)?)?;
        *g = next;
        Ok(())
    }
}

/// Write transaction on the registry (see [`ProxyRegistry::begin`]).
pub struct RegistryTxn<'a> {
    guard: parking_lot::RwLockWriteGuard<'a, BTreeMap<String, ProxyRecord>>,
    path: &'a Path,
}

impl RegistryTxn<'_> {
    pub fn get(&self, proxy_id: &str) -> Option<ProxyRecord> {
        self.guard.get(proxy_id).cloned()
    }

    /// The `proxy_id` that holds `fp` as current or next, in any state.
    pub fn fingerprint_owner(&self, fp: &str) -> Option<String> {
        self.guard
            .values()
            .find(|r| r.matches_fingerprint(fp))
            .map(|r| r.proxy_id.clone())
    }

    /// Persist the record (insert or replace) and then swap it into memory.
    /// On error nothing changed in memory.
    pub fn commit(mut self, record: ProxyRecord) -> Result<()> {
        let mut next = self.guard.clone();
        next.insert(record.proxy_id.clone(), record);
        let file = FileFormat {
            proxies: next.values().cloned().collect(),
        };
        write_atomic(self.path, &serde_json::to_vec_pretty(&file)?)?;
        *self.guard = next;
        Ok(())
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    let mut tmp = tempfile::Builder::new()
        .prefix(".proxies-")
        .tempfile_in(dir)?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    if let Ok(f) = std::fs::File::open(dir) {
        let _ = f.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str, state: ProxyState, cur: Option<&str>, next: Option<&str>) -> ProxyRecord {
        ProxyRecord {
            proxy_id: id.into(),
            display_name: id.into(),
            state,
            fp_current: cur.map(str::to_string),
            fp_next: next.map(str::to_string),
            created_at: "2026-10-11T00:00:00Z".into(),
            updated_at: "2026-10-11T00:00:00Z".into(),
        }
    }

    #[test]
    fn persists_and_reloads() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("sub/proxies.json");
        assert!(
            ProxyRegistry::open(&p, false).is_err(),
            "missing file refused"
        );
        let r = ProxyRegistry::open(&p, true).unwrap();
        assert!(r.get("px").is_none());
        r.seed_for_test(rec("px", ProxyState::Active, Some("aa"), Some("bb")))
            .unwrap();
        let r2 = ProxyRegistry::open(&p, false).unwrap();
        let got = r2.get("px").unwrap();
        assert_eq!(got.state, ProxyState::Active);
        assert!(got.matches_fingerprint("aa") && got.matches_fingerprint("bb"));
        assert!(!got.matches_fingerprint("cc"));
        assert!(r2.holds_fingerprint("bb") && !r2.holds_fingerprint("cc"));
    }

    #[test]
    fn broken_file_is_an_error() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("proxies.json");
        std::fs::write(&p, b"{not json").unwrap();
        assert!(ProxyRegistry::open(&p, false).is_err());
    }

    fn write_json(p: &Path, recs: &[ProxyRecord]) {
        let f = FileFormat {
            proxies: recs.to_vec(),
        };
        std::fs::write(p, serde_json::to_vec(&f).unwrap()).unwrap();
    }

    #[test]
    fn duplicate_ids_and_cross_id_fingerprints_refused() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("proxies.json");
        let a = rec("a", ProxyState::Active, Some("aa"), None);
        write_json(&p, &[a.clone(), a.clone()]);
        assert!(ProxyRegistry::open(&p, false).is_err());
        let b = rec("b", ProxyState::Active, None, Some("aa"));
        write_json(&p, &[a.clone(), b]);
        assert!(ProxyRegistry::open(&p, false).is_err());
        let c = rec("c", ProxyState::Active, Some("cc"), None);
        write_json(&p, &[a, c]);
        assert!(ProxyRegistry::open(&p, false).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn writable_or_symlinked_file_refused() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("proxies.json");
        write_json(&p, &[]);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o664)).unwrap();
        assert!(ProxyRegistry::open(&p, false).is_err());
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(ProxyRegistry::open(&p, false).is_ok());
        let l = d.path().join("link.json");
        std::os::unix::fs::symlink(&p, &l).unwrap();
        assert!(ProxyRegistry::open(&l, false).is_err());
    }
}
