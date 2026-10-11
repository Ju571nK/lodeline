//! Proxy registry: `proxy_id` to fingerprints + state (control-plane §1.2/§1.3).
//!
//! S1 storage: one JSON file, loaded into memory at boot and rewritten
//! atomically (tmp in same dir + fsync + rename) on every mutation.
// OPEN: moves to the S4 ledger DB.

use anyhow::{Context, Result};
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
    /// Load the registry, or start empty when the file does not exist. A
    /// present-but-broken file is a hard error (fail closed at boot).
    pub fn open(path: &Path) -> Result<Self> {
        let map = match std::fs::read(path) {
            Ok(b) => {
                let f: FileFormat =
                    serde_json::from_slice(&b).context("parse proxy registry JSON")?;
                f.proxies
                    .into_iter()
                    .map(|r| (r.proxy_id.clone(), r))
                    .collect()
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e).context("read proxy registry"),
        };
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

    /// Insert or replace a record and persist atomically.
    ///
    /// Test-only seeding helper for S1: there are no management routes yet
    /// (S2). Not for production callers.
    #[doc(hidden)]
    pub fn seed_for_test(&self, record: ProxyRecord) -> Result<()> {
        let mut g = self.inner.write();
        g.insert(record.proxy_id.clone(), record);
        let file = FileFormat {
            proxies: g.values().cloned().collect(),
        };
        write_atomic(&self.path, &serde_json::to_vec_pretty(&file)?)
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
        let r = ProxyRegistry::open(&p).unwrap();
        assert!(r.get("px").is_none());
        r.seed_for_test(rec("px", ProxyState::Active, Some("aa"), Some("bb")))
            .unwrap();
        let r2 = ProxyRegistry::open(&p).unwrap();
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
        assert!(ProxyRegistry::open(&p).is_err());
    }
}
