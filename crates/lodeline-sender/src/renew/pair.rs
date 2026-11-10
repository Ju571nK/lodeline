//! The host's key and certificate on disk, and how renewal replaces them as a pair.
//!
//! Next files sit beside the live ones: `<key>.next`, `<csr>.next`, `<crt>.next`. They
//! are written with [`write::put`], which leaves `<name>.tmp` while it works. Two files
//! cannot be renamed together, so [`settle`] brings every state a crash can leave to a
//! live key and certificate that fit each other. It runs at start and at every wake.
//! The old key is replaced only by a rename, after the new certificate is durable and
//! checked, so no state leaves the host without a matching pair.

use crate::enroll::cert;
use crate::enroll::write::{self, Put};
use rcgen::KeyPair;
use std::io;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

pub struct Paths {
    pub key: PathBuf,
    pub crt: PathBuf,
    pub ca: PathBuf,
    pub key_next: PathBuf,
    pub csr_next: PathBuf,
    pub crt_next: PathBuf,
}

fn next(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".next");
    path.with_file_name(name)
}

impl Paths {
    pub fn new(crt: &Path, key: &Path, ca: &Path) -> Self {
        Self {
            key: key.to_owned(),
            crt: crt.to_owned(),
            ca: ca.to_owned(),
            key_next: next(key),
            csr_next: next(&key.with_extension("csr")),
            crt_next: next(crt),
        }
    }

    fn dir(&self) -> &Path {
        match self.key.parent() {
            Some(d) if !d.as_os_str().is_empty() => d,
            _ => Path::new("."),
        }
    }
}

/// The parts of a certificate that renewal reads.
pub struct Leaf {
    pub pubkey: Vec<u8>,
    pub not_before: i64,
    pub not_after: i64,
}

/// The first certificate in `pem`.
pub fn leaf(pem: &[u8]) -> Option<Leaf> {
    let der = rustls_pemfile::certs(&mut &*pem).next()?.ok()?;
    let (_, x) = x509_parser::parse_x509_certificate(&der).ok()?;
    Some(Leaf {
        pubkey: x.public_key().subject_public_key.data.to_vec(),
        not_before: x.validity().not_before.timestamp(),
        not_after: x.validity().not_after.timestamp(),
    })
}

struct Cert {
    pem: String,
    leaf: Leaf,
}

fn read_key(path: &Path) -> io::Result<Option<KeyPair>> {
    Ok(write::read_existing(path)?
        .and_then(|b| String::from_utf8(b).ok())
        .and_then(|s| KeyPair::from_pem(&s).ok()))
}

fn read_cert(path: &Path) -> io::Result<Option<Cert>> {
    Ok(write::read_existing(path)?
        .and_then(|b| String::from_utf8(b).ok())
        .and_then(|pem| {
            Some(Cert {
                leaf: leaf(pem.as_bytes())?,
                pem,
            })
        }))
}

fn fits(key: &Option<KeyPair>, cert: &Option<Cert>) -> bool {
    matches!((key, cert), (Some(k), Some(c)) if c.leaf.pubkey == k.public_key_raw())
}

fn remove(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

fn rename_synced(from: &Path, to: &Path, dir: &Path) -> io::Result<()> {
    std::fs::rename(from, to)?;
    write::sync_dir(&write::open_dir(dir)?)
}

fn drop_next(p: &Paths) -> io::Result<()> {
    [&p.key_next, &p.csr_next, &p.crt_next]
        .into_iter()
        .try_for_each(|f| remove(f))
}

/// Key first, a directory sync, then the certificate and a directory sync. The request
/// is spent once the certificate is live, so its file goes last.
pub fn commit(p: &Paths) -> io::Result<()> {
    rename_synced(&p.key_next, &p.key, p.dir())?;
    rename_synced(&p.crt_next, &p.crt, p.dir())?;
    remove(&p.csr_next)
}

/// Bring the files in `p` to a live pair that fits, whatever a crash left. `Ok(Some(why))`
/// is a state this cannot repair: nothing is deleted, and the caller tells the operator.
pub fn settle(
    p: &Paths,
    host_id: &str,
    ca_pem: &str,
    now: OffsetDateTime,
) -> io::Result<Option<String>> {
    // A `.tmp` is an unfinished `put`. With two links it is the same file as its target.
    for n in [&p.key_next, &p.csr_next, &p.crt_next] {
        let mut tmp = n.file_name().unwrap_or_default().to_os_string();
        tmp.push(".tmp");
        remove(&n.with_file_name(tmp))?;
    }
    let (key, crt) = (read_key(&p.key)?, read_cert(&p.crt)?);
    let (key_next, crt_next) = (read_key(&p.key_next)?, read_cert(&p.crt_next)?);

    if !fits(&key, &crt) {
        // A commit stopped between its renames, or its directory sync was lost.
        if fits(&key_next, &crt) {
            rename_synced(&p.key_next, &p.key, p.dir())?;
        } else if fits(&key, &crt_next) {
            rename_synced(&p.crt_next, &p.crt, p.dir())?;
            remove(&p.csr_next)?;
        } else {
            return Ok(Some(
                "client.key and client.crt do not match. Run `lodeline-sender enroll` with a \
                 new token (move both files aside first)"
                    .into(),
            ));
        }
        return settle(p, host_id, ca_pem, now);
    }
    match (key_next, crt_next, crt) {
        (Some(k), Some(c), Some(live)) => {
            let usable = c.leaf.pubkey == k.public_key_raw()
                && c.leaf.not_after > live.leaf.not_after
                && cert::check(&c.pem, k.public_key_raw(), host_id, ca_pem, now).is_ok();
            if usable {
                commit(p)?;
            } else {
                drop_next(p)?;
            }
        }
        (_, Some(_), _) => drop_next(p)?,
        (None, None, _) => remove(&p.csr_next)?,
        _ => {}
    }
    Ok(None)
}

/// The new key and the CSR for it, from the next files when they are there. A repeat
/// sends the same CSR bytes, which the server allows after a lost answer.
pub fn prepare(p: &Paths, host_id: &str) -> anyhow::Result<(KeyPair, String)> {
    let key = match read_key(&p.key_next)? {
        Some(k) => k,
        None => {
            let k = crate::csr::new_key()?;
            write::put(&p.key_next, k.serialize_pem().as_bytes(), 0o600, false)
                .map_err(|e| anyhow::anyhow!("{}: {e}", p.key_next.display()))?;
            k
        }
    };
    let csr = match write::read_existing(&p.csr_next)? {
        Some(b) => String::from_utf8(b)?,
        None => {
            let c = crate::csr::csr_for(&key, host_id)?;
            write::put(&p.csr_next, c.as_bytes(), 0o600, false)
                .map_err(|e| anyhow::anyhow!("{}: {e}", p.csr_next.display()))?;
            c
        }
    };
    Ok((key, csr))
}

/// The new certificate, durable. It is not live until [`commit`].
pub fn store_cert(p: &Paths, bundle: &str) -> anyhow::Result<()> {
    match write::put(&p.crt_next, bundle.as_bytes(), 0o644, false) {
        Ok(Put::Written | Put::Same) => Ok(()),
        Err(e) => Err(anyhow::anyhow!("{}: {e}", p.crt_next.display())),
    }
}

/// Whether this account can create files beside the live pair. An `enroll` run as root
/// leaves a root-owned directory, and then it cannot.
pub fn writable(p: &Paths) -> io::Result<()> {
    let probe = p.dir().join(format!(".renew-probe-{}", std::process::id()));
    write::put(&probe, b"", 0o600, false).map_err(|e| io::Error::other(e.to_string()))?;
    remove(&probe)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enroll::cert::tests::{ca, leaf as mint, HOST};
    use rcgen::{CertifiedIssuer, ExtendedKeyUsagePurpose::ClientAuth};
    use time::Duration;

    /// One host directory, one CA, and the clock the certificates are made against.
    struct World {
        _dir: tempfile::TempDir,
        p: Paths,
        root: CertifiedIssuer<'static, KeyPair>,
        now: OffsetDateTime,
    }

    impl World {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let p = Paths::new(
                &dir.path().join("client.crt"),
                &dir.path().join("client.key"),
                &dir.path().join("server-ca.pem"),
            );
            let root = ca("root");
            std::fs::write(&p.ca, root.pem()).unwrap();
            Self {
                _dir: dir,
                p,
                root,
                now: OffsetDateTime::now_utc(),
            }
        }

        /// A certificate for `key` and `cn`, valid from `from` to `to` days around now.
        fn cert_for(&self, key: &KeyPair, cn: &str, from: i64, to: i64) -> String {
            let (nb, na) = (
                self.now + Duration::days(from),
                self.now + Duration::days(to),
            );
            format!(
                "{}{}",
                mint(&self.root, key, cn, ClientAuth, nb, na),
                self.root.pem()
            )
        }

        /// The first certificate: 20 days old, 10 left.
        fn old(&self, key: &KeyPair) -> String {
            self.cert_for(key, HOST, -20, 10)
        }

        /// A successor: 30 days from now.
        fn new_cert(&self, key: &KeyPair) -> String {
            self.cert_for(key, HOST, 0, 30)
        }

        fn put(&self, path: &Path, text: &str) {
            std::fs::write(path, text).unwrap();
        }

        fn put_key(&self, path: &Path, key: &KeyPair) {
            self.put(path, &key.serialize_pem());
        }

        fn settle(&self) -> Option<String> {
            settle(
                &self.p,
                HOST,
                &std::fs::read_to_string(&self.p.ca).unwrap(),
                self.now,
            )
            .unwrap()
        }

        fn live_fits(&self) -> bool {
            fits(
                &read_key(&self.p.key).unwrap(),
                &read_cert(&self.p.crt).unwrap(),
            )
        }

        fn live_not_after(&self) -> i64 {
            read_cert(&self.p.crt).unwrap().unwrap().leaf.not_after
        }

        fn exists(&self, path: &Path) -> bool {
            path.exists()
        }

        /// The live pair K0/C0 and the new key K1.
        fn start(&self) -> (KeyPair, String, KeyPair) {
            let (k0, k1) = (KeyPair::generate().unwrap(), KeyPair::generate().unwrap());
            let c0 = self.old(&k0);
            self.put_key(&self.p.key, &k0);
            self.put(&self.p.crt, &c0);
            (k0, c0, k1)
        }
    }

    // One test per state in the recovery table of docs/install-server.md (3.5). A crash
    // is a state on disk, so each test builds the state a crash leaves, runs `settle`,
    // and checks the files.

    #[test]
    fn a_leftover_tmp_is_removed_for_each_of_the_three_names() {
        for n in 0..3 {
            let w = World::new();
            w.start();
            let name = [&w.p.key_next, &w.p.csr_next, &w.p.crt_next][n];
            let tmp = name.with_file_name(format!(
                "{}.tmp",
                name.file_name().unwrap().to_str().unwrap()
            ));
            w.put(&tmp, "half written");
            assert_eq!(w.settle(), None);
            assert!(!w.exists(&tmp), "{tmp:?}");
            assert!(w.live_fits());
            // The name is free again, so the next `put` does not meet StaleTemp.
            assert!(write::put(name, b"x", 0o600, false).is_ok());
        }
    }

    #[test]
    fn a_next_file_with_two_links_is_one_file_once_its_tmp_is_gone() {
        let w = World::new();
        let (_, _, k1) = w.start();
        w.put_key(&w.p.key_next, &k1);
        let tmp = w.p.key_next.with_file_name("client.key.next.tmp");
        std::fs::hard_link(&w.p.key_next, &tmp).unwrap();
        assert!(
            write::read_existing(&w.p.key_next).is_err(),
            "two links are refused"
        );
        assert_eq!(w.settle(), None);
        assert!(!w.exists(&tmp));
        assert_eq!(
            read_key(&w.p.key_next).unwrap().unwrap().public_key_raw(),
            k1.public_key_raw()
        );
    }

    #[test]
    fn a_key_next_alone_is_kept_and_prepare_makes_its_csr() {
        let w = World::new();
        let (_, _, k1) = w.start();
        w.put_key(&w.p.key_next, &k1);
        assert_eq!(w.settle(), None);
        assert!(w.exists(&w.p.key_next));
        let (key, csr) = prepare(&w.p, HOST).unwrap();
        assert_eq!(key.public_key_raw(), k1.public_key_raw(), "the same key");
        assert_eq!(std::fs::read_to_string(&w.p.csr_next).unwrap(), csr);
    }

    #[test]
    fn key_and_csr_next_are_kept_and_the_same_csr_is_sent_again() {
        let w = World::new();
        w.start();
        let (_, first) = prepare(&w.p, HOST).unwrap();
        assert_eq!(w.settle(), None, "an unanswered request changes nothing");
        let (_, again) = prepare(&w.p, HOST).unwrap();
        assert_eq!(
            first, again,
            "the CSR bytes are the same, as a repeat needs"
        );
        assert!(w.exists(&w.p.key_next) && w.exists(&w.p.csr_next));
    }

    #[test]
    fn a_checked_crt_next_is_committed_and_csr_next_is_removed() {
        let w = World::new();
        let (_, _, k1) = w.start();
        let before = w.live_not_after();
        w.put_key(&w.p.key_next, &k1);
        w.put(&w.p.csr_next, "csr");
        w.put(&w.p.crt_next, &w.new_cert(&k1));
        assert_eq!(w.settle(), None);
        assert!(w.live_fits());
        assert!(
            w.live_not_after() > before,
            "the live certificate is the new one"
        );
        assert_eq!(
            read_key(&w.p.key).unwrap().unwrap().public_key_raw(),
            k1.public_key_raw()
        );
        for f in [&w.p.key_next, &w.p.csr_next, &w.p.crt_next] {
            assert!(!w.exists(f), "{f:?}");
        }
    }

    #[test]
    fn a_crt_next_without_csr_next_is_committed() {
        let w = World::new();
        let (_, _, k1) = w.start();
        w.put_key(&w.p.key_next, &k1);
        w.put(&w.p.crt_next, &w.new_cert(&k1));
        assert_eq!(w.settle(), None);
        assert!(w.live_fits());
        assert!(!w.exists(&w.p.crt_next) && !w.exists(&w.p.key_next));
    }

    #[test]
    fn a_key_renamed_first_is_finished_by_renaming_the_certificate() {
        let w = World::new();
        let (_, c0, k1) = w.start();
        // The key rename is done and synced; the certificate rename is not.
        w.put_key(&w.p.key, &k1);
        w.put(&w.p.crt, &c0);
        w.put(&w.p.crt_next, &w.new_cert(&k1));
        w.put(&w.p.csr_next, "csr");
        assert!(!w.live_fits(), "the pair is split until settle runs");
        assert_eq!(w.settle(), None);
        assert!(w.live_fits());
        assert!(!w.exists(&w.p.crt_next) && !w.exists(&w.p.csr_next));
    }

    #[test]
    fn a_finished_commit_with_a_leftover_csr_next_removes_it() {
        let w = World::new();
        let (_, _, k1) = w.start();
        w.put_key(&w.p.key, &k1);
        w.put(&w.p.crt, &w.new_cert(&k1));
        w.put(&w.p.csr_next, "csr");
        assert_eq!(w.settle(), None);
        assert!(w.live_fits());
        assert!(!w.exists(&w.p.csr_next));
    }

    #[test]
    fn a_certificate_renamed_first_is_finished_by_renaming_the_key() {
        let w = World::new();
        let (_, _, k1) = w.start();
        // Power loss kept the certificate rename and lost the key rename.
        w.put(&w.p.crt, &w.new_cert(&k1));
        w.put_key(&w.p.key_next, &k1);
        assert!(!w.live_fits());
        assert_eq!(w.settle(), None);
        assert!(w.live_fits());
        assert!(!w.exists(&w.p.key_next));
        assert_eq!(
            read_key(&w.p.key).unwrap().unwrap().public_key_raw(),
            k1.public_key_raw()
        );
    }

    #[test]
    fn next_files_that_do_not_beat_a_replaced_live_pair_are_dropped_and_the_pair_stays() {
        // enroll or a person replaced the live pair; the next files are from before.
        type Make = fn(&World, &KeyPair) -> String;
        let stale: [(&str, Make); 3] = [
            ("not later", |w, k| w.cert_for(k, HOST, -25, 5)),
            ("another host", |w, k| w.cert_for(k, "someone-else", 0, 30)),
            ("another key", |w, _| {
                w.new_cert(&KeyPair::generate().unwrap())
            }),
        ];
        for (why, make) in stale {
            let w = World::new();
            let (k2, k1) = (KeyPair::generate().unwrap(), KeyPair::generate().unwrap());
            w.put_key(&w.p.key, &k2);
            w.put(&w.p.crt, &w.cert_for(&k2, HOST, -1, 15));
            w.put_key(&w.p.key_next, &k1);
            w.put(&w.p.csr_next, "csr");
            w.put(&w.p.crt_next, &make(&w, &k1));
            let live = std::fs::read(&w.p.crt).unwrap();
            assert_eq!(w.settle(), None, "{why}");
            assert_eq!(
                std::fs::read(&w.p.crt).unwrap(),
                live,
                "{why}: the live certificate stays"
            );
            assert!(w.live_fits(), "{why}");
            for f in [&w.p.key_next, &w.p.csr_next, &w.p.crt_next] {
                assert!(!w.exists(f), "{why}: {f:?}");
            }
        }
    }

    #[test]
    fn a_live_key_that_fits_no_certificate_is_an_error_and_nothing_is_deleted() {
        let w = World::new();
        let (_, _, k1) = w.start();
        w.put_key(&w.p.key, &KeyPair::generate().unwrap());
        w.put_key(&w.p.key_next, &k1);
        let why = w.settle().expect("an error text");
        assert!(
            why.contains("do not match") && why.contains("enroll"),
            "{why}"
        );
        assert!(w.exists(&w.p.key) && w.exists(&w.p.crt) && w.exists(&w.p.key_next));
    }

    #[test]
    fn a_wrong_answer_on_disk_never_replaces_the_live_pair() {
        // The answer must fit the next key and name this host and chain to the CA.
        let w = World::new();
        let (k0, c0, k1) = w.start();
        let other_root = ca("not-the-server-ca");
        let (nb, na) = (w.now - Duration::days(1), w.now + Duration::days(30));
        let wrong = [
            w.cert_for(&KeyPair::generate().unwrap(), HOST, 0, 30),
            w.cert_for(&k1, "someone-else", 0, 30),
            format!(
                "{}{}",
                mint(&other_root, &k1, HOST, ClientAuth, nb, na),
                other_root.pem()
            ),
        ];
        for bundle in wrong {
            w.put_key(&w.p.key_next, &k1);
            w.put(&w.p.crt_next, &bundle);
            assert_eq!(w.settle(), None);
            assert_eq!(std::fs::read_to_string(&w.p.crt).unwrap(), c0);
            assert_eq!(
                read_key(&w.p.key).unwrap().unwrap().public_key_raw(),
                k0.public_key_raw()
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_probe_fails_in_a_directory_this_account_cannot_write() {
        use std::os::unix::fs::PermissionsExt;
        let w = World::new();
        assert!(writable(&w.p).is_ok());
        let dir = w.p.dir().to_owned();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        let root = unsafe { libc::geteuid() } == 0;
        let failed = writable(&w.p).is_err();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(failed || root);
    }
}
