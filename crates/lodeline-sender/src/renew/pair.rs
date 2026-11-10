//! The host's key and certificate on disk, and how renewal replaces them as a pair.
//!
//! Next files sit beside the live ones: `<key>.next` and `<csr>.next` in the key's
//! directory, `<crt>.next` in the certificate's, so no rename crosses a directory. They
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

    fn key_dir(&self) -> &Path {
        dir_of(&self.key)
    }

    fn crt_dir(&self) -> &Path {
        dir_of(&self.crt)
    }
}

fn dir_of(file: &Path) -> &Path {
    match file.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    }
}

/// The parts of a certificate that renewal reads.
pub struct Leaf {
    pub cn: Option<String>,
    pub pubkey: Vec<u8>,
    pub not_before: i64,
    pub not_after: i64,
}

/// The first certificate in `pem`.
pub fn leaf(pem: &[u8]) -> Option<Leaf> {
    let der = rustls_pemfile::certs(&mut &*pem).next()?.ok()?;
    let (_, x) = x509_parser::parse_x509_certificate(&der).ok()?;
    let cn = x
        .subject()
        .iter_common_name()
        .next()
        .and_then(|c| c.as_str().ok())
        .map(str::to_owned);
    Some(Leaf {
        cn,
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

/// The server CA file. Unreadable is an error, never an empty CA: an answer is not judged
/// against a CA that could not be read.
pub fn ca_pem(p: &Paths) -> io::Result<String> {
    std::fs::read_to_string(&p.ca)
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", p.ca.display())))
}

/// What a new certificate is, against the live one.
pub enum Verdict {
    /// It may replace the live pair.
    Usable,
    /// Not newer than the live certificate, or for another host: the files it came with
    /// are from before the live pair was replaced.
    Stale(String),
    /// It does not fit the new key, or fails the chain or purpose check.
    Unfit(String),
}

/// The one rule for whether an answer may replace the live pair, for a live answer and a
/// stored one alike.
pub fn judge(
    live_not_after: i64,
    key: &KeyPair,
    bundle: &str,
    host_id: &str,
    ca_pem: &str,
    now: OffsetDateTime,
) -> Verdict {
    let Some(new) = leaf(bundle.as_bytes()) else {
        return Verdict::Unfit("there is no certificate in it".into());
    };
    if new.cn.as_deref() != Some(host_id) {
        return Verdict::Stale("it names another host than this one".into());
    }
    if new.not_after <= live_not_after {
        return Verdict::Stale("it does not expire later than the certificate in use".into());
    }
    match cert::check(bundle, key.public_key_raw(), host_id, ca_pem, now) {
        Ok(_) => Verdict::Usable,
        Err(why) => Verdict::Unfit(why),
    }
}

fn remove(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Rename `from` to `to`, then sync the directory the two share.
fn rename_synced(from: &Path, to: &Path) -> io::Result<()> {
    std::fs::rename(from, to)?;
    write::sync_dir(&write::open_dir(dir_of(to))?)
}

fn drop_next(p: &Paths) -> io::Result<()> {
    [&p.key_next, &p.csr_next, &p.crt_next]
        .into_iter()
        .try_for_each(|f| remove(f))
}

/// Key first, a directory sync, then the certificate and a directory sync. The request
/// is spent once the certificate is live, so its file goes last.
pub fn commit(p: &Paths) -> io::Result<()> {
    rename_synced(&p.key_next, &p.key)?;
    rename_synced(&p.crt_next, &p.crt)?;
    remove(&p.csr_next)
}

/// Bring the files in `p` to a live pair that fits, whatever a crash left. `Ok(Some(why))`
/// is a state this cannot repair: nothing is deleted, and the caller tells the operator.
pub fn settle(p: &Paths, host_id: &str, now: OffsetDateTime) -> io::Result<Option<String>> {
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
            rename_synced(&p.key_next, &p.key)?;
        } else if fits(&key, &crt_next) {
            rename_synced(&p.crt_next, &p.crt)?;
            remove(&p.csr_next)?;
        } else {
            let gone: Vec<_> = [(&p.key, "client.key"), (&p.crt, "client.crt")]
                .into_iter()
                .filter(|(f, _)| !f.exists())
                .map(|(_, name)| name)
                .collect();
            return Ok(Some(if gone.is_empty() {
                "client.key and client.crt do not match. Run `lodeline-sender enroll` with a \
                 new token (move both files aside first)"
                    .into()
            } else {
                format!(
                    "{} missing. Run `lodeline-sender enroll` with a new token",
                    gone.join(" and ")
                )
            }));
        }
        return settle(p, host_id, now);
    }
    match (key_next, crt_next, crt) {
        (Some(k), Some(c), Some(live)) => {
            // Read the CA before anything is judged, so an unreadable one drops nothing.
            let ca = ca_pem(p)?;
            match judge(live.leaf.not_after, &k, &c.pem, host_id, &ca, now) {
                Verdict::Usable => commit(p)?,
                Verdict::Stale(_) => drop_next(p)?,
                // Keep the key and the request: the same CSR is sent again.
                Verdict::Unfit(_) => remove(&p.crt_next)?,
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

/// Whether this account can create files beside the live pair, in the directory of the key
/// and in the directory of the certificate. An `enroll` run as root leaves a root-owned
/// directory, and then it cannot.
pub fn writable(p: &Paths) -> io::Result<()> {
    let mut dirs = vec![p.key_dir()];
    if p.crt_dir() != p.key_dir() {
        dirs.push(p.crt_dir());
    }
    dirs.into_iter().try_for_each(|dir| {
        let probe = dir.join(format!(".renew-probe-{}", std::process::id()));
        let mut tmp = probe.clone().into_os_string();
        tmp.push(".tmp");
        // A crash inside an earlier probe by a process with this id left one of these.
        remove(&PathBuf::from(tmp))?;
        remove(&probe)?;
        write::put(&probe, b"", 0o600, false).map_err(|e| io::Error::other(e.to_string()))?;
        remove(&probe)
    })
}

/// Why renewal must stay off: the new key is made by this process, so it must own the
/// live key, or the account the sender runs as could not read the new key at its next
/// start.
pub fn owner_problem(euid: u32, key_owner: u32) -> Option<String> {
    (euid != key_owner).then(|| {
        format!(
            "certificate renewal is off: client.key is owned by uid {key_owner} and the sender \
             runs as uid {euid}. Renewal would make a key that the account owning client.key \
             could not read. Run the sender as the account that owns client.key (the packaged \
             service runs as `lodeline`) and restart it"
        )
    })
}

/// [`owner_problem`] for the files on disk. No live key, or not Unix: no problem here.
pub fn key_owner_problem(p: &Paths) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let owner = std::fs::metadata(&p.key).ok()?.uid();
        // SAFETY: geteuid has no preconditions.
        owner_problem(unsafe { libc::geteuid() }, owner)
    }
    #[cfg(not(unix))]
    {
        let _ = p;
        None
    }
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
            settle(&self.p, HOST, self.now).unwrap()
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
        #[cfg(unix)]
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
        let stale: [(&str, Make); 2] = [
            ("not later", |w, k| w.cert_for(k, HOST, -25, 5)),
            ("another host", |w, k| w.cert_for(k, "someone-else", 0, 30)),
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
    fn commit_renames_the_key_before_the_certificate() {
        // No certificate to rename, so the second rename fails: what the first did stays.
        let w = World::new();
        let (_, c0, k1) = w.start();
        w.put_key(&w.p.key_next, &k1);
        assert!(commit(&w.p).is_err());
        assert_eq!(
            read_key(&w.p.key).unwrap().unwrap().public_key_raw(),
            k1.public_key_raw(),
            "the key went first"
        );
        assert_eq!(std::fs::read_to_string(&w.p.crt).unwrap(), c0);
    }

    #[test]
    fn a_crt_next_alone_is_dropped_and_the_next_renewal_can_store_its_answer() {
        // A crash inside `drop_next` leaves this. Kept, it would make `store_cert` conflict.
        let w = World::new();
        let (_, c0, k1) = w.start();
        w.put(&w.p.crt_next, &w.new_cert(&k1));
        assert_eq!(w.settle(), None);
        assert!(!w.exists(&w.p.crt_next));
        assert_eq!(std::fs::read_to_string(&w.p.crt).unwrap(), c0);
        let (key, _) = prepare(&w.p, HOST).unwrap();
        assert!(store_cert(&w.p, &w.new_cert(&key)).is_ok());
    }

    #[test]
    fn an_input_that_cannot_be_read_drops_nothing_and_is_not_clean() {
        let w = World::new();
        let (_, c0, k1) = w.start();
        w.put_key(&w.p.key_next, &k1);
        w.put(&w.p.csr_next, "csr");
        w.put(&w.p.crt_next, &w.new_cert(&k1));
        std::fs::remove_file(&w.p.ca).unwrap();
        assert!(settle(&w.p, HOST, w.now).is_err());
        for f in [&w.p.key_next, &w.p.csr_next, &w.p.crt_next] {
            assert!(w.exists(f), "{f:?}");
        }
        assert_eq!(std::fs::read_to_string(&w.p.crt).unwrap(), c0);
        // The CA is back: the same files are now committed.
        std::fs::write(&w.p.ca, w.root.pem()).unwrap();
        assert_eq!(w.settle(), None);
        assert!(w.live_fits() && !w.exists(&w.p.crt_next));
    }

    #[test]
    fn a_crt_next_that_fails_its_check_is_dropped_alone_so_the_same_csr_is_sent_again() {
        let other_root = ca("not-the-server-ca");
        type Make = fn(&World, &KeyPair, &CertifiedIssuer<'static, KeyPair>) -> String;
        let bad: [(&str, Make); 2] = [
            ("another key", |w, _, _| {
                w.new_cert(&KeyPair::generate().unwrap())
            }),
            ("another CA", |w, k, o| {
                let (nb, na) = (w.now - Duration::days(1), w.now + Duration::days(30));
                format!("{}{}", mint(o, k, HOST, ClientAuth, nb, na), o.pem())
            }),
        ];
        for (why, make) in bad {
            let w = World::new();
            let (_, c0, k1) = w.start();
            w.put_key(&w.p.key_next, &k1);
            let (_, csr) = prepare(&w.p, HOST).unwrap();
            w.put(&w.p.crt_next, &make(&w, &k1, &other_root));
            assert_eq!(w.settle(), None, "{why}");
            assert!(!w.exists(&w.p.crt_next), "{why}");
            assert!(w.exists(&w.p.key_next) && w.exists(&w.p.csr_next), "{why}");
            assert_eq!(std::fs::read_to_string(&w.p.crt).unwrap(), c0, "{why}");
            let (key, again) = prepare(&w.p, HOST).unwrap();
            assert_eq!(again, csr, "{why}: the same CSR bytes");
            assert_eq!(key.public_key_raw(), k1.public_key_raw(), "{why}");
        }
    }

    #[test]
    fn a_missing_pair_says_the_files_are_missing() {
        for gone in [vec![0], vec![1], vec![0, 1]] {
            let w = World::new();
            w.start();
            let files = [&w.p.key, &w.p.crt];
            gone.iter()
                .for_each(|&i| std::fs::remove_file(files[i]).unwrap());
            let why = w.settle().expect("an error text");
            assert!(
                why.contains("missing") && !why.contains("do not match"),
                "{why}"
            );
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

    #[test]
    fn one_rule_judges_a_live_answer_and_a_stored_one() {
        let w = World::new();
        let (k0, k1) = (KeyPair::generate().unwrap(), KeyPair::generate().unwrap());
        let live = leaf(w.old(&k0).as_bytes()).unwrap().not_after;
        let ca = std::fs::read_to_string(&w.p.ca).unwrap();
        let judge = |key: &KeyPair, bundle: &str| judge(live, key, bundle, HOST, &ca, w.now);
        assert!(matches!(judge(&k1, &w.new_cert(&k1)), Verdict::Usable));
        let shorter = w.cert_for(&k1, HOST, -1, 5);
        assert!(
            matches!(judge(&k1, &shorter), Verdict::Stale(_)),
            "not later"
        );
        let other = w.cert_for(&k1, "someone-else", 0, 30);
        assert!(
            matches!(judge(&k1, &other), Verdict::Stale(_)),
            "another host"
        );
        assert!(matches!(judge(&k0, &w.new_cert(&k1)), Verdict::Unfit(_)));
        assert!(matches!(judge(&k1, "not a certificate"), Verdict::Unfit(_)));
    }

    #[test]
    fn renewal_needs_the_sender_to_own_the_live_key() {
        assert_eq!(owner_problem(995, 995), None);
        assert_eq!(owner_problem(0, 0), None);
        let why = owner_problem(0, 995).expect("root over a key the service account owns");
        assert!(why.contains("995") && why.contains("uid 0"), "{why}");
        assert!(owner_problem(995, 0).is_some());
    }

    #[cfg(unix)]
    #[test]
    fn the_key_this_process_made_is_its_own() {
        let w = World::new();
        w.start();
        assert_eq!(key_owner_problem(&w.p), None);
        std::fs::remove_file(&w.p.key).unwrap();
        assert_eq!(key_owner_problem(&w.p), None, "no live key, nothing to say");
    }

    #[test]
    fn a_leftover_probe_file_does_not_turn_renewal_off() {
        let w = World::new();
        let probe =
            w.p.key_dir()
                .join(format!(".renew-probe-{}", std::process::id()));
        let tmp = probe.with_file_name(format!(".renew-probe-{}.tmp", std::process::id()));
        w.put(&tmp, "");
        assert!(writable(&w.p).is_ok(), "an unfinished probe write");
        assert!(!w.exists(&tmp));
        w.put(&probe, "");
        assert!(
            writable(&w.p).is_ok(),
            "a finished probe that was not removed"
        );
        assert!(!w.exists(&probe));
    }

    /// A certificate and a key in two directories.
    fn split() -> (tempfile::TempDir, tempfile::TempDir, Paths) {
        let (kd, cd) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let p = Paths::new(
            &cd.path().join("client.crt"),
            &kd.path().join("client.key"),
            &cd.path().join("server-ca.pem"),
        );
        (kd, cd, p)
    }

    #[test]
    fn each_next_file_sits_beside_its_live_file() {
        let (_kd, _cd, p) = split();
        for (live, next) in [(&p.key, &p.key_next), (&p.crt, &p.crt_next)] {
            assert_eq!(live.parent(), next.parent(), "{next:?}");
        }
        assert_eq!(p.key.parent(), p.csr_next.parent());
    }

    #[test]
    fn a_pair_in_two_directories_is_committed_and_leaves_no_next_file() {
        let (kd, cd, p) = split();
        let w = World::new();
        let (k0, k1) = (KeyPair::generate().unwrap(), KeyPair::generate().unwrap());
        std::fs::write(&p.ca, w.root.pem()).unwrap();
        std::fs::write(&p.key, k0.serialize_pem()).unwrap();
        std::fs::write(&p.crt, w.old(&k0)).unwrap();
        std::fs::write(&p.key_next, k1.serialize_pem()).unwrap();
        std::fs::write(&p.csr_next, "csr").unwrap();
        std::fs::write(&p.crt_next, w.new_cert(&k1)).unwrap();
        assert_eq!(settle(&p, HOST, w.now).unwrap(), None);
        let pair = (read_key(&p.key).unwrap(), read_cert(&p.crt).unwrap());
        assert!(fits(&pair.0, &pair.1));
        assert_eq!(
            pair.0.unwrap().public_key_raw(),
            k1.public_key_raw(),
            "the new key"
        );
        for d in [kd.path(), cd.path()] {
            let names: Vec<_> = std::fs::read_dir(d)
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect();
            assert!(names.iter().all(|n| !n.contains("next")), "{names:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_probe_covers_the_certificate_directory_too() {
        use std::os::unix::fs::PermissionsExt;
        let (_kd, cd, p) = split();
        assert!(writable(&p).is_ok());
        std::fs::set_permissions(cd.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let root = unsafe { libc::geteuid() } == 0;
        let failed = writable(&p).is_err();
        std::fs::set_permissions(cd.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(failed || root);
    }

    #[cfg(unix)]
    #[test]
    fn the_probe_fails_in_a_directory_this_account_cannot_write() {
        use std::os::unix::fs::PermissionsExt;
        let w = World::new();
        assert!(writable(&w.p).is_ok());
        let dir = w.p.key_dir().to_owned();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        let root = unsafe { libc::geteuid() } == 0;
        let failed = writable(&w.p).is_err();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(failed || root);
    }
}
