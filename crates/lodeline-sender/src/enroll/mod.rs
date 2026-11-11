//! `lodeline-sender enroll <file>`: enroll this host from an enrollment file.
//!
//! State comes from the files on disk, never from a journal. Every refusal that
//! needs no server runs before the host_id claim and the request. The key is
//! durable before the token is sent, and the certificate is the first thing written
//! after the server answers, so a rerun either finishes without the network or says
//! exactly when a new token is needed.
//!
//! Exit codes: 0 enrolled or already enrolled, 1 failed, 2 bad enrollment file or
//! usage, 3 the host has another host_id, 4 a file enroll would write exists with
//! other content, 5 the token was refused or may be spent, 6 the listener could
//! not be reached or trusted.

pub mod cert;
pub mod claim;
pub mod file;
pub mod net;
pub mod write;

use crate::config::SenderConfig;
use crate::csr::{csr_for, new_key};
use claim::Claim;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;
use write::{Put, PutError};

/// The command line of `enroll`.
pub struct Args {
    pub file: PathBuf,
    pub config: Option<PathBuf>,
    pub state_db: Option<PathBuf>,
    pub events_dir: Option<PathBuf>,
    pub control_socket: Option<PathBuf>,
    pub keystore: Option<PathBuf>,
    pub sender_dir: Option<PathBuf>,
}

/// Where each file goes.
#[derive(Debug)]
pub struct Layout {
    pub config: PathBuf,
    pub ca: PathBuf,
    pub keystore: PathBuf,
    pub sender_dir: PathBuf,
    pub key: PathBuf,
    pub cert: PathBuf,
    pub events_dir: PathBuf,
    pub control_socket: PathBuf,
    /// Passed to the agent only when given; its own default applies otherwise.
    pub state_db: Option<PathBuf>,
}

/// What a run depends on, so a test can stand in for the agent and the clock of the host.
pub struct Env<'a> {
    pub root: bool,
    pub claim: &'a dyn Fn(&Layout, &str) -> Claim,
    pub pacing: net::Pacing,
    /// The ancestor walk for root stops here. `/` outside tests.
    pub top: PathBuf,
    /// Where the trust block goes: stderr outside tests.
    pub trust_out: &'a dyn Fn(&str),
}

type R<T> = Result<T, i32>;

const ANOTHER_HOST_ID: &str = "this host already has another host_id (`lodeline show host-id` \
     prints it; use `sudo` if you ran this command with `sudo`). Issue a token for \
     that id with `lodeline-server enroll-token --host-id <it>`, make a new enrollment file, and run enroll again. If this disk was cloned from another \
     host, the two now share an id.";

fn config_names_another(path: &Path) -> String {
    format!(
        "the sender config {} names another host_id (the agent's id may be the same as the \
         file's; `lodeline show host-id` prints it; use `sudo` if you ran this command with `sudo`). Issue a \
         token for the id this host should have with `lodeline-server enroll-token --host-id <it>`, make a new enrollment file, \
         and run enroll again.",
        path.display()
    )
}

fn die<T>(code: i32, msg: impl AsRef<str>) -> R<T> {
    eprintln!("lodeline-sender enroll: {}", msg.as_ref());
    Err(code)
}

fn warn(msg: impl AsRef<str>) {
    eprintln!("warning: {}", msg.as_ref());
}

#[cfg(unix)]
pub fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
pub fn is_root() -> bool {
    false
}

/// Entry point of the binary.
pub async fn main(args: Args) -> i32 {
    let claim = |l: &Layout, host_id: &str| match claim::locate_agent(is_root()) {
        Ok(agent) => claim::init_host_id(&agent, l.state_db.as_deref(), host_id),
        Err(m) => Claim::Failed(m),
    };
    let env = Env {
        root: is_root(),
        claim: &claim,
        pacing: net::Pacing::default(),
        top: PathBuf::from("/"),
        trust_out: &|t| eprint!("{t}"),
    };
    run(&args, &env).await
}

fn abs(p: &Path) -> R<PathBuf> {
    match std::path::absolute(p) {
        Ok(a) => Ok(a),
        Err(e) => die(1, format!("cannot make {} absolute: {e}", p.display())),
    }
}

/// As root, a directory enroll writes into is used through its resolved parent, so the
/// path that is checked is the path that is opened (see the rule in `write`).
fn resolved(root: bool, dir: PathBuf) -> R<PathBuf> {
    if !root {
        return Ok(dir);
    }
    match write::resolve_dir(&dir) {
        Ok(r) => Ok(r),
        Err(e) => die(1, format!("{}: {e}", dir.display())),
    }
}

fn resolved_file(root: bool, file: PathBuf) -> R<PathBuf> {
    match (file.parent(), file.file_name()) {
        (Some(dir), Some(name)) => Ok(resolved(root, dir.to_path_buf())?.join(name)),
        _ => Ok(file),
    }
}

fn plan(args: &Args, root: bool) -> R<Layout> {
    let given = [
        ("--config", args.config.is_some()),
        ("--state-db", args.state_db.is_some()),
        ("--events-dir", args.events_dir.is_some()),
        ("--control-socket", args.control_socket.is_some()),
        ("--keystore", args.keystore.is_some()),
        ("--sender-dir", args.sender_dir.is_some()),
    ];
    if !root && given.iter().any(|(_, g)| !g) {
        let missing: Vec<_> = given.iter().filter(|(_, g)| !g).map(|(n, _)| *n).collect();
        return die(
            1,
            format!(
                "run as root (sudo), or pass all of --state-db, --events-dir, --control-socket, \
                 --keystore, --config and --sender-dir for a user-mode agent (missing: {})",
                missing.join(", ")
            ),
        );
    }
    let config = resolved_file(
        root,
        abs(&args
            .config
            .clone()
            .unwrap_or_else(lodeline_core::paths::default_sender_config))?,
    )?;
    let config_dir = config.parent().unwrap_or(Path::new("/")).to_path_buf();
    let pick = |a: &Option<PathBuf>, default: &str| abs(a.as_deref().unwrap_or(Path::new(default)));
    let sender_dir = resolved(root, pick(&args.sender_dir, "/var/lib/lodeline-sender")?)?;
    Ok(Layout {
        ca: config_dir.join("server-ca.pem"),
        keystore: resolved_file(
            root,
            pick(&args.keystore, "/etc/lodeline/policy-signing-pubkeys.pem")?,
        )?,
        key: sender_dir.join("client.key"),
        cert: sender_dir.join("client.crt"),
        events_dir: pick(&args.events_dir, "/var/log/lodeline")?,
        control_socket: pick(&args.control_socket, "/var/run/lodeline/control.sock")?,
        state_db: args.state_db.as_deref().map(abs).transpose()?,
        sender_dir,
        config,
    })
}

/// Whether `cur` is the config `enroll` would write, except that it does not turn
/// renewal on.
fn lacks_only_renew(cur: &[u8], new: &[u8]) -> bool {
    match (
        serde_yaml::from_slice::<SenderConfig>(cur),
        serde_yaml::from_slice::<SenderConfig>(new),
    ) {
        (Ok(cur), Ok(new)) => {
            !cur.renew_client_cert
                && cur
                    == SenderConfig {
                        renew_client_cert: false,
                        ..new
                    }
        }
        _ => false,
    }
}

fn sender_config_yaml(l: &Layout, server_origin: &str, host_id: &str) -> R<Vec<u8>> {
    let p = |p: &Path| serde_json::Value::String(p.to_string_lossy().into_owned());
    // Through serde so the sender's own defaults fill the fields enroll does not set.
    let cfg: SenderConfig = match serde_json::from_value(serde_json::json!({
        "server_base_url": server_origin,
        "client_cert_path": p(&l.cert),
        "client_key_path": p(&l.key),
        "server_ca_path": p(&l.ca),
        "events_dir": p(&l.events_dir),
        "agent_control": p(&l.control_socket),
        "offset_path": p(&l.sender_dir.join("sender-offset.json")),
        "dead_letter_dir": p(&l.sender_dir.join("dead-letter")),
        "host_id": host_id,
        "renew_client_cert": true,
    })) {
        Ok(c) => c,
        Err(e) => return die(1, format!("cannot build sender.yaml: {e}")),
    };
    match serde_yaml::to_string(&cfg) {
        Ok(y) => Ok(format!("# Written by `lodeline-sender enroll`.\n{y}").into_bytes()),
        Err(e) => die(1, format!("cannot build sender.yaml: {e}")),
    }
}

pub async fn run(args: &Args, env: &Env<'_>) -> i32 {
    if cfg!(windows) {
        eprintln!("lodeline-sender enroll: not supported on Windows yet");
        return 1;
    }
    match enroll(args, env).await {
        Ok(()) => 0,
        Err(code) => code,
    }
}

async fn enroll(args: &Args, env: &Env<'_>) -> R<()> {
    let now = OffsetDateTime::now_utc();

    // E1: the file.
    let parsed = match file::read(&args.file, now) {
        Ok(p) => p,
        Err(m) => return die(2, format!("{}: {m}", args.file.display())),
    };
    for w in &parsed.warnings {
        warn(w);
    }
    let host_id = parsed.file.host_id.as_str();

    // E2: the layout.
    let l = plan(args, env.root)?;
    let outputs: [(&Path, Vec<u8>, u32); 3] = [
        (&l.ca, parsed.file.server_ca_pem.clone().into_bytes(), 0o644),
        (&l.keystore, parsed.keystore_json.clone(), 0o644),
        (
            &l.config,
            sender_config_yaml(&l, &parsed.server_origin, host_id)?,
            0o644,
        ),
    ];

    // E4: look at what is there, writing nothing.
    if env.root {
        for dir in [
            &l.sender_dir,
            l.config.parent().unwrap_or(Path::new("/")),
            l.keystore.parent().unwrap_or(Path::new("/")),
        ] {
            match write::untrusted_ancestor(dir, &env.top, 0) {
                Ok(None) => {}
                Ok(Some(bad)) => {
                    return die(
                        1,
                        format!(
                            "{} is above {} and is not a root-owned directory closed to group and \
                             others. As root, enroll writes only below such directories",
                            bad.display(),
                            dir.display()
                        ),
                    )
                }
                Err(e) => return die(1, format!("{}: {e}", dir.display())),
            }
        }
    }
    // The config first, so a config that names another host_id (exit 3) wins over a
    // differing CA or keystore (exit 4).
    let mut old_config = false;
    for (path, bytes, _) in outputs.iter().rev() {
        match write::read_existing(path) {
            Ok(Some(cur)) if cur != *bytes => {
                // A config from before `renew_client_cert` existed differs only by that
                // line. It stays as it is, and the run ends with the line to add.
                if path == &l.config && lacks_only_renew(&cur, bytes) {
                    old_config = true;
                    continue;
                }
                // A config that names another host says what the claim would: exit 3.
                if path == &l.config
                    && serde_yaml::from_slice::<SenderConfig>(&cur)
                        .ok()
                        .and_then(|c| c.host_id)
                        .is_some_and(|h| h != host_id)
                {
                    return die(3, config_names_another(path));
                }
                return die(
                    4,
                    format!(
                    "{} exists with other content; enroll never replaces it. Compare it with {}, \
                         move it aside, and run enroll again.",
                    path.display(),
                    args.file.display()
                ),
                );
            }
            Ok(_) => {}
            Err(e) => return die(4, format!("{}: {e}", path.display())),
        }
    }
    let existing_key = match write::read_existing(&l.key) {
        Ok(None) => None,
        Ok(Some(b)) => {
            let key = std::str::from_utf8(&b)
                .ok()
                .and_then(|s| rcgen::KeyPair::from_pem(s).ok())
                .filter(|k| k.algorithm() == &rcgen::PKCS_ECDSA_P256_SHA256);
            match key {
                Some(k) => Some(k),
                None => {
                    return die(
                        4,
                        format!(
                            "{} exists but is not a P-256 key; enroll never replaces it.",
                            l.key.display()
                        ),
                    )
                }
            }
        }
        Err(e) => return die(4, format!("{}: {e}", l.key.display())),
    };
    let existing_cert = match write::read_existing(&l.cert) {
        Ok(c) => c,
        Err(e) => return die(4, format!("{}: {e}", l.cert.display())),
    };
    let mut have_cert = false;
    if let Some(bytes) = &existing_cert {
        let Some(key) = &existing_key else {
            return die(
                4,
                format!(
                    "{} exists without {}; enroll never replaces it.",
                    l.cert.display(),
                    l.key.display()
                ),
            );
        };
        let check = std::str::from_utf8(bytes)
            .map_err(|_| "it is not text".to_string())
            .and_then(|b| {
                cert::check(
                    b,
                    key.public_key_raw(),
                    host_id,
                    &parsed.file.server_ca_pem,
                    now,
                )
            });
        match check {
            Ok(w) => {
                if let Some(w) = w {
                    warn(w);
                }
                have_cert = true;
            }
            Err(why) => {
                return die(4, refused_cert(&l.cert, &l.key, &why));
            }
        }
    }

    (env.trust_out)(&show_trust(&parsed));

    // E5: the host_id, before any key or request, so a conflict costs nothing.
    match (env.claim)(&l, host_id) {
        Claim::Done => {}
        Claim::Conflict => return die(3, ANOTHER_HOST_ID),
        Claim::OldAgent => return die(1, "this lodeline has no init-host-id; upgrade the agent"),
        Claim::Failed(m) => return die(1, m),
    }

    // E6: the directories and the key, durable before the token is sent.
    let config_dir = l.config.parent().unwrap_or(Path::new("/"));
    let keystore_dir = l.keystore.parent().unwrap_or(Path::new("/"));
    for (dir, mode) in [
        (l.sender_dir.as_path(), 0o750),
        (config_dir, 0o755),
        (keystore_dir, 0o755),
    ] {
        match write::ensure_dir(dir, mode, env.root) {
            Ok(true) if env.root && dir == l.sender_dir.as_path() => warn(format!(
                "created {} as root. The key stays root-owned until systemd or \
                 `systemd-tmpfiles --create` gives that directory to the sender account",
                dir.display()
            )),
            Ok(_) => {}
            Err(e) => return die(1, format!("{}: {e}", dir.display())),
        }
    }
    // Past the ancestor check above, so as root a file may go to its directory's owner.
    let give = env.root;
    let earlier_run = existing_key.is_some();
    let key = match existing_key {
        Some(k) => k,
        None => {
            let k = match new_key() {
                Ok(k) => k,
                Err(e) => return die(1, format!("cannot make a key: {e}")),
            };
            put_or_die(&l.key, k.serialize_pem().as_bytes(), 0o600, give)?;
            k
        }
    };

    // E7 and E8: the certificate.
    let mut asked = false;
    if !have_cert {
        let csr = match csr_for(&key, host_id) {
            Ok(c) => c,
            Err(e) => return die(1, format!("cannot make the CSR: {e}")),
        };
        let req = net::Request {
            enroll_url: &parsed.enroll_origin,
            server_ca_pem: &parsed.file.server_ca_pem,
            token: &parsed.file.token,
            host_id,
            csr_pem: &csr,
            expires_at: parsed.file.expires_at.as_deref(),
            earlier_run,
        };
        asked = true;
        let issued = match net::post(&req, &env.pacing).await {
            Ok(i) => i,
            Err(f) => return die(f.code, f.msg),
        };
        let mut bundle = issued.cert_pem;
        if !bundle.ends_with('\n') {
            bundle.push('\n');
        }
        bundle.push_str(&issued.chain_pem);
        match cert::check(
            &bundle,
            key.public_key_raw(),
            host_id,
            &parsed.file.server_ca_pem,
            now,
        ) {
            Ok(w) => {
                if let Some(w) = w {
                    warn(w);
                }
            }
            Err(why) => {
                let rejected = PathBuf::from(format!("{}.rejected", l.cert.display()));
                let saved = match write::put(&rejected, bundle.as_bytes(), 0o644, give) {
                    Ok(_) => format!("Saved it as {}.", rejected.display()),
                    Err(e) => format!("Could not save it ({}: {e}).", rejected.display()),
                };
                return die(
                    5,
                    format!(
                        "the server issued a certificate this host cannot use: {why}. The token is \
                         spent. {saved} If the cause is this host's clock or the file's \
                         server_ca_pem, fix that, move the saved file to {} and run enroll again. \
                         Otherwise fix the server's enrollment CA and issue a new token.",
                        l.cert.display()
                    ),
                );
            }
        }
        // E9: the first write after the answer.
        match write::put(&l.cert, bundle.as_bytes(), 0o644, give) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("{bundle}");
                return die(
                    1,
                    format!(
                        "{}: {e}. The certificate is printed above: save it to that path and run \
                         enroll again; no new token is needed.",
                        l.cert.display()
                    ),
                );
            }
        }
    }

    // E10: the rest.
    let mut wrote = asked;
    for (path, bytes, mode) in &outputs {
        if old_config && path == &l.config {
            continue;
        }
        match write::put(path, bytes, *mode, give) {
            Ok(Put::Written) => wrote = true,
            Ok(Put::Same) => {}
            Err(e) => {
                return die(
                    if matches!(e, PutError::Conflict) {
                        4
                    } else {
                        1
                    },
                    format!(
                        "{}: {e}. Run enroll again with the same file; the certificate is saved, \
                         so no new token is needed.",
                        path.display()
                    ),
                )
            }
        }
    }

    // E11: one look at the main port, only when this run changed something.
    if wrote {
        check_main_port(&l, &parsed.server_origin).await;
    }

    // E12.
    summary(&l, &parsed, args, wrote);
    if old_config {
        warn(format!(
            "{} was written by an older enroll and does not set renew_client_cert, so this \
             sender will not renew its certificate. Add the line `renew_client_cert: true` to it \
             and restart the sender.",
            l.config.display()
        ));
    }
    Ok(())
}

/// What exit 4 says about a certificate enroll will not use. An expired one is what a
/// host the sender could not renew in time ends up with, so it gets the whole way out.
fn refused_cert(cert: &Path, key: &Path, why: &str) -> String {
    let mut m = format!(
        "{} exists but {why}; enroll never replaces it. Move it aside, get a new token for this \
         host_id, and run enroll again.",
        cert.display()
    );
    if why == "it has expired" {
        m.push_str(&format!(
            " To enroll this host again: get a new token (`lodeline-server enroll-token \
             --host-id <host_id>`), move {} aside, and {} too for a new key (otherwise the old \
             key is kept), run enroll again, and if it exits 4 naming another file, move that \
             file aside too. The running sender picks up the new pair without a restart.",
            cert.display(),
            key.display()
        ));
    }
    m
}

fn put_or_die(path: &Path, bytes: &[u8], mode: u32, give: bool) -> R<()> {
    match write::put(path, bytes, mode, give) {
        Ok(_) => Ok(()),
        Err(e) => die(
            if matches!(e, PutError::Conflict) {
                4
            } else {
                1
            },
            format!("{}: {e}", path.display()),
        ),
    }
}

fn show_trust(p: &file::Parsed) -> String {
    use std::fmt::Write;
    let mut t = String::new();
    let _ = writeln!(t, "This enrollment file makes this host trust:");
    let _ = writeln!(t, "  enrollment listener  {}", p.enroll_origin);
    let _ = writeln!(t, "  main listener        {}", p.server_origin);
    let _ = writeln!(
        t,
        "  CA certificates (the host trusts servers and issued client certificates under these):"
    );
    for c in &p.cas {
        let _ = writeln!(t, "    {}  SHA-256 {}", c.subject, c.sha256);
    }
    let _ = writeln!(
        t,
        "  policy signing keys (the agent accepts signed policy from these):"
    );
    for k in &p.keys {
        let _ = writeln!(
            t,
            "    id {}  valid {} to {}  SHA-256 {}",
            k.id, k.valid_from, k.valid_until, k.sha256
        );
    }
    let _ = writeln!(
        t,
        "Compare these with the console, or with `openssl x509 -fingerprint -sha256 -noout -in <ca>` \
         and the `lodeline-sign keygen` output, before you rely on this host."
    );
    t
}

async fn check_main_port(l: &Layout, server_origin: &str) {
    use std::time::Duration;
    // Read through `read_existing`, so root follows no link in a directory the sender owns.
    let read = |p: &Path| match write::read_existing(p) {
        Ok(Some(b)) => Ok(b),
        Ok(None) => Err(format!("{} is gone", p.display())),
        Err(e) => Err(format!("{}: {e}", p.display())),
    };
    let built = (|| -> Result<reqwest::Client, String> {
        let mut identity = read(&l.cert)?;
        identity.push(b'\n');
        identity.extend(read(&l.key)?);
        let mut b = reqwest::Client::builder()
            .use_rustls_tls()
            .tls_built_in_root_certs(false)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(15))
            .identity(reqwest::Identity::from_pem(&identity).map_err(|e| e.to_string())?);
        for r in reqwest::Certificate::from_pem_bundle(&read(&l.ca)?).map_err(|e| e.to_string())? {
            b = b.add_root_certificate(r);
        }
        b.build().map_err(|e| e.to_string())
    })();
    let client = match built {
        Ok(c) => c,
        Err(e) => return warn(format!("cannot check the main port: {e}")),
    };
    match client
        .get(format!("{server_origin}/v1/healthz"))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => eprintln!("The main port answered over mTLS."),
        Ok(r) => warn(format!(
            "the main port answered {} to a health check; the sender may be refused",
            r.status().as_u16()
        )),
        Err(e) => warn(format!(
            "the main port check failed: {}. Check that the main listener's certificate chains to \
             the CA in the file and that its client CA includes the enrollment root",
            crate::transport::failure_cause(e)
        )),
    }
}

fn describe(path: &Path) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(m) = std::fs::metadata(path) {
            return format!(
                "owner {}:{} mode {:04o}",
                m.uid(),
                m.gid(),
                m.mode() & 0o7777
            );
        }
    }
    let _ = path;
    "not found".to_string()
}

fn summary(l: &Layout, p: &file::Parsed, args: &Args, wrote: bool) {
    println!(
        "{}",
        if wrote {
            format!("Enrolled host {}.", p.file.host_id)
        } else {
            format!(
                "Host {} is already enrolled; nothing was changed and no request was made.",
                p.file.host_id
            )
        }
    );
    for (what, path) in [
        ("client key        ", &l.key),
        ("client certificate", &l.cert),
        ("server CA         ", &l.ca),
        ("policy keystore   ", &l.keystore),
        ("sender config     ", &l.config),
    ] {
        println!("  {what} {}  ({})", path.display(), describe(path));
    }
    for k in &p.keys {
        println!("  policy key {} (ed25519, base64 {})", k.id, k.b64);
    }
    println!(
        "The token in {} is spent. The file still holds the CA and the public policy key; delete it when you no longer need it.",
        args.file.display()
    );
    println!("Enroll started and enabled nothing. A running agent loads the keystore only at start, so restart it.");
    let custom = args.state_db.is_some()
        || args.events_dir.is_some()
        || args.control_socket.is_some()
        || args.keystore.is_some();
    if custom {
        let db = l
            .state_db
            .as_ref()
            .map(|d| format!(" --state-db {}", d.display()))
            .unwrap_or_default();
        println!(
            "Run the agent with: lodeline{db} --events-dir {} --control-socket {} --keystore {} run",
            l.events_dir.display(),
            l.control_socket.display(),
            l.keystore.display()
        );
        println!(
            "Then the sender: lodeline-sender --config {} start",
            l.config.display()
        );
    } else {
        println!("With the packages: sudo systemctl enable --now lodeline lodeline-sender");
    }
    println!("Lodeline measures and reports this host's AI agent posture; enrolling blocks nothing on this host.");
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn as_root_an_output_directory_is_used_through_its_canonical_parent() {
        let t = tempfile::tempdir().unwrap();
        let d = std::fs::canonicalize(t.path()).unwrap();
        let (open, closed) = (d.join("open"), d.join("closed"));
        std::fs::create_dir_all(closed.join("etc")).unwrap();
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        // A link in a directory that fails the rule, pointing at one that passes it.
        symlink(&closed, open.join("link")).unwrap();
        let through = open.join("link");
        let args = Args {
            file: PathBuf::from("unused"),
            config: Some(through.join("etc/sender.yaml")),
            state_db: Some(d.join("state.db")),
            events_dir: Some(d.join("events")),
            control_socket: Some(d.join("ctl.sock")),
            keystore: Some(through.join("etc/ks.pem")),
            sender_dir: Some(through.join("sender")),
        };
        let l = plan(&args, true).unwrap();
        for p in [
            &l.sender_dir,
            &l.key,
            &l.cert,
            &l.config,
            &l.ca,
            &l.keystore,
        ] {
            assert!(
                p.starts_with(&closed),
                "{} still goes through the link",
                p.display()
            );
        }
    }

    #[test]
    fn an_expired_certificate_gets_the_steps_and_another_refusal_does_not() {
        let (crt, key) = (Path::new("/s/client.crt"), Path::new("/s/client.key"));
        let m = refused_cert(crt, key, "it has expired");
        for part in [
            "new token",
            "move /s/client.crt aside",
            "/s/client.key too",
            "naming another file",
            "without a restart",
        ] {
            assert!(m.contains(part), "{part}: {m}");
        }
        assert!(!refused_cert(crt, key, "it is for another key").contains("another file"));
    }
}
