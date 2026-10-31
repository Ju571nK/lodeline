//! `lodeline-server proxy ...` operator CLI.
//!
//! It is an HTTPS CLIENT of a running server's management API (management-
//! caller cert + key, bearer from an owner-only file). It never touches the
//! registry file, so the audit-before-effect rule and registry locking stay
//! with the server. The bearer is never a command-line argument.
//! `verifier-new` is local: it prints a fresh token once and the verifier
//! file entry to add.

use super::identity::is_dns_label;
use super::mgmt::{AUDIT_PATH, REGISTER_PATH, REQUESTED_BY_HEADER};
use super::verifiers::{
    read_owner_only_file, validate_key_id, validate_name, Scope, VerifierEntry,
};
use anyhow::{bail, ensure, Context, Result};
use clap::{ArgGroup, Args, Subcommand};
use lodeline_proxy_api::verifier;
use rand_core::{OsRng, RngCore};
use std::path::{Path, PathBuf};

#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct ConnArgs {
    /// Base URL of the server, https only (e.g. https://lodeline.example:8443).
    #[arg(long)]
    pub server_url: String,
    /// Management-caller client certificate (PEM).
    #[arg(long)]
    pub cert: PathBuf,
    /// Private key of `--cert` (PEM).
    #[arg(long)]
    pub key: PathBuf,
    /// CA certificate(s) (PEM) that signed the server's certificate.
    #[arg(long)]
    pub ca: PathBuf,
    /// File holding the bearer token (owner-only, not a symlink). The token is
    /// never accepted as an argument.
    #[arg(long)]
    pub token_file: PathBuf,
    /// Optional operator name sent as an ASSERTED `requested_by` (recorded in
    /// the audit trail as asserted, never used for authorization).
    #[arg(long)]
    pub requested_by: Option<String>,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum ProxyCommand {
    /// Create a pending registry entry (identity scope).
    Register {
        #[command(flatten)]
        conn: ConnArgs,
        #[arg(long)]
        proxy_id: String,
        #[arg(long)]
        display_name: String,
    },
    /// Register the next certificate fingerprint of a proxy (identity scope).
    #[command(group(ArgGroup::new("fp").required(true).args(["fingerprint", "cert_file"])))]
    Fingerprint {
        #[command(flatten)]
        conn: ConnArgs,
        #[arg(long)]
        proxy_id: String,
        /// blake3 hex of the proxy leaf certificate DER (64 lowercase hex).
        #[arg(long)]
        fingerprint: Option<String>,
        /// Or: the proxy leaf certificate (PEM); its fingerprint is computed.
        #[arg(long)]
        cert_file: Option<PathBuf>,
    },
    /// Disable a proxy (config scope).
    Disable {
        #[command(flatten)]
        conn: ConnArgs,
        #[arg(long)]
        proxy_id: String,
    },
    /// Re-enable a disabled proxy (identity scope).
    Enable {
        #[command(flatten)]
        conn: ConnArgs,
        #[arg(long)]
        proxy_id: String,
    },
    /// Retire a proxy permanently (identity scope).
    Retire {
        #[command(flatten)]
        conn: ConnArgs,
        #[arg(long)]
        proxy_id: String,
    },
    /// Read the management audit trail (the token file holds the READ bearer).
    Audit {
        #[command(flatten)]
        conn: ConnArgs,
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long)]
        limit: Option<u32>,
    },
    /// Generate a management token and the verifier-file entry for it. The
    /// token is printed once on stdout; the entry goes to stderr.
    VerifierNew {
        #[arg(long)]
        scope: Scope,
        /// blake3 hex of the management-caller certificate this token is bound to.
        #[arg(long)]
        caller_fingerprint: String,
        #[arg(long)]
        key_id: Option<String>,
        #[arg(long)]
        name: Option<String>,
        /// RFC 3339 expiry (recommended; rotation window).
        #[arg(long)]
        not_after: Option<String>,
    },
}

/// One HTTP request, built without any I/O so it can be unit-tested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub method: &'static str,
    pub path: String,
    pub query: Vec<(&'static str, String)>,
    pub body: Option<serde_json::Value>,
}

fn check_id(id: &str) -> Result<()> {
    ensure!(
        is_dns_label(id),
        "proxy_id must be a DNS label (alnum and '-', 1..=63)"
    );
    Ok(())
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// blake3 hex of the first certificate in a PEM file.
pub fn cert_fingerprint(pem_path: &Path) -> Result<String> {
    let data = std::fs::read(pem_path).with_context(|| format!("read {}", pem_path.display()))?;
    let mut rd = std::io::BufReader::new(&data[..]);
    let cert = rustls_pemfile::certs(&mut rd)
        .next()
        .context("no certificate in PEM")?
        .context("parse certificate")?;
    Ok(blake3::hash(cert.as_ref()).to_hex().to_string())
}

impl ProxyCommand {
    pub fn conn(&self) -> Option<&ConnArgs> {
        match self {
            ProxyCommand::Register { conn, .. }
            | ProxyCommand::Fingerprint { conn, .. }
            | ProxyCommand::Disable { conn, .. }
            | ProxyCommand::Enable { conn, .. }
            | ProxyCommand::Retire { conn, .. }
            | ProxyCommand::Audit { conn, .. } => Some(conn),
            ProxyCommand::VerifierNew { .. } => None,
        }
    }

    /// The request for a client subcommand (`None` for `verifier-new`).
    pub fn plan(&self) -> Result<Option<Plan>> {
        let post = |path: String, body: Option<serde_json::Value>| Plan {
            method: "POST",
            path,
            query: Vec::new(),
            body,
        };
        Ok(Some(match self {
            ProxyCommand::Register {
                proxy_id,
                display_name,
                ..
            } => {
                check_id(proxy_id)?;
                post(
                    REGISTER_PATH.to_string(),
                    Some(serde_json::json!({"proxy_id": proxy_id, "display_name": display_name})),
                )
            }
            ProxyCommand::Fingerprint {
                proxy_id,
                fingerprint,
                cert_file,
                ..
            } => {
                check_id(proxy_id)?;
                let fp = match (fingerprint, cert_file) {
                    (Some(f), None) => f.clone(),
                    (None, Some(c)) => cert_fingerprint(c)?,
                    _ => bail!("give exactly one of --fingerprint and --cert-file"),
                };
                ensure!(is_hex64(&fp), "fingerprint must be 64 lowercase hex");
                post(
                    format!("/v1/proxies/{proxy_id}/fingerprints"),
                    Some(serde_json::json!({"fingerprint": fp})),
                )
            }
            ProxyCommand::Disable { proxy_id, .. } => {
                check_id(proxy_id)?;
                post(format!("/v1/proxies/{proxy_id}/disable"), None)
            }
            ProxyCommand::Enable { proxy_id, .. } => {
                check_id(proxy_id)?;
                post(format!("/v1/proxies/{proxy_id}/enable"), None)
            }
            ProxyCommand::Retire { proxy_id, .. } => {
                check_id(proxy_id)?;
                post(format!("/v1/proxies/{proxy_id}/retire"), None)
            }
            ProxyCommand::Audit { cursor, limit, .. } => {
                let mut query = Vec::new();
                if let Some(c) = cursor {
                    query.push(("cursor", c.clone()));
                }
                if let Some(l) = limit {
                    query.push(("limit", l.to_string()));
                }
                Plan {
                    method: "GET",
                    path: AUDIT_PATH.to_string(),
                    query,
                    body: None,
                }
            }
            ProxyCommand::VerifierNew { .. } => return Ok(None),
        }))
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Generate a token and its verifier-file entry. Returns `(token, entry)`.
pub fn new_verifier(
    scope: Scope,
    caller_fingerprint: &str,
    key_id: Option<&str>,
    name: Option<&str>,
    not_after: Option<&str>,
) -> Result<(String, VerifierEntry)> {
    ensure!(
        is_hex64(caller_fingerprint),
        "caller fingerprint must be 64 lowercase hex (blake3 of the cert DER)"
    );
    if let Some(t) = not_after {
        time::OffsetDateTime::parse(t, &time::format_description::well_known::Rfc3339)
            .context("--not-after must be RFC 3339")?;
    }
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    let token = hex(&raw);
    let mut id_raw = [0u8; 4];
    OsRng.fill_bytes(&mut id_raw);
    let key_id = key_id.map_or_else(
        || format!("mgmt-{}-{}", scope.as_str(), hex(&id_raw)),
        str::to_string,
    );
    validate_key_id(&key_id)?;
    if let Some(n) = name {
        validate_name(n)?;
    }
    let entry = VerifierEntry {
        name: name.map_or_else(|| key_id.clone(), str::to_string),
        key_id,
        verifier: verifier::verifier_for(&token),
        scope,
        caller_cert_fingerprint: caller_fingerprint.to_string(),
        not_after: not_after.map(str::to_string),
    };
    Ok((token, entry))
}

fn read_token(path: &Path) -> Result<String> {
    let (bytes, _) = read_owner_only_file(path, 4096)?;
    let t = String::from_utf8(bytes).context("token file is not UTF-8")?;
    let t = t.trim().to_string();
    ensure!(
        !t.is_empty() && t.bytes().all(|b| b.is_ascii_graphic()),
        "token file must hold one printable token"
    );
    Ok(t)
}

fn build_client(c: &ConnArgs) -> Result<reqwest::Client> {
    let ca = std::fs::read(&c.ca).with_context(|| format!("read {}", c.ca.display()))?;
    // The private key goes through the same owner-only check as the token.
    let (mut id, _) = read_owner_only_file(&c.key, 64 * 1024)
        .with_context(|| format!("--key {}", c.key.display()))?;
    id.push(b'\n');
    id.extend(std::fs::read(&c.cert).with_context(|| format!("read {}", c.cert.display()))?);
    let mut b = reqwest::Client::builder()
        .use_rustls_tls()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .tls_built_in_root_certs(false)
        .identity(reqwest::Identity::from_pem(&id).context("client cert/key")?)
        .timeout(std::time::Duration::from_secs(30));
    for cert in reqwest::Certificate::from_pem_bundle(&ca).context("--ca")? {
        b = b.add_root_certificate(cert);
    }
    Ok(b.build()?)
}

/// Run a subcommand. Prints the server's JSON answer on stdout; a non-2xx
/// answer prints the body on stderr and returns an error (exit status 1).
pub async fn run(cmd: ProxyCommand) -> Result<()> {
    if let ProxyCommand::VerifierNew {
        scope,
        caller_fingerprint,
        key_id,
        name,
        not_after,
    } = &cmd
    {
        let (token, entry) = new_verifier(
            *scope,
            caller_fingerprint,
            key_id.as_deref(),
            name.as_deref(),
            not_after.as_deref(),
        )?;
        println!("{token}");
        eprintln!(
            "token above is shown ONCE; store it in an owner-only file (0600) on the caller host.\n\
             Add this entry to the \"entries\" array of the management verifier file \
             (proxy.management_verifiers, 0600), then reload with SIGHUP:\n{}",
            serde_json::to_string_pretty(&entry)?
        );
        return Ok(());
    }
    let conn = cmd.conn().expect("client subcommand").clone();
    let plan = cmd.plan()?.expect("client subcommand");
    ensure!(
        conn.server_url.starts_with("https://"),
        "--server-url must be https://"
    );
    let token = read_token(&conn.token_file)?;
    let client = build_client(&conn)?;
    let url = format!("{}{}", conn.server_url.trim_end_matches('/'), plan.path);
    let mut rb = match plan.method {
        "GET" => client.get(&url),
        _ => client.post(&url),
    }
    .bearer_auth(token)
    .query(&plan.query);
    if let Some(r) = &conn.requested_by {
        rb = rb.header(REQUESTED_BY_HEADER, r);
    }
    if let Some(b) = &plan.body {
        rb = rb.json(b);
    }
    let resp = rb.send().await.context("request failed")?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if status.is_success() {
        println!("{text}");
        Ok(())
    } else {
        eprintln!("{text}");
        bail!("server answered {status}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct W {
        #[command(subcommand)]
        c: ProxyCommand,
    }

    const CONN: &[&str] = &[
        "--server-url",
        "https://s:8443",
        "--cert",
        "c.pem",
        "--key",
        "k.pem",
        "--ca",
        "ca.pem",
        "--token-file",
        "t",
    ];

    fn parse(sub: &[&str]) -> Result<ProxyCommand, clap::Error> {
        let mut a = vec!["w"];
        a.extend_from_slice(sub);
        a.extend_from_slice(CONN);
        W::try_parse_from(a).map(|w| w.c)
    }

    const FP: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn plans() {
        let p = parse(&[
            "register",
            "--proxy-id",
            "px1",
            "--display-name",
            "Proxy One",
        ])
        .unwrap()
        .plan()
        .unwrap()
        .unwrap();
        assert_eq!((p.method, p.path.as_str()), ("POST", "/v1/proxies"));
        assert_eq!(
            p.body.unwrap(),
            serde_json::json!({"proxy_id":"px1","display_name":"Proxy One"})
        );
        let p = parse(&["fingerprint", "--proxy-id", "px1", "--fingerprint", FP])
            .unwrap()
            .plan()
            .unwrap()
            .unwrap();
        assert_eq!(p.path, "/v1/proxies/px1/fingerprints");
        for (verb, path) in [
            ("disable", "/v1/proxies/px1/disable"),
            ("enable", "/v1/proxies/px1/enable"),
            ("retire", "/v1/proxies/px1/retire"),
        ] {
            let p = parse(&[verb, "--proxy-id", "px1"])
                .unwrap()
                .plan()
                .unwrap()
                .unwrap();
            assert_eq!((p.method, p.path.as_str(), p.body), ("POST", path, None));
        }
        let p = parse(&["audit", "--cursor", "4", "--limit", "10"])
            .unwrap()
            .plan()
            .unwrap()
            .unwrap();
        assert_eq!(p.method, "GET");
        assert_eq!(
            p.query,
            vec![("cursor", "4".into()), ("limit", "10".into())]
        );
    }

    #[test]
    fn rejects_bad_input_and_has_no_token_argument() {
        // Path-injection shaped id and bad fingerprint are refused before any I/O.
        assert!(parse(&["disable", "--proxy-id", "../x"])
            .unwrap()
            .plan()
            .is_err());
        assert!(
            parse(&["fingerprint", "--proxy-id", "px", "--fingerprint", "XYZ"])
                .unwrap()
                .plan()
                .is_err()
        );
        // Exactly one of --fingerprint / --cert-file.
        assert!(parse(&["fingerprint", "--proxy-id", "px"]).is_err());
        assert!(parse(&[
            "fingerprint",
            "--proxy-id",
            "px",
            "--fingerprint",
            FP,
            "--cert-file",
            "c.pem"
        ])
        .is_err());
        // The bearer can only come from a file.
        assert!(parse(&["disable", "--proxy-id", "px", "--token", "secret"]).is_err());
        assert!(parse(&["disable", "--proxy-id", "px", "--bearer", "secret"]).is_err());
        // Missing required connection flag.
        assert!(W::try_parse_from(["w", "disable", "--proxy-id", "px"]).is_err());
    }

    #[test]
    fn verifier_new_matches_the_verify_rule() {
        let (token, e) = new_verifier(Scope::Identity, FP, Some("op-1"), None, None).unwrap();
        assert_eq!(token.len(), 64, "256-bit token as hex");
        assert!(verifier::verify(&token, &e.verifier));
        assert_eq!(
            (e.key_id.as_str(), e.name.as_str(), e.scope),
            ("op-1", "op-1", Scope::Identity)
        );
        let (t2, e2) =
            new_verifier(Scope::Config, FP, None, None, Some("2030-01-01T00:00:00Z")).unwrap();
        assert_ne!(token, t2);
        assert!(e2.key_id.starts_with("mgmt-config-"));
        assert!(new_verifier(Scope::Config, "short", None, None, None).is_err());
        assert!(new_verifier(Scope::Config, FP, Some("bad id"), None, None).is_err());
        assert!(new_verifier(Scope::Config, FP, Some("ok"), Some("bad\nname"), None).is_err());
        assert!(new_verifier(Scope::Config, FP, None, None, Some("tomorrow")).is_err());
        let w = parse_vn(&[
            "verifier-new",
            "--scope",
            "config",
            "--caller-fingerprint",
            FP,
        ]);
        assert!(matches!(
            w,
            ProxyCommand::VerifierNew {
                scope: Scope::Config,
                ..
            }
        ));
        assert!(W::try_parse_from([
            "w",
            "verifier-new",
            "--scope",
            "root",
            "--caller-fingerprint",
            FP
        ])
        .is_err());
    }

    fn parse_vn(a: &[&str]) -> ProxyCommand {
        let mut v = vec!["w"];
        v.extend_from_slice(a);
        W::try_parse_from(v).unwrap().c
    }
}
