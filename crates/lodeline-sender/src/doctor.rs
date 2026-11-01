//! `lodeline-sender doctor`: local checks of everything the sender needs. It makes
//! no network call, and it reads the metadata of the key file but never the key.

use crate::config::{ConfigError, SenderConfig};
use crate::transport::client_cert_expiry;
use lodeline_core::sender_status::status_path_for;
use lodeline_diag::{collect, safe, AgentRun, ClientCert, FleetLink, Level, Probe};
use std::fmt;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

#[derive(Debug)]
pub struct Check {
    pub level: Level,
    pub text: String,
}

impl Check {
    fn new(level: Level, subject: &str, text: impl fmt::Display) -> Self {
        Self {
            level,
            text: safe(&format!("{subject}: {text}")),
        }
    }

    pub fn is_failure(&self) -> bool {
        self.level == Level::Error
    }
}

impl fmt::Display for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.level.tag(), self.text)
    }
}

pub async fn run(config_path: &Path, now: OffsetDateTime) -> Vec<Check> {
    let config = match SenderConfig::load(config_path) {
        Ok(config) => config,
        Err(e) => return vec![Check::new(Level::Error, "config", config_error(&e))],
    };
    let mut checks = vec![
        Check::new(Level::Ok, "config", config_path.display()),
        server_url(&config.server_base_url),
    ];
    checks.extend(identity(&config, now));
    if let Some(ca) = &config.server_ca_path {
        checks.push(public_file("server CA", ca));
    }
    checks.push(events_dir(&config.events_dir));
    checks.extend(running_state(config_path, &config, now).await);
    checks
}

/// The YAML error can quote the file, so only its position is printed.
fn config_error(e: &ConfigError) -> String {
    match e {
        ConfigError::Read { .. } => e.to_string(),
        ConfigError::Parse { path, source } => match source.location() {
            Some(at) => format!(
                "{}: invalid at line {} column {}",
                path.display(),
                at.line(),
                at.column()
            ),
            None => format!("{}: invalid", path.display()),
        },
    }
}

/// Prints the origin only: a full URL can hold a credential.
fn server_url(raw: &str) -> Check {
    const SUBJECT: &str = "server_base_url";
    let Ok(url) = reqwest::Url::parse(raw) else {
        return Check::new(Level::Error, SUBJECT, "not a URL");
    };
    let origin = url.origin().ascii_serialization();
    match url.scheme() {
        "https" => Check::new(Level::Ok, SUBJECT, origin),
        "http" => Check::new(Level::Warn, SUBJECT, format!("{origin} is plain HTTP")),
        _ => Check::new(Level::Error, SUBJECT, "scheme is not https or http"),
    }
}

fn identity(config: &SenderConfig, now: OffsetDateTime) -> Vec<Check> {
    const SUBJECT: &str = "client certificate";
    const EXPIRY: &str = "client certificate expiry";
    let (cert, key) = match (&config.client_cert_path, &config.client_key_path) {
        (Some(cert), Some(key)) => (cert, key),
        (None, None) => {
            return vec![Check::new(
                Level::Warn,
                SUBJECT,
                "none configured, so no mTLS",
            )]
        }
        _ => {
            return vec![Check::new(
                Level::Error,
                SUBJECT,
                "client_cert_path and client_key_path must be set together",
            )]
        }
    };
    let mut checks = vec![public_file(SUBJECT, cert), key_file(key)];
    if checks[0].is_failure() {
        return checks;
    }
    match client_cert_expiry(cert) {
        Err(e) => checks.push(Check::new(Level::Error, EXPIRY, e)),
        Ok(expires_at) => checks.extend(
            ClientCert::at(expires_at, now)
                .summary()
                .map(|(level, text)| Check::new(level, EXPIRY, text)),
        ),
    }
    checks
}

#[cfg(unix)]
fn permission_bits(metadata: &std::fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(metadata.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
fn permission_bits(_metadata: &std::fs::Metadata) -> Option<u32> {
    None
}

/// `Ok` holds the permission bits, `None` where the platform has none.
fn regular_file(path: &Path) -> Result<Option<u32>, String> {
    match std::fs::metadata(path) {
        Err(e) => Err(format!("{}: {e}", path.display())),
        Ok(m) if !m.is_file() => Err(format!("{}: not a regular file", path.display())),
        Ok(m) => Ok(permission_bits(&m)),
    }
}

const ACL_NOT_CHECKED: &str = "file exists, Windows ACLs not checked";

fn public_file(subject: &str, path: &Path) -> Check {
    match regular_file(path) {
        Err(e) => Check::new(Level::Error, subject, e),
        Ok(None) => Check::new(
            Level::Ok,
            subject,
            format!("{} ({ACL_NOT_CHECKED})", path.display()),
        ),
        Ok(Some(mode)) if mode & 0o022 != 0 => Check::new(
            Level::Warn,
            subject,
            format!("{} is writable by others ({mode:o})", path.display()),
        ),
        Ok(Some(_)) => Check::new(Level::Ok, subject, path.display()),
    }
}

/// The group may read: the packaged sender reads `root:lodeline 0640`.
fn key_file(path: &Path) -> Check {
    const SUBJECT: &str = "client key";
    match regular_file(path) {
        Err(e) => Check::new(Level::Error, SUBJECT, e),
        Ok(None) => Check::new(
            Level::Ok,
            SUBJECT,
            format!("{} ({ACL_NOT_CHECKED})", path.display()),
        ),
        Ok(Some(mode)) if mode & 0o007 != 0 => Check::new(
            Level::Error,
            SUBJECT,
            format!("{} is open to all users ({mode:o})", path.display()),
        ),
        Ok(Some(mode)) if mode & 0o020 != 0 => Check::new(
            Level::Warn,
            SUBJECT,
            format!("{} is writable by its group ({mode:o})", path.display()),
        ),
        Ok(Some(_)) => Check::new(Level::Ok, SUBJECT, path.display()),
    }
}

fn events_dir(path: &Path) -> Check {
    const SUBJECT: &str = "events dir";
    match std::fs::read_dir(path) {
        Ok(_) => Check::new(Level::Ok, SUBJECT, path.display()),
        Err(e) => Check::new(Level::Error, SUBJECT, format!("{}: {e}", path.display())),
    }
}

/// Reuses `lodeline status`, so the two never disagree about the agent or the link.
async fn running_state(
    config_path: &Path,
    config: &SenderConfig,
    now: OffsetDateTime,
) -> Vec<Check> {
    let probe = Probe {
        search_dirs: Vec::new(),
        control_endpoints: vec![config.agent_control.clone()],
        sender_configs: vec![PathBuf::from(config_path)],
        ..Probe::detect()
    };
    let status = collect(&probe, now).await;
    let endpoint = config.agent_control.display();
    let mut checks = vec![match status.agent {
        AgentRun::Running { .. } => Check::new(
            Level::Ok,
            "agent control",
            format!("{endpoint}: agent running"),
        ),
        AgentRun::Stopped => Check::new(
            Level::Warn,
            "agent control",
            format!("{endpoint}: nothing is listening"),
        ),
        AgentRun::Unreachable { reason } => Check::new(Level::Warn, "agent control", reason),
    }];
    let status_path = status_path_for(&config.offset_path);
    let (level, text) = match status.fleet {
        FleetLink::Configured { link, .. } => link.summary(),
        FleetLink::NotConfigured | FleetLink::Unreadable { .. } => (
            Level::Warn,
            "not read: no usable server_base_url".to_string(),
        ),
    };
    checks.push(Check::new(
        level,
        "status file",
        format!("{}: {text}", status_path.display()),
    ));
    checks
}
