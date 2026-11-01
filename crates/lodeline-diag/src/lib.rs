//! Read-only health snapshot of Lodeline on this host. `lodeline status` renders
//! it as text, and the diagnostic UI will render the same data.
//!
//! Collecting changes nothing on disk, starts nothing, makes no network call, and
//! runs none of the binaries it finds. The only IPC is two read-only control
//! requests to a local daemon. Key and certificate files are never opened.

use lodeline_core::control_client::exchange;
use lodeline_core::control_proto::{Request, Response};
use lodeline_core::paths::default_sender_config;
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Bump when a change to the JSON would break a consumer. Adding a variant or a
/// field does not.
pub const SCHEMA_VERSION: u32 = 1;

const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_SENDER_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostStatus {
    pub schema_version: u32,
    pub tool_version: String,
    pub components: Vec<Component>,
    pub agent: AgentRun,
    pub fleet: FleetLink,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Component {
    pub name: ComponentName,
    pub presence: Presence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentName {
    Lodeline,
    LodelineSender,
    LodelineHook,
    LodelineMcp,
}

impl ComponentName {
    pub const ALL: [Self; 4] = [
        Self::Lodeline,
        Self::LodelineSender,
        Self::LodelineHook,
        Self::LodelineMcp,
    ];

    pub fn binary(self) -> &'static str {
        match self {
            Self::Lodeline => "lodeline",
            Self::LodelineSender => "lodeline-sender",
            Self::LodelineHook => "lodeline-hook",
            Self::LodelineMcp => "lodeline-mcp",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Presence {
    Missing,
    Installed {
        path: PathBuf,
        /// `None` unless `path` is the running binary. Found binaries are never
        /// executed, because a search directory can be user-writable.
        version: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPolicy {
    pub version: i64,
    pub expired: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AgentRun {
    Running {
        events_emitted_total: u64,
        /// `None` until the daemon applies a signed policy.
        signed_policy: Option<SignedPolicy>,
    },
    Stopped,
    /// A daemon may exist, but this process cannot tell: access was denied, it
    /// did not answer, or its peer is not trusted.
    Unreachable {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum FleetLink {
    NotConfigured,
    Configured {
        /// The `lodeline-server` scheme, host, and port. Nothing else of the URL.
        server_url: String,
        config_path: PathBuf,
        link: LinkState,
    },
    /// A sender config exists but gives no server URL, so this host is neither
    /// known single-host nor known fleet. `reason` never quotes the file.
    Unreadable {
        config_path: PathBuf,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum LinkState {
    Unknown,
}

/// Where to look. [`Probe::detect`] fills it from this machine.
#[derive(Debug, Clone)]
pub struct Probe {
    pub search_dirs: Vec<PathBuf>,
    pub self_exe: Option<PathBuf>,
    /// Control sockets, or the pipe on Windows, tried in order.
    pub control_endpoints: Vec<PathBuf>,
    /// Compared with the socket peer's uid. Unused on Windows.
    pub self_uid: u32,
    /// Sender configs, tried in order. The first one that exists decides.
    pub sender_configs: Vec<PathBuf>,
}

impl Probe {
    pub fn detect() -> Self {
        Self::from_env(
            |key| std::env::var_os(key),
            std::env::current_exe().ok(),
            effective_uid(),
        )
    }

    fn from_env(
        env: impl Fn(&str) -> Option<OsString>,
        self_exe: Option<PathBuf>,
        uid: u32,
    ) -> Self {
        let var = |key: &str| env(key).filter(|value| !value.is_empty());
        let mut search_dirs: Vec<PathBuf> = self_exe
            .as_deref()
            .and_then(Path::parent)
            .map(Path::to_path_buf)
            .into_iter()
            .collect();
        if let Some(path) = var("PATH") {
            search_dirs.extend(std::env::split_paths(&path).filter(|dir| dir.is_absolute()));
        }
        search_dirs.extend(install_dirs(&var));
        Self {
            search_dirs,
            self_exe,
            control_endpoints: control_endpoints(&var, uid),
            self_uid: uid,
            sender_configs: sender_configs(&var),
        }
    }
}

/// Install locations that may be missing from `PATH`, such as for a GUI process.
#[cfg(unix)]
fn install_dirs(var: &impl Fn(&str) -> Option<OsString>) -> Vec<PathBuf> {
    let home = var("HOME").map(PathBuf::from);
    let mut dirs: Vec<PathBuf> = home.iter().map(|h| h.join(".local/bin")).collect();
    let cargo_home = var("CARGO_HOME")
        .map(PathBuf::from)
        .or(home.map(|h| h.join(".cargo")));
    dirs.extend(cargo_home.map(|c| c.join("bin")));
    dirs.push(PathBuf::from("/usr/bin"));
    dirs.push(PathBuf::from("/usr/local/bin"));
    dirs
}

#[cfg(windows)]
fn install_dirs(var: &impl Fn(&str) -> Option<OsString>) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = var("LOCALAPPDATA")
        .map(|d| PathBuf::from(d).join(r"Programs\lodeline"))
        .into_iter()
        .collect();
    let cargo_home = var("CARGO_HOME")
        .map(PathBuf::from)
        .or(var("USERPROFILE").map(|h| PathBuf::from(h).join(".cargo")));
    dirs.extend(cargo_home.map(|c| c.join("bin")));
    dirs
}

/// A root daemon binds the system socket while this process may run as a user, so
/// resolving by this process's own uid alone would report that daemon as stopped.
#[cfg(unix)]
fn control_endpoints(var: &impl Fn(&str) -> Option<OsString>, uid: u32) -> Vec<PathBuf> {
    use lodeline_core::control_proto::resolve_control_socket as resolve;
    let text = |key: &str| var(key).and_then(|value| value.into_string().ok());
    let mut endpoints = vec![
        resolve(true, None, None, uid),
        resolve(uid == 0, text("XDG_RUNTIME_DIR"), text("TMPDIR"), uid),
    ];
    endpoints.dedup();
    endpoints
}

#[cfg(windows)]
fn control_endpoints(_var: &impl Fn(&str) -> Option<OsString>, _uid: u32) -> Vec<PathBuf> {
    vec![PathBuf::from(
        lodeline_core::control_proto::DEFAULT_CONTROL_PIPE,
    )]
}

#[cfg(unix)]
fn sender_configs(var: &impl Fn(&str) -> Option<OsString>) -> Vec<PathBuf> {
    let user_config = var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or(var("HOME").map(|h| PathBuf::from(h).join(".config")));
    std::iter::once(default_sender_config())
        .chain(user_config.map(|c| c.join("lodeline/sender.yaml")))
        .collect()
}

#[cfg(windows)]
fn sender_configs(_var: &impl Fn(&str) -> Option<OsString>) -> Vec<PathBuf> {
    vec![default_sender_config()]
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
fn effective_uid() -> u32 {
    0
}

pub async fn collect(probe: &Probe) -> HostStatus {
    HostStatus {
        schema_version: SCHEMA_VERSION,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        components: ComponentName::ALL
            .into_iter()
            .map(|name| find_component(name, probe))
            .collect(),
        agent: probe_agent(probe).await,
        fleet: read_fleet(&probe.sender_configs),
    }
}

fn find_component(name: ComponentName, probe: &Probe) -> Component {
    let file = format!("{}{}", name.binary(), std::env::consts::EXE_SUFFIX);
    let found = probe
        .search_dirs
        .iter()
        .map(|dir| dir.join(&file))
        .find(|path| path.is_file());
    let presence = match found {
        None => Presence::Missing,
        Some(path) => {
            let is_self = probe
                .self_exe
                .as_deref()
                .is_some_and(|exe| same_file(exe, &path));
            Presence::Installed {
                path,
                version: is_self.then(|| env!("CARGO_PKG_VERSION").to_string()),
            }
        }
    };
    Component { name, presence }
}

fn same_file(a: &Path, b: &Path) -> bool {
    matches!(
        (std::fs::canonicalize(a), std::fs::canonicalize(b)),
        (Ok(a), Ok(b)) if a == b
    )
}

/// `Running` at any endpoint wins, then the first `Unreachable`: a denied system
/// socket must not read as `Stopped`.
async fn probe_agent(probe: &Probe) -> AgentRun {
    let mut first_unreachable = None;
    for endpoint in &probe.control_endpoints {
        match probe_endpoint(endpoint, probe.self_uid).await {
            running @ AgentRun::Running { .. } => return running,
            AgentRun::Stopped => {}
            unreachable => {
                first_unreachable.get_or_insert(unreachable);
            }
        }
    }
    first_unreachable.unwrap_or(AgentRun::Stopped)
}

async fn probe_endpoint(endpoint: &Path, self_uid: u32) -> AgentRun {
    let unreachable = |why: String| AgentRun::Unreachable {
        reason: format!("{}: {why}", endpoint.display()),
    };
    match tokio::time::timeout(PROBE_TIMEOUT, ask_daemon(endpoint, self_uid)).await {
        Err(_) => unreachable(format!("no answer within {PROBE_TIMEOUT:?}")),
        Ok(Ok(running)) => running,
        Ok(Err(e)) if is_absent(&e) => AgentRun::Stopped,
        Ok(Err(e)) => unreachable(e.to_string()),
    }
}

/// Nothing listens here. A refused connection is the stale socket a killed daemon
/// leaves behind.
fn is_absent(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
    )
}

async fn ask_daemon(endpoint: &Path, self_uid: u32) -> io::Result<AgentRun> {
    let stats = request(endpoint, self_uid, &Request::Stats)
        .await?
        .stats
        .ok_or_else(|| io::Error::other("daemon sent no stats"))?;
    let policy = request(endpoint, self_uid, &Request::PolicyStatus)
        .await?
        .policy_status
        .ok_or_else(|| io::Error::other("daemon sent no policy status"))?;
    Ok(AgentRun::Running {
        events_emitted_total: stats.events_emitted_total,
        signed_policy: (policy.last_applied_policy_version > 0).then_some(SignedPolicy {
            version: policy.last_applied_policy_version,
            expired: policy.policy_expired_active,
        }),
    })
}

async fn request(endpoint: &Path, self_uid: u32, req: &Request) -> io::Result<Response> {
    let response = send(endpoint, self_uid, req).await?;
    if response.ok {
        return Ok(response);
    }
    let error = response.error.unwrap_or_else(|| "request refused".into());
    Err(io::Error::other(format!("daemon error: {error}")))
}

#[cfg(unix)]
async fn send(endpoint: &Path, self_uid: u32, req: &Request) -> io::Result<Response> {
    let stream = tokio::net::UnixStream::connect(endpoint).await?;
    let peer = stream.peer_cred()?.uid();
    if !lodeline_core::control_proto::peer_trusted(peer, self_uid) {
        return Err(io::Error::other(format!(
            "refusing to trust the socket: its peer runs as uid {peer}, not root or uid {self_uid}"
        )));
    }
    exchange(stream, req).await
}

#[cfg(windows)]
async fn send(endpoint: &Path, _self_uid: u32, req: &Request) -> io::Result<Response> {
    use tokio::net::windows::named_pipe::ClientOptions;
    exchange(ClientOptions::new().open(endpoint)?, req).await
}

fn read_fleet(candidates: &[PathBuf]) -> FleetLink {
    for path in candidates {
        match read_capped(path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                return FleetLink::Unreadable {
                    config_path: path.clone(),
                    reason: e.to_string(),
                }
            }
            Ok(bytes) => return parse_fleet(path, &bytes),
        }
    }
    FleetLink::NotConfigured
}

/// A FIFO would block forever and a device could be endless, so anything but a
/// regular file of bounded size is refused before it is read.
fn read_capped(path: &Path) -> io::Result<Vec<u8>> {
    if !std::fs::metadata(path)?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_SENDER_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_SENDER_CONFIG_BYTES {
        return Err(io::Error::other("larger than 1 MiB"));
    }
    Ok(bytes)
}

/// Reads only `server_base_url`. `lodeline-sender`'s own config type would link its
/// TLS stack into this crate.
#[derive(Deserialize)]
struct SenderServerUrl {
    server_base_url: String,
}

fn parse_fleet(path: &Path, bytes: &[u8]) -> FleetLink {
    let parsed = serde_yaml::from_slice::<SenderServerUrl>(bytes);
    match parsed
        .ok()
        .and_then(|config| redact_url(config.server_base_url.trim()))
    {
        Some(server_url) => FleetLink::Configured {
            server_url,
            config_path: path.to_path_buf(),
            link: LinkState::Unknown,
        },
        // The YAML error can quote the file, so it stays out of `reason`.
        None => FleetLink::Unreadable {
            config_path: path.to_path_buf(),
            reason: "no usable server_base_url".to_string(),
        },
    }
}

/// `scheme://host[:port]` or `host[:port]`. `None` when the authority fails
/// validation, which is what stops an unencoded `/` in a password: the authority
/// then ends inside the userinfo, so what is left is not a host and port.
fn redact_url(raw: &str) -> Option<String> {
    let (scheme, rest) = match raw.split_once("://") {
        Some((scheme, rest)) if is_scheme(scheme) => (Some(scheme), rest),
        _ => (None, raw),
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if !is_host_port(host_port) {
        return None;
    }
    Some(scheme.map_or(host_port.to_string(), |s| format!("{s}://{host_port}")))
}

fn is_scheme(text: &str) -> bool {
    text.starts_with(|c: char| c.is_ascii_alphabetic())
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'-'))
}

fn is_host_port(text: &str) -> bool {
    let (host, port) = match text.rsplit_once(':') {
        // The colon of a bracketed IPv6 literal with no port.
        Some((_, tail)) if tail.ends_with(']') => (text, None),
        Some((host, port)) => (host, Some(port)),
        None => (text, None),
    };
    let host_ok = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        Some(ip) => ip.parse::<std::net::Ipv6Addr>().is_ok(),
        None => {
            !host.is_empty()
                && host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        }
    };
    host_ok && port.is_none_or(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn probe_in(dir: &Path) -> Probe {
        Probe {
            search_dirs: vec![dir.join("bin")],
            self_exe: None,
            control_endpoints: vec![dir.join("control.sock")],
            self_uid: effective_uid(),
            sender_configs: vec![dir.join("sender.yaml")],
        }
    }

    fn install(dir: &Path, name: ComponentName) -> PathBuf {
        fs::create_dir_all(dir).unwrap();
        let path = dir.join(format!("{}{}", name.binary(), std::env::consts::EXE_SUFFIX));
        fs::write(&path, b"").unwrap();
        path
    }

    fn presence_of(status: &HostStatus, name: ComponentName) -> &Presence {
        &status
            .components
            .iter()
            .find(|c| c.name == name)
            .unwrap()
            .presence
    }

    fn fleet_with(yaml: &str) -> (tempfile::TempDir, FleetLink) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sender.yaml");
        fs::write(&path, yaml).unwrap();
        let fleet = read_fleet(&[path]);
        (dir, fleet)
    }

    #[tokio::test]
    async fn empty_host_is_single_host_with_stopped_agent_and_no_components() {
        let dir = tempfile::tempdir().unwrap();
        let status = collect(&probe_in(dir.path())).await;
        assert_eq!(status.schema_version, SCHEMA_VERSION);
        assert_eq!(status.fleet, FleetLink::NotConfigured);
        assert_eq!(status.agent, AgentRun::Stopped);
        for name in ComponentName::ALL {
            assert_eq!(presence_of(&status, name), &Presence::Missing);
        }
    }

    #[tokio::test]
    async fn found_component_reports_its_path_and_no_version() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        let path = install(&bin, ComponentName::LodelineHook);
        let status = collect(&probe_in(dir.path())).await;
        assert_eq!(
            presence_of(&status, ComponentName::LodelineHook),
            &Presence::Installed {
                path,
                version: None
            }
        );
        assert_eq!(
            presence_of(&status, ComponentName::Lodeline),
            &Presence::Missing
        );
    }

    #[tokio::test]
    async fn only_the_running_binary_reports_a_version() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        let probe = Probe {
            self_exe: Some(install(&bin, ComponentName::Lodeline)),
            ..probe_in(dir.path())
        };
        install(&bin, ComponentName::LodelineMcp);
        let status = collect(&probe).await;
        let version_of = |name| match presence_of(&status, name) {
            Presence::Installed { version, .. } => version.clone(),
            Presence::Missing => panic!("{name:?} should be installed"),
        };
        assert_eq!(
            version_of(ComponentName::Lodeline).as_deref(),
            Some(env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(version_of(ComponentName::LodelineMcp), None);
    }

    #[cfg(unix)]
    #[test]
    fn detect_searches_the_exe_dir_then_path_then_install_locations() {
        let env = |key: &str| {
            let value = match key {
                "HOME" => "/home/u",
                "PATH" => "/opt/x::relative",
                "TMPDIR" => "/tmp/t",
                "XDG_CONFIG_HOME" => "",
                _ => return None,
            };
            Some(OsString::from(value))
        };
        let probe = Probe::from_env(env, Some(PathBuf::from("/srv/app/lodeline")), 501);
        let dirs: Vec<&str> = probe
            .search_dirs
            .iter()
            .map(|d| d.to_str().unwrap())
            .collect();
        assert_eq!(
            dirs,
            [
                "/srv/app",
                "/opt/x",
                "/home/u/.local/bin",
                "/home/u/.cargo/bin",
                "/usr/bin",
                "/usr/local/bin"
            ]
        );
        assert_eq!(
            probe.control_endpoints,
            [
                PathBuf::from("/var/run/lodeline/control.sock"),
                PathBuf::from("/tmp/t/lodeline-501/control.sock")
            ]
        );
        assert_eq!(
            probe.sender_configs,
            [
                PathBuf::from("/etc/lodeline/sender.yaml"),
                PathBuf::from("/home/u/.config/lodeline/sender.yaml")
            ]
        );
    }

    #[test]
    fn sender_config_makes_the_host_a_fleet_host() {
        let (dir, fleet) = fleet_with("server_base_url: https://s.example:8443\n");
        assert_eq!(
            fleet,
            FleetLink::Configured {
                server_url: "https://s.example:8443".to_string(),
                config_path: dir.path().join("sender.yaml"),
                link: LinkState::Unknown,
            }
        );
    }

    #[test]
    fn first_existing_sender_config_decides() {
        let dir = tempfile::tempdir().unwrap();
        let second = dir.path().join("second.yaml");
        fs::write(&second, "server_base_url: https://second\n").unwrap();
        let fleet = read_fleet(&[dir.path().join("absent.yaml"), second.clone()]);
        assert!(matches!(
            fleet,
            FleetLink::Configured { server_url, config_path, .. }
                if server_url == "https://second" && config_path == second
        ));
    }

    #[test]
    fn server_url_keeps_only_scheme_host_and_port() {
        for (raw, expected) in [
            (
                "https://u:pw@srv.example:8443/?t=1",
                "https://srv.example:8443",
            ),
            (
                "https://u:pw@s.example:8443/base?token=t#f",
                "https://s.example:8443",
            ),
            ("https://s.example/?token=t", "https://s.example"),
            ("https://s.example#frag", "https://s.example"),
            ("https://s.example/a@b", "https://s.example"),
            ("https://s.example/tok3n/x", "https://s.example"),
            ("s.example/?token=abc&r=http://x", "s.example"),
            ("https://[::1]:8443/x", "https://[::1]:8443"),
            ("[::1]", "[::1]"),
            ("srv.example:8443", "srv.example:8443"),
            ("u:pw@s.example:8443", "s.example:8443"),
            ("https://s.example:8443", "https://s.example:8443"),
        ] {
            let (_dir, fleet) = fleet_with(&format!("server_base_url: \"{raw}\"\n"));
            let FleetLink::Configured { server_url, .. } = fleet else {
                panic!("{raw} should be configured, got {fleet:?}");
            };
            assert_eq!(server_url, expected);
        }
    }

    #[test]
    fn server_url_that_fails_validation_prints_nothing() {
        for raw in [
            "https://u:p/w@host/",
            "https://u:p?w@s.example/x",
            "https://",
            "s.example:",
            "s.example:80a",
            "https://s ex/",
            "https://[hunter2]/",
            "https://[::1",
            "1http://s.example",
        ] {
            let (_dir, fleet) = fleet_with(&format!("server_base_url: \"{raw}\"\n"));
            let FleetLink::Unreadable { reason, .. } = &fleet else {
                panic!("{raw} should be unreadable, got {fleet:?}");
            };
            assert_eq!(reason, "no usable server_base_url");
        }
    }

    #[test]
    fn broken_sender_config_is_not_single_host_and_does_not_quote_the_file() {
        for yaml in [
            "client_key_path: /secret/key.pem\n",
            "server_base_url: \"\"\n",
            "server_base_url: [hunter2]\n",
            ": : :\n",
        ] {
            let (_dir, fleet) = fleet_with(yaml);
            let FleetLink::Unreadable { reason, .. } = &fleet else {
                panic!("{yaml:?} should be unreadable, got {fleet:?}");
            };
            assert_eq!(reason, "no usable server_base_url");
        }
    }

    #[cfg(unix)]
    #[test]
    fn fifo_at_the_config_path_is_unreadable_and_does_not_block() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("sender.yaml");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || tx.send(read_fleet(&[fifo])));
        let fleet = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("reading a FIFO must not block");
        assert!(
            matches!(&fleet, FleetLink::Unreadable { reason, .. } if reason == "not a regular file"),
            "{fleet:?}"
        );
    }

    #[test]
    fn sender_config_is_read_up_to_the_size_cap() {
        let config = "server_base_url: https://s.example\n#";
        let at_cap = config.to_string() + &"x".repeat(1024 * 1024 - config.len());
        let (_dir, fleet) = fleet_with(&at_cap);
        assert!(matches!(fleet, FleetLink::Configured { .. }), "{fleet:?}");

        let (_dir, fleet) = fleet_with(&(at_cap + "x"));
        assert!(
            matches!(&fleet, FleetLink::Unreadable { reason, .. } if reason == "larger than 1 MiB"),
            "{fleet:?}"
        );
    }

    fn sample(agent: AgentRun, fleet: FleetLink) -> HostStatus {
        HostStatus {
            schema_version: SCHEMA_VERSION,
            tool_version: "1.2.3".to_string(),
            components: vec![
                Component {
                    name: ComponentName::Lodeline,
                    presence: Presence::Installed {
                        path: PathBuf::from("/usr/bin/lodeline"),
                        version: Some("1.2.3".to_string()),
                    },
                },
                Component {
                    name: ComponentName::LodelineSender,
                    presence: Presence::Missing,
                },
            ],
            agent,
            fleet,
        }
    }

    #[test]
    fn json_contract_for_a_fleet_host() {
        let status = sample(
            AgentRun::Running {
                events_emitted_total: 7,
                signed_policy: Some(SignedPolicy {
                    version: 3,
                    expired: false,
                }),
            },
            FleetLink::Configured {
                server_url: "https://s.example:8443".to_string(),
                config_path: PathBuf::from("/etc/lodeline/sender.yaml"),
                link: LinkState::Unknown,
            },
        );
        insta::assert_snapshot!(serde_json::to_string_pretty(&status).unwrap());
    }

    #[test]
    fn json_contract_for_a_single_host() {
        let status = sample(AgentRun::Stopped, FleetLink::NotConfigured);
        insta::assert_snapshot!(serde_json::to_string_pretty(&status).unwrap());
    }

    #[test]
    fn json_contract_for_unknown_states() {
        let status = sample(
            AgentRun::Unreachable {
                reason: "denied".to_string(),
            },
            FleetLink::Unreadable {
                config_path: PathBuf::from("/etc/lodeline/sender.yaml"),
                reason: "denied".to_string(),
            },
        );
        insta::assert_snapshot!(serde_json::to_string_pretty(&status).unwrap());
    }

    #[test]
    fn json_round_trips() {
        let status = sample(AgentRun::Stopped, FleetLink::NotConfigured);
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(serde_json::from_str::<HostStatus>(&json).unwrap(), status);
    }

    #[cfg(unix)]
    mod daemon {
        use super::*;
        use lodeline_core::control_proto::PolicyStatusPayload;
        use lodeline_core::stats::StatsSnapshot;
        use std::collections::BTreeMap;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::UnixListener;

        fn reply_to(req: &str, policy_version: i64, expired: bool) -> Response {
            let mut response = Response {
                ok: true,
                stats: None,
                apply_policy: None,
                policy_status: None,
                targets: None,
                risk: None,
                doctor_ai_guard: None,
                assess_verdict: None,
                error: None,
            };
            match req {
                r#"{"cmd":"stats"}"# => {
                    response.stats = Some(StatsSnapshot {
                        events_emitted_total: 7,
                        channel_stall_events_total: 0,
                        events_by_kind: BTreeMap::new(),
                        hash_p50_ms: 0,
                        hash_p99_ms: 0,
                    })
                }
                r#"{"cmd":"policy_status"}"# => {
                    response.policy_status = Some(PolicyStatusPayload {
                        last_applied_policy_version: policy_version,
                        active_envelope_valid_until: None,
                        policy_expired_active: expired,
                    })
                }
                other => panic!("status sent an unexpected request: {other}"),
            }
            response
        }

        fn spawn_daemon(listener: UnixListener, policy_version: i64, expired: bool) {
            tokio::spawn(async move {
                loop {
                    let (stream, _) = listener.accept().await.unwrap();
                    let (rd, mut wr) = stream.into_split();
                    let mut line = String::new();
                    BufReader::new(rd).read_line(&mut line).await.unwrap();
                    let reply = reply_to(line.trim(), policy_version, expired);
                    let mut bytes = serde_json::to_vec(&reply).unwrap();
                    bytes.push(b'\n');
                    wr.write_all(&bytes).await.unwrap();
                }
            });
        }

        #[tokio::test]
        async fn running_daemon_reports_its_counters_and_expired_policy() {
            let dir = tempfile::tempdir().unwrap();
            let probe = probe_in(dir.path());
            spawn_daemon(
                UnixListener::bind(&probe.control_endpoints[0]).unwrap(),
                3,
                true,
            );
            assert_eq!(
                collect(&probe).await.agent,
                AgentRun::Running {
                    events_emitted_total: 7,
                    signed_policy: Some(SignedPolicy {
                        version: 3,
                        expired: true
                    }),
                }
            );
        }

        #[tokio::test]
        async fn daemon_without_a_signed_policy_reports_none() {
            let dir = tempfile::tempdir().unwrap();
            let probe = probe_in(dir.path());
            spawn_daemon(
                UnixListener::bind(&probe.control_endpoints[0]).unwrap(),
                0,
                false,
            );
            assert!(matches!(
                collect(&probe).await.agent,
                AgentRun::Running {
                    signed_policy: None,
                    ..
                }
            ));
        }

        #[tokio::test]
        async fn user_daemon_is_found_after_an_absent_system_socket() {
            let dir = tempfile::tempdir().unwrap();
            let own = dir.path().join("own.sock");
            spawn_daemon(UnixListener::bind(&own).unwrap(), 0, false);
            let probe = Probe {
                control_endpoints: vec![dir.path().join("system.sock"), own],
                ..probe_in(dir.path())
            };
            assert!(matches!(
                collect(&probe).await.agent,
                AgentRun::Running { .. }
            ));
        }

        #[tokio::test]
        async fn stale_socket_file_is_stopped() {
            use std::os::unix::net::{UnixListener, UnixStream};
            let dir = tempfile::tempdir().unwrap();
            let probe = probe_in(dir.path());
            let socket = &probe.control_endpoints[0];
            drop(UnixListener::bind(socket).unwrap());
            assert!(socket.exists());
            // insta forks `cargo metadata`, and until its exec the child holds this
            // listener open, so the socket can accept for a moment after the drop.
            while UnixStream::connect(socket).is_ok() {
                tokio::task::yield_now().await;
            }
            assert_eq!(collect(&probe).await.agent, AgentRun::Stopped);
        }

        #[tokio::test]
        async fn silent_daemon_is_unreachable_not_stopped() {
            let dir = tempfile::tempdir().unwrap();
            let probe = probe_in(dir.path());
            let _listener = UnixListener::bind(&probe.control_endpoints[0]).unwrap();
            let AgentRun::Unreachable { reason } = collect(&probe).await.agent else {
                panic!("a socket with no answer is not a stopped agent");
            };
            assert!(reason.contains("no answer"), "{reason}");
        }

        #[tokio::test]
        async fn peer_of_another_user_is_unreachable_and_never_queried() {
            let me = effective_uid();
            if me == 0 {
                return; // root's peers are always trusted, so nothing is under test.
            }
            let dir = tempfile::tempdir().unwrap();
            let probe = Probe {
                self_uid: me + 1,
                ..probe_in(dir.path())
            };
            spawn_daemon(
                UnixListener::bind(&probe.control_endpoints[0]).unwrap(),
                0,
                false,
            );
            let AgentRun::Unreachable { reason } = collect(&probe).await.agent else {
                panic!("an untrusted peer must not read as running");
            };
            assert!(reason.contains("refusing to trust"), "{reason}");
        }

        #[tokio::test]
        async fn socket_this_user_may_not_open_is_unreachable_not_stopped() {
            use std::os::unix::fs::PermissionsExt;
            if effective_uid() == 0 {
                return; // root ignores the mode, so nothing is under test.
            }
            let dir = tempfile::tempdir().unwrap();
            let probe = probe_in(dir.path());
            let socket = &probe.control_endpoints[0];
            let _listener = UnixListener::bind(socket).unwrap();
            fs::set_permissions(socket, fs::Permissions::from_mode(0o000)).unwrap();
            assert!(matches!(
                collect(&probe).await.agent,
                AgentRun::Unreachable { .. }
            ));
        }

        #[tokio::test]
        async fn unreachable_endpoint_is_kept_when_the_next_one_is_stopped() {
            let dir = tempfile::tempdir().unwrap();
            let silent = dir.path().join("silent.sock");
            let _listener = UnixListener::bind(&silent).unwrap();
            let probe = Probe {
                control_endpoints: vec![silent, dir.path().join("absent.sock")],
                ..probe_in(dir.path())
            };
            assert!(matches!(
                collect(&probe).await.agent,
                AgentRun::Unreachable { .. }
            ));
        }
    }
}
