//! `lodeline status` — renders the `lodeline-diag` snapshot. Always exits 0
//! (informational), like `lodeline scan`.

use lodeline_diag::{AgentRun, FleetLink, HostStatus, LinkState, Presence, Probe};
use std::path::{Path, PathBuf};

pub struct StatusArgs {
    pub json: bool,
    pub sender_config: Option<PathBuf>,
    pub control_socket: Option<PathBuf>,
}

pub fn run(args: StatusArgs) -> anyhow::Result<()> {
    let mut probe = Probe::detect();
    if let Some(socket) = args.control_socket {
        probe.control_endpoints = vec![socket];
    }
    if let Some(config) = args.sender_config {
        probe.sender_configs = vec![config];
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let status = rt.block_on(lodeline_diag::collect(&probe));
    if args.json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        print!("{}", render(&status));
    }
    Ok(())
}

/// Values from config files, the environment, and the daemon can hold terminal
/// escape sequences, or characters that hide or reorder what the reader sees.
fn safe(value: &str) -> String {
    value
        .chars()
        .map(|c| if is_unsafe(c) { '\u{FFFD}' } else { c })
        .collect()
}

fn is_unsafe(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{2069}'
                | '\u{FEFF}'
        )
}

fn safe_path(path: &Path) -> String {
    safe(&path.display().to_string())
}

fn render(status: &HostStatus) -> String {
    let mut lines = vec![
        format!("Lodeline status {}", safe(&status.tool_version)),
        "─────────────────────────────────────────────".to_string(),
    ];
    for component in &status.components {
        let name = component.name.binary();
        lines.push(match &component.presence {
            Presence::Missing => format!("[INFO] {name}: not found"),
            Presence::Installed { path, version } => {
                let version = version.as_deref().map_or("version unknown".into(), safe);
                format!("[OK]   {name}: {} ({version})", safe_path(path))
            }
        });
    }
    match &status.agent {
        AgentRun::Running {
            events_emitted_total,
            signed_policy,
        } => {
            lines.push(format!(
                "[OK]   agent: running, {events_emitted_total} events emitted"
            ));
            lines.extend(signed_policy.as_ref().map(|policy| {
                let version = policy.version;
                if policy.expired {
                    format!("[WARN] signed policy: version {version} expired")
                } else {
                    format!("[OK]   signed policy: version {version}")
                }
            }));
        }
        AgentRun::Stopped => {
            lines.push("[WARN] agent: stopped (start it with `lodeline run`)".to_string());
        }
        AgentRun::Unreachable { reason } => {
            lines.push(format!("[WARN] agent: unreachable: {}", safe(reason)));
        }
    }
    lines.push(match &status.fleet {
        FleetLink::NotConfigured => "[INFO] fleet: not configured (single host)".to_string(),
        FleetLink::Configured {
            server_url,
            config_path,
            link,
        } => {
            let link = match link {
                LinkState::Unknown => "link state unknown",
            };
            format!(
                "[INFO] fleet: lodeline-server {} (from {}, {link})",
                safe(server_url),
                safe_path(config_path)
            )
        }
        FleetLink::Unreadable {
            config_path,
            reason,
        } => format!(
            "[WARN] fleet: cannot read {}: {}",
            safe_path(config_path),
            safe(reason)
        ),
    });
    lines.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;
    use lodeline_diag::{Component, ComponentName, SCHEMA_VERSION};

    fn status(agent: AgentRun, fleet: FleetLink) -> HostStatus {
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
    fn single_host_reads_as_single_host() {
        let out = render(&status(AgentRun::Stopped, FleetLink::NotConfigured));
        assert!(
            out.contains("[OK]   lodeline: /usr/bin/lodeline (1.2.3)"),
            "{out}"
        );
        assert!(out.contains("[INFO] lodeline-sender: not found"), "{out}");
        assert!(out.contains("[WARN] agent: stopped"), "{out}");
        assert!(out.contains("fleet: not configured (single host)"), "{out}");
    }

    #[test]
    fn terminal_escapes_in_untrusted_values_do_not_reach_the_terminal() {
        let esc = "\u{1b}]0;pwned\u{7}\u{9b}31m";
        for (agent, fleet) in [
            (
                AgentRun::Unreachable {
                    reason: format!("r{esc}"),
                },
                FleetLink::Configured {
                    server_url: format!("https://s{esc}"),
                    config_path: PathBuf::from(format!("/etc/{esc}")),
                    link: LinkState::Unknown,
                },
            ),
            (
                AgentRun::Stopped,
                FleetLink::Unreadable {
                    config_path: PathBuf::from(format!("/etc/{esc}")),
                    reason: format!("r{esc}"),
                },
            ),
        ] {
            let out = render(&status(agent, fleet));
            assert!(!out.chars().any(|c| c.is_control() && c != '\n'), "{out:?}");
            assert!(out.contains("pwned"), "the value stays readable: {out:?}");
        }
    }

    #[test]
    fn invisible_and_reordering_characters_do_not_reach_the_terminal() {
        let hidden = ('\u{200B}'..='\u{200F}')
            .chain('\u{2028}'..='\u{202E}')
            .chain('\u{2060}'..='\u{2069}')
            .chain(['\u{FEFF}']);
        for c in hidden {
            let out = render(&status(
                AgentRun::Unreachable {
                    reason: format!("a{c}b"),
                },
                FleetLink::NotConfigured,
            ));
            assert!(out.contains("a\u{FFFD}b"), "U+{:04X}: {out:?}", c as u32);
        }
    }
}
