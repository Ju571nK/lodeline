//! `lodeline status` — renders the `lodeline-diag` snapshot. Always exits 0
//! (informational), like `lodeline scan`.

use lodeline_diag::{safe, AgentRun, FleetLink, HostStatus, Presence, Probe};
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
    let now = time::OffsetDateTime::now_utc();
    let status = rt.block_on(lodeline_diag::collect(&probe, now));
    if args.json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        print!("{}", render(&status));
    }
    Ok(())
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
    match &status.fleet {
        FleetLink::NotConfigured => {
            lines.push("[INFO] fleet: not configured (single host)".to_string());
        }
        FleetLink::Configured {
            server_url,
            config_path,
            link,
            client_cert,
        } => {
            lines.push(format!(
                "[INFO] fleet: lodeline-server {} (from {})",
                safe(server_url),
                safe_path(config_path)
            ));
            let (level, text) = link.summary();
            lines.push(format!("{} sender link: {text}", level.tag()));
            lines.extend(
                client_cert
                    .summary()
                    .map(|(level, text)| format!("{} client certificate: {text}", level.tag())),
            );
        }
        FleetLink::Unreadable {
            config_path,
            reason,
        } => lines.push(format!(
            "[WARN] fleet: cannot read {}: {}",
            safe_path(config_path),
            safe(reason)
        )),
    }
    lines.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;
    use lodeline_diag::{
        ClientCert, Component, ComponentName, LinkFailure, LinkState, SCHEMA_VERSION,
    };
    use time::macros::datetime;

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

    fn fleet_output(link: LinkState, client_cert: ClientCert) -> String {
        render(&status(
            AgentRun::Stopped,
            FleetLink::Configured {
                server_url: "https://s.example:8443".to_string(),
                config_path: PathBuf::from("/etc/lodeline/sender.yaml"),
                link,
                client_cert,
            },
        ))
    }

    #[test]
    fn each_link_state_reads_as_itself() {
        let at = datetime!(2026-11-01 12:00 UTC);
        for (link, expected) in [
            (
                LinkState::NeverReported,
                "[WARN] sender link: no status file",
            ),
            (
                LinkState::Unreadable {
                    reason: "denied".to_string(),
                },
                "[WARN] sender link: cannot read the status file: denied",
            ),
            (
                LinkState::AwaitingContact { last_report_at: at },
                "[INFO] sender link: lodeline-sender is running, no server answer yet",
            ),
            (
                LinkState::Connected {
                    last_report_at: at,
                    last_ok_at: at,
                },
                "[OK]   sender link: connected, last success 2026-11-01T12:00:00Z",
            ),
            (
                LinkState::Failing {
                    last_report_at: at,
                    since: at,
                    failure: LinkFailure::Response {
                        last_response_code: 503,
                    },
                    last_ok_at: None,
                },
                "[ERROR] sender link: failing since 2026-11-01T12:00:00Z: server answered 503, \
                 no success yet",
            ),
            (
                LinkState::Stale {
                    last_report_at: at,
                    stale_after_secs: 90,
                    last_ok_at: None,
                },
                "[WARN] sender link: stale: last report 2026-11-01T12:00:00Z",
            ),
        ] {
            let out = fleet_output(link, ClientCert::NotReported);
            assert!(out.contains(expected), "{out}");
            assert!(!out.contains("client certificate"), "{out}");
        }
    }

    #[test]
    fn expired_and_expiring_soon_certificates_read_differently() {
        let expires_at = datetime!(2026-11-01 12:00 UTC);
        for (cert, expected) in [
            (
                ClientCert::Valid { expires_at },
                "[OK]   client certificate: expires 2026-11-01T12:00:00Z",
            ),
            (
                ClientCert::ExpiringSoon { expires_at },
                "[WARN] client certificate: expires soon, 2026-11-01T12:00:00Z",
            ),
            (
                ClientCert::Expired { expires_at },
                "[ERROR] client certificate: expired 2026-11-01T12:00:00Z",
            ),
        ] {
            let out = fleet_output(LinkState::NeverReported, cert);
            assert!(out.contains(expected), "{out}");
        }
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
                    link: LinkState::Unreadable {
                        reason: format!("r{esc}"),
                    },
                    client_cert: ClientCert::NotReported,
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
