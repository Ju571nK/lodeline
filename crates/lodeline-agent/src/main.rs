//! Lodeline agent — tokio runtime + system integration.

use clap::Parser;
#[cfg(feature = "operator-cli")]
use lodeline_agent::assess_cli;
use lodeline_agent::control::{default_control_pipe_name, default_control_socket};
#[cfg(feature = "operator-cli")]
use lodeline_agent::control_client;
use lodeline_agent::runtime::{default_events_dir, default_state_db_path};
use lodeline_agent::{cli, doctor, runtime, show};

fn main() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();
    match cli.command {
        cli::Command::Run => {
            let cfg = runtime::RuntimeConfig {
                policy_path: cli.policy.clone(),
                state_db_path: cli.state_db.clone().unwrap_or_else(default_state_db_path),
                events_dir: cli.events_dir.clone().unwrap_or_else(default_events_dir),
                control_socket: cli
                    .control_socket
                    .clone()
                    .unwrap_or_else(default_control_socket),
                control_pipe_name: default_control_pipe_name(),
                poll_watcher: cli.poll,
                keystore_path: cli.keystore.clone(),
            };
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let result = rt.block_on(runtime::run(cfg));
            // A timed-out blocking worker must not make Runtime::drop wait forever.
            rt.shutdown_timeout(std::time::Duration::from_secs(1));
            let code = result?;
            std::process::exit(code);
        }
        cli::Command::Doctor {
            verify_self,
            manifest,
        } => {
            let code = if verify_self {
                doctor::verify_self(manifest)
            } else {
                doctor::run(cli.policy, cli.state_db)
            };
            std::process::exit(code);
        }
        cli::Command::Show { what } => {
            let code = show::run(
                what,
                cli.policy.clone(),
                cli.events_dir.clone(),
                cli.state_db.clone().unwrap_or_else(default_state_db_path),
            )?;
            std::process::exit(code);
        }
        cli::Command::Version => {
            println!("lodeline {}", env!("CARGO_PKG_VERSION"));
        }
        cli::Command::Scan { json } => {
            let code = lodeline_agent::scan_cli::run(lodeline_agent::scan_cli::ScanArgs {
                json,
                home_override: None,
                cwd_override: None,
            });
            std::process::exit(code);
        }
        #[cfg(feature = "operator-cli")]
        cli::Command::Reload => {
            let code = reload();
            std::process::exit(code);
        }
        #[cfg(feature = "operator-cli")]
        cli::Command::Assess {
            command,
            args,
            mcp_config,
            mcp_stdin,
            mcp_name,
            fail_on_warn,
        } => {
            let code = assess_cli::run(assess_cli::AssessArgs {
                command,
                args,
                mcp_config,
                mcp_stdin,
                mcp_name,
                fail_on_warn,
                policy_override: cli.policy.clone(),
            });
            std::process::exit(code);
        }
    }
    Ok(())
}

#[cfg(feature = "operator-cli")]
fn reload() -> i32 {
    match control_client::query(&lodeline_agent::control::Request::ReloadPolicy) {
        Ok(resp) if resp.ok => {
            println!("reload requested — check `journalctl -u lodeline` for the result");
            0
        }
        Ok(resp) => {
            eprintln!(
                "lodeline reload: daemon refused the request{}",
                resp.error.map(|e| format!(": {e}")).unwrap_or_default()
            );
            1
        }
        Err(e) => {
            eprintln!("lodeline reload: {e}");
            1
        }
    }
}
