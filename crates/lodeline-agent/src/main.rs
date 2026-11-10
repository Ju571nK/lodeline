//! Lodeline agent — tokio runtime + system integration.

use clap::Parser;
#[cfg(feature = "operator-cli")]
use lodeline_agent::assess_cli;
use lodeline_agent::control::{default_control_pipe_name, default_control_socket};
#[cfg(feature = "operator-cli")]
use lodeline_agent::control_client;
use lodeline_agent::runtime::{default_events_dir, default_state_db_path};
use lodeline_agent::{cli, doctor, runtime, show};
use lodeline_core::host_meta::HostIdClaim;
use lodeline_core::state::HashCache;

fn main() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();
    let control_socket = cli
        .control_socket
        .clone()
        .unwrap_or_else(default_control_socket);
    match cli.command {
        cli::Command::Run => {
            let cfg = runtime::RuntimeConfig {
                policy_paths: runtime::policy_paths(cli.policy.clone()),
                state_db_path: cli.state_db.clone().unwrap_or_else(default_state_db_path),
                events_dir: cli.events_dir.clone().unwrap_or_else(default_events_dir),
                control_socket,
                control_pipe_name: default_control_pipe_name(),
                hook_pipe_name: lodeline_core::control_proto::DEFAULT_HOOK_PIPE.to_string(),
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
                doctor::run(cli.policy, cli.state_db, &control_socket)
            };
            std::process::exit(code);
        }
        cli::Command::Show { what } => {
            let code = show::run(
                what,
                cli.policy.clone(),
                cli.events_dir.clone(),
                cli.state_db.clone().unwrap_or_else(default_state_db_path),
                &control_socket,
            )?;
            std::process::exit(code);
        }
        cli::Command::InitHostId { host_id } => {
            let state_db = cli.state_db.clone().unwrap_or_else(default_state_db_path);
            std::process::exit(init_host_id(&host_id, &state_db));
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
        cli::Command::Status {
            json,
            sender_config,
        } => {
            lodeline_agent::status_cli::run(lodeline_agent::status_cli::StatusArgs {
                json,
                sender_config,
                control_socket: cli.control_socket.clone(),
            })?;
        }
        #[cfg(feature = "operator-cli")]
        cli::Command::Reload => {
            let code = reload(&control_socket);
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

fn init_host_id(host_id: &str, state_db: &std::path::Path) -> i32 {
    let db = state_db.display();
    // A relative path depends on the working directory, so `run` started elsewhere
    // opens another file. The Windows default is relative when %ProgramData% is unset.
    if !state_db.is_absolute() {
        eprintln!(
            "lodeline init-host-id: the state.db path {db} is not absolute. Pass the \
             absolute --state-db that `lodeline run` uses."
        );
        return 1;
    }
    let claim = || -> anyhow::Result<HostIdClaim> {
        if let Some(dir) = state_db.parent() {
            std::fs::create_dir_all(dir)?;
        }
        Ok(HashCache::open(state_db)?.host_meta_claim_host_id(host_id)?)
    };
    match claim() {
        Ok(HostIdClaim::Claimed) => {
            println!("host_id {host_id} stored (state.db: {db})");
            0
        }
        Ok(HostIdClaim::AlreadySet) => {
            println!("host_id {host_id} was already set; nothing written (state.db: {db})");
            0
        }
        Ok(HostIdClaim::Conflict { stored }) => {
            eprintln!(
                "lodeline init-host-id: this host already has host_id {stored}; nothing was \
                 written (state.db: {db}).\nIf this machine was enrolled before, {stored} is \
                 its identity. If its disk was copied from another host, two machines now \
                 share that host_id."
            );
            3
        }
        Err(e) => {
            eprintln!(
                "lodeline init-host-id: cannot write the host_id to {db}: {e:#}. Run this \
                 command as the account the agent runs as (root for the Linux packages)."
            );
            1
        }
    }
}

#[cfg(feature = "operator-cli")]
fn reload(control_socket: &std::path::Path) -> i32 {
    match control_client::query(
        control_socket,
        &lodeline_agent::control::Request::ReloadPolicy,
    ) {
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
