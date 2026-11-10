use anyhow::{Context, Result};
use clap::Parser;
use lodeline_core::paths::default_sender_config;
use lodeline_sender::cli::{Cli, Command};
use lodeline_sender::config::SenderConfig;
use lodeline_sender::csr::host_key_and_csr;
use lodeline_sender::doctor::{self, Check};
use lodeline_sender::enroll::write::put;
use lodeline_sender::runtime::{run, RuntimeCtx};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

/// Resolve the sender's host_id. Precedence: LODELINE_HOST_ID env (override) >
/// config `host_id` > error. Empty/whitespace is treated as unset.
fn resolve_host_id(env: Option<String>, cfg: Option<&str>) -> anyhow::Result<String> {
    let pick = |s: &str| {
        let t = s.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    };
    if let Some(v) = env.as_deref().and_then(pick) {
        return Ok(v);
    }
    if let Some(v) = cfg.and_then(pick) {
        return Ok(v);
    }
    anyhow::bail!(
        "sender host_id not configured: set `host_id:` in sender.yaml (or the \
         LODELINE_HOST_ID env var). It must equal the agent's host_id (the agent's \
         state.db UUID); the server rejects events whose host_id does not match."
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();
    let config_given = cli.config.clone();
    let config_path = cli.config.unwrap_or_else(default_sender_config);
    match cli.command {
        Command::Start => {
            // NOTE: control plane only today (policy poll + apply_policy IPC).
            // Data plane (read JSONL spool → POST /v1/events → ack) lands in
            // Plan B follow-up tickets B11.x; see crates/lodeline-sender/src/runtime.rs.
            let cfg = SenderConfig::load(&config_path)?;
            let host_id = resolve_host_id(
                std::env::var("LODELINE_HOST_ID").ok(),
                cfg.host_id.as_deref(),
            )?;
            let cancel = CancellationToken::new();
            let cancel_c = cancel.clone();
            tokio::spawn(async move {
                tokio::signal::ctrl_c().await.ok();
                cancel_c.cancel();
            });
            run(RuntimeCtx {
                config: cfg,
                host_id,
                agent_version: env!("CARGO_PKG_VERSION").to_string(),
                sender_version: env!("CARGO_PKG_VERSION").to_string(),
                shutdown: cancel,
            })
            .await?;
        }
        Command::Doctor => {
            println!("Lodeline sender doctor");
            let checks = doctor::run(&config_path, OffsetDateTime::now_utc()).await;
            for check in &checks {
                println!("{check}");
            }
            if checks.iter().any(Check::is_failure) {
                std::process::exit(1);
            }
        }
        Command::DryRun { url } => {
            println!("dry-run url={url} (not yet wired)");
        }
        Command::Enroll {
            file,
            state_db,
            events_dir,
            control_socket,
            keystore,
            sender_dir,
        } => {
            let code = lodeline_sender::enroll::main(lodeline_sender::enroll::Args {
                file,
                config: config_given,
                state_db,
                events_dir,
                control_socket,
                keystore,
                sender_dir,
            })
            .await;
            std::process::exit(code);
        }
        Command::Csr {
            host_id,
            key_out,
            csr_out,
        } => {
            let (key_pem, csr_pem) = host_key_and_csr(&host_id)?;
            // Never overwrite: replacing a key would lose the host identity its cert names.
            let refuse = |p: &Path| {
                format!(
                    "cannot create {} (an existing file is never overwritten)",
                    p.display()
                )
            };
            let mut csr_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&csr_out)
                .with_context(|| refuse(&csr_out))?;
            // The key goes through the same write as `enroll`, so as root it takes its
            // directory's owner.
            if let Err(e) = put(&key_out, key_pem.as_bytes(), 0o600) {
                drop(csr_file);
                let _ = std::fs::remove_file(&csr_out);
                return Err(anyhow::anyhow!("{e}")).with_context(|| refuse(&key_out));
            }
            csr_file.write_all(csr_pem.as_bytes())?;
            csr_file.sync_all()?;
            println!(
                "wrote private key {} and CSR {} (CN={host_id})",
                key_out.display(),
                csr_out.display()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::resolve_host_id;

    #[test]
    fn env_wins_over_cfg() {
        let result = resolve_host_id(Some("env-id".into()), Some("cfg-id")).unwrap();
        assert_eq!(result, "env-id");
    }

    #[test]
    fn cfg_used_when_env_unset() {
        let result = resolve_host_id(None, Some("cfg-id")).unwrap();
        assert_eq!(result, "cfg-id");
    }

    #[test]
    fn both_unset_returns_err() {
        let result = resolve_host_id(None, None);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("host_id not configured"));
    }

    #[test]
    fn empty_env_falls_through_to_cfg() {
        let result = resolve_host_id(Some("   ".into()), Some("cfg-id")).unwrap();
        assert_eq!(result, "cfg-id");
    }

    #[test]
    fn empty_env_and_empty_cfg_returns_err() {
        let result = resolve_host_id(Some("".into()), Some("  "));
        assert!(result.is_err());
    }
}
