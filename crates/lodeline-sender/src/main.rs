use anyhow::Result;
use clap::Parser;
use lodeline_core::paths::default_sender_config;
use lodeline_sender::cli::{Cli, Command};
use lodeline_sender::config::SenderConfig;
use lodeline_sender::doctor::{self, Check};
use lodeline_sender::runtime::{run, RuntimeCtx};
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
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
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
