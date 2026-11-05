//! `lodeline-manager`: the fleet web console. Configuration comes from the environment (see
//! `.env.example`); the process refuses to start when a required variable is missing.

mod api;
mod auth;
mod config;
mod conn;
mod fleet;
mod server;
mod spa;
#[cfg(test)]
mod testutil;
mod triage;

use std::sync::Arc;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    if std::env::args_os().nth(1).is_some_and(|a| a == "--version") {
        println!("lodeline-manager {}", env!("CARGO_PKG_VERSION"));
        return std::process::ExitCode::SUCCESS;
    }
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("lodeline-manager: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = config::Config::load(|k| std::env::var(k).ok())?;
    let legacy = config::legacy_env_names(
        std::env::vars_os().map(|(k, _)| k.to_string_lossy().into_owned()),
    );
    if !legacy.is_empty() {
        eprintln!("lodeline-manager: WARNING: ignoring renamed SIGIL_* env vars {legacy:?}; see https://github.com/Ju571nK/lodeline/blob/main/docs/migrate-from-sigil.md");
    }

    let store = Arc::new(triage::Store::open(&cfg.triage_db_path)?);
    let signer = Arc::new(auth::Signer::new(cfg.jwt_secret.as_bytes(), cfg.jwt_ttl)?);
    let oidc = match &cfg.oidc {
        Some(c) => {
            let http = auth::oidc::http_client(&[])?;
            Some(Arc::new(auth::oidc::Oidc::discover(c, http).await?))
        }
        None => None,
    };
    let app = server::router(server::AppState {
        signer,
        auth: Arc::new(api::auth::AuthConfig {
            admin_username: cfg.admin_username.clone(),
            admin_password_bcrypt: cfg.admin_password_bcrypt.clone(),
            // A TLS terminator fronts the binary in production; only exactly "1" turns Secure off.
            cookie_secure: std::env::var("LODELINE_INSECURE_COOKIE").as_deref() != Ok("1"),
        }),
        oidc,
        fleet: fleet::from_config(&cfg)?,
        triage: store,
        trusted_proxies: cfg.trusted_proxies.clone().into(),
    });
    let listener = conn::bind(&cfg.listen_addr).await?;
    let mode = if cfg.mock_fleet {
        "mock-fleet"
    } else {
        "live-fleet"
    };
    eprintln!(
        "lodeline-manager: mode={mode} addr={} db={}",
        cfg.listen_addr, cfg.triage_db_path
    );

    conn::serve(listener, app, shutdown_signal()).await;
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}
