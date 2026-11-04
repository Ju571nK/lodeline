//! `lodeline-manager`: the fleet web console. Configuration comes from the environment (see
//! `.env.example`); the process refuses to start when a required variable is missing.

mod auth;
mod config;
mod server;
mod spa;

use std::sync::Arc;
use std::time::Duration;

use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;

const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
const READ_HEADER_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() -> std::process::ExitCode {
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

    let app = server::router(server::AppState {
        signer: Arc::new(auth::Signer::new(cfg.jwt_secret.as_bytes())),
    });
    let listener = bind(&cfg.listen_addr).await?;
    let mode = if cfg.mock_fleet {
        "mock-fleet"
    } else {
        "live-fleet"
    };
    eprintln!(
        "lodeline-manager: mode={mode} addr={} db={}",
        cfg.listen_addr, cfg.triage_db_path
    );

    let graceful = GracefulShutdown::new();
    let mut signal = std::pin::pin!(shutdown_signal());
    loop {
        let stream = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => stream,
                Err(e) => {
                    eprintln!("lodeline-manager: accept: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            () = &mut signal => break,
        };
        // HTTP/1.1 only, as Go's server on a plain listener, with Go's ReadHeaderTimeout.
        let conn = http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(READ_HEADER_TIMEOUT)
            .serve_connection(TokioIo::new(stream), TowerToHyperService::new(app.clone()));
        let conn = graceful.watch(conn);
        tokio::spawn(async move {
            let _ = conn.await;
        });
    }

    drop(listener);
    eprintln!("lodeline-manager: shutdown signal received, draining for up to {SHUTDOWN_GRACE:?}");
    if tokio::time::timeout(SHUTDOWN_GRACE, graceful.shutdown())
        .await
        .is_err()
    {
        eprintln!("lodeline-manager: shutdown error: drain timed out");
    }
    Ok(())
}

/// Go's `:port` means every interface; try dual-stack IPv6 first, then IPv4.
async fn bind(addr: &str) -> std::io::Result<TcpListener> {
    match addr.strip_prefix(':') {
        Some(port) => match TcpListener::bind(format!("[::]:{port}")).await {
            Ok(l) => Ok(l),
            Err(_) => TcpListener::bind(format!("0.0.0.0:{port}")).await,
        },
        None => TcpListener::bind(addr).await,
    }
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
