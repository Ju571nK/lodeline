use anyhow::{Context, Result};
use clap::Parser;
use lodeline_server::allowlist;
use lodeline_server::app::{build_router_with_proxy, AppState, SharedState};
use lodeline_server::cli::{Cli, Command};
use lodeline_server::config::ServerConfig;
use lodeline_server::persist::HighWater;
use std::sync::{Arc, Mutex};

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    // rustls 0.23 needs an explicit crypto provider; we built with the `ring` feature.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();
    match cli.command {
        Command::Serve { config } => {
            let cfg = ServerConfig::load(&config)
                .with_context(|| format!("load config {}", config.display()))?;
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(run(cfg))?;
        }
        Command::EnrollToken {
            config,
            host_id,
            ttl,
        } => {
            let cfg = ServerConfig::load(&config)
                .with_context(|| format!("load config {}", config.display()))?;
            enroll_token(&cfg, &host_id, &ttl)?;
        }
        Command::Proxy { cmd } => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(lodeline_server::proxy::cli::run(cmd))?;
        }
    }
    Ok(())
}

/// #184 — `lodeline-server enroll-token`: issue one single-use, per-host token.
/// Prints the plaintext to stdout ONCE; only the hash is persisted.
fn enroll_token(cfg: &ServerConfig, host_id: &str, ttl: &str) -> Result<()> {
    use lodeline_server::enroll::tokens::TokenStore;

    let tokens_path = cfg
        .enroll_tokens_path
        .as_ref()
        .context("enroll_tokens_path not set in config — enrollment is not configured")?;
    // The agent stores only a canonical host_id, so a token for another spelling
    // could never be redeemed by it.
    anyhow::ensure!(
        lodeline_core::host_meta::is_canonical_v4(host_id),
        "host_id must be a lowercase, hyphenated version 4 UUID, the form the agent accepts"
    );
    #[cfg(unix)]
    refuse_root_in_foreign_dir(tokens_path)?;
    let ttl = parse_ttl(ttl).with_context(|| format!("invalid --ttl {ttl:?}"))?;
    let now = time::OffsetDateTime::now_utc();
    let expires_at = now + ttl;
    let plaintext = TokenStore::issue(tokens_path, host_id, expires_at, now)
        .map_err(|e| anyhow::anyhow!("issue token: {e}"))?;
    // The plaintext is shown exactly once; the store holds only its hash.
    println!("{plaintext}");
    eprintln!(
        "enrollment token issued for host_id={host_id}, expires_at={} (store: {})",
        expires_at
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
        tokens_path.display()
    );
    eprintln!("note: this token is shown only once; only its blake3 hash is stored.");
    Ok(())
}

/// As root, a token file made in a directory another account owns is one that
/// account's server cannot write, and every enrollment then answers 500. Nothing is
/// written or re-owned; the operator runs the command as the directory's owner.
#[cfg(unix)]
fn refuse_root_in_foreign_dir(tokens_path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let dir = match tokens_path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => std::path::Path::new("."),
    };
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    let owner = std::fs::metadata(dir).map(|m| m.uid()).ok();
    match owner {
        Some(uid) if foreign_owner(euid, uid) => anyhow::bail!(
            "{} is owned by uid {uid}, not root. A token file made by root there is one the \
             server cannot write. Run this command as that account, for example \
             `sudo -u lodeline lodeline-server enroll-token ...`",
            dir.display()
        ),
        _ => Ok(()),
    }
}

#[cfg(unix)]
fn foreign_owner(euid: u32, dir_uid: u32) -> bool {
    euid == 0 && dir_uid != 0
}

/// Parse a simple TTL like `1h`, `30m`, `45s`, `2d`. No unit ⇒ error.
fn parse_ttl(s: &str) -> Result<time::Duration> {
    let s = s.trim();
    let (num, unit) = s.split_at(
        s.find(|c: char| !c.is_ascii_digit())
            .context("ttl must be <number><unit>, e.g. 1h")?,
    );
    let n: i64 = num.parse().context("ttl number")?;
    anyhow::ensure!(n > 0, "ttl must be positive");
    let d = match unit {
        "s" => time::Duration::seconds(n),
        "m" => time::Duration::minutes(n),
        "h" => time::Duration::hours(n),
        "d" => time::Duration::days(n),
        other => anyhow::bail!("unknown ttl unit {other:?}; use s/m/h/d"),
    };
    Ok(d)
}

fn build_state(cfg: &ServerConfig) -> Result<SharedState> {
    use lodeline_server::auth::ReadToken;
    use lodeline_server::fleet_index::FleetIndex;

    let allowlist =
        allowlist::load(cfg.host_allowlist_path.as_deref()).context("load host allowlist")?;
    let high_water = HighWater::load(&cfg.high_water_path()).context("load high-water map")?;

    let read_token = ReadToken::from_env();
    if read_token.is_enabled() {
        tracing::info!("read API enabled (LODELINE_SERVER_READ_TOKEN set)");
    } else {
        tracing::warn!("LODELINE_SERVER_READ_TOKEN unset — read API disabled (404)");
    }

    // Fleet index starts empty; populated asynchronously in run() so the
    // listener can open immediately and boot_gate can serve 503 until ready (#19).
    let fleet_index = FleetIndex::new();

    let active_window_days = cfg.active_window_days();

    let audit_dir = cfg.high_water_path();
    let audit_dir = audit_dir
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let audit_key = lodeline_server::audit_key::AuditKey::load_or_create(audit_dir);
    match &audit_key {
        Some(k) => tracing::info!(pubkey_id = %k.pubkey_id, "audit signing key ready"),
        None => tracing::warn!("audit signing key unavailable; audit signing disabled"),
    }
    // Earlier releases appended a signed chain here; it is no longer written,
    // but an existing chain's head stays visible at /v1/meta.audit_head.
    let audit_head = lodeline_server::audit_chain::read_head(
        &lodeline_server::audit_chain::chain_path(audit_dir),
    );
    if let Some(h) = &audit_head {
        tracing::info!(seq = h.seq, hash = %h.hash, "existing audit chain head loaded (read-only)");
        if audit_key.as_ref().map(|k| &k.pubkey_id) != Some(&h.pubkey_id) {
            tracing::warn!(
                head_pubkey_id = %h.pubkey_id,
                "audit chain head was signed by a key this server does not hold; \
                 /v1/meta.audit_head omits `pubkey` (verify with the key named by pubkey_id)"
            );
        }
    }

    // #184 — enrollment state. Off unless cert+key+tokens AND host_allowlist are
    // all configured AND boot validation passes (see EnrollState::load).
    let enroll_audit_path = audit_dir.join("enrollment-audit.jsonl");
    let enroll = lodeline_server::enroll::EnrollState::load(
        cfg.enroll_ca_cert_path.as_deref(),
        cfg.enroll_ca_key_path.as_deref(),
        cfg.enroll_tokens_path.as_deref(),
        cfg.host_allowlist_path.as_deref(),
        cfg.mtls_enabled(),
        cfg.enroll_cert_days,
        enroll_audit_path,
        cfg.enroll_issuer_fingerprints.clone(),
    );
    if enroll.is_some() {
        tracing::info!("enrollment endpoint enabled (POST /v1/enroll)");
    }

    Ok(Arc::new(AppState {
        events_out_dir: cfg.events_out_dir.clone(),
        policy_bundle_path: cfg.policy_bundle_path.clone(),
        rule_packs_bundle_path: cfg.rule_packs_bundle_path.clone(),
        artifacts_dir: cfg.artifacts_dir.clone(),
        high_water_path: cfg.high_water_path(),
        allowlist: parking_lot::RwLock::new(allowlist),
        high_water: Mutex::new(high_water),
        fleet_index,
        read_token,
        active_window_days,
        audit_key,
        audit_head: Mutex::new(audit_head),
        allowlist_path: cfg.host_allowlist_path.clone(),
        enroll,
        // #194.2 — ServerConfig::load refused to start if this is set
        // without mTLS, so `true` here implies the mTLS listener (and thus
        // PeerIdentity injection) is active.
        events_require_cert_host_match: cfg.events_require_cert_host_match,
    }))
}

async fn run(cfg: ServerConfig) -> Result<()> {
    let state = build_state(&cfg)?;
    // #553: a port opened for enrollment must not answer 404.
    if cfg.enroll_listener.is_some() && state.enroll.is_none() {
        anyhow::bail!("enroll_listener is set but enrollment is off; see the enroll warning above");
    }
    // T-11: refuses to start on a bad proxy CA/registry; None means proxy off.
    let proxy = lodeline_server::proxy::ProxyContext::load(&cfg)?.map(Arc::new);

    // Boot rebuild runs off-thread so the listener opens immediately; boot_gate
    // serves 503 + Retry-After until this flips boot_complete to true (#19).
    let boot_complete = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        use lodeline_server::boot_rebuild::rebuild_from_jsonl;
        use std::sync::atomic::Ordering;
        let fleet_index = state.fleet_index.clone();
        let events_out_dir = cfg.events_out_dir.clone();
        let boot_complete = boot_complete.clone();
        tokio::spawn(async move {
            tracing::info!("boot rebuild: scanning JSONL (async)");
            let t0 = std::time::Instant::now();
            match tokio::task::spawn_blocking(move || rebuild_from_jsonl(&events_out_dir)).await {
                Ok(Ok(built)) => {
                    let n = built.len();
                    fleet_index.replace(built);
                    tracing::info!(hosts = n, elapsed_ms = ?t0.elapsed().as_millis(), "boot rebuild complete");
                }
                Ok(Err(e)) => {
                    tracing::error!(error = ?e, "boot rebuild failed; serving empty index")
                }
                Err(e) => {
                    tracing::error!(error = ?e, "boot rebuild task panicked; serving empty index")
                }
            }
            // Unconditionally flip ready on every completion path (success/error/panic-join)
            // so a failed rebuild serves an empty index rather than 503-ing forever. (The
            // only way this is skipped is if the spawned task itself panics before here —
            // not reachable today: replace() is infallible and the join is matched above.)
            boot_complete.store(true, Ordering::Relaxed);
        });
    }

    // SIGHUP re-reads the management verifier file (fail closed on error).
    #[cfg(unix)]
    if let Some(ctx) = proxy.clone().filter(|c| c.mgmt.is_some()) {
        lodeline_server::proxy::spawn_sighup_reload(ctx)?;
    }

    // T-11 S4: periodic ledger retention sweep (first run at once).
    if let Some(ctx) = proxy.clone() {
        let period = std::time::Duration::from_secs(u64::from(ctx.sweep_interval_secs));
        lodeline_server::proxy::spawn_ledger_sweep(ctx, period);
    }

    let app =
        build_router_with_proxy(state.clone(), proxy).layer(axum::middleware::from_fn_with_state(
            boot_complete.clone(),
            lodeline_server::app::boot_gate,
        ));

    if cfg.mtls_enabled() {
        let tls = build_mtls(&cfg)?;
        let bind = |addr| std::net::TcpListener::bind(addr).with_context(|| format!("bind {addr}"));
        let main_sock = bind(cfg.bind)?;
        // #553: bind both sockets before serving either.
        let enroll = match &cfg.enroll_listener {
            Some(l) => Some((
                bind(l.bind)?,
                lodeline_server::enroll::listener::tls_config(
                    cfg.tls_cert_path.as_ref().unwrap(),
                    cfg.tls_key_path.as_ref().unwrap(),
                )?,
            )),
            None => None,
        };
        tracing::info!(
            bind = %cfg.bind,
            enroll_bind = cfg.enroll_listener.as_ref().map(|l| tracing::field::display(l.bind)),
            "starting lodeline-server (mTLS)"
        );
        // #194 — PeerCertAcceptor wraps axum-server's rustls acceptor (same
        // handshake + timeout) and exposes the verified client cert to
        // handlers as an `Extension<Arc<PeerIdentity>>` on every request.
        let main = axum_server::from_tcp(main_sock)
            .acceptor(lodeline_server::tls_accept::PeerCertAcceptor::new(tls))
            .serve(app.into_make_service());
        let Some((sock, tls)) = enroll else {
            main.await.context("axum_server serve (mTLS)")?;
            return Ok(());
        };
        let enroll = lodeline_server::enroll::listener::serve(sock, tls, state);
        // Either listener stopping takes the process down (systemd restarts it).
        tokio::select! {
            r = main => {
                r.context("axum_server serve (mTLS)")?;
                anyhow::bail!("main listener stopped");
            }
            r = enroll => {
                r?;
                anyhow::bail!("enrollment listener stopped");
            }
        }
    } else {
        tracing::warn!(bind = %cfg.bind, "starting lodeline-server (PLAIN HTTP — no mTLS)");
        let listener = tokio::net::TcpListener::bind(cfg.bind)
            .await
            .with_context(|| format!("bind {}", cfg.bind))?;
        axum::serve(listener, app).await.context("axum serve")?;
    }
    Ok(())
}

fn build_mtls(cfg: &ServerConfig) -> Result<axum_server::tls_rustls::RustlsConfig> {
    use lodeline_server::tls_accept::{load_certs, load_key};

    let server_certs = load_certs(cfg.tls_cert_path.as_ref().unwrap())?;
    let server_key = load_key(cfg.tls_key_path.as_ref().unwrap())?;
    let client_ca = load_certs(cfg.client_ca_path.as_ref().unwrap())?;

    let mut roots = rustls::RootCertStore::empty();
    for c in client_ca {
        roots.add(c).context("add client CA to root store")?;
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .context("build client cert verifier")?;
    let server_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_certs, server_key)
        .context("build rustls ServerConfig")?;
    Ok(axum_server::tls_rustls::RustlsConfig::from_config(
        Arc::new(server_config),
    ))
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::foreign_owner;
    use super::parse_ttl;
    use time::Duration;

    #[cfg(unix)]
    #[test]
    fn only_root_in_a_directory_of_another_account_is_refused() {
        assert!(foreign_owner(0, 996));
        assert!(!foreign_owner(0, 0));
        assert!(!foreign_owner(996, 996));
        assert!(!foreign_owner(1000, 0));
    }

    #[test]
    fn parse_ttl_units() {
        assert_eq!(parse_ttl("45s").unwrap(), Duration::seconds(45));
        assert_eq!(parse_ttl("30m").unwrap(), Duration::minutes(30));
        assert_eq!(parse_ttl("1h").unwrap(), Duration::hours(1));
        assert_eq!(parse_ttl("2d").unwrap(), Duration::days(2));
    }

    #[test]
    fn parse_ttl_rejects_bad_input() {
        assert!(parse_ttl("1h30m").is_err()); // unknown unit "h30m"
        assert!(parse_ttl("h").is_err()); // no number
        assert!(parse_ttl("10").is_err()); // no unit
        assert!(parse_ttl("0h").is_err()); // non-positive
        assert!(parse_ttl("-1h").is_err()); // leading '-' is not a digit
    }
}
