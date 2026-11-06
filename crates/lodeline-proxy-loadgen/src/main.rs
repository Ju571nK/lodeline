use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::{Parser, Subcommand};

use lodeline_proxy_loadgen::client::Target;
use lodeline_proxy_loadgen::principals::{generate, Layout, Targets};
use lodeline_proxy_loadgen::run::{failures, run, summary, Plan, Side, SideName};
use lodeline_proxy_loadgen::schedule::{Mode, Window};
use lodeline_proxy_loadgen::server::{serve, Counters};

#[derive(Parser)]
#[command(
    name = "lodeline-proxy-loadgen",
    version,
    about = "Synthetic MCP load server and load driver for Lodeline Proxy measurements"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the synthetic upstream MCP server (loopback only).
    Serve {
        #[arg(long, default_value = "127.0.0.1:18090")]
        listen: SocketAddr,
    },
    /// Generate principal tokens, the proxy config and the driver's targets file.
    Principals {
        /// New directory for tokens/, config.json and targets.json.
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        proxy_id: String,
        /// The proxy listener the driver calls, host:port.
        #[arg(long, default_value = "127.0.0.1:8480")]
        listen: String,
        #[arg(long, default_value = "http://127.0.0.1:18090/mcp")]
        upstream_url: String,
        /// A credential ref the proxy bootstrap binds to the upstream origin.
        #[arg(long)]
        credential_ref: String,
        #[arg(long, default_value_t = 8)]
        principals: usize,
        #[arg(long, default_value_t = 4)]
        routes: usize,
    },
    /// Drive load and report latency, throughput and errors.
    Run(RunArgs),
}

#[derive(clap::Args)]
struct RunArgs {
    /// The load server's MCP URL (the direct side).
    #[arg(long)]
    direct: Option<String>,
    /// targets.json from `principals` (the proxied side).
    #[arg(long)]
    targets: Option<PathBuf>,
    /// Calls/s for an open loop. Without it the run is a closed loop.
    #[arg(long)]
    rate: Option<f64>,
    /// Most calls in flight (open loop) or the number of workers (closed loop).
    #[arg(long, default_value_t = 32)]
    concurrency: usize,
    /// Sessions on the direct side when there are no targets.
    #[arg(long)]
    lanes: Option<usize>,
    #[arg(long, default_value_t = 30.0)]
    warmup: f64,
    #[arg(long, default_value_t = 300.0)]
    duration: f64,
    #[arg(long, default_value_t = 3)]
    rounds: usize,
    #[arg(long, default_value_t = 1024)]
    request_bytes: usize,
    #[arg(long, default_value_t = 4096)]
    reply_bytes: usize,
    /// Per-call timeout in seconds.
    #[arg(long, default_value_t = 30.0)]
    timeout: f64,
    /// The load server's counters URL (default: derived from --direct).
    #[arg(long)]
    counters: Option<String>,
    /// Write the JSON report here (the summary goes to stdout).
    #[arg(long)]
    out: Option<PathBuf>,
    /// Free text stored in the report (commit, host class, limits).
    #[arg(long)]
    note: Option<String>,
    /// Exit 0 even with measured errors, for runs meant to hit a limit (429).
    /// An upstream count mismatch still fails.
    #[arg(long)]
    allow_errors: bool,
}

fn read_token(path: &Path) -> anyhow::Result<String> {
    let t = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    Ok(t.trim().to_string())
}

fn proxied_targets(path: &Path) -> anyhow::Result<Vec<Target>> {
    let t: Targets = serde_json::from_slice(
        &std::fs::read(path).with_context(|| format!("read {}", path.display()))?,
    )?;
    let base = path.parent().unwrap_or(Path::new("."));
    t.proxied
        .iter()
        .map(|l| {
            Ok(Target {
                url: l.url.clone(),
                token: Some(read_token(&base.join(&l.token_file))?),
            })
        })
        .collect()
}

async fn run_cmd(a: RunArgs) -> anyhow::Result<()> {
    let mode = match a.rate {
        Some(rate) => {
            anyhow::ensure!(rate > 0.0, "--rate must be positive");
            Mode::Open {
                rate,
                cap: a.concurrency,
            }
        }
        None => Mode::Closed {
            concurrency: a.concurrency,
        },
    };
    anyhow::ensure!(
        a.concurrency > 0 && a.rounds > 0 && a.duration > 0.0,
        "concurrency, rounds and duration must be positive"
    );
    let proxied = a.targets.as_deref().map(proxied_targets).transpose()?;
    let lanes = a.lanes.or(proxied.as_ref().map(Vec::len)).unwrap_or(1);
    let mut sides = Vec::new();
    if let Some(url) = &a.direct {
        let t = Target {
            url: url.clone(),
            token: None,
        };
        sides.push(Side {
            name: SideName::Direct,
            targets: vec![t; lanes],
        });
    }
    if let Some(p) = proxied {
        sides.push(Side {
            name: SideName::Proxied,
            targets: p,
        });
    }
    anyhow::ensure!(!sides.is_empty(), "give --direct, --targets or both");
    let counters_url = match (&a.counters, &a.direct) {
        (Some(c), _) => Some(c.clone()),
        (None, Some(d)) => {
            let mut u = reqwest::Url::parse(d).context("--direct")?;
            u.set_path("/_load/counters");
            Some(u.to_string())
        }
        (None, None) => None,
    };
    let plan = Plan {
        mode,
        window: Window {
            warmup: Duration::from_secs_f64(a.warmup),
            measure: Duration::from_secs_f64(a.duration),
        },
        rounds: a.rounds,
        request_bytes: a.request_bytes,
        reply_bytes: a.reply_bytes,
        timeout: Duration::from_secs_f64(a.timeout),
        counters_url,
        note: a.note,
    };
    let rep = run(&plan, &sides).await?;
    if let Some(out) = &a.out {
        std::fs::write(out, serde_json::to_vec_pretty(&rep)?)
            .with_context(|| format!("write {}", out.display()))?;
    }
    print!("{}", summary(&rep));
    let bad = failures(&rep, a.allow_errors);
    anyhow::ensure!(
        bad.is_empty(),
        "the run is not a clean measurement (report kept):\n{}",
        bad.join("\n")
    );
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().cmd {
        Cmd::Serve { listen } => {
            anyhow::ensure!(
                listen.ip().is_loopback(),
                "the load server binds loopback only"
            );
            let l = tokio::net::TcpListener::bind(listen)
                .await
                .with_context(|| format!("bind {listen}"))?;
            println!("listening on {}", l.local_addr()?);
            serve(l, Arc::new(Counters::default()), std::future::pending()).await?;
        }
        Cmd::Principals {
            out,
            proxy_id,
            listen,
            upstream_url,
            credential_ref,
            principals,
            routes,
        } => {
            let layout = Layout {
                proxy_id: &proxy_id,
                listen: &listen,
                upstream_url: &upstream_url,
                credential_ref: &credential_ref,
                principals,
                routes,
            };
            let t = generate(&layout, &out)?;
            println!(
                "wrote {} principals over {routes} routes to {}",
                t.proxied.len(),
                out.display()
            );
        }
        Cmd::Run(a) => run_cmd(a).await?,
    }
    Ok(())
}
