#![cfg(unix)]
//! The load driver through the real relay (`lifecycle::run_tuned`, real spool,
//! real `lodeline-server` control plane over mTLS) and the synthetic load server.
//! Principals are set up as an operator would: tokens and the config come from
//! `principals::generate`, and the config is PUT through the management API.
//!
//! Short runs only, to prove the driver measures the relay and counts its
//! refusals. The long run is `#[ignore]`d.

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lodeline_proxy::bootstrap::Bootstrap;
use lodeline_proxy::lifecycle::{run_tuned, RunTuning};
use lodeline_proxy::route::TableHandle;
use lodeline_proxy_loadgen::client::Target;
use lodeline_proxy_loadgen::principals::{generate, Layout};
use lodeline_proxy_loadgen::run::{run, summary, Plan, Report, Side, SideName};
use lodeline_proxy_loadgen::schedule::{Mode, Window};
use lodeline_proxy_loadgen::server::{serve, Counters};
use lodeline_server::proxy::identity::proxy_san;
use serde_json::{json, Value};

mod common;
use common::{client_ext, fingerprint, mgmt_identity, mtls_client, pki, Pki, Server, Tweak};

const PROXY: &str = "px-load";
const T_ID: &str = "tok-identity-load";
const T_CFG: &str = "tok-config-load";
const CRED: &str = "load-upstream";

struct Rig {
    _pki: Pki,
    srv: Server,
    direct: String,
    counters: String,
    proxied: Vec<Target>,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

async fn mgmt(c: &reqwest::Client, port: u16, method: &str, path: &str, bearer: &str, body: Value) {
    let r = c
        .request(
            method.parse().unwrap(),
            format!("https://127.0.0.1:{port}{path}"),
        )
        .bearer_auth(bearer)
        .json(&body)
        .send()
        .await
        .unwrap();
    let st = r.status().as_u16();
    assert!(
        (200..300).contains(&st),
        "{method} {path}: {st} {}",
        r.text().await.unwrap()
    );
}

/// Server, load server and proxy with `principals` principals over `routes` routes.
async fn rig(principals: usize, routes: usize) -> Option<Rig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let pki = pki("load")?;
    let up = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_port = up.local_addr().unwrap().port();
    tokio::spawn(serve(
        up,
        Arc::new(Counters::default()),
        std::future::pending(),
    ));
    let sock = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listen = sock.local_addr().unwrap().to_string();

    let upstream_url = format!("http://127.0.0.1:{up_port}/mcp");
    let layout = Layout {
        proxy_id: PROXY,
        listen: &listen,
        upstream_url: &upstream_url,
        credential_ref: CRED,
        principals,
        routes,
    };
    let out = pki.p("load");
    let targets = generate(&layout, &out).unwrap();
    let config: Value =
        serde_json::from_slice(&std::fs::read(out.join("config.json")).unwrap()).unwrap();

    let mgmt_cert = mgmt_identity(&pki, T_ID, T_CFG);
    let proxy_cert = pki.leaf("proxyca", "proxy", PROXY, &client_ext(&proxy_san(PROXY)));
    let tweak: Tweak = Arc::new(|_| {});
    let srv = Server::start(&pki, 0, true, &tweak).await;
    let m = mtls_client(&pki.p("hostca.crt"), &mgmt_cert.0, &mgmt_cert.1);
    mgmt(
        &m,
        srv.port,
        "POST",
        "/v1/proxies",
        T_ID,
        json!({"proxy_id": PROXY, "display_name": "load"}),
    )
    .await;
    let fp = json!({"fingerprint": fingerprint(&proxy_cert.0)});
    mgmt(
        &m,
        srv.port,
        "POST",
        &format!("/v1/proxies/{PROXY}/fingerprints"),
        T_ID,
        fp,
    )
    .await;
    let put = json!({"expected_revision": 0, "config": config});
    mgmt(
        &m,
        srv.port,
        "PUT",
        &format!("/v1/proxies/{PROXY}/config"),
        T_CFG,
        put,
    )
    .await;

    let secret = pki.p("upstream.secret");
    std::fs::write(&secret, "LOAD-UPSTREAM-SECRET\n").unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    let yaml = format!(
        "proxy_id: {PROXY}\nlisten: \"{listen}\"\ncontrol_plane_url: \"https://127.0.0.1:{}\"\n\
         state_dir: {}\nclient_cert_file: {}\nclient_key_file: {}\nca_file: {}\n\
         credentials:\n  {CRED}:\n    secret_file: {}\n    upstream_origins: [\"http://127.0.0.1:{up_port}\"]\n",
        srv.port,
        pki.p("proxy-state").display(),
        proxy_cert.0.display(),
        proxy_cert.1.display(),
        pki.p("hostca.crt").display(),
        secret.display(),
    );
    let b = Bootstrap::from_yaml(&yaml, pki.dir.path()).expect("bootstrap loads");
    let mut tune = RunTuning {
        listener: Some(sock),
        ..RunTuning::default()
    };
    tune.sync.poll = Duration::from_millis(150);
    tune.sync.retry = Duration::from_millis(150);
    let (stop, rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        run_tuned(
            &b,
            TableHandle::new(),
            async move {
                let _ = rx.await;
            },
            tune,
        )
        .await
    });

    let proxied: Vec<Target> = targets
        .proxied
        .iter()
        .map(|l| Target {
            url: l.url.clone(),
            token: Some(
                std::fs::read_to_string(out.join(&l.token_file))
                    .unwrap()
                    .trim()
                    .to_string(),
            ),
        })
        .collect();
    // Forwarding starts once the config is applied: an initialize gets a session.
    let start = Instant::now();
    let http = reqwest::Client::new();
    loop {
        let r = http
            .post(&proxied[0].url)
            .bearer_auth(proxied[0].token.as_deref().unwrap())
            .header("accept", "application/json, text/event-stream")
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "probe", "version": "1"}}}))
            .send()
            .await;
        if r.is_ok_and(|r| r.headers().contains_key("mcp-session-id")) {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "the proxy never forwarded"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Some(Rig {
        _pki: pki,
        srv,
        direct: upstream_url,
        counters: format!("http://127.0.0.1:{up_port}/_load/counters"),
        proxied,
        stop,
        task,
    })
}

impl Rig {
    fn sides(&self) -> [Side; 2] {
        let direct = Target {
            url: self.direct.clone(),
            token: None,
        };
        [
            Side {
                name: SideName::Direct,
                targets: vec![direct; self.proxied.len()],
            },
            Side {
                name: SideName::Proxied,
                targets: self.proxied.clone(),
            },
        ]
    }

    fn plan(&self, mode: Mode, warmup_ms: u64, measure_ms: u64, rounds: usize) -> Plan {
        Plan {
            mode,
            window: Window {
                warmup: Duration::from_millis(warmup_ms),
                measure: Duration::from_millis(measure_ms),
            },
            rounds,
            request_bytes: 1024,
            reply_bytes: 4096,
            timeout: Duration::from_secs(10),
            counters_url: Some(self.counters.clone()),
            note: None,
        }
    }

    async fn stop(self) {
        let _ = self.stop.send(());
        tokio::time::timeout(Duration::from_secs(20), self.task)
            .await
            .expect("proxy stops within the grace")
            .expect("proxy task joins")
            .expect("proxy run returns Ok");
        assert!(self.srv.stop().await > 0);
    }
}

fn assert_clean(rep: &Report, due: u64) {
    for r in &rep.runs {
        assert!(
            r.errors.is_empty() && r.warmup_errors.is_empty(),
            "{}",
            summary(rep)
        );
        assert_eq!(r.ok, due, "{}", summary(rep));
        assert_eq!(
            r.upstream_tools_calls,
            Some(r.ok_all),
            "one upstream call per reply"
        );
    }
}

/// Open loop at concurrency 32 over 4 principals on 2 routes: the per-principal
/// (8) and per-route (16) limits are met exactly and nothing is refused. A
/// closed loop of 40 workers puts 10 on each principal, and the driver counts
/// the proxy's 429s as their own class while the rest still succeed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_driver_measures_the_relay_and_counts_its_refusals() {
    let Some(rig) = rig(4, 2).await else {
        return;
    };
    let open = Mode::Open {
        rate: 200.0,
        cap: 32,
    };
    let rep = run(&rig.plan(open, 200, 1000, 1), &rig.sides())
        .await
        .unwrap();
    assert_clean(&rep, 200);
    assert_eq!(rep.runs[1].lanes, 4);
    assert_eq!(rep.added.len(), 1);

    let closed = Mode::Closed { concurrency: 40 };
    let rep = run(&rig.plan(closed, 0, 500, 1), &rig.sides()[1..])
        .await
        .unwrap();
    let r = &rep.runs[0];
    let busy = r
        .errors
        .get("http_429_too_many_requests")
        .copied()
        .unwrap_or(0);
    assert!(busy > 0, "{}", summary(&rep));
    assert_eq!(
        r.errors.len(),
        1,
        "429 is the only error: {}",
        summary(&rep)
    );
    assert!(r.ok > 0);
    assert_eq!(r.ok + busy, r.measured);
    assert_eq!(
        r.upstream_tools_calls,
        Some(r.ok_all),
        "a refused call never reached upstream"
    );
    rig.stop().await;
}

/// The validation shape at small scale: 100 calls/s at concurrency 32 over 8
/// principals on 4 routes, 3 alternating rounds. Minutes long; run by hand with
/// `cargo test -p lodeline-proxy-e2e --test loadgen_e2e -- --ignored`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "long: about 3 minutes"]
async fn alternating_rounds_at_the_validation_rate() {
    let Some(rig) = rig(8, 4).await else {
        return;
    };
    let open = Mode::Open {
        rate: 100.0,
        cap: 32,
    };
    let rep = run(&rig.plan(open, 5_000, 25_000, 3), &rig.sides())
        .await
        .unwrap();
    println!("{}", summary(&rep));
    assert_clean(&rep, 2_500);
    assert_eq!(rep.added.len(), 3);
    rig.stop().await;
}
