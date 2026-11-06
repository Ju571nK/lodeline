//! The driver against the load server over real loopback HTTP, no proxy.

use std::sync::Arc;
use std::time::Duration;

use lodeline_proxy_loadgen::client::Target;
use lodeline_proxy_loadgen::run::{run, summary, Plan, Side, SideName};
use lodeline_proxy_loadgen::schedule::{Mode, Window};
use lodeline_proxy_loadgen::server::{serve, Counters};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_call_is_answered_and_counted_once() {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let counters = Arc::new(Counters::default());
    tokio::spawn(serve(l, counters, std::future::pending()));
    let target = Target {
        url: format!("http://127.0.0.1:{port}/mcp"),
        token: None,
    };
    let plan = Plan {
        mode: Mode::Open {
            rate: 200.0,
            cap: 8,
        },
        window: Window {
            warmup: Duration::from_millis(200),
            measure: Duration::from_millis(500),
        },
        rounds: 2,
        request_bytes: 1024,
        reply_bytes: 4096,
        timeout: Duration::from_secs(5),
        counters_url: Some(format!("http://127.0.0.1:{port}/_load/counters")),
        note: None,
    };
    let side = Side {
        name: SideName::Direct,
        targets: vec![target; 2],
    };
    let rep = run(&plan, &[side]).await.unwrap();
    assert_eq!(rep.runs.len(), 2);
    for r in &rep.runs {
        assert!(
            r.errors.is_empty() && r.warmup_errors.is_empty(),
            "{}",
            summary(&rep)
        );
        assert_eq!((r.sent, r.measured, r.ok), (140, 100, 100));
        assert_eq!(r.upstream_tools_calls, Some(140));
        assert_eq!(r.latency_ms.count, 100);
    }
    assert!(rep.added.is_empty(), "one side has nothing to compare");
}

async fn load_server() -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(serve(
        l,
        Arc::new(Counters::default()),
        std::future::pending(),
    ));
    format!("http://127.0.0.1:{port}")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn even_rounds_run_the_sides_in_reverse() {
    let base = load_server().await;
    let target = Target {
        url: format!("{base}/mcp"),
        token: None,
    };
    let sides = [SideName::Direct, SideName::Proxied].map(|name| Side {
        name,
        targets: vec![target.clone()],
    });
    let plan = Plan {
        mode: Mode::Open {
            rate: 100.0,
            cap: 1,
        },
        window: Window {
            warmup: Duration::ZERO,
            measure: Duration::from_millis(50),
        },
        rounds: 3,
        request_bytes: 64,
        reply_bytes: 64,
        timeout: Duration::from_secs(5),
        counters_url: None,
        note: None,
    };
    let rep = run(&plan, &sides).await.unwrap();
    let (d, p) = (SideName::Direct, SideName::Proxied);
    assert_eq!(rep.round_order, vec![vec![d, p], vec![p, d], vec![d, p]]);
    let ran: Vec<_> = rep.runs.iter().map(|r| (r.round, r.side)).collect();
    assert_eq!(ran, [(1, d), (1, p), (2, p), (2, d), (3, d), (3, p)]);
    assert_eq!(rep.added.len(), 3);
}

/// The binary's exit status: 0 only for a clean run, unless errors are allowed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_run_fails_on_errors_and_upstream_mismatches() {
    let (base, other) = (load_server().await, load_server().await);
    let run = move |extra: &[&str]| {
        let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_lodeline-proxy-loadgen"));
        c.args(["run", "--direct", &format!("{base}/mcp"), "--rate", "20"])
            .args(["--concurrency", "2", "--warmup", "0", "--duration", "0.3"])
            .args(["--rounds", "1", "--timeout", "5"])
            .args(extra)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        c.status().unwrap().code()
    };
    let (clean, wrong_counters, too_big) = tokio::task::spawn_blocking(move || {
        let counters = format!("{other}/_load/counters");
        let wrong = ["--counters", counters.as_str()];
        // Over the load server's 2 MiB body limit: every call is refused.
        let big = ["--request-bytes", "3000000"];
        (
            run(&[]),
            [
                run(&wrong),
                run(&[&wrong[..], &["--allow-errors"]].concat()),
            ],
            [run(&big), run(&[&big[..], &["--allow-errors"]].concat())],
        )
    })
    .await
    .unwrap();
    assert_eq!(clean, Some(0));
    assert_eq!(
        wrong_counters,
        [Some(1), Some(1)],
        "a mismatch always fails"
    );
    assert_eq!(too_big, [Some(1), Some(0)], "errors fail unless allowed");
}
