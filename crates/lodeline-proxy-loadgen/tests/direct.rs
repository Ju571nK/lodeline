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
