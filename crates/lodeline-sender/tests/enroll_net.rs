//! The answer map of `enroll::net::post`, against a scripted HTTP server.
//!
//! Plain HTTP is enough here: the client logic is the same, and TLS failures are
//! covered by `enroll_e2e.rs` against the real listener.

use lodeline_sender::enroll::net::{post, Pacing, Request};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Any CA certificate: the client only needs one to build, since these tests use plain HTTP.
fn ca_pem() -> String {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut p = rcgen::CertificateParams::new(vec![]).unwrap();
    p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    p.self_signed(&key).unwrap().pem()
}

/// Answers each connection with the next scripted `(status, extra header, body)`.
async fn scripted(script: Vec<(u16, &'static str, String)>) -> (String, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let seen = Arc::new(AtomicUsize::new(0));
    let n = seen.clone();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = l.accept().await.unwrap();
            let i = n.fetch_add(1, Ordering::SeqCst);
            let (status, header, body) = script[i.min(script.len() - 1)].clone();
            let mut buf = vec![0u8; 65536];
            let _ = sock.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 {status} X\r\nconnection: close\r\ncontent-type: application/json\r\n{header}content-length: {}\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        }
    });
    (url, seen)
}

fn error_body(code: &str, message: &str) -> String {
    serde_json::json!({"error": {"code": code, "message": message}}).to_string()
}

fn issued() -> String {
    serde_json::json!({"client_cert_pem": "LEAF\n", "ca_chain_pem": "CHAIN\n"}).to_string()
}

async fn run(url: &str, earlier_run: bool) -> Result<(String, String), (i32, String)> {
    let r = Request {
        enroll_url: url,
        server_ca_pem: &ca_pem(),
        token: "tkn-9f8e7d6c",
        host_id: "3f2c6a1e-8b4d-4c2a-9e7f-1a2b3c4d5e6f",
        csr_pem: "csr",
        expires_at: Some("2026-11-10T13:00:00Z"),
        earlier_run,
    };
    let fast = Pacing {
        network_waits: vec![Duration::from_millis(10); 2],
    };
    post(&r, &fast)
        .await
        .map(|i| (i.cert_pem, i.chain_pem))
        .map_err(|f| (f.code, f.msg))
}

#[tokio::test]
async fn an_issued_certificate_is_returned() {
    let (url, seen) = scripted(vec![(200, "", issued())]).await;
    assert_eq!(
        run(&url, false).await.unwrap(),
        ("LEAF\n".into(), "CHAIN\n".into())
    );
    assert_eq!(seen.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn each_status_maps_to_its_exit_code_and_never_retries() {
    for (status, body, code, text) in [
        (
            400,
            error_body("bad_request", "missing token"),
            1,
            "malformed",
        ),
        (422, "nope".to_string(), 1, "malformed"),
        (413, String::new(), 1, "malformed"),
        (
            403,
            error_body("enrollment_denied", "enrollment denied"),
            5,
            "refused",
        ),
        (404, String::new(), 6, "not an enrollment listener"),
        (
            500,
            error_body("sign_failed", "token store error"),
            5,
            "may be spent",
        ),
        (200, "{}".to_string(), 5, "cannot read"),
        (418, String::new(), 1, "unexpected answer 418"),
    ] {
        let (url, seen) = scripted(vec![(status, "", body)]).await;
        let (c, m) = run(&url, false).await.unwrap_err();
        assert_eq!((c, seen.load(Ordering::SeqCst)), (code, 1), "{status}: {m}");
        assert!(m.contains(text), "{status}: {m}");
        assert!(
            !m.contains("tkn-9f8e7d6c"),
            "the token is never echoed: {m}"
        );
    }
}

#[tokio::test]
async fn a_refused_token_says_when_an_earlier_run_may_have_spent_it() {
    let (url, _) = scripted(vec![(403, "", String::new())]).await;
    let (_, with) = run(&url, true).await.unwrap_err();
    assert!(
        with.contains("An earlier run may have spent this token"),
        "{with}"
    );
    assert!(
        with.contains("2026-11-10T13:00:00Z") && with.contains("enroll-token --host-id"),
        "{with}"
    );
    let (_, without) = run(&url, false).await.unwrap_err();
    assert!(!without.contains("earlier run"), "{without}");
}

#[tokio::test]
async fn a_token_store_error_points_at_the_troubleshooting_row() {
    let (url, _) = scripted(vec![(
        500,
        "",
        error_body("sign_failed", "token store error"),
    )])
    .await;
    let (c, m) = run(&url, false).await.unwrap_err();
    assert_eq!(c, 5);
    assert!(m.contains("token file"), "{m}");
}

#[tokio::test]
async fn a_421_is_retried_once_at_once_and_then_it_is_a_bug() {
    let (url, seen) = scripted(vec![(421, "", String::new()), (200, "", issued())]).await;
    assert!(run(&url, false).await.is_ok());
    assert_eq!(seen.load(Ordering::SeqCst), 2);
    let (url, seen) = scripted(vec![(421, "", String::new())]).await;
    assert_eq!(run(&url, false).await.unwrap_err().0, 1);
    assert_eq!(seen.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_busy_server_is_retried_after_retry_after_and_then_gives_up() {
    let (url, seen) = scripted(vec![
        (503, "retry-after: 1\r\n", String::new()),
        (200, "", issued()),
    ])
    .await;
    let t = std::time::Instant::now();
    assert!(run(&url, false).await.is_ok());
    assert!(
        t.elapsed() >= Duration::from_millis(900),
        "waited for Retry-After"
    );
    assert_eq!(seen.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_refused_connection_is_retried_with_the_given_waits_and_then_exits_6() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    drop(l);
    let (c, m) = run(&url, false).await.unwrap_err();
    assert_eq!(c, 6);
    assert!(
        m.contains("could not reach") && m.contains("10 connections"),
        "{m}"
    );
}
