#![cfg(unix)]
//! Listener TLS (non-loopback binds require it; PX-008/014). Uses the `openssl`
//! CLI to mint a throwaway self-signed certificate; the test is skipped (and
//! says so) when the CLI is absent.

mod common;
use common::*;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The listener serves HTTP/1.1 over TLS, the bearer rules still apply, and the
/// relay works through it. Plain-text clients get no HTTP answer.
#[tokio::test]
async fn tls_listener_relays() {
    let dir = tempfile::tempdir().unwrap();
    let (c, k) = (dir.path().join("c.pem"), dir.path().join("k.pem"));
    let ok = std::process::Command::new("openssl")
        .args([
            "req",
            "-x509",
            // RSA, not EC: LibreSSL (macOS) writes EC keys with explicit
            // curve parameters, which rustls cannot load.
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            // LibreSSL (macOS) picks a random 8-byte serial that can encode as
            // a negative INTEGER, which webpki rejects.
            "-set_serial",
            "1",
        ])
        .args([
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ])
        .args(["-addext", "basicConstraints=critical,CA:FALSE"])
        .arg("-keyout")
        .arg(&k)
        .arg("-out")
        .arg(&c)
        .output();
    let Ok(out) = ok else {
        eprintln!("SKIPPED: openssl CLI not available");
        return;
    };
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o600)).unwrap();

    let acceptor = sigil_proxy::tls::load_acceptor(&c, &k).unwrap();
    let up = ok_upstream().await;
    let l = limits();
    let t = table(&[R::new("a", up.url("/up"), &[("pa", "tok-a")])], &l);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = sigil_proxy::route::TableHandle::new();
    handle.set(Some(t));
    let proxy =
        sigil_proxy::server::Proxy::new(l, handle, Arc::new(sigil_proxy::dest::SystemResolver));
    let task = tokio::spawn(async move {
        proxy
            .serve(listener, Some(acceptor), std::future::pending())
            .await
    });

    let mut roots = rustls::RootCertStore::empty();
    let pem = std::fs::read(&c).unwrap();
    for cert in rustls_pemfile::certs(&mut &pem[..]) {
        roots.add(cert.unwrap()).unwrap();
    }
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let conn = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let exchange = |token: &'static str| {
        let conn = conn.clone();
        async move {
            let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut s = conn
                .connect(
                    rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                    tcp,
                )
                .await
                .unwrap();
            let req = format!(
                "POST /mcp/a HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\nAuthorization: Bearer {token}\r\nContent-Length: 2\r\n\r\n{{}}",
                addr.port()
            );
            s.write_all(req.as_bytes()).await.unwrap();
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf).await;
            parse_response(buf)
        }
    };
    assert_eq!(exchange("tok-a").await.status, 200);
    assert_eq!(exchange("wrong").await.status, 401);
    assert_eq!(up.count(), 1);

    // plain text to the TLS port never yields an HTTP response
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let _ = s
        .write_all(b"POST /mcp/a HTTP/1.1\r\nHost: x\r\n\r\n")
        .await;
    let mut b = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), s.read_to_end(&mut b)).await;
    assert!(!b.starts_with(b"HTTP/1.1"));
    task.abort();
}
