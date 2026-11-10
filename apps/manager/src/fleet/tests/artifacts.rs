//! The release file routes through the console's own router, against a real `lodeline-server` in
//! process: the index, a file streamed byte for byte, and each refusal, told apart.

use std::sync::Mutex;

use axum::body::Body;
use axum::http::{header, HeaderMap, Request as HttpRequest, StatusCode};
use axum::middleware::Next;
use jsonwebtoken::{encode, EncodingKey, Header};
use tower::ServiceExt;

use super::*;
use crate::server::{router, AppState as Console};

const SECRET: &str = "0123456789abcdefghijklmnopqrstuv";
const ARCHIVE: &str = "lodeline-0.14.2-x86_64-unknown-linux-musl.tar.gz";

/// Past 3 MiB, in a pattern whose period (251) divides no power of two, so a lost or repeated
/// chunk shows.
fn archive_bytes() -> Vec<u8> {
    (0..(3 << 20) + 7).map(|i: u32| (i % 251) as u8).collect()
}

type Seen = Arc<Mutex<Vec<String>>>;

/// A server with `artifacts_dir` set to `artifacts`, the read token on or off, that records the
/// path of every request it gets.
async fn serve_artifacts(dir: &Path, artifacts: Option<PathBuf>, read_api: bool) -> (String, Seen) {
    let mut state = fleet_state(dir);
    let s = Arc::get_mut(&mut state).unwrap();
    s.artifacts_dir = artifacts;
    if !read_api {
        s.read_token = ReadToken(None);
    }
    let seen: Seen = Arc::default();
    let log = seen.clone();
    let app = build_router(state).layer(axum::middleware::from_fn(
        move |req: HttpRequest<Body>, next: Next| {
            log.lock().unwrap().push(req.uri().path().to_owned());
            next.run(req)
        },
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, seen)
}

/// A signed-in `GET` on the console that reads the server at `url`.
async fn console_get(url: &str, path: &str) -> (StatusCode, HeaderMap, Vec<u8>) {
    let client = HttpClient::new(url, READ_TOKEN, None, http::TIMEOUT).unwrap();
    let app = router(Console::for_tests(SECRET, Arc::new(client)));
    let claims = json!({"iss": "lodeline-manager", "sub": "admin", "exp": 4_000_000_000_i64});
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(SECRET.as_bytes()),
    )
    .unwrap();
    let req = HttpRequest::builder()
        .uri(path)
        .header(header::HOST, "console.example")
        .header(header::COOKIE, format!("lodeline_session={token}"))
        .body(Body::empty())
        .unwrap();
    let (parts, body) = app.oneshot(req).await.unwrap().into_parts();
    let body = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    (parts.status, parts.headers, body.to_vec())
}

fn error_code(body: &[u8]) -> String {
    let v: Value = serde_json::from_slice(body).unwrap();
    v["error"]["code"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn the_console_lists_and_streams_a_release_file_from_a_real_server() {
    let dir = temp_dir("artifacts");
    let files = dir.0.join("artifacts");
    std::fs::create_dir_all(&files).unwrap();
    let archive = archive_bytes();
    std::fs::write(files.join(ARCHIVE), &archive).unwrap();
    std::fs::write(files.join("SHA256SUMS"), "sums\n").unwrap();
    let (url, _) = serve_artifacts(&dir.0, Some(files), true).await;

    let (status, _, body) = console_get(&url, "/api/v1/fleet/artifacts").await;
    assert_eq!(status, StatusCode::OK);
    let (raw, _) = server_body::<Value>(&url, "/v1/artifacts").await;
    assert_eq!(serde_json::from_slice::<Value>(&body).unwrap(), raw);
    assert_eq!(raw, json!({"artifacts": ["SHA256SUMS", ARCHIVE]}));

    let (status, headers, body) =
        console_get(&url, &format!("/api/v1/fleet/artifacts/{ARCHIVE}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "application/octet-stream");
    assert_eq!(
        headers[header::CONTENT_DISPOSITION],
        format!("attachment; filename=\"{ARCHIVE}\"").as_str()
    );
    assert_eq!(
        headers[header::CONTENT_LENGTH],
        archive.len().to_string().as_str()
    );
    assert_eq!(body.len(), archive.len());
    assert!(body == archive, "the file differs from the server's");
}

#[tokio::test]
async fn a_missing_file_is_not_found_and_an_unsafe_name_never_reaches_the_server() {
    let dir = temp_dir("artifacts-refused");
    let files = dir.0.join("artifacts");
    std::fs::create_dir_all(&files).unwrap();
    std::fs::write(dir.0.join("outside"), "not served").unwrap();
    let (url, seen) = serve_artifacts(&dir.0, Some(files), true).await;

    let (status, _, body) = console_get(&url, "/api/v1/fleet/artifacts/missing.tar.gz").await;
    assert_eq!(
        (status, error_code(&body)),
        (StatusCode::NOT_FOUND, "not_found".into())
    );
    assert_eq!(*seen.lock().unwrap(), ["/v1/artifacts/missing.tar.gz"]);

    for name in [
        "..",
        "%2e%2e",
        "..%2Foutside",
        "a%20b",
        "a%2Fb",
        "caf%C3%A9",
        "%00",
    ] {
        let (status, _, body) = console_get(&url, &format!("/api/v1/fleet/artifacts/{name}")).await;
        assert_eq!(
            (status, error_code(&body)),
            (StatusCode::BAD_REQUEST, "bad_filename".into()),
            "{name}"
        );
    }
    assert_eq!(seen.lock().unwrap().len(), 1, "{:?}", seen.lock().unwrap());
}

/// Each reason the server gives no file has its own console code.
#[tokio::test]
async fn no_artifacts_dir_and_a_disabled_read_api_are_told_apart() {
    let dir = temp_dir("artifacts-off");
    for (read_api, code) in [
        (true, "artifacts_not_configured"),
        (false, "read_api_disabled"),
    ] {
        let (url, _) = serve_artifacts(&dir.0, None, read_api).await;
        for path in [
            "/api/v1/fleet/artifacts",
            "/api/v1/fleet/artifacts/SHA256SUMS",
        ] {
            let (status, _, body) = console_get(&url, path).await;
            assert_eq!(
                (status, error_code(&body)),
                (StatusCode::BAD_GATEWAY, code.into()),
                "{path}"
            );
        }
    }
}
