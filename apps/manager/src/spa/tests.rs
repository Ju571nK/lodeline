use super::*;

const INDEX: &[u8] = b"<!doctype html>index";
const APP: &[u8] = b"0123456789";
static FAKE: Assets = &[
    ("assets/app.js", "text/javascript; charset=utf-8", APP),
    ("favicon.svg", "image/svg+xml", b"<svg/>"),
    ("index.html", "text/html; charset=utf-8", INDEX),
];

fn get(method: Method, uri: &str, headers: &[(header::HeaderName, &str)]) -> Response {
    let mut req = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        req = req.header(k, *v);
    }
    serve(FAKE, &req.body(Body::empty()).unwrap())
}

async fn body(res: Response) -> Vec<u8> {
    axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec()
}

fn location(res: &Response) -> &str {
    res.headers()[header::LOCATION].to_str().unwrap()
}

#[tokio::test]
async fn serves_files_and_falls_back_to_index() {
    for (uri, want) in [
        ("/", INDEX),
        ("//", INDEX),
        ("/alerts/abc", INDEX),
        ("/index.html", INDEX),
        ("/assets/", INDEX),
        ("/assets/../favicon.svg", b"<svg/>"),
        ("/%61ssets/app.js", APP),
        ("/assets/app.js?v=1", APP),
    ] {
        let res = get(Method::GET, uri, &[]);
        assert_eq!(res.status(), StatusCode::OK, "{uri}");
        assert_eq!(res.headers()[header::ACCEPT_RANGES], "bytes", "{uri}");
        assert_eq!(body(res).await, want, "{uri}");
    }
    let res = get(Method::POST, "/", &[]);
    assert_eq!(
        res.headers()[header::CONTENT_TYPE],
        "text/html; charset=utf-8"
    );
}

#[tokio::test]
async fn redirects_as_go_file_server() {
    for (uri, want) in [
        ("/assets", "assets/"),
        ("/assets?x=1", "assets/?x=1"),
        ("/favicon.svg/", "../favicon.svg"),
        ("/.", "./"),
    ] {
        let res = get(Method::GET, uri, &[]);
        assert_eq!(res.status(), StatusCode::MOVED_PERMANENTLY, "{uri}");
        assert_eq!(location(&res), want, "{uri}");
        assert!(body(res).await.is_empty(), "{uri}");
    }
}

#[tokio::test]
async fn head_declares_the_length_without_a_body() {
    let res = get(Method::HEAD, "/assets/app.js", &[]);
    assert_eq!(res.headers()[header::CONTENT_LENGTH], "10");
    assert!(body(res).await.is_empty());
}

#[tokio::test]
async fn serves_one_byte_range() {
    for (range, want, content_range) in [
        ("bytes=0-3", &APP[0..4], "bytes 0-3/10"),
        ("bytes=7-", &APP[7..], "bytes 7-9/10"),
        ("bytes=-2", &APP[8..], "bytes 8-9/10"),
        ("bytes=5-99", &APP[5..], "bytes 5-9/10"),
        ("bytes=-99", APP, "bytes 0-9/10"),
    ] {
        let res = get(Method::GET, "/assets/app.js", &[(header::RANGE, range)]);
        assert_eq!(res.status(), StatusCode::PARTIAL_CONTENT, "{range}");
        assert_eq!(
            res.headers()[header::CONTENT_RANGE],
            content_range,
            "{range}"
        );
        assert_eq!(body(res).await, want, "{range}");
    }
    for range in [
        "bytes=0-1,4-5",
        "bytes=10-",
        "bytes=5-2",
        "items=0-1",
        "bytes=-0",
    ] {
        let res = get(Method::GET, "/assets/app.js", &[(header::RANGE, range)]);
        assert_eq!(res.status(), StatusCode::OK, "{range}");
    }
    let res = get(
        Method::GET,
        "/assets/app.js",
        &[(header::RANGE, "bytes=0-1"), (header::IF_RANGE, "\"x\"")],
    );
    assert_eq!(res.status(), StatusCode::OK);
}

#[test]
fn embeds_an_index_page() {
    let (_, mime, body) = ASSETS
        .iter()
        .find(|(path, _, _)| *path == "index.html")
        .expect("index.html embedded");
    assert_eq!(*mime, "text/html; charset=utf-8");
    assert!(body.starts_with(b"<!doctype html>"));
}
