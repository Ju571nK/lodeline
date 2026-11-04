//! The embedded SPA, served the way Go's `http.FileServer` over the embedded `dist` serves it,
//! with the `index.html` fallback for client-side routes. Two intended differences: a path
//! ending in `/index.html` gets that page instead of a 301 to `./`, and a directory path with a
//! trailing slash gets `index.html` instead of a directory listing.

use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::config::unescape;

include!(concat!(env!("OUT_DIR"), "/assets.rs"));

/// `(path, content type, bytes)`, sorted by path, as `build.rs` writes `ASSETS`.
pub type Assets = &'static [(&'static str, &'static str, &'static [u8])];

pub fn serve(assets: Assets, req: &Request) -> Response {
    // reject_bad_escapes has already refused a path that does not decode.
    let decoded = unescape(req.uri().path()).unwrap_or_default();
    let url_path = String::from_utf8_lossy(&decoded);
    let name = clean(&url_path);
    let is_dir = |name: &str| {
        name.is_empty()
            || assets
                .iter()
                .any(|(p, _, _)| p.strip_prefix(name).is_some_and(|r| r.starts_with('/')))
    };
    let file = assets.iter().find(|(p, _, _)| *p == name);
    let index = || file_response(assets, req, "index.html");

    if url_path.ends_with("/index.html") && file.is_some() {
        return index();
    }
    if is_dir(&name) {
        if !url_path.ends_with('/') {
            return redirect(req, &format!("{}/", base(&url_path)));
        }
        return index();
    }
    match file {
        Some(_) if url_path.ends_with('/') => redirect(req, &format!("../{}", base(&url_path))),
        Some((path, _, _)) => file_response(assets, req, path),
        None => index(),
    }
}

fn file_response(assets: Assets, req: &Request, name: &str) -> Response {
    let Some(&(_, mime, bytes)) = assets.iter().find(|(p, _, _)| *p == name) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let size = bytes.len();
    let (status, body, range) = match single_range(req, size) {
        Some((start, end)) => (
            StatusCode::PARTIAL_CONTENT,
            &bytes[start..=end],
            Some(format!("bytes {start}-{end}/{size}")),
        ),
        None => (StatusCode::OK, bytes, None),
    };
    let mut res = Response::builder()
        .status(status)
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CONTENT_TYPE, mime)
        .header(header::CONTENT_LENGTH, body.len());
    if let Some(range) = range {
        res = res.header(header::CONTENT_RANGE, range);
    }
    let body = if req.method() == Method::HEAD {
        Body::empty()
    } else {
        Body::from(body)
    };
    res.body(body).expect("static headers are valid")
}

/// One satisfiable `bytes=` range, inclusive, parsed as Go's `parseRange`. `If-Range` voids it,
/// because the embedded files have no ETag or modification time to match.
// shortcut: several ranges, or one Go would answer with 416, get the whole file with 200; Go
// sends multipart/byteranges or 416. Port those if a client ever depends on them.
fn single_range(req: &Request, size: usize) -> Option<(usize, usize)> {
    if req.headers().contains_key(header::IF_RANGE) {
        return None;
    }
    let spec = req
        .headers()
        .get(header::RANGE)?
        .to_str()
        .ok()?
        .strip_prefix("bytes=")?;
    if spec.contains(',') || size == 0 {
        return None;
    }
    let ws: &[char] = &[' ', '\t'];
    let (start, end) = spec.trim_matches(ws).split_once('-')?;
    let (start, end) = (start.trim_matches(ws), end.trim_matches(ws));
    if start.is_empty() {
        let n: usize = end.parse().ok().filter(|&n| n > 0)?;
        return Some((size - n.min(size), size - 1));
    }
    let start: usize = start.parse().ok().filter(|&s| s < size)?;
    let end = match end {
        "" => size - 1,
        e => e
            .parse::<usize>()
            .ok()
            .filter(|&e| e >= start)?
            .min(size - 1),
    };
    Some((start, end))
}

/// Go's `localRedirect`: a relative 301 that keeps the query.
fn redirect(req: &Request, to: &str) -> Response {
    let location = match req.uri().query() {
        Some(q) if !q.is_empty() => format!("{to}?{q}"),
        _ => to.to_owned(),
    };
    match HeaderValue::from_str(&location) {
        Ok(location) => (
            StatusCode::MOVED_PERMANENTLY,
            [(header::LOCATION, location)],
        )
            .into_response(),
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}

/// Go's `path.Clean` of a request path, without the leading slash.
fn clean(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    parts.join("/")
}

/// Go's `path.Base`.
fn base(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return "/";
    }
    trimmed.rsplit('/').next().unwrap_or(trimmed)
}

#[cfg(test)]
mod tests;
