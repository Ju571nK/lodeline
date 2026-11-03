//! Embeds the SPA build (`web/dist`) as a sorted `ASSETS` table of
//! `(path, content type, bytes)` in `$OUT_DIR/assets.rs`. Without a build it
//! embeds a placeholder page, so `cargo test` works without npm, unless
//! `LODELINE_MANAGER_REQUIRE_DIST=1`.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::{env, fs};

const PLACEHOLDER: &str = "<!doctype html><html><body><p>Placeholder. Build the web UI in apps/manager/web, then rebuild lodeline-manager.</p></body></html>";

fn main() {
    let dist = Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap()).join("web/dist");
    // A missing path makes every build dirty, so watch the nearest one that exists.
    match [dist.as_path(), dist.parent().unwrap()]
        .into_iter()
        .find(|p| p.exists())
    {
        Some(path) => println!("cargo:rerun-if-changed={}", path.display()),
        None => println!("cargo:rerun-if-changed=build.rs"),
    }
    println!("cargo:rerun-if-env-changed=LODELINE_MANAGER_REQUIRE_DIST");

    let mut table = String::from("pub static ASSETS: &[(&str, &str, &[u8])] = &[\n");
    if dist.join("index.html").is_file() {
        let mut files = Vec::new();
        walk(&dist, &mut files);
        files.sort();
        for file in files {
            let rel = file
                .strip_prefix(&dist)
                .unwrap()
                .to_str()
                .unwrap()
                .replace('\\', "/");
            let mime = content_type(&rel);
            writeln!(table, "    ({rel:?}, {mime:?}, include_bytes!({file:?})),").unwrap();
        }
    } else if env::var("LODELINE_MANAGER_REQUIRE_DIST").as_deref() == Ok("1") {
        panic!(
            "LODELINE_MANAGER_REQUIRE_DIST=1 but {} has no index.html; build the web UI first",
            dist.display()
        );
    } else {
        writeln!(
            table,
            "    (\"index.html\", \"text/html; charset=utf-8\", {PLACEHOLDER:?}.as_bytes()),"
        )
        .unwrap();
    }
    table.push_str("];\n");

    let out = Path::new(&env::var("OUT_DIR").unwrap()).join("assets.rs");
    fs::write(out, table).unwrap();
}

fn walk(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            walk(&path, files);
        } else {
            files.push(path);
        }
    }
}

fn content_type(path: &str) -> &'static str {
    match path.rsplit_once('.').map(|(_, ext)| ext) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json" | "map") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}
