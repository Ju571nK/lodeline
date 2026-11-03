include!(concat!(env!("OUT_DIR"), "/assets.rs"));

fn main() {
    println!(
        "lodeline-manager {}: {} embedded web files",
        env!("CARGO_PKG_VERSION"),
        ASSETS.len()
    );
}

#[cfg(test)]
mod tests {
    use super::ASSETS;

    #[test]
    fn embeds_an_index_page() {
        let (_, mime, body) = ASSETS
            .iter()
            .find(|(path, _, _)| *path == "index.html")
            .expect("index.html embedded");
        assert_eq!(*mime, "text/html; charset=utf-8");
        assert!(body.starts_with(b"<!doctype html>"));
    }
}
