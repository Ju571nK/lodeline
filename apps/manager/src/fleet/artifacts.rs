//! The release files that a server's operator placed in its `artifacts_dir`, as `lodeline-server`
//! serves them under `/v1/artifacts` (`crates/lodeline-server/src/routes/artifacts.rs`). The
//! console lists the names and streams a file as the server sends it. It checks nothing about the
//! contents.

use serde::{Deserialize, Serialize};

/// `GET /v1/artifacts`: the file names, as the server sends them.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ArtifactsIndex {
    pub artifacts: Vec<String>,
}

/// A file name that the server's `is_safe_name` accepts: ASCII letters, digits, `.`, `_` and
/// `-`, and neither `.` nor `..`. Such a name is one URL path segment, and it needs no quoting in
/// a header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactName(String);

impl ArtifactName {
    pub fn parse(name: &str) -> Option<Self> {
        let safe = !name.is_empty()
            && name != "."
            && name != ".."
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        safe.then(|| Self(name.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One file on its way from the server: the server's `Content-Length`, when it sent one, and the
/// body as it arrives.
pub struct Download {
    pub len: Option<u64>,
    pub body: axum::body::Body,
}

#[cfg(test)]
mod tests {
    use super::ArtifactName;

    /// The server's own cases (`routes/artifacts.rs`), so the two rules cannot drift apart.
    #[test]
    fn names_follow_the_servers_rule() {
        for n in [
            "lodeline-0.6.2-aarch64-unknown-linux-musl.tar.gz",
            "lodeline-0.6.2-aarch64-pc-windows-msvc.zip",
            "lodeline_0.6.2-1_arm64.deb",
            "lodeline-0.6.2-1.aarch64.rpm",
            "SHA256SUMS",
            "build-manifest.json",
            "...",
        ] {
            assert_eq!(ArtifactName::parse(n).unwrap().as_str(), n);
        }
        for n in [
            "",
            ".",
            "..",
            "../etc/passwd",
            "a/b",
            "a\\b",
            "foo/../bar",
            "a b",
            "name\0",
            "a%2Fb",
            "caf\u{e9}",
        ] {
            assert_eq!(ArtifactName::parse(n), None, "{n:?}");
        }
    }
}
