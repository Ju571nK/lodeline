//! Glob compilation wrapping `globset`.

use globset::{Glob, GlobMatcher};
use icu_normalizer::ComposingNormalizerBorrowed;
use std::borrow::Cow;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GlobError {
    #[error("invalid glob pattern: {0}")]
    Invalid(#[from] globset::Error),
}

/// A glob that matches regardless of Unicode normalization form: macOS keeps
/// a name in whichever form it was created (NFC or NFD) and reports it that
/// way, so pattern and path are both compared in NFC (#388).
#[derive(Debug)]
pub struct CompiledGlob(GlobMatcher);

fn nfc(s: &str) -> Cow<'_, str> {
    ComposingNormalizerBorrowed::new_nfc().normalize(s)
}

impl CompiledGlob {
    pub fn new(pattern: &str) -> Result<Self, GlobError> {
        let glob = Glob::new(&nfc(pattern))?;
        Ok(Self(glob.compile_matcher()))
    }

    pub fn is_match(&self, path: &Path) -> bool {
        match path.to_str() {
            Some(s) => self.0.is_match(&*nfc(s)),
            None => self.0.is_match(path),
        }
    }

    /// The pattern string the matcher was compiled from, in NFC.
    pub fn pattern(&self) -> &str {
        self.0.glob().glob()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn matches_star_glob() {
        let g = CompiledGlob::new("/Applications/*.app/Contents/Info.plist").unwrap();
        assert!(g.is_match(Path::new("/Applications/Cursor.app/Contents/Info.plist")));
        assert!(!g.is_match(Path::new("/tmp/Cursor.app/Contents/Info.plist")));
    }

    #[test]
    fn matches_question_mark_and_charclass() {
        let g = CompiledGlob::new("/tmp/file?.[ab]").unwrap();
        assert!(g.is_match(&PathBuf::from("/tmp/file1.a")));
        assert!(g.is_match(&PathBuf::from("/tmp/fileX.b")));
        assert!(!g.is_match(&PathBuf::from("/tmp/file12.a")));
    }

    #[test]
    fn literal_path_matches_exactly() {
        let g = CompiledGlob::new("/Users/alice/.claude.json").unwrap();
        assert!(g.is_match(Path::new("/Users/alice/.claude.json")));
        assert!(!g.is_match(Path::new("/Users/alice/.claude.jsonx")));
    }

    // 한글 written precomposed (NFC) and decomposed (NFD). APFS keeps
    // whichever form a file was created with and FSEvents reports it (#388).
    const HAN_NFC: &str = "\u{D55C}\u{AE00}";
    const HAN_NFD: &str = "\u{1112}\u{1161}\u{11AB}\u{1100}\u{1173}\u{11AF}";

    #[test]
    fn nfc_pattern_matches_nfd_path() {
        let g = CompiledGlob::new(&format!("/Users/a/{HAN_NFC}/config.json")).unwrap();
        assert!(g.is_match(Path::new(&format!("/Users/a/{HAN_NFD}/config.json"))));
        assert!(g.is_match(Path::new(&format!("/Users/a/{HAN_NFC}/config.json"))));
    }

    #[test]
    fn nfd_pattern_matches_nfc_path() {
        let g = CompiledGlob::new(&format!("/Users/a/{HAN_NFD}-*.json")).unwrap();
        assert!(g.is_match(Path::new(&format!("/Users/a/{HAN_NFC}-x.json"))));
        assert!(g.is_match(Path::new(&format!("/Users/a/{HAN_NFD}-x.json"))));
        assert!(!g.is_match(Path::new("/Users/a/other-x.json")));
    }

    #[test]
    fn pattern_round_trips_the_input_string() {
        let g = CompiledGlob::new("/Users/*/.claude/policy-*.json").unwrap();
        assert_eq!(g.pattern(), "/Users/*/.claude/policy-*.json");
    }
}
