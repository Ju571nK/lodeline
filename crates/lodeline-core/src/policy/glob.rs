//! Glob compilation wrapping `globset`.

use globset::{Glob, GlobMatcher};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GlobError {
    #[error("invalid glob pattern: {0}")]
    Invalid(#[from] globset::Error),
}

/// A path segment that is exactly `*`, followed by plain segments only, names
/// one folder (`skills/*/SKILL.md`), although globset's `*` would also cross `/`.
/// `above` matches the folders before that segment; `tail` counts the segments
/// after it.
#[derive(Debug)]
struct OneFolder {
    above: GlobMatcher,
    /// True when `above` has no glob character, so it names one folder.
    above_plain: bool,
    tail: usize,
}

#[derive(Debug)]
pub struct CompiledGlob {
    whole: GlobMatcher,
    one_folder: Option<OneFolder>,
}

fn is_plain(segment: &str) -> bool {
    !segment.contains(['*', '?', '[', ']', '{', '}'])
}

impl CompiledGlob {
    /// Matches as globset does: `*` crosses `/`. Every operator pattern uses this.
    pub fn new(pattern: &str) -> Result<Self, GlobError> {
        Ok(Self {
            whole: Glob::new(pattern)?.compile_matcher(),
            one_folder: None,
        })
    }

    /// As [`CompiledGlob::new`], but a `*` segment followed only by plain segments
    /// names one folder. For built-in targets only, so an operator's pattern keeps
    /// its meaning.
    pub fn new_one_folder(pattern: &str) -> Result<Self, GlobError> {
        let whole = Glob::new(pattern)?.compile_matcher();
        // shortcut: only the last `*` segment is held to one folder, and only
        // when plain segments follow it; upgrade when another entry needs more.
        let parts: Vec<_> = Path::new(pattern).components().collect();
        let one_folder = parts
            .iter()
            .rposition(|c| c.as_os_str() == "*")
            .filter(|&i| i > 0 && i + 1 < parts.len())
            .filter(|&i| {
                parts[i + 1..]
                    .iter()
                    .all(|c| is_plain(&c.as_os_str().to_string_lossy()))
            })
            .and_then(|i| {
                let above: std::path::PathBuf = parts[..i].iter().collect();
                let above = above.to_str()?;
                Some(OneFolder {
                    above: Glob::new(above).ok()?.compile_matcher(),
                    above_plain: is_plain(above),
                    tail: parts.len() - i - 1,
                })
            });
        Ok(Self { whole, one_folder })
    }

    pub fn is_match(&self, path: &Path) -> bool {
        self.whole.is_match(path)
            && self.one_folder.as_ref().is_none_or(|o| {
                path.ancestors()
                    .nth(o.tail + 1)
                    .is_some_and(|folder| o.above.is_match(folder))
            })
    }

    /// False when no file below `dir` can match: `dir` lies inside a folder
    /// that the `*` segment named, deeper than the plain tail reaches. Pruned
    /// only when the folders above the `*` are plain: an earlier `*` crosses `/`
    /// and can make a folder that looks too deep a match.
    pub fn may_match_below(&self, dir: &Path) -> bool {
        self.one_folder.as_ref().is_none_or(|o| {
            !o.above_plain
                || !dir
                    .ancestors()
                    .skip(o.tail)
                    .any(|star| star.parent().is_some_and(|above| o.above.is_match(above)))
        })
    }

    /// The original pattern string the matcher was compiled from.
    pub fn pattern(&self) -> &str {
        self.whole.glob().glob()
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

    #[test]
    fn pattern_round_trips_the_input_string() {
        let g = CompiledGlob::new("/Users/*/.claude/policy-*.json").unwrap();
        assert_eq!(g.pattern(), "/Users/*/.claude/policy-*.json");
    }

    #[test]
    fn star_segment_before_plain_segments_names_one_folder() {
        let g = CompiledGlob::new_one_folder("/h/.claude/skills/*/SKILL.md").unwrap();
        assert!(g.is_match(Path::new("/h/.claude/skills/a/SKILL.md")));
        assert!(!g.is_match(Path::new("/h/.claude/skills/a/b/SKILL.md")));
        assert!(!g.is_match(Path::new("/h/.claude/skills/SKILL.md")));
        assert!(g.may_match_below(Path::new("/h/.claude/skills")));
        assert!(g.may_match_below(Path::new("/h/.claude")));
        assert!(g.may_match_below(Path::new("/h/.claude/skills/a")));
        assert!(!g.may_match_below(Path::new("/h/.claude/skills/a/b")));
        let g = CompiledGlob::new_one_folder("/h/*/.claude/skills/*/SKILL.md").unwrap();
        assert!(g.is_match(Path::new("/h/alice/.claude/skills/a/SKILL.md")));
        assert!(!g.is_match(Path::new("/h/alice/.claude/skills/a/b/SKILL.md")));
    }

    #[test]
    fn may_match_below_keeps_a_folder_an_earlier_star_can_reach() {
        // The first `*` crosses `/`, so `a/skills/b` is one match of it and the
        // file below `a/skills/b/skills/c` is a match.
        let g = CompiledGlob::new_one_folder("/h/*/skills/*/SKILL.md").unwrap();
        let file = Path::new("/h/a/skills/b/skills/c/SKILL.md");
        assert!(g.is_match(file));
        assert!(g.may_match_below(Path::new("/h/a/skills/b/skills")));
        assert!(g.may_match_below(Path::new("/h/a/skills/b/skills/c")));
    }

    #[test]
    fn plain_constructor_keeps_the_star_crossing_folders() {
        let g = CompiledGlob::new("/h/.claude/skills/*/SKILL.md").unwrap();
        assert!(g.is_match(Path::new("/h/.claude/skills/a/b/SKILL.md")));
        assert!(g.may_match_below(Path::new("/h/.claude/skills/a/b")));
    }

    #[test]
    fn other_stars_still_cross_folders() {
        for (pattern, file) in [
            ("/h/.claude/hooks/*", "/h/.claude/hooks/a/b.sh"),
            ("/h/.claude/agents/*.md", "/h/.claude/agents/a/b.md"),
            ("/h/rules/**", "/h/rules/a/b.mdc"),
            ("/h/*/x/*.md", "/h/a/x/b/c.md"),
        ] {
            let g = CompiledGlob::new(pattern).unwrap();
            assert!(g.is_match(Path::new(file)), "{pattern} vs {file}");
            assert!(g.may_match_below(Path::new("/h/.claude/hooks/a/b")));
        }
    }
}
