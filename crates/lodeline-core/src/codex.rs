//! Codex config reads shared by AI Guard, `lodeline-hook`, and `lodeline doctor`.

use std::path::{Path, PathBuf};
use toml::Value;

/// Codex's system config folder, which holds `config.toml`, `hooks.json`, and
/// `requirements.toml`.
pub fn system_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("OpenAI")
            .join("Codex")
    }
    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from("/etc/codex")
    }
}

/// #200: `[features] hooks = false`, or its legacy name `codex_hooks`, turns
/// off every config hook (`ClaudeHooksEngine::new`, `hooks/src/engine/mod.rs`,
/// rust-v0.166.0). Codex applies the keys in sorted order, so in the merged
/// table `hooks` beats `codex_hooks`. A `[features]` pin in the system
/// `requirements.toml` overrides config (`managed_features.rs`); an MDM or
/// cloud pin, a profile, and `--disable hooks` are not seen.
///
/// `pin` is the parsed `requirements.toml`, `configs` the parsed
/// `config.toml` layers from low to high. Returns the label of the input that
/// turns hooks off and the key it set.
pub fn hooks_disabled_by<T: Copy>(
    pin: Option<(T, &Value)>,
    configs: &[(T, &Value)],
) -> Option<(T, &'static str)> {
    let winner = |tables: &[(T, &Value)]| {
        ["hooks", "codex_hooks"].into_iter().find_map(|key| {
            tables
                .iter()
                .rev()
                .find_map(|(label, t)| Some((t.get(key)?.as_bool()?, *label, key)))
        })
    };
    let pin = pin.and_then(|(label, r)| {
        let features = r
            .get("features")
            .or_else(|| r.get("feature_requirements"))?;
        winner(&[(label, features)])
    });
    let configs: Vec<_> = configs
        .iter()
        .filter_map(|(label, c)| Some((*label, c.get("features")?)))
        .collect();
    match pin.or_else(|| winner(&configs)) {
        Some((false, label, key)) => Some((label, key)),
        _ => None,
    }
}

/// Whether Codex runs hooks for the user whose Codex folder is `codex_home`.
/// Project `.codex/config.toml` layers are not read: they apply per folder.
#[derive(Debug, PartialEq, Eq)]
pub enum HooksFeature {
    On,
    Off { path: PathBuf, key: &'static str },
    Unreadable { path: PathBuf, error: String },
}

impl HooksFeature {
    pub fn read(system_dir: &Path, codex_home: &Path) -> Self {
        let files = [
            system_dir.join("requirements.toml"),
            system_dir.join("config.toml"),
            codex_home.join("config.toml"),
        ];
        let mut parsed = Vec::new();
        for path in files {
            let text = match std::fs::read_to_string(&path) {
                Ok(text) => text,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    parsed.push((path, None));
                    continue;
                }
                Err(e) => {
                    let error = e.to_string();
                    return Self::Unreadable { path, error };
                }
            };
            match toml::from_str::<Value>(&text) {
                Ok(value) => parsed.push((path, Some(value))),
                Err(e) => {
                    let error = e.message().to_string();
                    return Self::Unreadable { path, error };
                }
            }
        }
        let [(req_path, req), configs @ ..] = &parsed[..] else {
            unreachable!("three files are read")
        };
        let pin = req.as_ref().map(|r| (req_path, r));
        let configs: Vec<_> = configs
            .iter()
            .filter_map(|(p, v)| Some((p, v.as_ref()?)))
            .collect();
        match hooks_disabled_by(pin, &configs) {
            Some((path, key)) => Self::Off {
                path: path.clone(),
                key,
            },
            None => Self::On,
        }
    }

    /// One sentence for the user, or `None` when Codex runs hooks.
    pub fn warning(&self) -> Option<String> {
        match self {
            Self::On => None,
            Self::Off { path, key } => Some(format!(
                "Codex does not run hooks, so it never runs this one: {} sets `{key} = false` \
                 under [features]. To turn Codex hooks on, set `hooks = true` under [features] \
                 in that file.",
                path.display()
            )),
            Self::Unreadable { path, error } => Some(format!(
                "cannot read {} ({error}), so Lodeline cannot tell whether Codex runs hooks.",
                path.display()
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feature(requirements: &str, system: &str, user: &str) -> (tempfile::TempDir, HooksFeature) {
        let root = tempfile::tempdir().unwrap();
        let (sys, home) = (root.path().join("etc"), root.path().join("home"));
        for (dir, name, text) in [
            (&sys, "requirements.toml", requirements),
            (&sys, "config.toml", system),
            (&home, "config.toml", user),
        ] {
            std::fs::create_dir_all(dir).unwrap();
            if !text.is_empty() {
                std::fs::write(dir.join(name), text).unwrap();
            }
        }
        let got = HooksFeature::read(&sys, &home);
        (root, got)
    }

    #[test]
    fn hooks_false_names_the_file_and_key() {
        let (root, got) = feature("", "", "[features]\nhooks = false\n");
        let path = root.path().join("home").join("config.toml");
        assert_eq!(
            got,
            HooksFeature::Off {
                path: path.clone(),
                key: "hooks"
            }
        );
        let msg = got.warning().unwrap();
        assert!(msg.contains(&path.display().to_string()), "{msg}");
        assert!(
            msg.contains("`hooks = false`") && msg.contains("set `hooks = true` under [features]"),
            "{msg}"
        );
    }

    #[test]
    fn legacy_codex_hooks_false_is_named() {
        let (_root, got) = feature("", "", "[features]\ncodex_hooks = false\n");
        assert!(
            matches!(
                got,
                HooksFeature::Off {
                    key: "codex_hooks",
                    ..
                }
            ),
            "{got:?}"
        );
    }

    #[test]
    fn hooks_true_and_absent_key_are_on() {
        for user in ["[features]\nhooks = true\n", "model = \"o3\"\n", ""] {
            let (_root, got) = feature("", "", user);
            assert_eq!(got, HooksFeature::On, "{user:?}");
            assert_eq!(got.warning(), None);
        }
    }

    #[test]
    fn requirements_pin_wins_over_config() {
        let (root, got) = feature(
            "[features]\nhooks = false\n",
            "",
            "[features]\nhooks = true\n",
        );
        assert_eq!(
            got,
            HooksFeature::Off {
                path: root.path().join("etc").join("requirements.toml"),
                key: "hooks"
            }
        );
        let (_root, got) = feature(
            "[features]\nhooks = true\n",
            "",
            "[features]\nhooks = false\n",
        );
        assert_eq!(got, HooksFeature::On);
    }

    #[test]
    fn malformed_config_is_reported_not_fatal() {
        let (root, got) = feature("", "", "[features\nhooks = false\n");
        let HooksFeature::Unreadable { path, .. } = &got else {
            panic!("{got:?}")
        };
        assert_eq!(path, &root.path().join("home").join("config.toml"));
        assert!(got.warning().unwrap().starts_with("cannot read "));
    }
}
