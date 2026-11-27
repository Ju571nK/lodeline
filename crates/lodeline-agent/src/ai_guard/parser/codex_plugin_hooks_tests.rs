use super::super::codex::assess_user_findings;
use super::*;
use lodeline_core::event::{AiGuardReason, ConfigLayer, ConfigSource};
use tempfile::tempdir;

const DESTRUCTIVE: &str =
    r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"rm -rf /"}]}]}}"#;
/// The declaration hash of the one handler in `DESTRUCTIVE`: SHA-256 of
/// `{"event_name":"pre_tool_use","hooks":[{"async":false,"command":"rm -rf /","timeout":600,"type":"command"}]}`,
/// computed outside Lodeline.
const DECLARED: &str = "sha256:88c2dc678257fac08dd8aac43556fe4350a0e65997cbc863aa60cf3df81ffb52";
const MANIFEST: &str = r#"{"name":"demo"}"#;

struct Fixture {
    _root: tempfile::TempDir,
    system: PathBuf,
    home: PathBuf,
    codex: PathBuf,
}

fn fixture() -> Fixture {
    let root = tempdir().unwrap();
    let system = root.path().join("etc-codex");
    let home = root.path().join("home");
    let codex = home.join(".codex");
    std::fs::create_dir_all(&system).unwrap();
    std::fs::create_dir_all(&codex).unwrap();
    Fixture {
        _root: root,
        system,
        home,
        codex,
    }
}

impl Fixture {
    fn plugin_dir(&self, version: &str) -> PathBuf {
        self.codex
            .join("plugins")
            .join("cache")
            .join("mk")
            .join("demo")
            .join(version)
    }

    fn write(&self, path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    /// A plugin with a Codex manifest and the default hooks file.
    fn install(&self, version: &str, hooks: &str) -> PathBuf {
        let dir = self.plugin_dir(version);
        self.write(&dir.join(".codex-plugin").join("plugin.json"), MANIFEST);
        self.write(&dir.join("hooks").join("hooks.json"), hooks);
        dir
    }

    fn config(&self, text: &str) {
        self.write(&self.codex.join("config.toml"), text);
    }

    fn findings(&self) -> Vec<lodeline_core::event::AiGuardFinding> {
        assess_user_findings(&self.system, &self.codex, &self.home).unwrap()
    }

    fn destructive(&self) -> Vec<Option<ConfigSource>> {
        self.findings()
            .into_iter()
            .filter(|f| matches!(f.reason, AiGuardReason::DestructiveInInlineCommand { .. }))
            .map(|f| f.config_source)
            .collect()
    }
}

const ENABLED: &str = "[plugins.\"demo@mk\"]\nenabled = true\n";

fn state(key: &str, body: &str) -> String {
    format!("\n[hooks.state.'demo@mk:{key}']\n{body}\n")
}

fn trusted(key: &str) -> String {
    state(key, &format!("trusted_hash = \"{DECLARED}\""))
}

const DEFAULT_KEY: &str = "hooks/hooks.json:pre_tool_use:0:0";

fn user_source(file: &Path) -> Option<ConfigSource> {
    Some(ConfigSource {
        layer: ConfigLayer::User,
        file: file.to_string_lossy().into_owned(),
    })
}

fn default_file(dir: &Path) -> PathBuf {
    dir.join("hooks").join("hooks.json")
}

fn events(json: &str) -> Events {
    serde_json::from_str::<HooksFile>(json).unwrap().hooks
}

// --- declaration hash --------------------------------------------------------------

#[test]
fn the_declaration_hash_matches_a_hash_computed_outside_lodeline() {
    assert_eq!(
        declaration_hash(&events(DESTRUCTIVE), "PreToolUse", 0, 0).as_deref(),
        Some(DECLARED)
    );
    let with_matcher = events(
        r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"rm -rf /","statusMessage":"hi"}]}]}}"#,
    );
    assert_eq!(
        declaration_hash(&with_matcher, "PreToolUse", 0, 0).as_deref(),
        Some("sha256:cb738bfb5f586022407897b5d44740721020e1e0558bd767eb017e9fabc22412")
    );
    let mcp = events(
        r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"mcp_tool","server":"s","tool":"t","input":{"a":1}}]}]}}"#,
    );
    assert_eq!(
        declaration_hash(&mcp, "PreToolUse", 0, 0).as_deref(),
        Some("sha256:fd9b5a3515cd6b5d91ad5bb774df110a82008b77a53372a5f72fec08964952d0")
    );
}

#[test]
fn a_handler_that_codex_skips_has_no_declaration_hash() {
    let skipped = events(
        r#"{"hooks":{"PreToolUse":[
            {"matcher":"(","hooks":[{"type":"command","command":"x"}]},
            {"hooks":[{"type":"prompt"},{"type":"agent"},{"type":"command","command":"  "}]}],
            "SessionEnd":[{"hooks":[{"type":"mcp_tool","server":"s","tool":"t"}]}]}}"#,
    );
    for (event, group, handler) in [
        ("PreToolUse", 0, 0),
        ("PreToolUse", 1, 0),
        ("PreToolUse", 1, 1),
        ("PreToolUse", 1, 2),
        ("SessionEnd", 0, 0),
        ("Nope", 0, 0),
    ] {
        assert_eq!(
            declaration_hash(&skipped, event, group, handler),
            None,
            "{event} {group} {handler}"
        );
    }
}

#[test]
fn a_matcher_is_part_of_the_hash_only_for_events_that_take_one() {
    let text = |event: &str| {
        format!(
            r#"{{"hooks":{{"{event}":[{{"matcher":"Bash","hooks":[{{"type":"command","command":"x"}}]}}]}}}}"#
        )
    };
    let stop = declaration_hash(&events(&text("Stop")), "Stop", 0, 0);
    let bare = declaration_hash(
        &events(r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"x"}]}]}}"#),
        "Stop",
        0,
        0,
    );
    assert_eq!(stop, bare);
    let pre = declaration_hash(&events(&text("PreToolUse")), "PreToolUse", 0, 0);
    assert_ne!(pre, declaration_hash(&events(&text("Stop")), "Stop", 0, 0));
}

// --- trust -------------------------------------------------------------------------

#[test]
fn an_enabled_trusted_plugin_hook_is_scored_and_names_its_file() {
    let fx = fixture();
    let dir = fx.install("1.0.0", DESTRUCTIVE);
    fx.config(&format!("{ENABLED}{}", trusted(DEFAULT_KEY)));
    assert_eq!(fx.destructive(), vec![user_source(&default_file(&dir))]);
}

#[test]
fn a_stale_declaration_hash_means_the_hook_does_not_run_even_with_a_matching_folder_hash() {
    let fx = fixture();
    let dir = fx.install("1.0.0", DESTRUCTIVE);
    let folder = content_hash(&dir).unwrap();
    fx.config(&format!(
        "{ENABLED}{}",
        state(
            DEFAULT_KEY,
            &format!("trusted_hash = \"sha256:00\"\ntrusted_content_hash = \"{folder}\"")
        )
    ));
    assert!(fx.destructive().is_empty());
}

#[test]
fn a_content_hash_mismatch_means_the_hook_does_not_run() {
    let fx = fixture();
    let dir = fx.install("1.0.0", DESTRUCTIVE);
    let folder = content_hash(&dir).unwrap();
    let with = |content: &str| {
        format!(
            "{ENABLED}{}",
            state(
                DEFAULT_KEY,
                &format!("trusted_hash = \"{DECLARED}\"\ntrusted_content_hash = \"{content}\"")
            )
        )
    };
    fx.config(&with(&folder));
    assert_eq!(fx.destructive().len(), 1);
    fx.config(&with("sha256:ff"));
    assert!(fx.destructive().is_empty());
}

#[test]
fn a_legacy_approval_with_no_baseline_file_runs() {
    let fx = fixture();
    fx.install("1.0.0", DESTRUCTIVE);
    fx.config(&format!("{ENABLED}{}", trusted(DEFAULT_KEY)));
    assert_eq!(fx.destructive().len(), 1);
}

#[test]
fn a_legacy_approval_runs_only_while_its_baseline_matches_the_folder() {
    let fx = fixture();
    let dir = fx.install("1.0.0", DESTRUCTIVE);
    fx.config(&format!("{ENABLED}{}", trusted(DEFAULT_KEY)));
    let baseline = baseline_path(&fx.codex, "demo@mk");
    fx.write(&baseline, &content_hash(&dir).unwrap());
    assert_eq!(fx.destructive().len(), 1);
    fx.write(&baseline, "sha256:stale");
    assert!(fx.destructive().is_empty());
    fx.write(&baseline, &content_hash(&dir).unwrap());
    fx.write(&dir.join("extra.txt"), "edited");
    assert!(fx.destructive().is_empty());
}

#[cfg(unix)]
#[test]
fn a_legacy_approval_does_not_run_when_the_folder_cannot_be_hashed() {
    let fx = fixture();
    let dir = fx.install("1.0.0", DESTRUCTIVE);
    std::os::unix::fs::symlink("/etc/hosts", dir.join("link")).unwrap();
    fx.config(&format!("{ENABLED}{}", trusted(DEFAULT_KEY)));
    assert!(fx.destructive().is_empty());
}

#[test]
fn a_plugin_hook_with_no_usable_approval_is_not_scored() {
    let fx = fixture();
    fx.install("1.0.0", DESTRUCTIVE);
    for config in [
        ENABLED.to_string(),
        format!("{ENABLED}{}", state(DEFAULT_KEY, "enabled = true")),
        format!(
            "{ENABLED}{}",
            state(
                DEFAULT_KEY,
                &format!("trusted_hash = \"{DECLARED}\"\nenabled = false")
            )
        ),
        format!("{ENABLED}{}", state(DEFAULT_KEY, "trusted_hash = 5")),
        format!(
            "{ENABLED}{}",
            state(
                DEFAULT_KEY,
                &format!("trusted_hash = \"{DECLARED}\"\ntrusted_content_hash = 5")
            )
        ),
        format!(
            "{ENABLED}{}",
            state(
                DEFAULT_KEY,
                &format!("trusted_hash = \"{DECLARED}\"\nenabled = \"yes\"")
            )
        ),
    ] {
        fx.config(&config);
        assert!(fx.destructive().is_empty(), "{config}");
    }
}

#[test]
fn a_plugin_hook_is_skipped_when_requirements_allow_only_managed_hooks() {
    let fx = fixture();
    fx.install("1.0.0", DESTRUCTIVE);
    fx.config(&format!("{ENABLED}{}", trusted(DEFAULT_KEY)));
    assert_eq!(fx.destructive().len(), 1);
    fx.write(
        &fx.system.join("requirements.toml"),
        "allow_managed_hooks_only = true\n",
    );
    assert!(fx.destructive().is_empty());
}

// --- which plugins -----------------------------------------------------------------

#[test]
fn a_disabled_or_unlisted_plugin_contributes_nothing() {
    let fx = fixture();
    fx.install("1.0.0", DESTRUCTIVE);
    let state = trusted(DEFAULT_KEY);
    fx.config(&format!("[plugins.\"demo@mk\"]\nenabled = false\n{state}"));
    assert!(fx.destructive().is_empty());
    fx.config(&state);
    assert!(fx.destructive().is_empty());
    fx.config(&format!(
        "[plugins.\"demo@mk\"]\nenabled = \"yes\"\n{state}"
    ));
    assert!(fx.destructive().is_empty());
}

#[test]
fn a_plugin_entry_without_enabled_counts_as_enabled() {
    let fx = fixture();
    fx.install("1.0.0", DESTRUCTIVE);
    fx.config(&format!("[plugins.\"demo@mk\"]\n{}", trusted(DEFAULT_KEY)));
    assert_eq!(fx.destructive().len(), 1);
}

#[test]
fn only_the_ids_codex_accepts_name_a_plugin() {
    for (id, valid) in [
        ("demo@mk", true),
        ("my.plugin_2-x@mk-1", true),
        ("demo@m.k", false),
        (".demo@mk", false),
        ("demo.@mk", false),
        ("de..mo@mk", false),
        ("de mo@mk", false),
        ("démo@mk", false),
        ("a@b@mk", false),
        ("..@mk", false),
        ("demo@", false),
        ("@mk", false),
        ("demo", false),
        ("demo@C:", false),
        ("demo@mk/x", false),
        ("demo@mk\\x", false),
    ] {
        assert_eq!(parse_id(id).is_some(), valid, "{id}");
    }
}

#[test]
fn the_newest_version_folder_is_read_and_local_wins_over_it() {
    let fx = fixture();
    fx.config(&format!("{ENABLED}{}", trusted(DEFAULT_KEY)));
    fx.install("1.9.0", DESTRUCTIVE);
    let newest = default_file(&fx.install("1.10.0", DESTRUCTIVE));
    assert_eq!(fx.destructive(), vec![user_source(&newest)]);
    fx.install("v9", DESTRUCTIVE);
    let local = default_file(&fx.install("local", DESTRUCTIVE));
    assert_eq!(fx.destructive(), vec![user_source(&local)]);
}

#[test]
fn a_name_that_is_not_a_version_ranks_by_text_against_one_that_is() {
    let fx = fixture();
    fx.config(&format!("{ENABLED}{}", trusted(DEFAULT_KEY)));
    fx.install("2.0.0", DESTRUCTIVE);
    let text = default_file(&fx.install("abc", DESTRUCTIVE));
    assert_eq!(fx.destructive(), vec![user_source(&text)]);
}

// --- manifest ----------------------------------------------------------------------

#[test]
fn a_plugin_with_no_manifest_adds_nothing() {
    let fx = fixture();
    fx.write(&default_file(&fx.plugin_dir("1.0.0")), DESTRUCTIVE);
    fx.config(&format!("{ENABLED}{}", trusted(DEFAULT_KEY)));
    assert!(fx.destructive().is_empty());
}

#[test]
fn the_other_manifest_locations_are_found_and_the_first_one_wins() {
    let fx = fixture();
    let dir = fx.plugin_dir("1.0.0");
    fx.write(&default_file(&dir), DESTRUCTIVE);
    fx.config(&format!("{ENABLED}{}", trusted(DEFAULT_KEY)));
    for place in [".claude-plugin", ".cursor-plugin"] {
        fx.write(&dir.join(place).join("plugin.json"), MANIFEST);
        assert_eq!(fx.destructive().len(), 1, "{place}");
        std::fs::remove_dir_all(dir.join(place)).unwrap();
    }
    fx.write(&dir.join(".codex-plugin").join("plugin.json"), "{ not json");
    fx.write(&dir.join(".claude-plugin").join("plugin.json"), MANIFEST);
    assert!(fx.destructive().is_empty());
}

#[test]
fn a_manifest_that_does_not_load_means_the_plugin_adds_nothing() {
    let fx = fixture();
    let dir = fx.install("1.0.0", DESTRUCTIVE);
    fx.config(&format!("{ENABLED}{}", trusted(DEFAULT_KEY)));
    for manifest in ["{ not json", r#"{"name":17}"#, "[]", r#"{"keywords":[1]}"#] {
        fx.write(&dir.join(".codex-plugin").join("plugin.json"), manifest);
        assert!(fx.destructive().is_empty(), "{manifest}");
    }
}

#[test]
fn an_agent_plugin_manifest_at_the_root_has_no_hooks() {
    let fx = fixture();
    let dir = fx.install("1.0.0", DESTRUCTIVE);
    fx.config(&format!("{ENABLED}{}", trusted(DEFAULT_KEY)));
    fx.write(
        &dir.join("plugin.json"),
        r#"{"$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json","name":"demo"}"#,
    );
    assert!(fx.destructive().is_empty());
    fx.write(&dir.join("plugin.json"), r#"{"name":"unrelated"}"#);
    assert_eq!(fx.destructive().len(), 1);
}

#[test]
fn a_manifest_hooks_path_replaces_the_default_file_and_names_the_resolved_path() {
    let fx = fixture();
    let dir = fx.install("1.0.0", DESTRUCTIVE);
    fx.write(
        &dir.join(".codex-plugin").join("plugin.json"),
        r#"{"name":"demo","hooks":"./sub/./extra.json"}"#,
    );
    fx.write(&dir.join("sub").join("extra.json"), DESTRUCTIVE);
    fx.config(&format!(
        "{ENABLED}{}{}",
        trusted(DEFAULT_KEY),
        trusted("sub/extra.json:pre_tool_use:0:0")
    ));
    assert_eq!(
        fx.destructive(),
        vec![user_source(&dir.join("sub").join("extra.json"))]
    );
}

#[test]
fn a_list_of_manifest_paths_is_read_in_order_and_bad_paths_are_dropped() {
    let fx = fixture();
    let dir = fx.install("1.0.0", DESTRUCTIVE);
    fx.write(
        &dir.join(".codex-plugin").join("plugin.json"),
        r#"{"name":"demo","hooks":["./a.json","../out.json","/abs.json","b.json","./b.json"]}"#,
    );
    fx.write(&dir.join("a.json"), DESTRUCTIVE);
    fx.write(&dir.join("b.json"), DESTRUCTIVE);
    fx.config(&format!(
        "{ENABLED}{}{}",
        trusted("a.json:pre_tool_use:0:0"),
        trusted("b.json:pre_tool_use:0:0")
    ));
    assert_eq!(
        fx.destructive(),
        vec![
            user_source(&dir.join("a.json")),
            user_source(&dir.join("b.json"))
        ]
    );
}

#[test]
fn a_manifest_hooks_path_that_leaves_the_plugin_folder_falls_back_to_the_default_file() {
    let fx = fixture();
    let dir = fx.install("1.0.0", DESTRUCTIVE);
    fx.write(&dir.join("..").join("outside.json"), DESTRUCTIVE);
    fx.write(
        &dir.join(".codex-plugin").join("plugin.json"),
        r#"{"name":"demo","hooks":"./../outside.json"}"#,
    );
    fx.config(&format!(
        "{ENABLED}{}{}",
        trusted("../outside.json:pre_tool_use:0:0"),
        trusted(DEFAULT_KEY)
    ));
    assert_eq!(fx.destructive(), vec![user_source(&default_file(&dir))]);
}

#[test]
fn inline_manifest_hooks_are_keyed_by_their_index() {
    let fx = fixture();
    let dir = fx.install("1.0.0", DESTRUCTIVE);
    let manifest = dir.join(".codex-plugin").join("plugin.json");
    fx.write(
        &manifest,
        &format!(r#"{{"name":"demo","hooks":[{{"hooks":{{}}}},{DESTRUCTIVE}]}}"#),
    );
    fx.config(&format!(
        "{ENABLED}{}",
        trusted("plugin.json#hooks[1]:pre_tool_use:0:0")
    ));
    assert_eq!(fx.destructive(), vec![user_source(&manifest)]);
    fx.write(
        &manifest,
        &format!(r#"{{"name":"demo","hooks":{DESTRUCTIVE}}}"#),
    );
    fx.config(&format!(
        "{ENABLED}{}",
        trusted("plugin.json#hooks[0]:pre_tool_use:0:0")
    ));
    assert_eq!(fx.destructive(), vec![user_source(&manifest)]);
}

#[test]
fn an_invalid_inline_value_falls_back_to_the_default_file() {
    let fx = fixture();
    let dir = fx.install("1.0.0", DESTRUCTIVE);
    fx.config(&format!("{ENABLED}{}", trusted(DEFAULT_KEY)));
    for hooks in [r#"{"hooks":123}"#, r#"{"extra":1}"#, "5", "null", "[]"] {
        fx.write(
            &dir.join(".codex-plugin").join("plugin.json"),
            &format!(r#"{{"name":"demo","hooks":{hooks}}}"#),
        );
        assert_eq!(
            fx.destructive(),
            vec![user_source(&default_file(&dir))],
            "{hooks}"
        );
    }
}

#[test]
fn a_hooks_file_with_the_wrong_schema_or_json_is_skipped() {
    let fx = fixture();
    let dir = fx.install("1.0.0", DESTRUCTIVE);
    fx.config(&format!("{ENABLED}{}", trusted(DEFAULT_KEY)));
    for body in [
        "{ not json",
        r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"nope"}]}]}}"#,
        r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"command"}]}]}}"#,
        r#"{"hooks":{},"unknown":1}"#,
    ] {
        fx.write(&default_file(&dir), body);
        assert!(fx.destructive().is_empty(), "{body}");
    }
}

#[test]
fn a_named_hooks_file_that_is_missing_is_skipped() {
    let fx = fixture();
    let dir = fx.install("1.0.0", DESTRUCTIVE);
    fx.write(
        &dir.join(".codex-plugin").join("plugin.json"),
        r#"{"name":"demo","hooks":"./gone.json"}"#,
    );
    fx.config(&format!(
        "{ENABLED}{}",
        trusted("gone.json:pre_tool_use:0:0")
    ));
    assert!(fx.destructive().is_empty());
}

// --- containment and bounds --------------------------------------------------------

#[cfg(unix)]
#[test]
fn a_link_at_an_ancestor_of_the_plugin_does_not_leave_the_codex_folder() {
    let fx = fixture();
    let outside = fx._root.path().join("elsewhere");
    let real = outside.join("mk").join("demo").join("1.0.0");
    fx.write(&real.join(".codex-plugin").join("plugin.json"), MANIFEST);
    fx.write(&default_file(&real), DESTRUCTIVE);
    std::fs::create_dir_all(fx.codex.join("plugins")).unwrap();
    std::os::unix::fs::symlink(&outside, fx.codex.join("plugins").join("cache")).unwrap();
    fx.config(&format!("{ENABLED}{}", trusted(DEFAULT_KEY)));
    assert!(fx.destructive().is_empty());
}

#[cfg(unix)]
#[test]
fn a_link_to_a_folder_inside_the_codex_folder_is_followed() {
    let fx = fixture();
    let real = fx.codex.join("store");
    fx.write(
        &real
            .join("mk")
            .join("demo")
            .join("1.0.0")
            .join(".codex-plugin")
            .join("plugin.json"),
        MANIFEST,
    );
    fx.write(
        &default_file(&real.join("mk").join("demo").join("1.0.0")),
        DESTRUCTIVE,
    );
    std::fs::create_dir_all(fx.codex.join("plugins")).unwrap();
    std::os::unix::fs::symlink(&real, fx.codex.join("plugins").join("cache")).unwrap();
    fx.config(&format!("{ENABLED}{}", trusted(DEFAULT_KEY)));
    assert_eq!(fx.destructive().len(), 1);
}

#[cfg(unix)]
#[test]
fn a_link_inside_the_bundle_is_not_read_and_stops_the_folder_hash() {
    let fx = fixture();
    let dir = fx.install("1.0.0", DESTRUCTIVE);
    let outside = fx._root.path().join("outside.json");
    std::fs::write(&outside, DESTRUCTIVE).unwrap();
    std::fs::remove_file(default_file(&dir)).unwrap();
    std::os::unix::fs::symlink(&outside, default_file(&dir)).unwrap();
    fx.config(&format!("{ENABLED}{}", trusted(DEFAULT_KEY)));
    assert!(fx.destructive().is_empty());
    assert!(content_hash(&dir).is_err());
}

#[cfg(unix)]
#[test]
fn a_manifest_link_that_leaves_the_codex_folder_is_not_read() {
    let fx = fixture();
    let dir = fx.install("1.0.0", DESTRUCTIVE);
    let outside = fx._root.path().join("manifest.json");
    std::fs::write(&outside, MANIFEST).unwrap();
    let manifest = dir.join(".codex-plugin").join("plugin.json");
    std::fs::remove_file(&manifest).unwrap();
    std::os::unix::fs::symlink(&outside, &manifest).unwrap();
    fx.config(&format!("{ENABLED}{}", trusted(DEFAULT_KEY)));
    assert!(fx.destructive().is_empty());
}

#[cfg(unix)]
#[test]
fn a_hooks_file_that_is_not_a_regular_file_is_skipped_without_blocking() {
    let fx = fixture();
    let dir = fx.install("1.0.0", DESTRUCTIVE);
    std::fs::remove_file(default_file(&dir)).unwrap();
    let fifo = std::ffi::CString::new(default_file(&dir).to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    fx.config(&format!("{ENABLED}{}", trusted(DEFAULT_KEY)));
    assert!(fx.destructive().is_empty());
}

#[cfg(unix)]
#[test]
fn a_named_hooks_file_that_is_not_a_regular_file_is_skipped_without_blocking() {
    let fx = fixture();
    let dir = fx.install("1.0.0", DESTRUCTIVE);
    fx.write(
        &dir.join(".codex-plugin").join("plugin.json"),
        r#"{"name":"demo","hooks":["./fifo.json","./folder.json"]}"#,
    );
    let fifo = std::ffi::CString::new(dir.join("fifo.json").to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    std::fs::create_dir_all(dir.join("folder.json")).unwrap();
    fx.config(&format!(
        "{ENABLED}{}{}",
        trusted("fifo.json:pre_tool_use:0:0"),
        trusted("folder.json:pre_tool_use:0:0")
    ));
    assert!(fx.destructive().is_empty());
}

#[test]
fn a_hooks_or_manifest_file_over_the_byte_cap_is_skipped() {
    let fx = fixture();
    let dir = fx.install("1.0.0", DESTRUCTIVE);
    fx.config(&format!("{ENABLED}{}", trusted(DEFAULT_KEY)));
    let padding = " ".repeat(MAX_JSON_BYTES as usize);
    fx.write(&default_file(&dir), &format!("{DESTRUCTIVE}{padding}"));
    assert!(fx.destructive().is_empty());
    fx.write(&default_file(&dir), DESTRUCTIVE);
    assert_eq!(fx.destructive().len(), 1);
    fx.write(
        &dir.join(".codex-plugin").join("plugin.json"),
        &format!("{MANIFEST}{padding}"),
    );
    assert!(fx.destructive().is_empty());
}

#[test]
fn the_folder_hash_stops_at_each_cap() {
    let root = tempdir().unwrap();
    for i in 0..4 {
        std::fs::write(root.path().join(format!("f{i}")), "xx").unwrap();
    }
    std::fs::create_dir_all(root.path().join("d")).unwrap();
    let caps = |files, entries, bytes| Caps {
        files,
        entries,
        bytes,
    };
    assert!(content_hash_with(root.path(), caps(4, 6, 8)).is_ok());
    assert!(
        content_hash_with(root.path(), caps(3, 6, 8)).is_err(),
        "files"
    );
    assert!(
        content_hash_with(root.path(), caps(4, 5, 8)).is_err(),
        "entries"
    );
    assert!(
        content_hash_with(root.path(), caps(4, 6, 7)).is_err(),
        "bytes"
    );
}

#[test]
fn a_plugin_without_a_state_row_is_not_even_a_candidate() {
    let fx = fixture();
    let config: Value = toml::from_str(&format!("{ENABLED}{}", trusted(DEFAULT_KEY))).unwrap();
    let states = config
        .get("hooks")
        .and_then(|h| h.get("state"))
        .and_then(Value::as_table);
    assert_eq!(candidates(&fx.codex, Some(&config), states).len(), 1);
    assert!(candidates(&fx.codex, Some(&config), None).is_empty());
    let other: Value =
        toml::from_str("[hooks.state.'other@mk:x:pre_tool_use:0:0']\ntrusted_hash='a'").unwrap();
    let other_states = other
        .get("hooks")
        .and_then(|h| h.get("state"))
        .and_then(Value::as_table);
    assert!(candidates(&fx.codex, Some(&config), other_states).is_empty());
}

// --- folder hash -------------------------------------------------------------------

#[test]
fn the_content_hash_matches_the_codex_bundle_fingerprint() {
    let root = tempdir().unwrap();
    std::fs::write(root.path().join("a.txt"), "hi").unwrap();
    std::fs::write(root.path().join("b.txt"), "yo").unwrap();
    std::fs::create_dir_all(root.path().join("__pycache__")).unwrap();
    std::fs::write(root.path().join("__pycache__").join("c"), "x").unwrap();
    assert_eq!(
        content_hash(root.path()).unwrap(),
        "sha256:4a206b41951ed24079c3fc6916ca6dc307beb5c7c17662c465b091e0225da9db"
    );
}

/// Codex hashes a nested path with the separator of its platform.
#[cfg(unix)]
#[test]
fn the_content_hash_covers_a_nested_folder() {
    let root = tempdir().unwrap();
    std::fs::write(root.path().join("a.txt"), "hi").unwrap();
    std::fs::create_dir_all(root.path().join("d")).unwrap();
    std::fs::write(root.path().join("d").join("b.txt"), "yo").unwrap();
    assert_eq!(
        content_hash(root.path()).unwrap(),
        "sha256:d59b660b0c174d266ea94cbc88c3be574c5268db0608e06f7b761b3be7792cef"
    );
}

#[test]
fn the_content_hash_leaves_out_caches_environments_and_package_metadata() {
    let root = tempdir().unwrap();
    std::fs::write(root.path().join("a.txt"), "hi").unwrap();
    let base = content_hash(root.path()).unwrap();
    for (dir, file) in [
        ("__pycache__", "x"),
        (".venv", "x"),
        ("pkg.egg-info", "x"),
        ("sub", "m.pyc"),
    ] {
        std::fs::create_dir_all(root.path().join(dir)).unwrap();
        std::fs::write(root.path().join(dir).join(file), "x").unwrap();
    }
    std::fs::write(root.path().join("top.pyc"), "x").unwrap();
    std::fs::create_dir_all(root.path().join("sub")).unwrap();
    std::fs::remove_dir_all(root.path().join("sub")).unwrap();
    assert_eq!(content_hash(root.path()).unwrap(), base);
    std::fs::write(root.path().join("b.txt"), "x").unwrap();
    assert_ne!(content_hash(root.path()).unwrap(), base);
}

#[cfg(unix)]
#[test]
fn a_directory_link_inside_the_bundle_does_not_lead_a_named_file_out_of_the_codex_folder() {
    let fx = fixture();
    let dir = fx.install("1.0.0", DESTRUCTIVE);
    let outside = fx._root.path().join("outside");
    fx.write(&outside.join("named.json"), DESTRUCTIVE);
    std::os::unix::fs::symlink(&outside, dir.join("sub")).unwrap();
    fx.write(
        &dir.join(".codex-plugin").join("plugin.json"),
        r#"{"name":"demo","hooks":"./sub/named.json"}"#,
    );
    fx.config(&format!(
        "{ENABLED}{}",
        trusted("sub/named.json:pre_tool_use:0:0")
    ));
    assert!(fx.destructive().is_empty());
    assert!(content_hash(&dir).is_err());
}

#[cfg(unix)]
#[test]
fn a_backslash_in_a_manifest_path_stays_in_the_file_name_and_becomes_a_slash_in_the_key() {
    let fx = fixture();
    let dir = fx.install("1.0.0", DESTRUCTIVE);
    fx.write(
        &dir.join(".codex-plugin").join("plugin.json"),
        r#"{"name":"demo","hooks":"./sub\\named.json"}"#,
    );
    let file = dir.join("sub\\named.json");
    fx.write(&file, DESTRUCTIVE);
    fx.config(&format!(
        "{ENABLED}{}",
        trusted("sub/named.json:pre_tool_use:0:0")
    ));
    assert_eq!(fx.destructive(), vec![user_source(&file)]);
}

#[test]
fn a_hooks_file_named_twice_is_read_once() {
    let fx = fixture();
    let dir = fx.install("1.0.0", DESTRUCTIVE);
    fx.write(
        &dir.join(".codex-plugin").join("plugin.json"),
        r#"{"name":"demo","hooks":["./a.json","./a.json","./sub/../a.json","./a.json"]}"#,
    );
    fx.write(&dir.join("a.json"), DESTRUCTIVE);
    fx.config(&format!("{ENABLED}{}", trusted("a.json:pre_tool_use:0:0")));
    assert_eq!(fx.destructive().len(), 1);
}

#[test]
fn a_plugin_with_too_many_version_folders_is_skipped() {
    let fx = fixture();
    fx.install("1.0.0", DESTRUCTIVE);
    fx.config(&format!("{ENABLED}{}", trusted(DEFAULT_KEY)));
    let base = fx.plugin_dir("1.0.0").parent().unwrap().to_path_buf();
    for i in 0..MAX_VERSION_FOLDERS - 1 {
        std::fs::create_dir_all(base.join(format!("0.0.{i}"))).unwrap();
    }
    assert_eq!(fx.destructive().len(), 1);
    std::fs::create_dir_all(base.join("0.1.0")).unwrap();
    assert!(fx.destructive().is_empty());
}
