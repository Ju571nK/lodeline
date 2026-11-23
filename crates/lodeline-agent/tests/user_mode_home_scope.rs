//! A policy target that starts with `~` expands over every listed user home,
//! while a `$HOME` target expands to the home the environment names. The
//! user list and the environment are stubs, so no real home is read.
//!
//! Pins current behaviour; change with the user-mode home scope decision.

use lodeline_core::policy::expand::{expand_per_user, UserContext, VarLookup};
use std::path::PathBuf;

struct CustomHomeEnv(PathBuf);

impl VarLookup for CustomHomeEnv {
    fn lookup(&self, name: &str) -> Option<String> {
        (name == "HOME").then(|| self.0.to_string_lossy().into_owned())
    }
    fn home(&self) -> Option<PathBuf> {
        Some(self.0.clone())
    }
}

fn user(name: &str, uid: &str) -> UserContext {
    UserContext {
        name: name.into(),
        home: PathBuf::from("/listed").join(name),
        uid_or_sid: uid.into(),
    }
}

fn expand_ok(template: &str, users: &[UserContext], env: &CustomHomeEnv) -> Vec<PathBuf> {
    expand_per_user(template, users, env)
        .into_iter()
        .map(|r| r.unwrap())
        .collect()
}

#[test]
fn tilde_target_expands_to_listed_homes_not_the_custom_home() {
    let custom = PathBuf::from("/custom/home");
    let users = [user("alice", "501"), user("bob", "502")];
    let got = expand_ok("~/.claude/settings.json", &users, &CustomHomeEnv(custom));
    assert_eq!(
        got,
        vec![
            PathBuf::from("/listed/alice/.claude/settings.json"),
            PathBuf::from("/listed/bob/.claude/settings.json"),
        ]
    );
}

#[test]
fn home_variable_target_expands_once_to_the_custom_home() {
    let custom = PathBuf::from("/custom/home");
    let users = [user("alice", "501"), user("bob", "502")];
    let got = expand_ok(
        "$HOME/.claude/settings.json",
        &users,
        &CustomHomeEnv(custom.clone()),
    );
    assert_eq!(got, vec![custom.join(".claude/settings.json")]);
}
