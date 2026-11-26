//! Windows user profiles from the registry `ProfileList` key. The filtering is a plain
//! function so its tests run on every OS.

use lodeline_core::policy::expand::UserContext;
use std::path::{Path, PathBuf};

/// One subkey of `ProfileList`: the SID and its `ProfileImagePath` value, unexpanded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProfileEntry {
    pub(crate) sid: String,
    pub(crate) image_path: String,
}

/// Local, domain and Entra ID users. Service accounts (`S-1-5-18`, `-19`, `-20`) and
/// every other SID are not users.
fn is_user_sid(sid: &str) -> bool {
    sid.starts_with("S-1-5-21-") || sid.starts_with("S-1-12-1-")
}

/// Replace `%SystemDrive%` (any case) with `system_drive`.
fn expand_system_drive(path: &str, system_drive: &str) -> String {
    const TOKEN: &str = "%systemdrive%";
    match path.to_ascii_lowercase().find(TOKEN) {
        Some(at) => format!(
            "{}{}{}",
            &path[..at],
            system_drive,
            &path[at + TOKEN.len()..]
        ),
        None => path.to_string(),
    }
}

/// The users behind `entries`: the folder name is `name`, the SID is `uid_or_sid`.
/// A profile whose folder is gone is skipped. Sorted by name, then SID.
pub(crate) fn users_from_profiles(
    entries: &[ProfileEntry],
    system_drive: &str,
    dir_exists: impl Fn(&Path) -> bool,
) -> Vec<UserContext> {
    let mut users: Vec<UserContext> = entries
        .iter()
        .filter(|e| is_user_sid(&e.sid))
        .filter_map(|e| {
            let expanded = expand_system_drive(&e.image_path, system_drive);
            let home = PathBuf::from(&expanded);
            if !dir_exists(&home) {
                return None;
            }
            let name = expanded
                .trim_end_matches(['\\', '/'])
                .rsplit(['\\', '/'])
                .next()
                .filter(|n| !n.is_empty())?
                .to_string();
            Some(UserContext {
                name,
                home,
                uid_or_sid: e.sid.clone(),
            })
        })
        .collect();
    users.sort_by(|a, b| (&a.name, &a.uid_or_sid).cmp(&(&b.name, &b.uid_or_sid)));
    users
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(sid: &str, path: &str) -> ProfileEntry {
        ProfileEntry {
            sid: sid.into(),
            image_path: path.into(),
        }
    }

    #[test]
    fn keeps_user_sids_and_skips_service_and_other_sids() {
        let entries = [
            entry("S-1-5-18", r"C:\Windows\system32\config\systemprofile"),
            entry("S-1-5-19", r"C:\Windows\ServiceProfiles\LocalService"),
            entry("S-1-5-20", r"C:\Windows\ServiceProfiles\NetworkService"),
            entry("S-1-5-80-1-2", r"C:\Users\svc"),
            entry("S-1-5-21-1-2-3-1001", r"C:\Users\alice"),
            entry("S-1-12-1-9-8-7-6", r"C:\Users\bob"),
        ];
        let users = users_from_profiles(&entries, "C:", |_| true);
        let got: Vec<_> = users
            .iter()
            .map(|u| (u.name.as_str(), u.uid_or_sid.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("alice", "S-1-5-21-1-2-3-1001"),
                ("bob", "S-1-12-1-9-8-7-6")
            ]
        );
    }

    #[test]
    fn expands_system_drive_and_skips_missing_folders() {
        let entries = [
            entry("S-1-5-21-1-2-3-1001", r"%SystemDrive%\Users\alice"),
            entry("S-1-5-21-1-2-3-1002", r"%SYSTEMDRIVE%\Users\gone"),
        ];
        let users = users_from_profiles(&entries, "D:", |p| p == Path::new(r"D:\Users\alice"));
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].home, PathBuf::from(r"D:\Users\alice"));
        assert_eq!(users[0].name, "alice");
    }

    #[test]
    fn name_is_the_folder_name_not_the_account_name() {
        let entries = [entry("S-1-5-21-1-2-3-1001", r"C:\Users\alice.DESKTOP")];
        let users = users_from_profiles(&entries, "C:", |_| true);
        assert_eq!(users[0].name, "alice.DESKTOP");
    }

    #[test]
    fn a_non_ascii_folder_name_is_kept() {
        let entries = [entry(
            "S-1-5-21-1-2-3-1001",
            "%SystemDrive%\\Users\\\u{d14c}\u{c2a4}\u{d130}",
        )];
        let users = users_from_profiles(&entries, "C:", |_| true);
        assert_eq!(users[0].name, "\u{d14c}\u{c2a4}\u{d130}");
        assert_eq!(
            users[0].home,
            PathBuf::from("C:\\Users\\\u{d14c}\u{c2a4}\u{d130}")
        );
    }
}
