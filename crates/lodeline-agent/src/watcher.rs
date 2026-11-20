//! `notify` integration. Bridges OS-thread callbacks to a tokio mpsc.

use lodeline_core::event::FileChangeKind;
use notify::{
    event::{CreateKind, EventKind as NEvent, ModifyKind, RenameMode},
    Config, Event, PollWatcher, RecommendedWatcher, RecursiveMode, Watcher,
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, Weak};
use std::time::{Duration, SystemTime};
use thiserror::Error;
use tokio::sync::{mpsc, watch};

#[derive(Debug, Error)]
pub enum WatcherError {
    #[error("notify: {0}")]
    Notify(#[from] notify::Error),
    #[error("send to bridge channel failed (receiver dropped)")]
    BridgeClosed,
}

#[derive(Debug, Clone)]
pub struct RawFsEvent {
    pub path: PathBuf,
    pub kind: FileChangeKind,
    pub rename_id: Option<u64>, // notify reports a tracker id we surface for pairing
}

/// Holds the live OS watcher (keeping its thread alive) and lets callers
/// add/remove watch roots after construction.
pub struct WatcherHandle {
    pub backend_name: &'static str,
    watcher: Arc<Mutex<BackendWatcher>>,
    desired: BTreeMap<PathBuf, bool>,
    resolved: BTreeMap<PathBuf, bool>,
    active: BTreeMap<PathBuf, (bool, RootIdentity, PathBuf)>,
    catchups: BTreeMap<PathBuf, tokio::task::JoinHandle<()>>,
    tx: Arc<mpsc::Sender<RawFsEvent>>,
    runtime: tokio::runtime::Handle,
    /// Watched file paths to check each tick for being a link to a regular file.
    files: Vec<PathBuf>,
    aliases_tx: watch::Sender<crate::normalizer::AliasTable>,
    /// Link problems already logged, so a tick does not repeat them.
    warned: BTreeSet<(PathBuf, &'static str)>,
    activity: Arc<RootActivity>,
    /// Quiet time after which an active directory root is re-armed. `None` never re-arms.
    rearm_after: Option<Duration>,
}

/// ReadDirectoryChangesW can end a directory watch without telling the agent (#627), and a
/// root with traffic proves its watch is armed, so only a root quiet this long is re-armed.
/// Fifteen minutes keeps the cost to one handle and one listing per idle root per period.
const WINDOWS_REARM_AFTER: Duration = Duration::from_secs(15 * 60);

/// When each active root last had an event, or was armed if it has had none. The notify
/// callback writes it, so a root is told apart by the path prefix of an event.
#[derive(Default)]
struct RootActivity {
    last_live: Mutex<BTreeMap<PathBuf, SystemTime>>,
}

impl RootActivity {
    fn lock(&self) -> MutexGuard<'_, BTreeMap<PathBuf, SystemTime>> {
        self.last_live
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn arm(&self, root: &Path) {
        self.lock().insert(root.to_path_buf(), SystemTime::now());
    }

    fn disarm(&self, root: &Path) {
        self.lock().remove(root);
    }

    fn since(&self, root: &Path) -> Option<SystemTime> {
        self.lock().get(root).copied()
    }

    fn note(&self, paths: &[PathBuf]) {
        let now = SystemTime::now();
        for (root, last) in self.lock().iter_mut() {
            if paths.iter().any(|path| path.starts_with(root)) {
                *last = now;
            }
        }
    }
}

/// The files a re-arm listing sends: those created or modified after `after`, the last
/// moment the old watch was known to be live, up to `until`, when the new watch was in
/// place and its own events take over. A file untouched since its last event has an
/// older time, so it is not sent again.
#[derive(Clone, Copy)]
struct ChangeWindow {
    after: SystemTime,
    until: SystemTime,
}

impl ChangeWindow {
    fn holds(&self, meta: &std::fs::Metadata) -> bool {
        let latest = [meta.modified().ok(), meta.created().ok()]
            .into_iter()
            .flatten()
            .max();
        latest.is_some_and(|time| self.after < time && time <= self.until)
    }
}

pub(crate) const ROOT_RECHECK_INTERVAL: Duration = Duration::from_secs(5);

#[derive(PartialEq, Eq)]
struct RootIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    file: same_file::Handle,
    #[cfg(not(any(unix, windows)))]
    created: Option<std::time::SystemTime>,
}

impl RootIdentity {
    fn read(path: &Path) -> std::io::Result<Self> {
        #[cfg(not(windows))]
        let metadata = std::fs::metadata(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        #[cfg(windows)]
        {
            // Creation times can survive replacement (NTFS tunneling). Keep a
            // handle open and compare volume/file IDs, not timestamps.
            Ok(Self {
                file: same_file::Handle::from_path(path)?,
            })
        }
        #[cfg(not(any(unix, windows)))]
        Ok(Self {
            created: metadata.created().ok(),
        })
    }
}

enum BackendWatcher {
    Native(RecommendedWatcher),
    Poll(PollWatcher),
}

impl BackendWatcher {
    fn as_watcher_mut(&mut self) -> &mut dyn Watcher {
        match self {
            BackendWatcher::Native(w) => w,
            BackendWatcher::Poll(w) => w,
        }
    }
}

impl WatcherHandle {
    fn backend(&self) -> MutexGuard<'_, BackendWatcher> {
        self.watcher.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The `(real path, link path)` pairs of the followed file links. The pipeline
    /// spells an event under the real path as the link, as the operator wrote it.
    pub fn aliases_rx(&self) -> watch::Receiver<crate::normalizer::AliasTable> {
        self.aliases_tx.subscribe()
    }

    /// Set the watched file paths. Each one that is a link to a regular file is
    /// watched under its link path and aliased from its target.
    pub fn follow_files(&mut self, files: Vec<PathBuf>, catch_up: bool) {
        self.files = files;
        let _ = self.rebuild_roots(catch_up);
    }

    /// Record desired coverage, including failed registrations, for retry.
    pub fn watch(&mut self, root: &Path, recursive: bool) -> notify::Result<()> {
        let requested = resolve_directory_pattern(root);
        self.desired.insert(root.to_path_buf(), recursive);
        let mut errors = self.rebuild_roots(true);
        for path in requested {
            if let Some(error) = errors.remove(&path) {
                return Err(error);
            }
        }
        Ok(())
    }

    fn refresh_root(&mut self, root: &Path, catch_up: bool) -> notify::Result<()> {
        let recursive = self.resolved[root];
        let identity = RootIdentity::read(root);
        if let (Some((mode, previous, _)), Ok(current)) = (self.active.get(root), &identity) {
            if *mode == recursive && previous == current {
                return Ok(());
            }
        }
        // A deleted/replaced directory may retain a stale backend subscription.
        if let Some((_, _, registered)) = self.active.remove(root) {
            self.activity.disarm(root);
            let _ = self.backend().as_watcher_mut().unwatch(&registered);
        }
        if let Some(task) = self.catchups.remove(root) {
            task.abort();
        }
        let identity = identity.map_err(notify::Error::io)?;
        let mode = if recursive {
            RecursiveMode::Recursive
        } else {
            RecursiveMode::NonRecursive
        };
        let registered = self.backend_path(root);
        self.backend().as_watcher_mut().watch(&registered, mode)?;
        self.active
            .insert(root.to_path_buf(), (recursive, identity, registered));
        self.activity.arm(root);
        if catch_up {
            // Register first, then replay current files to cover the subscription gap.
            let task = self.runtime.spawn(catch_up_files(
                root.to_path_buf(),
                recursive,
                self.tx.clone(),
                None,
            ));
            self.catchups.insert(root.to_path_buf(), task);
            tracing::info!(root = %root.display(), recursive, "watch root recovered; scanning current files");
        }
        Ok(())
    }

    /// Expand only the directory components of configured patterns. Discovery
    /// never creates a recursive subscription on a broad ancestor (#223).
    fn rebuild_roots(&mut self, catch_up: bool) -> BTreeMap<PathBuf, notify::Error> {
        let mut resolved = BTreeMap::new();
        let mut matched = BTreeSet::new();
        let mut folder_links = BTreeSet::new();
        for (pattern, recursive) in &self.desired {
            for (root, via_link) in resolve_pattern(pattern) {
                if via_link {
                    folder_links.insert(root);
                    continue;
                }
                if has_glob(pattern) {
                    matched.insert(root.clone());
                }
                *resolved.entry(root).or_default() |= recursive;
            }
        }
        // A real folder that a wildcard found inside a recursive root is covered by it.
        let recursive_roots: Vec<_> = resolved
            .iter()
            .filter(|(_, recursive)| **recursive)
            .map(|(root, _)| root.clone())
            .collect();
        resolved.retain(|root, recursive| {
            *recursive
                || !matched.contains(root)
                || self.desired.contains_key(root)
                || !recursive_roots.iter().any(|r| root.starts_with(r))
        });
        // Publish the aliases before a root registers and re-reads its file.
        let links = self.follow_links(&resolved, folder_links);
        for (_, link) in &links {
            resolved.insert(link.clone(), false);
        }
        self.aliases_tx.send_if_modified(|table| {
            let changed = **table != links;
            if changed {
                *table = Arc::new(links);
            }
            changed
        });
        let obsolete: Vec<_> = self
            .resolved
            .keys()
            .filter(|root| !resolved.contains_key(*root))
            .cloned()
            .collect();
        for root in obsolete {
            // Backends may already have forgotten a deleted directory.
            let _ = self.remove_active(&root);
        }
        self.resolved = resolved;
        let mut errors = BTreeMap::new();
        for root in self.resolved.keys().cloned().collect::<Vec<_>>() {
            if let Err(error) = self.refresh_root(&root, catch_up) {
                tracing::debug!(root = %root.display(), %error, "watch root unavailable; will retry");
                errors.insert(root, error);
            }
        }
        errors
    }

    /// The `(real path, link path)` pair of each watched file or wildcard folder
    /// that is a link, in policy order. A link is left out, with one warning, when
    /// its target is missing or a watched root already covers it. A folder link is
    /// also left out when its target holds a watched folder, as `/` does. Two file
    /// links to one target both stay, and the first matches. A second folder link
    /// to one target is left out, so the folder gets one subscription.
    fn follow_links(
        &mut self,
        roots: &BTreeMap<PathBuf, bool>,
        folders: BTreeSet<PathBuf>,
    ) -> Vec<(PathBuf, PathBuf)> {
        let mut links: Vec<(PathBuf, PathBuf)> = Vec::new();
        let files: Vec<PathBuf> = self
            .files
            .iter()
            .flat_map(|file| {
                if has_glob(file) {
                    leaf_links(file)
                } else {
                    vec![file.clone()]
                }
            })
            .collect();
        for link in files {
            if !std::fs::symlink_metadata(&link).is_ok_and(|m| m.is_symlink()) {
                continue;
            }
            let Ok(real) = dunce::canonicalize(&link) else {
                self.warn_once(
                    &link,
                    "dangling",
                    "watched file is a link to a missing target",
                );
                continue;
            };
            if !real.is_file() {
                continue;
            }
            let real = crate::normalizer::match_form(real);
            if is_covered(roots, &link, &real, false) {
                self.warn_once(
                    &link,
                    "in-root",
                    "link target is in a watched root; not followed",
                );
                continue;
            }
            if links.iter().any(|(other, _)| *other == real) {
                self.warn_once(
                    &link,
                    "shared",
                    "link shares its target with an earlier link",
                );
            }
            links.push((real, link));
        }
        for link in folders {
            let Ok(real) = dunce::canonicalize(&link) else {
                continue;
            };
            let real = crate::normalizer::match_form(real);
            if is_covered(roots, &link, &real, true) {
                self.warn_once(
                    &link,
                    "in-root",
                    "link target is in a watched root; not followed",
                );
            } else if real.parent().is_none()
                || link.starts_with(&real)
                || roots.keys().any(|root| root.starts_with(&real))
            {
                self.warn_once(
                    &link,
                    "parent",
                    "link target is a parent of a watched folder; not followed",
                );
            } else if links.iter().any(|(other, _)| *other == real) {
                self.warn_once(
                    &link,
                    "shared",
                    "link shares its target with an earlier link",
                );
            } else {
                links.push((real, link));
            }
        }
        links
    }

    fn warn_once(&mut self, link: &Path, kind: &'static str, message: &str) {
        if self.warned.insert((link.to_path_buf(), kind)) {
            tracing::warn!(link = %link.display(), "{message}");
        }
    }

    /// Check only configured roots, never recursively subscribe to an ancestor.
    pub(crate) fn reconcile(&mut self) {
        self.catchups.retain(|_, task| !task.is_finished());
        let _ = self.rebuild_roots(true);
        self.rearm_idle_roots();
    }

    /// Start the watch of each quiet directory root again and list what changed while
    /// the old watch may have been down (#627). A root whose directory is gone is left
    /// to `rebuild_roots`.
    fn rearm_idle_roots(&mut self) {
        let Some(quiet) = self.rearm_after.filter(|_| false) else {
            return;
        };
        if matches!(*self.backend(), BackendWatcher::Poll(_)) {
            return;
        }
        let idle: Vec<_> = self
            .active
            .keys()
            .filter(|root| root.is_dir())
            .filter(|root| {
                self.activity.since(root).is_some_and(|last| {
                    SystemTime::now()
                        .duration_since(last)
                        .is_ok_and(|elapsed| elapsed >= quiet)
                })
            })
            .cloned()
            .collect();
        for root in idle {
            self.rearm(&root);
        }
    }

    fn rearm(&mut self, root: &Path) {
        let Some(after) = self.activity.since(root) else {
            return;
        };
        let Some((recursive, registered)) = self
            .active
            .get(root)
            .map(|(recursive, _, registered)| (*recursive, registered.clone()))
        else {
            return;
        };
        if let Some(task) = self.catchups.remove(root) {
            task.abort();
        }
        let mode = if recursive {
            RecursiveMode::Recursive
        } else {
            RecursiveMode::NonRecursive
        };
        let rewatched = {
            let mut backend = self.backend();
            let watcher = backend.as_watcher_mut();
            let _ = watcher.unwatch(&registered);
            watcher.watch(&registered, mode)
        };
        tracing::warn!(root = %root.display(), recursive, "watch root re-armed after a quiet period");
        if let Err(error) = rewatched {
            tracing::debug!(root = %root.display(), %error, "re-armed watch root unavailable; will retry");
            self.active.remove(root);
            self.activity.disarm(root);
            return;
        }
        self.activity.arm(root);
        let window = ChangeWindow {
            after,
            until: SystemTime::now(),
        };
        let task = self.runtime.spawn(catch_up_files(
            root.to_path_buf(),
            recursive,
            self.tx.clone(),
            Some(window),
        ));
        self.catchups.insert(root.to_path_buf(), task);
    }

    /// Stop watching a root.
    pub fn unwatch(&mut self, root: &Path) -> notify::Result<()> {
        self.desired.remove(root);
        // Other desired patterns may still own some of the same concrete roots.
        self.reconcile();
        Ok(())
    }

    fn remove_active(&mut self, root: &Path) -> notify::Result<()> {
        self.activity.disarm(root);
        if let Some(task) = self.catchups.remove(root) {
            task.abort();
        }
        match self.active.remove(root) {
            Some((_, _, registered)) => self.backend().as_watcher_mut().unwatch(&registered),
            None => Ok(()),
        }
    }

    /// The path the backend watches for `root`. The polling backend does not
    /// follow links, and reads the modification time of a linked file from the
    /// link itself, so it watches the file the link points to. Events under it are
    /// spelled as the link through the alias table.
    fn backend_path(&self, root: &Path) -> PathBuf {
        let linked_file = matches!(*self.backend(), BackendWatcher::Poll(_))
            && std::fs::symlink_metadata(root).is_ok_and(|m| m.is_symlink())
            && std::fs::metadata(root).is_ok_and(|m| !m.is_dir());
        if linked_file {
            if let Ok(real) = dunce::canonicalize(root) {
                return real;
            }
        }
        root.to_path_buf()
    }
}

/// True when a watched root already covers `real`. A folder watched without
/// recursion covers only the files directly in it, and the link's own folder does
/// not count, so a link to a sibling is followed.
fn is_covered(roots: &BTreeMap<PathBuf, bool>, link: &Path, real: &Path, folder: bool) -> bool {
    roots.iter().any(|(root, recursive)| {
        root == real
            || if !*recursive && link.parent() == Some(root) {
                false
            } else if *recursive {
                real.starts_with(root)
            } else {
                !folder && real.parent() == Some(root)
            }
    })
}

/// The links to regular files that a wildcard leaf such as `agents/*.md` matches.
/// The folder must be a literal path, so this goes one level and no further.
fn leaf_links(pattern: &Path) -> Vec<PathBuf> {
    let (Some(dir), Some(name)) = (pattern.parent(), pattern.file_name()) else {
        return Vec::new();
    };
    if has_glob(dir) || !has_glob(Path::new(name)) {
        return Vec::new();
    }
    let Ok(glob) = lodeline_core::policy::glob::CompiledGlob::new(&pattern.to_string_lossy())
    else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .take(crate::runtime::WARMUP_ENTRY_LIMIT)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_symlink()))
        .map(|entry| entry.path())
        .filter(|path| glob.is_match(&crate::normalizer::match_form(path.clone())))
        .take(crate::runtime::WARMUP_FILE_LIMIT)
        .collect()
}

/// The folder `link` leads to, when `link` is a link to a folder that is not `/`
/// and does not hold the link itself.
pub(crate) fn linked_folder(link: &Path) -> Option<PathBuf> {
    let real = crate::normalizer::match_form(dunce::canonicalize(link).ok()?);
    (real.is_dir() && real.parent().is_some() && !link.starts_with(&real)).then_some(real)
}

fn has_glob(path: &Path) -> bool {
    path.to_string_lossy()
        .contains(['*', '?', '[', ']', '{', '}'])
}

fn resolve_directory_pattern(pattern: &Path) -> Vec<PathBuf> {
    resolve_pattern(pattern)
        .into_iter()
        .map(|(root, _)| root)
        .collect()
}

/// Walk one directory level per pattern component, not an entire subtree.
/// Literal missing roots retain #219's retry behavior; wildcard roots are
/// discovered afresh so installation/removal/replacement needs no restart.
/// A link to a folder counts as a folder at the first wildcard component only,
/// and its root is flagged. A link under it, or a literal link, is not followed.
fn resolve_pattern(pattern: &Path) -> Vec<(PathBuf, bool)> {
    if !has_glob(pattern) {
        return vec![(pattern.to_path_buf(), false)];
    }
    let mut candidates = vec![(PathBuf::new(), false)];
    let mut in_pattern = false;
    for component in pattern.components() {
        let part = Path::new(component.as_os_str());
        if has_glob(part) {
            let first = !in_pattern;
            in_pattern = true;
            let Ok(glob) = lodeline_core::policy::glob::CompiledGlob::new(&part.to_string_lossy())
            else {
                return Vec::new();
            };
            let mut matches = Vec::new();
            for (parent, via_link) in candidates {
                let Ok(entries) = std::fs::read_dir(&parent) else {
                    continue;
                };
                for entry in entries.flatten() {
                    let Ok(kind) = entry.file_type() else {
                        continue;
                    };
                    let linked = first
                        && kind.is_symlink()
                        && std::fs::metadata(entry.path()).is_ok_and(|m| m.is_dir());
                    if (kind.is_dir() || linked)
                        && glob.is_match(&crate::normalizer::match_form(entry.file_name().into()))
                    {
                        matches.push((entry.path(), via_link || linked));
                    }
                }
            }
            candidates = matches;
        } else {
            candidates = candidates
                .into_iter()
                .filter_map(|(mut parent, via_link)| {
                    parent.push(part);
                    // Do not follow a wildcard match's symlink descendants outside
                    // the policy's canonical prefix (normalizer paths must agree).
                    if !in_pattern || std::fs::symlink_metadata(&parent).is_ok_and(|m| m.is_dir()) {
                        Some((parent, via_link))
                    } else {
                        None
                    }
                })
                .collect();
        }
    }
    candidates
}

impl Drop for WatcherHandle {
    fn drop(&mut self) {
        for task in self.catchups.values() {
            task.abort();
        }
    }
}

async fn catch_up_files(
    root: PathBuf,
    recursive: bool,
    tx: Arc<mpsc::Sender<RawFsEvent>>,
    window: Option<ChangeWindow>,
) {
    let Ok(meta) = tokio::fs::symlink_metadata(&root).await else {
        return;
    };
    let meta = if meta.is_symlink() {
        tokio::fs::metadata(&root).await.unwrap_or(meta)
    } else {
        meta
    };
    if meta.is_file() {
        if window.is_none_or(|window| window.holds(&meta)) {
            let _ = catch_up_file(root, &tx).await;
        }
        return;
    }
    if !meta.is_dir() {
        return;
    }
    let mut stack = Vec::new();
    match tokio::fs::read_dir(&root).await {
        Ok(entries) => stack.push(entries),
        Err(e) => {
            tracing::warn!(path = %root.display(), error = %e, "watch recovery scan could not read directory");
            return;
        }
    }
    // Stream depth-first with channel backpressure, without collecting the whole tree.
    while let Some(entries) = stack.last_mut() {
        match entries.next_entry().await {
            Ok(Some(entry)) => {
                let Ok(kind) = entry.file_type().await else {
                    continue;
                };
                if kind.is_file() {
                    if let Some(window) = window {
                        match entry.metadata().await {
                            Ok(meta) if window.holds(&meta) => {}
                            _ => continue,
                        }
                    }
                    if !catch_up_file(entry.path(), &tx).await {
                        return;
                    }
                } else if recursive && kind.is_dir() {
                    // Symlinked children are not followed outside the configured tree.
                    match tokio::fs::read_dir(entry.path()).await {
                        Ok(children) => stack.push(children),
                        Err(e) => {
                            tracing::warn!(path = %entry.path().display(), error = %e, "watch recovery scan could not read directory")
                        }
                    }
                }
            }
            Ok(None) => {
                stack.pop();
            }
            Err(e) => {
                tracing::warn!(root = %root.display(), error = %e, "watch recovery scan interrupted");
                stack.pop();
            }
        }
    }
}

async fn catch_up_file(path: PathBuf, tx: &mpsc::Sender<RawFsEvent>) -> bool {
    // A current-state observation, not a reconstructed creation time.
    tx.send(RawFsEvent {
        path,
        kind: FileChangeKind::Modified,
        rename_id: None,
    })
    .await
    .is_ok()
}

/// Spawn the filesystem watcher.
///
/// `poll_interval = Some(d)` forces a polling watcher with interval `d` — use
/// this where OS-native FS events are unreliable (NFS, `virtiofs`/`9p`,
/// bind-mounts in VM-backed container engines). `None` uses the OS-native
/// backend (inotify / FSEvents / ReadDirectoryChangesW). No backend follows a
/// link inside a recursive root, so a link is followed only where the agent
/// registers it.
pub fn spawn_watcher(
    roots: Vec<(PathBuf, bool)>,
    runtime_handle: tokio::runtime::Handle,
    capacity: usize,
    poll_interval: Option<Duration>,
) -> Result<(mpsc::Receiver<RawFsEvent>, WatcherHandle), WatcherError> {
    let (tx, rx) = mpsc::channel::<RawFsEvent>(capacity);
    let tx = Arc::new(tx);
    let tx_for_cb = tx.clone();
    let handle_for_cb = runtime_handle.clone();
    let activity = Arc::new(RootActivity::default());
    let activity_for_cb = activity.clone();
    // The polling backend finds files in new folders by itself.
    let catch_up_new_folders = cfg!(target_os = "linux") && poll_interval.is_none();
    let catch_up = Arc::new(NewFolderCatchUp::default());
    let catch_up_for_backend = catch_up.clone();

    let on_event = move |res: notify::Result<Event>| {
        let event = match res {
            Ok(ev) => ev,
            Err(e) => {
                tracing::warn!(error = %e, "notify backend reported an error");
                return;
            }
        };
        tracing::trace!(kind = ?event.kind, paths = ?event.paths, "raw notify event");
        activity_for_cb.note(&event.paths);
        if catch_up_new_folders {
            // inotify places the watch on a new folder only after this callback
            // returns, so a file already in it gives no event. List it now, then
            // list it again once the watch exists and send what the first
            // listing and the kernel events did not. A file gets one event,
            // except that a file created just after the watch exists can get
            // its kernel event and a late listing, and a subfolder created
            // after the new folder's watch but before notify walks it is listed
            // again by its own creation event, so a file in it may get a kernel
            // event too (same content).
            catch_up.record(&event.paths);
            for folder in new_folders(&event) {
                catch_up.begin(&folder);
                let listed = files_in_new_folder(&folder);
                catch_up.record(&listed);
                for file in listed {
                    let tx = tx_for_cb.clone();
                    handle_for_cb.spawn(async move {
                        catch_up_file(file, &tx).await;
                    });
                }
                #[cfg(test)]
                tests::after_new_folder_listing(&folder);
                catch_up.enqueue(folder, &handle_for_cb, &tx_for_cb);
            }
        }
        let mapped = map_notify_event(&event);
        for raw in mapped {
            tracing::debug!(path = %raw.path.display(), kind = ?raw.kind, "fs event");
            let tx = tx_for_cb.clone();
            handle_for_cb.spawn(async move {
                let _ = tx.send(raw).await;
            });
        }
    };

    let (backend, backend_name): (BackendWatcher, &'static str) = match poll_interval {
        Some(interval) => {
            let config = Config::default()
                .with_poll_interval(interval)
                .with_follow_symlinks(false);
            let w = PollWatcher::new(on_event, config)?;
            (BackendWatcher::Poll(w), "polling")
        }
        None => {
            let w =
                RecommendedWatcher::new(on_event, Config::default().with_follow_symlinks(false))?;
            (BackendWatcher::Native(w), os_backend_name())
        }
    };

    let backend = Arc::new(Mutex::new(backend));
    let _ = catch_up_for_backend.backend.set(Arc::downgrade(&backend));
    let mut handle = WatcherHandle {
        backend_name,
        watcher: backend,
        desired: BTreeMap::new(),
        resolved: BTreeMap::new(),
        active: BTreeMap::new(),
        catchups: BTreeMap::new(),
        tx,
        runtime: runtime_handle,
        files: Vec::new(),
        aliases_tx: watch::channel(Default::default()).0,
        warned: BTreeSet::new(),
        activity,
        rearm_after: cfg!(windows).then_some(WINDOWS_REARM_AFTER),
    };
    for (root, recursive) in roots {
        *handle.desired.entry(root).or_default() |= recursive;
    }
    let _ = handle.rebuild_roots(false);
    Ok((rx, handle))
}

/// Folders whose watch is not yet known to be in place, each with the files already
/// sent for it.
#[derive(Default)]
struct NewFolderCatchUp {
    pending: Mutex<HashMap<PathBuf, HashSet<PathBuf>>>,
    backend: OnceLock<Weak<Mutex<BackendWatcher>>>,
    queue: Mutex<CatchUpQueue>,
}

/// Folders waiting for their second listing, and how many workers drain them.
#[derive(Default)]
struct CatchUpQueue {
    folders: VecDeque<PathBuf>,
    workers: usize,
}

/// Most blocking tasks that finish new-folder catch-up at once. Each one waits on the
/// watcher lock, so more would only hold threads of the runtime's shared blocking pool.
const CATCH_UP_WORKERS: usize = 8;

impl NewFolderCatchUp {
    fn pending(&self) -> MutexGuard<'_, HashMap<PathBuf, HashSet<PathBuf>>> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn begin(&self, folder: &Path) {
        self.pending().entry(folder.to_path_buf()).or_default();
    }

    /// Note `paths` as sent for every pending folder that holds them.
    fn record(&self, paths: &[PathBuf]) {
        let mut pending = self.pending();
        if pending.is_empty() {
            return;
        }
        for (folder, sent) in pending.iter_mut() {
            sent.extend(paths.iter().filter(|p| p.starts_with(folder)).cloned());
        }
    }

    /// Return once the backend has handled every request made before this call.
    /// The inotify backend adds the watch for a new folder at the end of the
    /// batch that held its creation event, before it reads its next request,
    /// and answers a request only after handling it. A `configure` round trip
    /// therefore returns after that watch is in place. Calling it from the
    /// notify callback itself would deadlock, so it runs on a blocking task.
    fn wait_for_watch(&self) {
        let Some(backend) = self.backend.get().and_then(Weak::upgrade) else {
            return;
        };
        let mut backend = backend.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = backend
            .as_watcher_mut()
            .configure(Config::default().with_follow_symlinks(false));
    }

    /// Queue `folder` for its second listing. Starts a worker unless
    /// `CATCH_UP_WORKERS` already run; a worker drains the queue in order
    /// and ends when it is empty. A folder whose catch-up panics is dropped and
    /// the worker goes on, so a panic never uses up a worker slot.
    fn enqueue(
        self: &Arc<Self>,
        folder: PathBuf,
        runtime: &tokio::runtime::Handle,
        tx: &Arc<mpsc::Sender<RawFsEvent>>,
    ) {
        {
            let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
            queue.folders.push_back(folder);
            if queue.workers >= CATCH_UP_WORKERS {
                return;
            }
            queue.workers += 1;
        }
        let this = self.clone();
        let handle = runtime.clone();
        let tx = tx.clone();
        runtime.spawn_blocking(move || {
            #[cfg(test)]
            let _in_flight = tests::catch_up_task();
            loop {
                let folder = {
                    let mut queue = this.queue.lock().unwrap_or_else(PoisonError::into_inner);
                    match queue.folders.pop_front() {
                        Some(folder) => folder,
                        None => {
                            queue.workers -= 1;
                            return;
                        }
                    }
                };
                let finished = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    #[cfg(test)]
                    tests::before_catch_up(&folder);
                    this.wait_for_watch();
                    for file in this.finish(&folder) {
                        let tx = tx.clone();
                        handle.spawn(async move {
                            catch_up_file(file, &tx).await;
                        });
                    }
                }));
                if finished.is_err() {
                    this.pending().remove(&folder);
                    tracing::warn!(folder = %folder.display(), "new-folder catch-up panicked");
                }
            }
        });
    }

    /// The files now in `folder` that nothing has sent. Ends the folder's window.
    fn finish(&self, folder: &Path) -> Vec<PathBuf> {
        let mut pending = self.pending();
        let sent = pending.remove(folder).unwrap_or_default();
        files_in_new_folder(folder)
            .into_iter()
            .filter(|f| !sent.contains(f))
            .collect()
    }
}

/// Most entries (files and folders) one new-folder listing visits. The root catch-up has no such bound.
const NEW_FOLDER_ENTRY_LIMIT: usize = 512;

/// Directories that appeared under a watched folder, by creation or by a move in.
fn new_folders(event: &Event) -> Vec<PathBuf> {
    match event.kind {
        NEvent::Create(CreateKind::Folder) => event.paths.clone(),
        NEvent::Modify(ModifyKind::Name(RenameMode::To)) => event
            .paths
            .iter()
            .filter(|p| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir()))
            .cloned()
            .collect(),
        _ => Vec::new(),
    }
}

/// Files in `dir` and its subfolders, found by visiting at most
/// `NEW_FOLDER_ENTRY_LIMIT` entries, files and folders alike. Symbolic links are
/// not followed, as in `catch_up_files`.
fn files_in_new_folder(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut visited = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(folder) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&folder) else {
            continue;
        };
        for entry in entries.flatten() {
            if visited == NEW_FOLDER_ENTRY_LIMIT {
                tracing::warn!(path = %dir.display(), limit = NEW_FOLDER_ENTRY_LIMIT, "new folder has more entries than the catch-up limit; files not listed wait for their own events");
                return files;
            }
            visited += 1;
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                stack.push(entry.path());
            } else if kind.is_file() {
                files.push(entry.path());
            }
        }
    }
    files
}

fn os_backend_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "fsevents"
    } else if cfg!(target_os = "windows") {
        "read_directory_changes_w"
    } else if cfg!(target_os = "linux") {
        "inotify"
    } else {
        "polling"
    }
}

fn map_notify_event(event: &Event) -> Vec<RawFsEvent> {
    let mut out = Vec::new();
    let tracker_id = event.attrs.tracker().map(|t| t as u64);
    for path in event.paths.iter() {
        let kind = match event.kind {
            NEvent::Create(_) => Some(FileChangeKind::Created),
            NEvent::Modify(ModifyKind::Name(RenameMode::From))
            | NEvent::Modify(ModifyKind::Name(RenameMode::To))
            | NEvent::Modify(ModifyKind::Name(RenameMode::Both)) => Some(FileChangeKind::Renamed),
            NEvent::Modify(_) => Some(FileChangeKind::Modified),
            NEvent::Remove(_) => Some(FileChangeKind::Removed),
            _ => None,
        };
        if let Some(k) = kind {
            out.push(RawFsEvent {
                path: path.clone(),
                kind: k,
                rename_id: tracker_id,
            });
        }
    }
    out
}

#[cfg(test)]
pub(crate) mod test_logs {
    /// Everything `f` logs on this thread. The subscriber is process-wide because
    /// tracing caches a callsite's interest when any thread first reaches it, so a
    /// thread-local subscriber loses a callsite another test reached first.
    pub(crate) fn logs_of(f: impl FnOnce()) -> String {
        thread_local!(static LINES: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) });
        struct Lines;
        impl std::io::Write for Lines {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                // A thread that is exiting may log after its buffer is gone.
                let _ = LINES.try_with(|lines| lines.borrow_mut().extend_from_slice(bytes));
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        static SUBSCRIBER: std::sync::Once = std::sync::Once::new();
        SUBSCRIBER.call_once(|| tracing_subscriber::fmt().with_writer(|| Lines).init());
        // A callsite first reached during the install cached no subscriber.
        tracing::callsite::rebuild_interest_cache();
        LINES.take();
        f();
        String::from_utf8(LINES.take()).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;
    use std::time::Duration;
    use tempfile::TempDir;

    async fn receive_path(rx: &mut mpsc::Receiver<RawFsEvent>, path: &Path) {
        let expected = dunce::canonicalize(path).unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let event = rx.recv().await.expect("watcher channel closed");
                if dunce::canonicalize(event.path).ok().as_ref() == Some(&expected) {
                    break;
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("missing recovered file event for {}", path.display()));
    }

    async fn recovers_missing_root(poll: Option<Duration>) {
        let td = TempDir::new().unwrap();
        let root = td.path().join("missing/cache/tools");
        let (mut rx, mut watcher) = spawn_watcher(
            vec![(root.clone(), true)],
            tokio::runtime::Handle::current(),
            16,
            poll,
        )
        .unwrap();
        assert!(watcher.active.is_empty());
        assert_eq!(watcher.desired.len(), 1);
        assert!(!watcher.desired.contains_key(td.path()));
        let file = root.join("nested/snapshot.json");
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, b"written once before subscription").unwrap();
        watcher.reconcile();
        receive_path(&mut rx, &file).await;
        assert_eq!(watcher.active.len(), 1);
        // Wait for the catch-up task before testing the live backend separately.
        if let Some(task) = watcher.catchups.remove(&root) {
            task.await.unwrap();
        }
        let later = root.join("later.json");
        fs::write(&later, b"created after recovery").unwrap();
        receive_path(&mut rx, &later).await;

        // Replacement at the same path, without observing an intermediate absence.
        fs::rename(&root, td.path().join("old-tools")).unwrap();
        fs::create_dir_all(&root).unwrap();
        let replacement = root.join("replacement.json");
        fs::write(&replacement, b"new directory identity").unwrap();
        watcher.reconcile();
        receive_path(&mut rx, &replacement).await;
        watcher.unwatch(&root).unwrap();
        watcher.reconcile();
        assert!(watcher.desired.is_empty());
        assert!(watcher.active.is_empty());
        assert!(watcher.catchups.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_recovers_missing_and_replaced_roots() {
        recovers_missing_root(None).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn polling_recovers_missing_and_replaced_roots() {
        recovers_missing_root(Some(Duration::from_millis(100))).await;
    }

    async fn wildcard_directory_lifecycle(poll: Option<Duration>) {
        let td = TempDir::new().unwrap();
        let apps = td.path().join("Applications");
        let existing = apps.join("Existing.app/Contents");
        fs::create_dir_all(&existing).unwrap();
        fs::create_dir_all(apps.join("Unrelated/Contents/deep")).unwrap();
        let pattern = apps.join("*.app/Contents");
        let (mut rx, mut watcher) = spawn_watcher(
            vec![(pattern.clone(), false)],
            tokio::runtime::Handle::current(),
            32,
            poll,
        )
        .unwrap();
        assert_eq!(watcher.active.len(), 1);
        assert!(watcher.active.contains_key(&existing));
        assert!(!watcher.active[&existing].0);
        assert!(!watcher.active.contains_key(&apps));
        assert!(!watcher.active.contains_key(&pattern));
        tokio::time::sleep(Duration::from_millis(250)).await;
        let first = existing.join("Info.plist");
        fs::write(&first, b"live existing app").unwrap();
        receive_path(&mut rx, &first).await;

        let late = apps.join("New.app/Contents");
        fs::create_dir_all(&late).unwrap();
        let late_file = late.join("Info.plist");
        fs::write(&late_file, b"written once before discovery").unwrap();
        watcher.reconcile();
        receive_path(&mut rx, &late_file).await;
        assert_eq!(watcher.active.len(), 2);
        if let Some(task) = watcher.catchups.remove(&late) {
            task.await.unwrap();
        }
        watcher.reconcile();
        assert!(watcher.catchups.is_empty(), "stable roots must not rescan");

        fs::rename(&late, td.path().join("old-contents")).unwrap();
        fs::create_dir(&late).unwrap();
        let replaced = late.join("replacement.json");
        fs::write(&replaced, b"replacement").unwrap();
        watcher.reconcile();
        receive_path(&mut rx, &replaced).await;
        fs::remove_dir_all(apps.join("New.app")).unwrap();
        watcher.reconcile();
        assert!(!watcher.active.contains_key(&late));

        // Removing a glob on policy reload must retain a shared literal root.
        watcher.watch(&existing, true).unwrap();
        watcher.unwatch(&pattern).unwrap();
        assert_eq!(watcher.active.len(), 1);
        assert!(watcher.active[&existing].0);
        watcher.unwatch(&existing).unwrap();
        assert!(watcher.active.is_empty());
        assert!(watcher.resolved.is_empty());
        assert!(watcher.catchups.is_empty());
        fs::create_dir_all(&late).unwrap();
        watcher.reconcile();
        assert!(watcher.active.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_wildcard_directory_lifecycle() {
        wildcard_directory_lifecycle(None).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn polling_wildcard_directory_lifecycle() {
        wildcard_directory_lifecycle(Some(Duration::from_millis(100))).await;
    }

    #[test]
    fn nested_directory_patterns_use_policy_glob_syntax() {
        let td = TempDir::new().unwrap();
        let expected = td.path().join("GroupA/App1.app/Contents");
        fs::create_dir_all(&expected).unwrap();
        fs::create_dir_all(td.path().join("GroupB/App2.app/Contents")).unwrap();
        fs::create_dir_all(td.path().join("GroupA/App22.app/Contents")).unwrap();
        assert_eq!(
            resolve_directory_pattern(&td.path().join("Group[A]/{App,Tool}?.app/Contents")),
            vec![expected]
        );
        assert!(resolve_directory_pattern(&td.path().join("Missing*/*.app/Contents")).is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn nfc_directory_pattern_finds_an_nfd_stored_directory() {
        let td = TempDir::new().unwrap();
        let stored = td.path().join("\u{1112}\u{1161}\u{11AB}-app/Contents");
        fs::create_dir_all(&stored).unwrap();
        let pattern = td.path().join("\u{D55C}*/Contents");
        assert_eq!(resolve_directory_pattern(&pattern), vec![stored]);
    }

    #[cfg(windows)]
    #[test]
    fn mixed_windows_separators_resolve_the_same_directories() {
        let td = TempDir::new().unwrap();
        let expected = td.path().join("Example.app/Contents");
        fs::create_dir_all(&expected).unwrap();
        let pattern = PathBuf::from(format!("{}/*.app/Contents", td.path().display()));
        assert_eq!(resolve_directory_pattern(&pattern), vec![expected]);
    }

    #[cfg(unix)]
    #[test]
    fn wildcard_discovery_follows_a_link_only_at_the_first_wildcard_component() {
        let td = TempDir::new().unwrap();
        let outside = td.path().join("outside");
        fs::create_dir_all(outside.join("Contents")).unwrap();
        let apps = td.path().join("apps");
        fs::create_dir_all(apps.join("Real.app")).unwrap();
        std::os::unix::fs::symlink(&outside, apps.join("Link.app")).unwrap();
        std::os::unix::fs::symlink(outside.join("Contents"), apps.join("Real.app/Contents"))
            .unwrap();
        assert_eq!(
            resolve_directory_pattern(&apps.join("*.app/Contents")),
            [apps.join("Link.app/Contents")]
        );
        // A link at a second wildcard component stays unfollowed.
        fs::create_dir_all(apps.join("Group")).unwrap();
        std::os::unix::fs::symlink(&outside, apps.join("Group/Deep.app")).unwrap();
        assert!(resolve_directory_pattern(&apps.join("*/*.app/Contents")).is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn removed_pending_root_is_not_retried() {
        let td = TempDir::new().unwrap();
        let root = td.path().join("missing");
        let (_rx, mut watcher) = spawn_watcher(
            vec![],
            tokio::runtime::Handle::current(),
            16,
            Some(Duration::from_millis(100)),
        )
        .unwrap();
        assert!(watcher.watch(&root, false).is_err());
        assert!(watcher.desired.contains_key(&root));
        watcher.unwatch(&root).unwrap();
        fs::create_dir(&root).unwrap();
        watcher.reconcile();
        assert!(watcher.active.is_empty());
        assert!(watcher.catchups.is_empty());
    }

    #[tokio::test]
    async fn watch_result_does_not_report_an_unrelated_missing_root() {
        let td = TempDir::new().unwrap();
        let (_rx, mut watcher) = spawn_watcher(
            vec![(td.path().join("missing"), false)],
            tokio::runtime::Handle::current(),
            16,
            Some(Duration::from_secs(60)),
        )
        .unwrap();
        let existing = td.path().join("existing");
        fs::create_dir(&existing).unwrap();
        watcher.watch(&existing, false).unwrap();
        assert!(watcher.active.contains_key(&existing));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unchanged_roots_do_not_rescan_but_mode_changes_do() {
        let td = TempDir::new().unwrap();
        let root = td.path().to_path_buf();
        let file = root.join("nested/file.json");
        fs::create_dir(file.parent().unwrap()).unwrap();
        fs::write(&file, b"existing").unwrap();
        let (mut rx, mut watcher) = spawn_watcher(
            vec![(root.clone(), false)],
            tokio::runtime::Handle::current(),
            16,
            Some(Duration::from_secs(60)),
        )
        .unwrap();
        watcher.reconcile();
        assert!(watcher.catchups.is_empty());
        watcher.watch(&root, true).unwrap();
        receive_path(&mut rx, &file).await;
        watcher.catchups.remove(&root).unwrap().await.unwrap();
        watcher.reconcile();
        assert!(watcher.catchups.is_empty());
        assert!(watcher.active[&root].0);
    }

    #[tokio::test]
    async fn catchup_respects_depth_and_follows_only_a_root_link() {
        let td = TempDir::new().unwrap();
        let root = td.path().join("watched");
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(root.join("direct.json"), b"a").unwrap();
        fs::write(root.join("nested/child.json"), b"b").unwrap();
        #[cfg(unix)]
        {
            let outside = td.path().join("outside");
            fs::create_dir(&outside).unwrap();
            fs::write(outside.join("secret.json"), b"excluded").unwrap();
            std::os::unix::fs::symlink(outside, root.join("link")).unwrap();
        }
        for (recursive, expected) in [(false, 1), (true, 2)] {
            let (tx, mut rx) = mpsc::channel(8);
            catch_up_files(root.clone(), recursive, Arc::new(tx), None).await;
            let mut count = 0;
            while let Some(event) = rx.recv().await {
                assert_ne!(event.path.file_name().unwrap(), "secret.json");
                count += 1;
            }
            assert_eq!(count, expected);
        }
        #[cfg(unix)]
        {
            // The root itself may be a link, and a link inside it is still not followed.
            let linked_root = td.path().join("linked-root");
            std::os::unix::fs::symlink(&root, &linked_root).unwrap();
            let (tx, mut rx) = mpsc::channel(8);
            catch_up_files(linked_root.clone(), true, Arc::new(tx), None).await;
            let mut seen = Vec::new();
            while let Some(event) = rx.recv().await {
                seen.push(event.path);
            }
            seen.sort();
            assert_eq!(
                seen,
                [
                    linked_root.join("direct.json"),
                    linked_root.join("nested/child.json")
                ]
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unwatch_cancels_backpressured_catchup() {
        let td = TempDir::new().unwrap();
        let root = td.path().join("missing");
        let (mut rx, mut watcher) = spawn_watcher(
            vec![(root.clone(), true)],
            tokio::runtime::Handle::current(),
            1,
            Some(Duration::from_secs(60)),
        )
        .unwrap();
        fs::create_dir(&root).unwrap();
        for i in 0..20 {
            fs::write(root.join(format!("{i}.json")), b"x").unwrap();
        }
        watcher.reconcile();
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        let task = watcher.catchups.remove(&root).unwrap();
        // Put it back so unwatch owns and cancels it, retaining its abort handle for inspection.
        let abort = task.abort_handle();
        watcher.catchups.insert(root.clone(), task);
        watcher.unwatch(&root).unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while !abort.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_watcher_during_catchup_closes_raw_channel() {
        let td = TempDir::new().unwrap();
        let root = td.path().join("missing");
        let (mut rx, mut watcher) = spawn_watcher(
            vec![(root.clone(), true)],
            tokio::runtime::Handle::current(),
            1,
            Some(Duration::from_secs(60)),
        )
        .unwrap();
        fs::create_dir(&root).unwrap();
        for i in 0..20 {
            fs::write(root.join(format!("{i}.json")), b"x").unwrap();
        }
        watcher.reconcile();
        rx.recv().await.unwrap();
        drop(watcher);
        tokio::time::timeout(Duration::from_secs(2), async {
            while rx.recv().await.is_some() {}
        })
        .await
        .expect("shutdown retained a raw-event sender");
    }

    #[test]
    fn new_folder_listing_is_bounded_and_does_not_follow_links() {
        let td = TempDir::new().unwrap();
        let dir = td.path().join("new");
        fs::create_dir_all(dir.join("a/b")).unwrap();
        fs::write(dir.join("top.md"), b"x").unwrap();
        fs::write(dir.join("a/b/deep.md"), b"x").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(td.path(), dir.join("loop")).unwrap();
            std::os::unix::fs::symlink(dir.join("top.md"), dir.join("link.md")).unwrap();
        }
        let mut found = files_in_new_folder(&dir);
        found.sort();
        assert_eq!(found, [dir.join("a/b/deep.md"), dir.join("top.md")]);

        let many = td.path().join("many");
        fs::create_dir(&many).unwrap();
        for i in 0..NEW_FOLDER_ENTRY_LIMIT + 5 {
            fs::write(many.join(format!("{i}.md")), b"x").unwrap();
        }
        assert_eq!(files_in_new_folder(&many).len(), NEW_FOLDER_ENTRY_LIMIT);

        let wide = td.path().join("wide");
        for i in 0..NEW_FOLDER_ENTRY_LIMIT + 5 {
            fs::create_dir_all(wide.join(i.to_string())).unwrap();
            fs::write(wide.join(i.to_string()).join("f.md"), b"x").unwrap();
        }
        assert!(files_in_new_folder(&wide).is_empty());
    }

    static LATE_FILE: std::sync::Mutex<Option<(PathBuf, PathBuf)>> = std::sync::Mutex::new(None);

    static PANIC_FOLDERS: std::sync::Mutex<Vec<PathBuf>> = std::sync::Mutex::new(Vec::new());

    pub(super) fn before_catch_up(folder: &Path) {
        let mut doomed = PANIC_FOLDERS.lock().unwrap();
        if let Some(at) = doomed.iter().position(|f| f == folder) {
            doomed.remove(at);
            drop(doomed);
            panic!("injected catch-up panic");
        }
    }

    static IN_FLIGHT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    static PEAK_IN_FLIGHT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    pub(super) struct InFlight;

    impl Drop for InFlight {
        fn drop(&mut self) {
            IN_FLIGHT.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    pub(super) fn catch_up_task() -> InFlight {
        let now = IN_FLIGHT.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        PEAK_IN_FLIGHT.fetch_max(now, std::sync::atomic::Ordering::SeqCst);
        InFlight
    }

    pub(super) fn after_new_folder_listing(folder: &Path) {
        let late = LATE_FILE.lock().unwrap().clone();
        if let Some((watched, file)) = late {
            if watched == folder {
                fs::write(file, b"x").unwrap();
            }
        }
    }

    #[cfg(target_os = "linux")]
    async fn kinds_for(rx: &mut mpsc::Receiver<RawFsEvent>, file: &Path) -> Vec<FileChangeKind> {
        let mut kinds = Vec::new();
        let _ = tokio::time::timeout(Duration::from_millis(1500), async {
            while let Some(event) = rx.recv().await {
                if event.path == file {
                    kinds.push(event.kind);
                }
            }
        })
        .await;
        kinds
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_folder_moved_in_with_a_file_gives_one_event_for_it() {
        let td = TempDir::new().unwrap();
        let root = td.path().join("root");
        fs::create_dir(&root).unwrap();
        let staged = td.path().join("staged");
        fs::create_dir(&staged).unwrap();
        fs::write(staged.join("SKILL.md"), b"x").unwrap();
        let (mut rx, _watcher) = spawn_watcher(
            vec![(root.clone(), true)],
            tokio::runtime::Handle::current(),
            64,
            None,
        )
        .unwrap();
        fs::rename(&staged, root.join("demo")).unwrap();
        let kinds = kinds_for(&mut rx, &root.join("demo/SKILL.md")).await;
        assert_eq!(kinds, [FileChangeKind::Modified]);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_file_moved_in_just_after_its_new_folder_gives_one_event() {
        let td = TempDir::new().unwrap();
        let root = td.path().join("root");
        fs::create_dir(&root).unwrap();
        let staged = td.path().join("SKILL.md");
        fs::write(&staged, b"x").unwrap();
        let (mut rx, _watcher) = spawn_watcher(
            vec![(root.clone(), true)],
            tokio::runtime::Handle::current(),
            64,
            None,
        )
        .unwrap();
        let folder = root.join("demo");
        fs::create_dir(&folder).unwrap();
        fs::rename(&staged, folder.join("SKILL.md")).unwrap();
        let kinds = kinds_for(&mut rx, &folder.join("SKILL.md")).await;
        assert_eq!(
            kinds.len(),
            1,
            "one move must give one event, got {kinds:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_file_that_lands_between_the_listing_and_the_watch_gives_one_event() {
        let td = TempDir::new().unwrap();
        let root = td.path().join("root");
        fs::create_dir(&root).unwrap();
        let folder = root.join("demo");
        let late = folder.join("SKILL.md");
        *LATE_FILE.lock().unwrap() = Some((folder.clone(), late.clone()));
        let (mut rx, _watcher) = spawn_watcher(
            vec![(root.clone(), true)],
            tokio::runtime::Handle::current(),
            64,
            None,
        )
        .unwrap();
        fs::create_dir(&folder).unwrap();
        let kinds = kinds_for(&mut rx, &late).await;
        *LATE_FILE.lock().unwrap() = None;
        assert_eq!(kinds, [FileChangeKind::Modified], "got {kinds:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn folders_whose_catch_up_panics_do_not_stop_later_catch_up() {
        let td = TempDir::new().unwrap();
        let catch_up = Arc::new(NewFolderCatchUp::default());
        let (tx, mut rx) = mpsc::channel::<RawFsEvent>(64);
        let tx = Arc::new(tx);
        let runtime = tokio::runtime::Handle::current();
        let mut folders = Vec::new();
        for i in 0..=CATCH_UP_WORKERS {
            let folder = td.path().join(format!("folder-{i}"));
            fs::create_dir(&folder).unwrap();
            fs::write(folder.join("SKILL.md"), b"x").unwrap();
            folders.push(folder);
        }
        let (last, doomed) = folders.split_last().unwrap();
        PANIC_FOLDERS.lock().unwrap().extend(doomed.iter().cloned());
        for folder in doomed {
            catch_up.begin(folder);
            catch_up.enqueue(folder.clone(), &runtime, &tx);
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !PANIC_FOLDERS.lock().unwrap().is_empty() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "injected panics never ran"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        catch_up.begin(last);
        catch_up.enqueue(last.clone(), &runtime, &tx);
        receive_path(&mut rx, &last.join("SKILL.md")).await;
    }

    #[cfg(target_os = "linux")]
    const BULK_FOLDERS: usize = 2000;

    #[cfg(target_os = "linux")]
    static BULK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Counts the events each `SKILL.md` under `root` gets, until every one of
    /// `BULK_FOLDERS` has one and the stream has been quiet for 500 ms.
    #[cfg(target_os = "linux")]
    async fn count_bulk_events(rx: &mut mpsc::Receiver<RawFsEvent>) -> HashMap<PathBuf, usize> {
        let mut counts: HashMap<PathBuf, usize> = HashMap::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        loop {
            let quiet = counts.len() >= BULK_FOLDERS;
            let wait = if quiet {
                Duration::from_millis(500)
            } else {
                deadline.saturating_duration_since(tokio::time::Instant::now())
            };
            match tokio::time::timeout(wait, rx.recv()).await {
                Ok(Some(event)) if event.path.ends_with("SKILL.md") => {
                    *counts.entry(event.path).or_default() += 1;
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => return counts,
            }
        }
    }

    /// Waits for catch-up tasks left by an earlier test, so the peak counts only this one.
    #[cfg(target_os = "linux")]
    async fn reset_peak() {
        use std::sync::atomic::Ordering;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while IN_FLIGHT.load(Ordering::SeqCst) != 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        PEAK_IN_FLIGHT.store(0, Ordering::SeqCst);
    }

    #[cfg(target_os = "linux")]
    fn assert_catch_up_capped(cap: usize) {
        use std::sync::atomic::Ordering;
        let peak = PEAK_IN_FLIGHT.load(Ordering::SeqCst);
        assert!(
            peak <= cap,
            "catch-up tasks in flight at once: {peak}, cap {cap}"
        );
    }

    #[cfg(target_os = "linux")]
    fn report_bulk(name: &str, started: std::time::Instant, counts: &HashMap<PathBuf, usize>) {
        use std::sync::atomic::Ordering;
        let mut by_count: BTreeMap<usize, usize> = BTreeMap::new();
        for n in counts.values() {
            *by_count.entry(*n).or_default() += 1;
        }
        eprintln!(
            "bulk-catch-up {name}: folders={BULK_FOLDERS} seen={} events_per_file={by_count:?} peak_in_flight={} elapsed_ms={}",
            counts.len(),
            PEAK_IN_FLIGHT.load(Ordering::SeqCst),
            started.elapsed().as_millis()
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_thousand_folders_moved_in_give_one_event_per_file() {
        let _serial = BULK.lock().await;
        let td = TempDir::new().unwrap();
        let root = td.path().join("root");
        let staged = td.path().join("staged");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&staged).unwrap();
        for i in 0..BULK_FOLDERS {
            let dir = staged.join(format!("skill-{i}"));
            fs::create_dir(&dir).unwrap();
            fs::write(dir.join("SKILL.md"), b"x").unwrap();
        }
        let (mut rx, _watcher) = spawn_watcher(
            vec![(root.clone(), true)],
            tokio::runtime::Handle::current(),
            BULK_FOLDERS * 4,
            None,
        )
        .unwrap();
        reset_peak().await;
        let started = std::time::Instant::now();
        for i in 0..BULK_FOLDERS {
            fs::rename(
                staged.join(format!("skill-{i}")),
                root.join(format!("skill-{i}")),
            )
            .unwrap();
        }
        let counts = count_bulk_events(&mut rx).await;
        report_bulk("moved_in", started, &counts);
        let missing = (0..BULK_FOLDERS)
            .filter(|i| !counts.contains_key(&root.join(format!("skill-{i}/SKILL.md"))))
            .count();
        assert_eq!(missing, 0, "files with no event");
        let repeated: Vec<_> = counts.iter().filter(|(_, n)| **n != 1).take(3).collect();
        assert!(
            repeated.is_empty(),
            "files with other than one event, first few: {repeated:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(8));
        assert_catch_up_capped(8);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_thousand_folders_copied_in_all_give_an_event() {
        let _serial = BULK.lock().await;
        let td = TempDir::new().unwrap();
        let root = td.path().join("root");
        fs::create_dir(&root).unwrap();
        let (mut rx, _watcher) = spawn_watcher(
            vec![(root.clone(), true)],
            tokio::runtime::Handle::current(),
            BULK_FOLDERS * 8,
            None,
        )
        .unwrap();
        reset_peak().await;
        let started = std::time::Instant::now();
        for i in 0..BULK_FOLDERS {
            let dir = root.join(format!("skill-{i}"));
            fs::create_dir(&dir).unwrap();
            fs::write(dir.join("SKILL.md"), b"x").unwrap();
        }
        let counts = count_bulk_events(&mut rx).await;
        report_bulk("copied_in", started, &counts);
        let missing = (0..BULK_FOLDERS)
            .filter(|i| !counts.contains_key(&root.join(format!("skill-{i}/SKILL.md"))))
            .count();
        assert_eq!(missing, 0, "files with no event");
        assert!(started.elapsed() < Duration::from_secs(8));
        assert_catch_up_capped(8);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn detects_create_in_watched_dir() {
        let td = TempDir::new().unwrap();
        let handle = tokio::runtime::Handle::current();
        let (mut rx, _watcher) =
            spawn_watcher(vec![(td.path().to_path_buf(), false)], handle, 16, None).unwrap();

        // Give the watcher a moment to register on macOS FSEvents.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let p = td.path().join("new.json");
        let mut f = File::create(&p).unwrap();
        f.write_all(b"{}").unwrap();
        f.sync_all().unwrap();
        drop(f);

        let event = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("timed out")
            .expect("channel closed");
        assert!(matches!(
            event.kind,
            FileChangeKind::Created | FileChangeKind::Modified
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn detects_remove() {
        let td = TempDir::new().unwrap();
        let p = td.path().join("victim.json");
        File::create(&p).unwrap().write_all(b"x").unwrap();
        let handle = tokio::runtime::Handle::current();
        let (mut rx, _watcher) =
            spawn_watcher(vec![(td.path().to_path_buf(), false)], handle, 16, None).unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        fs::remove_file(&p).unwrap();
        let mut saw_remove = false;
        for _ in 0..10 {
            if let Ok(Some(ev)) = tokio::time::timeout(Duration::from_secs(1), rx.recv()).await {
                if ev.kind == FileChangeKind::Removed {
                    saw_remove = true;
                    break;
                }
            }
        }
        assert!(saw_remove);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn poll_watcher_detects_modify() {
        let td = TempDir::new().unwrap();
        let p = td.path().join("watched.json");
        fs::write(&p, b"a").unwrap();
        let handle = tokio::runtime::Handle::current();
        let (mut rx, watcher) = spawn_watcher(
            vec![(td.path().to_path_buf(), false)],
            handle,
            64,
            Some(Duration::from_millis(120)),
        )
        .unwrap();
        assert_eq!(watcher.backend_name, "polling");
        // There's no signal for "initial snapshot taken", so keep rewriting the
        // file (size + mtime change, which the default poll comparison detects)
        // until an event lands or we give up. Robust under loaded CI.
        let mut saw_change = false;
        for i in 0..40 {
            fs::write(&p, vec![b'x'; i + 2]).unwrap();
            if let Ok(Some(ev)) = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await
            {
                if matches!(ev.kind, FileChangeKind::Modified | FileChangeKind::Created) {
                    saw_change = true;
                    break;
                }
            }
        }
        assert!(saw_change, "poll watcher did not report the change");
    }

    #[cfg(unix)]
    fn idle_watcher(roots: Vec<(PathBuf, bool)>) -> (mpsc::Receiver<RawFsEvent>, WatcherHandle) {
        spawn_watcher(
            roots,
            tokio::runtime::Handle::current(),
            16,
            Some(Duration::from_secs(60)),
        )
        .unwrap()
    }

    #[cfg(unix)]
    fn aliases_of(watcher: &WatcherHandle) -> Vec<(PathBuf, PathBuf)> {
        watcher.aliases_rx().borrow().to_vec()
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_linked_file_is_watched_by_its_link_and_follows_a_retarget() {
        let td = TempDir::new().unwrap();
        let dir = dunce::canonicalize(td.path()).unwrap();
        fs::create_dir_all(dir.join("dotfiles")).unwrap();
        let (first, second) = (dir.join("dotfiles/a.json"), dir.join("dotfiles/b.json"));
        fs::write(&first, b"a").unwrap();
        fs::write(&second, b"b").unwrap();
        let link = dir.join("settings.json");
        std::os::unix::fs::symlink(&first, &link).unwrap();
        let (mut rx, mut watcher) = idle_watcher(vec![]);
        watcher.follow_files(vec![link.clone()], true);
        assert_eq!(aliases_of(&watcher), [(first, link.clone())]);
        receive_path(&mut rx, &link).await;

        let swap = dir.join("swap");
        std::os::unix::fs::symlink(&second, &swap).unwrap();
        fs::rename(&swap, &link).unwrap();
        watcher.reconcile();
        assert_eq!(aliases_of(&watcher), [(second, link.clone())]);
        receive_path(&mut rx, &link).await;
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dangling_link_warns_once_and_is_followed_when_its_target_appears() {
        let td = TempDir::new().unwrap();
        let dir = dunce::canonicalize(td.path()).unwrap();
        let target = dir.join("missing.json");
        let link = dir.join("settings.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let (_rx, mut watcher) = idle_watcher(vec![]);
        let logs = test_logs::logs_of(|| {
            watcher.follow_files(vec![link.clone()], true);
            watcher.reconcile();
        });
        assert_eq!(logs.matches("missing target").count(), 1, "{logs}");
        assert!(aliases_of(&watcher).is_empty());

        fs::write(&target, b"now").unwrap();
        watcher.reconcile();
        assert_eq!(aliases_of(&watcher), [(target, link)]);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_link_whose_target_is_in_a_watched_root_is_not_followed() {
        let td = TempDir::new().unwrap();
        let dir = dunce::canonicalize(td.path()).unwrap();
        fs::create_dir_all(dir.join("dotfiles")).unwrap();
        let target = dir.join("dotfiles/settings.json");
        fs::write(&target, b"a").unwrap();
        let link = dir.join("settings.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let (_rx, mut watcher) = idle_watcher(vec![(dir.join("dotfiles"), false)]);
        let logs = test_logs::logs_of(|| {
            watcher.follow_files(vec![link.clone()], true);
            watcher.reconcile();
        });
        assert_eq!(logs.matches("in a watched root").count(), 1, "{logs}");
        assert!(aliases_of(&watcher).is_empty());
        assert!(!watcher.active.contains_key(&link));
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_folder_watched_without_recursion_does_not_cover_a_deeper_target() {
        let td = TempDir::new().unwrap();
        let dir = dunce::canonicalize(td.path()).unwrap();
        let target = dir.join("dotfiles/settings.json");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, b"a").unwrap();
        let link = dir.join("settings.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let (_rx, mut watcher) = idle_watcher(vec![(dir.clone(), false)]);
        watcher.follow_files(vec![link.clone()], true);
        assert_eq!(aliases_of(&watcher), [(target, link)]);

        let (_rx, mut watcher) = idle_watcher(vec![(dir.clone(), true)]);
        watcher.follow_files(vec![dir.join("settings.json")], true);
        assert!(aliases_of(&watcher).is_empty());
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_links_to_one_target_both_stay_and_warn_once() {
        let td = TempDir::new().unwrap();
        let dir = dunce::canonicalize(td.path()).unwrap();
        let target = dir.join("dotfiles/settings.json");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, b"a").unwrap();
        let (one, two) = (dir.join("one.json"), dir.join("two.json"));
        std::os::unix::fs::symlink(&target, &one).unwrap();
        std::os::unix::fs::symlink(&target, &two).unwrap();
        let (_rx, mut watcher) = idle_watcher(vec![]);
        let logs = test_logs::logs_of(|| {
            watcher.follow_files(vec![one.clone(), two.clone()], true);
            watcher.reconcile();
        });
        assert_eq!(logs.matches("shares its target").count(), 1, "{logs}");
        assert_eq!(aliases_of(&watcher), [(target.clone(), one), (target, two)]);
    }

    /// `skills` (recursive) with `foo` linked to a folder outside it, and the
    /// wildcard root the agent adds for the link.
    #[cfg(unix)]
    fn skills_with_link() -> (TempDir, PathBuf, PathBuf) {
        let td = TempDir::new().unwrap();
        let dir = dunce::canonicalize(td.path()).unwrap();
        let skills = dir.join("skills");
        let outside = dir.join("outside/foo");
        fs::create_dir_all(skills.join("real")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("SKILL.md"), b"a").unwrap();
        (td, skills, outside)
    }

    /// What spawning a watcher on `roots` and one more reconcile log, and the watcher.
    #[cfg(unix)]
    fn watching(roots: Vec<(PathBuf, bool)>) -> (String, WatcherHandle) {
        let mut watcher = None;
        let logs = test_logs::logs_of(|| {
            let (_rx, mut handle) = idle_watcher(roots);
            handle.reconcile();
            watcher = Some(handle);
        });
        (logs, watcher.unwrap())
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_skill_link_added_later_is_watched_by_its_link_path() {
        let (_td, skills, outside) = skills_with_link();
        let (mut rx, mut watcher) =
            idle_watcher(vec![(skills.clone(), true), (skills.join("*"), false)]);
        assert!(aliases_of(&watcher).is_empty());
        let link = skills.join("foo");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        watcher.reconcile();
        assert_eq!(aliases_of(&watcher), [(outside, link.clone())]);
        receive_path(&mut rx, &link.join("SKILL.md")).await;
        // The real folder is already covered by the recursive root.
        let mut active: Vec<_> = watcher.active.keys().cloned().collect();
        active.sort();
        assert_eq!(active, [skills.clone(), link.clone()]);
        assert!(!watcher.active[&link].0);

        fs::remove_file(&link).unwrap();
        watcher.reconcile();
        assert!(aliases_of(&watcher).is_empty());
        assert_eq!(watcher.active.len(), 1);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_link_to_the_root_or_to_a_parent_of_a_watched_folder_is_refused_once() {
        let (_td, skills, _) = skills_with_link();
        std::os::unix::fs::symlink("/", skills.join("bar")).unwrap();
        std::os::unix::fs::symlink(skills.parent().unwrap(), skills.join("loop")).unwrap();
        // Not recursive: a polling watcher would walk the link to `/` for real.
        let (logs, watcher) = watching(vec![(skills.clone(), false), (skills.join("*"), false)]);
        assert_eq!(
            logs.matches("parent of a watched folder").count(),
            2,
            "{logs}"
        );
        assert!(aliases_of(&watcher).is_empty());
        assert!(watcher
            .active
            .keys()
            .all(|root| root.parent() != Some(&skills) || root.ends_with("real")));
    }

    /// A link inside a recursive root to the folder that holds the root is
    /// refused with one warning, and the watcher keeps reporting real edits.
    #[cfg(unix)]
    async fn a_loop_link_in_a_recursive_root_is_refused_and_the_watcher_keeps_working(
        poll: Option<Duration>,
    ) {
        let (_td, skills, _) = skills_with_link();
        let real = skills.join("real/SKILL.md");
        fs::write(&real, b"0").unwrap();
        let loop_link = skills.join("loop");
        std::os::unix::fs::symlink(skills.parent().unwrap(), &loop_link).unwrap();
        let mut watcher = None;
        let logs = test_logs::logs_of(|| {
            let (rx, mut handle) = spawn_watcher(
                vec![(skills.clone(), true), (skills.join("*"), false)],
                tokio::runtime::Handle::current(),
                64,
                poll,
            )
            .unwrap();
            handle.reconcile();
            watcher = Some((rx, handle));
        });
        let (mut rx, _handle) = watcher.unwrap();
        assert_eq!(
            logs.matches("parent of a watched folder").count(),
            1,
            "{logs}"
        );
        // A write in the startup gap can be lost, so keep writing until one lands.
        let mut seen = false;
        for n in 1..=100 {
            fs::write(&real, format!("change-{n}")).unwrap();
            while let Ok(Some(event)) =
                tokio::time::timeout(Duration::from_millis(100), rx.recv()).await
            {
                seen |= event.path == real;
            }
            if seen && n > 3 {
                break;
            }
        }
        assert!(seen, "the real edit was not reported");
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_a_loop_link_in_a_recursive_root_is_refused() {
        a_loop_link_in_a_recursive_root_is_refused_and_the_watcher_keeps_working(None).await;
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn polling_a_loop_link_in_a_recursive_root_is_refused() {
        a_loop_link_in_a_recursive_root_is_refused_and_the_watcher_keeps_working(Some(
            Duration::from_millis(120),
        ))
        .await;
    }

    /// A recursive root holding a link to a folder of files reports nothing from
    /// behind the link, while an edit inside the root still comes through.
    #[cfg(unix)]
    async fn a_recursive_root_does_not_walk_a_link(poll: Option<Duration>) {
        let td = TempDir::new().unwrap();
        let dir = dunce::canonicalize(td.path()).unwrap();
        let (root, behind) = (dir.join("root"), dir.join("behind"));
        fs::create_dir_all(root.join("real")).unwrap();
        fs::create_dir_all(&behind).unwrap();
        let outside_files: Vec<PathBuf> = (0..50).map(|n| behind.join(format!("{n}.md"))).collect();
        for file in &outside_files {
            fs::write(file, b"0").unwrap();
        }
        let link = root.join("linked");
        std::os::unix::fs::symlink(&behind, &link).unwrap();
        let real = root.join("real/SKILL.md");
        fs::write(&real, b"0").unwrap();
        let (mut rx, _watcher) = spawn_watcher(
            vec![(root.clone(), true)],
            tokio::runtime::Handle::current(),
            4096,
            poll,
        )
        .unwrap();
        let (mut saw_real, mut saw_behind) = (false, Vec::new());
        // A write in the startup gap can be lost, so keep writing until one lands.
        for n in 1..=40 {
            fs::write(&real, format!("change-{n}")).unwrap();
            for file in &outside_files {
                fs::write(file, format!("change-{n}")).unwrap();
            }
            while let Ok(Some(event)) =
                tokio::time::timeout(Duration::from_millis(100), rx.recv()).await
            {
                saw_real |= event.path == real;
                if event.path.starts_with(&behind)
                    || (event.path != link && event.path.starts_with(&link))
                {
                    saw_behind.push(event.path);
                }
            }
            if saw_real && n > 8 {
                break;
            }
        }
        assert!(saw_real, "the edit inside the root was not reported");
        assert!(
            saw_behind.is_empty(),
            "events from behind a link: {saw_behind:?}"
        );
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_a_recursive_root_does_not_walk_a_link() {
        a_recursive_root_does_not_walk_a_link(None).await;
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn polling_a_recursive_root_does_not_walk_a_link() {
        a_recursive_root_does_not_walk_a_link(Some(Duration::from_millis(100))).await;
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_links_to_one_folder_follow_the_first_and_warn_once() {
        let (_td, skills, outside) = skills_with_link();
        let (one, two) = (skills.join("a-first"), skills.join("b-second"));
        std::os::unix::fs::symlink(&outside, &one).unwrap();
        std::os::unix::fs::symlink(&outside, &two).unwrap();
        let (logs, watcher) = watching(vec![(skills.clone(), true), (skills.join("*"), false)]);
        assert_eq!(logs.matches("shares its target").count(), 1, "{logs}");
        assert_eq!(aliases_of(&watcher), [(outside, one.clone())]);
        assert!(watcher.active.contains_key(&one) && !watcher.active.contains_key(&two));
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_skill_link_to_a_folder_inside_the_recursive_root_is_not_followed() {
        let (_td, skills, _) = skills_with_link();
        std::os::unix::fs::symlink(skills.join("real"), skills.join("again")).unwrap();
        let (logs, watcher) = watching(vec![(skills.clone(), true), (skills.join("*"), false)]);
        assert_eq!(logs.matches("in a watched root").count(), 1, "{logs}");
        assert!(aliases_of(&watcher).is_empty());
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_subagent_file_link_at_a_wildcard_leaf_is_watched_by_its_link_path() {
        let td = TempDir::new().unwrap();
        let dir = dunce::canonicalize(td.path()).unwrap();
        let agents = dir.join("agents");
        fs::create_dir_all(&agents).unwrap();
        fs::create_dir_all(dir.join("outside")).unwrap();
        let target = dir.join("outside/a.md");
        fs::write(&target, b"a").unwrap();
        fs::write(agents.join("b.md"), b"b").unwrap();
        let link = agents.join("a.md");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let (mut rx, mut watcher) = idle_watcher(vec![(agents.clone(), true)]);
        watcher.follow_files(vec![agents.join("*.md")], true);
        assert_eq!(aliases_of(&watcher), [(target, link.clone())]);
        receive_path(&mut rx, &link).await;
    }
    fn drop_backend_watch(watcher: &WatcherHandle, root: &Path) {
        let registered = watcher.active[root].2.clone();
        watcher
            .backend()
            .as_watcher_mut()
            .unwatch(&registered)
            .unwrap();
    }

    async fn drain_for(rx: &mut mpsc::Receiver<RawFsEvent>, wait: Duration) -> Vec<PathBuf> {
        let mut seen = Vec::new();
        let _ = tokio::time::timeout(wait, async {
            while let Some(event) = rx.recv().await {
                seen.push(event.path);
            }
        })
        .await;
        seen
    }

    fn count_of(seen: &[PathBuf], name: &str) -> usize {
        seen.iter().filter(|path| path.ends_with(name)).count()
    }

    async fn armed_root_with_old_file(
    ) -> (TempDir, PathBuf, mpsc::Receiver<RawFsEvent>, WatcherHandle) {
        let td = TempDir::new().unwrap();
        let root = td.path().to_path_buf();
        fs::write(root.join("old.json"), b"before the watch").unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let (rx, mut watcher) = spawn_watcher(
            vec![(root.clone(), false)],
            tokio::runtime::Handle::current(),
            64,
            None,
        )
        .unwrap();
        watcher.rearm_after = Some(Duration::from_secs(3600));
        tokio::time::sleep(Duration::from_millis(500)).await;
        (td, root, rx, watcher)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rearm_sends_the_file_written_while_the_watch_was_down_once() {
        let (_td, root, mut rx, mut watcher) = armed_root_with_old_file().await;
        let before: Vec<_> = watcher.active.keys().cloned().collect();
        drop_backend_watch(&watcher, &root);
        fs::write(root.join("gap.json"), b"written while down").unwrap();
        let silent = drain_for(&mut rx, Duration::from_millis(800)).await;
        assert!(silent.is_empty(), "a dropped watch gave {silent:?}");

        watcher.rearm_after = Some(Duration::ZERO);
        let logs = test_logs::logs_of(|| watcher.reconcile());
        assert_eq!(logs.matches("watch root re-armed").count(), 1, "{logs}");
        watcher.catchups.remove(&root).unwrap().await.unwrap();
        let listed = drain_for(&mut rx, Duration::from_millis(800)).await;
        assert_eq!(count_of(&listed, "gap.json"), 1, "{listed:?}");
        assert_eq!(count_of(&listed, "old.json"), 0, "{listed:?}");

        watcher.rearm_after = Some(Duration::from_secs(3600));
        fs::write(root.join("after.json"), b"written after the re-arm").unwrap();
        let live = drain_for(&mut rx, Duration::from_secs(2)).await;
        assert!(count_of(&live, "after.json") >= 1, "{live:?}");
        assert_eq!(count_of(&live, "gap.json"), 0, "{live:?}");
        assert_eq!(watcher.active.keys().cloned().collect::<Vec<_>>(), before);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_root_with_recent_events_is_not_rearmed() {
        let (_td, root, mut rx, mut watcher) = armed_root_with_old_file().await;
        fs::write(root.join("live.json"), b"an event").unwrap();
        assert!(!drain_for(&mut rx, Duration::from_secs(2)).await.is_empty());
        watcher.rearm_after = Some(Duration::from_secs(1));
        let logs = test_logs::logs_of(|| watcher.reconcile());
        assert!(!logs.contains("re-armed"), "{logs}");
        assert!(watcher.catchups.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_vanished_root_is_left_to_the_existing_path() {
        let (td, root, _rx, mut watcher) = armed_root_with_old_file().await;
        let moved = td.path().with_extension("gone");
        fs::rename(&root, &moved).unwrap();
        watcher.rearm_after = Some(Duration::ZERO);
        let logs = test_logs::logs_of(|| watcher.reconcile());
        assert!(!logs.contains("re-armed"), "{logs}");
        assert!(watcher.active.is_empty());
        fs::rename(&moved, &root).unwrap();
    }

    #[cfg(windows)]
    fn process_handles() -> u32 {
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};
        let mut count = 0;
        // SAFETY: the pseudo handle of the current process is always valid and `count` is a live u32.
        assert_ne!(
            unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut count) },
            0
        );
        count
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn repeated_rearms_do_not_leak_handles() {
        let (_td, root, _rx, mut watcher) = armed_root_with_old_file().await;
        watcher.rearm_after = Some(Duration::ZERO);
        for _ in 0..5 {
            watcher.reconcile();
        }
        let before = process_handles();
        for _ in 0..200 {
            watcher.reconcile();
        }
        watcher.catchups.remove(&root);
        assert!(
            process_handles() <= before + 10,
            "handles grew from {before}"
        );
    }
}
