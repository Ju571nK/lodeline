#![cfg(unix)]
//! T-13b (#306): the inventory engine over the durable local registry
//! (registry.md R3/R4/R7, README m5): completeness, comparison, rebaseline with
//! links on key rotation, state loss, scope separation and restart behaviour.

use std::collections::HashSet;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use serde_json::json;
use sigil_proxy::inventory::{
    ComparisonKind, CursorHasher, CursorTag, InventoryEngine, InventoryLimits, ListingKey,
    ListingProgress, PageInput, ToolInput, MAX_COLLECTORS,
};
use sigil_proxy::registry_key::{ScopeKey, KEY_FILE};
use sigil_proxy::registry_store::{EntryState, OpenKind, RegistryStore, ToolLookup};
use sigil_proxy_api::registry::{
    Change, Comparison, Completeness, DefinitionComparison, IncompleteReason, InventoryReport,
    RebaselineReason,
};

const EPOCH: &str = "0f0f0f0f-1111-4222-8333-444444444444";

fn dir() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

fn open(d: &Path) -> (RegistryStore, OpenKind) {
    RegistryStore::open(d, "px-1").unwrap()
}

fn scope() -> ScopeKey {
    ScopeKey::live("px-1", "up-1", "cs-1")
}

fn lk(session: u64) -> ListingKey {
    ListingKey {
        session,
        scope: scope(),
    }
}

fn tool(name: &str, desc: &str) -> ToolInput {
    ToolInput {
        name: name.to_string(),
        definition: json!({"name": name, "description": desc,
                           "inputSchema": {"type": "object", "properties": {}}})
        .to_string(),
    }
}

fn hasher() -> &'static CursorHasher {
    static H: std::sync::OnceLock<CursorHasher> = std::sync::OnceLock::new();
    H.get_or_init(|| CursorHasher::new().unwrap())
}

/// The tag of "cursor n".
fn tag(n: u8) -> CursorTag {
    hasher().tag(&format!("cursor-{n}"))
}

fn page(tools: Vec<ToolInput>, request: Option<u8>, next: Option<u8>) -> PageInput {
    PageInput::Tools {
        request_cursor: request.map(tag),
        tools,
        next_cursor: next.map(tag),
    }
}

fn engine(store: &RegistryStore) -> InventoryEngine {
    InventoryEngine::new(store.clone(), EPOCH, InventoryLimits::default())
}

/// One whole listing in a single page.
fn list(e: &mut InventoryEngine, session: u64, tools: Vec<ToolInput>) -> ListingProgress {
    e.observe_page(&lk(session), page(tools, None, None))
        .unwrap()
}

fn complete(p: ListingProgress) -> sigil_proxy::inventory::CompleteListing {
    match p {
        ListingProgress::Complete(c) => c,
        other => panic!("expected a complete listing, got {other:?}"),
    }
}

/// Every queued report, oldest first.
fn reports(store: &RegistryStore) -> Vec<InventoryReport> {
    store
        .pending_reports(1000)
        .unwrap()
        .iter()
        .map(|r| sigil_proxy_api::parse_inventory_report(&r.body).unwrap())
        .collect()
}

fn last_report(store: &RegistryStore) -> InventoryReport {
    reports(store).pop().unwrap()
}

fn ref_of(c: &sigil_proxy::inventory::CompleteListing, name: &str) -> String {
    c.tools.iter().find(|(n, _)| n == name).unwrap().1.clone()
}

/// registry.md I-3 as the server applies it: the changes cover the membership
/// difference exactly, each ref once.
fn assert_i3(prev: &[String], members: &[String], changes: &[Change]) {
    let prev: HashSet<&str> = prev.iter().map(String::as_str).collect();
    let cur: HashSet<&str> = members.iter().map(String::as_str).collect();
    let added_side: HashSet<&str> = cur.difference(&prev).copied().collect();
    let removed_side: HashSet<&str> = prev.difference(&cur).copied().collect();
    let mut used_new = HashSet::new();
    let mut used_old = HashSet::new();
    for c in changes {
        match c {
            Change::Added { metadata_ref } => {
                assert!(added_side.contains(metadata_ref.as_str()));
                assert!(used_new.insert(metadata_ref.as_str().to_string()));
            }
            Change::Removed { metadata_ref } => {
                assert!(removed_side.contains(metadata_ref.as_str()));
                assert!(used_old.insert(metadata_ref.as_str().to_string()));
            }
            Change::Changed {
                metadata_ref,
                previous_metadata_ref,
            } => {
                assert!(added_side.contains(metadata_ref.as_str()));
                assert!(removed_side.contains(previous_metadata_ref.as_str()));
                assert!(used_new.insert(metadata_ref.as_str().to_string()));
                assert!(used_old.insert(previous_metadata_ref.as_str().to_string()));
            }
        }
    }
    assert_eq!(used_new.len(), added_side.len(), "added side fully covered");
    assert_eq!(
        used_old.len(),
        removed_side.len(),
        "removed side fully covered"
    );
}

// ------------------------------------------------------------------- baseline

#[test]
fn first_complete_listing_is_an_initial_baseline_and_durable() {
    let d = dir();
    let (store, kind) = open(d.path());
    assert_eq!(kind, OpenKind::Fresh);
    let mut e = engine(&store);
    let c = complete(list(&mut e, 1, vec![tool("a", "da"), tool("b", "db")]));
    assert_eq!(c.comparison, ComparisonKind::InitialBaseline);
    let r = last_report(&store);
    assert_eq!(r.completeness, Completeness::Complete);
    assert!(matches!(r.comparison, Some(Comparison::InitialBaseline {})));
    assert_eq!(r.members.as_ref().unwrap().len(), 2);
    assert_eq!(r.key_id.as_str(), store.key_id());
    assert_eq!(r.epoch_id.as_str(), EPOCH);
    assert_eq!(r.pages_observed.get(), 1);
    // The entries are durable and pending upload; the lookup resolves offline.
    for (name, mref) in &c.tools {
        let rec = store.entry(mref).unwrap().unwrap();
        assert_eq!(rec.state, EntryState::Pending);
        assert_eq!(&rec.tool_name, name);
        assert_eq!(
            store.lookup_tool(&scope(), name).unwrap(),
            ToolLookup::Found(mref.clone())
        );
    }
    assert_eq!(
        store.lookup_tool(&scope(), "zzz").unwrap(),
        ToolLookup::NotInInventory
    );
    assert_eq!(
        store
            .lookup_tool(&ScopeKey::live("px-1", "up-1", "other"), "a")
            .unwrap(),
        ToolLookup::NoCompleteInventory
    );

    // Dropping every handle and reopening finds all of it (durability), and the
    // same definition maps to the same ref (deterministic across restart).
    drop(e);
    drop(store);
    let (store2, kind2) = open(d.path());
    assert_eq!(kind2, OpenKind::Existing);
    assert_eq!(store2.pending_entry_count().unwrap(), 2);
    assert_eq!(store2.pending_reports(10).unwrap().len(), 1);
    let mut e2 = engine(&store2);
    let c2 = complete(list(&mut e2, 2, vec![tool("a", "da"), tool("b", "db")]));
    assert_eq!(c2.tools, c.tools, "restart + re-list maps to the same refs");
    assert_eq!(c2.comparison, ComparisonKind::Compared);
    match last_report(&store2).comparison.unwrap() {
        Comparison::Compared {
            previous_inventory_id,
            changes,
        } => {
            assert_eq!(previous_inventory_id.as_str(), c.inventory_id);
            assert!(changes.is_empty());
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        store2.pending_entry_count().unwrap(),
        2,
        "no duplicate entries"
    );
}

#[test]
fn db_and_key_files_are_owner_only() {
    let d = dir();
    let (store, _) = open(d.path());
    let mut e = engine(&store);
    complete(list(&mut e, 1, vec![tool("a", "x")]));
    for name in [KEY_FILE, "registry.sqlite3"] {
        let m = std::fs::metadata(d.path().join(name))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(m & 0o077, 0, "{name} must not be group/other accessible");
    }
}

#[test]
fn second_listing_yields_one_added_one_changed_one_removed() {
    let d = dir();
    let (store, _) = open(d.path());
    let mut e = engine(&store);
    let c1 = complete(list(
        &mut e,
        1,
        vec![tool("keep", "k"), tool("edit", "v1"), tool("gone", "g")],
    ));
    let c2 = complete(list(
        &mut e,
        1,
        vec![tool("keep", "k"), tool("edit", "v2"), tool("new", "n")],
    ));
    assert_eq!(c2.comparison, ComparisonKind::Compared);
    let r = reports(&store).pop().unwrap();
    let Some(Comparison::Compared {
        previous_inventory_id,
        changes,
    }) = r.comparison.clone()
    else {
        panic!("{:?}", r.comparison)
    };
    assert_eq!(previous_inventory_id.as_str(), c1.inventory_id);
    assert_eq!(changes.len(), 3, "exactly three changes");
    assert!(changes.contains(&Change::Added {
        metadata_ref: sigil_proxy_api::MetadataRef::new(ref_of(&c2, "new")).unwrap()
    }));
    assert!(changes.contains(&Change::Removed {
        metadata_ref: sigil_proxy_api::MetadataRef::new(ref_of(&c1, "gone")).unwrap()
    }));
    assert!(changes.contains(&Change::Changed {
        metadata_ref: sigil_proxy_api::MetadataRef::new(ref_of(&c2, "edit")).unwrap(),
        previous_metadata_ref: sigil_proxy_api::MetadataRef::new(ref_of(&c1, "edit")).unwrap(),
    }));
    let strs = |c: &sigil_proxy::inventory::CompleteListing| -> Vec<String> {
        c.tools.iter().map(|(_, r)| r.clone()).collect()
    };
    assert_i3(&strs(&c1), &strs(&c2), &changes);
    // Only the latest snapshot per scope key is kept.
    let snap = store.latest_snapshot(&scope()).unwrap().unwrap();
    assert_eq!(snap.inventory_id, c2.inventory_id);
}

#[test]
fn incomplete_listing_changes_nothing_and_the_next_complete_compares_to_the_old_snapshot() {
    let d = dir();
    let (store, _) = open(d.path());
    let mut e = engine(&store);
    let c1 = complete(list(&mut e, 1, vec![tool("a", "x"), tool("b", "y")]));
    // A failed listing that would have shown fewer tools.
    let p = e
        .observe_page(
            &lk(1),
            PageInput::Failed {
                request_cursor: None,
                reason: IncompleteReason::PageError,
            },
        )
        .unwrap();
    assert_eq!(p, ListingProgress::Incomplete(IncompleteReason::PageError));
    let inc = last_report(&store);
    assert_eq!(inc.completeness, Completeness::Incomplete);
    assert_eq!(inc.incomplete_reason, Some(IncompleteReason::PageError));
    assert!(inc.members.is_none() && inc.comparison.is_none() && inc.inventory_id.is_none());
    // Nothing was removed: the latest complete snapshot still serves lookups.
    assert_eq!(
        store
            .latest_snapshot(&scope())
            .unwrap()
            .unwrap()
            .inventory_id,
        c1.inventory_id
    );
    assert!(matches!(
        store.lookup_tool(&scope(), "b").unwrap(),
        ToolLookup::Found(_)
    ));
    // Later pages of the dead chain are ignored (no report storm).
    let n = reports(&store).len();
    let ign = e
        .observe_page(&lk(1), page(vec![tool("a", "x")], Some(1), None))
        .unwrap();
    assert_eq!(ign, ListingProgress::Ignored);
    assert_eq!(reports(&store).len(), n);
    // The next complete listing is compared with the earlier complete one.
    let c2 = complete(list(&mut e, 1, vec![tool("a", "x")]));
    match last_report(&store).comparison.unwrap() {
        Comparison::Compared {
            previous_inventory_id,
            changes,
        } => {
            assert_eq!(previous_inventory_id.as_str(), c1.inventory_id);
            assert_eq!(changes.len(), 1);
            assert!(matches!(changes[0], Change::Removed { .. }));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(c2.comparison, ComparisonKind::Compared);
}

// ---------------------------------------------------------------- completeness

#[test]
fn multi_page_chain_completes_only_on_the_last_page() {
    let d = dir();
    let (store, _) = open(d.path());
    let mut e = engine(&store);
    let k = lk(7);
    assert_eq!(
        e.observe_page(&k, page(vec![tool("a", "1")], None, Some(1)))
            .unwrap(),
        ListingProgress::Continue
    );
    assert_eq!(
        e.observe_page(&k, page(vec![tool("b", "2")], Some(1), Some(2)))
            .unwrap(),
        ListingProgress::Continue
    );
    assert!(reports(&store).is_empty(), "nothing is reported mid-chain");
    let c = complete(
        e.observe_page(&k, page(vec![tool("c", "3")], Some(2), None))
            .unwrap(),
    );
    assert_eq!(c.tools.len(), 3);
    assert_eq!(last_report(&store).pages_observed.get(), 3);
}

#[test]
fn a_chain_that_does_not_start_without_a_cursor_is_never_complete() {
    let d = dir();
    let (store, _) = open(d.path());
    let mut e = engine(&store);
    let p = e
        .observe_page(&lk(1), page(vec![tool("a", "1")], Some(1), None))
        .unwrap();
    assert_eq!(
        p,
        ListingProgress::Incomplete(IncompleteReason::CursorInvalid)
    );
    assert_eq!(
        last_report(&store).incomplete_reason,
        Some(IncompleteReason::CursorInvalid)
    );
    assert!(store.latest_snapshot(&scope()).unwrap().is_none());
}

#[test]
fn a_cursor_other_than_the_one_handed_out_breaks_the_chain() {
    let d = dir();
    let (store, _) = open(d.path());
    let mut e = engine(&store);
    let k = lk(5);
    e.observe_page(&k, page(vec![tool("a", "1")], None, Some(1)))
        .unwrap();
    // The next request carries cursor 9, not the cursor 1 page one handed out.
    let p = e
        .observe_page(&k, page(vec![tool("b", "1")], Some(9), None))
        .unwrap();
    assert_eq!(
        p,
        ListingProgress::Incomplete(IncompleteReason::CursorInvalid)
    );
    assert!(store.latest_snapshot(&scope()).unwrap().is_none());
    // A page without a cursor after a page with one is a fresh chain, and a
    // last page that arrives with NO cursor where one was handed out likewise.
    let k2 = lk(6);
    e.observe_page(&k2, page(vec![tool("a", "1")], None, Some(1)))
        .unwrap();
    let p = e
        .observe_page(&k2, page(vec![tool("b", "1")], Some(1), None))
        .unwrap();
    assert!(matches!(p, ListingProgress::Complete(_)));
    // Tags are opaque, equal for equal cursors under one hasher and differ
    // between hashers; they print nothing.
    assert_eq!(hasher().tag("x"), hasher().tag("x"));
    assert_ne!(hasher().tag("x"), CursorHasher::new().unwrap().tag("x"));
    assert!(!format!("{:?} {:?}", hasher().tag("secret-cursor"), hasher()).contains("secret"));
}

#[test]
fn a_quarantined_ref_is_left_out_of_later_listings() {
    let d = dir();
    let (store, _) = open(d.path());
    let mut e = engine(&store);
    let c1 = complete(list(&mut e, 1, vec![tool("keep", "k"), tool("bad", "b")]));
    store
        .quarantine(&ref_of(&c1, "bad"), "central_409")
        .unwrap();
    let c2 = complete(list(&mut e, 1, vec![tool("keep", "k"), tool("bad", "b")]));
    assert_eq!(c2.tools.len(), 1, "the quarantined tool is not a member");
    assert_eq!(
        store.lookup_tool(&scope(), "bad").unwrap(),
        ToolLookup::NotInInventory
    );
    // Compared with the earlier snapshot it simply shows as removed.
    match last_report(&store).comparison.unwrap() {
        Comparison::Compared { changes, .. } => {
            assert_eq!(changes.len(), 1);
            assert!(matches!(changes[0], Change::Removed { .. }));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn restarting_a_chain_or_ending_the_session_records_session_ended() {
    let d = dir();
    let (store, _) = open(d.path());
    let mut e = engine(&store);
    e.observe_page(&lk(1), page(vec![tool("a", "1")], None, Some(1)))
        .unwrap();
    // The client starts over without finishing: the first chain never completed.
    e.observe_page(&lk(1), page(vec![tool("a", "1")], None, Some(1)))
        .unwrap();
    assert_eq!(reports(&store).len(), 1);
    assert_eq!(
        last_report(&store).incomplete_reason,
        Some(IncompleteReason::SessionEnded)
    );
    assert_eq!(e.end_session(1).unwrap(), 1);
    assert_eq!(reports(&store).len(), 2);
    // A session with nothing in progress records nothing.
    assert_eq!(e.end_session(1).unwrap(), 0);
    assert_eq!(reports(&store).len(), 2);
    assert!(store.latest_snapshot(&scope()).unwrap().is_none());
}

#[test]
fn collectors_are_bounded() {
    let d = dir();
    let (store, _) = open(d.path());
    let mut e = engine(&store);
    for s in 0..(MAX_COLLECTORS as u64 + 3) {
        e.observe_page(&lk(s), page(vec![tool("a", "1")], None, Some(1)))
            .unwrap();
    }
    // The three oldest were ended as session_ended.
    assert_eq!(reports(&store).len(), 3);
}

#[test]
fn limits_make_the_listing_incomplete() {
    let d = dir();
    let (store, _) = open(d.path());
    let limits = InventoryLimits {
        max_pages: 2,
        max_tools: 3,
        max_bytes: 10_000,
    };
    let mut e = InventoryEngine::new(store.clone(), EPOCH, limits);

    // pages
    let k = lk(1);
    e.observe_page(&k, page(vec![tool("a", "1")], None, Some(1)))
        .unwrap();
    e.observe_page(&k, page(vec![tool("b", "1")], Some(1), Some(2)))
        .unwrap();
    let p = e
        .observe_page(&k, page(vec![tool("c", "1")], Some(2), Some(3)))
        .unwrap();
    assert_eq!(
        p,
        ListingProgress::Incomplete(IncompleteReason::PageLimitExceeded)
    );

    // tools
    let p = list(
        &mut e,
        2,
        vec![
            tool("a", "1"),
            tool("b", "1"),
            tool("c", "1"),
            tool("d", "1"),
        ],
    );
    assert_eq!(
        p,
        ListingProgress::Incomplete(IncompleteReason::ToolLimitExceeded)
    );

    // bytes
    let p = list(&mut e, 3, vec![tool("big", &"x".repeat(20_000))]);
    assert_eq!(
        p,
        ListingProgress::Incomplete(IncompleteReason::SizeLimitExceeded)
    );

    // one definition over the per-entry bound, even within max_bytes
    let mut big = InventoryEngine::new(
        store.clone(),
        EPOCH,
        InventoryLimits {
            max_pages: 10,
            max_tools: 10,
            max_bytes: 100 * 1024 * 1024,
        },
    );
    let p = list(&mut big, 4, vec![tool("big", &"x".repeat(300 * 1024))]);
    assert_eq!(
        p,
        ListingProgress::Incomplete(IncompleteReason::SizeLimitExceeded)
    );
    assert!(store.latest_snapshot(&scope()).unwrap().is_none());
    assert_eq!(reports(&store).len(), 4);
}

#[test]
fn what_cannot_be_canonicalised_or_named_uniquely_is_incomplete() {
    let d = dir();
    let (store, _) = open(d.path());
    let mut e = engine(&store);
    let bad = |def: &str| ToolInput {
        name: "t".into(),
        definition: def.to_string(),
    };
    for (i, def) in [
        r#"{"name":"t","n":1e400}"#,   // not a finite double
        r#"{"name":"t","a":1,"a":2}"#, // duplicate member
        r#"{"name":"t""#,              // not JSON
        r#"["t"]"#,                    // not an object
        r#"{}"#,                       // empty object
        r#"{"name":"other"}"#,         // name differs from the announced one
    ]
    .iter()
    .enumerate()
    {
        let p = list(&mut e, i as u64, vec![bad(def)]);
        assert_eq!(
            p,
            ListingProgress::Incomplete(IncompleteReason::CanonicalizationFailed),
            "{def}"
        );
    }
    // The same name twice is ambiguous.
    let p = list(&mut e, 99, vec![tool("dup", "1"), tool("dup", "2")]);
    assert_eq!(
        p,
        ListingProgress::Incomplete(IncompleteReason::AmbiguousName)
    );
    assert!(store.latest_snapshot(&scope()).unwrap().is_none());
    assert_eq!(
        store.pending_entry_count().unwrap(),
        0,
        "nothing is minted for an incomplete listing"
    );
}

// ----------------------------------------------------------------- scope keys

#[test]
fn another_credential_scope_is_a_separate_chain_with_no_comparison() {
    let d = dir();
    let (store, _) = open(d.path());
    let mut e = engine(&store);
    let c1 = complete(list(&mut e, 1, vec![tool("a", "1"), tool("b", "1")]));
    let other = ListingKey {
        session: 1,
        scope: ScopeKey::live("px-1", "up-1", "cs-2"),
    };
    let c2 = complete(
        e.observe_page(&other, page(vec![tool("a", "1")], None, None))
            .unwrap(),
    );
    assert_eq!(
        c2.comparison,
        ComparisonKind::InitialBaseline,
        "no marker, no comparison"
    );
    assert_ne!(ref_of(&c1, "a"), ref_of(&c2, "a"), "refs are scope-bound");
    // The old chain is untouched (no removals).
    let s = store.latest_snapshot(&scope()).unwrap().unwrap();
    assert_eq!(s.inventory_id, c1.inventory_id);
    assert_eq!(s.members.len(), 2);
}

// ------------------------------------------------------------- key rotation

#[test]
fn planned_rotation_rebaselines_with_links_and_destroys_the_old_key() {
    let d = dir();
    let (store, _) = open(d.path());
    let mut e = engine(&store);
    let c1 = complete(list(
        &mut e,
        1,
        vec![
            tool("same", "s"),
            tool("edited", "v1"),
            tool("dropped", "d"),
        ],
    ));
    let old_kid = store.key_id();
    let old_file = std::fs::read_to_string(d.path().join(KEY_FILE)).unwrap();

    let rot = store.rotate_key().unwrap();
    assert_eq!(rot.old_key_id, old_kid);
    assert_ne!(rot.new_key_id, old_kid);
    assert_eq!(store.key_id(), rot.new_key_id);
    // Old K is gone from the state directory at once (O-2).
    let new_file = std::fs::read_to_string(d.path().join(KEY_FILE)).unwrap();
    assert_ne!(old_file, new_file);
    let old_key_hex = serde_json::from_str::<serde_json::Value>(&old_file).unwrap()["key"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(!new_file.contains(&old_key_hex));
    for f in std::fs::read_dir(d.path()).unwrap() {
        let bytes = std::fs::read(f.unwrap().path()).unwrap();
        assert!(
            !String::from_utf8_lossy(&bytes).contains(&old_key_hex),
            "the old K must not survive anywhere in the state dir"
        );
    }
    // Old refs stay valid for events already referencing them.
    assert!(store.entry(&ref_of(&c1, "same")).unwrap().is_some());

    let c2 = complete(list(
        &mut e,
        1,
        vec![
            tool("same", "s"),
            tool("edited", "v2"),
            tool("brand-new", "n"),
        ],
    ));
    assert_eq!(
        c2.comparison,
        ComparisonKind::Rebaseline(RebaselineReason::KeyRotation)
    );
    for n in ["same", "edited"] {
        assert_ne!(ref_of(&c1, n), ref_of(&c2, n), "a new K re-mints every ref");
    }
    let r = last_report(&store);
    assert_eq!(r.key_id.as_str(), rot.new_key_id);
    let Some(Comparison::Rebaseline {
        previous_inventory_id,
        reason,
        links,
    }) = r.comparison.clone()
    else {
        panic!("{:?}", r.comparison)
    };
    assert_eq!(previous_inventory_id.as_str(), c1.inventory_id);
    assert_eq!(reason, RebaselineReason::KeyRotation);
    // Only tools with a counterpart are linked; add/remove are simply absent.
    assert_eq!(links.len(), 2);
    let link = |from: &str| {
        links
            .iter()
            .find(|l| l.from_metadata_ref.as_str() == from)
            .unwrap()
    };
    let l_same = link(&ref_of(&c1, "same"));
    assert_eq!(l_same.to_metadata_ref.as_str(), ref_of(&c2, "same"));
    assert_eq!(
        l_same.definition_comparison,
        DefinitionComparison::Identical
    );
    let l_edit = link(&ref_of(&c1, "edited"));
    assert_eq!(l_edit.to_metadata_ref.as_str(), ref_of(&c2, "edited"));
    assert_eq!(
        l_edit.definition_comparison,
        DefinitionComparison::Different
    );
    // I-8 shape: from in previous members, to in this snapshot, each once.
    let members: HashSet<String> = r
        .members
        .unwrap()
        .iter()
        .map(|m| m.as_str().to_string())
        .collect();
    for l in &links {
        assert!(members.contains(l.to_metadata_ref.as_str()));
        assert!(c1
            .tools
            .iter()
            .any(|(_, x)| x == l.from_metadata_ref.as_str()));
    }
    // The wire form of a link carries refs and a closed code, nothing else.
    let wire = serde_json::to_value(&links[0]).unwrap();
    let keys: HashSet<&str> = wire
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        HashSet::from([
            "from_metadata_ref",
            "to_metadata_ref",
            "definition_comparison"
        ])
    );

    // The listing after that is compared within the new domain.
    let c3 = complete(list(&mut e, 1, vec![tool("same", "s")]));
    assert_eq!(c3.comparison, ComparisonKind::Compared);
}

#[test]
fn rotation_survives_a_restart_before_the_next_listing() {
    let d = dir();
    let (store, _) = open(d.path());
    let mut e = engine(&store);
    complete(list(&mut e, 1, vec![tool("a", "1")]));
    store.rotate_key().unwrap();
    drop(e);
    drop(store);
    let (store, kind) = open(d.path());
    assert_eq!(kind, OpenKind::Existing);
    let mut e = engine(&store);
    let c = complete(list(&mut e, 1, vec![tool("a", "1")]));
    assert_eq!(
        c.comparison,
        ComparisonKind::Rebaseline(RebaselineReason::KeyRotation)
    );
}

#[test]
fn losing_the_key_with_the_database_kept_is_state_loss() {
    let d = dir();
    let (store, _) = open(d.path());
    let mut e = engine(&store);
    let c1 = complete(list(&mut e, 1, vec![tool("a", "1")]));
    let old_kid = store.key_id();
    drop(e);
    drop(store);
    std::fs::remove_file(d.path().join(KEY_FILE)).unwrap();

    let (store, kind) = open(d.path());
    assert_eq!(
        kind,
        OpenKind::KeyLost,
        "the caller starts a new producer epoch"
    );
    assert_ne!(store.key_id(), old_kid);
    // Entries are kept (events may reference them); comparison memory is gone.
    assert!(store.entry(&ref_of(&c1, "a")).unwrap().is_some());
    assert!(store.latest_snapshot(&scope()).unwrap().is_none());
    let mut e = engine(&store);
    let c2 = complete(list(&mut e, 1, vec![tool("a", "1")]));
    assert_eq!(c2.comparison, ComparisonKind::InitialBaseline);
    assert!(matches!(
        last_report(&store).comparison,
        Some(Comparison::InitialBaseline {})
    ));
}

#[test]
fn a_database_of_another_proxy_or_a_damaged_key_is_refused() {
    let d = dir();
    let (store, _) = open(d.path());
    drop(store);
    assert!(RegistryStore::open(d.path(), "px-2").is_err());
    std::fs::write(d.path().join(KEY_FILE), b"{}").unwrap();
    std::fs::set_permissions(
        d.path().join(KEY_FILE),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(RegistryStore::open(d.path(), "px-1").is_err());
}
