#![cfg(unix)]
//! T-13b (#306): the registry upload and inventory clients against a scripted
//! server (registry.md R2/R7, README M2b / N11 iii), plus privacy canaries.
//! The real mTLS transport is exercised in `registry_mtls.rs`.

use std::collections::{HashSet, VecDeque};
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use sigil_proxy::inventory::{
    InventoryEngine, InventoryLimits, ListingKey, ListingProgress, PageInput, ToolInput,
};
use sigil_proxy::registry_client::{
    classify_report, classify_upload, ConflictHandler, ConflictReporter, NoDependents,
    RegistryClient, RegistryParams, RegistryTransport, ReportOutcome, StepKind, UploadOutcome,
};
use sigil_proxy::registry_key::ScopeKey;
use sigil_proxy::registry_store::{EntryState, RegistryStore};
use sigil_proxy::status_report::{GapQueue, PostFuture, StatusReply};
use sigil_proxy_api::status::ConflictDetector;
use sigil_proxy_api::{ApiError, ErrorCode, ErrorItem, GapReport, MetadataRef};

const EPOCH: &str = "0f0f0f0f-1111-4222-8333-444444444444";

fn dir() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

fn scope() -> ScopeKey {
    ScopeKey::live("px-1", "up-1", "cs-1")
}

fn tool(name: &str, desc: &str) -> ToolInput {
    ToolInput {
        name: name.to_string(),
        definition: json!({"name": name, "description": desc,
                           "inputSchema": {"type": "object", "properties": {}}})
        .to_string(),
    }
}

fn list(e: &mut InventoryEngine, tools: Vec<ToolInput>) -> sigil_proxy::inventory::CompleteListing {
    match e
        .observe_page(
            &ListingKey {
                session: 1,
                scope: scope(),
            },
            PageInput::Tools {
                request_cursor: None,
                tools,
                next_cursor: None,
            },
        )
        .unwrap()
    {
        ListingProgress::Complete(c) => c,
        other => panic!("{other:?}"),
    }
}

fn reply(status: u16, body: &impl serde::Serialize) -> Option<StatusReply> {
    Some(StatusReply {
        status,
        body: serde_json::to_vec(body).unwrap(),
    })
}

fn err_reply(status: u16, code: ErrorCode, items: Vec<ErrorItem>) -> Option<StatusReply> {
    let e = ApiError::from_code(code);
    reply(
        status,
        &if items.is_empty() {
            e
        } else {
            e.with_items(items)
        },
    )
}

fn item(index: u32, mref: Option<&str>, code: ErrorCode) -> ErrorItem {
    ErrorItem {
        index,
        event_id: None,
        gap_id: None,
        metadata_ref: mref.map(|m| MetadataRef::new(m).unwrap()),
        code,
    }
}

// ------------------------------------------------------------------ the server

#[derive(Default)]
struct SimState {
    registered: HashSet<String>,
    /// Refs the server answers 409 with `metadata_ref` items for.
    conflict: HashSet<String>,
    /// Refs whose presence makes a multi-entry request an unattributed 409.
    hidden_conflict: HashSet<String>,
    /// Refs the server answers 422 (with an index item) for.
    poison: HashSet<String>,
    /// Answer 413 to uploads with more than this many entries.
    max_batch: Option<usize>,
    /// Scripted answers consumed first.
    meta_script: VecDeque<Option<StatusReply>>,
    inv_script: VecDeque<Option<StatusReply>>,
    meta_posts: Vec<Vec<String>>,
    meta_bodies: Vec<Vec<u8>>,
    inv_bodies: Vec<Vec<u8>>,
    log: Vec<&'static str>,
}

#[derive(Default)]
struct Sim(Mutex<SimState>);

impl Sim {
    fn st(&self) -> std::sync::MutexGuard<'_, SimState> {
        self.0.lock().unwrap()
    }
}

struct Tr(Arc<Sim>);

impl RegistryTransport for Tr {
    fn post_metadata(&self, body: Vec<u8>) -> PostFuture<'_> {
        Box::pin(async move {
            let mut s = self.0.st();
            s.log.push("meta");
            s.meta_bodies.push(body.clone());
            let v: Value = serde_json::from_slice(&body).unwrap();
            let refs: Vec<String> = v["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e["metadata_ref"].as_str().unwrap().to_string())
                .collect();
            s.meta_posts.push(refs.clone());
            if let Some(r) = s.meta_script.pop_front() {
                return r;
            }
            if s.max_batch.is_some_and(|m| refs.len() > m) {
                return err_reply(413, ErrorCode::PayloadTooLarge, vec![]);
            }
            let conflicts: Vec<ErrorItem> = refs
                .iter()
                .enumerate()
                .filter(|(_, r)| s.conflict.contains(*r))
                .map(|(i, r)| item(i as u32, Some(r), ErrorCode::RegistryConflict))
                .collect();
            if !conflicts.is_empty() {
                return err_reply(409, ErrorCode::Conflict, conflicts);
            }
            if refs.len() > 1 && refs.iter().any(|r| s.hidden_conflict.contains(r)) {
                return err_reply(409, ErrorCode::Conflict, vec![]);
            }
            if refs.len() == 1 && s.hidden_conflict.contains(&refs[0]) {
                return err_reply(409, ErrorCode::Conflict, vec![]);
            }
            let bad: Vec<ErrorItem> = refs
                .iter()
                .enumerate()
                .filter(|(_, r)| s.poison.contains(*r))
                .map(|(i, _)| item(i as u32, None, ErrorCode::SemanticInvalid))
                .collect();
            if !bad.is_empty() {
                return err_reply(422, ErrorCode::SemanticInvalid, bad);
            }
            let mut registered = Vec::new();
            let mut dup = Vec::new();
            for r in refs {
                if s.registered.insert(r.clone()) {
                    registered.push(r);
                } else {
                    dup.push(r);
                }
            }
            reply(
                200,
                &json!({"registered_metadata_refs": registered, "duplicate_metadata_refs": dup}),
            )
        })
    }

    fn post_inventory(&self, body: Vec<u8>) -> PostFuture<'_> {
        Box::pin(async move {
            let mut s = self.0.st();
            s.log.push("inv");
            s.inv_bodies.push(body.clone());
            if let Some(r) = s.inv_script.pop_front() {
                return r;
            }
            let v: Value = serde_json::from_slice(&body).unwrap();
            let missing: Vec<MetadataRef> = v["members"]
                .as_array()
                .map(|a| a.as_slice())
                .unwrap_or_default()
                .iter()
                .map(|m| m.as_str().unwrap().to_string())
                .filter(|m| !s.registered.contains(m))
                .map(|m| MetadataRef::new(m).unwrap())
                .collect();
            if !missing.is_empty() {
                return reply(
                    424,
                    &ApiError::from_code(ErrorCode::MetadataRefPending)
                        .with_pending_metadata_refs(missing),
                );
            }
            reply(200, &json!({}))
        })
    }
}

struct Events(Arc<Mutex<Vec<(String, String)>>>, Vec<String>);

impl ConflictHandler for Events {
    fn registry_conflict(&mut self, r: &str, k: &str) -> Vec<String> {
        self.0.lock().unwrap().push((r.to_string(), k.to_string()));
        self.1.clone()
    }
}

struct Fx {
    _d: tempfile::TempDir,
    store: RegistryStore,
    engine: InventoryEngine,
    sim: Arc<Sim>,
    gaps: GapQueue,
    handled: Arc<Mutex<Vec<(String, String)>>>,
    client: RegistryClient<Tr>,
}

fn fx_with(event_ids: Vec<String>) -> Fx {
    let d = dir();
    let (store, _) = RegistryStore::open(d.path(), "px-1").unwrap();
    let engine = InventoryEngine::new(store.clone(), EPOCH, InventoryLimits::default());
    let sim = Arc::new(Sim::default());
    let gaps = GapQueue::new();
    let handled = Arc::new(Mutex::new(Vec::new()));
    let conflicts = ConflictReporter::new(
        store.clone(),
        gaps.clone(),
        Box::new(Events(handled.clone(), event_ids)),
    );
    let client = RegistryClient::new(
        store.clone(),
        Tr(sim.clone()),
        conflicts,
        RegistryParams {
            poll: Duration::from_secs(1),
            retry: Duration::from_secs(5),
            max_backoff: Duration::from_secs(60),
            min_spacing: Duration::from_millis(10),
        },
    );
    Fx {
        _d: d,
        store,
        engine,
        sim,
        gaps,
        handled,
        client,
    }
}

fn fx() -> Fx {
    fx_with(vec![])
}

async fn drain(c: &mut RegistryClient<Tr>) {
    for _ in 0..40 {
        if c.sync_once().await.kind == StepKind::Idle {
            return;
        }
    }
    panic!("did not go idle");
}

fn uuid(n: u8) -> String {
    format!("{n:08x}-0000-4000-8000-000000000000")
}

// --------------------------------------------------------------------- tests

#[tokio::test]
async fn entries_are_uploaded_before_the_report_that_names_them() {
    let mut f = fx();
    let c = list(&mut f.engine, vec![tool("a", "da"), tool("b", "db")]);
    let s1 = f.client.sync_once().await;
    assert_eq!(
        s1.kind,
        StepKind::Upload(UploadOutcome::Done {
            refs: c.tools.iter().map(|(_, r)| r.clone()).collect()
        })
    );
    let s2 = f.client.sync_once().await;
    assert_eq!(s2.kind, StepKind::Report(ReportOutcome::Done));
    assert_eq!(f.client.sync_once().await.kind, StepKind::Idle);
    assert_eq!(f.sim.st().log, vec!["meta", "inv"]);
    for (_, r) in &c.tools {
        assert_eq!(f.store.entry(r).unwrap().unwrap().state, EntryState::Acked);
    }
    assert!(f.store.pending_reports(10).unwrap().is_empty());

    // Both bodies are valid against the contract types.
    let meta = f.sim.st().meta_bodies[0].clone();
    let up = sigil_proxy_api::parse_upload(&meta).unwrap();
    assert_eq!(up.proxy_id.as_str(), "px-1");
    assert_eq!(up.entries.len(), 2);
    assert!(up.entries.iter().all(|e| e.definition.is_object()));
    let inv = f.sim.st().inv_bodies[0].clone();
    sigil_proxy_api::parse_inventory_report(&inv).unwrap();
    // The report never carries a name or a definition.
    let text = String::from_utf8(inv).unwrap();
    assert!(
        !text.contains("description") && !text.contains("\"a\"") && !text.contains("inputSchema")
    );
    // The ACK recorded the immutable-field hash; it verifies.
    for (_, r) in &c.tools {
        assert_eq!(
            f.store.verify_entry(r).unwrap(),
            sigil_proxy::registry_store::EntryCheck::Verified
        );
    }
}

#[tokio::test]
async fn re_upload_of_known_entries_is_a_duplicate_ack() {
    let mut f = fx();
    let c = list(&mut f.engine, vec![tool("a", "da")]);
    drain(&mut f.client).await;
    // The server forgot nothing; a second proxy run lists the same tool again.
    let c2 = list(&mut f.engine, vec![tool("a", "da")]);
    assert_eq!(c.tools, c2.tools);
    drain(&mut f.client).await;
    assert_eq!(
        f.sim.st().meta_posts.len(),
        1,
        "an acked entry is not uploaded again"
    );
    assert_eq!(f.sim.st().log.iter().filter(|l| **l == "inv").count(), 2);
}

#[tokio::test]
async fn a_409_quarantines_the_entry_reports_the_gap_and_drops_the_dependent_report() {
    let ids: Vec<String> = (1..=3).map(uuid).collect();
    let mut f = fx_with(ids.clone());
    let c = list(&mut f.engine, vec![tool("good", "g"), tool("bad", "b")]);
    let bad = c.tools.iter().find(|(n, _)| n == "bad").unwrap().1.clone();
    let good = c.tools.iter().find(|(n, _)| n == "good").unwrap().1.clone();
    f.sim.st().conflict.insert(bad.clone());

    let s = f.client.sync_once().await;
    assert_eq!(
        s.kind,
        StepKind::Upload(UploadOutcome::Conflict {
            refs: vec![bad.clone()]
        })
    );
    assert!(s.progressed);
    assert_eq!(
        f.store.entry(&bad).unwrap().unwrap().state,
        EntryState::Quarantined
    );
    // The spool seam was called once with the ref and its key_id.
    assert_eq!(
        f.handled.lock().unwrap().clone(),
        vec![(bad.clone(), f.store.key_id())]
    );
    // The integrity gap: kind, ref, key_id, event ids, no field values.
    let gaps = f.gaps.pending_batch();
    assert_eq!(gaps.len(), 1);
    let GapReport::RegistryConflict(g) = &gaps[0] else {
        panic!("{gaps:?}")
    };
    assert_eq!(g.metadata_ref.as_str(), bad);
    assert_eq!(g.key_id.as_str(), f.store.key_id());
    assert_eq!(g.detected_by, ConflictDetector::Central409);
    assert_eq!(g.affected_event_count.get(), 3);
    assert_eq!(
        g.event_ids
            .iter()
            .map(|u| u.as_str().to_string())
            .collect::<Vec<_>>(),
        ids
    );
    let wire = serde_json::to_string(&gaps[0]).unwrap();
    assert!(!wire.contains("description") && !wire.contains("fingerprint"));

    // The rest is resent; the quarantined entry never is.
    drain(&mut f.client).await;
    assert_eq!(
        f.store.entry(&good).unwrap().unwrap().state,
        EntryState::Acked
    );
    let posts = f.sim.st().meta_posts.clone();
    assert_eq!(posts.len(), 2);
    assert_eq!(posts[1], vec![good]);
    // The report names the quarantined member, so it can never be accepted.
    assert_eq!(f.client.discarded_reports(), 1);
    // The server never saw that snapshot: the chain restarts at a baseline.
    assert!(f.store.latest_snapshot(&scope()).unwrap().is_none());
    assert!(f.sim.st().log.iter().all(|l| *l != "inv"));
    assert!(f.store.pending_reports(10).unwrap().is_empty());
    // A second quarantine of the same ref is a no-op (no second gap).
    f.client
        .conflicts()
        .report_conflict(&bad, ConflictDetector::Central409)
        .unwrap();
    assert_eq!(f.gaps.pending_batch().len(), 1);
}

#[tokio::test]
async fn gap_event_ids_are_chunked_at_100_with_the_same_total() {
    let ids: Vec<String> = (0..230u32)
        .map(|n| format!("{n:08x}-0000-4000-8000-000000000000"))
        .collect();
    let mut f = fx_with(ids);
    let c = list(&mut f.engine, vec![tool("bad", "b")]);
    f.sim.st().conflict.insert(c.tools[0].1.clone());
    f.client.sync_once().await;
    let gaps = f.gaps.pending_batch();
    assert_eq!(gaps.len(), 3);
    let mut total = 0;
    for g in &gaps {
        let GapReport::RegistryConflict(g) = g else {
            panic!()
        };
        assert!(g.event_ids.len() <= 100);
        assert_eq!(g.affected_event_count.get(), 230);
        total += g.event_ids.len();
    }
    assert_eq!(total, 230);
}

#[tokio::test]
async fn an_unattributed_409_is_isolated_by_singles() {
    let mut f = fx();
    let c = list(
        &mut f.engine,
        vec![tool("a", "1"), tool("culprit", "2"), tool("c", "3")],
    );
    let culprit = c.tools[1].1.clone();
    f.sim.st().hidden_conflict.insert(culprit.clone());
    drain(&mut f.client).await;
    assert_eq!(
        f.store.entry(&culprit).unwrap().unwrap().state,
        EntryState::Quarantined
    );
    for (n, r) in &c.tools {
        if n != "culprit" {
            assert_eq!(f.store.entry(r).unwrap().unwrap().state, EntryState::Acked);
        }
    }
    assert_eq!(f.handled.lock().unwrap().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn a_poisoned_entry_holds_back_neither_good_entries_nor_unrelated_reports() {
    let mut f = fx();
    let c = list(
        &mut f.engine,
        vec![tool("a", "1"), tool("poison", "2"), tool("c", "3")],
    );
    let poison = c.tools[1].1.clone();
    f.sim.st().poison.insert(poison.clone());
    let s = f.client.sync_once().await;
    assert_eq!(
        s.kind,
        StepKind::Upload(UploadOutcome::Invalid {
            refs: vec![poison.clone()]
        })
    );
    assert!(
        s.progressed,
        "a refusal of one entry does not back the link off"
    );
    // The others go through at once, together and without it.
    let s = f.client.sync_once().await;
    assert!(matches!(
        s.kind,
        StepKind::Upload(UploadOutcome::Done { .. })
    ));
    let posts = f.sim.st().meta_posts.clone();
    assert_eq!(posts[1].len(), 2);
    assert!(!posts[1].contains(&poison));
    // New unrelated work flows while the refused entry waits for its retry time.
    let other = list(&mut f.engine, vec![tool("x", "9")]);
    let _ = other;
    assert!(matches!(
        f.client.sync_once().await.kind,
        StepKind::Upload(UploadOutcome::Done { .. })
    ));
    // The first report (which names the refused entry) waits; the second one,
    // which does not, is sent.
    let s = f.client.sync_once().await;
    assert_eq!(s.kind, StepKind::Report(ReportOutcome::Done));
    assert_eq!(f.sim.st().log.iter().filter(|l| **l == "inv").count(), 1);
    assert_eq!(f.store.pending_reports(10).unwrap().len(), 1);
    // After the retry time the refused entry is tried alone, until it is
    // poisoned (3 refusals), never quarantined.
    for _ in 0..2 {
        tokio::time::advance(Duration::from_secs(120)).await;
        let s = f.client.sync_once().await;
        assert!(matches!(
            s.kind,
            StepKind::Upload(UploadOutcome::Invalid { .. })
        ));
    }
    assert_eq!(f.sim.st().meta_posts.last().unwrap(), &vec![poison.clone()]);
    assert_eq!(
        f.store.entry(&poison).unwrap().unwrap().state,
        EntryState::Poisoned
    );
    assert_eq!(f.client.health().unwrap().poisoned_entries, 1);
    // The report that names it is given up and its chain reset.
    let s = f.client.sync_once().await;
    assert_eq!(s.kind, StepKind::Dropped);
    assert_eq!(f.client.discarded_reports(), 1);
    assert!(f.store.pending_reports(10).unwrap().is_empty());
    assert_eq!(f.client.sync_once().await.kind, StepKind::Idle);
}

#[tokio::test]
async fn a_single_entry_413_is_poisoned_not_retried_forever() {
    let mut f = fx();
    let c = list(&mut f.engine, vec![tool("a", "1")]);
    f.sim.st().max_batch = Some(0);
    let s = f.client.sync_once().await;
    assert_eq!(s.kind, StepKind::Upload(UploadOutcome::TooLarge));
    assert_eq!(
        f.store.entry(&c.tools[0].1).unwrap().unwrap().state,
        EntryState::Poisoned
    );
    assert_eq!(f.client.health().unwrap().poisoned_entries, 1);
    let n = f.sim.st().meta_posts.len();
    for _ in 0..5 {
        f.client.sync_once().await;
    }
    assert_eq!(f.sim.st().meta_posts.len(), n, "never uploaded again");
}

#[tokio::test]
async fn discarding_a_report_rewrites_the_reports_that_were_built_on_it() {
    let mut f = fx();
    // A = [keep, gone]; B = [keep] compared with A, both queued before any send.
    let a = list(&mut f.engine, vec![tool("keep", "k"), tool("gone", "g")]);
    let b = list(&mut f.engine, vec![tool("keep", "k")]);
    let gone = a.tools.iter().find(|(n, _)| n == "gone").unwrap().1.clone();
    f.sim.st().conflict.insert(gone.clone());
    drain(&mut f.client).await;
    assert_eq!(
        f.client.discarded_reports(),
        1,
        "A names a quarantined member"
    );
    // Only B reached the server, and as a baseline (its previous, A, never did).
    let bodies = f.sim.st().inv_bodies.clone();
    assert_eq!(bodies.len(), 1);
    let r = sigil_proxy_api::parse_inventory_report(&bodies[0]).unwrap();
    assert_eq!(r.inventory_id.unwrap().as_str(), b.inventory_id);
    assert!(matches!(
        r.comparison,
        Some(sigil_proxy_api::Comparison::InitialBaseline {})
    ));
    // The local latest snapshot is B, and the next listing compares with it.
    assert_eq!(
        f.store
            .latest_snapshot(&scope())
            .unwrap()
            .unwrap()
            .inventory_id,
        b.inventory_id
    );
}

#[tokio::test]
async fn a_report_the_server_keeps_calling_pending_is_given_up_after_a_cap() {
    let mut f = fx();
    let c = list(&mut f.engine, vec![tool("a", "1")]);
    let r = c.tools[0].1.clone();
    for _ in 0..5 {
        f.sim.st().inv_script.push_back(reply(
            424,
            &ApiError::from_code(ErrorCode::MetadataRefPending)
                .with_pending_metadata_refs(vec![MetadataRef::new(r.clone()).unwrap()]),
        ));
    }
    let mut backoffs = 0;
    for _ in 0..40 {
        let s = f.client.sync_once().await;
        if matches!(s.kind, StepKind::Report(ReportOutcome::Pending { .. })) {
            assert!(!s.progressed || f.client.discarded_reports() == 1);
            backoffs += 1;
        }
        if s.kind == StepKind::Idle {
            break;
        }
    }
    assert_eq!(backoffs, 5);
    assert_eq!(f.client.discarded_reports(), 1);
    assert!(f.store.latest_snapshot(&scope()).unwrap().is_none());
}

#[tokio::test]
async fn an_unfinished_conflict_is_finished_after_a_restart() {
    let mut f = fx_with(vec![uuid(1), uuid(2)]);
    let c = list(&mut f.engine, vec![tool("a", "1")]);
    let r = c.tools[0].1.clone();
    // Crash after the quarantine row was written, before the seam and the gap.
    assert!(f.store.quarantine(&r, "central_409").unwrap());
    assert_eq!(f.store.gap_pending().unwrap().len(), 1);
    assert!(f.gaps.pending_batch().is_empty());
    f.client.sync_once().await; // first step resumes
    let gaps = f.gaps.pending_batch();
    assert_eq!(gaps.len(), 1);
    let GapReport::RegistryConflict(g) = &gaps[0] else {
        panic!()
    };
    assert_eq!(g.detected_by, ConflictDetector::Central409);
    assert_eq!(g.metadata_ref.as_str(), r);
    assert!(f.store.gap_pending().unwrap().is_empty());
    assert_eq!(f.handled.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn the_largest_entry_with_the_longest_ids_fits_the_limit() {
    use sigil_proxy::registry_store::MAX_DEFINITION_BYTES;
    let d = dir();
    let proxy = format!("p{}", "x".repeat(127));
    let (store, _) = RegistryStore::open(d.path(), &proxy).unwrap();
    let sc = ScopeKey::live(
        &proxy,
        &format!("u{}", "y".repeat(127)),
        &format!("c{}", "z".repeat(127)),
    );
    let mk = |len: usize| ToolInput {
        name: "t".into(),
        definition: json!({"name": "t", "description": "d".repeat(len),
                           "inputSchema": {"type": "object"}})
        .to_string(),
    };
    let overhead = sigil_proxy::jcs::canonicalize_str(&mk(0).definition)
        .unwrap()
        .len();
    let mut e = InventoryEngine::new(
        store.clone(),
        EPOCH,
        InventoryLimits {
            max_pages: 10,
            max_tools: 10,
            max_bytes: 100 << 20,
        },
    );
    let key = ListingKey {
        session: 1,
        scope: sc.clone(),
    };
    let go = |e: &mut InventoryEngine, t: ToolInput| {
        e.observe_page(
            &key,
            PageInput::Tools {
                request_cursor: None,
                tools: vec![t],
                next_cursor: None,
            },
        )
        .unwrap()
    };
    // One byte over the bound is refused as too large.
    assert_eq!(
        go(&mut e, mk(MAX_DEFINITION_BYTES - overhead + 1)),
        ListingProgress::Incomplete(sigil_proxy_api::registry::IncompleteReason::SizeLimitExceeded)
    );
    assert!(matches!(
        go(&mut e, mk(MAX_DEFINITION_BYTES - overhead)),
        ListingProgress::Complete(_)
    ));
    let sim = Arc::new(Sim::default());
    let mut client = RegistryClient::new(
        store.clone(),
        Tr(sim.clone()),
        ConflictReporter::new(store.clone(), GapQueue::new(), Box::new(NoDependents)),
        RegistryParams::default(),
    );
    assert!(matches!(
        client.sync_once().await.kind,
        StepKind::Upload(UploadOutcome::Done { .. })
    ));
    let body = sim.st().meta_bodies[0].clone();
    let v: Value = serde_json::from_slice(&body).unwrap();
    let entry = serde_json::to_vec(&v["entries"][0]).unwrap();
    assert!(entry.len() <= 256 * 1024, "entry is {} bytes", entry.len());
    assert!(entry.len() > MAX_DEFINITION_BYTES);
    assert_eq!(client.health().unwrap().poisoned_entries, 0);
}

#[tokio::test]
async fn a_413_halves_the_batch_and_success_grows_it_back() {
    let mut f = fx();
    let tools: Vec<ToolInput> = (0..8).map(|i| tool(&format!("t{i}"), "d")).collect();
    list(&mut f.engine, tools);
    f.sim.st().max_batch = Some(2);
    let s = f.client.sync_once().await;
    assert_eq!(s.kind, StepKind::Upload(UploadOutcome::TooLarge));
    drain(&mut f.client).await;
    let sizes: Vec<usize> = f.sim.st().meta_posts.iter().map(Vec::len).collect();
    assert_eq!(sizes[0], 8);
    assert_eq!(
        sizes[1], 4,
        "halved from the 8 that were refused: {sizes:?}"
    );
    assert_eq!(f.store.pending_entry_count().unwrap(), 0);
}

#[tokio::test]
async fn a_424_on_the_report_uploads_the_named_entries_again() {
    let mut f = fx();
    let c = list(&mut f.engine, vec![tool("a", "1"), tool("b", "2")]);
    f.client.sync_once().await; // upload
                                // The server "lost" one registration.
    let lost = c.tools[0].1.clone();
    f.sim.st().registered.remove(&lost);
    let s = f.client.sync_once().await;
    assert_eq!(
        s.kind,
        StepKind::Report(ReportOutcome::Pending {
            refs: vec![lost.clone()]
        })
    );
    assert_eq!(
        f.store.entry(&lost).unwrap().unwrap().state,
        EntryState::Pending
    );
    drain(&mut f.client).await;
    assert_eq!(f.sim.st().meta_posts.last().unwrap(), &vec![lost]);
    assert!(f.store.pending_reports(10).unwrap().is_empty());
    assert_eq!(f.client.discarded_reports(), 0);
}

#[tokio::test]
async fn a_report_the_server_cannot_accept_is_discarded_not_retried_forever() {
    for status in [409u16, 413, 422] {
        let mut f = fx();
        list(&mut f.engine, vec![tool("a", "1")]);
        f.client.sync_once().await;
        f.sim.st().inv_script.push_back(err_reply(
            status,
            match status {
                409 => ErrorCode::Conflict,
                413 => ErrorCode::PayloadTooLarge,
                _ => ErrorCode::SemanticInvalid,
            },
            vec![],
        ));
        let s = f.client.sync_once().await;
        assert_eq!(s.kind, StepKind::Report(ReportOutcome::Discard { status }));
        assert!(f.store.pending_reports(10).unwrap().is_empty());
        assert_eq!(f.client.discarded_reports(), 1);
        assert_eq!(f.client.sync_once().await.kind, StepKind::Idle);
    }
}

#[tokio::test]
async fn failures_back_off_with_a_bound_and_success_resets() {
    let mut f = fx();
    list(&mut f.engine, vec![tool("a", "1")]);
    let answers: Vec<Option<StatusReply>> = vec![
        None,
        err_reply(503, ErrorCode::StorageUnavailable, vec![]),
        err_reply(429, ErrorCode::RateLimited, vec![]),
        err_reply(404, ErrorCode::ProxyUnknown, vec![]),
        err_reply(403, ErrorCode::Disabled, vec![]),
        reply(200, &json!({"unexpected": true})),
        err_reply(500, ErrorCode::StorageUnavailable, vec![]),
    ];
    let mut delays = Vec::new();
    for a in answers {
        f.sim.st().meta_script.push_back(a);
        let s = f.client.sync_once().await;
        assert!(!s.progressed, "{:?}", s.kind);
        delays.push(f.client.next_delay(&s));
    }
    // Jittered in [d/2, d] with d doubling from 5 s up to the 60 s cap.
    for (i, d) in delays.iter().enumerate() {
        let base = Duration::from_secs((5u64 << i.min(10)).min(60));
        assert!(*d >= base / 2 && *d <= base, "step {i}: {d:?} vs {base:?}");
    }
    // Nothing was lost meanwhile: success follows and resets the streak.
    let s = f.client.sync_once().await;
    assert!(s.progressed);
    assert_eq!(f.client.consecutive_failures(), 0);
    assert_eq!(f.client.next_delay(&s), Duration::from_millis(10));
}

#[tokio::test]
async fn run_stops_on_shutdown() {
    let f = fx();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let h = tokio::spawn(f.client.run(async {
        let _ = rx.await;
    }));
    tokio::time::sleep(Duration::from_millis(30)).await;
    tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), h)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn the_local_hash_check_catches_a_tampered_entry() {
    let mut f = fx_with(vec![uuid(9)]);
    let c = list(&mut f.engine, vec![tool("a", "1"), tool("b", "2")]);
    drain(&mut f.client).await;
    let (a, b) = (c.tools[0].1.clone(), c.tools[1].1.clone());
    let refs = vec![a.clone(), b.clone()];
    assert!(f
        .client
        .conflicts()
        .check_entries(&refs)
        .unwrap()
        .is_empty());

    // Somebody edits the local registry file behind the proxy's back.
    let db = f._d.path().join("registry.sqlite3");
    let conn = rusqlite::Connection::open(&db).unwrap();
    conn.execute(
        "UPDATE entries SET fingerprint = ?1 WHERE metadata_ref = ?2",
        rusqlite::params!["0".repeat(64), a],
    )
    .unwrap();
    drop(conn);

    let bad = f.client.conflicts().check_entries(&refs).unwrap();
    assert_eq!(bad, vec![a.clone()]);
    assert_eq!(
        f.store.entry(&a).unwrap().unwrap().state,
        EntryState::Quarantined
    );
    assert_eq!(f.store.entry(&b).unwrap().unwrap().state, EntryState::Acked);
    let gaps = f.gaps.pending_batch();
    let GapReport::RegistryConflict(g) = &gaps[0] else {
        panic!()
    };
    assert_eq!(g.detected_by, ConflictDetector::LocalHashCheck);
    assert_eq!(g.metadata_ref.as_str(), a);
    // Once quarantined the ref stays unusable.
    assert_eq!(f.client.conflicts().check_entries(&refs).unwrap(), vec![a]);
}

#[tokio::test]
async fn key_rotation_reports_flow_through_the_client() {
    let mut f = fx();
    list(&mut f.engine, vec![tool("a", "1")]);
    drain(&mut f.client).await;
    f.store.rotate_key().unwrap();
    let c = list(&mut f.engine, vec![tool("a", "1")]);
    drain(&mut f.client).await;
    let body = f.sim.st().inv_bodies.last().unwrap().clone();
    let r = sigil_proxy_api::parse_inventory_report(&body).unwrap();
    assert!(matches!(
        r.comparison,
        Some(sigil_proxy_api::Comparison::Rebaseline { .. })
    ));
    assert_eq!(r.key_id.as_str(), f.store.key_id());
    assert_eq!(
        f.store.entry(&c.tools[0].1).unwrap().unwrap().state,
        EntryState::Acked
    );
}

// ----------------------------------------------------------- pure classifiers

#[test]
fn classifiers_are_fail_closed() {
    let sent = vec![uuid(1), uuid(2)]
        .into_iter()
        .map(|u| u.replace("-4000-8000", "-8000-8000"))
        .collect::<Vec<_>>();
    // 200 that names nothing we sent is not an ACK.
    let ok = reply(
        200,
        &json!({"registered_metadata_refs": [sent[0]], "duplicate_metadata_refs": []}),
    );
    assert_eq!(
        classify_upload(ok.as_ref(), &sent),
        UploadOutcome::Done {
            refs: vec![sent[0].clone()]
        }
    );
    let foreign = reply(
        200,
        &json!({"registered_metadata_refs": [uuid(7).replace("-4000-8000", "-8000-8000")], "duplicate_metadata_refs": []}),
    );
    assert_eq!(
        classify_upload(foreign.as_ref(), &sent),
        UploadOutcome::Retry
    );
    assert_eq!(
        classify_upload(
            Some(&StatusReply {
                status: 200,
                body: b"junk".to_vec()
            }),
            &sent
        ),
        UploadOutcome::Retry
    );
    assert_eq!(classify_upload(None, &sent), UploadOutcome::Unreachable);
    // 409 by index falls back to the sent order.
    let by_index = err_reply(
        409,
        ErrorCode::Conflict,
        vec![item(1, None, ErrorCode::RegistryConflict)],
    );
    assert_eq!(
        classify_upload(by_index.as_ref(), &sent),
        UploadOutcome::Conflict {
            refs: vec![sent[1].clone()]
        }
    );
    // An item naming a ref we did not send is not trusted.
    let alien = item(
        5,
        Some(&uuid(9).replace("-4000-8000", "-8000-8000")),
        ErrorCode::RegistryConflict,
    );
    assert_eq!(
        classify_upload(
            err_reply(409, ErrorCode::Conflict, vec![alien]).as_ref(),
            &sent
        ),
        UploadOutcome::UnattributedConflict
    );
    assert_eq!(classify_report(None), ReportOutcome::Unreachable);
    assert_eq!(
        classify_report(err_reply(503, ErrorCode::StorageUnavailable, vec![]).as_ref()),
        ReportOutcome::Unavailable
    );
    assert_eq!(
        classify_report(err_reply(403, ErrorCode::Forbidden, vec![]).as_ref()),
        ReportOutcome::Retry,
        "only disabled/retired are a rejection"
    );
}

// ------------------------------------------------------------------- privacy

/// A tracing subscriber that records everything any code path writes.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Capture {
        self.clone()
    }
}

const NAME_CANARY: &str = "CANARY_TOOL_NAME_7f3a";
const DESC_CANARY: &str = "CANARY_DESCRIPTION_SECRET_91bc";

#[tokio::test]
async fn definitions_and_keys_never_reach_logs_errors_reports_or_gaps() {
    let cap = Capture::default();
    let sub = tracing_subscriber::fmt()
        .with_writer(cap.clone())
        .with_max_level(tracing::Level::TRACE)
        .finish();
    let _g = tracing::subscriber::set_default(sub);

    let mut f = fx_with(vec![uuid(1)]);
    let mut seen_text = String::new();
    let mut note = |s: String| seen_text.push_str(&s);

    // A listing with canary content, one canary tool that conflicts, and
    // failure paths whose errors must be content-free.
    let c = list(
        &mut f.engine,
        vec![tool(NAME_CANARY, DESC_CANARY), tool("other", DESC_CANARY)],
    );
    note(format!("{c:?}"));
    for bad in [
        format!(r#"{{"name":"{NAME_CANARY}","d":"{DESC_CANARY}","n":9007199254740993}}"#),
        format!(r#"{{"name":"{NAME_CANARY}","d":"{DESC_CANARY}","d":1}}"#),
        format!(r#"{{"name":"{NAME_CANARY}","d":"{DESC_CANARY}""#),
    ] {
        let p = f
            .engine
            .observe_page(
                &ListingKey {
                    session: 9,
                    scope: scope(),
                },
                PageInput::Tools {
                    request_cursor: None,
                    tools: vec![ToolInput {
                        name: NAME_CANARY.into(),
                        definition: bad.clone(),
                    }],
                    next_cursor: None,
                },
            )
            .unwrap();
        note(format!("{p:?}"));
        note(format!(
            "{:?}",
            ToolInput {
                name: NAME_CANARY.into(),
                definition: bad.clone()
            }
        ));
        if let Err(e) = sigil_proxy::jcs::canonicalize_str(&bad) {
            note(format!("{e} {e:?}"));
        }
    }
    let conflicted = c.tools[0].1.clone();
    f.sim.st().conflict.insert(conflicted.clone());
    drain(&mut f.client).await;
    let rec = f.store.entry(&conflicted).unwrap().unwrap();
    note(format!(
        "{rec:?} {:?} {:?}",
        f.store,
        f.store.latest_snapshot(&scope()).unwrap()
    ));
    note(format!("{:?}", f.store.pending_entries(10, true).unwrap()));
    let key = std::fs::read_to_string(f._d.path().join("registry_key.json")).unwrap();
    let key_hex = serde_json::from_str::<Value>(&key).unwrap()["key"]
        .as_str()
        .unwrap()
        .to_string();
    for g in f.gaps.pending_batch() {
        note(serde_json::to_string(&g).unwrap());
    }
    let r = f.store.rotate_key().unwrap();
    note(format!("{r:?}"));
    note(format!("{:?}", f.engine.store()));

    // Logs: nothing was written (and nothing contains a canary or K).
    let logs = String::from_utf8_lossy(&cap.0.lock().unwrap()).to_string();
    for hay in [logs.as_str(), seen_text.as_str()] {
        for needle in [NAME_CANARY, DESC_CANARY, key_hex.as_str()] {
            assert!(!hay.contains(needle), "leak of {needle}");
        }
    }

    // Wire: the inventory report and the gap carry no content; the upload carries
    // the definition (R2) and nothing secret; K never travels.
    let sim = f.sim.st();
    for body in &sim.inv_bodies {
        let t = String::from_utf8_lossy(body);
        assert!(!t.contains(NAME_CANARY) && !t.contains(DESC_CANARY) && !t.contains(&key_hex));
    }
    assert!(sim
        .meta_bodies
        .iter()
        .any(|b| String::from_utf8_lossy(b).contains(DESC_CANARY)));
    for body in &sim.meta_bodies {
        assert!(!String::from_utf8_lossy(body).contains(&key_hex));
    }
    drop(sim);

    // At rest: the key lives only in the 0600 key file. Content lives only in
    // the entry columns the contract allows (tool_name, definition).
    drop(f.client);
    drop(f.engine);
    let db_path = f._d.path().join("registry.sqlite3");
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let mut tables_sorted = tables.clone();
    tables_sorted.sort();
    assert_eq!(
        tables_sorted,
        [
            "entries",
            "meta",
            "reports",
            "rotations",
            "snapshot_members",
            "snapshots"
        ]
    );
    for t in &tables {
        let cols: Vec<String> = conn
            .prepare(&format!("SELECT name FROM pragma_table_info('{t}')"))
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        for col in cols {
            let n: i64 = conn
                .query_row(
                    &format!("SELECT count(*) FROM {t} WHERE CAST({col} AS TEXT) LIKE '%CANARY%'"),
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            let allowed = t == "entries" && (col == "tool_name" || col == "definition");
            assert!(allowed || n == 0, "content found in {t}.{col}");
            let k: i64 = conn
                .query_row(
                    &format!("SELECT count(*) FROM {t} WHERE CAST({col} AS TEXT) LIKE ?1"),
                    [format!("%{key_hex}%")],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(k, 0, "K in {t}.{col}");
        }
    }
    let meta_json = serde_json::to_string(
        &conn
            .prepare("SELECT key, value FROM meta ORDER BY key")
            .unwrap()
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
    )
    .unwrap();
    assert!(meta_json.contains("proxy_id") && !meta_json.contains("CANARY"));
    // The stored definition is the tool object and nothing the proxy added.
    let def: String = conn
        .query_row(
            "SELECT definition FROM entries WHERE metadata_ref = ?1",
            [&conflicted],
            |r| r.get(0),
        )
        .unwrap();
    let v: Value = serde_json::from_str(&def).unwrap();
    let keys: HashSet<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(keys, HashSet::from(["name", "description", "inputSchema"]));
}

#[tokio::test(start_paused = true)]
async fn poison_is_a_pause_it_ends_after_the_interval_and_on_restart() {
    let mut f = fx();
    let c = list(&mut f.engine, vec![tool("a", "1")]);
    let r = c.tools[0].1.clone();
    f.sim.st().max_batch = Some(0);
    f.client.sync_once().await;
    assert_eq!(
        f.store.entry(&r).unwrap().unwrap().state,
        EntryState::Poisoned
    );
    assert_eq!(
        f.client.health().unwrap().poisoned_entries,
        1,
        "counted while poisoned"
    );
    let posts = f.sim.st().meta_posts.len();
    // Not retried before the interval...
    tokio::time::advance(Duration::from_secs(60)).await;
    f.client.sync_once().await;
    assert_eq!(f.sim.st().meta_posts.len(), posts);
    // ...but after it (jittered, at most POISON_RETRY) the entry is offered again.
    f.sim.st().max_batch = None;
    tokio::time::advance(sigil_proxy::registry_client::POISON_RETRY).await;
    drain(&mut f.client).await;
    assert_eq!(f.sim.st().meta_posts.len(), posts + 1);
    assert_eq!(f.store.entry(&r).unwrap().unwrap().state, EntryState::Acked);
    assert_eq!(f.client.health().unwrap().poisoned_entries, 0);

    // A restart (a new client over the same store) also gives it another go.
    let c2 = list(&mut f.engine, vec![tool("b", "2")]);
    let r2 = c2.tools[0].1.clone();
    f.sim.st().max_batch = Some(0);
    f.client.sync_once().await;
    assert_eq!(
        f.store.entry(&r2).unwrap().unwrap().state,
        EntryState::Poisoned
    );
    f.sim.st().max_batch = None;
    let conflicts = ConflictReporter::new(f.store.clone(), f.gaps.clone(), Box::new(NoDependents));
    let mut fresh = RegistryClient::new(
        f.store.clone(),
        Tr(f.sim.clone()),
        conflicts,
        RegistryParams::default(),
    );
    assert_eq!(
        f.store.entry(&r2).unwrap().unwrap().state,
        EntryState::Poisoned
    );
    drain(&mut fresh).await;
    assert_eq!(
        f.store.entry(&r2).unwrap().unwrap().state,
        EntryState::Acked
    );

    // After the pause, one more refusal poisons the entry again at once.
    let c3 = list(&mut f.engine, vec![tool("c", "3")]);
    let r3 = c3.tools[0].1.clone();
    f.sim.st().poison.insert(r3.clone());
    for _ in 0..3 {
        tokio::time::advance(Duration::from_secs(120)).await;
        fresh.sync_once().await;
    }
    assert_eq!(
        f.store.entry(&r3).unwrap().unwrap().state,
        EntryState::Poisoned
    );
    assert_eq!(f.store.unpoison_all(2).unwrap(), 1);
    tokio::time::advance(Duration::from_secs(120)).await;
    fresh.sync_once().await;
    assert_eq!(
        f.store.entry(&r3).unwrap().unwrap().state,
        EntryState::Poisoned,
        "one refusal suffices"
    );
}

#[tokio::test]
async fn the_conflict_gap_id_is_deterministic_across_a_crash_rerun() {
    let ids: Vec<String> = (1..=3).map(uuid).collect();
    let mut shuffled = ids.clone();
    shuffled.reverse();
    let mut f = fx_with(shuffled);
    let c = list(&mut f.engine, vec![tool("bad", "b")]);
    let r = c.tools[0].1.clone();
    f.sim.st().conflict.insert(r.clone());
    f.client.sync_once().await;
    // Crash after the gap was queued but before the mark was cleared: re-run.
    let conn = rusqlite::Connection::open(f._d.path().join("registry.sqlite3")).unwrap();
    conn.execute(
        "UPDATE entries SET gap_pending = 1, gap_detector = 'central_409' WHERE metadata_ref = ?1",
        [&r],
    )
    .unwrap();
    drop(conn);
    assert_eq!(f.client.conflicts().resume().unwrap(), 1);
    let gap_ids: HashSet<String> = f
        .gaps
        .pending_batch()
        .iter()
        .map(|g| match g {
            GapReport::RegistryConflict(g) => g.gap_id.as_str().to_string(),
            _ => panic!(),
        })
        .collect();
    assert_eq!(gap_ids.len(), 1, "same gap_id both times: {gap_ids:?}");
    // The id depends on exactly the ref, the key_id and the event ids.
    let g = sigil_proxy::registry_client::gap_id_for;
    let a = g("r", "k", &ids);
    assert_eq!(a, g("r", "k", &ids));
    assert_ne!(a, g("r", "k", &ids[..2]));
    assert_ne!(a, g("r2", "k", &ids));
    assert_ne!(a, g("r", "k2", &ids));
    assert!(sigil_proxy_api::Uuid::new(a).is_ok());
}

fn config_view() -> sigil_proxy::config_sync::ConfigView {
    sigil_proxy::config_sync::ConfigView {
        state: sigil_proxy_api::status::ConfigState::None,
        last_update_error: None,
        applied_revision: None,
        config_hash: None,
        observed_revision: None,
        expires_at: None,
        max_offline_retry_age_seconds: None,
        event_retention_seconds: None,
        route_upstreams: vec![],
    }
}

#[tokio::test]
async fn the_status_registry_section_reflects_real_counts() {
    use sigil_proxy::status_report::StatusBuilder;
    let mut f = fx_with(vec![uuid(1)]);
    let mut b = StatusBuilder::new("px-1", &uuid(77).replace("-4000-8000", "-4000-8000"));
    let now = time::OffsetDateTime::now_utc();
    let parse = |bytes: Vec<u8>| sigil_proxy_api::parse_status(&bytes).unwrap();

    // Without a probe: the old shape, no counters.
    let s = parse(b.build(&config_view(), &[], now).unwrap());
    assert!(s.registry.quarantined_entries.is_none() && s.registry.discarded_reports.is_none());

    // The first step of a client re-arms poisoned entries (restart), so let it run.
    list(&mut f.engine, vec![tool("warm", "w")]);
    drain(&mut f.client).await;
    b.set_registry(f.client.health_probe());
    let c = list(
        &mut f.engine,
        vec![tool("good", "g"), tool("bad", "b"), tool("pz", "p")],
    );
    let r = |n: &str| c.tools.iter().find(|(t, _)| t == n).unwrap().1.clone();
    let s = parse(b.build(&config_view(), &[], now).unwrap());
    assert_eq!(s.registry.pending_entries.get(), 3);
    assert_eq!(s.registry.quarantined_entries.unwrap().get(), 0);

    f.store.poison(&r("pz")).unwrap();
    f.sim.st().conflict.insert(r("bad"));
    drain(&mut f.client).await;

    let s = parse(b.build(&config_view(), &[], now).unwrap());
    assert_eq!(s.registry.pending_entries.get(), 0);
    assert!(!s.registry.sync_stalled);
    assert_eq!(s.registry.quarantined_entries.unwrap().get(), 1, "the 409");
    assert_eq!(s.registry.poisoned_entries.unwrap().get(), 1);
    assert_eq!(
        s.registry.discarded_reports.unwrap().get(),
        1,
        "the report naming the quarantined entry"
    );
    let h = f.client.health().unwrap();
    assert_eq!(
        (
            h.quarantined_entries,
            h.poisoned_entries,
            h.discarded_reports
        ),
        (1, 1, 1)
    );

    // A stalled link shows as sync_stalled through the same probe.
    list(&mut f.engine, vec![tool("late", "l")]);
    for _ in 0..5 {
        f.sim.st().meta_script.push_back(None);
        f.client.sync_once().await;
    }
    let s = parse(b.build(&config_view(), &[], now).unwrap());
    assert!(s.registry.sync_stalled);
    assert_eq!(s.registry.pending_entries.get(), 1);
}
