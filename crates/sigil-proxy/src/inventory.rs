//! Inventory engine: completeness state machine, minting, comparison and report
//! building (README "D-05 metadata registry (N9)" m5, `contracts/registry.md`
//! R3/R4/R7).
//!
//! The engine is fed `tools/list` PAGE OBSERVATIONS in the plain types below.
//! T-13c adapts them from the relay's `ToolListPage` (`tools`, `next_cursor`),
//! its `PageUnavailable` classes and the request's cursor flag. Nothing here
//! talks to the network or the upstream; the proxy never lists on its own.
//!
//! A listing is COMPLETE only when, for one session and one scope key, a chain
//! starts with a request without a cursor, every page succeeds within the
//! limits, and the last page has no next cursor. Anything else ends as an
//! INCOMPLETE report that changes nothing else: the latest complete snapshot
//! stays current and nothing is removed.
//!
//! On completion, under the store lock: every tool is canonicalised (JCS) and
//! minted (fingerprint, `metadata_ref`) with the current K; the entries and the
//! new snapshot are committed durably together with the report; the report is
//! built against the previous complete snapshot of the same scope key
//! (`initial_baseline`, `compared` or `rebaseline` with links).
//!
//! Tool names and definitions are untrusted content. No type here prints them
//! and no error carries them.

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde_json::Value;
use sigil_proxy_api::registry::{
    Canon, Change, Comparison, Completeness, DefinitionComparison, IncompleteReason,
    InventoryReport, InventoryScope, Link, ObservationSource, RebaselineReason,
    RegistryProtocolVersion,
};
use sigil_proxy_api::{
    Id, KeyId, MetadataRef, NonNegativeI64, SchemaVersion, Timestamp, Uuid, Validate,
};

use crate::jcs;
use crate::limits::Limits;
use crate::registry_key::{ScopeKey, CANON_V1};
use crate::registry_store::{
    CompleteCommit, EntryRecord, EntryState, Inner, RegistryError, RegistryStore, SnapshotRecord,
    StoredReport, MAX_DEFINITION_BYTES,
};

/// Listings in flight at once. The oldest is ended as `session_ended` beyond it.
pub const MAX_COLLECTORS: usize = 8;

/// The inventory bounds (`limits.rs`, D-04 initial values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InventoryLimits {
    pub max_pages: u64,
    pub max_tools: u64,
    pub max_bytes: u64,
}

impl InventoryLimits {
    pub fn from_limits(l: &Limits) -> InventoryLimits {
        InventoryLimits {
            max_pages: l.inventory_max_pages,
            // The report schema allows 10,000 members at most.
            max_tools: l.inventory_max_tools.min(10_000),
            max_bytes: l.inventory_max_bytes,
        }
    }
}

impl Default for InventoryLimits {
    fn default() -> Self {
        InventoryLimits::from_limits(&Limits::default())
    }
}

/// One tool of a page: its name and the tool object's JSON text, exactly as the
/// upstream sent it (untrusted).
#[derive(Clone)]
pub struct ToolInput {
    pub name: String,
    pub definition: String,
}

impl fmt::Debug for ToolInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ToolInput({} bytes)", self.definition.len())
    }
}

/// An opaque identity of a pagination cursor: HMAC-SHA-256 under a per-process
/// random key ([`CursorHasher`]). The cursor itself is never kept or compared.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CursorTag([u8; 32]);

impl fmt::Debug for CursorTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CursorTag(<opaque>)")
    }
}

/// Makes [`CursorTag`]s. One per process (T-13c holds it next to the relay): the
/// request cursor of page N+1 and the `nextCursor` of page N must be tagged by
/// the same hasher for the engine to see them as equal.
#[derive(Clone)]
pub struct CursorHasher {
    key: [u8; 32],
}

impl fmt::Debug for CursorHasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CursorHasher(<redacted>)")
    }
}

impl CursorHasher {
    pub fn new() -> Result<CursorHasher, RegistryError> {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).map_err(|_| RegistryError::Random)?;
        Ok(CursorHasher { key })
    }

    pub fn tag(&self, cursor: &str) -> CursorTag {
        CursorTag(crate::registry_key::hmac_sha256(
            &self.key,
            cursor.as_bytes(),
        ))
    }
}

/// What the relay saw of one `tools/list` response.
#[derive(Debug, Clone)]
pub enum PageInput {
    /// A usable page. `request_cursor`: the tag of the cursor the client's
    /// request carried (`None` for the first request of a chain). `next_cursor`:
    /// the tag of the page's `nextCursor` (`None` on the last page). A page of a
    /// chain is accepted only if its `request_cursor` equals the previous
    /// page's `next_cursor`.
    Tools {
        request_cursor: Option<CursorTag>,
        tools: Vec<ToolInput>,
        next_cursor: Option<CursorTag>,
    },
    /// The page cannot be used. `reason` is the T-13c mapping of the relay's
    /// `PageUnavailable` (`page_error`, `size_limit_exceeded`,
    /// `tool_limit_exceeded`, `cursor_invalid`, `access_denied`, ...).
    Failed {
        request_cursor: Option<CursorTag>,
        reason: IncompleteReason,
    },
}

impl PageInput {
    fn request_cursor(&self) -> Option<CursorTag> {
        match self {
            PageInput::Tools { request_cursor, .. } | PageInput::Failed { request_cursor, .. } => {
                *request_cursor
            }
        }
    }
}

/// One listing chain: one authenticated session (an opaque id chosen by the
/// caller) in one scope key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ListingKey {
    pub session: u64,
    pub scope: ScopeKey,
}

/// What a completed listing produced.
#[derive(Clone, PartialEq, Eq)]
pub struct CompleteListing {
    pub inventory_id: String,
    pub report_id: String,
    pub comparison: ComparisonKind,
    /// `(tool name, metadata_ref)` in listing order, committed durably.
    pub tools: Vec<(String, String)>,
}

impl fmt::Debug for CompleteListing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompleteListing")
            .field("inventory_id", &self.inventory_id)
            .field("comparison", &self.comparison)
            .field("tools", &self.tools.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComparisonKind {
    InitialBaseline,
    Compared,
    Rebaseline(RebaselineReason),
}

/// The result of feeding one page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListingProgress {
    /// More pages are expected.
    Continue,
    /// The chain is complete, committed and its report queued.
    Complete(CompleteListing),
    /// The chain ended incomplete; the incomplete report is queued.
    Incomplete(IncompleteReason),
    /// A page of a chain that already ended incomplete: ignored (no report).
    Ignored,
}

struct Collected {
    name: String,
    value: Value,
}

enum Chain {
    Collecting {
        pages: u64,
        bytes: u64,
        tools: Vec<Collected>,
        /// The cursor the next request of the chain must carry.
        expect: Option<CursorTag>,
    },
    /// Ended incomplete; later pages of the same chain are ignored until a
    /// request without a cursor starts a new chain.
    Dead,
}

struct Collector {
    chain: Chain,
    stamp: u64,
}

/// The inventory state machine of one proxy.
pub struct InventoryEngine {
    store: RegistryStore,
    epoch_id: String,
    limits: InventoryLimits,
    collectors: HashMap<ListingKey, Collector>,
    stamp: u64,
}

impl InventoryEngine {
    pub fn new(store: RegistryStore, epoch_id: &str, limits: InventoryLimits) -> InventoryEngine {
        InventoryEngine {
            store,
            epoch_id: epoch_id.to_string(),
            limits,
            collectors: HashMap::new(),
            stamp: 0,
        }
    }

    pub fn store(&self) -> &RegistryStore {
        &self.store
    }

    fn now(&self) -> String {
        crate::status_report::rfc3339(time::OffsetDateTime::now_utc())
    }

    fn tick(&mut self) -> u64 {
        self.stamp += 1;
        self.stamp
    }

    /// Feed one page. Blocking (SQLite) when the chain ends.
    pub fn observe_page(
        &mut self,
        key: &ListingKey,
        page: PageInput,
    ) -> Result<ListingProgress, RegistryError> {
        let request = page.request_cursor();
        if request.is_none() {
            // A request without a cursor starts a new chain. A chain still in
            // progress under this key never completed.
            if let Some(old) = self.collectors.remove(key) {
                self.end_chain(&key.scope, old, IncompleteReason::SessionEnded)?;
            }
            self.make_room()?;
            let stamp = self.tick();
            self.collectors.insert(
                key.clone(),
                Collector {
                    chain: Chain::Collecting {
                        pages: 0,
                        bytes: 0,
                        tools: Vec::new(),
                        expect: None,
                    },
                    stamp,
                },
            );
        } else {
            match self.collectors.get(key).map(|c| &c.chain) {
                None => {
                    // A cursor with no chain start seen (restart, eviction, a
                    // stale cursor): this chain can never be complete.
                    self.record_incomplete(&key.scope, IncompleteReason::CursorInvalid, 0)?;
                    self.make_room()?;
                    let stamp = self.tick();
                    self.collectors.insert(
                        key.clone(),
                        Collector {
                            chain: Chain::Dead,
                            stamp,
                        },
                    );
                    return Ok(ListingProgress::Incomplete(IncompleteReason::CursorInvalid));
                }
                Some(Chain::Dead) => return Ok(ListingProgress::Ignored),
                Some(Chain::Collecting { expect, .. }) => {
                    // The cursor must be the one the previous page handed out.
                    if *expect != request {
                        return self.fail(key, IncompleteReason::CursorInvalid);
                    }
                }
            }
        }

        let (tools, next) = match page {
            PageInput::Failed { reason, .. } => return self.fail(key, reason),
            PageInput::Tools {
                tools, next_cursor, ..
            } => (tools, next_cursor),
        };
        let limits = self.limits;
        let outcome = {
            let c = self.collectors.get_mut(key).expect("collector present");
            let Chain::Collecting {
                pages,
                bytes,
                tools: collected,
                expect,
            } = &mut c.chain
            else {
                return Ok(ListingProgress::Ignored);
            };
            *pages += 1;
            *expect = next;
            let mut failed = None;
            if *pages > limits.max_pages {
                failed = Some(IncompleteReason::PageLimitExceeded);
            }
            if failed.is_none() {
                for t in tools {
                    if collected.len() as u64 >= limits.max_tools {
                        failed = Some(IncompleteReason::ToolLimitExceeded);
                        break;
                    }
                    *bytes += t.definition.len() as u64;
                    if t.definition.len() > MAX_DEFINITION_BYTES || *bytes > limits.max_bytes {
                        failed = Some(IncompleteReason::SizeLimitExceeded);
                        break;
                    }
                    match collect_tool(t) {
                        Some(x) => collected.push(x),
                        None => {
                            failed = Some(IncompleteReason::CanonicalizationFailed);
                            break;
                        }
                    }
                }
            }
            failed
        };
        if let Some(reason) = outcome {
            return self.fail(key, reason);
        }
        if next.is_some() {
            return Ok(ListingProgress::Continue);
        }
        let c = self.collectors.remove(key).expect("collector present");
        let Chain::Collecting { pages, tools, .. } = c.chain else {
            return Ok(ListingProgress::Ignored);
        };
        self.finish(&key.scope, pages, tools)
    }

    /// The session ended: every chain of it that is still in progress is
    /// recorded as `session_ended`. Returns how many reports were queued.
    pub fn end_session(&mut self, session: u64) -> Result<usize, RegistryError> {
        let keys: Vec<ListingKey> = self
            .collectors
            .keys()
            .filter(|k| k.session == session)
            .cloned()
            .collect();
        let mut n = 0;
        for k in keys {
            if let Some(c) = self.collectors.remove(&k) {
                if matches!(c.chain, Chain::Collecting { .. }) {
                    n += 1;
                }
                self.end_chain(&k.scope, c, IncompleteReason::SessionEnded)?;
            }
        }
        Ok(n)
    }

    fn make_room(&mut self) -> Result<(), RegistryError> {
        while self.collectors.len() >= MAX_COLLECTORS {
            let Some(oldest) = self
                .collectors
                .iter()
                .min_by_key(|(_, c)| c.stamp)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            if let Some(c) = self.collectors.remove(&oldest) {
                self.end_chain(&oldest.scope, c, IncompleteReason::SessionEnded)?;
            }
        }
        Ok(())
    }

    fn end_chain(
        &self,
        scope: &ScopeKey,
        c: Collector,
        reason: IncompleteReason,
    ) -> Result<(), RegistryError> {
        match c.chain {
            Chain::Collecting { pages, .. } => self.record_incomplete(scope, reason, pages),
            Chain::Dead => Ok(()),
        }
    }

    fn fail(
        &mut self,
        key: &ListingKey,
        reason: IncompleteReason,
    ) -> Result<ListingProgress, RegistryError> {
        let pages = match self.collectors.get(key).map(|c| &c.chain) {
            Some(Chain::Collecting { pages, .. }) => *pages,
            _ => 0,
        };
        self.record_incomplete(&key.scope, reason, pages)?;
        let stamp = self.tick();
        self.collectors.insert(
            key.clone(),
            Collector {
                chain: Chain::Dead,
                stamp,
            },
        );
        Ok(ListingProgress::Incomplete(reason))
    }

    fn record_incomplete(
        &self,
        scope: &ScopeKey,
        reason: IncompleteReason,
        pages: u64,
    ) -> Result<(), RegistryError> {
        let now = self.now();
        let epoch = self.epoch_id.clone();
        self.store.with(|inner| {
            incomplete_report(inner, &epoch, &now, scope, reason, pages)
                .and_then(|r| inner.commit_incomplete(&r))
        })
    }

    fn finish(
        &mut self,
        scope: &ScopeKey,
        pages: u64,
        tools: Vec<Collected>,
    ) -> Result<ListingProgress, RegistryError> {
        let now = self.now();
        let epoch = self.epoch_id.clone();
        self.store
            .with(|inner| finish_complete(inner, &epoch, &now, scope, pages, &tools))
    }
}

/// Parse and canonicalise one tool. `None` when it cannot be canonicalised
/// (`canonicalization_failed`): not valid JSON, duplicate member, number outside
/// the JCS domain, not an object, or a `name` that is not the announced one.
fn collect_tool(t: ToolInput) -> Option<Collected> {
    let value = jcs::parse_strict(&t.definition).ok()?;
    let obj = value.as_object()?;
    if obj.is_empty() || obj.get("name").and_then(Value::as_str) != Some(t.name.as_str()) {
        return None;
    }
    jcs::canonicalize(&value).ok()?;
    Some(Collected {
        name: t.name,
        value,
    })
}

// ---------------------------------------------------------------- reports

fn to_invalid<E>(_: E) -> RegistryError {
    RegistryError::Invalid("report")
}

fn header(
    inner: &Inner,
    epoch: &str,
    now: &str,
    scope: &ScopeKey,
) -> Result<(Uuid, InventoryScope, KeyId, Timestamp, Uuid, Id), RegistryError> {
    let sc = InventoryScope {
        upstream_id: Id::new(&scope.upstream_id).map_err(to_invalid)?,
        credential_scope_id: Id::new(&scope.credential_scope_id).map_err(to_invalid)?,
        protocol_version: match scope.protocol_version.as_str() {
            "2025-11-25" => RegistryProtocolVersion::V2025_11_25,
            _ => return Err(RegistryError::Invalid("protocol_version")),
        },
        observation_source: match scope.observation_source.as_str() {
            "proxy_live" => ObservationSource::ProxyLive,
            _ => return Err(RegistryError::Invalid("observation_source")),
        },
    };
    Ok((
        Uuid::new(uuid::Uuid::new_v4().to_string()).map_err(to_invalid)?,
        sc,
        KeyId::new(inner.key().key_id()).map_err(to_invalid)?,
        Timestamp::new(now).map_err(to_invalid)?,
        Uuid::new(epoch).map_err(to_invalid)?,
        Id::new(&scope.proxy_id).map_err(to_invalid)?,
    ))
}

fn incomplete_report(
    inner: &Inner,
    epoch: &str,
    now: &str,
    scope: &ScopeKey,
    reason: IncompleteReason,
    pages: u64,
) -> Result<StoredReport, RegistryError> {
    let (report_id, sc, key_id, observed_at, epoch_id, proxy_id) =
        header(inner, epoch, now, scope)?;
    let report = InventoryReport {
        schema_version: SchemaVersion,
        report_id: report_id.clone(),
        proxy_id,
        epoch_id,
        observed_at,
        scope: sc,
        canon: Canon::SigilTooldefFpV1,
        key_id,
        completeness: Completeness::Incomplete,
        pages_observed: NonNegativeI64::new(pages.min(i64::MAX as u64) as i64)
            .map_err(to_invalid)?,
        incomplete_reason: Some(reason),
        inventory_id: None,
        members: None,
        comparison: None,
    };
    report.validate().map_err(to_invalid)?;
    Ok(StoredReport {
        report_id: report_id.as_str().to_string(),
        complete: false,
        body: serde_json::to_vec(&report).map_err(to_invalid)?,
    })
}

/// A minted tool of the current listing.
struct Minted {
    name: String,
    metadata_ref: String,
    jcs_text: String,
}

fn finish_complete(
    inner: &mut Inner,
    epoch: &str,
    now: &str,
    scope: &ScopeKey,
    pages: u64,
    tools: &[Collected],
) -> Result<ListingProgress, RegistryError> {
    let incomplete =
        |inner: &mut Inner, reason: IncompleteReason| -> Result<ListingProgress, RegistryError> {
            let r = incomplete_report(inner, epoch, now, scope, reason, pages)?;
            inner.commit_incomplete(&r)?;
            Ok(ListingProgress::Incomplete(reason))
        };

    // A repeated name makes the listing ambiguous (`ambiguous_name`).
    let mut names = HashSet::new();
    if !tools.iter().all(|t| names.insert(t.name.as_str())) {
        return incomplete(inner, IncompleteReason::AmbiguousName);
    }

    let key_id = inner.key().key_id();
    let mut entries = Vec::with_capacity(tools.len());
    let mut minted = Vec::with_capacity(tools.len());
    for t in tools {
        let Ok(d) = inner.key().derive(scope, &t.value) else {
            return incomplete(inner, IncompleteReason::CanonicalizationFailed);
        };
        let Ok(text) = jcs::canonicalize(&t.value) else {
            return incomplete(inner, IncompleteReason::CanonicalizationFailed);
        };
        let Ok(text) = String::from_utf8(text) else {
            return incomplete(inner, IncompleteReason::CanonicalizationFailed);
        };
        if text.len() > MAX_DEFINITION_BYTES {
            return incomplete(inner, IncompleteReason::SizeLimitExceeded);
        }
        entries.push(EntryRecord {
            metadata_ref: d.metadata_ref.clone(),
            scope: scope.clone(),
            canon: CANON_V1.to_string(),
            key_id: d.key_id,
            fingerprint: d.fingerprint,
            observed_at: now.to_string(),
            tool_name: t.name.clone(),
            definition: text.clone(),
            state: EntryState::Pending,
        });
        minted.push(Minted {
            name: t.name.clone(),
            metadata_ref: d.metadata_ref,
            jcs_text: text,
        });
    }

    // A ref the server can never hold (quarantined after a conflict, or refused
    // for good) is left out of the members: the listing stays complete for
    // everything else, the tool resolves as `not_in_inventory`, and later
    // reports are not stuck behind it. The integrity gap was reported when the
    // entry was quarantined.
    let mut unusable = HashSet::new();
    for m in &minted {
        if matches!(
            inner.entry_state(&m.metadata_ref)?,
            Some(EntryState::Quarantined | EntryState::Poisoned)
        ) {
            unusable.insert(m.metadata_ref.clone());
        }
    }
    entries.retain(|e| !unusable.contains(&e.metadata_ref));
    minted.retain(|m| !unusable.contains(&m.metadata_ref));

    let prev = inner.latest_snapshot(scope)?;
    let declared = inner.rotation_declared(&key_id)?;
    let (comparison, kind) = compare(inner, prev.as_ref(), CANON_V1, &key_id, declared, &minted)?;

    let (report_id, sc, kid, observed_at, epoch_id, proxy_id) = header(inner, epoch, now, scope)?;
    let inventory_id = uuid::Uuid::new_v4().to_string();
    let members: Vec<MetadataRef> = minted
        .iter()
        .map(|m| MetadataRef::new(&m.metadata_ref).map_err(to_invalid))
        .collect::<Result<_, _>>()?;
    let report = InventoryReport {
        schema_version: SchemaVersion,
        report_id: report_id.clone(),
        proxy_id,
        epoch_id,
        observed_at,
        scope: sc,
        canon: Canon::SigilTooldefFpV1,
        key_id: kid,
        completeness: Completeness::Complete,
        pages_observed: NonNegativeI64::new(pages.min(i64::MAX as u64) as i64)
            .map_err(to_invalid)?,
        incomplete_reason: None,
        inventory_id: Some(Uuid::new(&inventory_id).map_err(to_invalid)?),
        members: Some(members),
        comparison: Some(comparison),
    };
    if report.validate().is_err() {
        // More members than the report schema allows, for example.
        return incomplete(inner, IncompleteReason::ToolLimitExceeded);
    }
    let body = serde_json::to_vec(&report).map_err(to_invalid)?;
    let commit = CompleteCommit {
        entries,
        snapshot: SnapshotRecord {
            inventory_id: inventory_id.clone(),
            scope: scope.clone(),
            canon: CANON_V1.to_string(),
            key_id: key_id.clone(),
            observed_at: now.to_string(),
            members: minted
                .iter()
                .map(|m| (m.metadata_ref.clone(), m.name.clone()))
                .collect(),
        },
        report: StoredReport {
            report_id: report_id.as_str().to_string(),
            complete: true,
            body,
        },
    };
    inner.commit_complete(&commit)?;
    Ok(ListingProgress::Complete(CompleteListing {
        inventory_id,
        report_id: report_id.as_str().to_string(),
        comparison: kind,
        tools: minted
            .into_iter()
            .map(|m| (m.name, m.metadata_ref))
            .collect(),
    }))
}

/// Compare the new listing with the previous complete snapshot of the same
/// scope key (registry.md R7 `comparison.kind`).
///
/// * no previous snapshot: `initial_baseline`;
/// * equal `(canon, key_id)`: `compared`, pairing tools by their local identity
///   (the name): present on both sides with another ref is `changed`;
/// * different `key_id` after a DECLARED rotation, or a different canon:
///   `rebaseline` with links (same name on both sides), no changes;
/// * a different `key_id` that was never declared (state loss with the database
///   kept): `initial_baseline`, the server derives the marker (R5).
fn compare(
    inner: &Inner,
    prev: Option<&SnapshotRecord>,
    canon: &str,
    key_id: &str,
    declared: bool,
    cur: &[Minted],
) -> Result<(Comparison, ComparisonKind), RegistryError> {
    let Some(p) = prev else {
        return Ok((
            Comparison::InitialBaseline {},
            ComparisonKind::InitialBaseline,
        ));
    };
    let previous_inventory_id = Uuid::new(&p.inventory_id).map_err(to_invalid)?;
    let prev_by_name: HashMap<&str, &str> = p
        .members
        .iter()
        .map(|(r, n)| (n.as_str(), r.as_str()))
        .collect();
    let mref = |s: &str| MetadataRef::new(s).map_err(to_invalid);

    if p.canon == canon && p.key_id == key_id {
        let mut changes = Vec::new();
        let mut seen = HashSet::new();
        for m in cur {
            match prev_by_name.get(m.name.as_str()) {
                None => changes.push(Change::Added {
                    metadata_ref: mref(&m.metadata_ref)?,
                }),
                Some(old) => {
                    seen.insert(*old);
                    if *old != m.metadata_ref {
                        changes.push(Change::Changed {
                            metadata_ref: mref(&m.metadata_ref)?,
                            previous_metadata_ref: mref(old)?,
                        });
                    }
                }
            }
        }
        for (r, _) in &p.members {
            if !seen.contains(r.as_str()) {
                changes.push(Change::Removed {
                    metadata_ref: mref(r)?,
                });
            }
        }
        return Ok((
            Comparison::Compared {
                previous_inventory_id,
                changes,
            },
            ComparisonKind::Compared,
        ));
    }

    let reason = if p.key_id != key_id && declared {
        RebaselineReason::KeyRotation
    } else if p.canon != canon {
        RebaselineReason::CanonVersionChange
    } else {
        return Ok((
            Comparison::InitialBaseline {},
            ComparisonKind::InitialBaseline,
        ));
    };
    let mut links = Vec::new();
    for m in cur {
        let Some(old_ref) = prev_by_name.get(m.name.as_str()) else {
            continue;
        };
        // The proxy compares the old stored definition with the new one locally.
        let definition_comparison = match inner.entry(old_ref)? {
            Some(old) if old.definition == m.jcs_text => DefinitionComparison::Identical,
            Some(old) if jcs::canonicalize_str(&old.definition).is_ok() => {
                DefinitionComparison::Different
            }
            _ => DefinitionComparison::NotComparable,
        };
        links.push(Link {
            from_metadata_ref: mref(old_ref)?,
            to_metadata_ref: mref(&m.metadata_ref)?,
            definition_comparison,
        });
    }
    Ok((
        Comparison::Rebaseline {
            previous_inventory_id,
            reason,
            links,
        },
        ComparisonKind::Rebaseline(reason),
    ))
}
