/**
 * Wraps the read-only proxy, invocation and inventory handlers. Types mirror `src/fleet/proxy.rs`,
 * which keeps `lodeline-server`'s shape: `null` stays `null` and absent stays absent. Every enum
 * has an `unknown` member, which the console sends for a value a newer server added. Status
 * fields describe the proxy's last report, not live state.
 */

import { api } from './client';

export type ConnectionState = 'connected' | 'disconnected' | 'never_connected' | 'unknown';
export type ConfigState = 'none' | 'valid' | 'expired' | 'disabled' | 'unknown';
export type SpoolState = 'ok' | 'degraded' | 'full' | 'unknown';
export type RouteState = 'supported' | 'degraded' | 'unsupported' | 'disabled' | 'unknown';
export type GapState = 'open' | 'closed' | 'unknown';

export interface Spool {
  state: SpoolState;
  depth_events: number;
  unsent_events: number;
  bytes: number;
  capacity_bytes: number;
  oldest_unsent_age_seconds: number | null;
  quarantined_events: number;
  /** `null` for a proxy that predates the field. */
  quarantined_bytes: number | null;
  as_of: string | null;
}

export interface ProxySummary {
  proxy_id: string;
  display_name: string;
  connection_state: ConnectionState;
  last_seen: string | null;
  desired_revision: number | null;
  applied_revision: number | null;
  config_in_sync: boolean;
  config_state: ConfigState;
  config_expires_at: string | null;
  /** `null` until the proxy has sent a status report. */
  spool: Spool | null;
  open_gap_count: number;
  /** When the server applied the report the status fields come from. */
  status_as_of: string | null;
}

export interface ProxiesPage {
  items: ProxySummary[];
  /** Opaque; bound to the endpoint and the filters it came with. */
  next_cursor: string | null;
}

/** The three counters are absent for proxies that predate them. */
export interface Registry {
  pending_entries: number;
  sync_stalled: boolean;
  quarantined_entries?: number;
  poisoned_entries?: number;
  discarded_reports?: number;
}

export interface Central {
  last_ingest_ack_at: string | null;
  consecutive_failures: number;
  /** Sent only when true. While true, `spool.state` is `degraded` even when storage is fine. */
  ingest_stopped?: boolean;
}

export interface RouteHealth {
  upstream_id: string;
  state: RouteState;
  reason?: string;
}

export interface AuditGap {
  gap_id: string;
  kind: string;
  source: string;
  detected_at: string;
  state: GapState;
  /** Identifiers and counts only, by kind. */
  details: Record<string, unknown> | null;
}

export interface ProxyDetail extends ProxySummary {
  registry: Registry | null;
  routes: RouteHealth[];
  central: Central | null;
  /** Open first, then newest first, at most 50. Render in this order. */
  audit_gaps: AuditGap[];
  audit_gaps_total: number;
  /** Inventory gaps dropped at the server's per-proxy cap; above zero the list is incomplete. */
  audit_gaps_dropped: number;
  open_gap_counts: Record<string, number>;
}

export interface ProxiesParams {
  cursor?: string;
  limit?: number;
  connectionState?: Exclude<ConnectionState, 'unknown'>;
  configInSync?: boolean;
}

export function fleetProxies(p: ProxiesParams, signal?: AbortSignal): Promise<ProxiesPage> {
  const q = new URLSearchParams();
  if (p.cursor) q.set('cursor', p.cursor);
  if (p.limit) q.set('limit', String(p.limit));
  if (p.connectionState) q.set('connection_state', p.connectionState);
  if (p.configInSync !== undefined) q.set('config_in_sync', String(p.configInSync));
  const s = q.toString();
  return api<ProxiesPage>(`/fleet/proxies${s ? `?${s}` : ''}`, { signal });
}

export function fleetProxy(proxyId: string): Promise<ProxyDetail> {
  return api<ProxyDetail>(`/fleet/proxies/${encodeURIComponent(proxyId)}`);
}

/** Only `completed` carries a corroborated outcome. */
export type Lifecycle =
  | 'started'
  | 'completed'
  | 'completion_without_start'
  | 'cancel_without_start'
  | 'integrity_conflict'
  | 'unknown';
/** `unknown` is also an outcome proxies report, so a newer server's value reads as it too. */
export type Outcome =
  | 'success'
  | 'tool_error'
  | 'protocol_error'
  | 'timeout'
  | 'denied'
  | 'unknown';

export interface Actor {
  actor_id: string;
  actor_kind: string;
  authentication_method: string;
  evidence_source: string;
  /** Who owns the credential's permissions, not who ran the call. */
  credential_owner_id: string | null;
}

/** A metadata reference, or why there is none. Never a tool name. */
export interface Tool {
  status: string;
  metadata_ref?: string;
  reason?: string;
}

export interface InvocationSummary {
  invocation_id: string;
  proxy_id: string;
  lifecycle: Lifecycle;
  /** Set only when `lifecycle` is `completed`. */
  outcome: Outcome | null;
  delivery_state: string | null;
  reason: string | null;
  /** The proxy's uncorroborated claim under `completion_without_start` or `integrity_conflict`. */
  reported_outcome: Outcome | null;
  reported_delivery_state: string | null;
  reported_reason: string | null;
  duration_ms: number | null;
  response_bytes: number | null;
  method: string | null;
  protocol_version: string | null;
  upstream_id: string | null;
  route_revision: number | null;
  actor: Actor | null;
  tool: Tool | null;
  cancel_observed: boolean;
  /** Proxy clock, unverified. */
  started_at: string | null;
  completed_at: string | null;
  /** Server clock. */
  first_received_at: string;
  last_received_at: string;
  start_epoch_id: string | null;
  epoch_superseded: boolean;
  flags: string[];
}

export interface InvocationsPage {
  items: InvocationSummary[];
  /** Opaque; bound to the endpoint and the filters it came with. */
  next_cursor: string | null;
}

/** Envelope identifiers only; the server never returns a payload. */
export interface InvocationEvent {
  event_type: string;
  event_id: string;
  epoch_id: string;
  sequence: number;
  occurred_at: string;
  received_at: string;
}

export interface InvocationDetail extends InvocationSummary {
  events_total: number;
  /** True when more events exist than `events` lists (the server lists at most 32). */
  events_truncated: boolean;
  events: InvocationEvent[];
}

export interface InvocationsParams {
  cursor?: string;
  limit?: number;
  proxyId?: string;
  method?: string;
  outcome?: Outcome;
  lifecycle?: Exclude<Lifecycle, 'unknown'>;
}

export function fleetInvocations(
  p: InvocationsParams,
  signal?: AbortSignal,
): Promise<InvocationsPage> {
  const q = new URLSearchParams();
  if (p.cursor) q.set('cursor', p.cursor);
  if (p.limit) q.set('limit', String(p.limit));
  if (p.proxyId) q.set('proxy_id', p.proxyId);
  if (p.method) q.set('method', p.method);
  if (p.outcome) q.set('outcome', p.outcome);
  if (p.lifecycle) q.set('lifecycle', p.lifecycle);
  const s = q.toString();
  return api<InvocationsPage>(`/fleet/proxy-invocations${s ? `?${s}` : ''}`, { signal });
}

export function fleetInvocation(invocationId: string): Promise<InvocationDetail> {
  return api<InvocationDetail>(`/fleet/proxy-invocations/${encodeURIComponent(invocationId)}`);
}

/**
 * The chain an inventory row belongs to. Another credential scope or protocol version is a
 * separate chain, never compared with this one.
 */
export interface InventoryScope {
  proxy_id: string;
  upstream_id: string;
  credential_scope_id: string;
  protocol_version: string;
  observation_source: string;
}

/** Only `compared` has drift records. */
export type ComparisonState =
  | 'baseline'
  | 'compared'
  | 'rebaseline'
  | 'pending_previous'
  | 'inconsistent'
  | 'unknown';

/** A complete observation of an upstream's tool list, by reference. Never a tool name. */
export interface InventorySnapshot extends InventoryScope {
  inventory_id: string;
  canon: string;
  key_id: string;
  member_count: number;
  /** Proxy clock, as the report wrote it. */
  observed_at: string;
  received_at: string;
  is_latest: boolean;
  is_first_baseline: boolean;
  comparison_state: ComparisonState;
  /** Set only while `pending_previous`. */
  awaiting_inventory_id: string | null;
}

export type DriftChange = 'added' | 'removed' | 'changed' | 'unknown';

/** A change the proxy observed between two snapshots of a chain. Nothing approved it. */
export interface DriftRecord extends InventoryScope {
  drift_id: string;
  inventory_id: string;
  previous_inventory_id: string;
  change: DriftChange;
  metadata_ref: string;
  /** Sent only for `changed`. */
  previous_metadata_ref?: string;
  detected_at: string;
}

export type MarkerCause =
  | 'declared_key_rotation'
  | 'declared_canon_change'
  | 'epoch_change_detected'
  | 'key_change_undeclared'
  | 'baseline_restated'
  | 'unknown';

/** A baseline reset inside a chain. It never creates drift records. */
export interface RebaselineMarker extends InventoryScope {
  marker_id: string;
  inventory_id: string;
  previous_inventory_id: string | null;
  from_key_id: string;
  to_key_id: string;
  from_canon: string;
  to_canon: string;
  cause: MarkerCause;
  links_present: boolean;
  drift_computed: boolean;
  detected_at: string;
}

/** The row type of each view, by its path segment. */
export interface InventoryRows {
  'inventory-snapshots': InventorySnapshot;
  drift: DriftRecord;
  'rebaseline-markers': RebaselineMarker;
}

export type InventoryView = keyof InventoryRows;

export interface InventoryPage<V extends InventoryView> {
  items: InventoryRows[V][];
  /** Opaque; bound to the view, the proxy and the filters it came with. */
  next_cursor: string | null;
}

/** One page of a proxy's inventory view, newest first. */
export function fleetInventory<V extends InventoryView>(
  proxyId: string,
  view: V,
  p: { cursor?: string; limit?: number },
  signal?: AbortSignal,
): Promise<InventoryPage<V>> {
  const q = new URLSearchParams();
  if (p.cursor) q.set('cursor', p.cursor);
  if (p.limit) q.set('limit', String(p.limit));
  const s = q.toString();
  return api<InventoryPage<V>>(
    `/fleet/proxies/${encodeURIComponent(proxyId)}/${view}${s ? `?${s}` : ''}`,
    { signal },
  );
}
