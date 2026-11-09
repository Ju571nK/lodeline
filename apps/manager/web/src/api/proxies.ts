/**
 * Wraps the read-only proxy handlers. Types mirror `src/fleet/proxy.rs`, which keeps
 * `lodeline-server`'s shape: `null` stays `null` and absent stays absent. Every enum has an
 * `unknown` member, which the console sends for a value a newer server added. Status fields
 * describe the proxy's last report, not live state.
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
  /** Newest first, at most 50. */
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
