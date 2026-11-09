import type { ProxyDetail } from '@/api/proxies';

export const ago = (s: number) => new Date(Date.now() - s * 1000).toISOString();

/** A connected proxy with a stopped ingest and one open gap; `patch` changes any field. */
export function proxyDetail(patch: Partial<ProxyDetail> = {}): ProxyDetail {
  return {
    proxy_id: 'px-a',
    display_name: 'Proxy A',
    connection_state: 'connected',
    last_seen: ago(10),
    desired_revision: 8,
    applied_revision: 7,
    config_in_sync: false,
    config_state: 'valid',
    config_expires_at: ago(-240),
    spool: {
      state: 'degraded',
      depth_events: 1840,
      unsent_events: 1835,
      bytes: 7340032,
      capacity_bytes: 1073741824,
      oldest_unsent_age_seconds: 3600,
      quarantined_events: 8,
      quarantined_bytes: 40960,
      as_of: ago(20),
    },
    open_gap_count: 2,
    status_as_of: ago(20),
    registry: { pending_entries: 3, sync_stalled: true },
    routes: [{ upstream_id: 'up1', state: 'degraded', reason: 'health_check_failed' }],
    central: { last_ingest_ack_at: ago(3600), consecutive_failures: 9, ingest_stopped: true },
    audit_gaps: [
      {
        gap_id: 'g1',
        kind: 'event_quarantined',
        source: 'proxy_reported',
        detected_at: ago(1800),
        state: 'open',
        details: { code: 'semantic_invalid', event_ids: ['e1'] },
      },
    ],
    audit_gaps_total: 1,
    audit_gaps_dropped: 0,
    open_gap_counts: { event_quarantined: 2 },
    ...patch,
  };
}
