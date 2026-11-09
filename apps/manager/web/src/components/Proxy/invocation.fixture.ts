import type { InvocationSummary } from '@/api/proxies';

const ago = (s: number) => new Date(Date.now() - s * 1000).toISOString();

/** A completed, successful invocation for tests; `patch` changes any field. */
export function invocation(patch: Partial<InvocationSummary> = {}): InvocationSummary {
  return {
    invocation_id: '00000000-0000-4000-8000-000000000401',
    proxy_id: 'px-a',
    lifecycle: 'completed',
    outcome: 'success',
    delivery_state: 'sent',
    reason: null,
    reported_outcome: null,
    reported_delivery_state: null,
    reported_reason: null,
    duration_ms: 41,
    response_bytes: 1820,
    method: 'tools/call',
    protocol_version: '2025-11-25',
    upstream_id: 'up1',
    route_revision: 7,
    actor: null,
    tool: null,
    cancel_observed: false,
    started_at: ago(95),
    completed_at: ago(94),
    first_received_at: ago(90),
    last_received_at: ago(90),
    start_epoch_id: null,
    epoch_superseded: false,
    flags: [],
    ...patch,
  };
}
