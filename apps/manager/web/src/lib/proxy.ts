import type {
  Central,
  ConfigState,
  ConnectionState,
  GapState,
  RouteState,
  Spool,
  SpoolState,
} from '@/api/proxies';

export type Tone = 'ok' | 'warn' | 'bad' | 'neutral';

const NEWER = 'Unknown (newer server)';

export const connectionLabel: Record<ConnectionState, string> = {
  connected: 'Connected',
  disconnected: 'Disconnected',
  never_connected: 'Never connected',
  unknown: NEWER,
};

export const connectionTone: Record<ConnectionState, Tone> = {
  connected: 'ok',
  disconnected: 'bad',
  never_connected: 'neutral',
  unknown: 'neutral',
};

export const configStateLabel: Record<ConfigState, string> = {
  none: 'No config',
  valid: 'Valid',
  expired: 'Expired',
  disabled: 'Disabled',
  unknown: NEWER,
};

export const configStateTone: Record<ConfigState, Tone> = {
  none: 'neutral',
  valid: 'ok',
  expired: 'bad',
  disabled: 'warn',
  unknown: 'neutral',
};

export const routeStateLabel: Record<RouteState, string> = {
  supported: 'Supported',
  degraded: 'Degraded',
  unsupported: 'Unsupported',
  disabled: 'Disabled',
  unknown: NEWER,
};

export const routeStateTone: Record<RouteState, Tone> = {
  supported: 'ok',
  degraded: 'warn',
  unsupported: 'bad',
  disabled: 'neutral',
  unknown: 'neutral',
};

export const gapStateLabel: Record<GapState, string> = {
  open: 'Open',
  closed: 'Closed',
  unknown: NEWER,
};

const spoolStateLabel: Record<SpoolState, string> = {
  ok: 'OK',
  degraded: 'Degraded',
  full: 'Full',
  unknown: NEWER,
};

const spoolStateTone: Record<SpoolState, Tone> = {
  ok: 'ok',
  degraded: 'warn',
  full: 'bad',
  unknown: 'neutral',
};

export interface SpoolStatus {
  label: string;
  tone: Tone;
  note?: string;
}

/**
 * The spool state as an operator should read it. A proxy whose ingest stopped reports `degraded`
 * with healthy storage, so that pairing is labeled as the ingest stop. Only the detail carries
 * `central`; the list passes none and keeps a neutral `Degraded`.
 */
export function spoolStatus(spool: Spool, central?: Central | null): SpoolStatus {
  if (spool.state === 'degraded' && central?.ingest_stopped) {
    return {
      label: 'Degraded: ingest stopped',
      tone: 'warn',
      note: "The server keeps refusing this proxy's events, so the proxy reports its spool as degraded. This is not a storage fault.",
    };
  }
  return { label: spoolStateLabel[spool.state], tone: spoolStateTone[spool.state] };
}

const gapKindLabel: Record<string, string> = {
  producer_epoch_change: 'Producer epoch change',
  sequence_gap: 'Sequence gap',
  registry_conflict: 'Registry conflict',
  event_quarantined: 'Event quarantined',
  local_record_failed: 'Local record failed',
  spool_expired: 'Spool expired',
  unrecorded_calls: 'Unrecorded calls',
  central_outage: 'Central outage',
  inventory_incomplete: 'Inventory incomplete',
  comparison_inconsistent: 'Comparison inconsistent',
};

/** A known gap kind's name, or the server's own text for a kind this build does not know. */
export function gapKind(kind: string): string {
  return Object.hasOwn(gapKindLabel, kind) ? gapKindLabel[kind] : kind;
}

/** A byte count in binary units, e.g. "40 KiB". */
export function formatBytes(n: number): string {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${i === 0 ? v : v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
}

/** Quarantined bytes; a proxy that predates the field reports `null`. */
export function quarantinedBytes(n: number | null): string {
  return n === null ? 'unknown (older proxy)' : formatBytes(n);
}

/** A gap's details as `key=value` text, values as JSON. */
export function gapDetails(details: Record<string, unknown> | null): string {
  if (!details) return '';
  return Object.entries(details)
    .map(([k, v]) => `${k}=${typeof v === 'string' ? v : JSON.stringify(v)}`)
    .join(' · ');
}
