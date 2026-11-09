import type {
  Central,
  ConfigState,
  ConnectionState,
  GapState,
  InvocationSummary,
  Lifecycle,
  Outcome,
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

export const lifecycleLabel: Record<Lifecycle, string> = {
  started: 'Started',
  completed: 'Completed',
  completion_without_start: 'Completion without start',
  cancel_without_start: 'Cancel without start',
  integrity_conflict: 'Integrity conflict',
  unknown: NEWER,
};

export const outcomeLabel: Record<Outcome, string> = {
  success: 'Success',
  tool_error: 'Tool error',
  protocol_error: 'Protocol error',
  timeout: 'Timeout',
  denied: 'Denied',
  unknown: 'Unknown outcome',
};

const outcomeTone: Record<Outcome, Tone> = {
  success: 'ok',
  tool_error: 'bad',
  protocol_error: 'bad',
  timeout: 'warn',
  denied: 'warn',
  unknown: 'warn',
};

export interface InvocationStatus {
  label: string;
  tone: Tone;
  /** The record holds a completion that nothing corroborates. It never reads as success. */
  flagged: boolean;
  note?: string;
}

/**
 * The one place that decides an invocation's headline. Only `completed` shows its outcome.
 * `completion_without_start` and `integrity_conflict` are flagged: their outcome is withheld, and
 * the `reported_*` values stay the proxy's claim (see `reportedClaim`), never the headline.
 */
export function invocationStatus(
  inv: Pick<InvocationSummary, 'lifecycle' | 'outcome' | 'epoch_superseded'>,
): InvocationStatus {
  switch (inv.lifecycle) {
    case 'completed': {
      const outcome = inv.outcome ?? 'unknown';
      return { label: outcomeLabel[outcome], tone: outcomeTone[outcome], flagged: false };
    }
    case 'completion_without_start':
      return {
        label: 'Flagged: completion without start',
        tone: 'bad',
        flagged: true,
        note: 'The server has no start for this completion, so it withholds the outcome.',
      };
    case 'integrity_conflict':
      return {
        label: 'Flagged: integrity conflict',
        tone: 'bad',
        flagged: true,
        note: 'The events of this invocation contradict each other, so the server withholds the outcome.',
      };
    case 'started':
      return {
        label: 'No completion observed',
        tone: 'neutral',
        flagged: false,
        note: inv.epoch_superseded
          ? 'The proxy has since started a new epoch, so the completion may never arrive.'
          : undefined,
      };
    case 'cancel_without_start':
      return { label: 'Cancel only, no start', tone: 'neutral', flagged: false };
    default:
      return { label: lifecycleLabel.unknown, tone: 'neutral', flagged: false };
  }
}

/** The proxy's uncorroborated claim about the completion, or `null` when it made none. */
export function reportedClaim(
  inv: Pick<InvocationSummary, 'reported_outcome' | 'reported_delivery_state' | 'reported_reason'>,
): string | null {
  const parts = [
    inv.reported_outcome && `outcome ${inv.reported_outcome}`,
    inv.reported_delivery_state && `delivery ${inv.reported_delivery_state}`,
    inv.reported_reason && `reason ${inv.reported_reason}`,
  ].filter(Boolean);
  return parts.length ? `Proxy reported ${parts.join(', ')}. Not corroborated.` : null;
}

const flagLabel: Record<string, string> = {
  completion_contradicts_start: 'Completion contradicts start',
  duplicate_completion: 'Duplicate completion',
  duplicate_start: 'Duplicate start',
  event_limit: 'Event limit reached',
  start_binding_conflict: 'Start binding conflict',
};

/** A known flag's name, or the server's own code for a flag this build does not know. */
export function flagName(flag: string): string {
  return Object.hasOwn(flagLabel, flag) ? flagLabel[flag] : flag;
}
