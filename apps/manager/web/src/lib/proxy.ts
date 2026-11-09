import type {
  Central,
  ConfigState,
  ConnectionState,
  DriftChange,
  GapState,
  InventorySnapshot,
  InvocationSummary,
  Lifecycle,
  MarkerCause,
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
  /** The text of the detail's Outcome row. */
  outcome: string;
  /** The corroborated completion's delivery and reason. Only a completed invocation has one. */
  completion?: { delivery: string | null; reason: string | null };
}

const WITHHELD = 'withheld: no corroborated completion';

/**
 * The one place that decides an invocation's headline. Only `completed` shows its outcome.
 * `completion_without_start` and `integrity_conflict` are flagged: their outcome is withheld, and
 * the `reported_*` values stay the proxy's claim (see `reportedClaim`), never the headline.
 */
export function invocationStatus(
  inv: Pick<
    InvocationSummary,
    'lifecycle' | 'outcome' | 'delivery_state' | 'reason' | 'epoch_superseded'
  >,
): InvocationStatus {
  switch (inv.lifecycle) {
    case 'completed': {
      const outcome = inv.outcome ?? 'unknown';
      return {
        label: outcomeLabel[outcome],
        tone: outcomeTone[outcome],
        flagged: false,
        outcome: outcomeLabel[outcome],
        completion: { delivery: inv.delivery_state, reason: inv.reason },
      };
    }
    case 'completion_without_start':
      return {
        label: 'Flagged: completion without start',
        tone: 'bad',
        flagged: true,
        note: 'The server has no start for this completion, so it withholds the outcome.',
        outcome: WITHHELD,
      };
    case 'integrity_conflict':
      return {
        label: 'Flagged: integrity conflict',
        tone: 'bad',
        flagged: true,
        note: 'The events of this invocation contradict each other, so the server withholds the outcome.',
        outcome: WITHHELD,
      };
    case 'started':
      return {
        label: 'No completion observed',
        tone: 'neutral',
        flagged: false,
        note: inv.epoch_superseded
          ? 'The proxy has since started a new epoch, so the completion may never arrive.'
          : undefined,
        outcome: WITHHELD,
      };
    case 'cancel_without_start':
      return { label: 'Cancel only, no start', tone: 'neutral', flagged: false, outcome: WITHHELD };
    default:
      return { label: lifecycleLabel.unknown, tone: 'neutral', flagged: false, outcome: WITHHELD };
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

export interface SnapshotComparison {
  label: string;
  tone: Tone;
  note?: string;
}

/** How a snapshot relates to the one before it in its chain. A baseline is never an approval. */
export function snapshotComparison(
  s: Pick<InventorySnapshot, 'comparison_state' | 'is_first_baseline' | 'awaiting_inventory_id'>,
): SnapshotComparison {
  switch (s.comparison_state) {
    case 'baseline':
      return s.is_first_baseline
        ? {
            label: 'Initial baseline',
            tone: 'neutral',
            note: 'The first snapshot of this chain. A starting point, not an approval.',
          }
        : { label: 'Baseline restated', tone: 'neutral' };
    case 'compared':
      return { label: 'Compared', tone: 'neutral' };
    case 'rebaseline':
      return {
        label: 'Re-baseline',
        tone: 'neutral',
        note: 'A new key or canon. No drift is derived across it.',
      };
    case 'pending_previous':
      return {
        label: 'Waiting for previous snapshot',
        tone: 'neutral',
        note: `No drift until ${s.awaiting_inventory_id ?? 'the previous snapshot'} arrives.`,
      };
    case 'inconsistent':
      return {
        label: 'Inconsistent',
        tone: 'warn',
        note: 'The deferred checks failed, so the server derived no drift.',
      };
    default:
      return { label: NEWER, tone: 'neutral' };
  }
}

/**
 * How a reference changed between two snapshots. Drift is an observation, never an approval, so
 * no change reads as accepted: none has the `ok` tone.
 */
export const driftChangeLabel: Record<DriftChange, string> = {
  added: 'Added',
  removed: 'Removed',
  changed: 'Changed',
  unknown: NEWER,
};

export const driftChangeTone: Record<DriftChange, Tone> = {
  added: 'warn',
  removed: 'warn',
  changed: 'warn',
  unknown: 'neutral',
};

export const markerCauseLabel: Record<MarkerCause, string> = {
  declared_key_rotation: 'Declared key rotation',
  declared_canon_change: 'Declared canon change',
  epoch_change_detected: 'Producer epoch changed',
  key_change_undeclared: 'Undeclared key change',
  baseline_restated: 'Baseline restated',
  unknown: NEWER,
};

/** The proxy declared the first two causes; the server only detected the next two. */
export const markerCauseTone: Record<MarkerCause, Tone> = {
  declared_key_rotation: 'neutral',
  declared_canon_change: 'neutral',
  epoch_change_detected: 'warn',
  key_change_undeclared: 'warn',
  baseline_restated: 'neutral',
  unknown: 'neutral',
};
