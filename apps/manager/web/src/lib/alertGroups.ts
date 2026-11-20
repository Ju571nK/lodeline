import type { EventWithTriage, ReasonLike } from '@/api/fleet';
import { extractAiGuard } from '@/api/fleet';
import { humanKind } from './labels';
import { effectiveBucket } from './severity';

export type SortMode = 'severity_desc' | 'age_desc' | 'age_asc';

/** Alert rows that repeat one finding, newest first. `latest` is the row's event. */
export interface AlertGroup {
  key: string;
  latest: EventWithTriage;
  events: EventWithTriage[];
  count: number;
}

const BUCKET_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/**
 * Collapses events that carry the same finding into one group: same host, tool,
 * scope, user, rule pack and reason set (kinds and details, in any order), and the
 * same triage status and assignee. Triage attaches to one event, so grouping across
 * statuses would let the row show one event's status over an older event with another.
 * An event that is not an AI Guard assessment stays alone. Groups keep the position of
 * the first event they were built from.
 */
export function groupAlerts(events: EventWithTriage[]): AlertGroup[] {
  const byKey = new Map<string, AlertGroup>();
  for (const ev of events) {
    const key = groupKey(ev);
    const group = byKey.get(key);
    if (!group) {
      byKey.set(key, { key, latest: ev, events: [ev], count: 1 });
      continue;
    }
    group.events.push(ev);
    group.count += 1;
  }
  for (const group of byKey.values()) {
    group.events.sort((a, b) => compareDesc(a.ts, b.ts));
    group.latest = group.events[0];
  }
  return [...byKey.values()];
}

export function sortAlertGroups(groups: AlertGroup[], mode: SortMode): AlertGroup[] {
  const copy = [...groups];
  switch (mode) {
    case 'severity_desc':
      return copy.sort(
        (a, b) =>
          bucketRank(b.latest) - bucketRank(a.latest) || compareDesc(a.latest.ts, b.latest.ts),
      );
    case 'age_desc':
      return copy.sort((a, b) => compareDesc(a.latest.ts, b.latest.ts));
    case 'age_asc':
      return copy.sort((a, b) => compareDesc(b.latest.ts, a.latest.ts));
  }
}

/**
 * The reason part of a row title: the first reason kind the agent sent, and how many other
 * kinds the row has, such as "No Sandbox +2 more". A weight does not travel with an event, so
 * the title does not rank reasons; the drawer lists them all.
 */
export function reasonTitle(reasons: ReasonLike[] | null | undefined): string | undefined {
  const first = reasons?.[0];
  if (!first) return undefined;
  const others = new Set((reasons ?? []).map((r) => r.kind));
  others.delete(first.kind);
  return others.size > 0 ? `${humanKind(first.kind)} +${others.size} more` : humanKind(first.kind);
}

/** The Alerts header count: rows on screen and the events they stand for. */
export function rowsSummary(rows: number, events: number): string {
  return `${rows} ${rows === 1 ? 'row' : 'rows'} from ${events} ${events === 1 ? 'event' : 'events'}`;
}

function groupKey(ev: EventWithTriage): string {
  const ag = extractAiGuard(ev);
  if (!ag) return `single:${ev.host_id}:${ev.event_id}`;
  return stableJSON([
    ev.host_id,
    ag.tool,
    ag.tool_label ?? null,
    ag.scope ?? null,
    ag.user ?? null,
    ag.rule_pack_id ?? null,
    (ag.reasons ?? []).map(stableJSON).sort(),
    ev.triage?.status ?? 'open',
    ev.triage?.assignee ?? null,
  ]);
}

function stableJSON(value: unknown): string {
  return JSON.stringify(value, (_k, v) =>
    v && typeof v === 'object' && !Array.isArray(v)
      ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)))
      : v,
  );
}

function bucketRank(ev: EventWithTriage): number {
  const ag = extractAiGuard(ev);
  if (ag) return ag.bucket ? (BUCKET_RANK[effectiveBucket(ag.bucket, ag.score)] ?? 0) : 0;
  return ev.severity === 'warn' ? 2 : 0;
}

function compareDesc(a: string, b: string): number {
  return a < b ? 1 : a > b ? -1 : 0;
}
