import type { EventWithTriage, ReasonLike } from '@/api/fleet';

export type SortMode = 'severity_desc' | 'age_desc' | 'age_asc';

export interface AlertGroup {
  key: string;
  latest: EventWithTriage;
  events: EventWithTriage[];
  count: number;
}

export function groupAlerts(events: EventWithTriage[]): AlertGroup[] {
  return events.map((e) => ({ key: e.event_id, latest: e, events: [e], count: 1 }));
}

export function sortAlertGroups(groups: AlertGroup[], _mode: SortMode): AlertGroup[] {
  return groups;
}

export function alertTitleReason(reasons: ReasonLike[] | null | undefined): ReasonLike | undefined {
  return reasons?.[0];
}
