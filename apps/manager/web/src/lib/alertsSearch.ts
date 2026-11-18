import type { SortMode } from '@/components/AlertsQueue/QueueTable';
import type { AlertFilter } from '@/hooks/useAlerts';

/** The alerts list view in the URL: filters, sort and the selected alert. */
export interface AlertsSearch {
  minBucket?: AlertFilter['minBucket'];
  triageStatuses?: AlertFilter['triageStatuses'];
  since?: string | null;
  query?: string;
  /** Selected alert id; presence opens the slide-over (UI/UX §7.4). */
  alert?: string;
  sort?: SortMode;
}

const VALID_BUCKETS: AlertFilter['minBucket'][] = ['low', 'medium', 'high', 'critical'];
const VALID_STATUSES: AlertFilter['triageStatuses'][number][] = [
  'open',
  'acknowledged',
  'investigating',
  'resolved',
];
const VALID_SORTS: SortMode[] = ['severity_desc', 'age_desc', 'age_asc'];

export function validateAlertsSearch(raw: Record<string, unknown>): AlertsSearch {
  const out: AlertsSearch = {};
  if (typeof raw.minBucket === 'string' && (VALID_BUCKETS as string[]).includes(raw.minBucket)) {
    out.minBucket = raw.minBucket as AlertFilter['minBucket'];
  }
  const rawStatuses = Array.isArray(raw.triageStatuses)
    ? raw.triageStatuses
    : typeof raw.triageStatuses === 'string'
      ? raw.triageStatuses.split(',')
      : [];
  const triageStatuses = rawStatuses.filter(
    (s): s is AlertFilter['triageStatuses'][number] =>
      typeof s === 'string' && (VALID_STATUSES as string[]).includes(s),
  );
  if (triageStatuses.length > 0) out.triageStatuses = triageStatuses;
  if (typeof raw.since === 'string' && raw.since.length > 0) out.since = raw.since;
  if (typeof raw.query === 'string' && raw.query.length > 0) out.query = raw.query;
  if (typeof raw.alert === 'string' && raw.alert.length > 0) out.alert = raw.alert;
  if (typeof raw.sort === 'string' && (VALID_SORTS as string[]).includes(raw.sort)) {
    out.sort = raw.sort as SortMode;
  }
  return out;
}
