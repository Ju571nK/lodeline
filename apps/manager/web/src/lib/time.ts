import { format, formatDistanceToNowStrict } from 'date-fns';

/**
 * Bare relative age of an ISO timestamp, e.g. "3m", "2h". Returns "—" if the
 * timestamp can't be parsed. No suffix — callers append " ago" where wanted.
 */
export function relativeAge(ts: string): string {
  try {
    return formatDistanceToNowStrict(new Date(ts));
  } catch {
    return '—';
  }
}

/** Local date and time of an ISO timestamp, e.g. "Nov 5, 14:31", or the input if unparseable. */
export function shortTime(ts: string): string {
  try {
    return format(new Date(ts), 'MMM d, HH:mm');
  } catch {
    return ts;
  }
}
