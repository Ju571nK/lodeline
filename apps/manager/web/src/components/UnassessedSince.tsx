import { shortTime } from '@/lib/time';

/** Says in words that a parser is failing, so a stale or missing score never reads as current. */
export function UnassessedSince({ ts }: { ts: string }) {
  return (
    <span className="font-medium text-sev-medium">
      Unassessed since{' '}
      <time dateTime={ts} title={ts}>
        {shortTime(ts)}
      </time>
    </span>
  );
}
