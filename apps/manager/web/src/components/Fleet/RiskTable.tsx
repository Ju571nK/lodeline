import { Link } from '@tanstack/react-router';
import type { RiskRow } from '@/api/fleet';
import { SkeletonRows } from '@/components/Fleet/SkeletonRows';
import { UnassessedSince } from '@/components/UnassessedSince';
import { humanTool, sourceLabel } from '@/lib/labels';
import { cn } from '@/lib/utils';

interface Props {
  rows: RiskRow[];
  isPending: boolean;
}

/** Risk tab table (UI/UX §5.2). Hostnames are plain text — Plan 04 links them. */
export function RiskTable({ rows, isPending }: Props) {
  if (isPending) {
    return <SkeletonRows />;
  }
  if (rows.length === 0) {
    return (
      <div className="px-4 py-8 text-center text-sm text-text-muted">
        No hosts above the selected risk level.
      </div>
    );
  }
  return (
    <table className="w-full text-xs">
      <thead className="text-text-subtle">
        <tr className="border-b border-border-subtle text-left">
          <th className="px-3 py-2 font-medium">Risk</th>
          <th className="px-3 py-2 font-medium">Host</th>
          <th className="px-3 py-2 font-medium">Score</th>
          <th className="px-3 py-2 font-medium">Top tool</th>
          <th className="px-3 py-2 font-medium">Reasons</th>
          <th className="px-3 py-2 font-medium">
            <span title="Trailing-24h alert count — events matching the producer's alerts definition (ai_guard high/critical + 5 kinds). Alert-definition filtered as of lodeline #21 (contract §14.9.4).">
              Alerts 24h
            </span>
          </th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => (
          <tr key={row.host_id} className="border-b border-border-subtle">
            <td className="px-3 py-2">
              <RiskBar bucket={row.bucket} score={row.score} />
            </td>
            <td className="px-3 py-2 font-mono text-text-primary" title={row.host_id}>
              <Link
                to="/hosts/$hostId"
                params={{ hostId: row.host_id }}
                className="hover:text-accent hover:underline"
              >
                {row.hostname ?? row.host_id.split('-')[0]}
              </Link>
            </td>
            <td className="px-3 py-2 font-mono">{row.score.toFixed(1)}</td>
            <td className="px-3 py-2 text-text-muted">
              {humanTool(row.top_tool, row.source?.tool_label)}
              {row.source && <div className="text-text-subtle">{sourceLabel(row.source)}</div>}
              {row.unassessed_since && (
                <div>
                  <UnassessedSince ts={row.unassessed_since} />
                </div>
              )}
            </td>
            <td className="px-3 py-2 text-text-muted">{row.reasons_count}</td>
            <td className="px-3 py-2 text-text-muted">{row.open_alert_count_24h}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/**
 * Hosts with failing AI Guard sources and no score have no row, so say so rather than let an
 * empty or short table read as clean. `count` is absent from older servers: show nothing.
 */
export function NotAssessedNotice({ count }: { count?: number }) {
  if (!count) return null;
  const one = count === 1;
  return (
    <p role="status" className="mb-3 text-xs text-text-muted">
      <span className="font-medium text-sev-medium">
        {count} {one ? 'host is' : 'hosts are'} not assessed.
      </span>{' '}
      {one ? 'It has' : 'They have'} failing AI Guard sources and no score, so this table leaves{' '}
      {one ? 'it' : 'them'} out.{' '}
      <Link
        to="/fleet/devices"
        search={{ notAssessed: true }}
        className="text-accent hover:underline"
      >
        Show in Devices
      </Link>
    </p>
  );
}

function RiskBar({ bucket, score }: { bucket: string; score: number }) {
  const color = bucketBarColor(bucket);
  const pct = Math.max(0, Math.min(100, (score / 10) * 100));
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-20 rounded bg-bg-elevated">
        <div className={cn('h-full rounded', color)} style={{ width: `${pct}%` }} />
      </div>
      <span className="uppercase tracking-wide text-[10px] text-text-subtle">{bucket}</span>
    </div>
  );
}

function bucketBarColor(bucket: string): string {
  switch (bucket) {
    case 'critical':
      return 'bg-sev-critical';
    case 'high':
      return 'bg-sev-high';
    case 'medium':
      return 'bg-sev-medium';
    case 'low':
      return 'bg-sev-low';
    default:
      return 'bg-sev-info';
  }
}
