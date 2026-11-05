import type { ToolAiGuard, ToolUnassessed } from '@/api/fleet';
import { ObservedControls } from '@/components/ObservedControls';
import { ReasonList } from '@/components/ReasonList';
import { UnassessedSince } from '@/components/UnassessedSince';
import { humanKind, humanTool, scopeLabel, sourceLabel } from '@/lib/labels';
import { bucketTextColor } from '@/lib/severity';
import { shortTime } from '@/lib/time';
import { cn } from '@/lib/utils';

interface Props {
  byTool: Record<string, ToolAiGuard>;
  unassessed?: Record<string, ToolUnassessed>;
}

/**
 * AI Guard per-tool risk (UI/UX §5.3). Risky tools (bucket > low) get a card
 * with their reasons inline; quiet (low/0) tools collapse into one strip so
 * the signal isn't drowned out — most tools are quiet in real fleets.
 */
export function AiGuardByTool({ byTool, unassessed = {} }: Props) {
  const tools = Object.entries(byTool);
  const failing = Object.entries(unassessed);
  if (tools.length === 0 && failing.length === 0) {
    return (
      <Section>
        <p className="px-1 py-3 text-sm text-text-muted">No AI Guard assessments yet.</p>
      </Section>
    );
  }
  // A stale low score stays out of the collapsed strip, so it never reads as quiet.
  const isQuiet = (t: ToolAiGuard) => t.bucket === 'low' && !t.unassessed_since;
  const risky = tools.filter(([, t]) => !isQuiet(t)).sort((a, b) => b[1].score - a[1].score);
  const quiet = tools.filter(([, t]) => isQuiet(t));

  return (
    <Section>
      {tools.length === 0 && (
        <p className="px-1 pb-2 text-sm text-text-muted">No AI Guard scores yet.</p>
      )}
      {tools.length > 0 && risky.length === 0 && (
        <p className="px-1 pb-2 text-sm text-text-muted">No tools above the low bucket.</p>
      )}
      <div className="space-y-2">
        {risky.map(([tool, t]) => (
          <ToolCard key={tool} tool={tool} t={t} />
        ))}
      </div>
      {quiet.length > 0 && (
        <details className="mt-3 text-xs text-text-muted">
          <summary className="cursor-pointer select-none">
            Low ({quiet.length}): {quiet.map(([tool]) => humanTool(tool)).join(' · ')}
          </summary>
          <div className="mt-1 space-y-0.5 pl-3">
            {quiet.map(([tool, t]) => (
              <ToolCard key={tool} tool={tool} t={t} />
            ))}
          </div>
        </details>
      )}
      {failing.length > 0 && <UnassessedSources failing={failing} />}
    </Section>
  );
}

function UnassessedSources({ failing }: { failing: [string, ToolUnassessed][] }) {
  return (
    <section
      aria-label="Unassessed sources"
      className="mt-3 rounded-md border border-border border-l-2 border-l-sev-medium bg-bg-surface p-3 text-xs"
    >
      <h3 className="font-medium text-text-primary">Unassessed sources</h3>
      <p className="mt-1 text-text-muted">
        Lodeline could not assess these configs. Where the same tool shows a score above, it is the
        last good reading, not a current one.
      </p>
      <ul className="mt-2 space-y-2">
        {failing.map(([tool, u]) => (
          <li key={tool} className="min-w-0">
            <p className="flex flex-wrap gap-2">
              <span className="font-medium text-text-primary">{humanTool(tool)}</span>
              <UnassessedSince ts={u.since} />
              <span className="text-text-subtle">
                Last good reading:{' '}
                {u.last_assessed_ts ? (
                  <time dateTime={u.last_assessed_ts} title={u.last_assessed_ts}>
                    {shortTime(u.last_assessed_ts)}
                  </time>
                ) : (
                  'none reported'
                )}
              </span>
            </p>
            <ul className="mt-1 space-y-1 pl-3 text-text-muted">
              {u.sources.map((s) => (
                <li key={`${s.path}:${s.user}:${s.rule_pack_id}`} className="break-all">
                  {humanKind(s.error_kind)} · <code className="font-mono">{s.path}</code> ·{' '}
                  {sourceLabel(s)}
                </li>
              ))}
            </ul>
          </li>
        ))}
      </ul>
    </section>
  );
}

function Section({ children }: { children: React.ReactNode }) {
  return (
    <section className="mb-4">
      <h2 className="mb-2 text-xs font-medium uppercase tracking-wide text-text-subtle">
        AI Guard risk
      </h2>
      {children}
    </section>
  );
}

function ToolCard({ tool, t }: { tool: string; t: ToolAiGuard }) {
  const source = sourceLabel(t.source);
  return (
    <div
      className={cn('rounded-md border border-border bg-bg-surface p-3', bucketBorder(t.bucket))}
    >
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="font-medium text-text-primary">
          {humanTool(tool, t.source?.tool_label)}
        </span>
        <span className={cn('uppercase tracking-wide font-medium', bucketTextColor(t.bucket))}>
          {t.bucket} {t.score.toFixed(2)}
        </span>
        <span className="text-text-subtle">{scopeLabel(t.scope)}</span>
        {t.is_reattestation && <span className="text-text-subtle">· re-attested</span>}
        {source && <span className="text-text-subtle">· {source}</span>}
        {t.unassessed_since && <UnassessedSince ts={t.unassessed_since} />}
      </div>
      <ObservedControls controls={t.controls} assessedAt={t.assessed_ts} scope={t.scope} />
      {t.reasons && t.reasons.length > 0 && (
        <div className="mt-2 text-xs">
          <ReasonList reasons={t.reasons} />
        </div>
      )}
    </div>
  );
}

function bucketBorder(bucket: string): string {
  switch (bucket) {
    case 'critical':
      return 'border-l-2 border-l-sev-critical';
    case 'high':
      return 'border-l-2 border-l-sev-high';
    case 'medium':
      return 'border-l-2 border-l-sev-medium';
    default:
      return '';
  }
}
