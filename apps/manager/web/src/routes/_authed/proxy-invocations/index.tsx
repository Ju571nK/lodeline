import { createFileRoute, Link } from '@tanstack/react-router';
import {
  fleetInvocations,
  type InvocationSummary,
  type InvocationsPage,
  type Lifecycle,
  type Outcome,
} from '@/api/proxies';
import { Pagination } from '@/components/Fleet/Pagination';
import { SkeletonRows } from '@/components/Fleet/SkeletonRows';
import { InvocationTable } from '@/components/Proxy/InvocationTable';
import { ProxyReadError } from '@/components/Proxy/ProxyParts';
import { usePagedFleet } from '@/hooks/usePagedFleet';
import { lifecycleLabel, outcomeLabel } from '@/lib/proxy';

type Filterable = Exclude<Lifecycle, 'unknown'>;
const lifecycles = Object.keys(lifecycleLabel).filter((l) => l !== 'unknown') as Filterable[];
const outcomes = Object.keys(outcomeLabel) as Outcome[];
const methods = ['initialize', 'ping', 'tools/list', 'tools/call', 'unknown'];

interface InvocationSearch {
  proxy?: string;
  lifecycle?: Filterable;
  outcome?: Outcome;
  method?: string;
}

const oneOf = <T extends string>(v: unknown, allowed: readonly T[]) =>
  allowed.includes(v as T) ? (v as T) : undefined;

export const Route = createFileRoute('/_authed/proxy-invocations/')({
  validateSearch: (raw: Record<string, unknown>): InvocationSearch => ({
    proxy: typeof raw.proxy === 'string' && raw.proxy ? raw.proxy : undefined,
    lifecycle: oneOf(raw.lifecycle, lifecycles),
    outcome: oneOf(raw.outcome, outcomes),
    method: oneOf(raw.method, methods),
  }),
  component: InvocationsPageView,
});

const selectItems = (page: InvocationsPage) => page.items;
const invocationID = (i: InvocationSummary) => i.invocation_id;

function InvocationsPageView() {
  const search = Route.useSearch();
  const navigate = Route.useNavigate();
  const params = {
    limit: 100,
    proxyId: search.proxy,
    lifecycle: search.lifecycle,
    outcome: search.outcome,
    method: search.method,
  };
  // The filters are in the key, so a changed filter starts a new list and never reuses a cursor.
  const invocations = usePagedFleet(
    ['proxies', 'invocations', params],
    (cursor, signal) => fleetInvocations({ ...params, cursor }, signal),
    selectItems,
    invocationID,
  );
  const set = (patch: Partial<InvocationSearch>) => navigate({ search: { ...search, ...patch } });
  const inputClass = 'rounded border border-border bg-bg-surface px-2 py-1 text-sm';
  return (
    <div className="space-y-3">
      <Link to="/proxies" className="text-xs text-text-muted hover:text-text-primary">
        ← Proxies
      </Link>
      <h1 className="text-lg font-semibold text-text-primary">Proxy invocations</h1>
      <p className="text-sm text-text-muted">
        Tool calls through Lodeline Proxy, newest first, as the server reconstructs them from the
        proxies’ events. Only a completed invocation shows its outcome. A flagged one shows what the
        proxy reported, which nothing corroborates.
      </p>
      <div className="flex flex-wrap items-end gap-3 text-xs text-text-muted">
        {search.proxy && (
          <p className="grid gap-1">
            Proxy
            <span className="py-1 text-sm text-text-body">
              <span className="font-mono">{search.proxy}</span>{' '}
              <Link
                to="/proxy-invocations"
                search={{ ...search, proxy: undefined }}
                className="text-accent hover:underline"
              >
                all proxies
              </Link>
            </span>
          </p>
        )}
        <label className="grid gap-1">
          Lifecycle
          <select
            className={inputClass}
            value={search.lifecycle ?? ''}
            onChange={(e) => set({ lifecycle: (e.target.value || undefined) as Filterable })}
          >
            <option value="">All</option>
            {lifecycles.map((l) => (
              <option key={l} value={l}>
                {lifecycleLabel[l]}
              </option>
            ))}
          </select>
        </label>
        <label className="grid gap-1">
          Outcome
          <select
            className={inputClass}
            value={search.outcome ?? ''}
            onChange={(e) => set({ outcome: (e.target.value || undefined) as Outcome })}
          >
            <option value="">All</option>
            {outcomes.map((o) => (
              <option key={o} value={o}>
                {outcomeLabel[o]}
              </option>
            ))}
          </select>
        </label>
        <label className="grid gap-1">
          Method
          <select
            className={inputClass}
            value={search.method ?? ''}
            onChange={(e) => set({ method: e.target.value || undefined })}
          >
            <option value="">All</option>
            {methods.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
        </label>
      </div>
      {search.outcome && (
        <p className="text-xs text-text-muted">
          An outcome filter matches completed invocations only. Choose a lifecycle to find the
          flagged ones.
        </p>
      )}
      <div className="overflow-x-auto rounded-md border border-border bg-bg-surface">
        {invocations.isPending ? (
          <SkeletonRows />
        ) : invocations.rows.length === 0 && invocations.error ? (
          <ProxyReadError error={invocations.error} what="invocations" />
        ) : invocations.rows.length === 0 ? (
          <p className="p-6 text-sm text-text-muted">No invocations match.</p>
        ) : (
          <InvocationTable rows={invocations.rows} />
        )}
        {!invocations.isPending && (invocations.rows.length > 0 || !invocations.error) && (
          <Pagination {...invocations} count={invocations.rows.length} />
        )}
      </div>
    </div>
  );
}
