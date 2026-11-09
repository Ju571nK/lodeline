import type { ReactNode } from 'react';
import { ApiError, NotFoundError } from '@/api/client';
import type { ProxySummary } from '@/api/proxies';
import { connectionLabel, connectionTone, type Tone } from '@/lib/proxy';
import { relativeAge, shortTime } from '@/lib/time';
import { cn } from '@/lib/utils';

const toneClass: Record<Tone, string> = {
  ok: 'border-status-healthy/40 text-status-healthy',
  warn: 'border-status-degraded/40 text-status-degraded',
  bad: 'border-status-down/40 text-status-down',
  neutral: 'border-border text-text-muted',
};

export function TonePill({ tone, children }: { tone: Tone; children: ReactNode }) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded border px-1.5 py-0.5 text-[11px] leading-none',
        toneClass[tone],
      )}
    >
      {children}
    </span>
  );
}

export function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex gap-2">
      <dt className="w-32 shrink-0 text-text-subtle">{label}</dt>
      <dd className="text-text-body">{children}</dd>
    </div>
  );
}

/** A time as "Nov 5, 14:31 (3m ago)", or `none` when the server sent null. */
export function When({ ts, none = 'none' }: { ts: string | null; none?: string }) {
  if (!ts) return <span className="text-text-muted">{none}</span>;
  const past = new Date(ts).getTime() <= Date.now();
  return (
    <span title={ts}>
      {shortTime(ts)} ({past ? `${relativeAge(ts)} ago` : `in ${relativeAge(ts)}`})
    </span>
  );
}

/**
 * Connection state, always with the time of the report it rests on and the open gap count, so a
 * connected proxy with open gaps does not read as healthy (ledger-and-query.md L3, L4).
 */
export function ConnectionCell({ proxy }: { proxy: ProxySummary }) {
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5">
      <TonePill tone={connectionTone[proxy.connection_state]}>
        {connectionLabel[proxy.connection_state]}
      </TonePill>
      <TonePill tone={proxy.open_gap_count > 0 ? 'warn' : 'neutral'}>
        {proxy.open_gap_count} open {proxy.open_gap_count === 1 ? 'gap' : 'gaps'}
      </TonePill>
      <span className="text-text-muted">
        {proxy.status_as_of ? (
          <>
            status as of <When ts={proxy.status_as_of} />
          </>
        ) : (
          'no status report yet'
        )}
      </span>
    </span>
  );
}

const notFoundText = {
  proxy:
    'Proxy not found. It is not registered, or it is outside the read range of this console’s credential; the server answers both the same way.',
  invocation:
    'Invocation not found. The server has no such invocation, or its proxy is outside the read range of this console’s credential; the server answers both the same way.',
};

/** Answers that another try within the poll interval would not change. */
export const settled = (error: Error) =>
  error instanceof NotFoundError ||
  (error instanceof ApiError &&
    ['proxy_reads_unavailable', 'upstream_forbidden'].includes(error.code));

/** The panel for a failed proxy or invocation read, by the console's error code. */
export function ProxyReadError({
  error,
  what,
  target = 'proxy',
}: {
  error: Error;
  what: string;
  target?: keyof typeof notFoundText;
}) {
  const code = error instanceof ApiError ? error.code : '';
  const text =
    error instanceof NotFoundError
      ? notFoundText[target]
      : code === 'proxy_reads_unavailable'
        ? 'Proxy reads are not available on this lodeline-server. It runs without a proxy section, or it does not serve proxy reads to this console’s client certificate.'
        : code === 'upstream_forbidden'
          ? 'lodeline-server does not give this console’s read credential proxy reads.'
          : `Could not load ${what}: ${error.message}`;
  return (
    <p role="alert" className="rounded-md border border-border bg-bg-surface p-6 text-sm">
      {text}
    </p>
  );
}
