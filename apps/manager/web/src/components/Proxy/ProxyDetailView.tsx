import type { ReactNode } from 'react';
import type { ProxyDetail } from '@/api/proxies';
import { Card, Empty } from '@/components/Host/HostMetaCard';
import {
  configStateLabel,
  configStateTone,
  formatBytes,
  gapDetails,
  gapKind,
  gapStateLabel,
  quarantinedBytes,
  routeStateLabel,
  routeStateTone,
  spoolStatus,
} from '@/lib/proxy';
import { relativeAge } from '@/lib/time';
import { ConnectionCell, TonePill, When } from './ProxyParts';

/** One proxy's last report and its audit gaps. Read only: it renders no control. */
export function ProxyDetailView({ proxy }: { proxy: ProxyDetail }) {
  const spool = proxy.spool;
  const status = spool ? spoolStatus(spool, proxy.central) : null;
  const registry = proxy.registry;
  const central = proxy.central;
  const gapCounts = Object.entries(proxy.open_gap_counts).filter(([, n]) => n > 0);
  return (
    <div className="space-y-4">
      <header className="space-y-1">
        <h1 className="text-lg font-semibold text-text-primary">{proxy.display_name}</h1>
        <p className="font-mono text-xs text-text-muted">{proxy.proxy_id}</p>
        <div className="text-xs">
          <ConnectionCell proxy={proxy} />
        </div>
        <p className="text-xs text-text-muted">
          Last seen <When ts={proxy.last_seen} none="never" />. Status fields describe the last
          report the server applied, not live state.
        </p>
      </header>

      {central?.ingest_stopped && (
        <p role="alert" className="rounded-md border border-status-degraded/40 p-3 text-xs">
          Ingest stopped: lodeline-server keeps refusing this proxy’s events, so the proxy sends
          them slowly and reports its spool as degraded. Storage may be fine. The flag clears with
          the next accepted batch, and an idle proxy can keep it until then.
        </p>
      )}

      <div className="grid gap-3 md:grid-cols-2">
        <Card title="Config">
          <dl className="space-y-1 text-xs">
            <Row label="Desired revision">{proxy.desired_revision ?? 'none'}</Row>
            <Row label="Applied revision">{proxy.applied_revision ?? 'none reported'}</Row>
            <Row label="In sync">
              <TonePill tone={proxy.config_in_sync ? 'ok' : 'warn'}>
                {proxy.config_in_sync ? 'Yes' : 'No'}
              </TonePill>
            </Row>
            <Row label="Config state">
              <TonePill tone={configStateTone[proxy.config_state]}>
                {configStateLabel[proxy.config_state]}
              </TonePill>
            </Row>
            <Row label="Config expires">
              <When ts={proxy.config_expires_at} />
            </Row>
          </dl>
        </Card>

        <Card title="Spool">
          {spool && status ? (
            <dl className="space-y-1 text-xs">
              <Row label="Spool state">
                <TonePill tone={status.tone}>{status.label}</TonePill>
                {status.note && <p className="mt-1 text-text-muted">{status.note}</p>}
              </Row>
              <Row label="Depth">
                {spool.depth_events} events, {spool.unsent_events} unsent
              </Row>
              <Row label="Size">
                {formatBytes(spool.bytes)} of {formatBytes(spool.capacity_bytes)}
              </Row>
              <Row label="Oldest unsent">
                {spool.oldest_unsent_age_seconds === null
                  ? 'none'
                  : `${spool.oldest_unsent_age_seconds} s`}
              </Row>
              <Row label="Quarantined">
                {spool.quarantined_events} events, {quarantinedBytes(spool.quarantined_bytes)}
              </Row>
            </dl>
          ) : (
            <Empty>No status report yet.</Empty>
          )}
        </Card>

        <Card title="Central ingest">
          {central ? (
            <dl className="space-y-1 text-xs">
              <Row label="Last ack">
                <When ts={central.last_ingest_ack_at} none="none yet" />
              </Row>
              <Row label="Failures in a row">{central.consecutive_failures}</Row>
              <Row label="Ingest stopped">
                <TonePill tone={central.ingest_stopped ? 'warn' : 'neutral'}>
                  {central.ingest_stopped ? 'Yes' : 'No'}
                </TonePill>
              </Row>
            </dl>
          ) : (
            <Empty>No status report yet.</Empty>
          )}
        </Card>

        <Card title="Registry sync">
          {registry ? (
            <dl className="space-y-1 text-xs">
              <Row label="Pending entries">{registry.pending_entries}</Row>
              <Row label="Sync stalled">{registry.sync_stalled ? 'Yes' : 'No'}</Row>
              {registry.quarantined_entries !== undefined && (
                <Row label="Quarantined">{registry.quarantined_entries}</Row>
              )}
              {registry.poisoned_entries !== undefined && (
                <Row label="Paused (refused)">{registry.poisoned_entries}</Row>
              )}
              {registry.discarded_reports !== undefined && (
                <Row label="Discarded reports">{registry.discarded_reports}</Row>
              )}
            </dl>
          ) : (
            <Empty>No status report yet.</Empty>
          )}
        </Card>
      </div>

      <Card title="Route health">
        {proxy.routes.length ? (
          <Table head={['Upstream', 'State', 'Reason']}>
            {proxy.routes.map((r) => (
              <tr key={r.upstream_id} className="border-t border-border-subtle">
                <td className="px-2 py-1.5 font-mono">{r.upstream_id}</td>
                <td className="px-2 py-1.5">
                  <TonePill tone={routeStateTone[r.state]}>{routeStateLabel[r.state]}</TonePill>
                </td>
                <td className="px-2 py-1.5 text-text-muted">{r.reason ?? 'none'}</td>
              </tr>
            ))}
          </Table>
        ) : (
          <Empty>No routes reported.</Empty>
        )}
      </Card>

      <Card title="Audit gaps">
        <div className="mb-2 space-y-1 text-xs">
          <p>
            {gapCounts.length
              ? `Open: ${gapCounts.map(([kind, n]) => `${gapKind(kind)} ${n}`).join(', ')}.`
              : 'No open gaps.'}{' '}
            Showing {proxy.audit_gaps.length} of {proxy.audit_gaps_total}, newest first. A gap stays
            listed after it closes.
          </p>
          {proxy.audit_gaps_dropped > 0 && (
            <p role="alert" className="text-status-degraded">
              This gap list is incomplete: the server dropped {proxy.audit_gaps_dropped} inventory
              gap records at its per-proxy gap limit.
            </p>
          )}
        </div>
        {proxy.audit_gaps.length > 0 && (
          <Table head={['Detected', 'Kind', 'Source', 'State', 'Details']}>
            {proxy.audit_gaps.map((g) => (
              <tr key={g.gap_id} className="border-t border-border-subtle align-top">
                <td className="whitespace-nowrap px-2 py-1.5" title={g.detected_at}>
                  {relativeAge(g.detected_at)} ago
                </td>
                <td className="px-2 py-1.5">{gapKind(g.kind)}</td>
                <td className="px-2 py-1.5 text-text-muted">{g.source}</td>
                <td className="px-2 py-1.5">
                  <TonePill tone={g.state === 'open' ? 'warn' : 'neutral'}>
                    {gapStateLabel[g.state]}
                  </TonePill>
                </td>
                <td className="break-all px-2 py-1.5 font-mono text-text-muted">
                  {gapDetails(g.details)}
                </td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </div>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex gap-2">
      <dt className="w-32 shrink-0 text-text-subtle">{label}</dt>
      <dd className="text-text-body">{children}</dd>
    </div>
  );
}

function Table({ head, children }: { head: string[]; children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-xs">
        <thead className="text-text-muted">
          <tr>
            {head.map((h) => (
              <th key={h} className="px-2 py-1.5 font-medium">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}
