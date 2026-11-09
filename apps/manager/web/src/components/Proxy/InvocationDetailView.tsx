import type { InvocationDetail } from '@/api/proxies';
import { Card, Empty } from '@/components/Host/HostMetaCard';
import {
  flagName,
  formatBytes,
  invocationStatus,
  lifecycleLabel,
  reportedClaim,
} from '@/lib/proxy';
import { Row, TonePill, When } from './ProxyParts';

/** One invocation as the server projects it, and its event envelopes. Read only. */
export function InvocationDetailView({ invocation: inv }: { invocation: InvocationDetail }) {
  const status = invocationStatus(inv);
  const claim = reportedClaim(inv);
  const tool = inv.tool;
  const actor = inv.actor;
  return (
    <div className="space-y-4">
      <header className="space-y-1">
        <h1 className="text-lg font-semibold text-text-primary">Invocation</h1>
        <p className="font-mono text-xs text-text-muted">{inv.invocation_id}</p>
        <p className="text-xs">
          <TonePill tone={status.tone}>{status.label}</TonePill>{' '}
          <span className="text-text-muted">lifecycle {lifecycleLabel[inv.lifecycle]}</span>
        </p>
        {status.note && !status.flagged && <p className="text-xs text-text-muted">{status.note}</p>}
      </header>

      {status.flagged && (
        <p role="alert" className="rounded-md border border-status-down/40 p-3 text-xs">
          {status.note} Do not count this invocation as a success.
        </p>
      )}

      <div className="grid gap-3 md:grid-cols-2">
        <Card title="Request">
          {inv.method === null && actor === null ? (
            <Empty>No start observed.</Empty>
          ) : (
            <dl className="space-y-1 text-xs">
              <Row label="Method">{inv.method ?? 'none'}</Row>
              <Row label="Protocol">{inv.protocol_version ?? 'none'}</Row>
              <Row label="Upstream">{inv.upstream_id ?? 'none'}</Row>
              <Row label="Route revision">{inv.route_revision ?? 'none'}</Row>
              <Row label="Tool">
                {tool
                  ? [tool.status, tool.metadata_ref && `ref ${tool.metadata_ref}`, tool.reason]
                      .filter(Boolean)
                      .join(', ')
                  : 'none'}
              </Row>
              {actor && (
                <>
                  <Row label="Actor">{actor.actor_id}</Row>
                  <Row label="Actor kind">{actor.actor_kind}</Row>
                  <Row label="Authentication">
                    {actor.authentication_method}, from {actor.evidence_source}
                  </Row>
                  <Row label="Credential owner">
                    {actor.credential_owner_id ?? 'none'}
                    <p className="text-text-muted">
                      Owns the credential’s permissions. Not the one who ran the call.
                    </p>
                  </Row>
                </>
              )}
            </dl>
          )}
        </Card>

        <Card title="Completion">
          <dl className="space-y-1 text-xs">
            <Row label="Outcome">{status.outcome}</Row>
            {status.completion && (
              <>
                <Row label="Delivery">{status.completion.delivery ?? 'none'}</Row>
                <Row label="Reason">{status.completion.reason ?? 'none'}</Row>
              </>
            )}
            {claim && <Row label="Proxy reported">{claim}</Row>}
            <Row label="Duration">
              {inv.duration_ms === null ? 'none' : `${inv.duration_ms} ms`}
            </Row>
            <Row label="Response size">
              {inv.response_bytes === null ? 'none' : formatBytes(inv.response_bytes)}
            </Row>
            <Row label="Cancel observed">{inv.cancel_observed ? 'Yes' : 'No'}</Row>
          </dl>
        </Card>

        <Card title="Timing">
          <dl className="space-y-1 text-xs">
            <Row label="Started">
              <When ts={inv.started_at} /> <span className="text-text-muted">proxy clock</span>
            </Row>
            <Row label="Completed">
              <When ts={inv.completed_at} /> <span className="text-text-muted">proxy clock</span>
            </Row>
            <Row label="First received">
              <When ts={inv.first_received_at} />
            </Row>
            <Row label="Last received">
              <When ts={inv.last_received_at} />
            </Row>
            <Row label="Start epoch">
              <span className="font-mono">{inv.start_epoch_id ?? 'none'}</span>
            </Row>
            <Row label="Epoch superseded">{inv.epoch_superseded ? 'Yes' : 'No'}</Row>
          </dl>
        </Card>

        <Card title="Flags">
          {inv.flags.length ? (
            <ul className="space-y-1 text-xs">
              {inv.flags.map((f) => (
                <li key={f}>{flagName(f)}</li>
              ))}
            </ul>
          ) : (
            <Empty>No flags.</Empty>
          )}
        </Card>
      </div>

      <Card title="Events">
        <p className="mb-2 text-xs">
          Showing {inv.events.length} of {inv.events_total}, in the order the server accepted them.
          Identifiers only: the server never returns an event’s payload.
        </p>
        {inv.events_truncated && (
          <p role="alert" className="mb-2 text-xs text-status-degraded">
            This list is incomplete: the server returns at most {inv.events.length} events of an
            invocation, and {inv.events_total - inv.events.length} more are not shown.
          </p>
        )}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="text-text-muted">
              <tr>
                {['Type', 'Sequence', 'Occurred (proxy clock)', 'Received', 'Event'].map((h) => (
                  <th key={h} className="px-2 py-1.5 font-medium">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {inv.events.map((e) => (
                <tr key={e.event_id} className="border-t border-border-subtle">
                  <td className="px-2 py-1.5">{e.event_type}</td>
                  <td className="px-2 py-1.5">{e.sequence}</td>
                  <td className="whitespace-nowrap px-2 py-1.5">
                    <When ts={e.occurred_at} />
                  </td>
                  <td className="whitespace-nowrap px-2 py-1.5">
                    <When ts={e.received_at} />
                  </td>
                  <td className="px-2 py-1.5 font-mono text-text-muted">{e.event_id}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
