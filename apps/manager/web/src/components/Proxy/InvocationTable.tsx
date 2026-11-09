import { Link } from '@tanstack/react-router';
import type { InvocationSummary } from '@/api/proxies';
import { flagName, invocationStatus, reportedClaim } from '@/lib/proxy';
import { TonePill, When } from './ProxyParts';

/** Invocation rows, newest first. A flagged row never shows an outcome, only the proxy's claim. */
export function InvocationTable({ rows }: { rows: InvocationSummary[] }) {
  return (
    <table className="w-full text-left text-xs">
      <thead className="text-text-muted">
        <tr>
          {['Received', 'Invocation', 'Proxy', 'Method', 'Status', 'Duration', 'Flags'].map((h) => (
            <th key={h} className="px-3 py-2 font-medium">
              {h}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((inv) => {
          const status = invocationStatus(inv);
          const claim = status.flagged ? reportedClaim(inv) : null;
          return (
            <tr key={inv.invocation_id} className="border-t border-border-subtle align-top">
              <td className="whitespace-nowrap px-3 py-2">
                <When ts={inv.first_received_at} />
              </td>
              <td className="px-3 py-2">
                <Link
                  to="/proxy-invocations/$invocationId"
                  params={{ invocationId: inv.invocation_id }}
                  className="font-mono text-accent hover:underline"
                >
                  {inv.invocation_id}
                </Link>
              </td>
              <td className="whitespace-nowrap px-3 py-2">
                <Link
                  to="/proxies/$proxyId"
                  params={{ proxyId: inv.proxy_id }}
                  className="font-mono text-accent hover:underline"
                >
                  {inv.proxy_id}
                </Link>
              </td>
              <td className="whitespace-nowrap px-3 py-2">
                {inv.method ?? <span className="text-text-muted">none</span>}
                {inv.upstream_id && <div className="text-text-muted">{inv.upstream_id}</div>}
              </td>
              <td className="px-3 py-2">
                <TonePill tone={status.tone}>{status.label}</TonePill>
                {status.completion?.delivery && (
                  <span className="text-text-muted"> delivery {status.completion.delivery}</span>
                )}
                {claim && <div className="mt-1 text-text-muted">{claim}</div>}
              </td>
              <td className="whitespace-nowrap px-3 py-2">
                {inv.duration_ms === null ? '' : `${inv.duration_ms} ms`}
              </td>
              <td className="px-3 py-2 text-text-muted">{inv.flags.map(flagName).join(', ')}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
