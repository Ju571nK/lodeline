import { createFileRoute, Link } from '@tanstack/react-router';
import {
  type ConnectionState,
  fleetProxies,
  type ProxiesPage,
  type ProxySummary,
} from '@/api/proxies';
import { Pagination } from '@/components/Fleet/Pagination';
import { SkeletonRows } from '@/components/Fleet/SkeletonRows';
import { ConnectionCell, ProxyReadError, TonePill, When } from '@/components/Proxy/ProxyParts';
import { usePagedFleet } from '@/hooks/usePagedFleet';
import { configStateLabel, configStateTone, quarantinedBytes, spoolStatus } from '@/lib/proxy';

const states = ['connected', 'disconnected', 'never_connected'] as const;
type Filterable = Exclude<ConnectionState, 'unknown'>;
interface ProxySearch {
  connection?: Filterable;
  sync?: 'in_sync' | 'out_of_sync';
}

export const Route = createFileRoute('/_authed/proxies/')({
  validateSearch: (raw: Record<string, unknown>): ProxySearch => ({
    connection: states.includes(raw.connection as Filterable)
      ? (raw.connection as Filterable)
      : undefined,
    sync: raw.sync === 'in_sync' || raw.sync === 'out_of_sync' ? raw.sync : undefined,
  }),
  component: ProxiesPageView,
});

const selectItems = (page: ProxiesPage) => page.items;
const proxyID = (p: ProxySummary) => p.proxy_id;

function ProxiesPageView() {
  const { connection, sync } = Route.useSearch();
  const navigate = Route.useNavigate();
  const params = {
    limit: 100,
    connectionState: connection,
    configInSync: sync === undefined ? undefined : sync === 'in_sync',
  };
  // The filters are in the key, so a changed filter starts a new list and never reuses a cursor.
  const proxies = usePagedFleet(
    ['proxies', 'list', params],
    (cursor, signal) => fleetProxies({ ...params, cursor }, signal),
    selectItems,
    proxyID,
  );
  const inputClass = 'rounded border border-border bg-bg-surface px-2 py-1 text-sm';
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-baseline justify-between gap-3">
        <h1 className="text-lg font-semibold text-text-primary">Proxies</h1>
        <Link to="/proxy-invocations" className="text-sm text-accent hover:underline">
          All invocations
        </Link>
      </div>
      <p className="text-sm text-text-muted">
        Lodeline Proxy instances registered with lodeline-server, as of each proxy’s last report.
        This console only reads them: registering, disabling and config changes are done on the
        server with its operator CLI.
      </p>
      <div className="flex flex-wrap items-end gap-3 text-xs text-text-muted">
        <label className="grid gap-1">
          Connection
          <select
            className={inputClass}
            value={connection ?? ''}
            onChange={(e) =>
              navigate({
                search: { connection: (e.target.value || undefined) as Filterable, sync },
              })
            }
          >
            <option value="">All</option>
            {states.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
        <label className="grid gap-1">
          Config sync
          <select
            className={inputClass}
            value={sync ?? ''}
            onChange={(e) =>
              navigate({
                search: {
                  connection,
                  sync: (e.target.value || undefined) as ProxySearch['sync'],
                },
              })
            }
          >
            <option value="">All</option>
            <option value="in_sync">in sync</option>
            <option value="out_of_sync">out of sync</option>
          </select>
        </label>
      </div>
      <div className="overflow-x-auto rounded-md border border-border bg-bg-surface">
        {proxies.isPending ? (
          <SkeletonRows />
        ) : proxies.rows.length === 0 && proxies.error ? (
          <ProxyReadError error={proxies.error} what="proxies" />
        ) : proxies.rows.length === 0 ? (
          <p className="p-6 text-sm text-text-muted">No proxies match.</p>
        ) : (
          <table className="w-full text-left text-xs">
            <thead className="text-text-muted">
              <tr>
                {['Proxy', 'Connection', 'Config', 'Config expires', 'Spool', 'Last seen'].map(
                  (h) => (
                    <th key={h} className="px-3 py-2 font-medium">
                      {h}
                    </th>
                  ),
                )}
              </tr>
            </thead>
            <tbody>
              {proxies.rows.map((p) => (
                <tr key={p.proxy_id} className="border-t border-border-subtle align-top">
                  <td className="px-3 py-2">
                    <Link
                      to="/proxies/$proxyId"
                      params={{ proxyId: p.proxy_id }}
                      className="text-accent hover:underline"
                    >
                      {p.display_name}
                    </Link>
                    <div className="font-mono text-text-muted">{p.proxy_id}</div>
                  </td>
                  <td className="px-3 py-2">
                    <ConnectionCell proxy={p} />
                  </td>
                  <td className="px-3 py-2">
                    <TonePill tone={configStateTone[p.config_state]}>
                      {configStateLabel[p.config_state]}
                    </TonePill>{' '}
                    <span className={p.config_in_sync ? 'text-text-muted' : 'text-status-degraded'}>
                      applied {p.applied_revision ?? 'none'}, desired {p.desired_revision ?? 'none'}
                      {p.config_in_sync ? '' : ', out of sync'}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <When ts={p.config_expires_at} />
                  </td>
                  <td className="px-3 py-2">
                    {p.spool ? (
                      <>
                        <TonePill tone={spoolStatus(p.spool).tone}>
                          {spoolStatus(p.spool).label}
                        </TonePill>
                        <div className="text-text-muted">
                          {p.spool.depth_events} events, quarantined {p.spool.quarantined_events} (
                          {quarantinedBytes(p.spool.quarantined_bytes)})
                        </div>
                      </>
                    ) : (
                      <span className="text-text-muted">no report yet</span>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    <When ts={p.last_seen} none="never" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {!proxies.isPending && (proxies.rows.length > 0 || !proxies.error) && (
          <Pagination {...proxies} count={proxies.rows.length} />
        )}
      </div>
    </div>
  );
}
