import { createFileRoute, Link } from '@tanstack/react-router';
import { fleetProxy } from '@/api/proxies';
import { ProxyDetailView } from '@/components/Proxy/ProxyDetailView';
import { ProxyReadError, settled } from '@/components/Proxy/ProxyParts';
import { useFleetQuery } from '@/hooks/useFleetQuery';

export const Route = createFileRoute('/_authed/proxies/$proxyId')({
  component: ProxyDetailPage,
});

function ProxyDetailPage() {
  const { proxyId } = Route.useParams();
  const q = useFleetQuery(['proxies', 'detail', proxyId], () => fleetProxy(proxyId), {
    retry: (failureCount, error) => !settled(error) && failureCount < 2,
  });
  // keepPreviousData can hold another proxy's body while this one loads, and a settled error
  // means the last body no longer describes a readable proxy.
  const proxy = q.data?.proxy_id === proxyId && !(q.error && settled(q.error)) ? q.data : undefined;
  return (
    <div className="space-y-3">
      <p className="flex flex-wrap gap-3 text-xs text-text-muted">
        <Link to="/proxies" className="hover:text-text-primary">
          ← Proxies
        </Link>
        <Link
          to="/proxy-invocations"
          search={{ proxy: proxyId }}
          className="hover:text-text-primary"
        >
          Invocations of this proxy
        </Link>
      </p>
      {q.error && <ProxyReadError error={q.error} what="the proxy" />}
      {proxy ? (
        <ProxyDetailView proxy={proxy} />
      ) : (
        !q.error && <div className="h-24 w-full animate-pulse rounded bg-bg-elevated" />
      )}
    </div>
  );
}
