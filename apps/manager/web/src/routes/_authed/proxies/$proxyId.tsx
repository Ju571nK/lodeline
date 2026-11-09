import { createFileRoute, Link } from '@tanstack/react-router';
import { ApiError, NotFoundError } from '@/api/client';
import { fleetProxy } from '@/api/proxies';
import { ProxyDetailView } from '@/components/Proxy/ProxyDetailView';
import { ProxyReadError } from '@/components/Proxy/ProxyParts';
import { useFleetQuery } from '@/hooks/useFleetQuery';

export const Route = createFileRoute('/_authed/proxies/$proxyId')({
  component: ProxyDetailPage,
});

/** Answers that another try within the poll interval would not change. */
const settled = (error: Error) =>
  error instanceof NotFoundError ||
  (error instanceof ApiError &&
    ['proxy_reads_unavailable', 'upstream_forbidden'].includes(error.code));

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
      <Link to="/proxies" className="text-xs text-text-muted hover:text-text-primary">
        ← Proxies
      </Link>
      {q.error && <ProxyReadError error={q.error} what="the proxy" />}
      {proxy ? (
        <ProxyDetailView proxy={proxy} />
      ) : (
        !q.error && <div className="h-24 w-full animate-pulse rounded bg-bg-elevated" />
      )}
    </div>
  );
}
