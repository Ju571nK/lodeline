import { createFileRoute, Link } from '@tanstack/react-router';
import { fleetInvocation } from '@/api/proxies';
import { InvocationDetailView } from '@/components/Proxy/InvocationDetailView';
import { ProxyReadError, settled } from '@/components/Proxy/ProxyParts';
import { useFleetQuery } from '@/hooks/useFleetQuery';

export const Route = createFileRoute('/_authed/proxy-invocations/$invocationId')({
  component: InvocationDetailPage,
});

function InvocationDetailPage() {
  const { invocationId } = Route.useParams();
  const q = useFleetQuery(
    ['proxies', 'invocation', invocationId],
    () => fleetInvocation(invocationId),
    { retry: (failureCount, error) => !settled(error) && failureCount < 2 },
  );
  // keepPreviousData can hold another invocation while this one loads.
  const inv =
    q.data?.invocation_id === invocationId && !(q.error && settled(q.error)) ? q.data : undefined;
  return (
    <div className="space-y-3">
      <p className="flex flex-wrap gap-3 text-xs text-text-muted">
        <Link to="/proxy-invocations" className="hover:text-text-primary">
          ← Invocations
        </Link>
        {inv && (
          <>
            <Link
              to="/proxies/$proxyId"
              params={{ proxyId: inv.proxy_id }}
              className="hover:text-text-primary"
            >
              Proxy {inv.proxy_id}
            </Link>
            <Link
              to="/proxy-invocations"
              search={{ proxy: inv.proxy_id }}
              className="hover:text-text-primary"
            >
              Other invocations of this proxy
            </Link>
          </>
        )}
      </p>
      {q.error && <ProxyReadError error={q.error} what="the invocation" target="invocation" />}
      {inv ? (
        <InvocationDetailView invocation={inv} />
      ) : (
        !q.error && <div className="h-24 w-full animate-pulse rounded bg-bg-elevated" />
      )}
    </div>
  );
}
