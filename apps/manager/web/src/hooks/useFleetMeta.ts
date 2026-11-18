import { useQuery } from '@tanstack/react-query';
import { fleetMeta } from '@/api/fleet';

// The active-host count in /v1/meta moves as hosts enroll, so it is re-read every 30 s.
const META_STALE_MS = 15_000;
const META_POLL_MS = 30_000;

/**
 * Shared `/v1/meta` query. Uses the same `['fleet','meta']` key as
 * [`useAlerts`], so the fleet header and Settings reuse the cached
 * response instead of firing a second request.
 */
export function useFleetMeta(
  options: { refetchInterval?: number; refetchOnMount?: 'always' } = {},
) {
  return useQuery({
    queryKey: ['fleet', 'meta'],
    queryFn: fleetMeta,
    staleTime: META_STALE_MS,
    refetchInterval: META_POLL_MS,
    retry: false,
    refetchIntervalInBackground: false,
    ...options,
  });
}
