import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, renderHook } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { MetaResponse } from '@/api/fleet';
import { useFleetMeta } from './useFleetMeta';

const fleetMeta = vi.hoisted(() => vi.fn());
vi.mock('@/api/fleet', () => ({ fleetMeta }));

const meta = (count: number): MetaResponse => ({
  server_version: '0.0.0',
  schema_version: 1,
  ts: '2026-11-18T00:00:00Z',
  alerts_definition_default: { evidence_kinds: [], ai_guard_buckets: [], additional_kinds: [] },
  fleet: { active_host_count: count, active_window_days: 7 },
});

beforeEach(() => vi.useFakeTimers());
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  fleetMeta.mockReset();
});

describe('useFleetMeta', () => {
  it('picks up a host that enrolls while the page stays open', async () => {
    fleetMeta.mockResolvedValueOnce(meta(0)).mockResolvedValue(meta(1));
    const client = new QueryClient();
    const wrapper = ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    );
    const { result } = renderHook(() => useFleetMeta(), { wrapper });
    await act(() => vi.advanceTimersByTimeAsync(0));
    expect(result.current.data?.fleet?.active_host_count).toBe(0);

    await act(() => vi.advanceTimersByTimeAsync(2 * 60_000));
    expect(result.current.data?.fleet?.active_host_count).toBe(1);
  });
});
