import '@testing-library/jest-dom/vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  RouterProvider,
} from '@tanstack/react-router';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { EventWithTriage } from '@/api/fleet';
import { SlideOver } from './SlideOver';

const ev = (id: string, ts: string): EventWithTriage => ({
  schema_version: 1,
  event_id: id,
  ts,
  host_id: 'h1',
  agent_version: '0.18.0',
  severity: 'warn',
  source: { kind: 'file_system' },
  subject: {},
  target_id: null,
  evidence: {
    kind: 'ai_guard_risk_assessed',
    tool: 'codex',
    scope: { kind: 'user_global' },
    score: 5,
    bucket: 'high',
    reasons: [{ kind: 'no_sandbox' }],
    is_reattestation: false,
  },
  triage: null,
});

const latest = ev('e-new', '2026-11-18T10:00:49Z');
const older = ev('e-old', '2026-11-18T10:00:00Z');

let upserts: { event_id: string; status?: string }[];
let failFor: string | null;

beforeEach(() => {
  upserts = [];
  failFor = null;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: RequestInit) => {
      if (String(url).endsWith('/triage/upsert')) {
        const body = JSON.parse(String(init?.body));
        upserts.push(body);
        if (body.event_id === failFor) {
          return new Response('{"error":{"code":"internal","message":"disk full"}}', {
            status: 500,
          });
        }
        return new Response(
          JSON.stringify({
            host_id: body.host_id,
            event_id: body.event_id,
            status: body.status ?? 'open',
            assignee: null,
            evidence_snapshot: null,
            created_at: '2026-11-18T10:05:00Z',
            updated_at: '2026-11-18T10:05:00Z',
          }),
          { status: 200 },
        );
      }
      return new Response('{"error":{"code":"not_found"}}', { status: 404 });
    }),
  );
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

async function renderGroup(client: QueryClient, groupEvents: EventWithTriage[]) {
  const noop = () => {};
  const root = createRootRoute({
    component: () => (
      <SlideOver
        event={latest}
        groupEvents={groupEvents}
        onClose={noop}
        registerFocusAssign={noop}
        registerFocusNote={noop}
      />
    ),
  });
  const host = createRoute({ getParentRoute: () => root, path: '/hosts/$hostId' });
  const router = createRouter({
    routeTree: root.addChildren([host]),
    history: createMemoryHistory({ initialEntries: ['/'] }),
  });
  await act(async () => {
    render(
      <QueryClientProvider client={client}>
        <RouterProvider router={router as never} />
      </QueryClientProvider>,
    );
    await router.load();
  });
}

describe('triage on a collapsed row', () => {
  it('acknowledges every event of the group', async () => {
    await renderGroup(new QueryClient(), [latest, older]);
    fireEvent.click(screen.getByRole('button', { name: 'Acknowledge' }));
    await waitFor(() => expect(upserts).toHaveLength(2));
    expect(upserts.map((u) => u.event_id).sort()).toEqual(['e-new', 'e-old']);
    expect(upserts.every((u) => u.status === 'acknowledged')).toBe(true);
  });

  it('acts on one event when the row holds one', async () => {
    await renderGroup(new QueryClient(), [latest]);
    fireEvent.click(screen.getByRole('button', { name: 'Acknowledge' }));
    await waitFor(() => expect(upserts).toHaveLength(1));
    expect(upserts[0].event_id).toBe('e-new');
  });

  it('names the event that failed and refetches the list', async () => {
    failFor = 'e-old';
    const client = new QueryClient();
    const invalidate = vi.spyOn(client, 'invalidateQueries');
    await renderGroup(client, [latest, older]);
    fireEvent.click(screen.getByRole('button', { name: 'Acknowledge' }));
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('1 of 2');
    expect(alert.textContent).toContain('e-old');
    expect(alert.textContent).toContain('disk full');
    expect(alert.textContent).not.toContain('e-new');
    expect(upserts).toHaveLength(2);
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['fleet', 'events'] });
  });
});
