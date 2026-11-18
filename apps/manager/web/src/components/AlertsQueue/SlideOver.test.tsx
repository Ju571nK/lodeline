import '@testing-library/jest-dom/vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  RouterProvider,
} from '@tanstack/react-router';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { EventWithTriage, Evidence } from '@/api/fleet';
import type { AlertsSearch } from '@/lib/alertsSearch';
import { SlideOver } from './SlideOver';

beforeEach(() => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response('{"error":{"code":"not_found"}}', { status: 404 })),
  );
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const scope = { kind: 'user_global' };
const riskAssessed = {
  kind: 'ai_guard_risk_assessed',
  tool: 'claude_code',
  scope,
  score: 7.2,
  bucket: 'critical',
  reasons: [],
  is_reattestation: false,
};
const toggleDrift = {
  kind: 'ai_guard_toggle_drift',
  tool: 'claude_code',
  scope,
  toggle: 'auto_approval_enabled',
  rule_pack_id: 'acme-extended',
};

const baseEvent: EventWithTriage = {
  schema_version: 1,
  event_id: 'e1',
  ts: '2026-11-09T00:00:00Z',
  host_id: 'h1',
  agent_version: '0.14.1',
  severity: 'warn',
  source: { kind: 'file_system' },
  subject: { kind: 'path', value: '/home/u/.claude/settings.json' },
  evidence: riskAssessed,
  target_id: null,
  triage: null,
};

interface DetailOptions {
  evidence?: Evidence;
  position?: { index: number; total: number; onPrev: () => void; onNext: () => void };
  fullPageSearch?: AlertsSearch;
}

async function renderDrawer({ evidence = riskAssessed, position, fullPageSearch }: DetailOptions) {
  const event = { ...baseEvent, evidence };
  const client = new QueryClient();
  const noop = () => {};
  const root = createRootRoute({
    component: () => (
      <SlideOver
        event={event}
        onClose={noop}
        registerFocusAssign={noop}
        registerFocusNote={noop}
        position={position}
        fullPageSearch={fullPageSearch}
      />
    ),
  });
  const host = createRoute({ getParentRoute: () => root, path: '/hosts/$hostId' });
  const full = createRoute({ getParentRoute: () => root, path: '/alerts/$eventId' });
  const router = createRouter({
    routeTree: root.addChildren([host, full]),
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

const renderDetail = (evidence: Evidence) => renderDrawer({ evidence });

const fact = (label: string) => screen.getByText(label, { selector: 'dt' }).nextElementSibling;

const cases: [string, Evidence, string][] = [
  ['ai_guard_risk_assessed', riskAssessed, 'built-in rules'],
  ['ai_guard_toggle_drift', toggleDrift, 'rule pack acme-extended'],
];

describe('AI Guard event detail names the user whose home was assessed', () => {
  it.each(
    cases,
  )('%s shows the user when the reading carries one', async (_kind, evidence, rules) => {
    await renderDetail({ ...evidence, user: 'alice' });
    expect(fact('Source')?.textContent).toBe(`user alice · ${rules}`);
  });

  it.each(cases)('%s names no user when the reading has none', async (_kind, evidence, rules) => {
    await renderDetail(evidence);
    expect(fact('Source')?.textContent).toBe(`agent's own home · ${rules}`);
    expect(screen.queryByText(/alice/)).toBeNull();
  });
});

describe('alert drawer navigation', () => {
  const position = (index: number, total: number) => ({
    index,
    total,
    onPrev: vi.fn(),
    onNext: vi.fn(),
  });

  it('shows the position and moves with the previous and next buttons', async () => {
    const p = position(2, 7);
    await renderDrawer({ position: p });
    expect(screen.getByTestId('alert-position').textContent).toBe('3 of 7');
    fireEvent.click(screen.getByRole('button', { name: 'Next alert' }));
    fireEvent.click(screen.getByRole('button', { name: 'Previous alert' }));
    expect(p.onNext).toHaveBeenCalledTimes(1);
    expect(p.onPrev).toHaveBeenCalledTimes(1);
  });

  it('disables previous on the first alert and next on the last', async () => {
    await renderDrawer({ position: position(0, 7) });
    expect(screen.getByRole('button', { name: 'Previous alert' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Next alert' })).toBeEnabled();
    cleanup();
    await renderDrawer({ position: position(6, 7) });
    expect(screen.getByRole('button', { name: 'Next alert' })).toBeDisabled();
  });

  it('shows no position when the drawer has no list behind it', async () => {
    await renderDrawer({});
    expect(screen.queryByTestId('alert-position')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Next alert' })).toBeNull();
  });

  it('links the host id to the host page', async () => {
    await renderDrawer({});
    const link = screen.getByRole('link', { name: 'h1' });
    expect(link.getAttribute('href')).toBe('/hosts/h1');
  });

  it('offers the full page only when it is given a list view to return to', async () => {
    await renderDrawer({});
    expect(screen.queryByRole('link', { name: 'Open full page' })).toBeNull();
    cleanup();
    await renderDrawer({ fullPageSearch: { minBucket: 'high', sort: 'age_desc' } });
    const href = screen.getByRole('link', { name: 'Open full page' }).getAttribute('href');
    expect(href).toContain('/alerts/e1');
    expect(href).toContain('minBucket=high');
    expect(href).toContain('sort=age_desc');
    expect(href).not.toContain('alert=');
  });
});

describe('alert drawer width', () => {
  const sep = () => screen.getByRole('separator', { name: 'Resize alert panel' });
  const setViewport = (w: number) => {
    Object.defineProperty(window, 'innerWidth', { value: w, configurable: true });
  };

  let store: Record<string, string>;
  const fakeStorage = {
    getItem: (k: string) => store[k] ?? null,
    setItem: (k: string, v: string) => {
      store[k] = v;
    },
  };

  beforeEach(() => {
    store = {};
    vi.stubGlobal('localStorage', fakeStorage);
    setViewport(1600);
  });
  afterEach(() => {
    setViewport(1024);
  });

  it('starts wider than 420 px on a large window', async () => {
    await renderDrawer({});
    expect(Number(sep().getAttribute('aria-valuenow'))).toBeGreaterThan(600);
  });

  it('resizes with the arrow keys and remembers the width', async () => {
    await renderDrawer({});
    const before = Number(sep().getAttribute('aria-valuenow'));
    fireEvent.keyDown(sep(), { key: 'ArrowLeft' });
    expect(Number(sep().getAttribute('aria-valuenow'))).toBe(before + 20);
    fireEvent.keyDown(sep(), { key: 'ArrowRight', shiftKey: true });
    expect(Number(sep().getAttribute('aria-valuenow'))).toBe(before - 80);
    expect(Number(store['lodeline.alertDrawerWidth'])).toBe(before - 80);
  });

  it('reads the width a viewer saved', async () => {
    store['lodeline.alertDrawerWidth'] = '777';
    await renderDrawer({});
    expect(sep().getAttribute('aria-valuenow')).toBe('777');
  });

  it('still opens when browser storage throws', async () => {
    const blocked = () => {
      throw new Error('blocked');
    };
    vi.stubGlobal('localStorage', { getItem: blocked, setItem: blocked });
    await renderDrawer({});
    fireEvent.keyDown(sep(), { key: 'ArrowLeft' });
    expect(Number(sep().getAttribute('aria-valuenow'))).toBeGreaterThan(600);
  });

  it('takes the full width under 900 px and offers no handle', async () => {
    setViewport(800);
    await renderDrawer({});
    expect(screen.queryByRole('separator', { name: 'Resize alert panel' })).toBeNull();
    expect(screen.getByRole('dialog').style.width).toBe('100vw');
  });
});
