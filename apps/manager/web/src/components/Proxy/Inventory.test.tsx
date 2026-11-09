import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  createMemoryHistory,
  createRootRoute,
  createRouter,
  RouterProvider,
} from '@tanstack/react-router';
import { cleanup, render, screen, within } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type {
  DriftRecord,
  InventoryScope,
  InventorySnapshot,
  InventoryView,
  ProxyDetail,
} from '@/api/proxies';
import { driftChangeLabel, driftChangeTone } from '@/lib/proxy';
import { InventorySection } from './Inventory';
import { ProxyDetailView } from './ProxyDetailView';
import { ago, proxyDetail } from './proxy.fixture';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const scope: InventoryScope = {
  proxy_id: 'px-a',
  upstream_id: 'up1',
  credential_scope_id: 'cs-1',
  protocol_version: '2025-11-25',
  observation_source: 'proxy_live',
};

const snapshot: InventorySnapshot = {
  ...scope,
  inventory_id: 'inv-2',
  canon: 'sigil-tooldef-fp-v1',
  key_id: 'kid-1',
  member_count: 12,
  observed_at: ago(70),
  received_at: ago(60),
  is_latest: true,
  is_first_baseline: false,
  comparison_state: 'compared',
  awaiting_inventory_id: null,
};

const drift = (change: DriftRecord['change'], n: number): DriftRecord => ({
  ...scope,
  drift_id: `d-${n}`,
  inventory_id: 'inv-2',
  previous_inventory_id: 'inv-1',
  change,
  metadata_ref: `ref-${n}`,
  ...(change === 'changed' ? { previous_metadata_ref: 'ref-old' } : {}),
  detected_at: ago(60),
});

/** The console's answer for every request: `status` and `body` as JSON. */
function serve(status: number, body: unknown) {
  const fetch = vi.fn(
    async () =>
      new Response(JSON.stringify(body), {
        status,
        headers: { 'Content-Type': 'application/json' },
      }),
  );
  vi.stubGlobal('fetch', fetch);
  return fetch;
}

async function renderPage(children: ReactNode) {
  const rootRoute = createRootRoute({ component: () => <main>{children}</main> });
  const router = createRouter({ routeTree: rootRoute, history: createMemoryHistory() });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return screen.findByRole('main');
}

function section(view: InventoryView, proxy: ProxyDetail = proxyDetail()) {
  return renderPage(<InventorySection proxy={proxy} view={view} />);
}

/** The table whose header row names `header`. */
function tableWith(header: string) {
  const table = screen
    .getAllByRole('table')
    .find((t) => within(t).queryByRole('columnheader', { name: header }));
  if (!table) throw new Error(`no table with a ${header} column`);
  return table;
}

describe('inventory views', () => {
  it('shows drift as an observed change, never as an approval', async () => {
    const fetch = serve(200, {
      items: [drift('added', 1), drift('removed', 2), drift('changed', 3)],
      next_cursor: null,
    });
    await section('drift');
    const table = await screen.findByRole('table');
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/fleet/proxies/px-a/drift?limit=100',
      expect.anything(),
    );
    expect(within(table).getByRole('columnheader', { name: 'Observed change' })).toBeVisible();
    for (const label of ['Added', 'Removed', 'Changed']) {
      expect(within(table).getByText(label)).toBeVisible();
    }
    expect(within(table).queryByText(/approv|accept|review/i)).not.toBeInTheDocument();
    expect(screen.getByText(/A drift record is an observed change, not an approval/)).toBeVisible();
    expect(within(table).getByText('ref-old')).toBeVisible();
    for (const tone of Object.values(driftChangeTone)) expect(tone).not.toBe('ok');
    for (const label of Object.values(driftChangeLabel)) expect(label).not.toMatch(/approv/i);
  });

  it('lists an incomplete observation as an audit gap, not as a snapshot', async () => {
    const proxy = proxyDetail({
      audit_gaps: [
        {
          gap_id: 'g-inv',
          kind: 'inventory_incomplete',
          source: 'server_derived',
          detected_at: ago(30),
          state: 'open',
          details: {
            upstream_id: 'up1',
            credential_scope_id: 'cs-1',
            incomplete_reason: 'page_error',
            observed_at: ago(31),
          },
        },
      ],
      audit_gaps_total: 1,
      open_gap_counts: { inventory_incomplete: 1 },
    });
    serve(200, { items: [snapshot], next_cursor: null });
    await renderPage(
      <>
        <ProxyDetailView proxy={proxy} />
        <InventorySection proxy={proxy} view="inventory-snapshots" />
      </>,
    );
    await screen.findByText('inv-2');
    const gaps = within(tableWith('Kind')).getAllByRole('row').slice(1);
    expect(gaps).toHaveLength(1);
    expect(gaps[0]).toHaveTextContent('Inventory incomplete');
    expect(gaps[0]).toHaveTextContent('incomplete_reason=page_error');
    const snapshots = within(tableWith('Members')).getAllByRole('row').slice(1);
    expect(snapshots).toHaveLength(1);
    expect(snapshots[0]).toHaveTextContent('inv-2');
    expect(snapshots[0]).not.toHaveTextContent('page_error');
    expect(
      screen.getByText(/The server lists each one as an Inventory incomplete audit gap above: 1/),
    ).toBeVisible();
  });

  it('shows a first baseline as a starting point and a pending one as waiting', async () => {
    serve(200, {
      items: [
        {
          ...snapshot,
          inventory_id: 'inv-3',
          comparison_state: 'pending_previous',
          awaiting_inventory_id: 'inv-9',
        },
        { ...snapshot, comparison_state: 'baseline', is_first_baseline: true },
      ],
      next_cursor: null,
    });
    await section('inventory-snapshots');
    const rows = within(await screen.findByRole('table'))
      .getAllByRole('row')
      .slice(1);
    expect(rows[0]).toHaveTextContent('Waiting for previous snapshot');
    expect(rows[0]).toHaveTextContent('No drift until inv-9 arrives.');
    expect(rows[1]).toHaveTextContent('Initial baseline');
    expect(rows[1]).toHaveTextContent('A starting point, not an approval.');
  });

  it('renders no control that changes anything', async () => {
    serve(200, { items: [snapshot], next_cursor: null });
    const main = await section('inventory-snapshots');
    await screen.findByRole('table');
    expect(
      within(main)
        .getAllByRole('button')
        .map((b) => b.textContent),
    ).toEqual(['Refresh']);
    expect(within(main).queryAllByRole('textbox')).toHaveLength(0);
    expect(within(main).queryAllByRole('combobox')).toHaveLength(0);
    const tabs = within(screen.getByRole('navigation', { name: 'Inventory views' }));
    expect(tabs.getAllByRole('link').map((l) => l.textContent)).toEqual([
      'Snapshots',
      'Drift',
      'Re-baseline markers',
    ]);
    expect(tabs.getByRole('link', { name: 'Snapshots' })).toHaveAttribute('aria-current', 'page');
  });

  it('names a server that does not serve the inventory views', async () => {
    serve(502, {
      error: { code: 'proxy_reads_unavailable', message: 'proxy reads are not available' },
    });
    await section('rebaseline-markers');
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Inventory reads are not available on this lodeline-server.',
    );
  });
});
