import {
  createMemoryHistory,
  createRootRoute,
  createRouter,
  RouterProvider,
} from '@tanstack/react-router';
import { cleanup, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import type { InvocationSummary } from '@/api/proxies';
import { invocationStatus } from '@/lib/proxy';
import { InvocationTable } from './InvocationTable';
import { invocation } from './invocation.fixture';

afterEach(cleanup);

/** A completion the server could not corroborate: no outcome, only the proxy's claim. */
const claimed = {
  outcome: null,
  delivery_state: null,
  reported_outcome: 'success',
  reported_delivery_state: 'sent',
} as const;

async function renderRows(rows: InvocationSummary[]) {
  const rootRoute = createRootRoute({
    component: () => (
      <div data-testid="page">
        <InvocationTable rows={rows} />
      </div>
    ),
  });
  const router = createRouter({ routeTree: rootRoute, history: createMemoryHistory() });
  render(<RouterProvider router={router} />);
  return screen.findByTestId('page');
}

describe('invocation list', () => {
  it.each([
    ['completion_without_start', 'Flagged: completion without start'],
    ['integrity_conflict', 'Flagged: integrity conflict'],
  ] as const)('shows a null-outcome %s row as flagged, never as success', async (lifecycle, label) => {
    await renderRows([invocation({ lifecycle, ...claimed })]);
    const row = screen.getAllByRole('row')[1];
    expect(within(row).getByText(label)).toBeInTheDocument();
    expect(within(row).queryByText('Success')).not.toBeInTheDocument();
    expect(row).toHaveTextContent(
      'Proxy reported outcome success, delivery sent. Not corroborated.',
    );
  });

  it('shows the outcome of a completed invocation, and links it and its proxy', async () => {
    await renderRows([invocation()]);
    const row = screen.getAllByRole('row')[1];
    expect(within(row).getByText('Success')).toBeInTheDocument();
    expect(row).toHaveTextContent('delivery sent');
    expect(within(row).getByRole('link', { name: 'px-a' })).toHaveAttribute(
      'href',
      '/proxies/px-a',
    );
    expect(
      within(row).getByRole('link', { name: '00000000-0000-4000-8000-000000000401' }),
    ).toHaveAttribute('href', '/proxy-invocations/00000000-0000-4000-8000-000000000401');
  });

  it('renders upstream strings as text and has no control', async () => {
    await renderRows([invocation({ method: '<img src=x onerror=alert(1)>', flags: ['new_flag'] })]);
    expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeInTheDocument();
    expect(screen.getByText('new_flag')).toBeInTheDocument();
    expect(document.querySelector('img')).toBeNull();
    expect(screen.queryAllByRole('button')).toHaveLength(0);
  });

  it('never reads a lifecycle from a newer server as success', () => {
    const status = invocationStatus(invocation({ lifecycle: 'unknown', outcome: 'success' }));
    expect(status.label).toBe('Unknown (newer server)');
    expect(status.tone).not.toBe('ok');
  });
});
