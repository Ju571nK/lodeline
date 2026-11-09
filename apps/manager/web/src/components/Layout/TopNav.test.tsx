import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  createMemoryHistory,
  createRootRoute,
  createRouter,
  RouterProvider,
} from '@tanstack/react-router';
import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import { TopNav } from './TopNav';

afterEach(cleanup);

async function proxiesLinkAt(path: string) {
  const rootRoute = createRootRoute({ component: TopNav });
  const router = createRouter({
    routeTree: rootRoute,
    history: createMemoryHistory({ initialEntries: [path] }),
  });
  // No fetch: the nav's health and meta queries stay idle.
  const client = new QueryClient({ defaultOptions: { queries: { enabled: false } } });
  render(
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return screen.findByRole('link', { name: 'Proxies' });
}

describe('top nav', () => {
  it.each([
    '/proxies',
    '/proxies/px-a',
    '/proxy-invocations',
    '/proxy-invocations/00000000-0000-4000-8000-000000000401',
  ])('marks Proxies as the current section on %s', async (path) => {
    expect(await proxiesLinkAt(path)).toHaveAttribute('aria-current', 'page');
  });

  it.each(['/fleet', '/alerts', '/proxies-old'])('leaves Proxies inactive on %s', async (path) => {
    expect(await proxiesLinkAt(path)).not.toHaveAttribute('aria-current');
  });
});
