import '@testing-library/jest-dom/vitest';
import {
  createMemoryHistory,
  createRootRoute,
  createRouter,
  RouterProvider,
} from '@tanstack/react-router';
import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import { NotAssessedNotice } from './RiskTable';

afterEach(cleanup);

async function renderNotice(count: number | undefined, link = true) {
  const rootRoute = createRootRoute({
    component: () => (
      <div data-testid="page">
        <NotAssessedNotice count={count} link={link} />
      </div>
    ),
  });
  const router = createRouter({ routeTree: rootRoute, history: createMemoryHistory() });
  render(<RouterProvider router={router} />);
  return screen.findByTestId('page');
}

describe('not-assessed notice on the Risk tab', () => {
  it('counts the hosts and links to them in Devices', async () => {
    await renderNotice(3);
    expect(screen.getByRole('status')).toHaveTextContent(
      '3 hosts are not assessed. They have failing AI Guard sources and no score, so this table leaves them out. Show in Devices',
    );
    expect(screen.getByRole('link', { name: 'Show in Devices' })).toHaveAttribute(
      'href',
      '/fleet/devices?notAssessed=true',
    );
  });

  it('uses the singular for one host', async () => {
    await renderNotice(1);
    expect(screen.getByRole('status')).toHaveTextContent(
      '1 host is not assessed. It has failing AI Guard sources and no score, so this table leaves it out.',
    );
  });

  it('leaves out the link when asked', async () => {
    await renderNotice(2, false);
    expect(screen.getByRole('status')).toHaveTextContent(
      /^2 hosts are not assessed\. .* leaves them out\.$/,
    );
    expect(screen.queryByRole('link')).toBeNull();
  });

  // 0: no such host. undefined: a server that predates the count.
  it.each([0, undefined])('shows nothing for %s', async (count) => {
    const page = await renderNotice(count);
    expect(page).toBeEmptyDOMElement();
  });
});
