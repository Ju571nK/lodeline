import { cleanup, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import { ApiError } from '@/api/client';
import { ProxyReadError } from './ProxyParts';

afterEach(cleanup);

const unavailable = new ApiError(502, 'proxy_reads_unavailable', 'proxy reads are not available');

describe('ProxyReadError when the server has no proxy section', () => {
  it.each([
    'proxy',
    'invocation',
  ] as const)('keeps the sentence and adds a numbered setup guide for the %s pages', (target) => {
    render(<ProxyReadError error={unavailable} what="proxies" target={target} />);
    const box = screen.getByRole('alert');
    expect(box).toHaveTextContent(
      'Proxy reads are not available on this lodeline-server. It runs without a proxy section.',
    );
    expect(within(box).getByRole('list').tagName).toBe('OL');
    expect(box).toHaveTextContent('proxy: section');
    expect(box).toHaveTextContent('Restart the console');
    const env = within(box).getByText(/^LODELINE_SERVER_BASE_URL=/);
    expect(env.textContent).toContain('LODELINE_SERVER_CLIENT_CERT_PATH=');
    expect(env.textContent).toContain('LODELINE_SERVER_CLIENT_KEY_PATH=');
    expect(env.textContent).toContain('LODELINE_SERVER_READ_TOKEN=');
    expect(within(box).getByRole('link', { name: /Proxy reads/ })).toHaveAttribute(
      'href',
      'https://github.com/Ju571nK/lodeline/blob/main/apps/manager/README.md#proxy-reads',
    );
    expect(within(box).getByRole('button', { name: 'Copy console variables' })).toBeVisible();
  });

  it('leaves the inventory sentence as it is, because that server only predates the routes', () => {
    render(<ProxyReadError error={unavailable} what="inventory" target="inventory" />);
    const box = screen.getByRole('alert');
    expect(box).toHaveTextContent(
      'Inventory reads are not available on this lodeline-server. It predates them.',
    );
    expect(screen.queryByRole('list')).toBeNull();
  });

  it('adds no guide to other failures', () => {
    render(<ProxyReadError error={new ApiError(500, 'internal', 'boom')} what="proxies" />);
    expect(screen.getByRole('alert')).toHaveTextContent('Could not load proxies: boom');
    expect(screen.queryByRole('list')).toBeNull();
  });
});
