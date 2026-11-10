import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { certificateRefused } from '@/lib/server-status';
import { Downloads } from './Downloads';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

/** The console's answer to the index request: `status` and `body` as JSON. */
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

const consoleError = (code: string) => ({ error: { code, message: 'from the console' } });

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <Downloads />
    </QueryClientProvider>,
  );
}

describe('Downloads page', () => {
  it('says it is loading until the list arrives', () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => new Promise(() => {})),
    );
    renderPage();
    expect(screen.getByRole('status')).toHaveTextContent('Loading the file list');
  });

  it('links each file to the console route that streams it', async () => {
    const fetch = serve(200, { artifacts: ['SHA256SUMS', 'lodeline-0.14.2-x.tar.gz'] });
    renderPage();
    const sums = await screen.findByRole('link', { name: 'SHA256SUMS' });
    expect(sums).toHaveAttribute('href', '/api/v1/fleet/artifacts/SHA256SUMS');
    expect(sums).toHaveAttribute('download', 'SHA256SUMS');
    expect(screen.getByRole('link', { name: 'lodeline-0.14.2-x.tar.gz' })).toHaveAttribute(
      'href',
      '/api/v1/fleet/artifacts/lodeline-0.14.2-x.tar.gz',
    );
    expect(fetch).toHaveBeenCalledWith('/api/v1/fleet/artifacts', expect.anything());
    expect(screen.getByText(/It does not check the files\./)).toBeInTheDocument();
  });

  it('says so when the folder is empty', async () => {
    serve(200, { artifacts: [] });
    renderPage();
    const status = await screen.findByText(/holds no files/);
    expect(status).toHaveAttribute('role', 'status');
    expect(status).toHaveTextContent('The artifacts_dir of lodeline-server holds no files.');
    expect(screen.queryByRole('link')).toBeNull();
  });

  it('tells the operator what to set when the server has no artifacts_dir', async () => {
    serve(502, consoleError('artifacts_not_configured'));
    renderPage();
    const status = await screen.findByText(/does not serve release files/);
    expect(status).toHaveAttribute('role', 'status');
    expect(status).toHaveTextContent('sets artifacts_dir in server.yaml');
    expect(status).toHaveTextContent('See section 5.1 of docs/install-server.md.');
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it.each([
    ['certificate_refused', 502, certificateRefused],
    ['read_api_disabled', 502, 'Read API disabled.'],
    ['upstream_unauthorized', 502, 'Read API token rejected.'],
    ['service_unavailable', 503, 'Rebuilding index (503).'],
    ['upstream_error', 502, 'Read API unavailable.'],
  ])('names a failed read (%s)', async (code, status, text) => {
    serve(status, consoleError(code));
    renderPage();
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Could not load the file list.');
    expect(alert).toHaveTextContent(text);
    expect(screen.queryByRole('link')).toBeNull();
  });
});
