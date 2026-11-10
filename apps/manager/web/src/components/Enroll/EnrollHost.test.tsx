import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  createMemoryHistory,
  createRootRoute,
  createRouter,
  RouterProvider,
} from '@tanstack/react-router';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EnrollHost } from './EnrollHost';

const HOST = '3f9c1e2a-7b4d-4c8e-9a10-5d6e7f8a9b0c';
const OTHER = '0b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e';
const MARKER = 'MARKER-TOKEN-5c1d9e7a';
const EXPIRES = '2030-05-06T07:08:09Z';

const ready = {
  enabled: true,
  can_enroll: true,
  server_url: 'https://lodeline.example.com:8443',
  enroll_url: 'https://lodeline.example.com:8444',
  ca: [{ subject: 'CN=example-ca', sha256: 'AA:BB:CC' }],
  policy_keys: [
    {
      id: 'key-one',
      sha256: 'DD:EE:FF',
      valid_from: '2020-01-01T00:00:00Z',
      valid_until: '2099-01-01T00:00:00Z',
    },
  ],
};

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const consoleError = (status: number, code: string, message = 'from the console') =>
  json(status, { error: { code, message } });
const fileAnswer = (host: string | null = HOST, expires: string | null = EXPIRES) => {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-Test-File': '1',
  };
  if (host) headers['X-Lodeline-Enroll-Host-Id'] = host;
  if (expires) headers['X-Lodeline-Enroll-Expires-At'] = expires;
  return new Response(JSON.stringify({ token: MARKER }), { status: 200, headers });
};
const withZone = (iso: string) =>
  new Date(iso).toLocaleString(undefined, { timeZoneName: 'short' });
const isFileAnswer = (r: unknown) => (r as Response).headers.get('X-Test-File') !== null;

type Route = () => Response | Promise<Response>;

/** Stubs fetch by method and path. `post` answers `POST /api/v1/enrollment/files`. */
function serve(opts: { status?: Route; post?: Route; me?: Route }) {
  const fetch = vi.fn(async (url: string, init?: RequestInit) => {
    if (init?.method === 'POST') return (opts.post ?? (() => fileAnswer()))();
    if (url.endsWith('/auth/me')) return (opts.me ?? (() => json(200, { username: 'alice' })))();
    return (opts.status ?? (() => json(200, ready)))();
  });
  vi.stubGlobal('fetch', fetch);
  return fetch;
}
const posts = (fetch: ReturnType<typeof serve>) =>
  fetch.mock.calls.filter(([, init]) => init?.method === 'POST');

let client: QueryClient;
let revoked: string[];
let saved: { href: string; name: string; blob: Blob }[];

beforeEach(() => {
  revoked = [];
  saved = [];
  const blobs = new Map<string, Blob>();
  vi.stubGlobal('URL', {
    createObjectURL: vi.fn((b: Blob) => {
      const u = `blob:test/${blobs.size}`;
      blobs.set(u, b);
      return u;
    }),
    revokeObjectURL: vi.fn((u: string) => revoked.push(u)),
  });
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
    this: HTMLAnchorElement,
  ) {
    saved.push({ href: this.href, name: this.download, blob: blobs.get(this.href) as Blob });
  });
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

async function renderPage() {
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const router = createRouter({
    routeTree: createRootRoute({ component: EnrollHost }),
    history: createMemoryHistory({ initialEntries: ['/'] }),
  });
  render(
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  await screen.findByRole('heading', { level: 1 });
}
const button = () => screen.findByRole('button', { name: 'Make an enrollment file' });
const hostInput = () => screen.findByLabelText(/Host id/);

describe('Enroll a host page: states', () => {
  it('says it is loading until the settings arrive', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => new Promise(() => {})),
    );
    await renderPage();
    expect(screen.getByRole('status')).toHaveTextContent('Loading the enrollment settings');
  });

  it('names the missing variables and has no button when the console is off', async () => {
    serve({
      status: () =>
        json(200, {
          enabled: false,
          missing: ['LODELINE_PUBLIC_ORIGIN', 'LODELINE_ENROLL_MINT_TOKEN'],
        }),
    });
    await renderPage();
    const status = await screen.findByRole('status');
    expect(status).toHaveTextContent('LODELINE_PUBLIC_ORIGIN, LODELINE_ENROLL_MINT_TOKEN');
    expect(status).toHaveTextContent('Enroll a host section of the console');
    expect(screen.queryByRole('button')).toBeNull();
  });

  it('shows the signed-in subject and no button when it is not on the enroll list', async () => {
    serve({
      status: () => json(200, { ...ready, can_enroll: false }),
      me: () => json(200, { username: 'oidc:abc123' }),
    });
    await renderPage();
    const status = await screen.findByText(/is not on the enroll list/);
    await waitFor(() => expect(status).toHaveTextContent('oidc:abc123'));
    expect(screen.queryByRole('button')).toBeNull();
  });

  it('shows one h1, the table of what the file holds, the labelled input and the button', async () => {
    serve({});
    await renderPage();
    await button();
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
    const table = screen.getByRole('table');
    for (const text of [
      'https://lodeline.example.com:8443',
      'https://lodeline.example.com:8444',
      'CN=example-ca',
      'AA:BB:CC',
      'key-one',
      'DD:EE:FF',
    ]) {
      expect(within(table).getByText(new RegExp(text))).toBeInTheDocument();
    }
    expect(screen.getByText(/It holds no private key/)).toBeInTheDocument();
    expect(await hostInput()).toHaveAccessibleDescription(/sudo lodeline show host-id/);
  });

  it('names a settings error the console reports on the read', async () => {
    serve({
      status: () =>
        consoleError(500, 'enroll_misconfigured', 'LODELINE_ENROLL_FILE_CA_PATH: is not valid PEM'),
    });
    await renderPage();
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('LODELINE_ENROLL_FILE_CA_PATH: is not valid PEM');
    expect(screen.queryByRole('button')).toBeNull();
  });
});

describe('Enroll a host page: the click', () => {
  it('makes one request for a double click, even before the button is disabled', async () => {
    const fetch = serve({});
    await renderPage();
    const b = await button();
    act(() => {
      b.click();
      b.click();
    });
    await screen.findByText(/Valid until/);
    expect(posts(fetch)).toHaveLength(1);
  });

  it('disables the button and changes its label while the request is pending', async () => {
    let release: (r: Response) => void = () => {};
    const fetch = serve({ post: () => new Promise<Response>((r) => (release = r)) });
    await renderPage();
    fireEvent.click(await button());
    const pending = await screen.findByRole('button', { name: 'Making the file…' });
    expect(pending).toBeDisabled();
    fireEvent.click(pending);
    expect(posts(fetch)).toHaveLength(1);
    release(fileAnswer());
    expect(await button()).toBeEnabled();
  });

  it('moves the focus to the success box when the file was made', async () => {
    serve({});
    await renderPage();
    fireEvent.click(await button());
    const done = await screen.findByRole('status', { name: 'The file was made' });
    await waitFor(() => expect(document.activeElement).toBe(done));
    expect(done).toHaveAttribute('tabindex', '-1');
  });

  it('moves the focus to the error box when the answer is an error', async () => {
    serve({ post: () => consoleError(409, 'host_exists') });
    await renderPage();
    fireEvent.click(await button());
    const alert = await screen.findByRole('alert');
    await waitFor(() => expect(document.activeElement).toBe(alert));
    expect(alert).toHaveAttribute('tabindex', '-1');
  });

  it('makes one file for Enter in the host id field, and none while one is pending', async () => {
    let release: (r: Response) => void = () => {};
    const fetch = serve({ post: () => new Promise<Response>((r) => (release = r)) });
    await renderPage();
    const form = (await hostInput()).closest('form') as HTMLFormElement;
    expect(form).not.toBeNull();
    fireEvent.submit(form);
    await screen.findByRole('button', { name: 'Making the file…' });
    fireEvent.submit(form);
    expect(posts(fetch)).toHaveLength(1);
    release(fileAnswer());
    await screen.findByText(/Valid until/);
    expect(posts(fetch)).toHaveLength(1);
  });

  it('sends {} without a host id and the given one, trimmed, with it', async () => {
    const fetch = serve({});
    await renderPage();
    fireEvent.click(await button());
    await screen.findByText(/Valid until/);
    expect(posts(fetch)[0]?.[1]?.body).toBe('{}');
    fireEvent.change(await hostInput(), { target: { value: `  ${OTHER}\n` } });
    fireEvent.click(await button());
    await waitFor(() => expect(posts(fetch)).toHaveLength(2));
    expect(posts(fetch)[1]?.[1]?.body).toBe(JSON.stringify({ host_id: OTHER }));
    expect(posts(fetch)[1]?.[0]).toBe('/api/v1/enrollment/files');
  });

  it.each([
    'not-a-uuid',
    HOST.toUpperCase(),
    HOST.replace('-4c8e-', '-1c8e-'),
    HOST.replace('-9a10-', '-ca10-'),
    HOST.replaceAll('-', ''),
  ])('sends nothing for the host id %s', async (bad) => {
    const fetch = serve({});
    await renderPage();
    fireEvent.change(await hostInput(), { target: { value: bad } });
    fireEvent.click(await button());
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'not a lower-case, hyphenated version 4 UUID',
    );
    expect(posts(fetch)).toHaveLength(0);
  });

  it('takes the file name and the host id shown from the answer headers', async () => {
    serve({ post: () => fileAnswer(OTHER) });
    await renderPage();
    fireEvent.click(await button());
    const done = await screen.findByRole('status', { name: 'The file was made' });
    expect(saved).toHaveLength(1);
    expect(saved[0]?.name).toBe(`lodeline-enroll-${OTHER}.json`);
    expect(done).toHaveTextContent(`Your browser was given lodeline-enroll-${OTHER}.json to save.`);
    expect(done).not.toHaveTextContent('The browser saved');
    expect(done).toHaveTextContent(`Host id: ${OTHER}`);
    expect(done).toHaveTextContent(`sudo lodeline-sender enroll lodeline-enroll-${OTHER}.json`);
    expect(done).toHaveTextContent(`Valid until ${withZone(EXPIRES)}`);
    expect(withZone(EXPIRES)).not.toBe(new Date(EXPIRES).toLocaleString());
  });

  it('says that the file is a secret, works once and was not kept, and gives the steps', async () => {
    serve({});
    await renderPage();
    fireEvent.click(await button());
    const done = await screen.findByRole('status', { name: 'The file was made' });
    expect(done).toHaveTextContent(
      'This file is a secret until the host uses it or it expires. It works once. The console did not keep a copy.',
    );
    const steps = within(done)
      .getAllByRole('listitem')
      .map((li) => li.textContent);
    expect(steps[0]).toContain('mode 0600');
    expect(steps[1]).toContain('lodeline-sender');
    expect(within(done).getByRole('link', { name: 'Downloads' })).toHaveAttribute(
      'href',
      '/downloads',
    );
    expect(steps[2]).toContain('fingerprints before it writes anything');
    expect(steps[3]).toContain('sudo systemctl enable --now lodeline lodeline-sender');
    expect(done).toHaveTextContent('On macOS, enroll needs its path flags');
    expect(done).toHaveTextContent('Windows is not supported yet');
  });

  it('gives the three recovery texts after a file was made', async () => {
    serve({});
    await renderPage();
    fireEvent.click(await button());
    const done = await screen.findByRole('status', { name: 'The file was made' });
    expect(done).toHaveTextContent('paste its output into the host id field');
    expect(done).toHaveTextContent(
      'If a later try on this page says that the host id already exists on the server, the console cannot help: run lodeline-server enroll-token on the server',
    );
    expect(done).toHaveTextContent(
      'If it says that a file for this host id is still valid, use that file, wait until it expires, or run lodeline-server enroll-token',
    );
    expect(done).not.toHaveTextContent('If the answer is');
    expect(done).toHaveTextContent('run sudo lodeline show host-id on the host');
  });

  it('revokes the object URL it made', async () => {
    serve({});
    await renderPage();
    fireEvent.click(await button());
    await screen.findByText(/Valid until/);
    expect(saved).toHaveLength(1);
    expect(revoked).toEqual([saved[0]?.href]);
  });

  it('hands the answer bytes to the download, and keeps the token out of everything else', async () => {
    const json = vi.spyOn(Response.prototype, 'json');
    const text = vi.spyOn(Response.prototype, 'text');
    const setItem = vi.spyOn(Storage.prototype, 'setItem');
    const logs = (['log', 'info', 'warn', 'error', 'debug'] as const).map((k) =>
      vi.spyOn(console, k).mockImplementation(() => {}),
    );
    serve({});
    await renderPage();
    fireEvent.click(await button());
    await screen.findByText(/Valid until/);

    expect(await saved[0]?.blob.text()).toContain(MARKER);
    // the status read is a GET and may parse its own answer; the file answer is never parsed
    expect(json.mock.contexts.filter(isFileAnswer)).toHaveLength(0);
    expect(text.mock.contexts.filter(isFileAnswer)).toHaveLength(0);
    expect(JSON.stringify(logs.map((l) => l.mock.calls))).not.toContain(MARKER);
    expect(document.documentElement.innerHTML).not.toContain(MARKER);
    expect(setItem).not.toHaveBeenCalled();
    expect(JSON.stringify({ ...localStorage })).not.toContain(MARKER);
    expect(JSON.stringify({ ...sessionStorage })).not.toContain(MARKER);
    expect(window.location.href).not.toContain(MARKER);
    const cached = JSON.stringify([
      client
        .getQueryCache()
        .getAll()
        .map((q) => q.state),
      client
        .getMutationCache()
        .getAll()
        .map((m) => ({ data: m.state.data, vars: m.state.variables, err: m.state.error })),
    ]);
    expect(cached).not.toContain(MARKER);
    expect(cached).toContain(HOST);
  });
});

describe('Enroll a host page: errors', () => {
  const stopped = 'paste its output';
  it.each([
    ['not_an_enroller', 403, 'not on the enroll list'],
    ['origin_not_allowed', 403, 'address in LODELINE_PUBLIC_ORIGIN'],
    ['invalid_host_id', 422, 'not a lower-case, hyphenated version 4 UUID'],
    ['invalid_request', 400, 'did not accept the request'],
    ['host_exists', 409, 'cannot make a file for it'],
    ['token_outstanding', 409, 'A file for this host id is still valid'],
    ['enrollment_limit_reached', 429, 'enroll_mint.max_tokens'],
    ['enroll_unavailable', 502, 'section 3.6 of docs/install-server.md'],
    ['enroll_refused', 502, 'refused this console'],
    ['enroll_failed', 502, 'may have made a token'],
    ['enroll_misconfigured', 500, 'LODELINE_ENROLL_FILE_CA_PATH is missing'],
    ['enrollment_not_configured', 404, 'not configured on this console'],
    ['unsupported_media_type', 415, 'did not accept the request'],
    ['body_too_large', 413, 'did not accept the request'],
    ['request_timeout', 408, 'took too long'],
    ['internal', 500, 'could not make a host id'],
    ['unauthorized', 401, 'Your session ended'],
    ['session_expired', 401, 'Your session ended'],
    ['something_new', 500, 'answered an error (something_new)'],
  ])('shows one alert for %s', async (code, status, text) => {
    serve({ post: () => consoleError(status, code, 'LODELINE_ENROLL_FILE_CA_PATH is missing') });
    await renderPage();
    fireEvent.click(await button());
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(text);
    expect(screen.getAllByRole('alert')).toHaveLength(1);
    expect(saved).toHaveLength(0);
    expect(await button()).toBeEnabled();
  });

  it.each([
    ['host_exists', 'lodeline-server enroll-token'],
    ['token_outstanding', 'lodeline-server enroll-token'],
    ['enroll_failed', 'lodeline-server enroll-token'],
  ])('%s points to the server command and never says only "make another"', async (code, text) => {
    serve({ post: () => consoleError(409, code) });
    await renderPage();
    fireEvent.click(await button());
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(text);
    expect(alert).not.toHaveTextContent(/make another/i);
  });

  it('names a lost connection as a possible lost token', async () => {
    const fetch = serve({});
    await renderPage();
    fetch.mockImplementation(async (_u: string, init?: RequestInit) => {
      if (init?.method === 'POST') throw new TypeError('network down');
      return json(200, ready);
    });
    fireEvent.click(await button());
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'A token may have been made and lost',
    );
  });

  it.each([
    ['both headers', () => fileAnswer(null, null)],
    ['a host id that is not a v4 id', () => fileAnswer(HOST.toUpperCase(), null)],
  ])('saves a 200 that lacks %s under the general name and says what is missing', async (_n, post) => {
    const json = vi.spyOn(Response.prototype, 'json');
    const text = vi.spyOn(Response.prototype, 'text');
    const logs = (['log', 'info', 'warn', 'error', 'debug'] as const).map((k) =>
      vi.spyOn(console, k).mockImplementation(() => {}),
    );
    serve({ post });
    await renderPage();
    fireEvent.click(await button());
    const done = await screen.findByRole('status', { name: 'The file was made' });
    expect(screen.queryByRole('alert')).toBeNull();
    expect(saved).toHaveLength(1);
    expect(saved[0]?.name).toBe('lodeline-enroll.json');
    expect(await saved[0]?.blob.text()).toContain(MARKER);
    expect(done).toHaveTextContent('Your browser was given lodeline-enroll.json to save.');
    expect(done).toHaveTextContent('The answer did not carry the host id and the expiry.');
    expect(done).toHaveTextContent('X-Lodeline-Enroll-Host-Id and X-Lodeline-Enroll-Expires-At');
    expect(done).toHaveTextContent('host_id and expires_at fields of the saved file');
    expect(done).not.toHaveTextContent('Valid until');
    expect(done).not.toHaveTextContent('Host id:');
    expect(done).toHaveTextContent('sudo lodeline-sender enroll lodeline-enroll.json');
    expect(json.mock.contexts.filter(isFileAnswer)).toHaveLength(0);
    expect(text.mock.contexts.filter(isFileAnswer)).toHaveLength(0);
    expect(JSON.stringify(logs.map((l) => l.mock.calls))).not.toContain(MARKER);
    expect(document.documentElement.innerHTML).not.toContain(MARKER);
    expect(JSON.stringify({ ...localStorage, ...sessionStorage })).not.toContain(MARKER);
    const cached = JSON.stringify(
      client
        .getMutationCache()
        .getAll()
        .map((m) => ({ data: m.state.data, vars: m.state.variables })),
    );
    expect(cached).not.toContain(MARKER);
  });

  it('shows the host id and names the expiry when only the expiry header is missing', async () => {
    serve({ post: () => fileAnswer(OTHER, null) });
    await renderPage();
    fireEvent.click(await button());
    const done = await screen.findByRole('status', { name: 'The file was made' });
    expect(saved).toHaveLength(1);
    expect(saved[0]?.name).toBe(`lodeline-enroll-${OTHER}.json`);
    expect(done).toHaveTextContent(`Host id: ${OTHER}`);
    expect(done).toHaveTextContent('The answer did not carry the expiry.');
    expect(done).not.toHaveTextContent('Valid until');
  });

  it('shows the expiry and names the host id when only the host id header is missing', async () => {
    serve({ post: () => fileAnswer(null, EXPIRES) });
    await renderPage();
    fireEvent.click(await button());
    const done = await screen.findByRole('status', { name: 'The file was made' });
    expect(saved[0]?.name).toBe('lodeline-enroll.json');
    expect(done).toHaveTextContent(`Valid until ${withZone(EXPIRES)}`);
    expect(done).toHaveTextContent('The answer did not carry the host id.');
    expect(done).not.toHaveTextContent('Host id:');
  });

  it('keeps the recovery text of the host id field', async () => {
    serve({});
    await renderPage();
    expect(await hostInput()).toHaveAccessibleDescription(new RegExp(stopped));
  });
});
