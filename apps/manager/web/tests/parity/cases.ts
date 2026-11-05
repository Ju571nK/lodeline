/**
 * The parity table. Rows run top to bottom against one server process, so
 * the triage rows are a sequence: later rows see the writes of earlier ones.
 *
 * Path placeholders, filled from the run before the request is sent:
 *   {event:N}   mock event ID for recipe index N (EVT#N in goldens)
 *   {seed-6h}   mock seed shifted back by hours (h) or minutes (m), as RFC3339 seconds
 *   {asset:js}  the entry script that dist/index.html references
 *   {asset:css} the stylesheet that dist/index.html references
 */

/** Every route in the Go router at e4fb077: 18 API routes plus the SPA catch-all. */
export const ROUTES = [
  'GET /api/health',
  'POST /api/v1/auth/login',
  'GET /api/v1/auth/methods',
  'GET /api/v1/auth/oidc/start',
  'GET /api/v1/auth/oidc/callback',
  'POST /api/v1/auth/logout',
  'GET /api/v1/auth/me',
  'GET /api/v1/fleet/meta',
  'GET /api/v1/fleet/healthz',
  'GET /api/v1/fleet/events',
  'GET /api/v1/fleet/events/{event_id}',
  'GET /api/v1/fleet/risk',
  'GET /api/v1/fleet/compliance',
  'GET /api/v1/fleet/hosts',
  'GET /api/v1/fleet/hosts/{host_id}',
  'POST /api/v1/triage/upsert',
  'POST /api/v1/triage/note',
  'GET /api/v1/triage/{host_id}/{event_id}',
  'GET /*',
] as const;

export type Route = (typeof ROUTES)[number];

/** Routes that have no success case here, and why. */
export const NO_SUCCESS_CASE: Partial<Record<Route, string>> = {
  'GET /api/v1/auth/oidc/start':
    'needs an HTTPS OIDC provider; the Rust port carries over the Go OIDC unit tests instead',
  'GET /api/v1/auth/oidc/callback':
    'needs an HTTPS OIDC provider; the Rust port carries over the Go OIDC unit tests instead',
};

/** Session cookie a case sends. Crafted forms are signed by the recorder with the test secret. */
export type Auth =
  | 'session'
  | 'none'
  | 'empty'
  | 'garbage'
  | 'expired'
  | 'expired-wrong-issuer'
  | 'tampered-payload'
  | 'wrong-key'
  | 'alg-none'
  | 'alg-hs512'
  | 'wrong-issuer'
  | 'empty-subject'
  | 'not-yet-valid'
  | 'recorder-minted'
  | 'no-exp'
  | 'expired-5s'
  | 'not-yet-valid-5s'
  | 'issued-in-5s'
  | 'other-subject'
  | 'fractional-exp'
  | 'with-audience';

/** What the stub upstream answers for the next request from the live-mode manager. */
export interface UpstreamReply {
  status: number;
  headers?: Record<string, string>;
  json?: unknown;
  text?: string;
  /** Wait this long before answering. */
  delayMs?: number;
  /** Close the connection after the request instead of answering. */
  close?: boolean;
}

export interface Case {
  name: string;
  route: Route;
  /** `ok` cases succeed; `error` cases exercise a failure path of the same route. */
  outcome: 'ok' | 'error';
  method: string;
  path: string;
  /**
   * `live` talks to the manager wired to the stub upstream instead of the mock fleet, `down` to
   * one whose upstream port has no listener.
   */
  server?: 'mock' | 'live' | 'down';
  auth?: Auth;
  /** Cookie header lines, each holding one `lodeline_session` pair per entry; replaces `auth`. */
  cookies?: Auth[][];
  headers?: Record<string, string>;
  /** Sent as JSON with `Content-Type: application/json`. */
  json?: unknown;
  /** Sent verbatim, with a `Content-Type` header only when `headers` names one. */
  raw?: string;
  upstream?: UpstreamReply;
  /** Requests sent first and not recorded, for example to fill a rate-limit window. */
  prelude?: PreludeStep[];
  /**
   * Send no `X-Forwarded-For` unless the request names one, so the limiter counts the request
   * for the recorder's own 127.0.0.1. Without it, a request that names none gets the case's own
   * client address (see `send` in run.parity.ts).
   */
  direct?: boolean;
  /** The response must take at least, or at most, this long. */
  minMs?: number;
  maxMs?: number;
  /** The body is a directory listing; see recordListing in run.parity.ts. */
  listing?: boolean;
  /**
   * Dot paths into the JSON body whose text is also recorded as the server spelled it, for raw
   * JSON that the server passes through and the parsed comparison cannot see.
   */
  rawText?: string[];
}

/** `count` requests (default 1) with the case's auth; each must answer `status`. */
export interface PreludeStep {
  count?: number;
  status: number;
  method?: string;
  path?: string;
  headers?: Record<string, string>;
  raw?: string;
}

const H_ALICE = '5a7c3e91-aaaa-bbbb-cccc-111111111111';
const H_BOB = '5a7c3e91-aaaa-bbbb-cccc-222222222222';
const H_DAVE = '5a7c3e91-aaaa-bbbb-cccc-444444444444';
const H_MISSING = '5a7c3e91-aaaa-bbbb-cccc-999999999999';
const EVT_MISSING = '00000000-0000-7000-8000-000000000000';
const SNAPSHOT = { kind: 'ai_guard_risk_assessed', tool: 'claude_code', score: 7.2 };

const LIVE_TS = '2026-01-02T03:04:05Z';
const LIVE_EVENT_ID = '01900000-0000-7000-8000-000000000001';
const LIVE_EVENT = {
  schema_version: 1,
  event_id: LIVE_EVENT_ID,
  ts: LIVE_TS,
  host_id: H_ALICE,
  agent_version: '0.12.4',
  severity: 'warn',
  source: { kind: 'file_system' },
  subject: { kind: 'path', path: '/home/user/.claude/settings.json' },
  evidence: { kind: 'future_variant', payload: { nested: [1, 2, 3] } },
  target_id: null,
  added_later: 'kept or dropped',
};
const LIVE_ALERTS = {
  evidence_kinds: ['ai_guard_risk_assessed'],
  ai_guard_buckets: ['high', 'critical'],
  additional_kinds: [],
};

/** One `<route> without a session` row per authenticated route. */
function noSession(route: Route, method: string, path: string, name: string): Case {
  return { name, route, outcome: 'error', method, path, auth: 'none' };
}

function sessionForm(auth: Auth): Case {
  return {
    name: `session-${auth}`,
    route: 'GET /api/v1/auth/me',
    outcome: auth === 'recorder-minted' ? 'ok' : 'error',
    method: 'GET',
    path: '/api/v1/auth/me',
    auth,
  };
}

/** Ten attempts that the limiter lets through, then one it refuses. */
function limited(
  name: string,
  headers: Record<string, string>,
  prelude: PreludeStep[] = [{ count: 10, status: 400, headers }],
): Case {
  return {
    name,
    route: 'POST /api/v1/auth/login',
    outcome: 'error',
    method: 'POST',
    path: '/api/v1/auth/login',
    auth: 'none',
    headers,
    raw: '{',
    prelude: prelude.map((p) => ({ raw: '{', ...p })),
  };
}

/** A login or note body sent verbatim with the given Content-Type. */
function body(
  name: string,
  route: 'POST /api/v1/auth/login' | 'POST /api/v1/triage/note',
  raw: string,
  outcome: 'ok' | 'error',
  contentType = 'application/json',
): Case {
  return {
    name,
    route,
    outcome,
    method: 'POST',
    path: route.slice(5),
    ...(route === 'POST /api/v1/auth/login' ? { auth: 'none' as const } : {}),
    headers: { 'Content-Type': contentType },
    raw,
  };
}

/** A mock-mode events query whose `since` the Go parser accepts or rejects. */
function since(name: string, value: string, outcome: 'ok' | 'error'): Case {
  return {
    name: `fleet-events-since-${name}`,
    route: 'GET /api/v1/fleet/events',
    outcome,
    method: 'GET',
    path: `/api/v1/fleet/events?limit=1&since=${value}`,
  };
}

function cookieCase(name: string, cookies: Auth[][], outcome: 'ok' | 'error'): Case {
  return {
    name,
    route: 'GET /api/v1/auth/me',
    outcome,
    method: 'GET',
    path: '/api/v1/auth/me',
    cookies,
  };
}

function upstream(
  name: string,
  route: Route,
  path: string,
  reply: UpstreamReply,
  outcome: 'ok' | 'error' = 'error',
): Case {
  return { name, route, outcome, method: 'GET', path, server: 'live', upstream: reply };
}

export const CASES: Case[] = [
  // Health and SPA.
  { name: 'health', route: 'GET /api/health', outcome: 'ok', method: 'GET', path: '/api/health' },
  {
    name: 'health-wrong-method',
    route: 'GET /api/health',
    outcome: 'error',
    method: 'POST',
    path: '/api/health',
  },
  // chi registers GET alone, so HEAD gets 405 too.
  {
    name: 'health-head',
    route: 'GET /api/health',
    outcome: 'error',
    method: 'HEAD',
    path: '/api/health',
  },
  { name: 'spa-root', route: 'GET /*', outcome: 'ok', method: 'GET', path: '/' },
  { name: 'spa-deep-link', route: 'GET /*', outcome: 'ok', method: 'GET', path: '/alerts/abc' },
  { name: 'spa-asset', route: 'GET /*', outcome: 'ok', method: 'GET', path: '{asset:js}' },
  { name: 'spa-favicon', route: 'GET /*', outcome: 'ok', method: 'GET', path: '/favicon.svg' },
  { name: 'spa-index-html', route: 'GET /*', outcome: 'ok', method: 'GET', path: '/index.html' },
  {
    name: 'spa-assets-dir',
    route: 'GET /*',
    outcome: 'ok',
    method: 'GET',
    path: '/assets/',
    listing: true,
  },
  { name: 'spa-assets-no-slash', route: 'GET /*', outcome: 'ok', method: 'GET', path: '/assets' },
  { name: 'spa-head-root', route: 'GET /*', outcome: 'ok', method: 'HEAD', path: '/' },
  { name: 'spa-head-asset', route: 'GET /*', outcome: 'ok', method: 'HEAD', path: '{asset:js}' },
  { name: 'spa-asset-css', route: 'GET /*', outcome: 'ok', method: 'GET', path: '{asset:css}' },
  {
    name: 'spa-head-asset-css',
    route: 'GET /*',
    outcome: 'ok',
    method: 'HEAD',
    path: '{asset:css}',
  },
  {
    name: 'spa-head-deep-link',
    route: 'GET /*',
    outcome: 'ok',
    method: 'HEAD',
    path: '/alerts/abc',
  },
  {
    name: 'spa-asset-range',
    route: 'GET /*',
    outcome: 'ok',
    method: 'GET',
    path: '{asset:js}',
    headers: { Range: 'bytes=0-99' },
  },
  {
    name: 'spa-dot-segment',
    route: 'GET /*',
    outcome: 'ok',
    method: 'GET',
    path: '/assets/../favicon.svg',
  },
  { name: 'spa-double-slash', route: 'GET /*', outcome: 'ok', method: 'GET', path: '//api/health' },
  {
    name: 'api-trailing-slash',
    route: 'GET /*',
    outcome: 'error',
    method: 'GET',
    path: '/api/v1/fleet/meta/',
  },
  { name: 'spa-post-root', route: 'GET /*', outcome: 'ok', method: 'POST', path: '/' },
  // Go's server refuses a malformed escape before any handler runs.
  { name: 'spa-bad-escape', route: 'GET /*', outcome: 'error', method: 'GET', path: '/%zz' },
  { name: 'spa-unknown-api', route: 'GET /*', outcome: 'error', method: 'GET', path: '/api/x' },
  {
    name: 'spa-unknown-api-v1',
    route: 'GET /*',
    outcome: 'error',
    method: 'GET',
    path: '/api/v1/nope',
  },

  // Auth.
  {
    name: 'auth-methods-oidc-off',
    route: 'GET /api/v1/auth/methods',
    outcome: 'ok',
    method: 'GET',
    path: '/api/v1/auth/methods',
    auth: 'none',
  },
  {
    name: 'auth-methods-wrong-method',
    route: 'GET /api/v1/auth/methods',
    outcome: 'error',
    method: 'POST',
    path: '/api/v1/auth/methods',
    auth: 'none',
  },
  {
    name: 'oidc-start-oidc-off',
    route: 'GET /api/v1/auth/oidc/start',
    outcome: 'error',
    method: 'GET',
    path: '/api/v1/auth/oidc/start',
    auth: 'none',
  },
  {
    name: 'oidc-start-wrong-method',
    route: 'GET /api/v1/auth/oidc/start',
    outcome: 'error',
    method: 'POST',
    path: '/api/v1/auth/oidc/start',
    auth: 'none',
  },
  {
    name: 'oidc-callback-oidc-off',
    route: 'GET /api/v1/auth/oidc/callback',
    outcome: 'error',
    method: 'GET',
    path: '/api/v1/auth/oidc/callback?code=c&state=s',
    auth: 'none',
  },
  {
    name: 'login-ok',
    route: 'POST /api/v1/auth/login',
    outcome: 'ok',
    method: 'POST',
    path: '/api/v1/auth/login',
    auth: 'none',
    json: { username: '{admin}', password: '{password}' },
  },
  {
    name: 'login-wrong-password',
    route: 'POST /api/v1/auth/login',
    outcome: 'error',
    method: 'POST',
    path: '/api/v1/auth/login',
    auth: 'none',
    json: { username: '{admin}', password: 'not-the-password' },
    minMs: 250,
  },
  {
    name: 'login-wrong-username',
    route: 'POST /api/v1/auth/login',
    outcome: 'error',
    method: 'POST',
    path: '/api/v1/auth/login',
    auth: 'none',
    json: { username: 'someone-else', password: '{password}' },
    minMs: 250,
  },
  {
    name: 'login-empty-credentials',
    route: 'POST /api/v1/auth/login',
    outcome: 'error',
    method: 'POST',
    path: '/api/v1/auth/login',
    auth: 'none',
    json: {},
    minMs: 250,
  },
  {
    name: 'login-malformed-json',
    route: 'POST /api/v1/auth/login',
    outcome: 'error',
    method: 'POST',
    path: '/api/v1/auth/login',
    auth: 'none',
    raw: '{"username":',
  },
  {
    name: 'login-no-body',
    route: 'POST /api/v1/auth/login',
    outcome: 'error',
    method: 'POST',
    path: '/api/v1/auth/login',
    auth: 'none',
    raw: '',
  },
  {
    name: 'login-wrong-method',
    route: 'POST /api/v1/auth/login',
    outcome: 'error',
    method: 'GET',
    path: '/api/v1/auth/login',
    auth: 'none',
  },
  {
    name: 'login-trailing-data',
    route: 'POST /api/v1/auth/login',
    outcome: 'ok',
    method: 'POST',
    path: '/api/v1/auth/login',
    auth: 'none',
    headers: { 'Content-Type': 'application/json' },
    raw: '{"username":"{admin}","password":"{password}"} {"username":"x"} trailing',
  },
  {
    name: 'login-key-case',
    route: 'POST /api/v1/auth/login',
    outcome: 'ok',
    method: 'POST',
    path: '/api/v1/auth/login',
    auth: 'none',
    json: { USERNAME: '{admin}', Password: '{password}' },
  },
  {
    name: 'login-options',
    route: 'POST /api/v1/auth/login',
    outcome: 'error',
    method: 'OPTIONS',
    path: '/api/v1/auth/login',
    auth: 'none',
  },
  // chi registers POST alone, so HEAD gets 405 and never reaches the limiter.
  {
    name: 'login-head',
    route: 'POST /api/v1/auth/login',
    outcome: 'error',
    method: 'HEAD',
    path: '/api/v1/auth/login',
    auth: 'none',
  },
  body(
    'login-text-plain',
    'POST /api/v1/auth/login',
    '{"username":"{admin}","password":"{password}"}',
    'ok',
    'text/plain',
  ),
  body(
    'login-extra-fields',
    'POST /api/v1/auth/login',
    '{"username":"{admin}","password":"{password}","remember":true,"username2":"x"}',
    'ok',
  ),
  { ...body('login-null-body', 'POST /api/v1/auth/login', 'null', 'error'), minMs: 250 },
  body('login-array-body', 'POST /api/v1/auth/login', '[]', 'error'),
  body(
    'login-wrong-field-type',
    'POST /api/v1/auth/login',
    '{"username":"{admin}","password":12345}',
    'error',
  ),

  // Login limiter: 10 per minute per client address, shared by login and the two OIDC routes.
  // Go reads the address from True-Client-IP, X-Real-IP, then the first X-Forwarded-For hop
  // (chi RealIP) and never limits loopback. The Rust port reads only X-Forwarded-For, and only
  // from a trusted proxy (the recorder, through TRUSTED_PROXIES), taking the rightmost hop that
  // is not one, and limits loopback too. The multi-hop, X-Real-IP, True-Client-IP, precedence
  // and loopback goldens were recorded from the Rust build for those differences. Each case
  // uses its own documentation address.
  limited('login-rate-limited', { 'X-Forwarded-For': '203.0.113.7' }),
  limited('login-rate-limited-multi-hop', { 'X-Forwarded-For': '203.0.113.20' }, [
    { count: 10, status: 400, headers: { 'X-Forwarded-For': '203.0.113.20, 198.51.100.7' } },
  ]),
  // The prelude names another client in X-Forwarded-For, so only a header that is read would
  // carry its attempts over to the last request.
  limited('login-rate-limited-real-ip', { 'X-Real-IP': '203.0.113.21' }, [
    {
      count: 10,
      status: 400,
      headers: { 'X-Real-IP': '203.0.113.21', 'X-Forwarded-For': '198.51.100.21' },
    },
  ]),
  limited('login-rate-limited-true-client-ip', { 'True-Client-IP': '203.0.113.22' }, [
    {
      count: 10,
      status: 400,
      headers: { 'True-Client-IP': '203.0.113.22', 'X-Forwarded-For': '198.51.100.22' },
    },
  ]),
  limited('login-rate-limited-header-precedence', { 'True-Client-IP': '203.0.113.23' }, [
    {
      count: 10,
      status: 400,
      headers: {
        'True-Client-IP': '203.0.113.23',
        'X-Real-IP': '203.0.113.24',
        'X-Forwarded-For': '203.0.113.25',
      },
    },
    { status: 400, headers: { 'X-Real-IP': '203.0.113.24' } },
    // Go: 400, since True-Client-IP took the ten attempts. Rust: X-Forwarded-For did.
    { status: 429, headers: { 'X-Forwarded-For': '203.0.113.25' } },
  ]),
  // No address is exempt. Every loopback form, and an X-Forwarded-For hop that is not an
  // address, counts for the recorder's own 127.0.0.1.
  {
    ...limited('login-loopback-limited', {}, [
      { count: 4, status: 400 },
      { count: 3, status: 400, headers: { 'X-Forwarded-For': '127.0.0.1' } },
      { count: 2, status: 400, headers: { 'X-Forwarded-For': '::ffff:127.0.0.1' } },
      { count: 1, status: 400, headers: { 'X-Forwarded-For': 'not-an-address' } },
    ]),
    direct: true,
  },
  // The test host has only 127.0.0.1 on its loopback interface, so these send the other
  // loopback forms through X-Forwarded-For. Built from parts so the source holds only
  // 127.0.0.1 as a literal address.
  limited('login-forwarded-loopback-127-0-0-2-limited', {
    'X-Forwarded-For': [127, 0, 0, 2].join('.'),
  }),
  limited('login-forwarded-loopback-ipv6-limited', { 'X-Forwarded-For': '::1' }),
  {
    // Successful logins count toward the limit too.
    name: 'login-rate-limited-after-successes',
    route: 'POST /api/v1/auth/login',
    outcome: 'error',
    method: 'POST',
    path: '/api/v1/auth/login',
    auth: 'none',
    headers: { 'X-Forwarded-For': '203.0.113.28', 'Content-Type': 'application/json' },
    raw: '{"username":"{admin}","password":"{password}"}',
    prelude: [
      {
        count: 10,
        status: 200,
        headers: { 'X-Forwarded-For': '203.0.113.28', 'Content-Type': 'application/json' },
        raw: '{"username":"{admin}","password":"{password}"}',
      },
    ],
  },
  {
    name: 'oidc-callback-rate-limited-shared',
    route: 'GET /api/v1/auth/oidc/callback',
    outcome: 'error',
    method: 'GET',
    path: '/api/v1/auth/oidc/callback?code=c&state=s',
    auth: 'none',
    headers: { 'X-Forwarded-For': '203.0.113.26' },
    prelude: [
      {
        count: 5,
        status: 400,
        method: 'POST',
        path: '/api/v1/auth/login',
        headers: { 'X-Forwarded-For': '203.0.113.26' },
        raw: '{',
      },
      {
        count: 4,
        status: 404,
        path: '/api/v1/auth/oidc/start',
        headers: { 'X-Forwarded-For': '203.0.113.26' },
      },
      { status: 200, path: '/api/v1/auth/methods', headers: { 'X-Forwarded-For': '203.0.113.26' } },
      { status: 404, headers: { 'X-Forwarded-For': '203.0.113.26' } },
    ],
  },
  {
    name: 'oidc-start-rate-limited-shared',
    route: 'GET /api/v1/auth/oidc/start',
    outcome: 'error',
    method: 'GET',
    path: '/api/v1/auth/oidc/start',
    auth: 'none',
    headers: { 'X-Forwarded-For': '203.0.113.27' },
    prelude: [
      {
        count: 10,
        status: 404,
        path: '/api/v1/auth/oidc/callback',
        headers: { 'X-Forwarded-For': '203.0.113.27' },
      },
    ],
  },
  {
    name: 'me-ok',
    route: 'GET /api/v1/auth/me',
    outcome: 'ok',
    method: 'GET',
    path: '/api/v1/auth/me',
  },
  noSession('GET /api/v1/auth/me', 'GET', '/api/v1/auth/me', 'me-no-session'),
  // The method check runs before the session check, HEAD included.
  noSession('GET /api/v1/auth/me', 'HEAD', '/api/v1/auth/me', 'me-head-no-session'),
  sessionForm('empty'),
  sessionForm('garbage'),
  sessionForm('expired'),
  sessionForm('expired-wrong-issuer'),
  sessionForm('tampered-payload'),
  sessionForm('wrong-key'),
  sessionForm('alg-none'),
  sessionForm('alg-hs512'),
  sessionForm('wrong-issuer'),
  sessionForm('empty-subject'),
  sessionForm('not-yet-valid'),
  sessionForm('recorder-minted'),
  sessionForm('no-exp'),
  sessionForm('expired-5s'),
  sessionForm('not-yet-valid-5s'),
  sessionForm('issued-in-5s'),
  sessionForm('other-subject'),
  sessionForm('fractional-exp'),
  sessionForm('with-audience'),
  // Go reads the first lodeline_session pair across all Cookie lines.
  cookieCase('cookie-lines-valid-first', [['session'], ['garbage']], 'ok'),
  cookieCase('cookie-lines-invalid-first', [['garbage'], ['session']], 'error'),
  cookieCase('cookie-pairs-valid-first', [['session', 'garbage']], 'ok'),
  cookieCase('cookie-pairs-invalid-first', [['garbage', 'session']], 'error'),
  {
    name: 'logout-ok',
    route: 'POST /api/v1/auth/logout',
    outcome: 'ok',
    method: 'POST',
    path: '/api/v1/auth/logout',
  },
  noSession('POST /api/v1/auth/logout', 'POST', '/api/v1/auth/logout', 'logout-no-session'),
  noSession(
    'POST /api/v1/auth/logout',
    'GET',
    '/api/v1/auth/logout',
    'logout-wrong-method-no-session',
  ),
  {
    name: 'live-login-secure-cookie',
    route: 'POST /api/v1/auth/login',
    outcome: 'ok',
    method: 'POST',
    path: '/api/v1/auth/login',
    server: 'live',
    auth: 'none',
    json: { username: '{admin}', password: '{password}' },
  },
  {
    name: 'live-logout-secure-cookie',
    route: 'POST /api/v1/auth/logout',
    outcome: 'ok',
    method: 'POST',
    path: '/api/v1/auth/logout',
    server: 'live',
  },
  {
    name: 'me-after-logout',
    route: 'GET /api/v1/auth/me',
    outcome: 'ok',
    method: 'GET',
    path: '/api/v1/auth/me',
  },

  // Fleet reads against the mock.
  {
    name: 'fleet-meta',
    route: 'GET /api/v1/fleet/meta',
    outcome: 'ok',
    method: 'GET',
    path: '/api/v1/fleet/meta',
  },
  noSession('GET /api/v1/fleet/meta', 'GET', '/api/v1/fleet/meta', 'fleet-meta-no-session'),
  // The method check runs before the session check.
  noSession(
    'GET /api/v1/fleet/meta',
    'POST',
    '/api/v1/fleet/meta',
    'fleet-meta-wrong-method-no-session',
  ),
  {
    name: 'fleet-healthz',
    route: 'GET /api/v1/fleet/healthz',
    outcome: 'ok',
    method: 'GET',
    path: '/api/v1/fleet/healthz',
  },
  noSession(
    'GET /api/v1/fleet/healthz',
    'GET',
    '/api/v1/fleet/healthz',
    'fleet-healthz-no-session',
  ),
  {
    name: 'fleet-events',
    route: 'GET /api/v1/fleet/events',
    outcome: 'ok',
    method: 'GET',
    path: '/api/v1/fleet/events',
  },
  {
    name: 'fleet-events-page',
    route: 'GET /api/v1/fleet/events',
    outcome: 'ok',
    method: 'GET',
    path: '/api/v1/fleet/events?limit=3&cursor={event:4}',
  },
  {
    name: 'fleet-events-filters',
    route: 'GET /api/v1/fleet/events',
    outcome: 'ok',
    method: 'GET',
    path: `/api/v1/fleet/events?host_id=${H_ALICE}&host_id=${H_BOB}&severity=warn&since={seed-12h}&min_ai_guard_bucket=high`,
  },
  {
    name: 'fleet-events-until-comma-hosts',
    route: 'GET /api/v1/fleet/events',
    outcome: 'ok',
    method: 'GET',
    path: `/api/v1/fleet/events?host_id=${H_ALICE},${H_DAVE}&until={seed-6h}&limit=500`,
  },
  {
    name: 'fleet-events-bad-limit',
    route: 'GET /api/v1/fleet/events',
    outcome: 'error',
    method: 'GET',
    path: '/api/v1/fleet/events?limit=ten',
  },
  {
    name: 'fleet-events-bad-since',
    route: 'GET /api/v1/fleet/events',
    outcome: 'error',
    method: 'GET',
    path: '/api/v1/fleet/events?since=yesterday',
  },
  {
    name: 'fleet-events-bad-until',
    route: 'GET /api/v1/fleet/events',
    outcome: 'error',
    method: 'GET',
    path: '/api/v1/fleet/events?until=2026-01-01',
  },
  {
    name: 'fleet-events-limit-plus-encoded',
    route: 'GET /api/v1/fleet/events',
    outcome: 'ok',
    method: 'GET',
    path: '/api/v1/fleet/events?limit=%2B3',
  },
  {
    // A raw `+` in a query decodes to a space.
    name: 'fleet-events-limit-plus-raw',
    route: 'GET /api/v1/fleet/events',
    outcome: 'error',
    method: 'GET',
    path: '/api/v1/fleet/events?limit=+3',
  },
  {
    name: 'fleet-events-comma-spaces',
    route: 'GET /api/v1/fleet/events',
    outcome: 'ok',
    method: 'GET',
    path: '/api/v1/fleet/events?severity=%20warn%20,,high',
  },
  {
    name: 'fleet-events-duplicate-key',
    route: 'GET /api/v1/fleet/events',
    outcome: 'ok',
    method: 'GET',
    path: '/api/v1/fleet/events?severity=info&severity=warn',
  },
  {
    // Mock events sit 44 minutes apart from the seed: since is inclusive, until exclusive.
    name: 'fleet-events-since-until-boundary',
    route: 'GET /api/v1/fleet/events',
    outcome: 'ok',
    method: 'GET',
    path: '/api/v1/fleet/events?since={seed-88m}&until={seed-44m}',
  },
  {
    // An empty value is the same as an absent one.
    name: 'fleet-events-empty-values',
    route: 'GET /api/v1/fleet/events',
    outcome: 'ok',
    method: 'GET',
    path: '/api/v1/fleet/events?limit=&since=&until=',
  },
  {
    name: 'fleet-events-limit-space',
    route: 'GET /api/v1/fleet/events',
    outcome: 'error',
    method: 'GET',
    path: '/api/v1/fleet/events?limit=%20',
  },
  since('lowercase-t', '2026-01-01t00:00:00Z', 'error'),
  since('lowercase-z', '2026-01-01T00:00:00z', 'error'),
  since('offset-no-colon', '2026-01-01T00:00:00%2B0900', 'error'),
  since('space-separator', '2026-01-01%2000:00:00Z', 'error'),
  since('comma-fraction', '2026-01-01T00:00:00,5Z', 'ok'),
  since('leap-second', '2026-01-01T23:59:60Z', 'error'),
  since('unknown-offset', '2026-01-01T00:00:00-00:00', 'ok'),
  since('offset-24h', '2026-01-01T00:00:00%2B24:00', 'ok'),
  since('no-seconds', '2026-01-01T00:00Z', 'error'),
  since('day-out-of-range', '2026-02-30T00:00:00Z', 'error'),
  noSession('GET /api/v1/fleet/events', 'GET', '/api/v1/fleet/events', 'fleet-events-no-session'),
  {
    name: 'fleet-event',
    route: 'GET /api/v1/fleet/events/{event_id}',
    outcome: 'ok',
    method: 'GET',
    path: '/api/v1/fleet/events/{event:3}',
  },
  {
    name: 'fleet-event-not-found',
    route: 'GET /api/v1/fleet/events/{event_id}',
    outcome: 'error',
    method: 'GET',
    path: `/api/v1/fleet/events/${EVT_MISSING}`,
  },
  // Go's server refuses a malformed escape before routing, session or not.
  {
    name: 'fleet-event-bad-escape',
    route: 'GET /api/v1/fleet/events/{event_id}',
    outcome: 'error',
    method: 'GET',
    path: '/api/v1/fleet/events/%zz',
  },
  noSession(
    'GET /api/v1/fleet/events/{event_id}',
    'GET',
    '/api/v1/fleet/events/{event:3}',
    'fleet-event-no-session',
  ),
  {
    name: 'fleet-risk',
    route: 'GET /api/v1/fleet/risk',
    outcome: 'ok',
    method: 'GET',
    path: '/api/v1/fleet/risk',
  },
  {
    name: 'fleet-risk-filters',
    route: 'GET /api/v1/fleet/risk',
    outcome: 'ok',
    method: 'GET',
    path: '/api/v1/fleet/risk?min_bucket=high&tool=claude_code,continue_dev',
  },
  {
    name: 'fleet-risk-page',
    route: 'GET /api/v1/fleet/risk',
    outcome: 'ok',
    method: 'GET',
    path: `/api/v1/fleet/risk?limit=1&cursor=${H_ALICE}`,
  },
  {
    name: 'fleet-risk-bad-limit',
    route: 'GET /api/v1/fleet/risk',
    outcome: 'error',
    method: 'GET',
    path: '/api/v1/fleet/risk?limit=1.5',
  },
  {
    name: 'fleet-risk-limit-zero',
    route: 'GET /api/v1/fleet/risk',
    outcome: 'ok',
    method: 'GET',
    path: '/api/v1/fleet/risk?limit=0',
  },
  {
    name: 'fleet-risk-limit-empty',
    route: 'GET /api/v1/fleet/risk',
    outcome: 'ok',
    method: 'GET',
    path: '/api/v1/fleet/risk?limit=',
  },
  // Go drops a query pair holding `;`, and reads the first of repeated keys.
  {
    name: 'fleet-risk-semicolon-pair',
    route: 'GET /api/v1/fleet/risk',
    outcome: 'ok',
    method: 'GET',
    path: '/api/v1/fleet/risk?limit=x;y&limit=1',
  },
  noSession('GET /api/v1/fleet/risk', 'GET', '/api/v1/fleet/risk', 'fleet-risk-no-session'),
  {
    name: 'fleet-compliance',
    route: 'GET /api/v1/fleet/compliance',
    outcome: 'ok',
    method: 'GET',
    path: '/api/v1/fleet/compliance',
  },
  {
    name: 'fleet-compliance-page',
    route: 'GET /api/v1/fleet/compliance',
    outcome: 'ok',
    method: 'GET',
    path: '/api/v1/fleet/compliance?limit=2',
  },
  {
    name: 'fleet-compliance-bad-limit',
    route: 'GET /api/v1/fleet/compliance',
    outcome: 'error',
    method: 'GET',
    path: '/api/v1/fleet/compliance?limit=x',
  },
  {
    name: 'fleet-compliance-limit-over-max',
    route: 'GET /api/v1/fleet/compliance',
    outcome: 'ok',
    method: 'GET',
    path: '/api/v1/fleet/compliance?limit=2000',
  },
  {
    name: 'fleet-compliance-limit-space',
    route: 'GET /api/v1/fleet/compliance',
    outcome: 'error',
    method: 'GET',
    path: '/api/v1/fleet/compliance?limit=%20',
  },
  {
    name: 'fleet-compliance-duplicate-limit',
    route: 'GET /api/v1/fleet/compliance',
    outcome: 'error',
    method: 'GET',
    path: '/api/v1/fleet/compliance?limit=x&limit=1',
  },
  noSession(
    'GET /api/v1/fleet/compliance',
    'GET',
    '/api/v1/fleet/compliance',
    'fleet-compliance-no-session',
  ),
  {
    name: 'fleet-hosts',
    route: 'GET /api/v1/fleet/hosts',
    outcome: 'ok',
    method: 'GET',
    path: '/api/v1/fleet/hosts',
  },
  {
    name: 'fleet-hosts-filters',
    route: 'GET /api/v1/fleet/hosts',
    outcome: 'ok',
    method: 'GET',
    path: '/api/v1/fleet/hosts?status=healthy,stale&sort=risk&limit=2',
  },
  {
    name: 'fleet-hosts-cursor-past-end',
    route: 'GET /api/v1/fleet/hosts',
    outcome: 'ok',
    method: 'GET',
    path: `/api/v1/fleet/hosts?cursor=5a7c3e91-aaaa-bbbb-cccc-555555555555`,
  },
  {
    name: 'fleet-hosts-bad-limit',
    route: 'GET /api/v1/fleet/hosts',
    outcome: 'error',
    method: 'GET',
    path: '/api/v1/fleet/hosts?limit=-',
  },
  {
    name: 'fleet-hosts-limit-negative',
    route: 'GET /api/v1/fleet/hosts',
    outcome: 'ok',
    method: 'GET',
    path: '/api/v1/fleet/hosts?limit=-1',
  },
  {
    name: 'fleet-hosts-limit-empty',
    route: 'GET /api/v1/fleet/hosts',
    outcome: 'ok',
    method: 'GET',
    path: '/api/v1/fleet/hosts?limit=',
  },
  {
    name: 'fleet-hosts-duplicate-limit',
    route: 'GET /api/v1/fleet/hosts',
    outcome: 'ok',
    method: 'GET',
    path: '/api/v1/fleet/hosts?limit=1&limit=x',
  },
  noSession('GET /api/v1/fleet/hosts', 'GET', '/api/v1/fleet/hosts', 'fleet-hosts-no-session'),
  {
    name: 'fleet-host',
    route: 'GET /api/v1/fleet/hosts/{host_id}',
    outcome: 'ok',
    method: 'GET',
    path: `/api/v1/fleet/hosts/${H_ALICE}`,
  },
  {
    name: 'fleet-host-no-meta',
    route: 'GET /api/v1/fleet/hosts/{host_id}',
    outcome: 'ok',
    method: 'GET',
    path: `/api/v1/fleet/hosts/${H_DAVE}`,
  },
  {
    name: 'fleet-host-not-found',
    route: 'GET /api/v1/fleet/hosts/{host_id}',
    outcome: 'error',
    method: 'GET',
    path: `/api/v1/fleet/hosts/${H_MISSING}`,
  },
  noSession(
    'GET /api/v1/fleet/hosts/{host_id}',
    'GET',
    `/api/v1/fleet/hosts/${H_ALICE}`,
    'fleet-host-no-session',
  ),

  // Triage write sequence on EVT#3 (an alice-mbp event in the mock), then reads.
  {
    name: 'triage-get-before-insert',
    route: 'GET /api/v1/triage/{host_id}/{event_id}',
    outcome: 'error',
    method: 'GET',
    path: `/api/v1/triage/${H_ALICE}/{event:3}`,
  },
  {
    name: 'triage-note-missing-row',
    route: 'POST /api/v1/triage/note',
    outcome: 'error',
    method: 'POST',
    path: '/api/v1/triage/note',
    json: { host_id: H_ALICE, event_id: '{event:3}', body: 'first look' },
  },
  {
    name: 'triage-upsert-insert-without-snapshot',
    route: 'POST /api/v1/triage/upsert',
    outcome: 'error',
    method: 'POST',
    path: '/api/v1/triage/upsert',
    json: { host_id: H_ALICE, event_id: '{event:3}', status: 'open' },
  },
  {
    name: 'triage-upsert-insert',
    route: 'POST /api/v1/triage/upsert',
    outcome: 'ok',
    method: 'POST',
    path: '/api/v1/triage/upsert',
    json: { host_id: H_ALICE, event_id: '{event:3}', status: 'open', evidence_snapshot: SNAPSHOT },
  },
  {
    name: 'triage-upsert-status',
    route: 'POST /api/v1/triage/upsert',
    outcome: 'ok',
    method: 'POST',
    path: '/api/v1/triage/upsert',
    json: { host_id: H_ALICE, event_id: '{event:3}', status: 'acknowledged' },
  },
  {
    name: 'triage-upsert-assign',
    route: 'POST /api/v1/triage/upsert',
    outcome: 'ok',
    method: 'POST',
    path: '/api/v1/triage/upsert',
    json: { host_id: H_ALICE, event_id: '{event:3}', assignee: 'analyst-1' },
  },
  {
    name: 'triage-upsert-clear-assignee',
    route: 'POST /api/v1/triage/upsert',
    outcome: 'ok',
    method: 'POST',
    path: '/api/v1/triage/upsert',
    json: { host_id: H_ALICE, event_id: '{event:3}', clear_assignee: true },
  },
  {
    name: 'triage-upsert-no-content-type',
    route: 'POST /api/v1/triage/upsert',
    outcome: 'ok',
    method: 'POST',
    path: '/api/v1/triage/upsert',
    raw: `{"host_id":"${H_ALICE}","event_id":"{event:3}","status":"investigating"}`,
  },
  {
    name: 'triage-upsert-invalid-status',
    route: 'POST /api/v1/triage/upsert',
    outcome: 'error',
    method: 'POST',
    path: '/api/v1/triage/upsert',
    json: { host_id: H_ALICE, event_id: '{event:3}', status: 'closed' },
  },
  {
    name: 'triage-upsert-missing-fields',
    route: 'POST /api/v1/triage/upsert',
    outcome: 'error',
    method: 'POST',
    path: '/api/v1/triage/upsert',
    json: { host_id: H_ALICE, status: 'open' },
  },
  {
    name: 'triage-upsert-malformed-json',
    route: 'POST /api/v1/triage/upsert',
    outcome: 'error',
    method: 'POST',
    path: '/api/v1/triage/upsert',
    raw: '{"host_id":',
  },
  {
    // A separate row, so the EVT#3 sequence above stays as it is.
    name: 'triage-upsert-null-snapshot',
    route: 'POST /api/v1/triage/upsert',
    outcome: 'ok',
    method: 'POST',
    path: '/api/v1/triage/upsert',
    json: { host_id: H_BOB, event_id: '{event:6}', status: 'open', evidence_snapshot: null },
  },
  noSession(
    'POST /api/v1/triage/upsert',
    'POST',
    '/api/v1/triage/upsert',
    'triage-upsert-no-session',
  ),
  {
    name: 'triage-note',
    route: 'POST /api/v1/triage/note',
    outcome: 'ok',
    method: 'POST',
    path: '/api/v1/triage/note',
    json: { host_id: H_ALICE, event_id: '{event:3}', body: 'Checked the hook <script> & "quotes"' },
  },
  {
    name: 'triage-note-second',
    route: 'POST /api/v1/triage/note',
    outcome: 'ok',
    method: 'POST',
    path: '/api/v1/triage/note',
    json: { host_id: H_ALICE, event_id: '{event:3}', body: 'Second note' },
  },
  {
    name: 'triage-note-missing-fields',
    route: 'POST /api/v1/triage/note',
    outcome: 'error',
    method: 'POST',
    path: '/api/v1/triage/note',
    json: { host_id: H_ALICE, event_id: '{event:3}' },
  },
  {
    name: 'triage-note-malformed-json',
    route: 'POST /api/v1/triage/note',
    outcome: 'error',
    method: 'POST',
    path: '/api/v1/triage/note',
    raw: 'not json',
  },
  noSession('POST /api/v1/triage/note', 'POST', '/api/v1/triage/note', 'triage-note-no-session'),
  {
    name: 'triage-get',
    route: 'GET /api/v1/triage/{host_id}/{event_id}',
    outcome: 'ok',
    method: 'GET',
    path: `/api/v1/triage/${H_ALICE}/{event:3}`,
  },
  {
    name: 'triage-get-wrong-host',
    route: 'GET /api/v1/triage/{host_id}/{event_id}',
    outcome: 'error',
    method: 'GET',
    path: `/api/v1/triage/${H_BOB}/{event:3}`,
  },
  noSession(
    'GET /api/v1/triage/{host_id}/{event_id}',
    'GET',
    `/api/v1/triage/${H_ALICE}/{event:3}`,
    'triage-get-no-session',
  ),
  {
    name: 'fleet-events-with-triage',
    route: 'GET /api/v1/fleet/events',
    outcome: 'ok',
    method: 'GET',
    path: `/api/v1/fleet/events?host_id=${H_ALICE}`,
  },
  {
    name: 'fleet-event-with-triage',
    route: 'GET /api/v1/fleet/events/{event_id}',
    outcome: 'ok',
    method: 'GET',
    path: '/api/v1/fleet/events/{event:3}',
  },

  // Note bodies on the H_BOB row that triage-upsert-null-snapshot wrote; triage-get-bob reads
  // back what they stored.
  body(
    'triage-note-text-plain',
    'POST /api/v1/triage/note',
    `{"host_id":"${H_BOB}","event_id":"{event:6}","body":"sent as text/plain"}`,
    'ok',
    'text/plain',
  ),
  body(
    'triage-note-extra-fields',
    'POST /api/v1/triage/note',
    `{"host_id":"${H_BOB}","event_id":"{event:6}","body":"extra fields","author":"someone-else","id":99}`,
    'ok',
  ),
  body('triage-note-null-body', 'POST /api/v1/triage/note', 'null', 'error'),
  body('triage-note-array-body', 'POST /api/v1/triage/note', '[]', 'error'),
  body(
    'triage-note-wrong-field-type',
    'POST /api/v1/triage/note',
    `{"host_id":"${H_BOB}","event_id":"{event:6}","body":7}`,
    'error',
  ),
  {
    name: 'triage-get-bob',
    route: 'GET /api/v1/triage/{host_id}/{event_id}',
    outcome: 'ok',
    method: 'GET',
    path: `/api/v1/triage/${H_BOB}/{event:6}`,
  },

  // Snapshots keep the client's JSON text: Go stores it as sent and writes it compacted, with
  // `<`, `>`, `&`, U+2028 and U+2029 escaped. The rows are new, so the cases above see none of them.
  {
    name: 'triage-upsert-snapshot-text',
    route: 'POST /api/v1/triage/upsert',
    outcome: 'ok',
    method: 'POST',
    path: '/api/v1/triage/upsert',
    headers: { 'Content-Type': 'application/json' },
    raw: `{"host_id":"${H_DAVE}","event_id":"snapshot-text","evidence_snapshot": {
      "float" : 1.0, "exp": 1e2, "upper": -1.50E+02,
      "big": 123456789012345678901234567890, "long": 0.1000000000000000000001,
      "html": "<b>&amp;</b>", "escapes": "\\u0041\\/\\"\\\\\\n\\t",
      "unicode": "\u00e9\\u00e9", "separators": "\u2028\u2029\\u2028",
      "nested": [ 1 , { "x" : null } , [ ] , { } ], "spaces": "  kept  " } }`,
    rawText: ['evidence_snapshot'],
  },
  {
    name: 'triage-upsert-snapshot-number',
    route: 'POST /api/v1/triage/upsert',
    outcome: 'ok',
    method: 'POST',
    path: '/api/v1/triage/upsert',
    headers: { 'Content-Type': 'application/json' },
    raw: `{"host_id":"${H_DAVE}","event_id":"snapshot-number","evidence_snapshot":  -1.50E+02  }`,
    rawText: ['evidence_snapshot'],
  },
  {
    name: 'triage-get-snapshot-text',
    route: 'GET /api/v1/triage/{host_id}/{event_id}',
    outcome: 'ok',
    method: 'GET',
    path: `/api/v1/triage/${H_DAVE}/snapshot-text`,
    rawText: ['row.evidence_snapshot'],
  },

  // Live mode: the manager reads the stub upstream.
  upstream(
    'live-meta-legacy-license',
    'GET /api/v1/fleet/meta',
    '/api/v1/fleet/meta',
    {
      status: 200,
      json: {
        server_version: '0.8.3',
        schema_version: 1,
        ts: LIVE_TS,
        alerts_definition_default: LIVE_ALERTS,
        license: { current_host_count: 7, active_window_days: 30, tier: 'oss' },
      },
    },
    'ok',
  ),
  upstream(
    'live-meta-fleet',
    'GET /api/v1/fleet/meta',
    '/api/v1/fleet/meta',
    {
      status: 200,
      json: {
        server_version: '0.12.4',
        schema_version: 1,
        ts: LIVE_TS,
        alerts_definition_default: LIVE_ALERTS,
        fleet: { active_host_count: 3, active_window_days: 14 },
        audit_head: { seq: 9, hash: 'h', sig: 's', pubkey_id: 'k1', pubkey: 'ed25519:AAAA' },
        license: { current_host_count: 99, active_window_days: 1 },
        added_later: true,
      },
    },
    'ok',
  ),
  upstream(
    'live-healthz',
    'GET /api/v1/fleet/healthz',
    '/api/v1/fleet/healthz',
    { status: 200, json: { status: 'ok', ts: LIVE_TS } },
    'ok',
  ),
  upstream(
    'live-events-query',
    'GET /api/v1/fleet/events',
    `/api/v1/fleet/events?limit=5&cursor=c1&host_id=${H_ALICE}&host_id=${H_BOB}&since=2026-01-01T00:00:00Z&until=2026-01-02T00:00:00%2B09:00&evidence_kind=a,b&severity=warn&source=agent&min_ai_guard_bucket=high&unknown=1`,
    { status: 200, json: { events: [LIVE_EVENT], next_cursor: LIVE_EVENT_ID } },
    'ok',
  ),
  upstream(
    'live-event',
    'GET /api/v1/fleet/events/{event_id}',
    `/api/v1/fleet/events/${LIVE_EVENT_ID}`,
    { status: 200, json: LIVE_EVENT },
    'ok',
  ),
  upstream(
    'live-risk-query',
    'GET /api/v1/fleet/risk',
    '/api/v1/fleet/risk?limit=2&cursor=c2&tool=codex,gemini&min_bucket=medium',
    {
      status: 200,
      json: {
        rows: [
          {
            host_id: H_ALICE,
            hostname: null,
            score: 8,
            bucket: 'critical',
            top_tool: 'codex',
            reasons_count: 2,
            assessed_ts: LIVE_TS,
            open_alert_count_24h: 1,
          },
        ],
        next_cursor: null,
      },
    },
    'ok',
  ),
  upstream(
    'live-compliance-query',
    'GET /api/v1/fleet/compliance',
    '/api/v1/fleet/compliance?limit=7&cursor=c3',
    {
      status: 200,
      json: {
        rows: [
          {
            host_id: H_ALICE,
            hostname: 'alice-mbp',
            last_applied_policy_version: 4,
            server_current_policy_version: 5,
            version_drift: 1,
            policy_expired_active: false,
            last_policy_reload_ts: null,
            signature_failures_24h: 0,
          },
        ],
        next_cursor: 'c4',
      },
    },
    'ok',
  ),
  upstream(
    'live-hosts-query',
    'GET /api/v1/fleet/hosts',
    '/api/v1/fleet/hosts?limit=3&cursor=c5&status=stale&bucket=high,critical&sort=host_id',
    {
      status: 200,
      json: {
        hosts: [
          {
            host_id: H_ALICE,
            hostname: null,
            agent_version: '0.12.4',
            last_seen_ts: LIVE_TS,
            status: 'stale',
            current_risk: null,
            open_event_counts_24h: {},
          },
        ],
        next_cursor: null,
        total_estimated: 1,
      },
    },
    'ok',
  ),
  upstream(
    'live-hosts-missing-fields',
    'GET /api/v1/fleet/hosts',
    '/api/v1/fleet/hosts',
    { status: 200, json: { hosts: [{ host_id: H_ALICE }] } },
    'ok',
  ),
  upstream(
    'live-host',
    'GET /api/v1/fleet/hosts/{host_id}',
    `/api/v1/fleet/hosts/${H_ALICE}`,
    {
      status: 200,
      json: {
        host_id: H_ALICE,
        hostname: 'alice-mbp',
        agent_version: '0.12.4',
        last_seen_ts: LIVE_TS,
        status: 'healthy',
        current_risk: {
          max_score: 4.5,
          max_bucket: 'medium',
          by_tool: { codex: { score: 4.5, bucket: 'medium', assessed_ts: LIVE_TS } },
        },
        open_event_counts_24h: { warn: 2 },
        host_meta: null,
        policy_state: {
          last_applied_policy_version: 3,
          policy_expired_active: true,
          last_policy_reload_ts: LIVE_TS,
        },
        agent_health: {
          recent_channel_stalls_24h: 0,
          recent_watcher_degraded_24h: 1,
          recent_sender_lag_critical_24h: 0,
          last_heartbeat_ts: null,
          hash_p99_ms_latest: 12,
          jsonl_above_soft_floor_latest: null,
        },
        ai_guard: {
          by_tool: {
            codex: {
              score: 4.5,
              bucket: 'medium',
              assessed_ts: LIVE_TS,
              is_reattestation: false,
              scope: { kind: 'user_global' },
              reasons: [{ kind: 'k' }],
            },
            gemini: {
              controls: [],
              score: 1,
              bucket: 'low',
              assessed_ts: LIVE_TS,
              is_reattestation: true,
              scope: { kind: 'project', path: '/p' },
              reasons: [],
            },
          },
        },
        added_later: 1,
      },
    },
    'ok',
  ),
  upstream(
    // Go stores the zero value for a null map entry.
    'live-host-null-entries',
    'GET /api/v1/fleet/hosts/{host_id}',
    `/api/v1/fleet/hosts/${H_ALICE}`,
    {
      status: 200,
      json: {
        host_id: H_ALICE,
        last_seen_ts: LIVE_TS,
        status: 'healthy',
        current_risk: { max_score: 1, max_bucket: 'low', by_tool: { codex: null } },
        open_event_counts_24h: { warn: null, info: 2 },
        ai_guard: { by_tool: { gemini: null } },
      },
    },
    'ok',
  ),
  upstream(
    // Go reads -0 into an integer field as 0. A float -0 stays -0, which a golden cannot hold.
    'live-host-minus-zero',
    'GET /api/v1/fleet/hosts/{host_id}',
    `/api/v1/fleet/hosts/${H_ALICE}`,
    {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
      text: `{"host_id":"${H_ALICE}","last_seen_ts":"${LIVE_TS}","status":"healthy","current_risk":{"max_score":1,"max_bucket":"low","by_tool":{}},"open_event_counts_24h":{"warn":-0},"policy_state":{"last_applied_policy_version":-0,"policy_expired_active":false},"agent_health":{"recent_channel_stalls_24h":-0,"hash_p99_ms_latest":-0}}`,
    },
    'ok',
  ),
  upstream(
    // Go leaves the evidence kind empty for "kind": null and keeps the raw object.
    'live-event-null-kind',
    'GET /api/v1/fleet/events/{event_id}',
    `/api/v1/fleet/events/${LIVE_EVENT_ID}`,
    {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
      text: `{"schema_version":-0,"event_id":"${LIVE_EVENT_ID}","ts":"${LIVE_TS}","host_id":"${H_ALICE}","agent_version":"0.12.4","severity":"warn","source":{"kind":"agent"},"subject":null,"evidence":{"kind":null,"detail":1}}`,
    },
    'ok',
  ),
  {
    // A number past f64 in one event's evidence: the page is served and the evidence text
    // relayed as the server wrote it, key order and number spelling included.
    ...upstream(
      'live-events-out-of-range-number',
      'GET /api/v1/fleet/events',
      '/api/v1/fleet/events',
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
        text: `{"events":[{"schema_version":1,"event_id":"01900000-0000-7000-8000-000000000002","ts":"${LIVE_TS}","host_id":"${H_ALICE}","agent_version":"0.12.4","severity":"warn","source":{"kind":"agent"},"subject":null,"evidence":{"kind":"future_variant","huge":1e400,"exact":1.50,"big":18446744073709551616}},${JSON.stringify(LIVE_EVENT)}],"next_cursor":null}`,
      },
      'ok',
    ),
    rawText: ['events.0.evidence'],
  },
  ...[
    ['plus3', '%2B3'],
    ['007', '007'],
    ['0', '0'],
    ['minus1', '-1'],
    ['2000', '2000'],
  ].map(([label, limit]) =>
    upstream(
      `live-events-limit-${label}`,
      'GET /api/v1/fleet/events',
      `/api/v1/fleet/events?limit=${limit}`,
      { status: 200, json: { events: [], next_cursor: null } },
      'ok',
    ),
  ),
  upstream(
    'live-events-empty-values',
    'GET /api/v1/fleet/events',
    '/api/v1/fleet/events?limit=&cursor=&host_id=&since=&until=&severity=',
    { status: 200, json: { events: [], next_cursor: null } },
    'ok',
  ),
  upstream(
    'live-events-limit-space',
    'GET /api/v1/fleet/events',
    '/api/v1/fleet/events?limit=%20',
    { status: 200, json: { events: [], next_cursor: null } },
  ),
  upstream(
    // Go forwards since and until in UTC, whole seconds.
    'live-events-time-forms',
    'GET /api/v1/fleet/events',
    '/api/v1/fleet/events?since=2026-01-01T00:00:00,5%2B24:00&until=2026-01-01T09:00:00.999-00:00',
    { status: 200, json: { events: [], next_cursor: null } },
    'ok',
  ),
  ...[
    ['space', 'a%20b'],
    ['slash', 'a%2Fb'],
    ['plus', 'a%2Bb'],
    ['unreserved', '%41bc'],
    // Go escapes `*` in a path, so `%2A` is read decoded and `a*b%20c` raw.
    ['star', '%2A'],
    ['star-space', 'a*b%20c'],
  ].flatMap(([label, id]) => [
    upstream(
      `live-event-id-${label}`,
      'GET /api/v1/fleet/events/{event_id}',
      `/api/v1/fleet/events/${id}`,
      { status: 404, json: { error: { code: 'not_found', message: 'no such event' } } },
    ),
    upstream(
      `live-host-id-${label}`,
      'GET /api/v1/fleet/hosts/{host_id}',
      `/api/v1/fleet/hosts/${id}`,
      { status: 404, json: { error: { code: 'not_found', message: 'no such host' } } },
    ),
  ]),
  upstream('upstream-401', 'GET /api/v1/fleet/events', '/api/v1/fleet/events', {
    status: 401,
    json: { error: { code: 'unauthorized', message: 'bad token' } },
  }),
  upstream('upstream-404-list', 'GET /api/v1/fleet/risk', '/api/v1/fleet/risk', {
    status: 404,
    text: 'not found',
  }),
  upstream(
    'upstream-404-event',
    'GET /api/v1/fleet/events/{event_id}',
    `/api/v1/fleet/events/${LIVE_EVENT_ID}`,
    { status: 404, json: { error: { code: 'not_found', message: 'no such event' } } },
  ),
  upstream(
    'upstream-404-host',
    'GET /api/v1/fleet/hosts/{host_id}',
    `/api/v1/fleet/hosts/${H_ALICE}`,
    {
      status: 404,
      text: '',
    },
  ),
  upstream('upstream-503-healthz', 'GET /api/v1/fleet/healthz', '/api/v1/fleet/healthz', {
    status: 503,
    headers: { 'Retry-After': '7' },
    json: { error: { code: 'service_unavailable', message: 'rebuilding' } },
  }),
  {
    // Three attempts with the upstream's 1 s Retry-After between them.
    ...upstream(
      'upstream-503-retried',
      'GET /api/v1/fleet/compliance',
      '/api/v1/fleet/compliance',
      {
        status: 503,
        headers: { 'Retry-After': '1' },
        json: { error: { code: 'service_unavailable', message: 'rebuilding' } },
      },
    ),
    minMs: 2000,
    maxMs: 3000,
  },
  upstream('upstream-500-json', 'GET /api/v1/fleet/hosts', '/api/v1/fleet/hosts', {
    status: 500,
    json: { error: { code: 'internal', message: 'upstream detail stays upstream' } },
  }),
  upstream('upstream-500-text', 'GET /api/v1/fleet/meta', '/api/v1/fleet/meta', {
    status: 500,
    text: 'panic at http://upstream.invalid/v1/meta',
  }),
  upstream('upstream-bad-json', 'GET /api/v1/fleet/events', '/api/v1/fleet/events', {
    status: 200,
    text: '{"events": [',
  }),
  upstream('upstream-closed', 'GET /api/v1/fleet/hosts', '/api/v1/fleet/hosts', {
    status: 200,
    close: true,
  }),
  {
    // The 5 s client timeout ends the one attempt: a timeout is not retried.
    ...upstream('upstream-timeout', 'GET /api/v1/fleet/risk', '/api/v1/fleet/risk', {
      status: 200,
      json: { rows: [], next_cursor: null },
      delayMs: 6500,
    }),
    minMs: 5000,
    maxMs: 6000,
  },
  {
    name: 'upstream-refused',
    route: 'GET /api/v1/fleet/events',
    outcome: 'error',
    method: 'GET',
    path: '/api/v1/fleet/events',
    server: 'down',
  },

  // Last, seconds after the first health case, so a cached timestamp shows.
  {
    name: 'health-end-of-run',
    route: 'GET /api/health',
    outcome: 'ok',
    method: 'GET',
    path: '/api/health',
  },
];
