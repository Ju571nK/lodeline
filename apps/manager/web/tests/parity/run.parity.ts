import { execFileSync } from 'node:child_process';
import { createHash, createHmac } from 'node:crypto';
import { readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
import { type Auth, CASES, type Case, NO_SUCCESS_CASE, ROUTES } from './cases.ts';
import * as env from './env.ts';
import {
  dropNullAt,
  mockEventIds,
  type NormalizeContext,
  normalizeJson,
  parseSetCookie,
} from './normalize.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const GOLDENS = join(HERE, 'goldens');
const DIST = join(HERE, '..', '..', 'dist');
const TESTDATA = join(HERE, '..', '..', '..', 'testdata');
const MOCK_EVENT_COUNT = 32;
const RECORDED_HEADERS = [
  'content-type',
  'cache-control',
  'location',
  'retry-after',
  'allow',
  'content-security-policy',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
];

interface AllowEntry {
  case: string;
  path: string;
  rule: 'null-or-absent';
  reason: string;
}
const ALLOWLIST: AllowEntry[] = JSON.parse(readFileSync(join(HERE, 'allowlist.json'), 'utf8'));

interface Run {
  session: string;
  seedMs: number;
  eventIds: Map<string, string>;
  distByHash: Map<string, string>;
  entryScript: string;
}
let run: Run;

function b64url(v: string | Buffer): string {
  return Buffer.from(v).toString('base64url');
}

function jwt(header: object, claims: object, secret = env.JWT_SECRET, alg = 'sha256'): string {
  const head = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`;
  return `${head}.${createHmac(alg, secret).update(head).digest('base64url')}`;
}

/** Fixed instants so crafted tokens, and their goldens, never change between runs. */
const PAST = 1_600_000_000;
const FUTURE = 4_000_000_000;

function craftedToken(auth: Exclude<Auth, 'session' | 'none' | 'empty' | 'garbage'>): string {
  const hs256 = { alg: 'HS256', typ: 'JWT' };
  const claims = {
    iss: 'lodeline-manager',
    sub: env.ADMIN_USERNAME,
    iat: PAST,
    nbf: PAST,
    exp: FUTURE,
  };
  switch (auth) {
    case 'expired':
      return jwt(hs256, { ...claims, exp: PAST + 3600 });
    case 'expired-wrong-issuer':
      return jwt(hs256, { ...claims, iss: 'someone-else', exp: PAST + 3600 });
    case 'tampered-payload': {
      const [h, , s] = jwt(hs256, claims).split('.');
      return `${h}.${b64url(JSON.stringify({ ...claims, sub: 'other-user' }))}.${s}`;
    }
    case 'wrong-key':
      return jwt(hs256, claims, 'a-different-secret-of-at-least-32-bytes');
    case 'alg-none':
      return `${b64url(JSON.stringify({ alg: 'none', typ: 'JWT' }))}.${b64url(JSON.stringify(claims))}.`;
    case 'alg-hs512':
      return jwt({ alg: 'HS512', typ: 'JWT' }, claims, env.JWT_SECRET, 'sha512');
    case 'wrong-issuer':
      return jwt(hs256, { ...claims, iss: 'someone-else' });
    case 'empty-subject':
      return jwt(hs256, { ...claims, sub: '' });
    case 'not-yet-valid':
      return jwt(hs256, { ...claims, nbf: FUTURE - 3600 });
    case 'recorder-minted':
      return jwt(hs256, claims);
  }
}

function cookieValue(auth: Auth): string | null {
  switch (auth) {
    case 'none':
      return null;
    case 'session':
      return run.session;
    case 'empty':
      return '';
    case 'garbage':
      return 'not-a-token';
    default:
      return craftedToken(auth);
  }
}

function rfc3339Seconds(ms: number): string {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/** Fills the placeholders that cases.ts documents. */
function fill(s: string): string {
  return s
    .replace(/\{event:(\d+)\}/g, (_, i) => [...run.eventIds.keys()][Number(i)])
    .replace(/\{seed-(\d+)h\}/g, (_, h) => rfc3339Seconds(run.seedMs - Number(h) * 3_600_000))
    .replace('{asset:js}', run.entryScript)
    .replace(/\{admin\}/g, env.ADMIN_USERNAME)
    .replace(/\{password\}/g, env.ADMIN_PASSWORD);
}

function walkFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((d) =>
    d.isDirectory() ? walkFiles(join(dir, d.name)) : [join(dir, d.name)],
  );
}

function sha256(b: Buffer): string {
  return createHash('sha256').update(b).digest('hex');
}

/** JSON is compared parsed; SPA files by identity with web/dist; other bodies as short text or a hash. */
function recordBody(contentType: string, bytes: Buffer, ctx: NormalizeContext): unknown {
  if (bytes.length === 0) return '';
  const text = bytes.toString('utf8');
  if (contentType.includes('json')) {
    try {
      return normalizeJson(JSON.parse(text), ctx);
    } catch {
      return { unparsed: text };
    }
  }
  const dist = run.distByHash.get(sha256(bytes));
  // Vite names assets by content hash; the name is dropped so goldens survive SPA edits.
  if (dist) return `<dist:${dist.replace(/-[\w-]{8}(\.\w+)$/, '-<hash>$1')}>`;
  if (bytes.length <= 4096) return text;
  return `<sha256:${sha256(bytes)} ${bytes.length} bytes>`;
}

function recordHeaders(res: Response): Record<string, string> {
  const out: Record<string, string> = {};
  for (const name of RECORDED_HEADERS) {
    let v = res.headers.get(name);
    if (v === null) continue;
    // The 429 wait counts down from the first request in the window.
    if (name === 'retry-after' && res.status === 429 && /^\d+$/.test(v) && +v >= 1 && +v <= 61) {
      v = '<1..61>';
    }
    out[name] = v;
  }
  return out;
}

async function send(c: Case, base: string, raw?: string, extra?: Record<string, string>) {
  const headers: Record<string, string> = { ...extra };
  let body: Buffer | string | undefined;
  if (c.json !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = fill(JSON.stringify(c.json));
  } else if (raw !== undefined) {
    // A Buffer body makes fetch send no Content-Type at all.
    body = Buffer.from(fill(raw));
  }
  const cookie = cookieValue(c.auth ?? 'session');
  if (cookie !== null) headers.Cookie = `lodeline_session=${cookie}`;
  return fetch(base + fill(c.path), { method: c.method, headers, body, redirect: 'manual' });
}

async function recordCase(c: Case): Promise<Record<string, unknown>> {
  const base = c.server === 'live' ? env.LIVE_URL : env.MOCK_URL;
  if (c.upstream) {
    await fetch(`${env.STUB_URL}/__stub/reply`, {
      method: 'POST',
      body: JSON.stringify(c.upstream),
    });
  }
  for (let i = 0; i < (c.prelude?.count ?? 0); i++) {
    await (await send(c, base, c.prelude?.raw, c.prelude?.headers)).arrayBuffer();
  }
  const started = performance.now();
  const res = await send(c, base, c.raw, c.headers);
  const bytes = Buffer.from(await res.arrayBuffer());
  const elapsed = performance.now() - started;
  if (c.minMs !== undefined) {
    expect(elapsed, `${c.name} must take at least ${c.minMs} ms`).toBeGreaterThanOrEqual(c.minMs);
  }
  const ctx: NormalizeContext = {
    seedMs: c.server === 'live' ? null : run.seedMs,
    windowStartMs: env.RUN_START_MS,
    windowEndMs: Date.now(),
    ttlHours: env.JWT_TTL_HOURS,
    eventIds: run.eventIds,
    fixedWidthTimestamps: c.path.startsWith('/api/v1/triage/'),
  };
  const record: Record<string, unknown> = {
    request: { method: c.method, path: c.path, server: c.server ?? 'mock' },
    status: res.status,
    headers: recordHeaders(res),
    cookies: res.headers.getSetCookie().map((h) => parseSetCookie(h, ctx)),
    body: c.skipBody
      ? `<not recorded: ${c.skipBody}>`
      : recordBody(res.headers.get('content-type') ?? '', bytes, ctx),
  };
  const body = record.body as Record<string, unknown>;
  // The build stamps its own version string into /api/health.
  if (c.route === 'GET /api/health' && typeof body?.version === 'string')
    body.version = '<version>';
  if (c.upstream) {
    record.upstream = await (await fetch(`${env.STUB_URL}/__stub/calls`)).json();
  }
  return record;
}

function allowlisted(name: string, record: Record<string, unknown>): Record<string, unknown> {
  const copy = structuredClone(record);
  for (const e of ALLOWLIST) {
    if (e.case === '*' || e.case === name) dropNullAt(copy, e.path.split('.'));
  }
  return copy;
}

test.beforeAll(async () => {
  const login = await fetch(`${env.MOCK_URL}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: env.ADMIN_USERNAME, password: env.ADMIN_PASSWORD }),
  });
  expect(login.status, 'recorder login').toBe(200);
  const session = /^lodeline_session=([^;]+)/.exec(login.headers.getSetCookie()[0] ?? '')?.[1];
  expect(session, 'session cookie').toBeTruthy();
  const healthz = await fetch(`${env.MOCK_URL}/api/v1/fleet/healthz`, {
    headers: { Cookie: `lodeline_session=${session}` },
  });
  const seedMs = Date.parse(((await healthz.json()) as { ts: string }).ts);
  expect(Number.isNaN(seedMs), 'mock seed from fleet/healthz ts').toBe(false);

  const distByHash = new Map<string, string>();
  for (const f of walkFiles(DIST)) distByHash.set(sha256(readFileSync(f)), relative(DIST, f));
  const entryScript = /src="(\/assets\/index-[^"]+\.js)"/.exec(
    readFileSync(join(DIST, 'index.html'), 'utf8'),
  )?.[1];
  expect(entryScript, 'entry script in dist/index.html').toBeTruthy();

  run = {
    session: session!,
    seedMs,
    eventIds: mockEventIds(seedMs, MOCK_EVENT_COUNT),
    distByHash,
    entryScript: entryScript!,
  };
});

test('the table covers every route with a success and an error case', () => {
  const lines = ROUTES.map((r) => {
    const rows = CASES.filter((c) => c.route === r);
    const ok = rows.filter((c) => c.outcome === 'ok').length;
    if (!NO_SUCCESS_CASE[r]) expect(ok, `${r} success cases`).toBeGreaterThan(0);
    expect(rows.length - ok, `${r} error cases`).toBeGreaterThan(0);
    return `  ${String(rows.length).padStart(3)}  ${r}`;
  });
  expect(new Set(CASES.map((c) => c.name)).size, 'unique case names').toBe(CASES.length);
  console.log(`parity: ${CASES.length} cases over ${ROUTES.length} routes\n${lines.join('\n')}`);
});

test('every allowlist entry names a reason and a known case', () => {
  for (const e of ALLOWLIST) {
    expect(e.reason.trim().length, `reason for ${e.path}`).toBeGreaterThan(0);
    expect(e.rule).toBe('null-or-absent');
    expect(e.case === '*' || CASES.some((c) => c.name === e.case), `case ${e.case}`).toBe(true);
  }
});

for (const c of CASES) {
  test(c.name, async () => {
    const record = await recordCase(c);
    const file = join(GOLDENS, `${c.name}.json`);
    if (env.UPDATE) {
      writeFileSync(file, `${JSON.stringify(record, null, 2)}\n`);
      return;
    }
    const golden = JSON.parse(readFileSync(file, 'utf8'));
    expect(allowlisted(c.name, record)).toEqual(allowlisted(c.name, golden));
  });
}

test('goldens match the table', () => {
  const names = new Set(CASES.map((c) => `${c.name}.json`));
  const stale = readdirSync(GOLDENS).filter((f) => !names.has(f));
  if (env.UPDATE) {
    for (const f of stale) rmSync(join(GOLDENS, f));
    return;
  }
  expect(stale, 'golden files with no case').toEqual([]);
});

test('write testdata from this run', () => {
  test.skip(!env.WRITE_TESTDATA, 'set PARITY_TESTDATA=1 to rewrite apps/manager/testdata');
  writeFileSync(join(TESTDATA, 'session-token.txt'), `${run.session}\n`);
  const db = join(TESTDATA, 'triage.sqlite');
  rmSync(db, { force: true });
  // .backup reads through the live WAL, so the copy holds every committed write.
  // The copy is switched to a rollback journal so opening it leaves no -wal file.
  execFileSync('sqlite3', [env.MOCK_DB, `.backup '${db}'`]);
  execFileSync('sqlite3', [db, 'PRAGMA journal_mode=DELETE;']);
  rmSync(`${db}-shm`, { force: true });
  const insert = CASES.find((c) => c.name === 'triage-upsert-insert')?.json as { host_id: string };
  const recording = {
    mock_seed: rfc3339Seconds(run.seedMs),
    admin_username: env.ADMIN_USERNAME,
    jwt_ttl_hours: env.JWT_TTL_HOURS,
    triage_row: { host_id: insert.host_id, event_id: fill('{event:3}'), golden: 'triage-get' },
  };
  writeFileSync(join(TESTDATA, 'recording.json'), `${JSON.stringify(recording, null, 2)}\n`);
});
