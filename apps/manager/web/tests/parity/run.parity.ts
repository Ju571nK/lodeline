import { execFileSync } from 'node:child_process';
import { createHash, createHmac } from 'node:crypto';
import {
  appendFileSync,
  existsSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import http from 'node:http';
import { dirname, join, relative } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { expect, test } from '@playwright/test';
import { type Auth, CASES, type Case, NO_SUCCESS_CASE, ROUTES } from './cases.ts';
import * as env from './env.ts';
import {
  type Bracket,
  dropNullAt,
  mockEventIds,
  type NormalizeContext,
  normalizeJson,
  parseSetCookie,
  rawJsonAt,
} from './normalize.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const GOLDENS = join(HERE, 'goldens');
const DIST = join(HERE, '..', '..', 'dist');
const TESTDATA = join(HERE, '..', '..', '..', 'testdata');
const BRACKETS = join(env.RUN_DIR, 'brackets.jsonl');
const MOCK_EVENT_COUNT = 32;
/** Goldens are recorded only from the Go build at this commit (its /api/health version prefix). */
const GO_REFERENCE = 'e4fb077';
/** Response headers left out of the record: framing, or set per response by the HTTP layer. */
const UNRECORDED_HEADERS = new Set([
  'date',
  'content-length',
  'transfer-encoding',
  'connection',
  'keep-alive',
  'set-cookie',
]);
/** Sent on every request, as a browser does, so a server that compresses shows it. */
const BASE_HEADERS = { Accept: '*/*', 'Accept-Encoding': 'gzip, deflate, br' };
// Wider than twice the clock slack in normalize.ts, so two requests' brackets never overlap.
const GAP_MS = 6;
// Go truncates the session `exp` to the second; later requests must not share the login's second.
const LOGIN_PAUSE_MS = 1_100;
const HASHED = /-[\w-]{8}(\.\w+)$/;

type Rec = Record<string, unknown>;
type AllowEntry = { cases: string[]; reason: string } & (
  | { rule: 'null-or-absent'; path: string }
  | { rule: 'alternative'; record: Rec }
);
const RECORD_KEYS = ['status', 'headers', 'cookies', 'body'];
const SECURITY_HEADERS = [
  'content-security-policy',
  'referrer-policy',
  'x-content-type-options',
  'x-frame-options',
];
const ALLOWLIST: AllowEntry[] = JSON.parse(readFileSync(join(HERE, 'allowlist.json'), 'utf8'));

interface Run {
  session: string;
  seedMs: number;
  eventIds: Map<string, string>;
  distByHash: Map<string, string>;
  /** dist paths the table names by placeholder, mapped to that placeholder. */
  distNames: Map<string, string>;
  assetFiles: string[];
  entryScript: string;
  entryStyle: string;
}
let run: Run;

interface Reply {
  status: number;
  rawHeaders: string[];
  body: Buffer;
}

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
  // Tokens a few seconds off the request time: Go allows no leeway.
  const now = Math.floor(Date.now() / 1000);
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
    case 'no-exp': {
      const { exp: _, ...rest } = claims;
      return jwt(hs256, rest);
    }
    case 'expired-5s':
      return jwt(hs256, { ...claims, exp: now - 5 });
    case 'not-yet-valid-5s':
      return jwt(hs256, { ...claims, nbf: now + 5 });
    case 'issued-in-5s':
      return jwt(hs256, { ...claims, iat: now + 5 });
    case 'other-subject':
      return jwt(hs256, { ...claims, sub: 'someone-else' });
    case 'fractional-exp':
      return jwt(hs256, { ...claims, exp: FUTURE + 0.75 });
    case 'with-audience':
      return jwt(hs256, { ...claims, aud: 'some-other-service' });
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
    .replace(/\{seed-(\d+)([hm])\}/g, (_, n, unit) =>
      rfc3339Seconds(run.seedMs - Number(n) * (unit === 'h' ? 3_600_000 : 60_000)),
    )
    .replace('{asset:js}', run.entryScript)
    .replace('{asset:css}', run.entryStyle)
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

type Headers = Record<string, string | string[]>;

const PORTS = { mock: env.MOCK_PORT, live: env.LIVE_PORT, down: env.DOWN_PORT };

/**
 * Raw HTTP, so the server sees the exact path (fetch would resolve `..` and `//`). Headers go
 * out as a raw list, so a list value is sent as repeated lines; Node then adds no Host itself.
 */
function request(
  port: number,
  method: string,
  path: string,
  headers: Headers,
  body?: Buffer,
): Promise<Reply> {
  const raw = ['Host', `127.0.0.1:${port}`];
  for (const [k, v] of Object.entries(headers)) for (const one of [v].flat()) raw.push(k, one);
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path, headers: raw }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () =>
        resolve({
          status: res.statusCode ?? 0,
          rawHeaders: res.rawHeaders,
          body: Buffer.concat(chunks),
        }),
      );
      res.on('error', reject);
    });
    req.on('error', reject);
    req.end(body);
  });
}

interface Send {
  method: string;
  path: string;
  headers?: Headers;
  json?: unknown;
  raw?: string;
}

/**
 * The managers trust the recorder as a proxy (TRUSTED_PROXIES), so a request that names no
 * client gets its case's own address, a /64 per case, and the login limiter counts each case
 * apart. Every request would otherwise count for 127.0.0.1 and pass the limit within the table.
 */
function caseClient(c: Case): string {
  return `2001:db8:1:${CASES.indexOf(c).toString(16)}::1`;
}

function send(c: Case, s: Send): Promise<Reply> {
  const headers: Headers = { ...BASE_HEADERS, ...s.headers };
  if (!c.direct && !Object.keys(headers).some((k) => k.toLowerCase() === 'x-forwarded-for')) {
    headers['X-Forwarded-For'] = caseClient(c);
  }
  let body: Buffer | undefined;
  if (s.json !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = Buffer.from(fill(JSON.stringify(s.json)));
  } else if (s.raw !== undefined) {
    body = Buffer.from(fill(s.raw));
  }
  if (body) headers['Content-Length'] = String(body.length);
  const lines = (c.cookies ?? [[c.auth ?? 'session']]).map((pairs) =>
    pairs
      .map(cookieValue)
      .filter((v) => v !== null)
      .map((v) => `lodeline_session=${v}`)
      .join('; '),
  );
  if (lines.some(Boolean)) headers.Cookie = lines;
  const port = PORTS[c.server ?? 'mock'];
  return request(port, s.method, fill(s.path), headers, body);
}

function headerValues(reply: Reply, name: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < reply.rawHeaders.length; i += 2) {
    if (reply.rawHeaders[i].toLowerCase() === name) out.push(reply.rawHeaders[i + 1]);
  }
  return out;
}

/** The dist file the case asked for, if its path names one; index.html for SPA fallbacks. */
function requestedFile(c: Case): string | null {
  const pathname = decodeURIComponent(fill(c.path).split('?')[0]);
  const file = join(DIST, pathname);
  if (existsSync(file) && statSync(file).isFile()) return file;
  return c.route === 'GET /*' ? join(DIST, 'index.html') : null;
}

/** A dist file by the name the table uses for it: its placeholder, or its path when unhashed. */
function distName(rel: string): string {
  return run.distNames.get(rel) ?? rel;
}

function recordHeaders(c: Case, reply: Reply): Record<string, string | string[]> {
  const grouped = new Map<string, string[]>();
  // With no body to frame, Content-Length is the size the server declares, so it is recorded.
  const declaredLength = c.method === 'HEAD' || reply.body.length === 0;
  for (let i = 0; i < reply.rawHeaders.length; i += 2) {
    const name = reply.rawHeaders[i].toLowerCase();
    if (UNRECORDED_HEADERS.has(name) && !(name === 'content-length' && declaredLength)) continue;
    let v = reply.rawHeaders[i + 1];
    const file = name === 'content-length' && v !== '0' ? requestedFile(c) : null;
    if (file && readFileSync(file).length === Number(v)) {
      v = `<size of ${distName(relative(DIST, file))}>`;
    }
    // Go answers 429 with the seconds left in a 60 s window, plus 1, so a full window is 60 or 61.
    if (name === 'retry-after' && reply.status === 429 && /^(59|60|61)$/.test(v)) v = '<59..61>';
    const range = name === 'content-range' ? /^bytes (\d+-\d+)\/(\d+)$/.exec(v) : null;
    const ranged = range ? requestedFile(c) : null;
    if (range && ranged && readFileSync(ranged).length === Number(range[2])) {
      v = `bytes ${range[1]}/<size of ${distName(relative(DIST, ranged))}>`;
    }
    grouped.set(name, [...(grouped.get(name) ?? []), v]);
  }
  const out: Record<string, string | string[]> = {};
  for (const name of [...grouped.keys()].sort()) {
    const vs = grouped.get(name) ?? [];
    out[name] = vs.length === 1 ? vs[0] : vs;
  }
  return out;
}

/** Go's directory listing: the entries become one token when they are exactly dist/assets. */
function recordListing(text: string): string {
  const entries = text.match(/^<a href=".*<\/a>$/gm) ?? [];
  const block = entries.join('\n');
  const expected = run.assetFiles.map((n) => `<a href="${n}">${n}</a>`).join('\n');
  if (block === expected) return text.replace(block, '<every file in dist/assets, sorted>');
  const stripped = entries.map((e) => e.replace(/-[\w-]{8}(\.\w+)(?=["<])/g, '-<hash>$1')).sort();
  return text.replace(block, stripped.join('\n'));
}

/** JSON is compared parsed; SPA files by identity with web/dist; other bodies as short text or a hash. */
function recordBody(c: Case, reply: Reply, ctx: NormalizeContext): unknown {
  const bytes = reply.body;
  if (bytes.length === 0) return '';
  const text = bytes.toString('utf8');
  if ((headerValues(reply, 'content-type')[0] ?? '').includes('json')) {
    try {
      return normalizeJson(JSON.parse(text), ctx);
    } catch {
      return { unparsed: text };
    }
  }
  const dist = run.distByHash.get(sha256(bytes));
  if (dist) return `<dist:${distName(dist)}>`;
  const range = /^bytes (\d+)-(\d+)\//.exec(headerValues(reply, 'content-range')[0] ?? '');
  const file = range ? requestedFile(c) : null;
  if (range && file) {
    const slice = readFileSync(file).subarray(Number(range[1]), Number(range[2]) + 1);
    if (slice.equals(bytes))
      return `<dist:${distName(relative(DIST, file))} bytes ${range[1]}-${range[2]}>`;
  }
  if (c.listing) return recordListing(text);
  if (bytes.length <= 4096) return text;
  return `<sha256:${sha256(bytes)} ${bytes.length} bytes>`;
}

function readBrackets(): Bracket[] {
  if (!existsSync(BRACKETS)) return [];
  const byLabel = new Map<string, Bracket>();
  for (const line of readFileSync(BRACKETS, 'utf8').split('\n').filter(Boolean)) {
    const b = JSON.parse(line) as Bracket;
    byLabel.delete(b.label);
    byLabel.set(b.label, b);
  }
  return [...byLabel.values()];
}

function saveBracket(b: Bracket): void {
  appendFileSync(BRACKETS, `${JSON.stringify(b)}\n`);
}

async function recordCase(c: Case): Promise<Record<string, unknown>> {
  if (c.upstream) {
    await fetch(`${env.STUB_URL}/__stub/reply`, {
      method: 'POST',
      body: JSON.stringify(c.upstream),
    });
  }
  for (const [i, step] of (c.prelude ?? []).entries()) {
    for (let n = 0; n < (step.count ?? 1); n++) {
      const reply = await send(c, { method: c.method, path: c.path, ...step });
      expect(reply.status, `${c.name} prelude step ${i} request ${n + 1}`).toBe(step.status);
    }
  }
  const startMs = Date.now();
  const reply = await send(c, c);
  const endMs = Date.now();
  const elapsed = endMs - startMs;
  if (c.minMs !== undefined) {
    expect(elapsed, `${c.name} must take at least ${c.minMs} ms`).toBeGreaterThanOrEqual(c.minMs);
  }
  if (c.maxMs !== undefined) {
    expect(elapsed, `${c.name} must take at most ${c.maxMs} ms`).toBeLessThanOrEqual(c.maxMs);
  }
  const current: Bracket = { label: c.name, startMs, endMs };
  const ctx: NormalizeContext = {
    seedMs: (c.server ?? 'mock') === 'mock' ? run.seedMs : null,
    current,
    earlier: readBrackets(),
    ttlHours: env.JWT_TTL_HOURS,
    eventIds: run.eventIds,
    fixedWidthTimestamps: c.path.startsWith('/api/v1/triage/'),
  };
  const record: Record<string, unknown> = {
    request: { method: c.method, path: c.path, server: c.server ?? 'mock' },
    status: reply.status,
    headers: recordHeaders(c, reply),
    cookies: headerValues(reply, 'set-cookie').map((h) => parseSetCookie(h, ctx)),
    body: recordBody(c, reply, ctx),
  };
  if (c.rawText) {
    const text = reply.body.toString('utf8');
    const parsed = typeof record.body === 'object' && !('unparsed' in (record.body ?? {}));
    record.rawText = Object.fromEntries(
      c.rawText.map((p) => [p, (parsed ? rawJsonAt(text, p) : undefined) ?? null]),
    );
  }
  const body = record.body as Record<string, unknown>;
  // The build stamps its own version string into /api/health; an empty one stays raw.
  if (c.route === 'GET /api/health' && typeof body?.version === 'string' && body.version !== '')
    body.version = '<version>';
  if (c.upstream) {
    record.upstream = await (await fetch(`${env.STUB_URL}/__stub/calls`)).json();
  }
  saveBracket(current);
  await sleep(GAP_MS);
  return record;
}

/** The record and the golden with the case's allowlist entries applied. */
function allowlisted(name: string, record: Rec, golden: Rec): [Rec, Rec] {
  const [r, g] = [structuredClone(record), structuredClone(golden)];
  for (const e of ALLOWLIST) {
    if (!e.cases.includes(name)) continue;
    if (e.rule === 'null-or-absent') {
      for (const v of [r, g]) dropNullAt(v, e.path.split('.'));
    } else if (Object.entries(e.record).every(([k, v]) => isDeepStrictEqual(r[k], v))) {
      // A record that is exactly the stated alternative compares as the golden.
      for (const k of Object.keys(e.record)) r[k] = g[k];
    }
  }
  return [r, g];
}

function securityHeaders(record: Rec): Rec {
  const headers = record.headers as Rec;
  return Object.fromEntries(SECURITY_HEADERS.map((h) => [h, headers[h]]));
}

/** Refuses to write goldens or testdata from anything but the Go reference build. */
async function checkReference(): Promise<void> {
  if (!env.UPDATE && !env.WRITE_TESTDATA) return;
  const { version } = (await (await fetch(`${env.MOCK_URL}/api/health`)).json()) as {
    version: string;
  };
  if (String(version).startsWith(GO_REFERENCE)) return;
  const msg = `MANAGER_BIN reports version "${version}", not the Go reference ${GO_REFERENCE}`;
  if (!env.ALLOW_ANY_REFERENCE) {
    throw new Error(`${msg}. Refusing to write goldens; see tests/parity/README.md.`);
  }
  console.warn(
    `\n!!! PARITY_ALLOW_ANY_REFERENCE=1: ${msg}. Goldens written now are not Go's. !!!\n`,
  );
}

test.beforeAll(async () => {
  await checkReference();
  // A worker restarted after a failure logs in again; keep that login's second to itself too.
  if (readBrackets().length > 0) await sleep(LOGIN_PAUSE_MS);
  const startMs = Date.now();
  const login = await fetch(`${env.MOCK_URL}/api/v1/auth/login`, {
    method: 'POST',
    // A client of its own, so no case's limiter window holds this login.
    headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': '2001:db8:2::1' },
    body: JSON.stringify({ username: env.ADMIN_USERNAME, password: env.ADMIN_PASSWORD }),
  });
  saveBracket({ label: 'recorder-login', startMs, endMs: Date.now() });
  expect(login.status, 'recorder login').toBe(200);
  const session = /^lodeline_session=([^;]+)/.exec(login.headers.getSetCookie()[0] ?? '')?.[1];
  expect(session, 'session cookie').toBeTruthy();
  const healthz = await fetch(`${env.MOCK_URL}/api/v1/fleet/healthz`, {
    headers: { Cookie: `lodeline_session=${session}` },
  });
  const ts = ((await healthz.json()) as { ts: string }).ts;
  // Go anchors the mock at process start, truncated to the second.
  expect(ts, 'mock seed is a whole second').toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
  const seedMs = Date.parse(ts);
  expect(seedMs, 'mock seed not before the run').toBeGreaterThanOrEqual(
    Math.floor(env.RUN_START_MS / 1000) * 1000,
  );
  expect(seedMs, 'mock seed not in the future').toBeLessThanOrEqual(Date.now());

  const distByHash = new Map<string, string>();
  for (const f of walkFiles(DIST)) distByHash.set(sha256(readFileSync(f)), relative(DIST, f));
  const entryScript = /src="(\/assets\/index-[^"]+\.js)"/.exec(
    readFileSync(join(DIST, 'index.html'), 'utf8'),
  )?.[1];
  expect(entryScript, 'entry script in dist/index.html').toBeTruthy();
  const entryStyle = /href="(\/assets\/index-[^"]+\.css)"/.exec(
    readFileSync(join(DIST, 'index.html'), 'utf8'),
  )?.[1];
  expect(entryStyle, 'entry stylesheet in dist/index.html').toBeTruthy();
  const distNames = new Map([
    [entryScript!.slice(1), '{asset:js}'],
    [entryStyle!.slice(1), '{asset:css}'],
  ]);
  for (const rel of distByHash.values()) {
    if (HASHED.test(rel) && !distNames.has(rel)) distNames.set(rel, `unrequested ${rel}`);
  }

  run = {
    session: session!,
    seedMs,
    eventIds: mockEventIds(seedMs, MOCK_EVENT_COUNT),
    distByHash,
    distNames,
    assetFiles: readdirSync(join(DIST, 'assets')).sort(),
    entryScript: entryScript!,
    entryStyle: entryStyle!,
  };
  await sleep(LOGIN_PAUSE_MS);
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

test('every allowlist entry names a reason and known cases', () => {
  for (const e of ALLOWLIST) {
    const what = e.rule === 'null-or-absent' ? e.path : `alternative for ${e.cases}`;
    expect(e.reason.trim().length, `reason for ${what}`).toBeGreaterThan(0);
    expect(['null-or-absent', 'alternative']).toContain(e.rule);
    if (e.rule === 'alternative') {
      expect(Object.keys(e.record).length, what).toBeGreaterThan(0);
      for (const k of Object.keys(e.record)) expect(RECORD_KEYS, what).toContain(k);
    }
    expect(e.cases.length, `cases for ${what}`).toBeGreaterThan(0);
    for (const name of e.cases) {
      expect(
        CASES.some((c) => c.name === name),
        `case ${name}`,
      ).toBe(true);
    }
  }
});

for (const c of CASES) {
  test(c.name, async () => {
    // In the form a golden holds it: JSON has no Infinity, so a relayed `1e400` reads as null.
    const record = JSON.parse(JSON.stringify(await recordCase(c)));
    const file = join(GOLDENS, `${c.name}.json`);
    if (env.UPDATE) {
      writeFileSync(file, `${JSON.stringify(record, null, 2)}\n`);
      return;
    }
    const golden = JSON.parse(readFileSync(file, 'utf8'));
    // Checked on its own first, so a run shows them even where the rest of the record differs.
    expect(securityHeaders(record), 'security headers').toEqual(securityHeaders(golden));
    const [r, g] = allowlisted(c.name, record, golden);
    expect(r).toEqual(g);
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
