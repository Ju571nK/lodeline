import { createHash } from 'node:crypto';

/**
 * Turns one recorded response into a run-independent value. Every rule here
 * is listed in tests/parity/README.md with its reason; add a rule there when
 * you add one here.
 */

/** When one recorded request ran, by the recorder's clock: [startMs, endMs] from send to last byte. */
export interface Bracket {
  label: string;
  startMs: number;
  endMs: number;
}

export interface NormalizeContext {
  /** Mock fleet seed in ms (from /api/v1/fleet/healthz `ts`), or null for live-mode cases. */
  seedMs: number | null;
  /** The request this response answers. */
  current: Bracket;
  /** Requests recorded before this one, oldest first; a body can carry times they wrote. */
  earlier: readonly Bracket[];
  /** Session lifetime the server was started with. */
  ttlHours: number;
  /** Mock event IDs computed from the seed, mapped to `EVT#<recipe index>`. */
  eventIds: ReadonlyMap<string, string>;
  /** True for /api/v1/triage/* bodies, whose timestamps use a fixed-width layout. */
  fixedWidthTimestamps: boolean;
}

const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/;

/** Keys whose timestamps come from the server's clock while handling a request. */
const REQUEST_CLOCK_KEYS = new Set(['created_at', 'updated_at', 'at', 'timestamp']);
// Covers the millisecond rounding of Date.now(); the recorder leaves a wider gap between requests.
const CLOCK_SLACK_NS = 2_000_000n;
const MS = 1_000_000n;
const IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const DOC_IPV4 = /^(127\.0\.0\.1|0\.0\.0\.0|192\.0\.2\.\d+|198\.51\.100\.\d+|203\.0\.113\.\d+)$/;

/** Event ID the Go mock assigns to recipe `index` (internal/fleet/mock.go uuidv7At). */
export function mockEventId(seedMs: number, index: number, total: number): string {
  const ms = BigInt(seedMs - index * 44 * 60_000);
  const counter = BigInt(total - index);
  const hex = (v: bigint, width: number) => v.toString(16).padStart(width, '0');
  const hi32 = (ms >> 16n) & 0xffffffffn;
  const mid16 = ms & 0xffffn;
  const rand1 = counter & 0xfffn;
  const rand2 = (counter >> 12n) & 0xfffn;
  const rand3 = (counter >> 24n) & 0xffffffffffffn;
  return `${hex(hi32, 8)}-${hex(mid16, 4)}-7${hex(rand1, 3)}-8${hex(rand2, 3)}-${hex(rand3, 12)}`;
}

export function mockEventIds(seedMs: number, total: number): Map<string, string> {
  const out = new Map<string, string>();
  for (let i = 0; i < total; i++) out.set(mockEventId(seedMs, i, total), `EVT#${i}`);
  return out;
}

/** Layout tag: fraction width and zone. Width is exact only where the layout is fixed. */
function layoutTag(m: RegExpExecArray, fixedWidth: boolean): string {
  const frac = m[2];
  const zone = m[3];
  if (frac === undefined) return zone;
  return `.${fixedWidth ? frac.length : 'f'}${zone}`;
}

function toNs(s: string, m: RegExpExecArray): bigint {
  const wholeMs = Date.parse(s.replace(/\.\d+/, ''));
  return BigInt(wholeMs) * 1_000_000n + BigInt((m[2] ?? '').padEnd(9, '0') || '0');
}

function offsetLabel(deltaMs: number): string {
  const sign = deltaMs < 0 ? '-' : '+';
  const abs = Math.abs(deltaMs);
  if (abs % 3_600_000 === 0) return `${sign}${abs / 3_600_000}h`;
  if (abs % 60_000 === 0) return `${sign}${abs / 60_000}m`;
  if (abs % 1_000 === 0) return `${sign}${abs / 1_000}s`;
  return `${sign}${abs}ms`;
}

/** Nanoseconds one unit of the value's last digit spans: a value truncated to it covers [ns, ns + unit). */
function unitNs(m: RegExpExecArray): bigint {
  return 10n ** BigInt(9 - (m[2]?.length ?? 0));
}

function within(ns: bigint, unit: bigint, b: Bracket): boolean {
  return (
    ns + unit > BigInt(b.startMs) * MS - CLOCK_SLACK_NS &&
    ns < BigInt(b.endMs + 1) * MS + CLOCK_SLACK_NS
  );
}

/** The request whose clock produced this instant: the current one, an earlier one, or none. */
function clockSource(ns: bigint, unit: bigint, ctx: NormalizeContext): Bracket | undefined {
  if (within(ns, unit, ctx.current)) return ctx.current;
  return ctx.earlier.find((b) => within(ns, unit, b));
}

function ipToken(ip: string): string {
  if (DOC_IPV4.test(ip)) return ip;
  return `<ipv4 ${createHash('sha256').update(ip).digest('hex').slice(0, 8)}>`;
}

/** Collects request-clock timestamps so equal instants share a rank within a case. */
function collectClock(value: unknown, key: string, ctx: NormalizeContext, out: bigint[]): void {
  if (typeof value === 'string') {
    const m = RFC3339.exec(value);
    if (!m || !REQUEST_CLOCK_KEYS.has(key)) return;
    const ns = toNs(value, m);
    if (within(ns, unitNs(m), ctx.current)) out.push(ns);
  } else if (Array.isArray(value)) {
    for (const v of value) collectClock(v, key, ctx, out);
  } else if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) collectClock(v, k, ctx, out);
  }
}

function normalizeString(s: string, key: string, ctx: NormalizeContext, ranks: bigint[]): string {
  const evt = ctx.eventIds.get(s);
  if (evt) return evt;
  const m = RFC3339.exec(s);
  if (m) return normalizeTimestamp(s, m, key, ctx, ranks);
  return s.replace(IPV4, ipToken);
}

function normalizeTimestamp(
  s: string,
  m: RegExpExecArray,
  key: string,
  ctx: NormalizeContext,
  ranks: bigint[],
): string {
  const ns = toNs(s, m);
  if (REQUEST_CLOCK_KEYS.has(key)) {
    if (ctx.fixedWidthTimestamps && m[2]?.length !== 9) return s;
    const layout = layoutTag(m, ctx.fixedWidthTimestamps);
    const src = clockSource(ns, unitNs(m), ctx);
    if (src === ctx.current) return `<now#${ranks.indexOf(ns) + 1} ${layout}>`;
    return src ? `<now@${src.label} ${layout}>` : s;
  }
  if (key === 'expires_at') return expiryToken(ns, unitNs(m), layoutTag(m, false), ctx) ?? s;
  if (ctx.seedMs === null) return s;
  return `<seed${offsetLabel(Date.parse(s) - ctx.seedMs)} ${layoutTag(m, false)}>`;
}

/**
 * A session expiry is `issuing request time + TTL`, where the issuing request is this one or an
 * earlier one (the recorder's login for /auth/me). Anything else stays raw so it shows in the diff.
 */
export function expiryToken(
  ns: bigint,
  unit: bigint,
  layout: string,
  ctx: NormalizeContext,
): string | null {
  const src = clockSource(ns - BigInt(ctx.ttlHours) * 3_600_000n * MS, unit, ctx);
  if (!src) return null;
  return `<now${src === ctx.current ? '' : `@${src.label}`}+${ctx.ttlHours}h ${layout}>`;
}

function walk(value: unknown, key: string, ctx: NormalizeContext, ranks: bigint[]): unknown {
  if (typeof value === 'string') return normalizeString(value, key, ctx, ranks);
  if (Array.isArray(value)) return value.map((v) => walk(v, key, ctx, ranks));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value).sort()) {
      out[k] = walk((value as Record<string, unknown>)[k], k, ctx, ranks);
    }
    return out;
  }
  return value;
}

/** Normalizes a parsed JSON body. Object keys come back sorted so goldens diff cleanly. */
export function normalizeJson(value: unknown, ctx: NormalizeContext): unknown {
  const found: bigint[] = [];
  collectClock(value, '', ctx, found);
  const ranks = [...new Set(found)].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return walk(value, '', ctx, ranks);
}

export interface ParsedCookie {
  name: string;
  value: string;
  /** In the order sent, each name in the case sent. */
  attributes: [string, string | true][];
}

const WEEKDAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const IMF_FIXDATE = /^(\w{3}), \d{2} \w{3} \d{4} \d\d:\d\d:\d\d GMT$/;

/** The instant an IMF-fixdate (RFC 9110) names, or NaN when its shape or weekday is wrong. */
export function imfFixdate(v: string): number {
  const m = IMF_FIXDATE.exec(v);
  const t = m ? Date.parse(v) : Number.NaN;
  return !Number.isNaN(t) && WEEKDAYS[new Date(t).getUTCDay()] === m?.[1] ? t : Number.NaN;
}

/** Splits one Set-Cookie header; the value is reduced to `<set>` or empty. */
export function parseSetCookie(header: string, ctx: NormalizeContext): ParsedCookie {
  const [pair, ...attrs] = header.split(';').map((p) => p.trim());
  const eq = pair.indexOf('=');
  const attributes: [string, string | true][] = attrs.map((a) => {
    const i = a.indexOf('=');
    const name = i < 0 ? a : a.slice(0, i);
    let v: string | true = i < 0 ? true : a.slice(i + 1);
    const t =
      name.toLowerCase() === 'expires' && typeof v === 'string' ? imfFixdate(v) : Number.NaN;
    if (!Number.isNaN(t)) v = expiryToken(BigInt(t) * MS, 1000n * MS, 'http-date', ctx) ?? v;
    return [name, v];
  });
  return {
    name: pair.slice(0, eq),
    value: pair.slice(eq + 1) === '' ? '' : '<set>',
    attributes,
  };
}

/** Removes `null` at the given dot paths (`*` matches any key or index). */
export function dropNullAt(value: unknown, path: string[]): void {
  if (!value || typeof value !== 'object' || path.length === 0) return;
  const [head, ...rest] = path;
  const obj = value as Record<string, unknown>;
  const keys = head === '*' ? Object.keys(obj) : [head];
  for (const k of keys) {
    if (!(k in obj)) continue;
    if (rest.length === 0) {
      if (obj[k] === null) delete obj[k];
    } else {
      dropNullAt(obj[k], rest);
    }
  }
}
