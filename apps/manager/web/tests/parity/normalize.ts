import { createHash } from 'node:crypto';

/**
 * Turns one recorded response into a run-independent value. Every rule here
 * is listed in tests/parity/README.md with its reason; add a rule there when
 * you add one here.
 */

export interface NormalizeContext {
  /** Mock fleet seed in ms (from /api/v1/fleet/healthz `ts`), or null for live-mode cases. */
  seedMs: number | null;
  /** Earliest and latest instant a request-clock value may carry in this run. */
  windowStartMs: number;
  windowEndMs: number;
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
const CLOCK_SLACK_MS = 2_000;
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

function inWindow(ms: number, ctx: NormalizeContext): boolean {
  return ms >= ctx.windowStartMs - CLOCK_SLACK_MS && ms <= ctx.windowEndMs + CLOCK_SLACK_MS;
}

function ipToken(ip: string): string {
  if (DOC_IPV4.test(ip)) return ip;
  return `<ipv4 ${createHash('sha256').update(ip).digest('hex').slice(0, 8)}>`;
}

/** Collects request-clock timestamps so equal instants share a rank within a case. */
function collectClock(value: unknown, key: string, out: bigint[]): void {
  if (typeof value === 'string') {
    const m = RFC3339.exec(value);
    if (m && REQUEST_CLOCK_KEYS.has(key)) out.push(toNs(value, m));
  } else if (Array.isArray(value)) {
    for (const v of value) collectClock(v, key, out);
  } else if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) collectClock(v, k, out);
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
  const ms = Date.parse(s);
  if (REQUEST_CLOCK_KEYS.has(key)) {
    if (ctx.fixedWidthTimestamps && m[2]?.length !== 9) return s;
    if (!inWindow(ms, ctx)) return s;
    const rank = ranks.indexOf(toNs(s, m)) + 1;
    return `<now#${rank} ${layoutTag(m, ctx.fixedWidthTimestamps)}>`;
  }
  if (key === 'expires_at') return expiryToken(ms, layoutTag(m, false), ctx) ?? s;
  if (ctx.seedMs === null) return s;
  return `<seed${offsetLabel(ms - ctx.seedMs)} ${layoutTag(m, false)}>`;
}

/** A session expiry is `request time + TTL`; anything else stays raw so it shows in the diff. */
export function expiryToken(ms: number, layout: string, ctx: NormalizeContext): string | null {
  const issuedMs = ms - ctx.ttlHours * 3_600_000;
  return inWindow(issuedMs, ctx) ? `<now+${ctx.ttlHours}h ${layout}>` : null;
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
  collectClock(value, '', found);
  const ranks = [...new Set(found)].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return walk(value, '', ctx, ranks);
}

export interface ParsedCookie {
  name: string;
  value: string;
  attributes: Record<string, string | true>;
}

/** Splits one Set-Cookie header; the value is reduced to `<set>` or empty. */
export function parseSetCookie(header: string, ctx: NormalizeContext): ParsedCookie {
  const [pair, ...attrs] = header.split(';').map((p) => p.trim());
  const eq = pair.indexOf('=');
  const attributes: Record<string, string | true> = {};
  for (const a of attrs) {
    const i = a.indexOf('=');
    const name = (i < 0 ? a : a.slice(0, i)).toLowerCase();
    let v: string | true = i < 0 ? true : a.slice(i + 1);
    if (name === 'expires' && typeof v === 'string')
      v = expiryToken(Date.parse(v), 'http-date', ctx) ?? v;
    attributes[name] = v;
  }
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
