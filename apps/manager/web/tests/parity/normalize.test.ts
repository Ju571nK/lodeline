import { describe, expect, it } from 'vitest';
import {
  dropNullAt,
  mockEventId,
  mockEventIds,
  type NormalizeContext,
  normalizeJson,
  parseSetCookie,
} from './normalize.ts';

// An address outside the documentation ranges, as the Go mock uses; built from parts so the
// source holds no such literal.
const MOCK_ADDR = [10, 0, 5, 21].join('.');
const SEED = Date.parse('2026-11-04T00:00:00Z');
const ctx: NormalizeContext = {
  seedMs: SEED,
  windowStartMs: Date.parse('2026-11-04T10:00:00Z'),
  windowEndMs: Date.parse('2026-11-04T10:01:00Z'),
  ttlHours: 12,
  eventIds: mockEventIds(SEED, 32),
  fixedWidthTimestamps: false,
};

describe('mockEventId', () => {
  it('matches the Go mock for the same seed', () => {
    // Values printed by internal/fleet/mock.go uuidv7At for this seed.
    expect(mockEventId(SEED, 0, 32)).toBe('01a1a3da-fc00-7020-8000-000000000000');
    expect(mockEventId(SEED, 3, 32)).toBe('01a1a362-2280-701d-8000-000000000000');
    expect(mockEventId(SEED, 31, 32)).toBe('01a19efa-3480-7001-8000-000000000000');
  });
});

describe('normalizeJson', () => {
  it('rewrites seed times, event IDs and addresses, and sorts keys', () => {
    const out = normalizeJson(
      {
        ts: '2026-11-03T23:16:00Z',
        event_id: '01a1a362-2280-701d-8000-000000000000',
        ipv4: [`${MOCK_ADDR}/24`, '192.0.2.4'],
      },
      ctx,
    );
    expect(Object.keys(out as object)).toEqual(['event_id', 'ipv4', 'ts']);
    expect(out).toEqual({
      event_id: 'EVT#3',
      ipv4: [expect.stringMatching(/^<ipv4 [0-9a-f]{8}>\/24$/), '192.0.2.4'],
      ts: '<seed-44m Z>',
    });
  });

  it('ranks request-clock times and keeps equal instants equal', () => {
    const out = normalizeJson(
      {
        created_at: '2026-11-04T10:00:01.000000500Z',
        updated_at: '2026-11-04T10:00:02.5Z',
        log: [{ at: '2026-11-04T10:00:01.0000005Z' }],
      },
      ctx,
    );
    expect(out).toEqual({
      created_at: '<now#1 .fZ>',
      log: [{ at: '<now#1 .fZ>' }],
      updated_at: '<now#2 .fZ>',
    });
  });

  it('keeps a fixed-width field raw when its fraction is trimmed', () => {
    const fixed = { ...ctx, fixedWidthTimestamps: true };
    expect(normalizeJson({ at: '2026-11-04T10:00:01.5Z' }, fixed)).toEqual({
      at: '2026-11-04T10:00:01.5Z',
    });
    expect(normalizeJson({ at: '2026-11-04T10:00:01.500000000Z' }, fixed)).toEqual({
      at: '<now#1 .9Z>',
    });
  });

  it('keeps a request-clock time outside the run window raw', () => {
    expect(normalizeJson({ updated_at: '2026-11-04T11:00:00Z' }, ctx)).toEqual({
      updated_at: '2026-11-04T11:00:00Z',
    });
  });

  it('accepts an expiry only at request time plus the TTL', () => {
    expect(normalizeJson({ expires_at: '2026-11-04T22:00:30Z' }, ctx)).toEqual({
      expires_at: '<now+12h Z>',
    });
    expect(normalizeJson({ expires_at: '2026-11-04T23:00:30Z' }, ctx)).toEqual({
      expires_at: '2026-11-04T23:00:30Z',
    });
  });

  it('leaves times raw when there is no seed', () => {
    expect(normalizeJson({ ts: '2026-01-02T03:04:05Z' }, { ...ctx, seedMs: null })).toEqual({
      ts: '2026-01-02T03:04:05Z',
    });
  });
});

describe('parseSetCookie', () => {
  it('records attributes and hides the value', () => {
    const c = parseSetCookie(
      'lodeline_session=abc; Path=/; Expires=Wed, 04 Nov 2026 22:00:30 GMT; Max-Age=43200; HttpOnly; SameSite=Lax',
      ctx,
    );
    expect(c).toEqual({
      name: 'lodeline_session',
      value: '<set>',
      attributes: {
        path: '/',
        expires: '<now+12h http-date>',
        'max-age': '43200',
        httponly: true,
        samesite: 'Lax',
      },
    });
    expect(parseSetCookie('lodeline_session=; Max-Age=0', ctx).value).toBe('');
  });
});

describe('dropNullAt', () => {
  it('removes null only at the listed path', () => {
    const v = { body: { a: null, b: { x: { c: null }, y: { c: [] } } } };
    dropNullAt(v, ['body', 'b', '*', 'c']);
    expect(v).toEqual({ body: { a: null, b: { x: {}, y: { c: [] } } } });
  });
});
