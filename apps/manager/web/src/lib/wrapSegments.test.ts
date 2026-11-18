import { describe, expect, it } from 'vitest';
import { wrapSegments } from './wrapSegments';

const words = (segments: string[]) => segments.filter((s) => !/^\s+$/.test(s));

describe('wrapSegments', () => {
  it('returns the text unchanged when joined', () => {
    const text = 'rm -rf /tmp/build-cache && echo "done"\n  next-line';
    expect(wrapSegments(text).join('')).toBe(text);
  });

  it('keeps short text in one piece', () => {
    expect(wrapSegments('host-1')).toEqual(['host-1']);
  });

  it('offers a break after a hyphen, slash or dot in an id or path', () => {
    const id = 'c0a80101-5b2e-4d6f-9a3c-1f2e3d4c5b6a';
    const segments = wrapSegments(id);
    expect(segments.length).toBeGreaterThan(1);
    expect(segments.join('')).toBe(id);
    expect(wrapSegments('/home/alice/.claude/settings.json').length).toBeGreaterThan(2);
  });

  it('chops a long hash into groups so no line can hold a lone character', () => {
    for (const n of [17, 25, 33, 40, 64, 65, 97]) {
      const hash = 'a1b2c3d4e5f60718'.repeat(8).slice(0, n);
      const segments = wrapSegments(hash);
      expect(segments.join('')).toBe(hash);
      for (const s of segments) expect(s.length).toBeGreaterThanOrEqual(4);
      for (const s of segments) expect(s.length).toBeLessThanOrEqual(12);
    }
  });

  it('never splits whitespace from the text around it', () => {
    const segments = wrapSegments('echo   hi');
    expect(segments.join('')).toBe('echo   hi');
    expect(words(segments)).toEqual(['echo', 'hi']);
  });
});
