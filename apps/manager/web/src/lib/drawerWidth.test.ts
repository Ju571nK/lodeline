import { describe, expect, it } from 'vitest';
import {
  clampWidth,
  defaultWidth,
  isFullWidth,
  loadWidth,
  MIN_WIDTH,
  STORAGE_KEY,
  saveWidth,
} from './drawerWidth';

function memoryStorage(initial: Record<string, string> = {}) {
  const data = { ...initial };
  return {
    data,
    getItem: (k: string) => data[k] ?? null,
    setItem: (k: string, v: string) => {
      data[k] = v;
    },
  };
}

const throwing = {
  getItem: () => {
    throw new Error('blocked');
  },
  setItem: () => {
    throw new Error('blocked');
  },
};

describe('drawer width', () => {
  it('is wider on large windows than the old fixed 420 px', () => {
    expect(defaultWidth(1800)).toBeGreaterThan(800);
    expect(defaultWidth(1280)).toBeGreaterThan(560);
    expect(defaultWidth(1000)).toBeGreaterThan(MIN_WIDTH);
  });

  it('never starts outside the range a drag can reach', () => {
    for (const vw of [900, 1000, 1280, 1600, 1800, 2560]) {
      expect(defaultWidth(vw)).toBe(clampWidth(defaultWidth(vw), vw));
    }
  });

  it('takes the full width under 900 px only', () => {
    expect(isFullWidth(899)).toBe(true);
    expect(isFullWidth(900)).toBe(false);
  });

  it('keeps a dragged width between the minimum and the room beside the list', () => {
    expect(clampWidth(100, 1800)).toBe(MIN_WIDTH);
    expect(clampWidth(5000, 1800)).toBe(960);
    expect(clampWidth(5000, 1000)).toBe(760);
    expect(clampWidth(700, 1800)).toBe(700);
  });

  it('remembers the width per viewer and reads it back', () => {
    const s = memoryStorage();
    saveWidth(733, s);
    expect(s.data[STORAGE_KEY]).toBe('733');
    expect(loadWidth(s)).toBe(733);
  });

  it('ignores a stored value that is not a usable width', () => {
    expect(loadWidth(memoryStorage({ [STORAGE_KEY]: 'wide' }))).toBeNull();
    expect(loadWidth(memoryStorage({ [STORAGE_KEY]: '-5' }))).toBeNull();
    expect(loadWidth(memoryStorage())).toBeNull();
  });

  it('survives storage that throws', () => {
    expect(loadWidth(throwing)).toBeNull();
    expect(() => saveWidth(700, throwing)).not.toThrow();
  });
});
