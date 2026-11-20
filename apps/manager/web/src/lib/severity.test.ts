import { describe, expect, it } from 'vitest';
import { bucketTextColor, effectiveBucket, scoreBucket } from './severity';

describe('bucketTextColor', () => {
  it('maps each known bucket to its sev text token', () => {
    expect(bucketTextColor('critical')).toBe('text-sev-critical');
    expect(bucketTextColor('high')).toBe('text-sev-high');
    expect(bucketTextColor('medium')).toBe('text-sev-medium');
    expect(bucketTextColor('low')).toBe('text-sev-low');
  });

  it('falls back to the info token for unknown/future buckets', () => {
    expect(bucketTextColor('info')).toBe('text-sev-info');
    expect(bucketTextColor('whatever')).toBe('text-sev-info');
    expect(bucketTextColor('')).toBe('text-sev-info');
  });

  it('derives a background token via the documented replace idiom', () => {
    expect(bucketTextColor('critical').replace('text-', 'bg-')).toBe('bg-sev-critical');
  });
});

describe('an unknown bucket with a score', () => {
  it('takes the color of the bucket its score falls in', () => {
    expect(bucketTextColor('severe', 0.5)).toBe('text-sev-low');
    expect(bucketTextColor('severe', 3)).toBe('text-sev-medium');
    expect(bucketTextColor('severe', 6)).toBe('text-sev-high');
    expect(bucketTextColor('severe', 8)).toBe('text-sev-critical');
  });

  it('keeps a known bucket color whatever the score', () => {
    expect(bucketTextColor('low', 9)).toBe('text-sev-low');
    expect(bucketTextColor('critical', 0)).toBe('text-sev-critical');
  });

  it('keeps the info color for an unknown bucket with no usable score', () => {
    expect(bucketTextColor('severe')).toBe('text-sev-info');
    expect(bucketTextColor('severe', null)).toBe('text-sev-info');
    expect(bucketTextColor('severe', Number.NaN)).toBe('text-sev-info');
  });
});

describe('scoreBucket', () => {
  it('cuts at 1, 4 and 7', () => {
    expect(
      [0, 0.99, 1, 3.99, 4, 6.99, 7, 10].map((s) => scoreBucket(s)),
    ).toEqual(['low', 'low', 'medium', 'medium', 'high', 'high', 'critical', 'critical']);
  });

  it('leaves a known bucket name alone in effectiveBucket', () => {
    expect(effectiveBucket('info', 9)).toBe('info');
    expect(effectiveBucket('medium', 9)).toBe('medium');
    expect(effectiveBucket('severe', 9)).toBe('critical');
  });
});
