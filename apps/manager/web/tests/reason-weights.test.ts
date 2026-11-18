import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { DEFAULT_REASON_WEIGHTS } from '@/lib/reasonWeights';

const RUBRIC = resolve(process.cwd(), '../../../crates/lodeline-agent/src/ai_guard/rubric.rs');

function rubricDefaults(): Record<string, number> {
  const out: Record<string, number> = {};
  for (const m of readFileSync(RUBRIC, 'utf8').matchAll(/w\.insert\("([a-z_]+)",\s*([0-9.]+)\)/g)) {
    out[m[1]] = Number(m[2]);
  }
  return out;
}

describe('DEFAULT_REASON_WEIGHTS', () => {
  it('matches the agent rubric defaults, kind for kind', () => {
    expect(Object.keys(rubricDefaults()).length).toBeGreaterThan(30);
    expect(DEFAULT_REASON_WEIGHTS).toEqual(rubricDefaults());
  });
});
