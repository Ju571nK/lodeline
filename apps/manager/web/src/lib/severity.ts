import type { JsonNumber } from '@/api/client';

const KNOWN_BUCKETS = ['critical', 'high', 'medium', 'low', 'info'];

/** The bucket a score falls in: low below 1, medium below 4, high below 7, critical from 7. */
export function scoreBucket(score: number): 'low' | 'medium' | 'high' | 'critical' {
  if (score >= 7) return 'critical';
  if (score >= 4) return 'high';
  if (score >= 1) return 'medium';
  return 'low';
}

/**
 * The bucket to rank and color a reading by: a bucket name this build knows stays as it is,
 * an unknown one takes the bucket its score falls in. Without a score an unknown name stays.
 */
export function effectiveBucket(bucket: string, score?: number | JsonNumber | null): string {
  if (KNOWN_BUCKETS.includes(bucket)) return bucket;
  const n = score == null ? Number.NaN : Number(score);
  return Number.isFinite(n) ? scoreBucket(n) : bucket;
}

/**
 * Maps an AI Guard / severity bucket to its Tailwind text-color token
 * (`text-sev-*`). Shared by the alerts queue rows and the host AI Guard block
 * so the bucket→color mapping lives in one place. An unknown/future bucket takes
 * the color of the bucket its `score` falls in, and the info color when no score is given. Callers that need a background derive it with
 * `.replace('text-', 'bg-')`.
 */
export function bucketTextColor(bucket: string, score?: number | JsonNumber | null): string {
  switch (effectiveBucket(bucket, score)) {
    case 'critical':
      return 'text-sev-critical';
    case 'high':
      return 'text-sev-high';
    case 'medium':
      return 'text-sev-medium';
    case 'low':
      return 'text-sev-low';
    default:
      return 'text-sev-info';
  }
}
