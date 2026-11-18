import { describe, expect, it } from 'vitest';
import { validateAlertsSearch } from './alertsSearch';

describe('validateAlertsSearch', () => {
  it('keeps known filters and drops the rest', () => {
    expect(
      validateAlertsSearch({
        minBucket: 'high',
        triageStatuses: 'open,resolved,bogus',
        sort: 'age_asc',
        alert: 'e1',
        junk: 1,
      }),
    ).toEqual({
      minBucket: 'high',
      triageStatuses: ['open', 'resolved'],
      sort: 'age_asc',
      alert: 'e1',
    });
  });

  it('ignores an unknown bucket or sort', () => {
    expect(validateAlertsSearch({ minBucket: 'huge', sort: 'random' })).toEqual({});
  });
});
