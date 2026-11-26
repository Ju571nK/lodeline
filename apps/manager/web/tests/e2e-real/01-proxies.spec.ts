import { expect, test } from '@playwright/test';

/**
 * Each test starts signed in (auth.setup.ts). The values come from the seed in
 * apps/manager/src/fleet/tests/proxies.rs, served by a real lodeline-server. The files are
 * numbered because the seed's last contact is only seconds old at the server start: the list
 * test reads connection state first, and the order of the files is the order they run in.
 */
test.describe('proxy pages on a real server', () => {
  test('the Proxies list shows the three seeded proxies in scope', async ({ page }) => {
    await page.goto('/proxies');
    const rows = page.locator('main tbody tr');
    await expect(rows).toHaveCount(3, { timeout: 10_000 });
    const a = rows.filter({ hasText: 'px-a' });
    await expect(a).toContainText('Connected');
    await expect(a).toContainText('3 open gaps');
    await expect(a).toContainText('applied 2, desired 3, out of sync');
    await expect(a).toContainText('4 events, quarantined 1 (512 B)');
    const c = rows.filter({ hasText: 'px-c' });
    await expect(c).toContainText('Never connected');
    await expect(c).toContainText('no status report yet');
    const d = rows.filter({ hasText: 'px-d' });
    await expect(d).toContainText('1 open gap');
    await expect(d).toContainText('quarantined 1 (unknown (older proxy))');
    await expect(page.locator('main tbody')).not.toContainText('px-b');
    await expect(page.getByText('3 loaded')).toBeVisible();
    await expect(page.locator('main').getByRole('button')).toHaveText(['Refresh']);
  });

  test('a proxy page shows its config revisions, spool and gaps', async ({ page }) => {
    await page.goto('/proxies/px-a');
    await expect(page.getByRole('heading', { name: 'Proxy px-a' })).toBeVisible({
      timeout: 10_000,
    });
    const main = page.locator('main');
    await expect(main).toContainText('Desired revision3');
    await expect(main).toContainText('Applied revision2');
    await expect(main).toContainText('Degraded: ingest stopped');
    await expect(main).toContainText('This is not a storage fault.');
    await expect(main).toContainText('4 events, 3 unsent');
    await expect(main).toContainText('99 B of 1000 B');
    await expect(main).toContainText('Failures in a row9');
    await expect(main).toContainText('health_check_failed');
    const gaps = page.locator('section', {
      has: page.getByRole('heading', { name: 'Audit gaps' }),
    });
    await expect(gaps).toContainText('Open: Comparison inconsistent 1, Event quarantined 1');
    await expect(gaps.locator('tbody tr')).toHaveCount(4);
    await expect(gaps.locator('tbody tr', { hasText: 'Sequence gap' })).toContainText('Closed');
    await expect(gaps.locator('tbody tr', { hasText: 'Event quarantined' })).toContainText(
      'code=semantic_invalid',
    );
    await expect(main.getByRole('button')).toHaveText(['Refresh']);
  });

  test('a proxy that never reported says so', async ({ page }) => {
    await page.goto('/proxies/px-c');
    await expect(page.getByRole('heading', { name: 'Proxy px-c' })).toBeVisible({
      timeout: 10_000,
    });
    const main = page.locator('main');
    await expect(main).toContainText('Never connected');
    await expect(main).toContainText('Last seen never.');
    await expect(main).toContainText('Desired revisionnone');
    await expect(main).toContainText('No status report yet.');
    await expect(main).toContainText('No routes reported.');
    await expect(main).toContainText('No open gaps. Showing 0 of 0');
  });

  test('an older proxy leaves the fields it lacks as unknown', async ({ page }) => {
    await page.goto('/proxies/px-d');
    await expect(page.getByRole('heading', { name: 'Proxy px-d' })).toBeVisible({
      timeout: 10_000,
    });
    const main = page.locator('main');
    await expect(main).toContainText('1 events, unknown (older proxy)');
    await expect(main).toContainText('Spool stateDegraded');
    await expect(main).not.toContainText('ingest stopped');
    await expect(main).not.toContainText('Discarded reports');
    await expect(main).toContainText('Open: Event quarantined 1.');
  });

  test('a proxy outside the read scope is not found', async ({ page }) => {
    await page.goto('/proxies/px-b');
    await expect(page.getByRole('alert')).toContainText('Proxy not found.', { timeout: 10_000 });
  });
});
