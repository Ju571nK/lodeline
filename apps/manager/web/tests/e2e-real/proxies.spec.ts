import { expect, test } from '@playwright/test';

/**
 * Each test starts signed in (auth.setup.ts). The values come from the seed of
 * apps/manager/src/fleet/tests/proxies.rs, served by a real lodeline-server.
 */
test.describe('proxy list on a real server', () => {
  // First in the file: the seed's last contact is only seconds old at the server start.
  test('the Proxies list shows the three seeded proxies in scope', async ({ page }) => {
    await page.goto('/proxies');
    const rows = page.locator('main tbody tr');
    await expect(rows).toHaveCount(3, { timeout: 10_000 });
    await expect(rows.filter({ hasText: 'px-a' })).toContainText('Connected');
    await expect(rows.filter({ hasText: 'px-c' })).toContainText('no status report yet');
    await expect(rows.filter({ hasText: 'px-d' })).toContainText('unknown (older proxy)');
    await expect(page.locator('main tbody')).not.toContainText('px-b');
  });
});
