import { expect, test } from '@playwright/test';

/** Each test starts signed in (auth.setup.ts). The inventory is seed_inventory of src/fleet/tests/proxies.rs. */
test.describe('proxy inventory views on a real server', () => {
  const inventory = (page: import('@playwright/test').Page) =>
    page.locator('section', { has: page.getByRole('heading', { name: 'Inventory' }) });

  test('the snapshots show each comparison state the server derived', async ({ page }) => {
    await page.goto('/proxies/px-a');
    const section = inventory(page);
    const rows = section.locator('tbody tr');
    await expect(rows).toHaveCount(10, { timeout: 10_000 });
    await expect(section.getByRole('link', { name: 'Snapshots' })).toHaveAttribute(
      'aria-current',
      'page',
    );
    await expect(rows.filter({ hasText: '000000001021' })).toContainText('Inconsistent');
    await expect(rows.filter({ hasText: '000000001008' })).toContainText(
      'Waiting for previous snapshot',
    );
    await expect(rows.filter({ hasText: '000000001007' })).toContainText('Baseline restated');
    await expect(rows.filter({ hasText: '000000001020' })).toContainText('Initial baseline');
    await expect(section).toContainText('Inventory incomplete audit gap above: 1 on this proxy.');
    await expect(section.locator('tbody')).not.toContainText('page_error');
  });

  test('the drift shows the three observed changes as not approved', async ({ page }) => {
    await page.goto('/proxies/px-a?inventory=drift');
    const section = inventory(page);
    const rows = section.locator('tbody tr');
    await expect(rows).toHaveCount(3, { timeout: 10_000 });
    await expect(section.getByRole('link', { name: 'Drift' })).toHaveAttribute(
      'aria-current',
      'page',
    );
    await expect(section).toContainText('A drift record is an observed change, not an approval');
    await expect(rows.filter({ hasText: 'Added' })).toContainText('000000000003');
    await expect(rows.filter({ hasText: 'Removed' })).toContainText('000000000002');
    await expect(rows.filter({ hasText: 'Changed' })).toContainText('000000000004');
    await expect(rows.filter({ hasText: 'Changed' })).toContainText('000000000005');
    await expect(section.locator('tbody')).not.toContainText(/approv|accept/i);
  });

  test('a re-baseline marker names its cause', async ({ page }) => {
    await page.goto('/proxies/px-a?inventory=rebaseline-markers');
    const section = inventory(page);
    const rows = section.locator('tbody tr');
    await expect(rows).toHaveCount(5, { timeout: 10_000 });
    await expect(rows.filter({ hasText: 'Baseline restated' })).toHaveCount(1);
    await expect(rows.filter({ hasText: 'Producer epoch changed' })).toHaveCount(1);
    await expect(rows.filter({ hasText: 'Declared key rotation' })).toContainText('Yes');
  });

  test('a proxy without inventory says so', async ({ page }) => {
    await page.goto('/proxies/px-d?inventory=drift');
    await expect(page.getByText('No drift observed.')).toBeVisible({ timeout: 10_000 });
    await page.goto('/proxies/px-d');
    await expect(page.getByText('No snapshots.')).toBeVisible({ timeout: 10_000 });
  });
});
