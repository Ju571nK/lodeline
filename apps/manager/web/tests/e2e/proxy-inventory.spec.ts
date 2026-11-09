import { expect, test } from '@playwright/test';

/** Each test starts signed in (playwright.config.ts). The mock fleet's inventory is in testdata. */
test.describe('proxy inventory views', () => {
  test('a proxy shows its snapshots, then its drift as observed changes', async ({
    page,
  }, testInfo) => {
    await page.goto('/proxies/px-edge-01');
    const inventory = page.locator('section', {
      has: page.getByRole('heading', { name: 'Inventory' }),
    });
    const rows = inventory.locator('tbody tr');
    await expect(rows).toHaveCount(5, { timeout: 5_000 });
    const tabs = page.getByRole('navigation', { name: 'Inventory views' });
    await expect(tabs.getByRole('link', { name: 'Snapshots' })).toHaveAttribute(
      'aria-current',
      'page',
    );
    await expect(rows.first()).toContainText('Compared');
    await expect(rows.last()).toContainText('Initial baseline');
    await expect(inventory).toContainText('0 on this proxy');
    await page.screenshot({ path: testInfo.outputPath('inventory-snapshots.png'), fullPage: true });

    await tabs.getByRole('link', { name: 'Drift' }).click();
    await expect(page).toHaveURL(/\/proxies\/px-edge-01\?inventory=drift$/);
    await expect(tabs.getByRole('link', { name: 'Drift' })).toHaveAttribute('aria-current', 'page');
    await expect(rows).toHaveCount(4);
    await expect(inventory.getByRole('columnheader', { name: 'Observed change' })).toBeVisible();
    await expect(inventory).toContainText('A drift record is an observed change, not an approval');
    await expect(inventory.locator('tbody')).not.toContainText(/approv|accept/i);
    await expect(rows.filter({ hasText: 'Changed' })).toContainText('000000000802');
    await expect(page.locator('main').getByRole('button')).toHaveText(['Refresh']);
    // The tab colors fade; a screenshot taken mid-fade shows the old tab.
    await page.screenshot({
      path: testInfo.outputPath('inventory-drift.png'),
      fullPage: true,
      animations: 'disabled',
    });
  });

  test('a re-baseline marker names its cause and its links', async ({ page }, testInfo) => {
    await page.goto('/proxies/px-edge-01?inventory=rebaseline-markers');
    const inventory = page.locator('section', {
      has: page.getByRole('heading', { name: 'Inventory' }),
    });
    const rows = inventory.locator('tbody tr');
    await expect(rows).toHaveCount(1, { timeout: 5_000 });
    await expect(rows.first()).toContainText('Declared key rotation');
    await expect(rows.first()).toContainText('docs-search');
    await expect(rows.first()).toContainText('Yes');
    await page.screenshot({ path: testInfo.outputPath('inventory-markers.png'), fullPage: true });
  });

  test('an incomplete observation stays an audit gap, not a snapshot', async ({
    page,
  }, testInfo) => {
    await page.goto('/proxies/px-lab-03');
    const inventory = page.locator('section', {
      has: page.getByRole('heading', { name: 'Inventory' }),
    });
    await expect(inventory.locator('tbody tr')).toHaveCount(2, { timeout: 5_000 });
    await expect(inventory).toContainText(
      'Inventory incomplete audit gap above: 1 on this proxy, and the gap list is incomplete.',
    );
    await expect(inventory.locator('tbody')).not.toContainText('page_error');
    const gaps = page.locator('section', {
      has: page.getByRole('heading', { name: 'Audit gaps' }),
    });
    await expect(gaps.locator('tbody tr', { hasText: 'Inventory incomplete' })).toContainText(
      'incomplete_reason=page_error',
    );
    await page.screenshot({
      path: testInfo.outputPath('inventory-incomplete-gap.png'),
      fullPage: true,
    });
  });

  test('a proxy without inventory says so', async ({ page }) => {
    await page.goto('/proxies/px-new-04?inventory=drift');
    await expect(page.getByText('No drift observed.')).toBeVisible({ timeout: 5_000 });
  });

  test('the Proxies nav item stays active on the invocation pages', async ({ page }) => {
    for (const path of [
      '/proxy-invocations',
      '/proxy-invocations/00000000-0000-4000-8000-000000000402',
    ]) {
      await page.goto(path);
      await expect(page.getByRole('link', { name: /^Proxies$/ })).toHaveAttribute(
        'aria-current',
        'page',
      );
      await expect(page.getByRole('link', { name: /^Fleet$/ })).not.toHaveAttribute('aria-current');
    }
  });
});
