import { expect, test } from '@playwright/test';

const id = (n: number) => `00000000-0000-4000-8000-000000000${n}`;

/** Each test starts signed in (playwright.config.ts). The mock fleet has 10 invocations. */
test.describe('proxy invocation pages', () => {
  test('a proxy links to its invocations, and flagged rows never read as success', async ({
    page,
  }, testInfo) => {
    await page.goto('/proxies/px-edge-02');
    await page.getByRole('link', { name: 'Invocations of this proxy' }).click();
    await expect(page).toHaveURL(/\/proxy-invocations\?proxy=px-edge-02$/);
    const rows = page.locator('main tbody tr');
    await expect(rows).toHaveCount(3, { timeout: 5_000 });
    for (const [n, label] of [
      [401, 'Flagged: completion without start'],
      [402, 'Flagged: integrity conflict'],
    ] as const) {
      const row = rows.filter({ hasText: id(n) });
      await expect(row).toContainText(label);
      await expect(row).toContainText(
        'Proxy reported outcome success, delivery sent. Not corroborated.',
      );
      await expect(row.getByText('Success', { exact: true })).toHaveCount(0);
    }
    await expect(rows.filter({ hasText: id(409) })).toContainText('Protocol error');
    await expect(page.locator('main').getByRole('button')).toHaveText(['Refresh']);
    await page.screenshot({ path: testInfo.outputPath('invocations-list.png'), fullPage: true });
  });

  test('the Proxies page lists every invocation, and the filters narrow it', async ({ page }) => {
    await page.goto('/proxies');
    await page.getByRole('link', { name: 'All invocations' }).click();
    await expect(page).toHaveURL(/\/proxy-invocations$/);
    const rows = page.locator('main tbody tr');
    await expect(rows).toHaveCount(10, { timeout: 5_000 });
    await page.getByLabel('Outcome').selectOption('success');
    await expect(page).toHaveURL(/outcome=success/);
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toContainText(id(403));
    await page.getByLabel('Outcome').selectOption('');
    await page.getByLabel('Lifecycle').selectOption('integrity_conflict');
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toContainText(id(402));
  });

  test('a flagged invocation withholds its outcome', async ({ page }, testInfo) => {
    await page.goto(`/proxy-invocations/${id(402)}`);
    await expect(page.getByRole('heading', { name: 'Invocation' })).toBeVisible({ timeout: 5_000 });
    await expect(page.getByRole('alert')).toContainText(
      'Do not count this invocation as a success.',
    );
    await expect(page.getByText('withheld: no corroborated completion')).toBeVisible();
    await expect(page.getByText('Completion contradicts start')).toBeVisible();
    await expect(page.getByRole('link', { name: 'Proxy px-edge-02' })).toBeVisible();
    await expect(page.locator('main').getByRole('button')).toHaveCount(0);
    await page.screenshot({
      path: testInfo.outputPath('invocation-detail-flagged.png'),
      fullPage: true,
    });
  });

  test('a truncated event list says so', async ({ page }, testInfo) => {
    await page.goto(`/proxy-invocations/${id(404)}`);
    await expect(page.getByRole('alert')).toContainText(
      'This list is incomplete: the server returns at most 32 events of an invocation, and 8 more are not shown.',
      { timeout: 5_000 },
    );
    await expect(page.getByText(/^Showing 32 of 40/)).toBeVisible();
    await expect(page.locator('main tbody tr')).toHaveCount(32);
    await expect(page.getByText('Outcome').locator('xpath=..')).toContainText('Timeout');
    await page.screenshot({
      path: testInfo.outputPath('invocation-detail-truncated.png'),
      fullPage: true,
    });
  });

  test('an unknown invocation gets the not found panel', async ({ page }) => {
    await page.goto(`/proxy-invocations/${id(999)}`);
    await expect(page.getByRole('alert')).toContainText('Invocation not found.', {
      timeout: 5_000,
    });
  });
});
