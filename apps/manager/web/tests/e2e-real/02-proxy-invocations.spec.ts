import { expect, test } from '@playwright/test';

const id = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;

/** Each test starts signed in (auth.setup.ts). The invocations are seed_invocations of src/fleet/tests/proxies.rs. */
test.describe('proxy invocation pages on a real server', () => {
  test('the list holds the invocations in scope and flags never read as success', async ({
    page,
  }) => {
    await page.goto('/proxy-invocations');
    const rows = page.locator('main tbody tr');
    // 13 are seeded; invocation 12 belongs to px-b, outside the read scope.
    await expect(rows).toHaveCount(12, { timeout: 10_000 });
    await expect(rows.filter({ hasText: id(12) })).toHaveCount(0);
    for (const [n, label] of [
      [8, 'Flagged: completion without start'],
      [10, 'Flagged: integrity conflict'],
    ] as const) {
      const row = rows.filter({ hasText: id(n) });
      await expect(row).toContainText(label);
      await expect(row).toContainText(
        'Proxy reported outcome success, delivery sent. Not corroborated.',
      );
      await expect(row.getByText('Success', { exact: true })).toHaveCount(0);
    }
    await expect(rows.filter({ hasText: id(2) })).toContainText('Success');
    await expect(rows.filter({ hasText: id(3) })).toContainText('Tool error');
    await expect(rows.filter({ hasText: id(4) })).toContainText('Protocol error');
    await expect(rows.filter({ hasText: id(9) })).toContainText('Cancel only, no start');
    await expect(rows.filter({ hasText: id(13) })).toContainText('px-d');
    await expect(page.locator('main').getByRole('button')).toHaveText(['Refresh']);
  });

  test('the filters narrow the list on the server', async ({ page }) => {
    await page.goto('/proxy-invocations');
    const rows = page.locator('main tbody tr');
    await expect(rows).toHaveCount(12, { timeout: 10_000 });
    await page.getByLabel('Outcome').selectOption('timeout');
    await expect(page).toHaveURL(/outcome=timeout/);
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toContainText(id(5));
    await page.getByLabel('Outcome').selectOption('');
    await page.getByLabel('Lifecycle').selectOption('integrity_conflict');
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toContainText(id(10));
  });

  test('a proxy links to its own invocations', async ({ page }) => {
    await page.goto('/proxies/px-d');
    await page.getByRole('link', { name: 'Invocations of this proxy' }).click();
    await expect(page).toHaveURL(/\/proxy-invocations\?proxy=px-d$/);
    const rows = page.locator('main tbody tr');
    await expect(rows).toHaveCount(1, { timeout: 10_000 });
    await expect(rows.first()).toContainText(id(13));
  });

  test('a completed invocation shows its outcome and its two events', async ({ page }) => {
    await page.goto(`/proxy-invocations/${id(3)}`);
    const main = page.locator('main');
    await expect(main.getByText('lifecycle')).toBeVisible({ timeout: 10_000 });
    await expect(main).toContainText('OutcomeTool error');
    await expect(main).toContainText('Deliverysent');
    await expect(main).toContainText('Duration12 ms');
    await expect(main).toContainText('Response size34 B');
    await expect(main).toContainText('Showing 2 of 2');
    await expect(main.locator('tbody tr')).toHaveCount(2);
    await expect(main.locator('tbody tr').first()).toContainText('invocation.started');
    await expect(main.getByRole('link', { name: 'Proxy px-a' })).toBeVisible();
  });

  test('a completion without a start withholds its outcome', async ({ page }) => {
    await page.goto(`/proxy-invocations/${id(8)}`);
    await expect(page.getByRole('alert')).toContainText(
      'Do not count this invocation as a success.',
      { timeout: 10_000 },
    );
    await expect(page.getByText('withheld: no corroborated completion')).toBeVisible();
    await expect(page.getByText('No start observed.')).toBeVisible();
  });

  test('an event list longer than the server returns says so', async ({ page }) => {
    await page.goto(`/proxy-invocations/${id(11)}`);
    await expect(page.getByRole('alert')).toContainText('This list is incomplete', {
      timeout: 10_000,
    });
    await expect(page.getByText(/^Showing 32 of 33/)).toBeVisible();
    await expect(page.locator('main tbody tr')).toHaveCount(32);
  });

  test('an invocation outside the read scope is not found', async ({ page }) => {
    await page.goto(`/proxy-invocations/${id(12)}`);
    await expect(page.getByRole('alert')).toContainText('Invocation not found.', {
      timeout: 10_000,
    });
  });
});
