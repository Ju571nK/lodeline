import { expect, test } from '@playwright/test';

/** Each test starts signed in (playwright.config.ts). The mock fleet has 5 proxies. */
test.describe('proxy pages', () => {
  test('the Proxies nav lists every proxy with its report time and gaps', async ({
    page,
  }, testInfo) => {
    await page.goto('/alerts');
    await page.getByRole('link', { name: /^Proxies$/ }).click();
    await expect(page).toHaveURL(/\/proxies$/);
    const rows = page.locator('main tbody tr');
    await expect(rows).toHaveCount(5, { timeout: 5_000 });
    const edge2 = rows.filter({ hasText: 'px-edge-02' });
    await expect(edge2).toContainText('Connected');
    await expect(edge2).toContainText('2 open gaps');
    await expect(edge2).toContainText('status as of');
    await expect(edge2).toContainText('applied 7, desired 8, out of sync');
    await expect(rows.filter({ hasText: 'px-new-04' })).toContainText('no status report yet');
    await expect(rows.filter({ hasText: 'px-off-05' })).toContainText('Disabled');
    await expect(rows.filter({ hasText: 'px-lab-03' })).toContainText('unknown (older proxy)');
    // Read only: the page's own buttons only reload what the server holds.
    await expect(page.locator('main').getByRole('button')).toHaveText(['Refresh']);
    await page.screenshot({ path: testInfo.outputPath('proxies-list.png'), fullPage: true });

    await page.getByLabel('Connection').selectOption('disconnected');
    await expect(page).toHaveURL(/connection=disconnected/);
    await expect(rows).toHaveCount(2);
    await page.getByLabel('Config sync').selectOption('out_of_sync');
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toContainText('px-lab-03');
  });

  test('a stopped ingest is not shown as a storage fault', async ({ page }, testInfo) => {
    await page.goto('/proxies');
    await page.getByRole('link', { name: 'Edge proxy 02' }).click();
    await expect(page).toHaveURL(/\/proxies\/px-edge-02$/);
    await expect(page.getByRole('heading', { name: 'Edge proxy 02' })).toBeVisible();
    await expect(page.getByText('Degraded: ingest stopped')).toBeVisible();
    await expect(page.getByText(/This is not a storage fault\./)).toBeVisible();
    await expect(page.getByRole('alert').first()).toContainText('Ingest stopped:');
    await expect(page.getByText('8 events, 40 KiB')).toBeVisible();
    await expect(page.getByText('health_check_failed')).toBeVisible();
    // Read only: the one button reloads the inventory list.
    await expect(page.locator('main').getByRole('button')).toHaveText(['Refresh']);
    await page.screenshot({
      path: testInfo.outputPath('proxy-detail-ingest-stopped.png'),
      fullPage: true,
    });
  });

  test('an older proxy and a capped gap list are labeled', async ({ page }, testInfo) => {
    await page.goto('/proxies/px-lab-03');
    await expect(page.getByRole('heading', { name: 'Lab proxy 03' })).toBeVisible({
      timeout: 5_000,
    });
    await expect(page.getByText('4 events, unknown (older proxy)')).toBeVisible();
    await expect(page.getByText(/This gap list is incomplete: the server dropped 3/)).toBeVisible();
    await expect(page.getByText('Expired', { exact: true })).toBeVisible();
    await expect(page.getByText('Discarded reports')).toHaveCount(0);
    // One route, three gaps and the two inventory snapshots.
    await expect(page.locator('main tbody tr')).toHaveCount(6);
    await expect(page.locator('main').getByRole('button')).toHaveText(['Refresh']);
    await page.screenshot({ path: testInfo.outputPath('proxy-detail-older.png'), fullPage: true });
  });

  test('an unknown proxy gets the not found panel', async ({ page }) => {
    await page.goto('/proxies/px-missing');
    await expect(page.getByRole('alert')).toContainText('Proxy not found.', { timeout: 5_000 });
  });

  test('a server without proxy reads is named as such', async ({ page }) => {
    // Renders the console's answer for a server that does not mount the proxy routes. The parity
    // suite's live cases prove the binary sends this answer for that server.
    await page.route('**/api/v1/fleet/proxies**', (route) =>
      route.fulfill({
        status: 502,
        contentType: 'application/json',
        body: JSON.stringify({
          error: {
            code: 'proxy_reads_unavailable',
            message: 'proxy reads are not available on this lodeline-server',
          },
        }),
      }),
    );
    await page.goto('/proxies');
    await expect(page.getByRole('alert')).toContainText(
      'Proxy reads are not available on this lodeline-server. It runs without a proxy section.',
      { timeout: 5_000 },
    );
  });

  test('a refused client certificate is named as such', async ({ page }) => {
    // The parity case live-proxy-host-unknown proves the binary sends this answer when the
    // server refuses the console's certificate.
    await page.route('**/api/v1/fleet/proxies**', (route) =>
      route.fulfill({
        status: 502,
        json: { error: { code: 'certificate_refused', message: 'refused' } },
      }),
    );
    await page.goto('/proxies');
    await expect(page.getByRole('alert')).toContainText(
      'Client certificate refused. Issue the certificate in LODELINE_SERVER_CLIENT_CERT_PATH',
      { timeout: 5_000 },
    );
  });
});
