import { readFileSync } from 'node:fs';
import { expect, test } from '@playwright/test';

/**
 * Each test starts signed in (playwright.config.ts). The mock fleet has a mock mint whose token works
 * nowhere, and playwright.config.ts sets LODELINE_PUBLIC_ORIGIN to the test server's origin.
 */
test.describe('Enroll a host page', () => {
  test('the nav link opens the page, which lists what the file holds', async ({
    page,
  }, testInfo) => {
    await page.goto('/alerts');
    await page.getByRole('link', { name: 'Enroll a host' }).click();
    await expect(page).toHaveURL(/\/enroll$/);
    await expect(page.getByRole('heading', { level: 1, name: 'Enroll a host' })).toBeVisible();
    const table = page.getByRole('table');
    await expect(table).toContainText('https://lodeline.example.com:8443');
    await expect(table).toContainText('https://lodeline.example.com:8444');
    await expect(table).toContainText('CN=lodeline-mock-ca');
    await expect(table).toContainText('mock-key-1');
    await expect(
      table.locator('td.font-mono').filter({ hasText: /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/ }),
    ).toHaveCount(2);
    await page.screenshot({ path: testInfo.outputPath('enroll.png'), fullPage: true });
  });

  test('the click saves a file for a new host id and shows the steps', async ({
    page,
  }, testInfo) => {
    await page.goto('/enroll');
    const saved = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Make an enrollment file' }).click();
    const download = await saved;
    const file = testInfo.outputPath('enrollment.json');
    await download.saveAs(file);
    const body = JSON.parse(readFileSync(file, 'utf8'));
    expect(body.lodeline_enrollment).toBe(1);
    expect(body.host_id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
    expect(download.suggestedFilename()).toBe(`lodeline-enroll-${body.host_id}.json`);

    const done = page.getByRole('status', { name: 'The file was made' });
    await expect(done).toContainText(`Host id: ${body.host_id}`);
    await expect(done).toContainText('This file is a secret until the host uses it or it expires.');
    await expect(done).toContainText(
      `sudo lodeline-sender enroll lodeline-enroll-${body.host_id}.json`,
    );
    await expect(page.locator('body')).not.toContainText(body.token);
    expect(page.url()).not.toContain(body.token);
    await page.screenshot({ path: testInfo.outputPath('enroll-made.png'), fullPage: true });
  });

  test('a host id the page cannot accept sends no request', async ({ page }) => {
    let posted = 0;
    await page.route('**/api/v1/enrollment/files', (route) => {
      posted += 1;
      return route.abort();
    });
    await page.goto('/enroll');
    await page.getByLabel(/Host id/).fill('not-a-uuid');
    await page.getByRole('button', { name: 'Make an enrollment file' }).click();
    await expect(page.getByRole('alert')).toContainText(
      'not a lower-case, hyphenated version 4 UUID',
    );
    expect(posted).toBe(0);
  });

  test('a server that does not accept the mint certificate is named as such', async ({
    page,
  }, testInfo) => {
    await page.route('**/api/v1/enrollment/files', (route) =>
      route.fulfill({
        status: 502,
        json: { error: { code: 'enroll_unavailable', message: 'no mint endpoint' } },
      }),
    );
    await page.goto('/enroll');
    await page.getByRole('button', { name: 'Make an enrollment file' }).click();
    await expect(page.getByRole('alert')).toContainText('section 3.6 of docs/install-server.md');
    await page.screenshot({ path: testInfo.outputPath('enroll-unavailable.png'), fullPage: true });
  });
});
