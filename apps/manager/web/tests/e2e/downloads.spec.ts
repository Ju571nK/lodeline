import { readFileSync } from 'node:fs';
import { expect, test } from '@playwright/test';

/** Each test starts signed in (playwright.config.ts). The mock fleet serves 4 release files. */
test.describe('downloads page', () => {
  test('the Downloads nav lists the server files and the browser saves one', async ({
    page,
  }, testInfo) => {
    await page.goto('/alerts');
    await page.getByRole('link', { name: 'Downloads' }).click();
    await expect(page).toHaveURL(/\/downloads$/);
    await expect(page.locator('main li a')).toHaveText([
      'SHA256SUMS',
      'build-manifest.json',
      'lodeline-0.14.2-aarch64-apple-darwin.tar.gz',
      'lodeline-0.14.2-x86_64-unknown-linux-musl.tar.gz',
    ]);
    await expect(page.getByText(/It does not check the files\./)).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath('downloads.png'), fullPage: true });

    const saved = page.waitForEvent('download');
    await page.getByRole('link', { name: 'build-manifest.json' }).click();
    const download = await saved;
    expect(download.suggestedFilename()).toBe('build-manifest.json');
    const file = testInfo.outputPath('build-manifest.json');
    await download.saveAs(file);
    expect(readFileSync(file, 'utf8')).toBe(
      'build-manifest.json: a mock file from MOCK_FLEET=1, not a release file\n',
    );
    await expect(page).toHaveURL(/\/downloads$/);
  });

  test('a server without artifacts_dir is named as such', async ({ page }, testInfo) => {
    await page.route('**/api/v1/fleet/artifacts', (route) =>
      route.fulfill({
        status: 502,
        json: { error: { code: 'artifacts_not_configured', message: 'no artifacts_dir' } },
      }),
    );
    await page.goto('/downloads');
    await expect(page.getByText(/does not serve release files/)).toContainText(
      'sets artifacts_dir in server.yaml',
    );
    await expect(page.locator('main li a')).toHaveCount(0);
    await page.screenshot({
      path: testInfo.outputPath('downloads-not-configured.png'),
      fullPage: true,
    });
  });
});
