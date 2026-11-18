import { expect, type Page, test } from '@playwright/test';

/**
 * The mock fleet has all three features on, so each off state is the console's own answer, served
 * by a route. The parity suite proves the binary sends these answers for a real server that lacks
 * the feature.
 */
const off = {
  enroll: (page: Page) =>
    page.route('**/api/v1/enrollment', (route) =>
      route.fulfill({
        json: {
          enabled: false,
          missing: [
            'LODELINE_ENROLL_MINT_TOKEN',
            'LODELINE_ENROLL_MINT_CERT_PATH',
            'LODELINE_ENROLL_MINT_KEY_PATH',
            'LODELINE_ENROLL_FILE_SERVER_URL',
            'LODELINE_ENROLL_FILE_ENROLL_URL',
            'LODELINE_ENROLL_FILE_CA_PATH',
            'LODELINE_ENROLL_FILE_POLICY_KEYSTORE_PATH',
            'LODELINE_PUBLIC_ORIGIN',
          ],
        },
      }),
    ),
  downloads: (page: Page) =>
    page.route('**/api/v1/fleet/artifacts', (route) =>
      route.fulfill({
        status: 502,
        json: { error: { code: 'artifacts_not_configured', message: 'no artifacts_dir' } },
      }),
    ),
  proxies: (page: Page) =>
    page.route('**/api/v1/fleet/proxies**', (route) =>
      route.fulfill({
        status: 502,
        json: { error: { code: 'proxy_reads_unavailable', message: 'not available' } },
      }),
    ),
};

const pages = [
  { name: 'enroll', url: '/enroll', role: 'status', copies: 2 },
  { name: 'downloads', url: '/downloads', role: 'status', copies: 2 },
  { name: 'proxies', url: '/proxies', role: 'alert', copies: 1 },
] as const;

test.describe('setup guides for the off states', () => {
  test.use({ permissions: ['clipboard-read', 'clipboard-write'] });

  for (const p of pages) {
    test(`${p.name}: numbered steps and a copy button for each snippet`, async ({
      page,
    }, testInfo) => {
      await off[p.name](page);
      await page.goto(p.url);
      const guide = page.locator('main').getByRole(p.role);
      await expect(guide.locator('ol > li').first()).toBeVisible();
      await expect(guide.getByRole('button', { name: /^Copy / })).toHaveCount(p.copies);
      await expect(
        guide.getByRole('link', { name: /section of the console README/ }),
      ).toBeVisible();

      const copy = guide.getByRole('button', { name: /^Copy / }).last();
      await copy.focus();
      await expect(copy).toBeFocused();
      await page.keyboard.press('Enter');
      await expect(copy).toHaveText('Copied');
      const code = await copy.locator('xpath=preceding-sibling::pre').innerText();
      expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(code);
      await page.screenshot({ path: testInfo.outputPath(`${p.name}-guide.png`), fullPage: true });
    });

    test(`${p.name}: at phone width the guide stays inside the screen`, async ({
      page,
    }, testInfo) => {
      await page.setViewportSize({ width: 390, height: 900 });
      await off[p.name](page);
      await page.goto(p.url);
      const guide = page.locator('main').getByRole(p.role);
      await expect(guide.locator('ol > li').first()).toBeVisible();
      const box = await guide.boundingBox();
      expect(box).not.toBeNull();
      expect((box?.x ?? 0) + (box?.width ?? 0)).toBeLessThanOrEqual(390);
      const overflowing = await guide.evaluate(
        (el) =>
          [...el.querySelectorAll('*')].filter(
            (n) =>
              n.closest('pre') === null &&
              n.getBoundingClientRect().right > el.getBoundingClientRect().right,
          ).length,
      );
      expect(overflowing).toBe(0);
      const pres = guide.locator('pre');
      for (let i = 0; i < (await pres.count()); i++) {
        const pre = pres.nth(i);
        expect(await pre.evaluate((el) => getComputedStyle(el).overflowX)).toBe('auto');
        const right = (await pre.boundingBox())?.x ?? 0;
        expect(right).toBeLessThan(390);
      }
      await page.screenshot({ path: testInfo.outputPath(`${p.name}-390.png`), fullPage: true });
    });
  }
});
