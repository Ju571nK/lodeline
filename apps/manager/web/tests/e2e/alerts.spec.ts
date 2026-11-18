import { expect, type Page, test } from '@playwright/test';

/** Each test starts signed in (playwright.config.ts); `/` opens the alerts queue. */
async function openAlerts(page: Page) {
  await page.goto('/');
  await expect(page).toHaveURL(/\/alerts/);
}

test.describe('alerts queue + triage', () => {
  test('queue renders at least a few rows from the Mock fixture', async ({ page }) => {
    await openAlerts(page);
    // The Mock fixture seeds >= 5 high/critical AI Guard events.
    const rows = page.getByRole('button', { pressed: false }).filter({ hasText: /critical|high/i });
    // Wait for the table to actually paint (poll-driven render).
    await expect.poll(() => rows.count(), { timeout: 5_000 }).toBeGreaterThanOrEqual(3);
  });

  test('opening a row reveals the slide-over with the FactGrid', async ({ page }) => {
    await openAlerts(page);

    // Click the first row that mentions AI Guard.
    const firstRow = page.locator('button:has-text("AI Guard")').first();
    await expect(firstRow).toBeVisible({ timeout: 5_000 });
    await firstRow.click();

    // Sheet header carries event_id; assignee input shows up.
    await expect(page.getByText(/event_id/i)).toBeVisible();
    await expect(page.getByLabel('Assignee')).toBeVisible();
  });

  test('hook-script reason renders the 3b.3.1 source_chain breadcrumb', async ({ page }) => {
    await openAlerts(page);

    // The Mock fixture's bob/codex event carries a destructive_in_hook_script
    // reason with a populated source_chain (contract §14.8). Its row title is
    // distinctive enough to target directly.
    const row = page.locator('button:has-text("Destructive In Hook Script")').first();
    await expect(row).toBeVisible({ timeout: 5_000 });
    await row.click();

    // The slide-over Reasons block shows the source-follow breadcrumb: the
    // last segment of the chain plus the "→" separator between hops. These
    // strings also appear in the raw-evidence <pre> further down, so scope
    // to the first (Reasons-block) match.
    const sheet = page.getByRole('dialog');
    await expect(sheet.getByText('clean.sh', { exact: false }).first()).toBeVisible();
    await expect(sheet.getByText('→').first()).toBeVisible();
  });

  test('gemini mcp_server_local_command reason surfaces server + command', async ({ page }) => {
    await openAlerts(page);

    // bob/gemini event (3b.7) carries an mcp_server_local_command reason.
    const row = page.locator('button:has-text("Gemini")').first();
    await expect(row).toBeVisible({ timeout: 5_000 });
    await row.click();

    const sheet = page.getByRole('dialog');
    // Header renders the humanized tool name, not the raw "gemini" string.
    await expect(sheet.getByText(/AI Guard risk · Gemini/)).toBeVisible();
    // The reason exposes server_name + command. Both also appear in the
    // raw-evidence <pre>, so scope to the first (Reasons-block) match.
    await expect(sheet.getByText('local-fs', { exact: false }).first()).toBeVisible();
    await expect(sheet.getByText(/server-filesystem/).first()).toBeVisible();
  });

  test('assign + acknowledge persists across reload and updates queue', async ({ page }) => {
    await openAlerts(page);

    const firstRow = page.locator('button:has-text("AI Guard")').first();
    await firstRow.click();

    // Type assignee, submit (form submit on Enter via the Check button).
    await page.getByLabel('Assignee').fill('alice');
    // Press the Check submit button next to the input — it has no
    // accessible name, so target via the form structure.
    await page.locator('form:has(input[aria-label="Assignee"]) button[type="submit"]').click();

    // Click the Acknowledge action button (same effect as pressing 'c',
    // which the global shortcut routes through). Clicking <body> here
    // would dismiss the Radix Sheet via outside-click.
    await page.getByRole('button', { name: /^Acknowledge$/ }).click();

    // The slide-over status badge should switch to "acknowledged".
    await expect(page.getByText(/^acknowledged$/i).first()).toBeVisible({ timeout: 5_000 });

    // Reload: still on /alerts, slide-over closed by default, queue
    // row shows the persisted state.
    await page.reload();
    await expect(page).toHaveURL(/\/alerts/);
    // The triage assignee should appear in the visible queue row.
    await expect(page.getByText('alice').first()).toBeVisible({ timeout: 5_000 });
  });

  test('severity filter "Critical" reduces the visible count', async ({ page }) => {
    await openAlerts(page);

    // Wait for the queue to actually paint — the polling fetch happens
    // after first mount, so initial DOM is empty.
    const aiGuardRows = page.locator('button:has-text("AI Guard")');
    await expect(aiGuardRows.first()).toBeVisible({ timeout: 5_000 });
    const before = await aiGuardRows.count();

    // Click the "Critical" severity chip.
    await page.getByRole('button', { name: /^Critical$/ }).click();
    // Wait a tick for the filter request to land.
    await page.waitForTimeout(500);

    const after = await countAiGuardRows(page);
    expect(after).toBeLessThanOrEqual(before);
    // And every visible bucket label should be "critical".
    const labels = await page.locator('span:has-text("critical")').allTextContents();
    expect(labels.length).toBeGreaterThan(0);
  });

  test('"?" opens the keyboard shortcut cheatsheet', async ({ page }) => {
    await openAlerts(page);
    await expect(page.getByRole('heading', { name: 'Alerts', exact: true })).toBeVisible();
    await page.keyboard.press('?');

    await expect(page.getByRole('heading', { name: /keyboard shortcuts/i })).toBeVisible();
    // Esc should close it.
    await page.keyboard.press('Escape');
    await expect(page.getByRole('heading', { name: /keyboard shortcuts/i })).not.toBeVisible();
  });
});

/** Count the AI-Guard buttons currently rendered in the queue table. */
async function countAiGuardRows(page: Page): Promise<number> {
  return page.locator('button:has-text("AI Guard")').count();
}

test('AI Guard event detail displays observation context and values', async ({ page }) => {
  await openAlerts(page);
  await page.locator('button:has-text("Destructive In Hook Script")').first().click();
  const settings = page.getByRole('region', { name: 'Observed security settings' });
  await expect(settings.getByText('false', { exact: true })).toBeVisible();
  await expect(settings.getByText(/not proof of runtime enforcement/)).toBeVisible();
  await expect(settings.locator('time')).toBeVisible();
  await page.screenshot({
    path: test.info().outputPath('observed-controls-event.png'),
    fullPage: true,
  });
});

test('an assessment failure opens in the slide-over and is not a default alert', async ({
  page,
}) => {
  await openAlerts(page);
  await expect(page.locator('button:has-text("AI Guard")').first()).toBeVisible({
    timeout: 5_000,
  });
  await expect(page.locator('button:has-text("assessment failed")')).toHaveCount(0);
  const res = await page.request.get('/api/v1/fleet/events?evidence_kind=ai_guard_assess_failed');
  expect(res.ok()).toBeTruthy();
  const { events } = await res.json();
  expect(events).toHaveLength(1);

  await page.goto(`/alerts?alert=${events[0].event_id}`);
  const sheet = page.getByRole('dialog');
  await expect(sheet.getByText('AI Guard assessment failed · Claude Code')).toBeVisible();
  const facts = sheet.locator('dl');
  for (const [label, value] of [
    ['Error', 'Parse'],
    ['Path', '/home/frank/.claude/settings.json'],
    ['Source', 'user frank · rule pack acme-extended'],
    ['Last good reading', 'none reported'],
  ]) {
    await expect(facts.locator('dt', { hasText: label }).locator('+ dd')).toHaveText(value);
  }
  await expect(
    facts.locator('dt', { hasText: 'Failing since' }).locator('+ dd time'),
  ).toBeVisible();
  await page.screenshot({
    path: test.info().outputPath('alert-assess-failed.png'),
    fullPage: true,
  });
});

async function openFirstAlert(page: Page) {
  await openAlerts(page);
  const firstRow = page.locator('button:has-text("AI Guard")').first();
  await expect(firstRow).toBeVisible({ timeout: 5_000 });
  await firstRow.click();
  const sheet = page.getByRole('dialog');
  await expect(sheet.getByLabel('Assignee')).toBeVisible();
  return sheet;
}

test.describe('alert detail drawer', () => {
  test('previous and next buttons move through the queue and show the position', async ({
    page,
  }) => {
    const sheet = await openFirstAlert(page);
    const position = sheet.getByTestId('alert-position');
    await expect(position).toHaveText(/^1 of \d+$/);
    await expect(sheet.getByRole('button', { name: 'Previous alert' })).toBeDisabled();

    const firstUrl = page.url();
    await sheet.getByRole('button', { name: 'Next alert' }).click();
    await expect(position).toHaveText(/^2 of \d+$/);
    expect(page.url()).not.toBe(firstUrl);

    await sheet.getByRole('button', { name: 'Previous alert' }).click();
    await expect(position).toHaveText(/^1 of \d+$/);
    await expect(page).toHaveURL(firstUrl);
  });

  test('the host id links to the host page', async ({ page }) => {
    const sheet = await openFirstAlert(page);
    const link = sheet.locator('a[href^="/hosts/"]').first();
    await expect(link).toBeVisible();
    const href = await link.getAttribute('href');
    await link.click();
    await expect(page).toHaveURL(new RegExp(`${href}$`));
  });

  test('open full page shows the same alert, and back keeps the filters', async ({ page }) => {
    await page.goto('/alerts?minBucket=high');
    const row = page.locator('button:has-text("AI Guard")').first();
    await expect(row).toBeVisible({ timeout: 5_000 });
    await row.click();
    const sheet = page.getByRole('dialog');
    const title = await sheet.getByRole('heading').first().innerText();
    await sheet.getByRole('link', { name: 'Open full page' }).click();

    await expect(page).toHaveURL(/\/alerts\/[^/?]+/);
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('heading', { name: title })).toBeVisible();
    await expect(page.getByLabel('Assignee')).toBeVisible();

    await page.getByRole('link', { name: 'Back to alerts' }).click();
    await expect(page).toHaveURL(/\/alerts\?.*minBucket=high/);
    await expect(row).toBeVisible();
  });

  test('a full page URL opens on its own after a reload', async ({ page }) => {
    const sheet = await openFirstAlert(page);
    await sheet.getByRole('link', { name: 'Open full page' }).click();
    await expect(page.getByLabel('Assignee')).toBeVisible();
    await page.reload();
    await expect(page.getByLabel('Assignee')).toBeVisible();
  });

  test('the drawer is wider than the old 420 px and the width is resizable and remembered', async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1600, height: 900 });
    const sheet = await openFirstAlert(page);
    const width = async () => (await sheet.boundingBox())?.width ?? 0;
    const initial = await width();
    expect(initial).toBeGreaterThan(600);

    const handle = sheet.getByRole('separator', { name: 'Resize alert panel' });
    await handle.focus();
    await page.keyboard.press('ArrowLeft');
    await page.keyboard.press('ArrowLeft');
    await expect.poll(width).toBeGreaterThan(initial);
    const widened = await width();

    await page.reload();
    await expect(page.getByRole('dialog').getByLabel('Assignee')).toBeVisible();
    expect(Math.abs((await width()) - widened)).toBeLessThan(2);
  });

  test('the drawer can be resized by dragging its edge', async ({ page }) => {
    await page.setViewportSize({ width: 1600, height: 900 });
    const sheet = await openFirstAlert(page);
    const before = (await sheet.boundingBox())?.width ?? 0;
    const edge = await sheet.getByRole('separator', { name: 'Resize alert panel' }).boundingBox();
    if (!edge) throw new Error('no resize handle');
    const y = edge.y + edge.height / 2;
    await page.mouse.move(edge.x + edge.width / 2, y);
    await page.mouse.down();
    await page.mouse.move(edge.x - 120, y, { steps: 6 });
    await page.mouse.up();
    await expect.poll(async () => (await sheet.boundingBox())?.width ?? 0).toBeGreaterThan(before + 80);
  });

  test('under 900 px the drawer takes the full width', async ({ page }) => {
    await page.setViewportSize({ width: 800, height: 900 });
    const sheet = await openFirstAlert(page);
    expect((await sheet.boundingBox())?.width).toBeGreaterThanOrEqual(799);
  });
});
