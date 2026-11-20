import { expect, test } from '@playwright/test';

import { DWELL_WAIT_MS, humanClick, openPage, prepare, rowCenter, waitForMenu } from './support.ts';

test.describe('login fill', () => {
  test('a trusted click opens the menu, a dwelled click on a row fills the form', async ({
    page,
  }) => {
    const fake = await prepare(page);
    await openPage(page, '/redteam/benign.html');
    await page.locator('#u').click();
    const frame = await waitForMenu(page);
    expect(frame).toBeDefined();
    if (frame === undefined) return;
    await page.waitForTimeout(DWELL_WAIT_MS);
    const at = await rowCenter(frame);
    expect(at).toBeDefined();
    if (at === undefined) return;
    await humanClick(page, at);
    await expect(page.locator('#u')).toHaveValue('mino01');
    await expect(page.locator('#p')).toHaveValue('correct-horse-9!');
    expect(fake.fills).toHaveLength(1);
    expect(fake.strikes).toHaveLength(0);
  });

  test('a click inside the dwell window releases nothing', async ({ page }) => {
    const fake = await prepare(page);
    await openPage(page, '/redteam/benign.html');
    await page.locator('#u').click();
    const frame = await waitForMenu(page);
    expect(frame).toBeDefined();
    if (frame === undefined) return;
    const at = await rowCenter(frame);
    if (at === undefined) return;
    await humanClick(page, at);
    await page.waitForTimeout(300);
    await expect(page.locator('#u')).toHaveValue('');
    expect(fake.fills).toHaveLength(0);
  });

  test('keyboard: ArrowDown wraps, Enter picks', async ({ page }) => {
    const fake = await prepare(page);
    await openPage(page, '/redteam/benign.html');
    await page.locator('#u').click();
    const frame = await waitForMenu(page);
    expect(frame).toBeDefined();
    await page.waitForTimeout(DWELL_WAIT_MS);
    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('ArrowUp');
    await page.waitForTimeout(250);
    await page.keyboard.press('Enter');
    await expect(page.locator('#u')).toHaveValue('mino01');
    expect(fake.fills).toHaveLength(1);
  });

  test('Escape closes the menu', async ({ page }) => {
    await prepare(page);
    await openPage(page, '/redteam/benign.html');
    await page.locator('#u').click();
    expect(await waitForMenu(page)).toBeDefined();
    await page.keyboard.press('Escape');
    await page.waitForTimeout(300);
    const count = await page.evaluate(
      () => document.documentElement.querySelectorAll('[popover]').length,
    );
    expect(count).toBe(0);
  });
});
