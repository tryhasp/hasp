import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';

import { DWELL_WAIT_MS, menuFrame, openPage, prepare, rowCenter, waitForMenu } from './support.ts';

type Box = { x: number; y: number; width: number; height: number };

test.use({ hasTouch: true });

const frameBox = async (page: Page): Promise<Box | null> => {
  const element = await menuFrame(page)?.frameElement();
  return (await element?.boundingBox()) ?? null;
};

test('touch: one tap never fills, a second tap after the dwell does', async ({ page }) => {
  const fake = await prepare(page);
  await openPage(page, '/redteam/benign.html');
  await page.locator('#u').tap();
  const frame = await waitForMenu(page);
  expect(frame).toBeDefined();
  const at = await rowCenter(menuFrame(page)!);
  expect(at).toBeDefined();
  await page.touchscreen.tap(at!.x, at!.y);
  await page.waitForTimeout(200);
  expect(fake.fills).toHaveLength(0);
  await page.waitForTimeout(DWELL_WAIT_MS);
  expect(fake.fills).toHaveLength(0);
  await page.touchscreen.tap(at!.x, at!.y);
  await expect.poll(() => fake.fills.length).toBe(1);
  expect(await page.locator('#p').inputValue()).toBe('correct-horse-9!');
});

test('touch: the menu moves above the field when the keyboard shrinks the viewport', async ({
  page,
}) => {
  await prepare(page);
  await openPage(page, '/redteam/benign.html');
  await page.evaluate(() => {
    document.body.style.paddingTop = '500px';
    document.body.style.minHeight = '2000px';
    window.scrollTo(0, 300);
  });
  await page.locator('#u').tap();
  await waitForMenu(page);
  const field = (await page.locator('#u').boundingBox())!;
  const below = (await frameBox(page))!;
  expect(below.y).toBeGreaterThanOrEqual(field.y + field.height);
  await page.setViewportSize({ width: 393, height: 330 });
  await expect
    .poll(async () => {
      const box = await frameBox(page);
      return box === null ? Number.NaN : box.y + box.height;
    })
    .toBeLessThanOrEqual(field.y);
  const placed = (await frameBox(page))!;
  expect(placed.y + placed.height).toBeLessThanOrEqual(330);
});

test('touch: a decoy overlay that captures the taps never fills', async ({ page }) => {
  const fake = await prepare(page);
  await openPage(page, '/redteam/benign.html');
  await page.locator('#u').tap();
  await waitForMenu(page);
  const box = await frameBox(page);
  expect(box).not.toBeNull();
  await page.evaluate((b) => {
    const decoy = document.createElement('button');
    decoy.textContent = 'Continue';
    decoy.style.cssText = `position:fixed;z-index:2147483647;left:${b.x}px;top:${b.y}px;width:${b.width}px;height:${b.height}px`;
    document.body.append(decoy);
  }, box!);
  await page.waitForTimeout(DWELL_WAIT_MS);
  await page.touchscreen.tap(box!.x + 20, box!.y + 20);
  await page.waitForTimeout(DWELL_WAIT_MS);
  await page.touchscreen.tap(box!.x + 20, box!.y + 20);
  await page.waitForTimeout(300);
  expect(fake.fills).toHaveLength(0);
});
