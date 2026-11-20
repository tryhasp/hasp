import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';

import { type Launched, launchExtension } from './support/extension.ts';
import { type TestServer, startHaspd } from './support/haspd.ts';
import { addLogin, signInPopup } from './support/helpers.ts';

const IPHONE = {
  viewport: { width: 393, height: 659 },
  deviceScaleFactor: 3,
  isMobile: true,
  hasTouch: true,
  isCoarsePointer: true,
} as const;
const MIN_TOUCH_PX = 44;

let server: TestServer;
let browser: Launched;

const expectFitsSheet = async (popup: Page): Promise<void> => {
  const overflow = await popup.evaluate(() => ({
    scroll: document.documentElement.scrollWidth,
    inner: window.innerWidth,
    body: document.body.getBoundingClientRect().width,
  }));
  expect(overflow.scroll).toBeLessThanOrEqual(overflow.inner);
  expect(overflow.body).toBeLessThanOrEqual(overflow.inner);
};

const smallTargets = async (popup: Page): Promise<string[]> => {
  const found = await popup.evaluate((min) => {
    const small: string[] = [];
    for (const el of document.querySelectorAll('button, input, [role="button"]')) {
      const box = (el.closest('label') ?? el).getBoundingClientRect();
      if (box.width === 0 || box.height === 0) continue;
      const label = el.getAttribute('data-testid') ?? el.tagName;
      if (box.height < min) small.push(`${label}:${Math.round(box.height)}`);
    }
    return small;
  }, MIN_TOUCH_PX);
  return found;
};

test.describe.serial('iPhone popup layout', () => {
  test.beforeAll(async () => {
    server = await startHaspd();
    addLogin(server, 'Demo shop', 'https://shop.example/', 'dora@example.com', 'sheet-secret-5521');
    browser = await launchExtension(IPHONE);
  });

  test.afterAll(async () => {
    await browser.close();
    server.stop();
  });

  test('sign-in, main list and locked screens fit the sheet with 44 pt targets', async () => {
    const popup = await browser.popup();
    expect(await popup.evaluate("matchMedia('(pointer: coarse)').matches")).toBe(true);
    await expectFitsSheet(popup);
    expect(await smallTargets(popup)).toEqual([]);
    await signInPopup(popup, server);
    await expect(popup.getByTestId('item-row').first()).toBeVisible();
    await expectFitsSheet(popup);
    expect(await smallTargets(popup)).toEqual([]);
    const fontSize = await popup
      .getByTestId('search')
      .evaluate((el) => getComputedStyle(el).fontSize);
    expect(Number.parseFloat(fontSize)).toBeGreaterThanOrEqual(16);
    await popup.getByTestId('lock').click();
    await expect(popup.getByTestId('locked')).toBeVisible();
    await expectFitsSheet(popup);
    expect(await smallTargets(popup)).toEqual([]);
  });
});
