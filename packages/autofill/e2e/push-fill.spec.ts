import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';

import { FRAME_ORIGIN, OTHER_ORIGIN, PAGE_ORIGIN } from './ports.ts';
import { defaultItems, prepare } from './support.ts';

const item = defaultItems[0]?.itemId ?? 'item-1';

const form = (extra: string, passwordStyle = ''): string =>
  `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>push</title><style>body{margin:40px;font:14px sans-serif}input{display:block;width:300px;height:32px;margin:8px 0}</style></head><body><form id="f" method="post" action="#"><input id="u" name="username" autocomplete="username"><input id="p" name="password" type="password" autocomplete="current-password" style="${passwordStyle}"><button type="submit">Sign in</button></form>${extra}</body></html>`;

const serve = async (page: Page, name: string, html: string): Promise<void> => {
  await page.route(`**/redteam/${name}.html`, async (route) => {
    await route.fulfill({ contentType: 'text/html', body: html });
  });
};

const open = async (page: Page, origin: string, name: string): Promise<void> => {
  await page.goto(`${origin}/redteam/${name}.html`);
  await page.waitForFunction('window.haspEngine !== undefined');
};

const push = async (
  page: Page,
  message: { nonce: string; itemId: string; token: string },
): Promise<void> => {
  await page.evaluate((m) => window.haspEngine?.push({ kind: 'fill-form', ...m }), message);
  await page.waitForTimeout(700);
};

const values = async (page: Page): Promise<string[]> =>
  page.evaluate(() => [...document.querySelectorAll('input')].map((i) => i.value));

test('push fill: a plain visible login form is filled and the attestation is measured', async ({
  page,
}) => {
  const fake = await prepare(page);
  await serve(page, 'push-control', form(''));
  await open(page, PAGE_ORIGIN, 'push-control');
  await push(page, await fake.armPush(page, item));
  expect(await values(page)).toEqual(['mino01', 'correct-horse-9!']);
  expect(fake.fills).toHaveLength(1);
});

test('push fill: navigation between decision and fill-form is refused', async ({ page }) => {
  const fake = await prepare(page);
  await serve(page, 'push-nav', form(''));
  await open(page, PAGE_ORIGIN, 'push-nav');
  const armed = await fake.armPush(page, item);
  await open(page, OTHER_ORIGIN, 'push-nav');
  await push(page, armed);
  expect(await values(page)).toEqual(['', '']);
  expect(fake.fills).toHaveLength(0);
  expect(fake.refusals).toContain('origin-changed');
});

test('push fill: an invisible password field chosen by the classifier is never sent for filling', async ({
  page,
}) => {
  const fake = await prepare(page);
  await serve(page, 'push-hidden', form('', 'opacity:0'));
  await open(page, PAGE_ORIGIN, 'push-hidden');
  await push(page, await fake.armPush(page, item));
  expect(await values(page)).toEqual(['', '']);
  expect(fake.requests).not.toContain('fill-request');
  expect(fake.fills).toHaveLength(0);
  expect(fake.strikes.map((s) => s.check)).toContain('C1');
});

test('push fill: a cross-origin iframe overlay on the form is refused', async ({ page }) => {
  const fake = await prepare(page);
  const overlay = `<iframe src="${FRAME_ORIGIN}/menu.html" style="position:fixed;left:0;top:0;width:100%;height:100%;border:0;background:transparent;z-index:9"></iframe>`;
  await serve(page, 'push-overlay', form(overlay));
  await open(page, PAGE_ORIGIN, 'push-overlay');
  await push(page, await fake.armPush(page, item));
  expect(await values(page)).toEqual(['', '']);
  expect(fake.requests).not.toContain('fill-request');
  expect(fake.strikes.map((s) => s.check)).toContain('C3');
});

test('push fill: a field swapped after approval receives nothing', async ({ page }) => {
  const fake = await prepare(page);
  await serve(page, 'push-swap', form(''));
  await open(page, PAGE_ORIGIN, 'push-swap');
  fake.hooks.beforeFillReply = async () => {
    await page.evaluate(() => {
      const old = document.getElementById('p');
      if (old === null) return;
      const clone = old.cloneNode(true);
      old.replaceWith(clone);
    });
  };
  await push(page, await fake.armPush(page, item));
  expect(await values(page)).toEqual(['', '']);
  await expect(page.evaluate('window.haspNotices')).resolves.toContain('fill-refused');
});
