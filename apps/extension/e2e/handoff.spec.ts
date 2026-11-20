import { type Page, expect, test } from '@playwright/test';

import { type Launched, launchExtension } from './support/extension.ts';
import { type TestServer, startHaspd } from './support/haspd.ts';
import { addLogin, listItems, menuFrame, revealPassword, signInPopup } from './support/helpers.ts';
import { type TestSite, startSite } from './support/pages.ts';

let server: TestServer;
let site: TestSite;
let browser: Launched;

const pageStorageOf = async (page: Page): Promise<string> =>
  page.evaluate(() =>
    JSON.stringify({
      session: Object.entries(window.sessionStorage),
      local: Object.entries(window.localStorage),
      cookie: document.cookie,
      name: window.name,
    }),
  );

const hasMenuFrame = (page: Page): boolean =>
  page.frames().some((frame) => frame.url().includes('menu-frame.html'));

const confirmSave = async (page: Page): Promise<void> => {
  const frame = await menuFrame(page);
  const save = frame.locator('button.btn.pri');
  await expect(save).toBeVisible();
  await save.hover();
  await page.waitForTimeout(700);
  await save.click();
};

const passwordsOf = (title: string): string[] =>
  listItems(server)
    .filter((item) => item.title.includes(title))
    .map((item) => revealPassword(server, item.id));

test.describe.serial('typed credentials survive worker eviction at submit', () => {
  test.beforeAll(async () => {
    server = await startHaspd();
    site = await startSite();
    browser = await launchExtension();
    const popup = await browser.popup();
    await signInPopup(popup, server);
    await popup.close();
  });

  test.afterAll(async () => {
    await browser.close();
    site.stop();
    server.stop();
  });

  test('offers to save a typed sign-in password after eviction at submit', async () => {
    const page = await browser.context.newPage();
    await page.goto(`${site.origin}/login`);
    await page.locator('#user').fill('erin@example.com');
    await page.locator('#pass').fill('typed-signin-4417');
    await browser.evictWorker();
    await page.locator('#submit').click();
    await expect(page.locator('#dashboard')).toBeVisible();
    await confirmSave(page);
    await expect
      .poll(() => passwordsOf('localhost'), { timeout: 30_000 })
      .toContain('typed-signin-4417');
    expect(await pageStorageOf(page)).not.toContain('typed-signin-4417');
    await page.close();
  });

  test('offers to update the stored password after a change with eviction at submit', async () => {
    addLogin(server, 'Bank', `${site.origin}/`, 'bob@example.com', 'old-bank-pass-1');
    const popup = await browser.popup();
    await popup.getByTestId('sync').click();
    await popup.getByTestId('search').fill('Bank');
    await expect(popup.getByTestId('results').getByText('Bank')).toBeVisible({ timeout: 30_000 });
    await popup.close();
    const page = await browser.context.newPage();
    await page.goto(`${site.origin}/change`);
    await page.locator('#cur').fill('old-bank-pass-1');
    await page.locator('#pass').fill('new-bank-pass-2');
    await page.locator('#pass2').fill('new-bank-pass-2');
    await browser.evictWorker();
    await page.locator('#submit').click();
    await expect(page.locator('#changed')).toBeVisible();
    await confirmSave(page);
    await expect.poll(() => site.changes.length).toBe(1);
    await expect.poll(() => passwordsOf('Bank'), { timeout: 30_000 }).toEqual(['new-bank-pass-2']);
    expect(await pageStorageOf(page)).not.toContain('new-bank-pass-2');
    await page.close();
  });

  test('keeps typed values out of every page-readable store after submit', async () => {
    const page = await browser.context.newPage();
    await page.goto(`${site.origin}/login`);
    await page.locator('#user').fill('gina@example.com');
    await page.locator('#pass').fill('short-lived-secret-5');
    await page.evaluate(() => {
      document.querySelector('form')?.addEventListener('submit', (e) => e.preventDefault());
    });
    await page.locator('#submit').click();
    await page.waitForTimeout(500);
    const dump = await pageStorageOf(page);
    expect(dump).not.toContain('short-lived-secret-5');
    expect(dump).not.toContain('gina@example.com');
    await page.close();
  });

  test('a handoff forged by the page produces no save prompt', async () => {
    const page = await browser.context.newPage();
    await page.goto(`${site.origin}/welcome`);
    await page.evaluate(() => {
      const record = JSON.stringify({
        atMs: Date.now(),
        origin: location.origin,
        values: { username: 'victim@example.com', newPassword: 'attacker-chosen' },
      });
      for (const key of ['hasp:submit-handoff', 'handoff', `handoff:top:${location.origin}`]) {
        window.sessionStorage.setItem(key, record);
        window.localStorage.setItem(key, record);
      }
    });
    await page.reload();
    await page.waitForTimeout(3000);
    expect(hasMenuFrame(page)).toBe(false);
    await page.close();
  });
});
