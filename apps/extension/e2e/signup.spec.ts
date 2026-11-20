import { type Page, expect, test } from '@playwright/test';

import { type Launched, launchExtension } from './support/extension.ts';
import { type TestServer, startHaspd } from './support/haspd.ts';
import {
  clickWithDwell,
  listItems,
  menuFrame,
  revealPassword,
  signInPopup,
} from './support/helpers.ts';
import { type TestSite, startSite } from './support/pages.ts';

let server: TestServer;
let site: TestSite;
let browser: Launched;

const newUser = 'dave@example.com';

const generateOnSignup = async (page: Page): Promise<string> => {
  await page.goto(`${site.origin}/signup`);
  await page.locator('#user').fill(newUser);
  await page.locator('#pass').click();
  const frame = await menuFrame(page);
  const items = frame.getByRole('menuitem');
  await expect(items.last()).toBeVisible();
  await clickWithDwell(frame, '[role=menuitem]', (await items.count()) - 1);
  await expect(page.locator('#pass')).not.toHaveValue('');
  const generated = await page.locator('#pass').inputValue();
  await expect(page.locator('#pass2')).toHaveValue(generated);
  return generated;
};

const saveFromPrompt = async (page: Page): Promise<void> => {
  await page.locator('#submit').click();
  await expect(page.locator('#welcome')).toBeVisible();
  const frame = await menuFrame(page);
  const save = frame.locator('button.btn.pri');
  await expect(save).toBeVisible();
  await save.hover();
  await page.waitForTimeout(700);
  await save.click();
};

test.describe.serial('sign-up with a generated password', () => {
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

  test('saves the generated password after the sign-up', async () => {
    const page = await browser.context.newPage();
    const generated = await generateOnSignup(page);
    await saveFromPrompt(page);
    await expect.poll(() => site.signups.length).toBe(1);

    expect(site.signups[0]).toEqual({ user: newUser, password: generated });
    await expect
      .poll(() => listItems(server).filter((item) => item.title.includes('localhost')).length, {
        timeout: 30_000,
      })
      .toBe(1);
    const saved = listItems(server).find((item) => item.title.includes('localhost'));
    expect(revealPassword(server, saved?.id ?? '')).toBe(generated);
    await page.close();
  });

  const evictionPoints = ['before-generate', 'after-generate', 'after-prompt'] as const;

  for (const point of evictionPoints) {
    test(`loses no generated password when the service worker is evicted ${point}`, async () => {
      const page = await browser.context.newPage();
      if (point === 'before-generate') await browser.evictWorker();
      const generated = await generateOnSignup(page);
      if (point === 'after-generate') await browser.evictWorker();
      await page.locator('#submit').click();
      await expect(page.locator('#welcome')).toBeVisible();
      const frame = await menuFrame(page);
      const save = frame.locator('button.btn.pri');
      await expect(save).toBeVisible();
      if (point === 'after-prompt') await browser.evictWorker();
      await save.hover();
      await page.waitForTimeout(700);
      await save.click();
      await expect.poll(() => site.signups.at(-1)?.password, { timeout: 30_000 }).toBe(generated);
      await expect
        .poll(
          () => listItems(server).some((item) => revealPassword(server, item.id) === generated),
          { timeout: 30_000 },
        )
        .toBe(true);
      const popup = await browser.popup();
      await expect(popup.getByTestId('generated')).toBeVisible();
      await popup.close();
      await page.close();
    });
  }
});
