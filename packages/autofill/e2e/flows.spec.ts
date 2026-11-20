import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';

import {
  DWELL_WAIT_MS,
  humanClick,
  menuFrame,
  openPage,
  prepare,
  rowCenter,
  waitForMenu,
} from './support.ts';

const pickFirst = async (page: Page, selector = '[role="menuitem"]', index = 0): Promise<void> => {
  const frame = await waitForMenu(page);
  expect(frame).toBeDefined();
  if (frame === undefined) return;
  await page.waitForTimeout(DWELL_WAIT_MS);
  const at = await rowCenter(frame, selector, index);
  expect(at).toBeDefined();
  if (at !== undefined) await humanClick(page, at);
};

test('username-first SPA flow continues with one approval', async ({ page }) => {
  const fake = await prepare(page);
  fake.options.isAutosubmit = true;
  await openPage(page, '/redteam/flow-spa.html');
  await page.locator('#u').click();
  await pickFirst(page);
  await expect(page.locator('#p')).toHaveValue('correct-horse-9!', { timeout: 6000 });
  expect(fake.fills.map((f) => f.purposes)).toEqual([['username'], ['password']]);
});

test('split otp cells are filled one per cell', async ({ page }) => {
  await prepare(page);
  await openPage(page, '/redteam/otp-split.html');
  await page.locator('#cells input').first().click();
  await pickFirst(page);
  await expect(page.locator('#cells input').nth(5)).toHaveValue('6');
  const values = await page
    .locator('#cells input')
    .evaluateAll((els) => els.map((e) => (e instanceof HTMLInputElement ? e.value : '')).join(''));
  expect(values).toBe('123456');
});

test('generated password respects maxlength and fills both fields', async ({ page }) => {
  const fake = await prepare(page);
  await openPage(page, '/redteam/signup-gen.html');
  await page.locator('#n').click();
  const frame = await waitForMenu(page);
  expect(frame).toBeDefined();
  await page.waitForTimeout(DWELL_WAIT_MS);
  await page.keyboard.press('ArrowDown');
  await page.keyboard.press('Enter');
  await expect(page.locator('#n')).toHaveValue('Qx7!kM2-pR9#');
  await expect(page.locator('#c')).toHaveValue('Qx7!kM2-pR9#');
  expect(fake.fills).toHaveLength(0);
  expect(await fake.store.get('generated')).toHaveLength(1);
});

test('typed credentials produce a save prompt after the form disappears', async ({ page }) => {
  const fake = await prepare(page, []);
  await openPage(page, '/redteam/save-login.html');
  await page.locator('#u').click();
  await page.keyboard.type('newuser');
  await page.locator('#p').click();
  await page.keyboard.type('s3cret-pass!');
  await page.keyboard.press('Enter');
  const frame = await waitForMenu(page, 5000);
  expect(frame).toBeDefined();
  if (frame === undefined) return;
  await page.waitForTimeout(DWELL_WAIT_MS);
  const at = await rowCenter(frame, '.btn.pri');
  expect(at).toBeDefined();
  if (at !== undefined) await humanClick(page, at);
  await expect.poll(() => fake.saved.length).toBe(1);
  expect(fake.saved[0]).toEqual({ username: 'newuser', password: 's3cret-pass!' });
});

test('cross-origin and sandboxed iframes get no inline menu', async ({ page }) => {
  const fake = await prepare(page, [
    { itemId: 'i2', title: 'Loopback', username: 'u', password: 'p', host: '127.0.0.1' },
  ]);
  await openPage(page, '/redteam/iframe-cross.html');
  const inner = page.frameLocator('#x').locator('#u');
  await inner.click();
  await page.waitForTimeout(1200);
  expect(menuFrame(page)).toBeUndefined();
  await page.frameLocator('#s').locator('#u').click();
  await page.waitForTimeout(600);
  expect(menuFrame(page)).toBeUndefined();
  expect(fake.fills).toHaveLength(0);
});

const typeCredentials = async (page: Page, user: string, password: string): Promise<void> => {
  await page.locator('#u').click();
  await page.keyboard.type(user);
  await page.locator('#p').click();
  await page.keyboard.type(password);
};

const confirmSave = async (page: Page): Promise<void> => {
  const frame = await waitForMenu(page, 5000);
  expect(frame).toBeDefined();
  if (frame === undefined) return;
  await page.waitForTimeout(DWELL_WAIT_MS);
  const at = await rowCenter(frame, '.btn.pri');
  expect(at).toBeDefined();
  if (at !== undefined) await humanClick(page, at);
};

const pageStorageDump = async (page: Page): Promise<string> =>
  page.evaluate(() =>
    JSON.stringify({
      session: Object.entries(window.sessionStorage),
      local: Object.entries(window.localStorage),
      cookie: document.cookie,
      name: window.name,
    }),
  );

test('typed credentials are saved when the capture and submit messages are lost', async ({
  page,
}) => {
  const fake = await prepare(page, []);
  fake.options.isSubmitMessageLost = true;
  await openPage(page, '/redteam/save-login.html');
  await typeCredentials(page, 'newuser', 's3cret-pass!');
  await page.keyboard.press('Enter');
  await confirmSave(page);
  await expect.poll(() => fake.saved.length).toBe(1);
  expect(fake.saved[0]).toEqual({ username: 'newuser', password: 's3cret-pass!' });
  expect(fake.handoff).toBeUndefined();
});

test('typed credentials are saved after a navigation when the messages are lost', async ({
  page,
}) => {
  const fake = await prepare(page, []);
  fake.options.isSubmitMessageLost = true;
  await openPage(page, '/redteam/save-login-nav.html');
  await typeCredentials(page, 'navuser', 'n4v-secret!');
  await page.keyboard.press('Enter');
  await page.waitForURL('**/redteam/ready.html');
  await confirmSave(page);
  await expect.poll(() => fake.saved.length).toBe(1);
  expect(fake.saved[0]).toEqual({ username: 'navuser', password: 'n4v-secret!' });
  expect(fake.handoff).toBeUndefined();
});

test('a form that posts to another origin never writes its values to the handoff', async ({
  page,
}) => {
  const fake = await prepare(page, []);
  fake.options.isSubmitMessageLost = true;
  await openPage(page, '/redteam/save-login-cross.html');
  await typeCredentials(page, 'xuser', 'x-secret-pw!');
  await page.keyboard.press('Enter');
  await expect.poll(() => fake.handoff).toBeDefined();
  const stored = JSON.stringify(fake.handoff);
  expect(stored).not.toContain('x-secret-pw!');
  expect(stored).not.toContain('xuser');
  expect(fake.saved).toHaveLength(0);
});

test('a page cannot read the typed values from any page storage after submit', async ({ page }) => {
  const fake = await prepare(page, []);
  fake.options.isSubmitMessageLost = true;
  await openPage(page, '/redteam/save-login.html');
  await typeCredentials(page, 'readuser', 'read-secret-pw!');
  await page.keyboard.press('Enter');
  await expect.poll(() => fake.handoff).toBeDefined();
  const dump = await pageStorageDump(page);
  expect(dump).not.toContain('read-secret-pw!');
  expect(dump).not.toContain('readuser');
  expect(dump).not.toContain('submit-handoff');
  expect(JSON.stringify(fake.handoff)).toContain('read-secret-pw!');
});

test('a handoff forged in page storage never produces a save prompt', async ({ page }) => {
  const fake = await prepare(page, []);
  await openPage(page, '/redteam/ready.html');
  await page.evaluate(() => {
    const record = JSON.stringify({
      atMs: Date.now(),
      origin: location.origin,
      values: { username: 'victim@x.com', newPassword: 'attacker-chosen' },
    });
    for (const key of ['hasp:submit-handoff', 'handoff', 'handoff:top:' + location.origin]) {
      window.sessionStorage.setItem(key, record);
      window.localStorage.setItem(key, record);
    }
  });
  await page.reload();
  await page.waitForFunction('window.haspEngine !== undefined');
  await page.waitForTimeout(1500);
  expect(menuFrame(page)).toBeUndefined();
  expect(fake.saved).toHaveLength(0);
  expect(fake.requests).not.toContain('capture');
  expect(await fake.store.get('pending:1:localhost')).toBeUndefined();
});
