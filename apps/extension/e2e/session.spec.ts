import { expect, test } from '@playwright/test';

import { type Launched, launchExtension, sessionGet, storageDump } from './support/extension.ts';
import { type TestServer, startHaspd } from './support/haspd.ts';
import { signInPopup } from './support/helpers.ts';

const forms = (password: string): string[] => {
  const bytes = Buffer.from(password);
  return [
    password,
    password.normalize('NFKD'),
    bytes.toString('hex'),
    bytes.toString('base64'),
    bytes.toString('base64url'),
    JSON.stringify(password).slice(1, -1),
  ];
};

let server: TestServer;
let browser: Launched;

test.describe.serial('standalone session', () => {
  test.beforeAll(async () => {
    server = await startHaspd();
    browser = await launchExtension();
  });

  test.afterAll(async () => {
    await browser.close();
    server.stop();
  });

  test('signs in with the password and secret key', async () => {
    const popup = await browser.popup();
    await expect(popup.getByTestId('sign-in')).toBeVisible();
    await signInPopup(popup, server);
    await popup.close();
  });

  test('locks and unlocks with the password', async () => {
    const popup = await browser.popup();
    await popup.getByTestId('lock').click();
    await expect(popup.getByTestId('locked')).toBeVisible();
    await popup.getByTestId('unlock-password').fill('wrong password here');
    await popup.getByTestId('unlock-submit').click();
    await expect(popup.getByRole('alert')).toBeVisible({ timeout: 60_000 });
    await popup.getByTestId('unlock-password').fill(server.password);
    await popup.getByTestId('unlock-submit').click();
    await expect(popup.getByTestId('search')).toBeVisible({ timeout: 60_000 });
    await popup.close();
  });

  test('never stores the password, after unlock or after eviction', async () => {
    const popup = await browser.popup();
    await expect(popup.getByTestId('search')).toBeVisible();
    await popup.close();
    let worker = await browser.worker();
    const afterUnlock = await storageDump(worker);
    for (const form of forms(server.password)) expect(afterUnlock).not.toContain(form);
    const ticket = await sessionGet(worker, 'hasp:ticket');
    expect(ticket).toMatchObject({ kind: 'session' });

    await browser.evictWorker();
    worker = await browser.worker();
    const resumed = await browser.popup();
    await expect(resumed.getByTestId('search')).toBeVisible({ timeout: 60_000 });
    await resumed.getByTestId('search').fill('x');
    await resumed.close();
    const afterEviction = await storageDump(worker);
    for (const form of forms(server.password)) expect(afterEviction).not.toContain(form);
    expect(await sessionGet(worker, 'hasp:ticket')).toMatchObject({ kind: 'session' });
  });

  test('clears the session blob on lock', async () => {
    const popup = await browser.popup();
    await popup.getByTestId('lock').click();
    await expect(popup.getByTestId('locked')).toBeVisible();
    const worker = await browser.worker();
    expect(await sessionGet(worker, 'hasp:ticket')).toBeUndefined();
    await popup.close();
  });
});
