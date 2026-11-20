import { type Page, expect, test } from '@playwright/test';

import { type Launched, launchExtension } from './support/extension.ts';
import { type TestServer, startHaspd } from './support/haspd.ts';
import { signInPopup } from './support/helpers.ts';
import { type RelyingParty, startRelyingParty } from './support/rp.ts';

let server: TestServer;
let rp: RelyingParty;
let browser: Launched;

const passkeyWindow = async (action: () => Promise<void>): Promise<Page> => {
  const opened = browser.context.waitForEvent('page', {
    predicate: (candidate) => candidate.url().includes('passkey.html'),
  });
  await action();
  const window = await opened;
  await window.waitForLoadState('domcontentloaded');
  return window;
};

const resultOf = async (page: Page): Promise<string> => {
  await expect(page.locator('#result')).not.toBeEmpty({ timeout: 30_000 });
  return (await page.locator('#result').textContent()) ?? '';
};

test.describe.serial('passkeys in the browser', () => {
  test.beforeAll(async () => {
    server = await startHaspd();
    rp = await startRelyingParty();
    browser = await launchExtension();
    const popup = await browser.popup();
    await signInPopup(popup, server);
    await popup.close();
  });

  test.afterAll(async () => {
    await browser.close();
    rp.stop();
    server.stop();
  });

  test('registers a passkey after the origin-bound confirm and the RP verifies it', async () => {
    const page = await browser.context.newPage();
    await page.goto(`${rp.origin}/`);
    const card = await passkeyWindow(async () => {
      await page.locator('#register').click();
    });
    await expect(card.getByTestId('passkey-account')).toHaveText('alice@rp.test');
    await card.getByTestId('passkey-password').fill(server.password);
    await card.getByTestId('passkey-use').click();
    expect(await resultOf(page)).toContain('"ok":true');
    expect(rp.registrations).toHaveLength(1);
    expect(rp.failures).toEqual([]);
    await page.close();
  });

  test('signs in with the Hasp passkey and the RP verifies the signature', async () => {
    const page = await browser.context.newPage();
    await page.goto(`${rp.origin}/`);
    const card = await passkeyWindow(async () => {
      await page.locator('#login').click();
    });
    await expect(card.getByTestId('passkey-option')).toHaveCount(1);
    await card.getByTestId('passkey-password').fill(server.password);
    await card.getByTestId('passkey-use').click();
    expect(await resultOf(page)).toContain('"ok":true');
    expect(rp.assertions).toHaveLength(1);
    expect(rp.assertions[0]?.credentialId).toBe(rp.registrations[0]?.credentialId);
    expect(rp.assertions[0]?.userVerified).toBe(true);
    expect(rp.failures).toEqual([]);
    await page.close();
  });

  test('asks for the master password when the RP requires user verification', async () => {
    const page = await browser.context.newPage();
    await page.goto(`${rp.origin}/?uv=required`);
    const card = await passkeyWindow(async () => {
      await page.locator('#login').click();
    });
    await card.getByTestId('passkey-password').fill('not the password');
    await card.getByTestId('passkey-use').click();
    await expect(card.getByRole('alert')).toBeVisible({ timeout: 60_000 });
    await card.getByTestId('passkey-password').fill(server.password);
    await card.getByTestId('passkey-use').click();
    expect(await resultOf(page)).toContain('"ok":true');
    expect(rp.assertions.at(-1)?.userVerified).toBe(true);
    await page.close();
  });

  test('reports user verification only when a re-authentication really happened', async () => {
    const page = await browser.context.newPage();
    await page.goto(`${rp.origin}/?uv=discouraged`);
    const card = await passkeyWindow(async () => {
      await page.locator('#login').click();
    });
    await expect(card.getByTestId('passkey-password')).toHaveCount(0);
    await card.getByTestId('passkey-use').click();
    expect(await resultOf(page)).toContain('"ok":true');
    expect(rp.assertions.at(-1)?.userVerified).toBe(false);
    await page.close();
  });

  test('falls back to the native authenticator when the user declines', async () => {
    const page = await browser.context.newPage();
    const cdp = await browser.context.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2',
        transport: 'internal',
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true,
      },
    });
    await page.goto(`${rp.origin}/`);
    const before = rp.registrations.length;
    const card = await passkeyWindow(async () => {
      await page.locator('#register').click();
    });
    await card.getByTestId('passkey-decline').click();
    expect(await resultOf(page)).toContain('"ok":true');
    expect(rp.registrations).toHaveLength(before + 1);
    expect(rp.registrations.at(-1)?.credentialId).not.toBe(rp.registrations[0]?.credentialId);
    await page.close();
  });
});
