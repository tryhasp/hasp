import { mkdirSync } from 'node:fs';
import { join } from 'node:path';

import { expect, test } from '@playwright/test';

import { type Launched, launchExtension, localSet, sessionSet } from './support/extension.ts';
import { type TestServer, startHaspd } from './support/haspd.ts';
import { menuFrame } from './support/helpers.ts';
import { type TestSite, startSite } from './support/pages.ts';

const directory = process.env['HASP_EXT_SHOTS_DIR'];
const popupSize = { width: 360, height: 560 };

let server: TestServer;
let site: TestSite;
let browser: Launched;

test.describe.serial('screenshots', () => {
  test.skip(directory === undefined, 'set HASP_EXT_SHOTS_DIR to write the screenshots');

  test.beforeAll(async () => {
    if (directory !== undefined) mkdirSync(directory, { recursive: true });
    server = await startHaspd();
    site = await startSite();
    const seed = (title: string, url: string, user: string): void => {
      server.cli(
        [
          'item',
          'create',
          '--title',
          title,
          '--url',
          url,
          '--subtitle',
          user,
          '--field',
          `username=${user}`,
          '--field-stdin',
          'password',
        ],
        'seed-secret-1\n',
      );
    };
    seed('Demo shop', `${site.origin}/`, 'bob@example.com');
    seed('네이버', 'https://nid.naver.com/', 'mino.dev');
    seed('GitHub', 'https://github.com/', 'octocat');
    browser = await launchExtension();
  });

  test.afterAll(async () => {
    await browser.close();
    site.stop();
    server.stop();
  });

  const shoot = async (
    target: { screenshot: (o: { path: string }) => Promise<unknown> },
    name: string,
  ) => {
    if (directory === undefined) return;
    await target.screenshot({ path: join(directory, `${name}.png`) });
  };

  test('onboarding with the fingerprint step', async () => {
    await localSet(await browser.worker(), 'hasp:locale', 'ko');
    const popup = await browser.popup();
    await popup.setViewportSize(popupSize);
    await shoot(popup, 'onboarding-server');
    await popup.getByTestId('signin-server').fill(server.origin);
    await popup.getByTestId('signin-next').click();
    await expect(popup.getByTestId('signin-fingerprint-shown')).toHaveText(server.fingerprint);
    await shoot(popup, 'onboarding-fingerprint');
    await popup.getByTestId('signin-fingerprint').fill(server.fingerprint);
    await popup.getByTestId('signin-confirm').click();
    await popup.getByTestId('signin-login').fill(server.login);
    await shoot(popup, 'onboarding-account');
    await popup.getByTestId('signin-secret-key').fill(server.secretKey);
    await popup.getByTestId('signin-password').fill(server.password);
    await popup.getByTestId('signin-submit').click();
    await expect(popup.getByTestId('search')).toBeVisible({ timeout: 60_000 });
    await popup.close();
  });

  test('popup, inline menu, settings and confirm', async () => {
    const options = await browser.context.newPage();
    await options.setViewportSize({ width: 900, height: 900 });
    await options.goto(`chrome-extension://${browser.extensionId}/options.html`);
    await options.getByTestId('tag-word').fill('lighthouse');
    await options.getByTestId('glyph-4').click();
    await shoot(options, 'settings');
    await options.getByTestId('settings-save').click();
    await expect(options.getByText('저장했어요')).toBeVisible();
    await options.close();

    const page = await browser.context.newPage();
    await page.setViewportSize({ width: 900, height: 520 });
    await page.goto(`${site.origin}/`);
    await page.locator('#user').click();
    const frame = await menuFrame(page);
    await expect(frame.getByRole('menuitem').first()).toContainText('Demo shop');
    await page.waitForTimeout(600);
    await shoot(page, 'inline-menu');

    const popup = await browser.popup();
    await popup.setViewportSize(popupSize);
    await page.bringToFront();
    await popup.reload();
    await expect(popup.getByTestId('site-matches').getByText('Demo shop')).toBeVisible();
    await shoot(popup, 'popup');
    await popup.getByTestId('search').fill('네이');
    await expect(popup.getByTestId('results')).toBeVisible();
    await shoot(popup, 'popup-search');
    await popup.close();
    await page.close();

    const worker = await browser.worker();
    const id = 'e2e-confirm-shot-0001';
    await sessionSet(worker, `hasp:confirm:${id}`, {
      tabId: 1,
      frameId: 0,
      vault: 'a'.repeat(32),
      item: 'b'.repeat(32),
      title: '쿠팡',
      subtitle: 'mino@example.com',
      savedHost: 'www.coupang.com',
      currentHost: 'www.coupang-login.example',
      expiresMs: Date.now() + 600_000,
    });
    const confirm = await browser.context.newPage();
    await confirm.setViewportSize({ width: 420, height: 520 });
    await confirm.goto(`chrome-extension://${browser.extensionId}/confirm.html?id=${id}`);
    await expect(confirm.getByTestId('confirm-card')).toBeVisible();
    await shoot(confirm, 'confirm');
    await confirm.close();
  });
});
