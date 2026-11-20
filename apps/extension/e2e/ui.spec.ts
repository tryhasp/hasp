import { expect, test } from '@playwright/test';

import {
  type Launched,
  launchExtension,
  sessionGet,
  sessionKeys,
  sessionSet,
} from './support/extension.ts';
import { type TestServer, startHaspd } from './support/haspd.ts';
import { signInPopup } from './support/helpers.ts';

let server: TestServer;
let browser: Launched;

const confirmId = 'e2e-confirm-0000000001';

test.describe.serial('browser-owned UI', () => {
  test.beforeAll(async () => {
    server = await startHaspd();
    browser = await launchExtension();
    const popup = await browser.popup();
    await signInPopup(popup, server);
    await popup.close();
  });

  test.afterAll(async () => {
    await browser.close();
    server.stop();
  });

  test('shows the secret tag in the popup after it is set in the settings page', async () => {
    const options = await browser.context.newPage();
    await options.goto(`chrome-extension://${browser.extensionId}/options.html`);
    await expect(options.getByTestId('tag-section')).toBeVisible();
    await options.getByTestId('tag-word').fill('lighthouse');
    await options.getByTestId('glyph-4').click();
    await options.getByTestId('idle-minutes').fill('7');
    await options.getByTestId('settings-save').click();
    await expect(options.getByText('Saved').or(options.getByText('저장했어요'))).toBeVisible();
    await options.close();
    const popup = await browser.popup();
    await expect(popup.getByTestId('secret-tag')).toHaveText('lighthouse');
    await popup.close();
  });

  test('the confirm window defaults to Cancel and fills only after an explicit click', async () => {
    const worker = await browser.worker();
    await sessionSet(worker, `hasp:confirm:${confirmId}`, {
      tabId: 1,
      frameId: 0,
      vault: 'a'.repeat(32),
      item: 'b'.repeat(32),
      title: 'Card shop',
      subtitle: 'carol',
      savedHost: 'pay.store.example',
      currentHost: 'shop.example',
      origin: 'https://shop.example',
      expiresMs: Date.now() + 60_000,
    });
    const confirm = await browser.context.newPage();
    await confirm.goto(`chrome-extension://${browser.extensionId}/confirm.html?id=${confirmId}`);
    await expect(confirm.getByTestId('confirm-card')).toBeVisible();
    await expect(confirm.getByTestId('confirm-cancel')).toBeFocused();
    await expect(confirm.getByTestId('secret-tag')).toHaveText('lighthouse');
    await expect(confirm.getByText('pay.store.example').first()).toBeVisible();
    await confirm.getByTestId('confirm-fill').click();
    await expect
      .poll(async () => {
        const stored = await sessionGet(worker, `hasp:confirm:${confirmId}`);
        return stored;
      })
      .toBeUndefined();
    expect(await sessionKeys(worker, 'hasp:approval:')).toHaveLength(1);
  });
});
