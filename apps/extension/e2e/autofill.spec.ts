import { type Page, expect, test } from '@playwright/test';

import { type Launched, launchExtension } from './support/extension.ts';
import { type TestServer, startHaspd } from './support/haspd.ts';
import { addLogin, clickWithDwell, menuFrame, signInPopup } from './support/helpers.ts';
import { type TestSite, startSite } from './support/pages.ts';

let server: TestServer;
let site: TestSite;
let browser: Launched;

const knownUser = 'bob@example.com';
const knownPassword = 'known-secret-9981';

test.describe.serial('autofill in the browser', () => {
  test.beforeAll(async () => {
    server = await startHaspd();
    site = await startSite();
    addLogin(server, 'Demo shop', `${site.origin}/`, knownUser, knownPassword);
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

  test('syncs an item that another device added', async () => {
    addLogin(
      server,
      'Second shop',
      'https://second.example/',
      'carol@example.com',
      'second-secret-77',
    );
    const popup = await browser.popup();
    await popup.getByTestId('sync').click();
    await popup.getByTestId('search').fill('Second');
    await expect(popup.getByTestId('results').getByText('Second shop')).toBeVisible({
      timeout: 30_000,
    });
    await popup.close();
  });

  test('finds items by search in the popup', async () => {
    const popup = await browser.popup();
    await popup.getByTestId('search').fill('Demo');
    await expect(popup.getByTestId('results').getByText('Demo shop')).toBeVisible();
    await popup.getByTestId('search').fill('nothing-matches-this');
    await expect(popup.getByTestId('results').getByText('Demo shop')).toBeHidden();
    await popup.close();
  });

  test('lists current-site matches in the popup', async () => {
    const page: Page = await browser.context.newPage();
    await page.goto(`${site.origin}/`);
    const popup = await browser.popup();
    await page.bringToFront();
    await popup.reload();
    await expect(popup.getByTestId('site-matches').getByText('Demo shop')).toBeVisible();
    await popup.close();
    await page.close();
  });

  test('fills a login from the inline menu', async () => {
    const page = await browser.context.newPage();
    await page.goto(`${site.origin}/`);
    await page.locator('#user').click();
    const frame = await menuFrame(page);
    await expect(frame.getByRole('menuitem').first()).toContainText('Demo shop');
    await clickWithDwell(frame, '[role=menuitem]', 0);
    await expect.poll(() => site.logins).toEqual([{ user: knownUser, password: knownPassword }]);
    await page.close();
  });
});
