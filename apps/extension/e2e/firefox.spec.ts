import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { expect, test } from '@playwright/test';

import { type TestServer, startHaspd } from './support/haspd.ts';
import { addLogin } from './support/helpers.ts';
import { type FirefoxSession, firefoxPath, launchFirefox } from './support/marionette.ts';
import { type TestSite, startSite } from './support/pages.ts';

const root = fileURLToPath(new URL('..', import.meta.url));
const outDir = fileURLToPath(new URL('../.output-e2e/firefox-mv3', import.meta.url));

let server: TestServer;
let site: TestSite;
let ff: FirefoxSession;

const knownUser = 'bob@example.com';
const knownPassword = 'known-secret-9981';

test.describe.serial('Firefox (Marionette, temporary add-on)', () => {
  test.skip(!existsSync(firefoxPath()), 'Playwright Firefox is not installed');

  test.beforeAll(async () => {
    execFileSync('pnpm', ['exec', 'wxt', 'build', '-b', 'firefox'], {
      cwd: root,
      env: { ...process.env, HASP_E2E: '1' },
      stdio: 'ignore',
    });
    server = await startHaspd();
    site = await startSite();
    addLogin(server, 'Demo shop', `${site.origin}/`, knownUser, knownPassword);
    ff = await launchFirefox(outDir);
  });

  test.afterAll(async () => {
    await ff.close();
    site.stop();
    server.stop();
  });

  test('signs in after comparing the server fingerprint', async () => {
    await ff.open(`${ff.extensionOrigin}/popup.html`);
    await ff.type('[data-testid=signin-server]', server.origin);
    await ff.click('[data-testid=signin-next]');
    await expect
      .poll(async () => {
        const text = await ff.text('[data-testid=signin-fingerprint-shown]');
        return text;
      })
      .toBe(server.fingerprint);
    await ff.type('[data-testid=signin-fingerprint]', server.fingerprint);
    await ff.click('[data-testid=signin-confirm]');
    await ff.type('[data-testid=signin-login]', server.login);
    await ff.type('[data-testid=signin-secret-key]', server.secretKey);
    await ff.type('[data-testid=signin-password]', server.password);
    await ff.click('[data-testid=signin-submit]');
    await ff.waitFor('[data-testid=search]', 90_000);
  });

  test('finds items by search in the popup', async () => {
    await ff.type('[data-testid=search]', 'Demo');
    await expect
      .poll(async () => {
        const text = await ff.text('[data-testid=results]');
        return text;
      })
      .toContain('Demo shop');
  });

  test('fills a login from the inline menu', async () => {
    await ff.open(`${site.origin}/`);
    await ff.click('#user');
    const host = await ff.waitFor('div[popover]');
    const shadow = await ff.command('WebDriver:GetShadowRoot', { id: host });
    expect(shadow).toBeDefined();
    const frame = await ff.frameInShadow(host);
    await ff.command('WebDriver:SwitchToFrame', { id: frame });
    await ff.waitFor('[role=menuitem]');
    await ff.sleep(900);
    await ff.click('[role=menuitem]');
    await expect
      .poll(() => site.logins, { timeout: 30_000 })
      .toEqual([{ user: knownUser, password: knownPassword }]);
  });
});
