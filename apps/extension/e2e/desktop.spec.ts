import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { expect, test } from '@playwright/test';
import { z } from 'zod';

import { type Launched, launchExtension, localSet } from './support/extension.ts';
import { type TestServer, startHaspd } from './support/haspd.ts';
import { addLogin, listItems, signInPopup } from './support/helpers.ts';
import { type TestSite, startSite } from './support/pages.ts';

const hostScript = fileURLToPath(new URL('./support/fake-host.ts', import.meta.url));
const vaultsSchema = z.object({ data: z.array(z.object({ id: z.string() })) });
const frameSchema = z.object({
  type: z.string(),
  id: z.number(),
  host: z.string().nullable().optional(),
  focused: z.boolean().optional(),
  outcome: z.string().optional(),
});

let server: TestServer;
let site: TestSite;
let browser: Launched;
let scratch: string;

test.describe.serial('desktop fill channel', () => {
  test.beforeAll(async () => {
    server = await startHaspd();
    site = await startSite();
    addLogin(server, 'Demo shop', `${site.origin}/`, 'dora@example.com', 'desktop-secret-5521');
    scratch = mkdtempSync(join(tmpdir(), 'hasp-fake-host-'));
    browser = await launchExtension();
    const popup = await browser.popup();
    await signInPopup(popup, server);
    await popup.close();
  });

  test.afterAll(async () => {
    await browser.close();
    site.stop();
    server.stop();
    rmSync(scratch, { recursive: true, force: true });
  });

  test('answers page_query and fills the active tab on fill_request', async () => {
    const vault = vaultsSchema.parse(JSON.parse(server.cli(['vault', 'list'], ''))).data[0]?.id;
    const item = listItems(server).find((entry) => entry.title === 'Demo shop')?.id;
    if (vault === undefined || item === undefined) throw new Error('fixture missing');
    const log = join(scratch, 'host.log');
    const wrapper = join(scratch, 'host.sh');
    writeFileSync(
      wrapper,
      `#!/bin/sh\nexec "${process.execPath}" "${hostScript}" "${log}" "${vault}" "${item}"\n`,
    );
    chmodSync(wrapper, 0o755);
    const hostsDir = join(browser.profile, 'NativeMessagingHosts');
    mkdirSync(hostsDir, { recursive: true });
    writeFileSync(
      join(hostsDir, 'kr.jmo.hasp.nmh.json'),
      JSON.stringify({
        name: 'kr.jmo.hasp.nmh',
        description: 'fake Hasp desktop',
        path: wrapper,
        type: 'stdio',
        allowed_origins: [`chrome-extension://${browser.extensionId}/`],
      }),
    );

    const page = await browser.context.newPage();
    await page.goto(`${site.origin}/`);
    await page.bringToFront();
    const worker = await browser.worker();
    await localSet(worker, 'hasp:desktop-device', { hex: 'ab'.repeat(16) });
    await browser.evictWorker();
    await page.bringToFront();
    const wake = await browser.popup();
    await wake.close();
    await page.bringToFront();

    await expect
      .poll(() => site.logins, { timeout: 30_000 })
      .toEqual([{ user: 'dora@example.com', password: 'desktop-secret-5521' }]);
    await expect
      .poll(
        () =>
          readFileSync(log, 'utf8')
            .trim()
            .split('\n')
            .map((line) => frameSchema.parse(JSON.parse(line))),
        {
          timeout: 15_000,
        },
      )
      .toEqual([
        { type: 'page_reply', id: 1, host: 'localhost', focused: true },
        { type: 'fill_reply', id: 2, outcome: 'filled' },
      ]);
    await page.close();
  });

  test('shows a code in an extension window and sends a fresh 16 byte nonce on every unlock', async () => {
    const log = join(scratch, 'host.log');
    writeFileSync(`${log}.slow`, '');
    const popup = await browser.popup();
    await popup.getByTestId('lock').click();
    await expect(popup.getByTestId('locked')).toBeVisible();
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const opened = browser.context.waitForEvent('page', { timeout: 15_000 });
      await popup.getByTestId('unlock-desktop').click();
      const window = await opened;
      expect(window.url()).toContain('/code.html');
      await expect(window.getByTestId('code-value')).toHaveText(/^\d{3} \d{3}$/);
      await expect(window.getByTestId('code-value')).toBeVisible();
    }
    await popup.close();
    const read = (): { bytes: number; isFresh: boolean; isUrlSafe: boolean }[] =>
      readFileSync(log, 'utf8')
        .trim()
        .split('\n')
        .map((line): unknown => JSON.parse(line))
        .filter((entry) => z.object({ type: z.literal('unlock_check') }).safeParse(entry).success)
        .map((entry) =>
          z
            .object({ bytes: z.number(), isFresh: z.boolean(), isUrlSafe: z.boolean() })
            .parse(entry),
        );
    await expect.poll(read, { timeout: 15_000 }).toEqual([
      { bytes: 16, isFresh: true, isUrlSafe: true },
      { bytes: 16, isFresh: true, isUrlSafe: true },
    ]);
  });
});
