import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { Frame, Page } from '@playwright/test';

import { createFakeBackground } from './fake-background.ts';
import type { FakeBackground, VaultItem } from './fake-background.ts';
import { FRAME_ORIGIN, PAGE_ORIGIN } from './ports.ts';

const here = dirname(fileURLToPath(import.meta.url));

export const distScript = (name: string): string =>
  readFileSync(join(here, 'dist', `${name}.js`), 'utf8');

export const defaultItems: VaultItem[] = [
  {
    itemId: 'item-1',
    title: 'Local site',
    username: 'mino01',
    password: 'correct-horse-9!',
    host: 'localhost',
    otp: '123456',
  },
];

export const prepare = async (
  page: Page,
  items: VaultItem[] = defaultItems,
): Promise<FakeBackground> => {
  const fake = createFakeBackground(items);
  await page.exposeBinding('haspBg', async (source, raw: string) => {
    const reply = await fake.handle(source, raw);
    return reply;
  });
  await page.exposeBinding('haspHandoff', (_source, command: string, payload?: string) => {
    if (command === 'put') fake.handoff = payload === undefined ? undefined : JSON.parse(payload);
    if (command === 'clear') fake.handoff = undefined;
    return command === 'take' && fake.handoff !== undefined ? JSON.stringify(fake.handoff) : null;
  });
  await page.addInitScript(distScript('page'));
  return fake;
};

export const openPage = async (page: Page, path: string): Promise<void> => {
  await page.goto(`${PAGE_ORIGIN}${path}`);
  await page.waitForFunction('window.haspEngine !== undefined');
};

export const menuFrame = (page: Page): Frame | undefined =>
  page.frames().find((f) => f.url().startsWith(FRAME_ORIGIN));

export const waitForMenu = async (page: Page, timeoutMs = 3000): Promise<Frame | undefined> => {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const frame = menuFrame(page);
    if (frame !== undefined) {
      const count = await frame
        .locator('[role="menuitem"],.btn')
        .count()
        .catch(() => 0);
      if (count > 0) return frame;
    }
    await page.waitForTimeout(50);
  }
  return undefined;
};

export const rowCenter = async (
  frame: Frame,
  selector = '[role="menuitem"]',
  index = 0,
): Promise<{ x: number; y: number } | undefined> => {
  const box = await frame
    .locator(selector)
    .nth(index)
    .boundingBox({ timeout: 500 })
    .catch(() => null);
  return box === null ? undefined : { x: box.x + box.width / 2, y: box.y + box.height / 2 };
};

const isTouchPage = async (page: Page): Promise<boolean> => {
  const touch = await page.evaluate('navigator.maxTouchPoints > 0');
  return touch === true;
};

export const humanClick = async (page: Page, at: { x: number; y: number }): Promise<void> => {
  if (await isTouchPage(page)) {
    await page.touchscreen.tap(at.x, at.y);
    await page.waitForTimeout(DWELL_WAIT_MS);
    await page.touchscreen.tap(at.x, at.y);
    return;
  }
  await page.mouse.move(at.x - 6, at.y - 3);
  await page.mouse.move(at.x, at.y, { steps: 3 });
  await page.waitForTimeout(60);
  await page.mouse.click(at.x, at.y);
};

export const DWELL_WAIT_MS = 650;
