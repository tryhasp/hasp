import { type Frame, type Page, expect } from '@playwright/test';
import { z } from 'zod';

import type { TestServer } from './haspd.ts';

const listSchema = z.object({ data: z.array(z.object({ id: z.string(), title: z.string() })) });
const detailSchema = z.object({
  data: z.object({
    fields: z.array(z.object({ purpose: z.string().nullable(), value: z.string() })),
  }),
});

export const signInPopup = async (popup: Page, server: TestServer): Promise<void> => {
  await popup.getByTestId('signin-server').fill(server.origin);
  await popup.getByTestId('signin-next').click();
  await expect(popup.getByTestId('signin-fingerprint-shown')).toHaveText(server.fingerprint);
  await popup.getByTestId('signin-fingerprint').fill(server.fingerprint);
  await popup.getByTestId('signin-confirm').click();
  await popup.getByTestId('signin-login').fill(server.login);
  await popup.getByTestId('signin-secret-key').fill(server.secretKey);
  await popup.getByTestId('signin-password').fill(server.password);
  await popup.getByTestId('signin-submit').click();
  await expect(popup.getByTestId('search')).toBeVisible({ timeout: 60_000 });
};

export const menuFrame = async (page: Page): Promise<Frame> => {
  let found: Frame | undefined;
  await expect
    .poll(
      () => {
        found = page.frames().find((frame) => frame.url().includes('menu-frame.html'));
        return found !== undefined;
      },
      { timeout: 15_000 },
    )
    .toBe(true);
  if (found === undefined) throw new Error('menu frame missing');
  await found.waitForLoadState('domcontentloaded');
  return found;
};

export const clickWithDwell = async (
  frame: Frame,
  selector: string,
  index: number,
): Promise<void> => {
  const target = frame.locator(selector).nth(index);
  await target.waitFor({ state: 'visible' });
  await target.hover();
  await frame.page().waitForTimeout(700);
  await target.click();
};

export const addLogin = (
  server: TestServer,
  title: string,
  url: string,
  username: string,
  password: string,
): void => {
  server.cli(
    [
      'item',
      'create',
      '--title',
      title,
      '--url',
      url,
      '--field',
      `username=${username}`,
      '--field-stdin',
      'password',
    ],
    `${password}\n`,
  );
};

export const listItems = (server: TestServer): { id: string; title: string }[] => {
  server.cli(['sync'], '');
  return listSchema.parse(JSON.parse(server.cli(['item', 'list'], ''))).data;
};

export const revealPassword = (server: TestServer, id: string): string => {
  const parsed = detailSchema.parse(JSON.parse(server.cli(['--reveal', 'item', 'get', id], '')));
  return parsed.data.fields.find((field) => field.purpose === 'password')?.value ?? '';
};
