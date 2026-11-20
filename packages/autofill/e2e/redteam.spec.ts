import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';

import { techniques } from '../redteam/build.ts';
import { writeMetrics } from './metrics.ts';
import {
  DWELL_WAIT_MS,
  humanClick,
  menuFrame,
  openPage,
  prepare,
  rowCenter,
  waitForMenu,
} from './support.ts';

type Expectation = 'blocked' | 'allowed';

const expectations: Readonly<Record<string, Expectation>> = {
  benign: 'allowed',
  'port-spoof': 'allowed',
  'hidden-duplicate-fields': 'allowed',
};

const passive: ReadonlySet<string> = new Set(['synthetic-events', 'fake-menu']);

const values = async (page: Page): Promise<string[]> => {
  const result = await page.evaluate(() =>
    [...document.querySelectorAll('input')].map((i) => i.value),
  );
  return result;
};

const attempt = async (
  page: Page,
  name: string,
): Promise<{ sawMenu: boolean; fillsBeforeClick: number }> => {
  if (!passive.has(name)) {
    await page
      .locator('#u')
      .click({ force: true, timeout: 2000 })
      .catch(() => undefined);
    await page.evaluate("document.getElementById('u')?.focus()");
  }
  const frame = await waitForMenu(page, 1500);
  if (name === 'fake-menu') {
    await humanClick(page, { x: 200, y: 284 });
    return { sawMenu: false, fillsBeforeClick: 0 };
  }
  if (frame !== undefined) await page.waitForTimeout(DWELL_WAIT_MS);
  await page.evaluate('window.attack && window.attack()');
  await page.waitForTimeout(350);
  const live = menuFrame(page);
  const at = live === undefined ? undefined : await rowCenter(live);
  const fillsBeforeClick = 0;
  if (at !== undefined) await humanClick(page, at);
  await page.waitForTimeout(500);
  return { sawMenu: frame !== undefined, fillsBeforeClick };
};

for (const technique of techniques) {
  test(`red team: ${technique.name}`, async ({ page }, info) => {
    const fake = await prepare(page);
    await openPage(page, `/redteam/${technique.name}.html`);
    const expected = expectations[technique.name] ?? 'blocked';
    if (technique.name === 'port-spoof') {
      await page.locator('#u').click();
      await waitForMenu(page);
      await page.waitForTimeout(DWELL_WAIT_MS);
      await page.evaluate('window.attack && window.attack()');
      await page.waitForTimeout(400);
      expect(fake.fills).toHaveLength(0);
    }
    const result = await attempt(page, technique.name);
    const vals = await values(page);
    writeMetrics(`redteam-${technique.name}`, info.project.name, {
      expected,
      sawMenu: result.sawMenu,
      fills: fake.fills.length,
      strikes: fake.strikes.map((s) => s.check),
      values: vals.map((v) => (v === '' ? 'empty' : 'set')),
      source: technique.source,
    });
    if (expected === 'blocked') {
      expect(vals.every((v) => v === '')).toBe(true);
      expect(fake.fills).toHaveLength(0);
    } else {
      expect(vals.slice(0, 2)).toEqual(['mino01', 'correct-horse-9!']);
      expect(fake.fills).toHaveLength(1);
      if (technique.name === 'hidden-duplicate-fields') {
        expect(vals.slice(2)).toEqual(['', '']);
      }
    }
  });
}

test('red team: three obscured attempts disable the inline menu for the page session', async ({
  page,
}) => {
  const fake = await prepare(page);
  await openPage(page, '/redteam/opacity-body-after-show.html');
  for (let i = 0; i < 3; i += 1) {
    await page.evaluate("document.body.style.opacity=''");
    await page.evaluate('document.activeElement && document.activeElement.blur()');
    await page.locator('#u').click();
    await waitForMenu(page, 1500);
    await page.waitForTimeout(DWELL_WAIT_MS);
    await page.evaluate('window.attack && window.attack()');
    await page.waitForTimeout(450);
  }
  await page.evaluate("document.body.style.opacity=''");
  expect(fake.strikes.length).toBeGreaterThanOrEqual(3);
  const notices = await page.evaluate('window.haspNotices');
  expect(notices).toContain('strike-limit');
  await page.evaluate('document.activeElement && document.activeElement.blur()');
  await page.locator('#u').click();
  await page.waitForTimeout(800);
  expect(menuFrame(page)).toBeUndefined();
});
