// oxlint-disable typescript/promise-function-async -- mocks return resolved promises
import { err, ok } from '@hasp/autofill';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { DesktopLink, ExtensionMessage } from '../platform/native.ts';

const sent: ExtensionMessage[] = [];
const shown: { device: string; nonce: string }[] = [];
const closed: string[] = [];
const events: string[] = [];

vi.mock('@hasp/wasm', () => ({
  settleAsync: (p: Promise<unknown>) => p.then((value) => ({ ok: true, value })),
}));
vi.mock('../platform/clipboard.ts', () => ({ clearClipboardWhenDue: () => Promise.resolve() }));
vi.mock('../platform/log.ts', () => ({ report: () => undefined }));
vi.mock('../platform/browser.ts', () => ({ targetBrowser: () => 'chrome' }));
vi.mock('../platform/native.ts', () => ({
  isDesktopReachable: () => Promise.resolve(true),
  newRequestId: () => 1,
  errorOfCode: () => ({ kind: 'declined' }),
  openDesktopLink: (): DesktopLink => ({
    send: (message) => {
      sent.push(message);
      events.push('send');
      return Promise.resolve(ok(null));
    },
    receive: () => {
      events.push('receive');
      return Promise.resolve(err({ kind: 'declined' as const }));
    },
    close: () => undefined,
  }),
}));
vi.mock('../platform/storage.ts', () => ({
  defineKey: (area: string, name: string) => ({ area, name }),
  clearSession: () => Promise.resolve(),
  readKey: () => Promise.resolve({ ok: true, value: { hex: 'ab'.repeat(16) } }),
  removeKey: () => Promise.resolve(),
  writeKey: () => Promise.resolve({ ok: true, value: null }),
}));
vi.mock('../platform/tabs.ts', () => ({
  hasOriginPermission: () => Promise.resolve(true),
  pushToAllTabs: () => Promise.resolve(),
  uiLocale: () => 'en',
}));
vi.mock('./client.ts', () => ({
  adoptClient: () => Promise.resolve(),
  createClient: () => Promise.resolve({}),
  dropClient: () => Promise.resolve(),
  getClient: () => Promise.resolve({}),
  persistIfChanged: () => Promise.resolve(),
  statusOf: () => Promise.resolve({ ok: true, value: { state: 'locked' } }),
  unlockedClient: () => Promise.resolve({ ok: false }),
  withUnlocked: () => Promise.resolve({ ok: false }),
}));
vi.mock('./code-window.ts', () => ({
  showUnlockCode: (device: string, nonce: string) => {
    shown.push({ device, nonce });
    events.push('show');
    return Promise.resolve({
      close: () => {
        closed.push(nonce);
        events.push('close');
        return Promise.resolve();
      },
    });
  },
  showPairingCode: () => Promise.resolve({ close: () => Promise.resolve() }),
}));

const { unlockWithDesktop } = await import('./account.ts');

const decodeLength = (text: string): number => {
  const padded = text.replaceAll('-', '+').replaceAll('_', '/');
  return Buffer.from(padded, 'base64').length;
};

beforeEach(() => {
  sent.length = 0;
  shown.length = 0;
  closed.length = 0;
  events.length = 0;
});

describe('desktop unlock', () => {
  it('sends a fresh 16 byte nonce and shows the same nonce code before the desktop asks', async () => {
    await unlockWithDesktop();
    const message = sent[0];
    if (message?.type !== 'unlock') throw new Error('unlock expected');
    expect(decodeLength(message.nonce)).toBe(16);
    expect(message.nonce).not.toMatch(/[=+/]/);
    expect(shown).toEqual([{ device: 'ab'.repeat(16), nonce: message.nonce }]);
    expect(events.indexOf('show')).toBeLessThan(events.indexOf('send'));
  });

  it('closes the code window when the reply arrives', async () => {
    await unlockWithDesktop();
    expect(closed).toHaveLength(1);
  });

  it('uses a different nonce for every request', async () => {
    await unlockWithDesktop();
    await unlockWithDesktop();
    const nonces = sent.flatMap((m) => (m.type === 'unlock' ? [m.nonce] : []));
    expect(new Set(nonces).size).toBe(2);
  });
});
