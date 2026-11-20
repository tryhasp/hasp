// oxlint-disable typescript/promise-function-async -- mocks return resolved promises
import { mintGestureToken } from '@hasp/autofill';
import type { ContentRequest } from '@hasp/autofill';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { Sender } from '../platform/messaging.ts';

const store = new Map<string, unknown>();
const calls: { plan: unknown[]; payload: unknown[] } = { plan: [], payload: [] };
const facts: { value: { isActive: boolean; isWindowFocused: boolean } } = {
  value: { isActive: true, isWindowFocused: true },
};
const stepUp: { value: string } = { value: 'allow' };
const desktopNonces = new Set<string>();

vi.mock('../platform/storage.ts', () => ({
  defineKey: (area: string, name: string) => ({ area, name }),
  readKey: (key: { name: string }) => Promise.resolve({ ok: true, value: store.get(key.name) }),
  writeKey: (key: { name: string }, value: unknown) => {
    store.set(key.name, value);
    return Promise.resolve({ ok: true, value: null });
  },
  removeKey: (key: { name: string }) => {
    store.delete(key.name);
    return Promise.resolve();
  },
  listSessionKeys: () => Promise.resolve([...store.keys()]),
  sessionStore: {
    get: (name: string) => Promise.resolve(store.get(name)),
    set: (name: string, value: unknown) => {
      store.set(name, value);
      return Promise.resolve({ ok: true, value: null });
    },
    remove: (name: string) => {
      store.delete(name);
      return Promise.resolve();
    },
  },
}));
vi.mock('../platform/tabs.ts', () => ({ tabFacts: () => Promise.resolve(facts.value) }));
vi.mock('../platform/messaging.ts', () => ({
  okReply: (value: unknown) => ({ ok: true, value }),
  errReply: (error: unknown) => ({ ok: false, error }),
  denied: (reason: string) => ({ ok: false, error: { kind: 'denied', reason } }),
}));
vi.mock('../shared/host.ts', () => ({
  splitHost: (host: string) => ({ subdomain: '', registrable: host }),
}));
vi.mock('./account.ts', () => ({ touchActivity: () => Promise.resolve() }));
vi.mock('./confirm.ts', () => ({ requestConfirm: () => Promise.resolve() }));
vi.mock('./sync.ts', () => ({ runSync: () => Promise.resolve(0) }));
vi.mock('./passkey.ts', () => ({ passkeyRequest: () => Promise.resolve({ ok: true, value: {} }) }));
vi.mock('./desktop.ts', () => ({
  isDesktopFill: (nonce: string) => desktopNonces.has(nonce),
  settleDesktopFill: () => undefined,
}));
vi.mock('./client.ts', () => {
  const client = {
    fillPlan: (request: unknown) => {
      calls.plan.push(request);
      return Promise.resolve({ stepUp: stepUp.value });
    },
    fillPayload: (request: unknown) => {
      calls.payload.push(request);
      return Promise.resolve({
        values: [{ purpose: 'password', value: new TextEncoder().encode('secret') }],
        autosubmitAllowed: false,
      });
    },
    settings: () => Promise.resolve({ language: 'en', secretTag: undefined }),
    vaults: () => Promise.resolve([]),
    autofillQuery: () =>
      Promise.resolve({ candidates: [{ item: 'i'.repeat(32) }], refusal: undefined }),
  };
  return {
    unlockedClient: () => Promise.resolve({ ok: true, value: client }),
    withUnlocked: async (work: (c: typeof client) => Promise<unknown>) => ({
      ok: true,
      value: await work(client),
    }),
  };
});

const { contentHandlers, frameHandlers } = await import('./autofill.ts');
const { menuKey, flowKey } = await import('./keys.ts');

const vault = 'v'.repeat(32);
const item = 'i'.repeat(32);
const nonce = 'n'.repeat(32);
const token = 't'.repeat(32);

const sender = (origin: string): Sender => ({
  kind: 'tab-frame',
  tabId: 3,
  frameId: 0,
  origin,
  url: `${origin}/login`,
});

const attestation = () => ({
  checkedAtMs: Date.now(),
  passed: ['C1', 'C2', 'C3', 'C5'] as ('C1' | 'C2' | 'C3' | 'C5')[],
  isC4Supported: false,
});

const fillRequest = (): Extract<ContentRequest, { kind: 'fill-request' }> => ({
  kind: 'fill-request',
  nonce,
  token,
  itemId: item,
  formId: '1',
  formKind: 'login',
  purposes: ['password'],
  attestation: attestation(),
});

const session = (origin: string) => ({
  nonce,
  tabId: 3,
  frameId: 0,
  origin,
  url: `${origin}/login`,
  host: new URL(origin).hostname,
  mode: 'menu',
  formKind: 'login',
  frame: 'top',
  createdMs: Date.now(),
  candidates: [{ vault, item, title: 'T', username: 'u', tier: 'exact', hasTotp: false }],
  canGenerate: false,
});

const arm = async (origin: string): Promise<void> => {
  store.set(menuKey(nonce).name, session(origin));
  await mintGestureToken(
    {
      get: (k) => Promise.resolve(store.get(k)),
      set: (k, v) => {
        store.set(k, v);
        return Promise.resolve({ ok: true as const, value: null });
      },
      remove: (k) => {
        store.delete(k);
        return Promise.resolve();
      },
    },
    { tabId: 3, frameId: 0, nonce, itemId: item },
    Date.now(),
    token,
  );
};

const kindOf = (reply: { ok: boolean; value?: unknown; error?: unknown }): unknown =>
  reply.ok
    ? Reflect.get(reply.value as object, 'kind')
    : Reflect.get(reply.error as object, 'reason');

beforeEach(() => {
  store.clear();
  calls.plan.length = 0;
  calls.payload.length = 0;
  facts.value = { isActive: true, isWindowFocused: true };
  stepUp.value = 'allow';
  desktopNonces.clear();
});

describe('fill-request binds the approval to the decision origin', () => {
  it('fills on the origin the decision was taken for', async () => {
    await arm('https://a.example.com');
    const reply = await contentHandlers['fill-request'](
      fillRequest(),
      sender('https://a.example.com'),
    );
    expect(kindOf(reply)).toBe('payload');
  });

  it('refuses when the tab navigated to another origin before the fill push', async () => {
    await arm('https://a.example.com');
    const reply = await contentHandlers['fill-request'](
      fillRequest(),
      sender('https://b.example.com'),
    );
    expect(kindOf(reply)).toBe('no-session');
    expect(calls.payload).toHaveLength(0);
  });
});

describe('fill-continue compares the flow origin', () => {
  it('refuses a continuation on a different origin than the first step', async () => {
    store.set(flowKey(3).name, {
      vault,
      item,
      origin: 'https://a.example.com',
      frame: 'top',
      atMs: Date.now(),
      isAnswered: false,
    });
    const reply = await contentHandlers['fill-continue'](
      {
        kind: 'fill-continue',
        formId: '1',
        formKind: 'login',
        purposes: ['password'],
        attestation: attestation(),
      },
      sender('https://b.example.com'),
    );
    expect(kindOf(reply)).toBe('refused');
    expect(calls.payload).toHaveLength(0);
  });
});

describe('approved is only sent after a step-up was answered', () => {
  it('sends approved false and no remember when no step-up applies', async () => {
    await arm('https://a.example.com');
    await contentHandlers['fill-request'](fillRequest(), sender('https://a.example.com'));
    expect(calls.payload[0]).toMatchObject({ approved: false, rememberHost: false });
  });

  it('counts an inline menu pick as the answer and remembers the host', async () => {
    stepUp.value = 'inline-confirm-host';
    await arm('https://a.example.com');
    await contentHandlers['fill-request'](fillRequest(), sender('https://a.example.com'));
    expect(calls.payload[0]).toMatchObject({ approved: true, rememberHost: true });
  });

  it('never counts a desktop-requested fill as answered', async () => {
    stepUp.value = 'inline-confirm-host';
    desktopNonces.add(nonce);
    await arm('https://a.example.com');
    const reply = await contentHandlers['fill-request'](
      fillRequest(),
      sender('https://a.example.com'),
    );
    expect(kindOf(reply)).toBe('browser-ui');
    expect(calls.payload).toHaveLength(0);
  });

  it('does not waive the window focus check for a desktop-requested fill', async () => {
    desktopNonces.add(nonce);
    facts.value = { isActive: true, isWindowFocused: false };
    await arm('https://a.example.com');
    const reply = await contentHandlers['fill-request'](
      fillRequest(),
      sender('https://a.example.com'),
    );
    expect(kindOf(reply)).toBe('refused');
    expect(calls.payload).toHaveLength(0);
  });
});

const extensionFrame = (tabId: number): Sender => ({
  kind: 'extension-page',
  tabId,
  frameId: 4,
  origin: 'chrome-extension://abc',
  url: 'chrome-extension://abc/menu-frame.html',
});
describe('frame-hello is bound to the handover nonce', () => {
  const other = 'o'.repeat(32);

  it('answers with the session that owns the claimed nonce, not the newest one of the tab', async () => {
    await arm('https://a.example.com');
    store.set(menuKey(other).name, {
      ...session('https://b.example.com'),
      nonce: other,
      createdMs: Date.now() + 1000,
    });
    const reply = await frameHandlers['frame-hello'](
      { kind: 'frame-hello', nonce },
      extensionFrame(3),
    );
    expect(reply.ok && Reflect.get(reply.value as object, 'nonce')).toBe(nonce);
  });

  it('refuses a nonce the tab does not own or that does not exist', async () => {
    await arm('https://a.example.com');
    const wrongTab = await frameHandlers['frame-hello'](
      { kind: 'frame-hello', nonce },
      extensionFrame(9),
    );
    const unknown = await frameHandlers['frame-hello'](
      { kind: 'frame-hello', nonce: 'z'.repeat(32) },
      extensionFrame(3),
    );
    expect(wrongTab.ok).toBe(false);
    expect(unknown.ok).toBe(false);
  });
});
