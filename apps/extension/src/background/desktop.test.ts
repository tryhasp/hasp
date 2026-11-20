// oxlint-disable typescript/promise-function-async -- mocks return resolved promises
import { err, ok } from '@hasp/autofill';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { DesktopLink, DesktopMessage, ExtensionMessage } from '../platform/native.ts';
import { serveDesktopMessages } from '../platform/native.ts';

const store = new Map<string, unknown>();
const pushes: { tabId: number; frameId: number | undefined; message: unknown }[] = [];
const confirms: unknown[] = [];

const tab: { value: { id: number; url: string | undefined; windowId: number } | undefined } = {
  value: { id: 4, url: 'https://login.example.com/signin', windowId: 1 },
};
const decision: { value: string } = { value: 'fill' };
const locked: { value: boolean } = { value: false };

const candidate = {
  vault: 'a'.repeat(32),
  item: 'b'.repeat(32),
  title: 'Example',
  subtitle: 'alice',
  tier: 'exact',
  fill: 'oneClick',
  hasTotp: false,
  hostToConfirm: undefined,
};

const windowFocused: { value: boolean } = { value: true };

vi.mock('../platform/tabs.ts', () => ({
  activeTab: () => Promise.resolve(tab.value),
  isLastFocusedWindowFocused: () => Promise.resolve(windowFocused.value),
}));
vi.mock('../platform/messaging.ts', () => ({
  pushToFrame: (tabId: number, frameId: number | undefined, message: unknown) => {
    pushes.push({ tabId, frameId, message });
    return Promise.resolve(true);
  },
}));
vi.mock('../platform/storage.ts', () => ({
  defineKey: (area: string, name: string, schema: unknown) => ({ area, name, schema }),
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
  writeKey: (key: { name: string }, value: unknown) => {
    store.set(key.name, value);
    return Promise.resolve({ ok: true, value: null });
  },
}));
vi.mock('./confirm.ts', () => ({
  requestConfirm: (input: unknown) => {
    confirms.push(input);
    return Promise.resolve();
  },
}));
vi.mock('./client.ts', () => ({
  unlockedClient: () =>
    Promise.resolve(
      locked.value
        ? { ok: false, error: { kind: 'locked' } }
        : {
            ok: true,
            value: {
              browserFillDecision: () => Promise.resolve(decision.value),
              autofillQuery: () => Promise.resolve({ candidates: [candidate], refusal: undefined }),
            },
          },
    ),
}));

const { activePageHost, fillOnActiveTab, isDesktopFill, settleDesktopFill } =
  await import('./desktop.ts');

const vault = candidate.vault;
const item = candidate.item;

beforeEach(() => {
  store.clear();
  pushes.length = 0;
  confirms.length = 0;
  tab.value = { id: 4, url: 'https://login.example.com/signin', windowId: 1 };
  decision.value = 'fill';
  locked.value = false;
});

describe('activePageHost', () => {
  it('gives the host of the active tab and nothing else', async () => {
    expect(await activePageHost()).toEqual({ host: 'login.example.com', focused: true });
  });

  it('says the profile is not focused when its last focused window is not the OS focused one', async () => {
    windowFocused.value = false;
    expect(await activePageHost()).toEqual({ host: 'login.example.com', focused: false });
    windowFocused.value = true;
  });

  it.each([undefined, 'chrome://extensions', 'about:blank'])('gives null for %s', async (url) => {
    tab.value = { id: 4, url, windowId: 1 };
    expect((await activePageHost()).host).toBeNull();
  });
});

describe('fillOnActiveTab', () => {
  it('answers locked while locked', async () => {
    locked.value = true;
    expect(await fillOnActiveTab(vault, item)).toBe('locked');
  });

  it('answers no_matching_page without a web page or a matching item', async () => {
    tab.value = { id: 4, url: 'about:blank', windowId: 1 };
    expect(await fillOnActiveTab(vault, item)).toBe('no_matching_page');
    tab.value = { id: 4, url: 'https://login.example.com/', windowId: 1 };
    decision.value = 'no-matching-page';
    expect(await fillOnActiveTab(vault, item)).toBe('no_matching_page');
  });

  it('shows the confirm card and asks for confirmation when the step-up applies', async () => {
    decision.value = 'confirm-in-browser';
    expect(await fillOnActiveTab(vault, item)).toBe('needs_confirmation');
    expect(confirms).toHaveLength(1);
    expect(confirms[0]).toMatchObject({ tabId: 4, vault, item, currentHost: 'login.example.com' });
    expect(pushes).toHaveLength(0);
  });

  it('pushes a one-time fill to the top frame and reports filled once the gate accepted it', async () => {
    const outcome = fillOnActiveTab(vault, item);
    await vi.waitFor(() => {
      expect(pushes).toHaveLength(1);
    });
    const push = pushes[0];
    expect(push).toMatchObject({
      tabId: 4,
      frameId: 0,
      message: { kind: 'fill-form', itemId: item },
    });
    const nonce = String(Reflect.get(push?.message as object, 'nonce'));
    expect(isDesktopFill(nonce)).toBe(true);
    settleDesktopFill(nonce, 'payload');
    expect(await outcome).toBe('filled');
    expect(isDesktopFill(nonce)).toBe(false);
  });

  it('reports needs_confirmation when the fill gate itself demands browser UI', async () => {
    const outcome = fillOnActiveTab(vault, item);
    await vi.waitFor(() => {
      expect(pushes).toHaveLength(1);
    });
    settleDesktopFill(String(Reflect.get(pushes[0]?.message as object, 'nonce')), 'browser-ui');
    expect(await outcome).toBe('needs_confirmation');
  });

  it('reports unavailable when the page never answers', async () => {
    vi.useFakeTimers();
    const outcome = fillOnActiveTab(vault, item);
    await vi.advanceTimersByTimeAsync(7000);
    expect(await outcome).toBe('unavailable');
    vi.useRealTimers();
  });
});

describe('native port to fill outcome', () => {
  it('runs page_query and fill_request from a fake desktop through the same gate', async () => {
    const queue: DesktopMessage[] = [
      { type: 'page_query', id: 1 },
      { type: 'fill_request', id: 2, vault, item },
    ];
    const sent: ExtensionMessage[] = [];
    const link: DesktopLink = {
      send: (message) => {
        sent.push(message);
        return Promise.resolve(ok(null));
      },
      receive: () => {
        const next = queue.shift();
        return Promise.resolve(
          next === undefined ? err({ kind: 'unavailable' as const }) : ok(next),
        );
      },
      close: () => undefined,
    };
    decision.value = 'confirm-in-browser';
    await serveDesktopMessages(
      link,
      { onLock: () => undefined, onPageQuery: activePageHost, onFillRequest: fillOnActiveTab },
      new AbortController().signal,
    );
    await vi.waitFor(() => {
      expect(sent).toHaveLength(2);
    });
    expect(sent).toContainEqual({
      type: 'page_reply',
      id: 1,
      host: 'login.example.com',
      focused: true,
    });
    expect(sent).toContainEqual({ type: 'fill_reply', id: 2, outcome: 'needs_confirmation' });
    expect(JSON.stringify(sent)).not.toContain('https://');
  });
});
