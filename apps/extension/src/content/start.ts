import {
  backgroundPushSchema,
  createContentBackground,
  startAutofillContentScript,
  startPasskeyBridgeForWindow,
} from '@hasp/autofill';
import type { ContentRequest, ContentScriptOptions, Engine, HandoffStore } from '@hasp/autofill';

import { api } from '../platform/browser.ts';
import { report } from '../platform/log.ts';
import { request, subscribePush } from '../platform/messaging.ts';

export type ContentContext = { signal: AbortSignal };

const PASSKEY_TIMEOUT_MS = 125_000;

const send = async (message: ContentRequest): Promise<unknown> => {
  const reply = await request(
    message,
    message.kind === 'passkey-request' ? PASSKEY_TIMEOUT_MS : undefined,
  );
  return reply;
};

const TAB_KEY = 'hasp:tab';

// Why: the handoff must belong to this tab only; the page can read this random key but it names a slot inside extension storage the page cannot reach, so knowing it grants neither read nor write.
const tabToken = (): string => {
  try {
    const known = window.sessionStorage.getItem(TAB_KEY);
    if (known !== null && /^[0-9a-f-]{36}$/.test(known)) return known;
    const fresh = crypto.randomUUID();
    window.sessionStorage.setItem(TAB_KEY, fresh);
    return fresh;
  } catch {
    return 'none';
  }
};

const handoffKey = (): string =>
  `handoff:${tabToken()}:${window.top === window ? 'top' : 'sub'}:${window.location.origin}`;

const handoff: HandoffStore = {
  put: async (record) => {
    await api.storage.session.set({ [handoffKey()]: record });
  },
  take: async () => {
    const stored = await api.storage.session.get(handoffKey());
    const record: unknown = stored[handoffKey()];
    return record;
  },
  clear: async () => {
    await api.storage.session.remove(handoffKey());
  },
};

const options = (signal: AbortSignal): ContentScriptOptions => ({
  background: createContentBackground(send),
  handoff,
  frameUrl: api.runtime.getURL('/menu-frame.html'),
  report,
  notify: () => undefined,
  signal,
});

const whenReady = async (signal: AbortSignal): Promise<void> => {
  if (document.readyState !== 'loading') return;
  await new Promise<void>((resolve) => {
    document.addEventListener(
      'DOMContentLoaded',
      () => {
        resolve();
      },
      { once: true, signal },
    );
  });
};

export const startContent = async (context: ContentContext): Promise<void> => {
  const setup = options(context.signal);
  startPasskeyBridgeForWindow(setup);
  await whenReady(context.signal);
  if (context.signal.aborted) return;
  const engine: Engine = await startAutofillContentScript(setup);
  subscribePush((raw) => {
    const parsed = backgroundPushSchema.safeParse(raw);
    if (parsed.success) engine.push(parsed.data);
  }, context.signal);
};
