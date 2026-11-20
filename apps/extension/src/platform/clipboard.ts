// oxlint-disable typescript/strict-void-return -- Chrome keeps the reply channel open when a listener returns true
import { z } from 'zod';

import { api, familyOf, targetBrowser } from './browser.ts';
import { sha256Hex, shouldClear } from './clipboard-policy.ts';
import { spawn } from './spawn.ts';
import { defineKey, readKey, removeKey, writeKey } from './storage.ts';

const OFFSCREEN_PATH = '/offscreen.html';
export const CLIPBOARD_ALARM = 'hasp-clipboard-clear';
const MIN_ALARM_MINUTES = 0.5;

const pendingClearKey = defineKey(
  'session',
  'hasp:clipboard-clear',
  z.strictObject({ digest: z.string(), dueMs: z.number() }),
);

const offscreenMessageSchema = z.discriminatedUnion('op', [
  z.strictObject({
    target: z.literal('hasp-offscreen'),
    op: z.literal('copy'),
    text: z.string(),
    clearAfterMs: z.number().int().nonnegative(),
    digest: z.string(),
  }),
  z.strictObject({
    target: z.literal('hasp-offscreen'),
    op: z.literal('clear'),
    digest: z.string(),
  }),
]);

const readClipboard = async (): Promise<string | undefined> => {
  try {
    return await navigator.clipboard.readText();
  } catch {
    return undefined;
  }
};

const clearHere = async (digest: string): Promise<void> => {
  if (!(await shouldClear(await readClipboard(), digest))) return;
  copyViaTextarea(' ');
  await navigator.clipboard.writeText('').catch(() => undefined);
};

const copyViaTextarea = (text: string): void => {
  const area = document.createElement('textarea');
  area.value = text;
  area.setAttribute('readonly', '');
  document.body.append(area);
  area.select();
  // oxlint-disable-next-line typescript/no-deprecated -- the offscreen document has no focus, so the async clipboard API is unavailable
  document.execCommand('copy');
  area.remove();
};

const copyHere = async (text: string, clearAfterMs: number, digest: string): Promise<void> => {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    copyViaTextarea(text);
  }
  if (clearAfterMs > 0) {
    setTimeout(() => {
      spawn(clearHere(digest));
    }, clearAfterMs);
  }
};

const ensureOffscreen = async (): Promise<void> => {
  const contexts = await api.runtime.getContexts({
    contextTypes: ['OFFSCREEN_DOCUMENT'],
  });
  if (contexts.length > 0) return;
  await api.offscreen.createDocument({
    url: OFFSCREEN_PATH,
    reasons: ['CLIPBOARD'],
    justification: 'Copy a secret and clear it later',
  });
};

const isChromium = (): boolean => familyOf(targetBrowser()) === 'chromium';

export const copyText = async (text: string, clearAfterSeconds: number): Promise<void> => {
  const clearAfterMs = clearAfterSeconds * 1000;
  const digest = await sha256Hex(text);
  if (clearAfterMs > 0) {
    await writeKey(pendingClearKey, { digest, dueMs: Date.now() + clearAfterMs });
    await api.alarms.create(CLIPBOARD_ALARM, {
      delayInMinutes: Math.max(MIN_ALARM_MINUTES, clearAfterSeconds / 60),
    });
  }
  if (isChromium()) {
    await ensureOffscreen();
    await api.runtime.sendMessage({
      target: 'hasp-offscreen',
      op: 'copy',
      text,
      clearAfterMs,
      digest,
    });
    return;
  }
  await copyHere(text, clearAfterMs, digest);
};

export const clearClipboardWhenDue = async (isForced = false): Promise<void> => {
  const stored = await readKey(pendingClearKey);
  if (!stored.ok || stored.value === undefined) return;
  if (!isForced && stored.value.dueMs > Date.now()) return;
  await removeKey(pendingClearKey);
  if (isChromium()) {
    await ensureOffscreen();
    await api.runtime.sendMessage({
      target: 'hasp-offscreen',
      op: 'clear',
      digest: stored.value.digest,
    });
    return;
  }
  await clearHere(stored.value.digest);
};

export const serveOffscreenClipboard = (): void => {
  api.runtime.onMessage.addListener((raw: unknown, sender) => {
    if (sender.id !== api.runtime.id) return false;
    const parsed = offscreenMessageSchema.safeParse(raw);
    if (!parsed.success) return false;
    const message = parsed.data;
    spawn(
      message.op === 'copy'
        ? copyHere(message.text, message.clearAfterMs, message.digest)
        : clearHere(message.digest),
    );
    return false;
  });
};
