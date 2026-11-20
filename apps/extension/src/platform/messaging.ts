// oxlint-disable typescript/strict-void-return -- Chrome keeps the reply channel open when a listener returns true
import type { z } from 'zod';

import { api } from './browser.ts';
import { report } from './log.ts';
import { spawn } from './spawn.ts';

export type ErrorBody =
  | { kind: 'locked' }
  | { kind: 'denied'; reason: string }
  | { kind: 'internal' }
  | { kind: 'timeout' };

export type Envelope<T> = { ok: true; value: T } | { ok: false; error: ErrorBody };

export type SenderKind = 'extension-page' | 'tab-frame' | 'unknown';

export type Sender = {
  kind: SenderKind;
  tabId: number | undefined;
  frameId: number | undefined;
  origin: string | undefined;
  url: string | undefined;
};

type Tagged = { kind: string };

export type Handlers<M extends Tagged> = {
  [K in M['kind']]: (
    message: Extract<M, { kind: K }>,
    sender: Sender,
  ) => Promise<Envelope<unknown>>;
};

const REPLY_TIMEOUT_MS = 30_000;

export const okReply = <T>(value: T): Envelope<T> => ({ ok: true, value });
export const errReply = (error: ErrorBody): Envelope<never> => ({ ok: false, error });
export const denied = (reason: string): Envelope<never> => errReply({ kind: 'denied', reason });

const senderOf = (raw: chrome.runtime.MessageSender): Sender => {
  const extensionRoot = new URL('/', api.runtime.getURL('/popup.html')).href;
  const url = raw.url;
  const isOwnPage = url !== undefined && url.startsWith(extensionRoot);
  const kind: SenderKind = isOwnPage
    ? 'extension-page'
    : raw.tab === undefined
      ? 'unknown'
      : 'tab-frame';
  return {
    kind,
    tabId: raw.tab?.id,
    frameId: raw.frameId,
    origin: raw.origin,
    url,
  };
};

export const listen = <M extends Tagged>(schema: z.ZodType<M>, handlers: Handlers<M>): void => {
  api.runtime.onMessage.addListener((raw: unknown, rawSender, sendResponse) => {
    if (rawSender.id !== api.runtime.id) return false;
    const parsed = schema.safeParse(raw);
    if (!parsed.success) return false;
    const message = parsed.data;
    const sender = senderOf(rawSender);
    const kind: M['kind'] = message.kind;
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the handler map and the schema union are keyed by the same kind
    const handler = handlers[kind] as (m: M, s: Sender) => Promise<Envelope<unknown>>;
    const respond = async (): Promise<void> => {
      try {
        sendResponse(await handler(message, sender));
      } catch (cause) {
        report(cause instanceof Error ? cause.name : 'handler');
        sendResponse(errReply({ kind: 'internal' }));
      }
    };
    spawn(respond());
    return true;
  });
};

export const request = async (
  message: object,
  timeoutMs: number = REPLY_TIMEOUT_MS,
): Promise<unknown> => {
  const reply: unknown = await Promise.race([
    api.runtime.sendMessage(message),
    new Promise<never>((_resolve, reject) => {
      AbortSignal.timeout(timeoutMs).addEventListener('abort', () => {
        reject(new Error('timeout'));
      });
    }),
  ]);
  return reply;
};

export const pushToFrame = async (
  tabId: number,
  frameId: number | undefined,
  message: object,
): Promise<boolean> => {
  try {
    await api.tabs.sendMessage(tabId, message, frameId === undefined ? {} : { frameId });
    return true;
  } catch {
    return false;
  }
};

export const subscribePush = (listener: (message: unknown) => void, signal: AbortSignal): void => {
  const handler = (raw: unknown, rawSender: chrome.runtime.MessageSender): boolean => {
    if (rawSender.id !== api.runtime.id || rawSender.tab !== undefined) return false;
    listener(raw);
    return false;
  };
  api.runtime.onMessage.addListener(handler);
  signal.addEventListener('abort', () => {
    api.runtime.onMessage.removeListener(handler);
  });
};
