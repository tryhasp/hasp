import { err, ok } from '@hasp/autofill';
import type { Result } from '@hasp/autofill';
import { z } from 'zod';

import { api, familyOf, targetBrowser } from './browser.ts';
import { spawn } from './spawn.ts';

const HOST_NAME = 'kr.jmo.hasp.nmh';
const SAFARI_APP = 'kr.jmo.hasp';
const MAX_ID = 2 ** 53 - 1;

export const desktopMessageSchema = z.discriminatedUnion('type', [
  z.strictObject({ type: z.literal('enrol_reply'), id: z.number().int(), data: z.string() }),
  z.strictObject({
    type: z.literal('unlock_reply'),
    id: z.number().int(),
    k_ext: z.string(),
    valid_until: z.number().int(),
  }),
  z.strictObject({ type: z.literal('lock') }),
  z.strictObject({ type: z.literal('page_query'), id: z.number().int() }),
  z.strictObject({
    type: z.literal('fill_request'),
    id: z.number().int(),
    vault: z.string().regex(/^[0-9a-f]{32}$/),
    item: z.string().regex(/^[0-9a-f]{32}$/),
  }),
  z.strictObject({
    type: z.literal('error'),
    id: z.number().int().nullable(),
    code: z.enum(['malformed', 'refused', 'declined', 'revoked', 'locked', 'unavailable']),
  }),
]);
export type DesktopMessage = z.infer<typeof desktopMessageSchema>;

export type FillOutcome =
  | 'filled'
  | 'needs_confirmation'
  | 'no_matching_page'
  | 'locked'
  | 'unavailable';

export type ExtensionMessage =
  | { type: 'enrol_request'; id: number; data: string }
  | { type: 'unlock'; id: number; device_id: string; nonce: string }
  | { type: 'page_reply'; id: number; host: string | null; focused: boolean }
  | { type: 'fill_reply'; id: number; outcome: FillOutcome };

export type NativeError =
  | { kind: 'unavailable' }
  | { kind: 'timeout' }
  | { kind: 'declined' }
  | { kind: 'revoked' }
  | { kind: 'locked' }
  | { kind: 'refused' };

export type DesktopLink = {
  send: (message: ExtensionMessage) => Promise<Result<null, NativeError>>;
  receive: (signal: AbortSignal) => Promise<Result<DesktopMessage, NativeError>>;
  close: () => void;
};

const nextId = (): number => crypto.getRandomValues(new Uint32Array(1))[0] ?? 1;

export const newRequestId = (): number => Math.min(nextId(), MAX_ID);

export const errorOfCode = (
  code: 'malformed' | 'refused' | 'declined' | 'revoked' | 'locked' | 'unavailable',
): NativeError => {
  switch (code) {
    case 'declined':
      return { kind: 'declined' };
    case 'revoked':
      return { kind: 'revoked' };
    case 'locked':
      return { kind: 'locked' };
    case 'refused':
    case 'malformed':
      return { kind: 'refused' };
    case 'unavailable':
      return { kind: 'unavailable' };
  }
};

const portLink = (): DesktopLink => {
  const port = api.runtime.connectNative(HOST_NAME);
  const queue: DesktopMessage[] = [];
  const waiting: { resolve: (r: Result<DesktopMessage, NativeError>) => void }[] = [];
  const state: { isClosed: boolean } = { isClosed: false };
  port.onMessage.addListener((raw: unknown) => {
    const parsed = desktopMessageSchema.safeParse(raw);
    if (!parsed.success) return;
    const waiter = waiting.shift();
    if (waiter === undefined) queue.push(parsed.data);
    else waiter.resolve(ok(parsed.data));
  });
  port.onDisconnect.addListener(() => {
    state.isClosed = true;
    for (const waiter of waiting.splice(0)) waiter.resolve(err({ kind: 'unavailable' }));
  });
  return {
    send: async (message) => {
      if (state.isClosed) return err({ kind: 'unavailable' });
      try {
        port.postMessage(message);
        return await Promise.resolve(ok(null));
      } catch {
        return err({ kind: 'unavailable' });
      }
    },
    receive: async (signal) => {
      const queued = queue.shift();
      if (queued !== undefined) return ok(queued);
      if (state.isClosed) return err({ kind: 'unavailable' });
      const reply = await new Promise<Result<DesktopMessage, NativeError>>((resolve) => {
        const entry = { resolve };
        waiting.push(entry);
        signal.addEventListener('abort', () => {
          const index = waiting.indexOf(entry);
          if (index >= 0) waiting.splice(index, 1);
          resolve(err({ kind: 'timeout' }));
        });
      });
      return reply;
    },
    close: () => {
      state.isClosed = true;
      port.disconnect();
    },
  };
};

const safariLink = (): DesktopLink => {
  const queue: Promise<Result<DesktopMessage, NativeError>>[] = [];
  return {
    send: async (message) => {
      queue.push(
        (async (): Promise<Result<DesktopMessage, NativeError>> => {
          try {
            const reply: unknown = await api.runtime.sendNativeMessage(SAFARI_APP, message);
            const parsed = desktopMessageSchema.safeParse(reply);
            return parsed.success ? ok(parsed.data) : err({ kind: 'refused' });
          } catch {
            return err({ kind: 'unavailable' });
          }
        })(),
      );
      const sent: Result<null, NativeError> = await Promise.resolve(ok(null));
      return sent;
    },
    receive: async (signal) => {
      const next = queue.shift();
      if (next === undefined) return err({ kind: 'unavailable' });
      const aborted = new Promise<Result<DesktopMessage, NativeError>>((resolve) => {
        signal.addEventListener('abort', () => {
          resolve(err({ kind: 'timeout' }));
        });
      });
      const winner = await Promise.race([next, aborted]);
      return winner;
    },
    close: () => undefined,
  };
};

export const openDesktopLink = (): DesktopLink =>
  familyOf(targetBrowser()) === 'safari' ? safariLink() : portLink();

export const isDesktopReachable = async (): Promise<boolean> => {
  if (familyOf(targetBrowser()) === 'safari') return true;
  const link = portLink();
  const probe = await link.receive(AbortSignal.timeout(250));
  link.close();
  return !(!probe.ok && probe.error.kind === 'unavailable');
};

export type PageAnswer = { host: string | null; focused: boolean };

export type DesktopHandlers = {
  onLock: () => void;
  onPageQuery: () => Promise<PageAnswer>;
  onFillRequest: (vault: string, item: string) => Promise<FillOutcome>;
};

export const serveDesktopMessages = async (
  link: DesktopLink,
  handlers: DesktopHandlers,
  signal: AbortSignal,
): Promise<void> => {
  const answer = async (message: DesktopMessage): Promise<void> => {
    if (message.type === 'lock') {
      handlers.onLock();
      return;
    }
    if (message.type === 'page_query') {
      const page = await handlers.onPageQuery();
      await link.send({
        type: 'page_reply',
        id: message.id,
        host: page.host,
        focused: page.focused,
      });
      return;
    }
    if (message.type === 'fill_request') {
      const outcome = await handlers.onFillRequest(message.vault, message.item);
      await link.send({ type: 'fill_reply', id: message.id, outcome });
    }
  };
  const loop = async (): Promise<void> => {
    while (!signal.aborted) {
      const next = await link.receive(signal);
      if (!next.ok) return;
      spawn(answer(next.value));
    }
  };
  await loop();
};

export const watchDesktop = (
  handlers: DesktopHandlers,
  onClosed: () => void,
  signal: AbortSignal,
): void => {
  if (familyOf(targetBrowser()) === 'safari') return;
  const link = portLink();
  const run = async (): Promise<void> => {
    try {
      await serveDesktopMessages(link, handlers, signal);
    } finally {
      link.close();
      onClosed();
    }
  };
  spawn(run());
  signal.addEventListener('abort', () => {
    link.close();
  });
};
