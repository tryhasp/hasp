import { portToContentSchema, portToFrameSchema } from '../protocol.ts';
import type { PortToContent, PortToFrame } from '../protocol.ts';

const HANDOVER_KIND = 'hasp-port';
const HANDOVER_TIMEOUT_MS = 5000;

export type ContentEnd = {
  send: (m: PortToFrame) => void;
  listen: (handler: (m: PortToContent) => void, signal: AbortSignal) => void;
  close: () => void;
};

export type FrameEnd = {
  send: (m: PortToContent) => void;
  listen: (handler: (m: PortToFrame) => void, signal: AbortSignal) => void;
  close: () => void;
};

export const handoverPort = (
  iframe: HTMLIFrameElement,
  frameOrigin: string,
  nonce: string,
): ContentEnd | undefined => {
  const target = iframe.contentWindow;
  if (target === null) return undefined;
  const channel = new MessageChannel();
  target.postMessage({ kind: HANDOVER_KIND, nonce }, frameOrigin, [channel.port2]);
  const port = channel.port1;
  return {
    send: (m) => {
      port.postMessage(m);
    },
    listen: (handler, signal) => {
      port.addEventListener(
        'message',
        (e: MessageEvent<unknown>) => {
          const parsed = portToContentSchema.safeParse(e.data);
          if (parsed.success) handler(parsed.data);
        },
        { signal },
      );
      port.start();
    },
    close: () => {
      port.close();
    },
  };
};

export type HandoverInbox = {
  claim: (expected: string) => Promise<FrameEnd | undefined>;
  nonceAt: (index: number) => Promise<string | undefined>;
};

export const collectHandovers = (win: Window, signal: AbortSignal): HandoverInbox => {
  const seen: { nonce: string; port: MessagePort }[] = [];
  const waiter: { expected: string | undefined; resolve: (m: MessagePort | undefined) => void } = {
    expected: undefined,
    resolve: () => undefined,
  };
  const watchers: (() => void)[] = [];
  const tryMatch = (): void => {
    const hit = seen.find((s) => s.nonce === waiter.expected);
    if (hit !== undefined) waiter.resolve(hit.port);
  };
  win.addEventListener(
    'message',
    (e: MessageEvent<unknown>) => {
      const d: unknown = e.data;
      const port = e.ports[0];
      if (e.source !== win.parent || port === undefined || seen.length >= 8) return;
      if (typeof d !== 'object' || d === null) return;
      if (Reflect.get(d, 'kind') !== HANDOVER_KIND) return;
      const nonce: unknown = Reflect.get(d, 'nonce');
      if (typeof nonce !== 'string') return;
      seen.push({ nonce, port });
      tryMatch();
      for (const watcher of watchers.splice(0)) watcher();
    },
    { signal },
  );
  return {
    nonceAt: async (index) => {
      if (seen[index] === undefined) {
        const arrived = Promise.withResolvers<void>();
        watchers.push(arrived.resolve);
        const timer = win.setTimeout(arrived.resolve, HANDOVER_TIMEOUT_MS);
        await arrived.promise;
        win.clearTimeout(timer);
      }
      return seen[index]?.nonce;
    },
    claim: async (expected) => {
      const matched = Promise.withResolvers<MessagePort | undefined>();
      waiter.expected = expected;
      waiter.resolve = matched.resolve;
      const timer = win.setTimeout(() => {
        matched.resolve(undefined);
      }, HANDOVER_TIMEOUT_MS);
      tryMatch();
      const port = await matched.promise;
      win.clearTimeout(timer);
      return port === undefined ? undefined : frameEnd(port);
    },
  };
};

const frameEnd = (port: MessagePort): FrameEnd => ({
  send: (m) => {
    port.postMessage(m);
  },
  listen: (handler, s) => {
    port.addEventListener(
      'message',
      (e: MessageEvent<unknown>) => {
        const parsed = portToFrameSchema.safeParse(e.data);
        if (parsed.success) handler(parsed.data);
      },
      { signal: s },
    );
    port.start();
  },
  close: () => {
    port.close();
  },
});
