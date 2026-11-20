import { BRIDGE_READY, HOOK_HELLO } from '../passkey/protocol.ts';

export type HookPort = {
  post: (message: object) => void;
  listen: (handler: (data: unknown) => void) => void;
};

export const connectHook = (win: Window, onConnected: (port: HookPort) => void): void => {
  let isConnected = false;
  const hello = (): void => {
    if (isConnected) return;
    const channel = new MessageChannel();
    const port = channel.port1;
    const origin = win.location.origin === 'null' ? '*' : win.location.origin;
    win.postMessage({ kind: HOOK_HELLO }, origin, [channel.port2]);
    isConnected = true;
    onConnected({
      post: (m) => {
        port.postMessage(m);
      },
      listen: (handler) => {
        port.addEventListener('message', (e: MessageEvent<unknown>) => {
          handler(e.data);
        });
        port.start();
      },
    });
  };
  hello();
  win.addEventListener('message', (e: MessageEvent<unknown>) => {
    const d = e.data;
    if (e.source !== win || typeof d !== 'object' || d === null) return;
    if (Reflect.get(d, 'kind') === BRIDGE_READY && !isConnected) hello();
  });
};

export type BridgePort = {
  post: (message: object) => void;
  listen: (handler: (data: unknown) => void) => void;
};

export const listenForHook = (
  win: Window,
  onConnected: (port: BridgePort) => void,
  signal: AbortSignal,
): void => {
  let isAccepted = false;
  win.addEventListener(
    'message',
    (e: MessageEvent<unknown>) => {
      const d = e.data;
      const port = e.ports[0];
      if (isAccepted || e.source !== win || port === undefined) return;
      if (typeof d !== 'object' || d === null || Reflect.get(d, 'kind') !== HOOK_HELLO) return;
      isAccepted = true;
      e.stopImmediatePropagation();
      onConnected({
        post: (m) => {
          port.postMessage(m);
        },
        listen: (handler) => {
          port.addEventListener('message', (ev: MessageEvent<unknown>) => {
            handler(ev.data);
          });
          port.start();
        },
      });
    },
    { capture: true, signal },
  );
  win.postMessage(
    { kind: BRIDGE_READY },
    win.location.origin === 'null' ? '*' : win.location.origin,
  );
};
