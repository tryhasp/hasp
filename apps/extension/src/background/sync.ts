import { settleAsync } from '@hasp/wasm';
import type { HaspClient } from '@hasp/wasm';

import { spawn } from '../platform/spawn.ts';
import { decodeText } from '../shared/bytes.ts';
import { wsUrlOf } from '../shared/server.ts';
import { afterLock } from './account.ts';
import { getClient, persistIfChanged, withUnlocked } from './client.ts';

const PING_EVERY_MS = 25_000;

export const runSync = async (): Promise<number> => {
  const result = await withUnlocked(async (client) => {
    const value = await client.sync();
    return value;
  });
  return result.ok ? result.value.changed : 0;
};

const authenticate = async (client: HaspClient, socket: WebSocket): Promise<void> => {
  try {
    const frame = await client.hintAuthFrame();
    socket.send(decodeText(frame));
    frame.fill(0);
  } catch {
    socket.close();
  }
};

export type Hints = { ensure: () => Promise<void>; stop: () => void };

export const createHints = (): Hints => {
  const state: { socket: WebSocket | undefined; ping: ReturnType<typeof setInterval> | undefined } =
    {
      socket: undefined,
      ping: undefined,
    };
  const stop = (): void => {
    if (state.ping !== undefined) clearInterval(state.ping);
    state.ping = undefined;
    state.socket?.close();
    state.socket = undefined;
  };
  const ensure = async (): Promise<void> => {
    if (state.socket !== undefined) return;
    const client = await getClient();
    if (client === undefined) return;
    const status = await settleAsync(client.status());
    if (!status.ok || status.value.state !== 'unlocked' || status.value.origin === undefined)
      return;
    const socket = new WebSocket(wsUrlOf(status.value.origin));
    state.socket = socket;
    socket.addEventListener('open', () => {
      spawn(authenticate(client, socket));
      state.ping = setInterval(() => {
        socket.send('{"t":"ping"}');
      }, PING_EVERY_MS);
    });
    socket.addEventListener('message', (event: MessageEvent<unknown>) => {
      const data = event.data;
      if (typeof data !== 'string') return;
      const handle = async (): Promise<void> => {
        await client.handleHintFrame(data);
        await persistIfChanged(client);
      };
      spawn(handle());
    });
    socket.addEventListener('close', () => {
      if (state.socket === socket) {
        if (state.ping !== undefined) clearInterval(state.ping);
        state.ping = undefined;
        state.socket = undefined;
      }
    });
  };
  return { ensure, stop };
};

export const watchEvents = async (signal: AbortSignal): Promise<void> => {
  const client = await getClient();
  if (client === undefined) return;
  while (!signal.aborted) {
    const next = await settleAsync(client.nextEvent());
    if (!next.ok) return;
    const kind = next.value.kind;
    if (kind === 'locked' || kind === 'session-revoked' || kind === 'device-revoked') {
      await afterLock();
    }
    await persistIfChanged(client);
  }
};
