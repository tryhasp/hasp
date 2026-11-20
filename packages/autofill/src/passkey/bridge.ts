import type { ContentBackground } from '../engine.ts';
import { detectFrameKind } from '../frame-kind.ts';
import { listenForHook } from '../platform/passkey-channel.ts';
import type { Report } from '../spawn.ts';
import { spawn } from '../spawn.ts';
import { hookRequestSchema } from './protocol.ts';
import type { BridgeReply } from './protocol.ts';
import { isRpIdSuffixOfHost } from './rp-id.ts';

export type BridgeDeps = {
  win: Window;
  background: ContentBackground;
  report: Report;
  signal: AbortSignal;
};

const rpIdOf = (options: string): string | undefined => {
  try {
    const parsed: unknown = JSON.parse(options);
    if (typeof parsed !== 'object' || parsed === null) return undefined;
    const direct: unknown = Reflect.get(parsed, 'rpId');
    if (typeof direct === 'string') return direct;
    const rp: unknown = Reflect.get(parsed, 'rp');
    const id: unknown = typeof rp === 'object' && rp !== null ? Reflect.get(rp, 'id') : undefined;
    return typeof id === 'string' ? id : undefined;
  } catch {
    return undefined;
  }
};

export const startPasskeyBridge = (deps: BridgeDeps): void => {
  const { win, background } = deps;
  listenForHook(
    win,
    (port) => {
      const reply = (r: BridgeReply): void => {
        port.post(r);
      };
      port.listen((data) => {
        const parsed = hookRequestSchema.safeParse(data);
        if (!parsed.success) return;
        const req = parsed.data;
        const rpId = rpIdOf(req.options);
        const frame = detectFrameKind(win);
        const isOpaque = frame === 'opaque' || frame === 'sandboxed';
        if (isOpaque || (rpId !== undefined && !isRpIdSuffixOfHost(win.location.hostname, rpId))) {
          reply({ id: req.id, outcome: 'fallback' });
          return;
        }
        spawn(
          (async () => {
            const result = await background.request({
              kind: 'passkey-request',
              op: req.op,
              frame,
              options: req.options,
            });
            reply(
              result.ok
                ? { id: req.id, outcome: 'handled', payload: result.value.payload }
                : { id: req.id, outcome: 'fallback' },
            );
          })(),
          deps.report,
        );
      });
    },
    deps.signal,
  );
};
