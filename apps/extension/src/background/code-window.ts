import { extensionPairingCode, extensionUnlockCode } from '@hasp/wasm';

import type { CodeView } from '../messages/ui.ts';
import { closeWindow, onWindowClosed, openCodeWindow, uiLocale } from '../platform/tabs.ts';
import { randomHex } from './random.ts';

type Shown = { view: CodeView; windowId: number | undefined };

const shown = new Map<string, Shown>();

export const codeView = (id: string): CodeView | undefined => shown.get(id)?.view;

export type CodeHandle = { close: () => Promise<void> };

const open = async (kind: CodeView['kind'], code: string): Promise<CodeHandle> => {
  const id = randomHex(16);
  const entry: Shown = { view: { kind, code, locale: uiLocale() }, windowId: undefined };
  shown.set(id, entry);
  const windowId = await openCodeWindow(id);
  entry.windowId = windowId;
  const stop =
    windowId === undefined
      ? undefined
      : onWindowClosed(windowId, () => {
          shown.delete(id);
        });
  return {
    close: async () => {
      stop?.();
      shown.delete(id);
      if (windowId !== undefined) await closeWindow(windowId);
    },
  };
};

const none: CodeHandle = {
  close: async () => {
    await Promise.resolve();
  },
};

export const showUnlockCode = async (device: string, nonce: string): Promise<CodeHandle> => {
  const code = extensionUnlockCode(device, nonce);
  return code.ok ? open('unlock', code.value) : none;
};

export const showPairingCode = async (enrolRequest: Uint8Array): Promise<CodeHandle> => {
  const code = extensionPairingCode(enrolRequest);
  return code.ok ? open('pair', code.value) : none;
};
