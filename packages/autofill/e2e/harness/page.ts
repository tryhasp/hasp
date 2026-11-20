import { createContentBackground } from '../../src/background-client.ts';
import { startEngine } from '../../src/engine.ts';
import type { Engine, EngineNotice } from '../../src/engine.ts';
import { startPasskeyBridge } from '../../src/passkey/bridge.ts';
import { captureNatives } from '../../src/snapshot/natives.ts';
import { defaultShadowRootGetter } from '../../src/snapshot/shadow.ts';
import { FRAME_URL } from '../ports.ts';

const isFrameOrigin = location.origin === new URL(FRAME_URL).origin;

declare global {
  // oxlint-disable-next-line typescript/consistent-type-definitions -- global augmentation must be an interface
  interface Window {
    haspBg: (raw: string) => Promise<string>;
    haspHandoff: (command: string, payload?: string) => Promise<string | null>;
    haspNotices: EngineNotice[];
    haspEngine: Engine | undefined;
  }
}

const natives = captureNatives(window);
const controller = new AbortController();
const background = createContentBackground(async (message) => {
  const raw = await window.haspBg(JSON.stringify(message));
  const parsed: unknown = JSON.parse(raw);
  return parsed;
});
const handoff = {
  put: async (record: unknown): Promise<void> => {
    await window.haspHandoff('put', JSON.stringify(record));
  },
  take: async (): Promise<unknown> => {
    const raw = await window.haspHandoff('take');
    return raw === null ? undefined : JSON.parse(raw);
  },
  clear: async (): Promise<void> => {
    await window.haspHandoff('clear');
  },
};
window.haspNotices = [];
window.haspEngine = undefined;

const start = async (): Promise<void> => {
  window.haspEngine = await startEngine({
    win: window,
    natives,
    getShadowRoot: defaultShadowRootGetter,
    background,
    handoff,
    frameUrl: FRAME_URL,
    nowMs: natives.now,
    report: () => undefined,
    notify: (notice) => {
      window.haspNotices.push(notice);
    },
    signal: controller.signal,
  });
};

if (!isFrameOrigin) {
  startPasskeyBridge({
    win: window,
    background,
    report: () => undefined,
    signal: controller.signal,
  });
}

if (isFrameOrigin) {
  // Why: the real extension never injects the content script into its own menu frame
} else if (document.readyState === 'loading') {
  document.addEventListener(
    'DOMContentLoaded',
    () => {
      start().catch(() => undefined);
    },
    { once: true },
  );
} else {
  start().catch(() => undefined);
}
