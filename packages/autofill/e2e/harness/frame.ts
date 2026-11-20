import { createFrameBackground } from '../../src/background-client.ts';
import { mountMenuFrame } from '../../src/menu/menu-frame.ts';

declare global {
  // oxlint-disable-next-line typescript/consistent-type-definitions -- global augmentation must be an interface
  interface Window {
    haspBg: (raw: string) => Promise<string>;
  }
}

const controller = new AbortController();
const background = createFrameBackground(async (message) => {
  const raw = await window.haspBg(JSON.stringify(message));
  const parsed: unknown = JSON.parse(raw);
  return parsed;
});

mountMenuFrame({
  win: window,
  background,
  nowMs: () => performance.timeOrigin + performance.now(),
  report: () => undefined,
  signal: controller.signal,
}).catch(() => undefined);
