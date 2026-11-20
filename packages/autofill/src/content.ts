import { startEngine } from './engine.ts';
import type { ContentBackground, Engine, EngineNotice, HandoffStore } from './engine.ts';
import { startPasskeyBridge } from './passkey/bridge.ts';
import { platformShadowRootGetter } from './platform/shadow-root.ts';
import { captureNatives } from './snapshot/natives.ts';
import type { Report } from './spawn.ts';

export type ContentScriptOptions = {
  background: ContentBackground;
  handoff: HandoffStore;
  frameUrl: string;
  report: Report;
  notify: (notice: EngineNotice) => void;
  signal: AbortSignal;
};

export const startAutofillContentScript = async (
  options: ContentScriptOptions,
): Promise<Engine> => {
  const natives = captureNatives(window);
  const engine = await startEngine({
    win: window,
    natives,
    getShadowRoot: platformShadowRootGetter(),
    background: options.background,
    frameUrl: options.frameUrl,
    nowMs: natives.now,
    handoff: options.handoff,
    report: options.report,
    notify: options.notify,
    signal: options.signal,
  });
  return engine;
};

export const startPasskeyBridgeForWindow = (options: ContentScriptOptions): void => {
  startPasskeyBridge({
    win: window,
    background: options.background,
    report: options.report,
    signal: options.signal,
  });
};
