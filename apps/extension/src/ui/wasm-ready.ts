import { useSyncExternalStore } from 'react';

import { ensureWasm } from '../wasm/runtime.ts';

const state = { isReady: false };
const listeners = new Set<() => void>();

export const startWasm = async (): Promise<void> => {
  try {
    await ensureWasm();
  } catch {
    return;
  }
  state.isReady = true;
  for (const listener of listeners) listener();
};

const subscribe = (listener: () => void): (() => void) => {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
};

export const useWasmReady = (): boolean => useSyncExternalStore(subscribe, () => state.isReady);
