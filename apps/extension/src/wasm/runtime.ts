import { loadWasm } from '@hasp/wasm';
import wasmPath from '@hasp/wasm/wasm?url';

const WASM_INIT_TIMEOUT_MS = 20_000;

const cell: { loading: Promise<void> | undefined } = { loading: undefined };

export const ensureWasm = async (): Promise<void> => {
  cell.loading ??= loadWasm(
    { kind: 'url', url: new URL(wasmPath, import.meta.url) },
    AbortSignal.timeout(WASM_INIT_TIMEOUT_MS),
  );
  try {
    await cell.loading;
  } catch (cause) {
    cell.loading = undefined;
    throw cause;
  }
};
