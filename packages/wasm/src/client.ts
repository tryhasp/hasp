import init, {
  Client as HaspClient,
  extensionPairingCode as wasmExtensionPairingCode,
  extensionUnlockCode as wasmExtensionUnlockCode,
  initSync,
  normaliseLogin as wasmNormaliseLogin,
  normalisePassword as wasmNormalisePassword,
  parseKitQr,
  registrableDomain as wasmRegistrableDomain,
  replayVectors,
  vectorGroups,
} from '../generated/hasp_wasm.js';
import type { HaspError, ReplayOutcome } from '../generated/hasp_wasm.js';

export type * from '../generated/hasp_wasm.js';
export { HaspClient, parseKitQr };

export type WasmSource =
  | { readonly kind: 'url'; readonly url: URL }
  | { readonly kind: 'bytes'; readonly bytes: BufferSource };

export type Result<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: HaspError };

const errorKinds = {
  format: true,
  version: true,
  sig: true,
  aead: true,
  pin: true,
  rollback: true,
  fork: true,
  roster: true,
  'kdf-params': true,
  epoch: true,
  root: true,
  auth: true,
  'server-key': true,
  authz: true,
  invite: true,
  locked: true,
  cancelled: true,
  offline: true,
  'not-found': true,
  refused: true,
  pending: true,
  'read-only': true,
  'rate-limited': true,
  conflict: true,
  quarantined: true,
  unconfirmed: true,
  'device-revoked': true,
  internal: true,
} satisfies Record<HaspError['kind'], true>;

function isHaspError(value: unknown): value is HaspError {
  return (
    typeof value === 'object' &&
    value !== null &&
    'kind' in value &&
    typeof value.kind === 'string' &&
    Object.hasOwn(errorKinds, value.kind)
  );
}

function settle<T>(run: () => T): Result<T> {
  try {
    return { ok: true, value: run() };
  } catch (thrown) {
    if (isHaspError(thrown)) {
      return { ok: false, error: thrown };
    }
    throw thrown;
  }
}

export async function settleAsync<T>(work: Promise<T>): Promise<Result<T>> {
  try {
    return { ok: true, value: await work };
  } catch (thrown) {
    if (isHaspError(thrown)) {
      return { ok: false, error: thrown };
    }
    throw thrown;
  }
}

let loading: Promise<void> | undefined;

async function instantiate(source: WasmSource): Promise<void> {
  try {
    if (source.kind === 'url') {
      await init({ module_or_path: source.url });
    } else {
      initSync({ module: source.bytes });
    }
  } catch (failure) {
    loading = undefined;
    throw failure;
  }
}

export async function loadWasm(source: WasmSource, signal: AbortSignal): Promise<void> {
  signal.throwIfAborted();
  loading ??= instantiate(source);
  const aborted = new Promise<never>((_resolve, reject) => {
    signal.addEventListener('abort', () => reject(new Error('aborted', { cause: signal.reason })), {
      once: true,
    });
  });
  await Promise.race([loading, aborted]);
}

export const groups = (): readonly string[] => vectorGroups();

export const replay = (group: string, vectors: string): Result<readonly ReplayOutcome[]> =>
  settle(() => replayVectors(group, vectors).outcomes);

export const normalisePassword = (input: string): string => wasmNormalisePassword(input);

export const normaliseLogin = (input: string): Result<string> =>
  settle(() => wasmNormaliseLogin(input));

export const extensionUnlockCode = (device: string, nonce: string): Result<string> =>
  settle(() => wasmExtensionUnlockCode(device, nonce));

export const extensionPairingCode = (enrolRequest: Uint8Array): Result<string> =>
  settle(() => wasmExtensionPairingCode(enrolRequest));

export const registrableDomain = (host: string): string | undefined => wasmRegistrableDomain(host);
