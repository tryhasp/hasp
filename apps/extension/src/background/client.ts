import { HaspClient, settleAsync } from '@hasp/wasm';
import type { AccountStatus, HaspError, Result } from '@hasp/wasm';

import { targetBrowser } from '../platform/browser.ts';
import { readKey, removeKey, writeKey } from '../platform/storage.ts';
import { fromBase64, toBase64 } from '../shared/bytes.ts';
import { ensureWasm } from '../wasm/runtime.ts';
import { accountKey, storeKey, ticketKey } from './keys.ts';

export type CallError = HaspError | { kind: 'no-account' };
export type CallResult<T> = { ok: true; value: T } | { ok: false; error: CallError };

type Cell = {
  client: Promise<HaspClient | undefined> | undefined;
  recovery: Promise<boolean> | undefined;
};

const cell: Cell = { client: undefined, recovery: undefined };
const revisions = new WeakMap<HaspClient, number>();

const platformName = (): string => targetBrowser();

const openStored = async (): Promise<HaspClient | undefined> => {
  await ensureWasm();
  const account = await readKey(accountKey);
  if (!account.ok || account.value === undefined) return undefined;
  const stored = await readKey(storeKey);
  const snapshot = stored.ok && stored.value !== undefined ? fromBase64(stored.value) : undefined;
  const client = new HaspClient(account.value.origin, platformName(), snapshot);
  revisions.set(client, client.storeRevision());
  return client;
};

export const getClient = async (): Promise<HaspClient | undefined> => {
  cell.client ??= openStored();
  try {
    return await cell.client;
  } catch (cause) {
    cell.client = undefined;
    throw cause;
  }
};

export const createClient = async (origin: string): Promise<HaspClient> => {
  await ensureWasm();
  return new HaspClient(origin, platformName(), undefined);
};

export const adoptClient = async (client: HaspClient, origin: string): Promise<void> => {
  const previous = await getClient();
  if (previous !== undefined && previous !== client) previous.free();
  cell.client = Promise.resolve(client);
  cell.recovery = undefined;
  await writeKey(accountKey, { origin });
  await persistIfChanged(client);
};

export const dropClient = async (): Promise<void> => {
  const current = await getClient();
  current?.free();
  cell.client = Promise.resolve(undefined);
  cell.recovery = undefined;
  await removeKey(accountKey);
  await removeKey(storeKey);
};

export const persistIfChanged = async (client: HaspClient): Promise<void> => {
  const revision = client.storeRevision();
  if (revisions.get(client) === revision) return;
  const snapshot = client.exportStore();
  await writeKey(storeKey, toBase64(snapshot));
  revisions.set(client, revision);
};

export const statusOf = async (client: HaspClient): Promise<Result<AccountStatus>> => {
  const status = await settleAsync(client.status());
  return status;
};

const recover = async (client: HaspClient): Promise<boolean> => {
  const ticket = await readKey(ticketKey);
  if (!ticket.ok || ticket.value === undefined) return false;
  const value = ticket.value;
  if (value.kind === 'extension') {
    if (Date.now() >= value.validUntilMs) {
      await removeKey(ticketKey);
      return false;
    }
    const key = fromBase64(value.key);
    const opened = await settleAsync(client.unlockExtension(key));
    key.fill(0);
    return opened.ok;
  }
  const blob = fromBase64(value.blob);
  const opened = await settleAsync(client.resumeSession(blob));
  blob.fill(0);
  if (!opened.ok && (opened.error.kind === 'auth' || opened.error.kind === 'format')) {
    await removeKey(ticketKey);
  }
  await persistIfChanged(client);
  return opened.ok;
};

export const unlockedClient = async (): Promise<CallResult<HaspClient>> => {
  const client = await getClient();
  if (client === undefined) return { ok: false, error: { kind: 'no-account' } };
  const status = await statusOf(client);
  if (!status.ok) return status;
  if (status.value.state === 'empty') return { ok: false, error: { kind: 'no-account' } };
  if (status.value.state === 'locked') {
    cell.recovery ??= recover(client);
    const recovered = await cell.recovery;
    cell.recovery = undefined;
    if (!recovered) return { ok: false, error: { kind: 'locked' } };
  }
  return { ok: true, value: client };
};

export const withUnlocked = async <T>(
  work: (client: HaspClient) => Promise<T>,
): Promise<CallResult<T>> => {
  const unlocked = await unlockedClient();
  if (!unlocked.ok) return unlocked;
  const result = await settleAsync(work(unlocked.value));
  await persistIfChanged(unlocked.value);
  return result;
};

export const withClient = async <T>(
  work: (client: HaspClient) => Promise<T>,
): Promise<CallResult<T>> => {
  const client = await getClient();
  if (client === undefined) return { ok: false, error: { kind: 'no-account' } };
  const result = await settleAsync(work(client));
  await persistIfChanged(client);
  return result;
};
