import { z } from 'zod';

import type { SessionStore, StorageError } from '../ports.ts';
import { err, ok } from '../result.ts';
import type { Result } from '../result.ts';

export const PENDING_TTL_MS = 30 * 60 * 1000;
export const GENERATED_TTL_MS = 24 * 60 * 60 * 1000;

export const submitKinds = ['login', 'signup', 'change-password', 'password-only'] as const;
export type SubmitKind = (typeof submitKinds)[number];
export const GENERATED_KEEP = 20;
const INDEX_KEY = 'pending-index';
const GENERATED_KEY = 'generated';

const pendingSchema = z.strictObject({
  username: z.string().optional(),
  password: z.string().optional(),
  newPassword: z.string().optional(),
  isGenerated: z.boolean(),
  isSubmitted: z.boolean(),
  submittedKind: z.enum(submitKinds).optional(),
  capturedAtMs: z.number(),
});
export type Pending = z.infer<typeof pendingSchema>;

const generatedEntrySchema = z.strictObject({
  id: z.string(),
  value: z.string(),
  site: z.string(),
  atMs: z.number(),
  isSaved: z.boolean(),
  isVerified: z.boolean(),
});
export type GeneratedEntry = z.infer<typeof generatedEntrySchema>;

const generatedListSchema = z.array(generatedEntrySchema);
const indexSchema = z.array(z.string());

export type PendingKey = { tabId: number; site: string };

const queues = new WeakMap<SessionStore, Promise<unknown>>();

// Why: content scripts fire capture and submit-signal without waiting, and a worker restarted by eviction handles them back to back; unserialised read-modify-write lost isSubmitted.
const serialised = async <T>(store: SessionStore, work: () => Promise<T>): Promise<T> => {
  const run = (queues.get(store) ?? Promise.resolve()).then(work, work);
  queues.set(
    store,
    run.then(
      () => undefined,
      () => undefined,
    ),
  );
  return run;
};

const keyOf = (k: PendingKey): string => `pending:${k.tabId}:${k.site}`;
const isFresh = (atMs: number, nowMs: number, ttlMs: number): boolean =>
  nowMs - atMs <= ttlMs && nowMs >= atMs;

export const submittedPassword = (pending: Pending): string | undefined =>
  pending.submittedKind === 'login' ? pending.password : (pending.newPassword ?? pending.password);

const addToIndex = async (
  store: SessionStore,
  key: string,
): Promise<Result<null, StorageError>> => {
  const index = indexSchema.safeParse(await store.get(INDEX_KEY));
  const keys = index.success ? index.data : [];
  if (keys.includes(key)) return ok(null);
  const written = await store.set(INDEX_KEY, [...keys, key]);
  return written;
};

export const capturePending = async (
  store: SessionStore,
  key: PendingKey,
  update: Partial<Pick<Pending, 'username' | 'password' | 'newPassword' | 'isGenerated'>>,
  nowMs: number,
): Promise<Result<Pending, StorageError>> => {
  const result = await serialised(store, async () => captureNow(store, key, update, nowMs));
  return result;
};

const captureNow = async (
  store: SessionStore,
  key: PendingKey,
  update: Partial<Pick<Pending, 'username' | 'password' | 'newPassword' | 'isGenerated'>>,
  nowMs: number,
): Promise<Result<Pending, StorageError>> => {
  const current = await readPending(store, key, nowMs);
  const next: Pending = {
    isGenerated: false,
    isSubmitted: false,
    ...current,
    ...update,
    capturedAtMs: nowMs,
  };
  const written = await store.set(keyOf(key), next);
  if (!written.ok) return written;
  const indexed = await addToIndex(store, keyOf(key));
  return indexed.ok ? ok(next) : indexed;
};

export const readPending = async (
  store: SessionStore,
  key: PendingKey,
  nowMs: number,
): Promise<Pending | undefined> => {
  const parsed = pendingSchema.safeParse(await store.get(keyOf(key)));
  if (!parsed.success) return undefined;
  if (isFresh(parsed.data.capturedAtMs, nowMs, PENDING_TTL_MS)) return parsed.data;
  await store.remove(keyOf(key));
  return undefined;
};

const withoutGenerated = (pending: Pending): Pending => {
  const { newPassword: _discarded, ...rest } = pending;
  return { ...rest, isGenerated: false };
};

export const markSubmitted = async (
  store: SessionStore,
  key: PendingKey,
  nowMs: number,
  kind?: SubmitKind,
): Promise<Result<Pending, StorageError>> =>
  serialised(store, async () => {
    const current = await readPending(store, key, nowMs);
    const base = kind === 'login' && current !== undefined ? withoutGenerated(current) : current;
    const next: Pending = {
      isGenerated: false,
      ...base,
      ...(kind === undefined ? {} : { submittedKind: kind }),
      isSubmitted: true,
      capturedAtMs: current?.capturedAtMs ?? nowMs,
    };
    const written = await store.set(keyOf(key), next);
    if (!written.ok) return written;
    const indexed = await addToIndex(store, keyOf(key));
    return indexed.ok ? ok(next) : indexed;
  });

export const clearPending = async (store: SessionStore, key: PendingKey): Promise<void> =>
  serialised(store, async () => {
    await store.remove(keyOf(key));
  });

export const recordGenerated = async (
  store: SessionStore,
  entry: Omit<GeneratedEntry, 'isSaved' | 'isVerified'>,
  nowMs: number,
): Promise<Result<null, StorageError>> =>
  serialised(store, async () => {
    const list = await listGenerated(store, nowMs);
    const next = [...list, { ...entry, isSaved: false, isVerified: true }].slice(-GENERATED_KEEP);
    const written = await store.set(GENERATED_KEY, next);
    return written;
  });

export const listGenerated = async (
  store: SessionStore,
  nowMs: number,
): Promise<GeneratedEntry[]> => {
  const parsed = generatedListSchema.safeParse(await store.get(GENERATED_KEY));
  if (!parsed.success) return [];
  return parsed.data.filter((e) => isFresh(e.atMs, nowMs, GENERATED_TTL_MS));
};

const updateGenerated = async (
  store: SessionStore,
  id: string,
  patch: Partial<Pick<GeneratedEntry, 'isSaved' | 'isVerified'>>,
  nowMs: number,
): Promise<Result<null, StorageError | { kind: 'unknown-entry' }>> =>
  serialised(store, async () => {
    const list = await listGenerated(store, nowMs);
    if (!list.some((e) => e.id === id)) return err({ kind: 'unknown-entry' });
    const written = await store.set(
      GENERATED_KEY,
      list.map((e) => (e.id === id ? { ...e, ...patch } : e)),
    );
    return written;
  });

export const markGeneratedSaved = async (
  store: SessionStore,
  id: string,
  nowMs: number,
): Promise<Result<null, StorageError | { kind: 'unknown-entry' }>> => {
  const result = await updateGenerated(store, id, { isSaved: true }, nowMs);
  return result;
};

export const markGeneratedUnverified = async (
  store: SessionStore,
  id: string,
  nowMs: number,
): Promise<Result<null, StorageError | { kind: 'unknown-entry' }>> => {
  const result = await updateGenerated(store, id, { isVerified: false }, nowMs);
  return result;
};

export const unsavedSignups = async (
  store: SessionStore,
  nowMs: number,
): Promise<GeneratedEntry[]> =>
  (await listGenerated(store, nowMs)).filter((e) => !e.isSaved && e.isVerified);

export const clearOnLock = async (store: SessionStore): Promise<void> =>
  serialised(store, async () => {
    const index = indexSchema.safeParse(await store.get(INDEX_KEY));
    for (const key of index.success ? index.data : []) await store.remove(key);
    await store.remove(INDEX_KEY);
    await store.remove(GENERATED_KEY);
  });
