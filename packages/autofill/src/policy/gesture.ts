import { z } from 'zod';

import type { SessionStore, StorageError } from '../ports.ts';
import { err, ok } from '../result.ts';
import type { Result } from '../result.ts';

export const GESTURE_TOKEN_TTL_MS = 2000;
export const ATTESTATION_MAX_AGE_MS = 300;
const TOKEN_KEY_PREFIX = 'gesture:';

const tokenRecordSchema = z.strictObject({
  tabId: z.number().int(),
  frameId: z.number().int(),
  nonce: z.string(),
  itemId: z.string(),
  issuedAtMs: z.number(),
});
export type GestureBinding = Omit<z.infer<typeof tokenRecordSchema>, 'issuedAtMs'>;

export type GestureError =
  | StorageError
  | { kind: 'unknown-token' }
  | { kind: 'expired' }
  | { kind: 'mismatch' };

export const mintGestureToken = async (
  store: SessionStore,
  binding: GestureBinding,
  nowMs: number,
  token: string,
): Promise<Result<string, StorageError>> => {
  const stored = await store.set(`${TOKEN_KEY_PREFIX}${token}`, { ...binding, issuedAtMs: nowMs });
  return stored.ok ? ok(token) : stored;
};

export const consumeGestureToken = async (
  store: SessionStore,
  token: string,
  expected: GestureBinding,
  nowMs: number,
): Promise<Result<null, GestureError>> => {
  const key = `${TOKEN_KEY_PREFIX}${token}`;
  const parsed = tokenRecordSchema.safeParse(await store.get(key));
  await store.remove(key);
  if (!parsed.success) return err({ kind: 'unknown-token' });
  const rec = parsed.data;
  if (nowMs - rec.issuedAtMs > GESTURE_TOKEN_TTL_MS || nowMs < rec.issuedAtMs) {
    return err({ kind: 'expired' });
  }
  const matches =
    rec.tabId === expected.tabId &&
    rec.frameId === expected.frameId &&
    rec.nonce === expected.nonce &&
    rec.itemId === expected.itemId;
  return matches ? ok(null) : err({ kind: 'mismatch' });
};
