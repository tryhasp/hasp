import type { Result } from './result.ts';

export type StorageError = { kind: 'quota' } | { kind: 'unavailable' };

export type SessionStore = {
  get: (key: string) => Promise<unknown>;
  set: (key: string, value: unknown) => Promise<Result<null, StorageError>>;
  remove: (key: string) => Promise<void>;
};

export type Clock = { nowMs: () => number };
export type RandomToken = { token: () => string };
