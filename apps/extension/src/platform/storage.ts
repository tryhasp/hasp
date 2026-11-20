import type { SessionStore } from '@hasp/autofill';
import { err, ok } from '@hasp/autofill';
import type { Result } from '@hasp/autofill';
import type { z } from 'zod';

import { api } from './browser.ts';

export type StorageError = { kind: 'quota' } | { kind: 'unavailable' } | { kind: 'invalid' };

export type Area = 'local' | 'session';

export type Key<T> = { area: Area; name: string; schema: z.ZodType<T> };

export const defineKey = <T>(area: Area, name: string, schema: z.ZodType<T>): Key<T> => ({
  area,
  name,
  schema,
});

const areaOf = (area: Area): chrome.storage.StorageArea =>
  area === 'local' ? api.storage.local : api.storage.session;

const isQuota = (cause: unknown): boolean => cause instanceof Error && /quota/i.test(cause.message);

// Why: the content script must reach its own handoff record in session storage; page scripts never see extension storage, only the isolated content-script world does.
export const protectSession = async (): Promise<void> => {
  try {
    await api.storage.session.setAccessLevel({ accessLevel: 'TRUSTED_AND_UNTRUSTED_CONTEXTS' });
  } catch {
    return;
  }
};

export const readKey = async <T>(key: Key<T>): Promise<Result<T | undefined, StorageError>> => {
  try {
    const stored = await areaOf(key.area).get(key.name);
    const raw: unknown = stored[key.name];
    if (raw === undefined) return ok(undefined);
    const parsed = key.schema.safeParse(raw);
    return parsed.success ? ok(parsed.data) : err({ kind: 'invalid' });
  } catch {
    return err({ kind: 'unavailable' });
  }
};

export const writeKey = async <T>(key: Key<T>, value: T): Promise<Result<null, StorageError>> => {
  try {
    await areaOf(key.area).set({ [key.name]: value });
    return ok(null);
  } catch (cause) {
    return err(isQuota(cause) ? { kind: 'quota' } : { kind: 'unavailable' });
  }
};

export const removeKey = async (key: Key<unknown>): Promise<void> => {
  try {
    await areaOf(key.area).remove(key.name);
  } catch {
    return;
  }
};

export const clearSession = async (): Promise<void> => {
  try {
    await api.storage.session.clear();
  } catch {
    return;
  }
};

export const sessionStore: SessionStore = {
  get: async (name) => {
    try {
      const stored = await api.storage.session.get(name);
      const value: unknown = stored[name];
      return value;
    } catch {
      return undefined;
    }
  },
  set: async (name, value) => {
    try {
      await api.storage.session.set({ [name]: value });
      return ok(null);
    } catch (cause) {
      return err(isQuota(cause) ? { kind: 'quota' } : { kind: 'unavailable' });
    }
  },
  remove: async (name) => {
    try {
      await api.storage.session.remove(name);
    } catch {
      return;
    }
  },
};

export const listSessionKeys = async (prefix: string): Promise<string[]> => {
  try {
    const all = await api.storage.session.get(null);
    return Object.keys(all).filter((name) => name.startsWith(prefix));
  } catch {
    return [];
  }
};
