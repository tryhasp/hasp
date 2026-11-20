import { describe, expect, it } from 'vitest';

import type { SessionStore } from '../src/ports.ts';
import { ok } from '../src/result.ts';
import { decideSaveKind } from '../src/save/decide.ts';
import {
  GENERATED_KEEP,
  GENERATED_TTL_MS,
  PENDING_TTL_MS,
  capturePending,
  clearOnLock,
  listGenerated,
  markGeneratedSaved,
  markGeneratedUnverified,
  markSubmitted,
  readPending,
  recordGenerated,
  submittedPassword,
  unsavedSignups,
} from '../src/save/pending-store.ts';

const backing = (): { data: Map<string, unknown>; store: () => SessionStore } => {
  const data = new Map<string, unknown>();
  return {
    data,
    store: () => ({
      get: async (k) => {
        await Promise.resolve();
        return structuredClone(data.get(k));
      },
      set: async (k, v) => {
        await Promise.resolve();
        data.set(k, structuredClone(v));
        return ok(null);
      },
      remove: async (k) => {
        await Promise.resolve();
        data.delete(k);
      },
    }),
  };
};

const key = { tabId: 1, site: 'example.test' };

describe('save decisions', () => {
  it.each([
    [
      'no item with that username',
      {
        username: 'a',
        isChangeForm: false,
        matches: [{ username: 'b', isSamePassword: false }],
        suppression: undefined,
      },
      'new',
    ],
    [
      'same username, different password',
      {
        username: 'a',
        isChangeForm: false,
        matches: [{ username: 'a', isSamePassword: false }],
        suppression: undefined,
      },
      'update',
    ],
    [
      'identical',
      {
        username: 'a',
        isChangeForm: false,
        matches: [{ username: 'a', isSamePassword: true }],
        suppression: undefined,
      },
      'none',
    ],
    [
      'change-password form, one item',
      {
        username: undefined,
        isChangeForm: true,
        matches: [{ username: 'a', isSamePassword: false }],
        suppression: undefined,
      },
      'update',
    ],
    [
      'never_save',
      { username: 'a', isChangeForm: false, matches: [], suppression: 'never-save' },
      'none',
    ],
    [
      'skip_save quirk',
      { username: 'a', isChangeForm: false, matches: [], suppression: 'skip-save-quirk' },
      'none',
    ],
    [
      'sites that append 2FA',
      { username: 'a', isChangeForm: false, matches: [], suppression: 'appends-2fa' },
      'none',
    ],
    [
      'cross-origin payment frame',
      { username: 'a', isChangeForm: false, matches: [], suppression: 'cross-origin-frame' },
      'none',
    ],
    [
      'generated password the page did not receive',
      { username: 'a', isChangeForm: false, matches: [], suppression: 'generated-unverified' },
      'none',
    ],
  ] as const)('%s -> %s', (_n, input, expected) => {
    expect(decideSaveKind(input)).toBe(expected);
  });
});

describe('pending captures', () => {
  it('merges field updates and expires after 24 h', async () => {
    const { store } = backing();
    const s = store();
    await capturePending(s, key, { username: 'a' }, 1000);
    const merged = await capturePending(s, key, { password: 'p' }, 2000);
    expect(merged).toMatchObject({
      ok: true,
      value: { username: 'a', password: 'p', isSubmitted: false },
    });
    expect(await readPending(s, key, 2000 + PENDING_TTL_MS)).toBeDefined();
    expect(await readPending(s, key, 2000 + PENDING_TTL_MS + 1)).toBeUndefined();
  });

  it('keeps a submitted capture across a simulated service worker eviction', async () => {
    const { store } = backing();
    await capturePending(store(), key, { username: 'a', password: 'p' }, 1000);
    await markSubmitted(store(), key, 1500);
    const afterEviction = store();
    expect(await readPending(afterEviction, key, 9000)).toMatchObject({
      username: 'a',
      password: 'p',
      isSubmitted: true,
    });
  });

  it('is cleared on lock, including the index and generated list', async () => {
    const { store, data } = backing();
    await capturePending(store(), key, { password: 'p' }, 1000);
    await recordGenerated(
      store(),
      { id: 'g1', value: 'v', site: 'example.test', atMs: 1000 },
      1000,
    );
    await clearOnLock(store());
    expect([...data.keys()]).toEqual([]);
  });
});

describe('generated passwords survive eviction', () => {
  it('is written before the fill and still listed after the worker restarts', async () => {
    const { store } = backing();
    await recordGenerated(
      store(),
      { id: 'g1', value: 'Qx7!kM2-pR9#vT4s', site: 'shop.test', atMs: 1000 },
      1000,
    );
    const restarted = store();
    expect(await listGenerated(restarted, 2000)).toHaveLength(1);
    expect(await unsavedSignups(restarted, 2000)).toMatchObject([{ id: 'g1', site: 'shop.test' }]);
  });

  it('keeps the last 20 for 24 h', async () => {
    const { store } = backing();
    const s = store();
    for (let i = 0; i < GENERATED_KEEP + 5; i += 1) {
      await recordGenerated(
        s,
        { id: `g${i}`, value: 'v', site: 's.test', atMs: 1000 + i },
        1000 + i,
      );
    }
    const list = await listGenerated(s, 5000);
    expect(list).toHaveLength(GENERATED_KEEP);
    expect(list[0]?.id).toBe('g5');
    expect(await listGenerated(s, 1000 + GENERATED_TTL_MS + 100)).toHaveLength(0);
  });

  it('drops saved entries from the unsaved list and unverified ones from saving', async () => {
    const { store } = backing();
    const s = store();
    await recordGenerated(s, { id: 'a', value: 'v', site: 's.test', atMs: 1000 }, 1000);
    await recordGenerated(s, { id: 'b', value: 'v', site: 's.test', atMs: 1000 }, 1000);
    await markGeneratedSaved(s, 'a', 1100);
    await markGeneratedUnverified(s, 'b', 1100);
    expect(await unsavedSignups(s, 1200)).toEqual([]);
    expect(await markGeneratedSaved(s, 'nope', 1200)).toEqual({
      ok: false,
      error: { kind: 'unknown-entry' },
    });
  });
});

describe('concurrent session writes', () => {
  it('keeps the submit mark and the generated password when capture and submit race', async () => {
    const { store } = backing();
    const s = store();
    await capturePending(s, key, { newPassword: 'g', isGenerated: true }, 1000);
    await Promise.all([
      capturePending(s, key, { username: 'dave' }, 1001),
      markSubmitted(s, key, 1002),
      capturePending(s, key, { username: 'dave' }, 1003),
    ]);
    expect(await readPending(s, key, 1004)).toMatchObject({
      newPassword: 'g',
      username: 'dave',
      isGenerated: true,
      isSubmitted: true,
    });
  });

  it('keeps the submit mark when the submit arrives before any capture', async () => {
    const { store } = backing();
    const s = store();
    await Promise.all([
      markSubmitted(s, key, 1000),
      capturePending(s, key, { password: 'p' }, 1001),
    ]);
    expect(await readPending(s, key, 1002)).toMatchObject({ password: 'p', isSubmitted: true });
  });

  it('keeps every generated entry when records and marks interleave', async () => {
    const { store } = backing();
    const s = store();
    await recordGenerated(s, { id: 'a', value: 'x', site: 'example.test', atMs: 1000 }, 1000);
    await Promise.all([
      recordGenerated(s, { id: 'b', value: 'y', site: 'example.test', atMs: 1001 }, 1001),
      markGeneratedSaved(s, 'a', 1001),
    ]);
    const list = await listGenerated(s, 1002);
    expect(list.map((e) => e.id)).toEqual(['a', 'b']);
    expect(list[0]?.isSaved).toBe(true);
  });

  it('keeps the pending ttl at 30 minutes', () => {
    expect(PENDING_TTL_MS).toBe(30 * 60 * 1000);
  });

  it('proposes the typed password after an abandoned signup then a login', async () => {
    const { store } = backing();
    const s = store();
    await capturePending(s, key, { newPassword: 'generated-G', isGenerated: true }, 1000);
    await capturePending(s, key, { username: 'me', password: 'typed-P' }, 2000);
    await markSubmitted(s, key, 2100, 'login');
    const pending = await readPending(s, key, 2200);
    expect(pending).toBeDefined();
    if (pending === undefined) return;
    expect(pending.newPassword).toBeUndefined();
    expect(pending.isGenerated).toBe(false);
    expect(submittedPassword(pending)).toBe('typed-P');
  });

  it('uses the new password for signup and change-password submits', async () => {
    const { store } = backing();
    for (const kind of ['signup', 'change-password'] as const) {
      const s = store();
      await capturePending(
        s,
        key,
        { password: 'old', newPassword: 'new', isGenerated: true },
        1000,
      );
      await markSubmitted(s, key, 1100, kind);
      const pending = await readPending(s, key, 1200);
      expect(pending && submittedPassword(pending)).toBe('new');
      expect(pending?.isGenerated).toBe(true);
    }
  });

  it('ignores a forged newPassword on a login submit', () => {
    expect(
      submittedPassword({
        password: 'typed',
        newPassword: 'forged',
        isGenerated: false,
        isSubmitted: true,
        submittedKind: 'login',
        capturedAtMs: 1,
      }),
    ).toBe('typed');
  });
});
