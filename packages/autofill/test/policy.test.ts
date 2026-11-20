import { describe, expect, it } from 'vitest';

import { verifyFillRequest } from '../src/policy/fill-gate.ts';
import {
  GESTURE_TOKEN_TTL_MS,
  consumeGestureToken,
  mintGestureToken,
} from '../src/policy/gesture.ts';
import { decideStepUp } from '../src/policy/step-up.ts';
import type { StepUpInput } from '../src/policy/step-up.ts';
import type { SessionStore } from '../src/ports.ts';
import { ok } from '../src/result.ts';

const base: StepUpInput = {
  fill: 'password',
  frame: 'top',
  level: 'exact',
  isHostConfirmed: false,
  isCardHostRemembered: false,
  isObscured: false,
  isC4Supported: true,
  settings: { isAskBeforeFilling: false },
};

describe('step-up policy', () => {
  it.each([
    ['exact-host password in the top frame', {}, { kind: 'none' }],
    ['exact-host otp', { fill: 'otp' }, { kind: 'none' }],
    ['exact-host passkey sign-in', { fill: 'passkey-sign-in' }, { kind: 'none' }],
    [
      'first cross-host fill',
      { level: 'domain' },
      { kind: 'inline-confirm', reason: 'first-cross-host' },
    ],
    ['confirmed cross-host fill', { level: 'domain', isHostConfirmed: true }, { kind: 'none' }],
    [
      'related site first use',
      { level: 'related' },
      { kind: 'inline-confirm', reason: 'first-cross-host' },
    ],
    ['card first time', { fill: 'card' }, { kind: 'inline-confirm', reason: 'card' }],
    ['card remembered for host', { fill: 'card', isCardHostRemembered: true }, { kind: 'none' }],
    ['identity first time', { fill: 'identity' }, { kind: 'inline-confirm', reason: 'identity' }],
    [
      'passkey creation',
      { fill: 'passkey-create' },
      { kind: 'inline-confirm', reason: 'passkey-create' },
    ],
    ['obscured', { isObscured: true }, { kind: 'browser-ui', reason: 'obscured' }],
    [
      'cross-origin frame',
      { frame: 'cross-origin' },
      { kind: 'browser-ui', reason: 'cross-origin-frame' },
    ],
    ['same-origin frame behaves as top', { frame: 'same-origin' }, { kind: 'none' }],
    ['C4 unsupported: password is not escalated', { isC4Supported: false }, { kind: 'none' }],
    [
      'C4 unsupported: card uses browser UI',
      { fill: 'card', isC4Supported: false },
      { kind: 'browser-ui', reason: 'visibility-unsupported' },
    ],
    [
      'C4 unsupported: first cross-host uses browser UI',
      { level: 'domain', isC4Supported: false },
      { kind: 'browser-ui', reason: 'visibility-unsupported' },
    ],
    [
      'ask before filling',
      { settings: { isAskBeforeFilling: true } },
      { kind: 'inline-confirm', reason: 'ask-always' },
    ],
  ] as const)('%s', (_name, over, expected) => {
    expect(decideStepUp({ ...base, ...over })).toEqual(expected);
  });

  it.each(['sandboxed', 'opaque', 'blank', 'blob'] as const)('refuses %s frames', (frame) => {
    expect(decideStepUp({ ...base, frame })).toEqual({
      kind: 'refuse',
      reason: 'frame-not-allowed',
    });
  });
});

const memory = (): SessionStore => {
  const data = new Map<string, unknown>();
  return {
    get: async (k) => {
      await Promise.resolve();
      return data.get(k);
    },
    set: async (k, v) => {
      await Promise.resolve();
      data.set(k, v);
      return ok(null);
    },
    remove: async (k) => {
      data.delete(k);
      await Promise.resolve();
    },
  };
};

const binding = { tabId: 3, frameId: 0, nonce: 'n'.repeat(24), itemId: 'item-1' };

describe('gesture tokens (C7, C8)', () => {
  it('accepts a fresh token once', async () => {
    const store = memory();
    await mintGestureToken(store, binding, 1000, 'tok');
    expect((await consumeGestureToken(store, 'tok', binding, 1500)).ok).toBe(true);
    expect(await consumeGestureToken(store, 'tok', binding, 1500)).toEqual({
      ok: false,
      error: { kind: 'unknown-token' },
    });
  });

  it('rejects after the 2 s TTL', async () => {
    const store = memory();
    await mintGestureToken(store, binding, 1000, 'tok');
    expect(
      await consumeGestureToken(store, 'tok', binding, 1000 + GESTURE_TOKEN_TTL_MS + 1),
    ).toEqual({ ok: false, error: { kind: 'expired' } });
  });

  it.each([
    ['tab', { tabId: 9 }],
    ['frame', { frameId: 5 }],
    ['nonce', { nonce: 'x'.repeat(24) }],
    ['item', { itemId: 'item-2' }],
  ] as const)('rejects a token bound to a different %s and burns it', async (_n, over) => {
    const store = memory();
    await mintGestureToken(store, binding, 1000, 'tok');
    expect(await consumeGestureToken(store, 'tok', { ...binding, ...over }, 1100)).toEqual({
      ok: false,
      error: { kind: 'mismatch' },
    });
    expect((await consumeGestureToken(store, 'tok', binding, 1100)).ok).toBe(false);
  });
});

const attestation = {
  checkedAtMs: 1000,
  passed: ['C1', 'C2', 'C3', 'C4', 'C5'] as ('C1' | 'C2' | 'C3' | 'C4' | 'C5')[],
  isC4Supported: true,
};
const gate = {
  isUnlocked: true,
  isTabActiveAndFocused: true,
  isSenderBoundFrame: true,
  isTokenAccepted: true,
  attestation,
  nowMs: 1200,
};

describe('fill gate (C8)', () => {
  it('passes with everything fresh', () => {
    expect(verifyFillRequest(gate).ok).toBe(true);
  });

  it.each([
    ['locked', { isUnlocked: false }, 'locked'],
    ['wrong frame', { isSenderBoundFrame: false }, 'sender-mismatch'],
    ['background tab', { isTabActiveAndFocused: false }, 'tab-not-active'],
    ['bad token', { isTokenAccepted: false }, 'token-rejected'],
    ['stale attestation', { nowMs: 1301 }, 'attestation-stale'],
    ['attestation from the future', { nowMs: 940 }, 'attestation-stale'],
    ['attestation far in the future', { nowMs: 800 }, 'attestation-stale'],
    [
      'missing C3',
      {
        attestation: {
          ...attestation,
          passed: ['C1', 'C2', 'C4', 'C5'] as typeof attestation.passed,
        },
      },
      'attestation-incomplete',
    ],
  ] as const)('refuses: %s', (_n, over, reason) => {
    expect(verifyFillRequest({ ...gate, ...over })).toEqual({ ok: false, error: reason });
  });

  it('does not require C4 when the browser cannot observe visibility', () => {
    const noC4 = {
      checkedAtMs: 1000,
      passed: ['C1', 'C2', 'C3', 'C5'] as typeof attestation.passed,
      isC4Supported: false,
    };
    expect(verifyFillRequest({ ...gate, attestation: noC4 }).ok).toBe(true);
  });
});
