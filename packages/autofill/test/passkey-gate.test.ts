import { describe, expect, it } from 'vitest';

import { FALLBACK_DELAY_MS, fallbackWaitMs, shouldAsk } from '../src/passkey/gate.ts';

const base = { op: 'get' as const, mediation: undefined, isActivationActive: true, inFlight: 0 };

describe('passkey prompt gate', () => {
  it('asks when the page has a live user activation', () => {
    expect(shouldAsk(base)).toBe(true);
    expect(shouldAsk({ ...base, op: 'create' })).toBe(true);
  });

  it.each(['create', 'get'] as const)('goes native for %s without activation', (op) => {
    expect(shouldAsk({ ...base, op, isActivationActive: false })).toBe(false);
  });

  it('lets conditional get pass without activation', () => {
    expect(shouldAsk({ ...base, mediation: 'conditional', isActivationActive: false })).toBe(true);
  });

  it('refuses a second prompt while one is open', () => {
    expect(shouldAsk({ ...base, inFlight: 1 })).toBe(false);
  });
});

describe('fallbackWaitMs', () => {
  it('pads a fast fallback up to the fixed delay', () => {
    expect(fallbackWaitMs(3)).toBe(FALLBACK_DELAY_MS - 3);
    expect(fallbackWaitMs(FALLBACK_DELAY_MS + 50)).toBe(0);
    expect(fallbackWaitMs(-5)).toBe(FALLBACK_DELAY_MS);
  });
});
