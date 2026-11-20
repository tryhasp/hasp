import { describe, expect, it } from 'vitest';

import { ticketKey } from '../src/background/keys.ts';

describe('ticketKey', () => {
  it('accepts a session blob and the paired key', () => {
    expect(ticketKey.schema.safeParse({ kind: 'session', blob: 'AQ==' }).success).toBe(true);
    expect(
      ticketKey.schema.safeParse({ kind: 'extension', key: 'AQ==', validUntilMs: 1 }).success,
    ).toBe(true);
  });

  it('has no shape that can hold the account password', () => {
    expect(ticketKey.schema.safeParse({ kind: 'password', password: 'x' }).success).toBe(false);
    expect(ticketKey.schema.safeParse({ kind: 'session', blob: 'x', password: 'x' }).success).toBe(
      false,
    );
  });
});
