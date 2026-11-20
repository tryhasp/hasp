import { describe, expect, it } from 'vitest';

import { sha256Hex, shouldClear } from './clipboard-policy.ts';

describe('shouldClear', () => {
  it('clears when the clipboard still holds the secret', async () => {
    const digest = await sha256Hex('s3cret');
    expect(await shouldClear('s3cret', digest)).toBe(true);
  });

  it('leaves something the user copied afterwards', async () => {
    const digest = await sha256Hex('s3cret');
    expect(await shouldClear('another thing', digest)).toBe(false);
  });

  it('clears best effort when the clipboard cannot be read', async () => {
    const digest = await sha256Hex('s3cret');
    expect(await shouldClear(undefined, digest)).toBe(true);
  });
});
