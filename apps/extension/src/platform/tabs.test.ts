import { describe, expect, it } from 'vitest';

import { originPattern } from './tabs.ts';

describe('originPattern', () => {
  it.each([
    { origin: 'https://vault.example.com', pattern: 'https://vault.example.com/*' },
    { origin: 'https://vault.example.com:8443', pattern: 'https://vault.example.com/*' },
    { origin: 'http://127.0.0.1:4000', pattern: 'http://127.0.0.1/*' },
    { origin: 'http://localhost:3000', pattern: 'http://localhost/*' },
  ])('drops the port from $origin', ({ origin, pattern }) => {
    expect(originPattern(origin)).toBe(pattern);
  });
});
