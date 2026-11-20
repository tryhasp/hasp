import { describe, expect, it } from 'vitest';

import { normalizeServer, wsUrlOf } from './server.ts';

describe('normalizeServer', () => {
  it.each([
    { text: 'https://vault.example.com/some/path?x=1', origin: 'https://vault.example.com' },
    { text: '  http://127.0.0.1:8080/  ', origin: 'http://127.0.0.1:8080' },
    { text: 'ftp://vault.example.com', origin: undefined },
    { text: 'vault.example.com', origin: undefined },
    { text: 'java'.concat('script:alert(1)'), origin: undefined },
  ])('reads $text', ({ text, origin }) => {
    expect(normalizeServer(text)).toBe(origin);
  });
});

describe('wsUrlOf', () => {
  it('uses wss for https and ws for http', () => {
    expect(wsUrlOf('https://vault.example.com')).toBe('wss://vault.example.com/v1/ws');
    expect(wsUrlOf('http://127.0.0.1:8080')).toBe('ws://127.0.0.1:8080/v1/ws');
  });
});
