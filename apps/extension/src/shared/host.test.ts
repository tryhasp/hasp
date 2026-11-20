import { readFileSync } from 'node:fs';

import { loadWasm } from '@hasp/wasm';
import { describe, expect, it } from 'vitest';

import { hostOfUrl, splitHost } from './host.ts';

await loadWasm(
  {
    kind: 'bytes',
    bytes: readFileSync(
      new URL('../../../../packages/wasm/generated/hasp_wasm_bg.wasm', import.meta.url),
    ),
  },
  AbortSignal.timeout(10_000),
);

describe('splitHost', () => {
  it.each([
    { host: 'nid.naver.com', subdomain: 'nid', registrable: 'naver.com' },
    { host: 'naver.com', subdomain: '', registrable: 'naver.com' },
    { host: 'a.b.example.co.kr', subdomain: 'a.b', registrable: 'example.co.kr' },
    { host: 'example.co.kr', subdomain: '', registrable: 'example.co.kr' },
    { host: 'localhost', subdomain: '', registrable: 'localhost' },
    { host: '127.0.0.1', subdomain: '', registrable: '127.0.0.1' },
    { host: 'www.example.com', subdomain: 'www', registrable: 'example.com' },
  ])('splits $host', ({ host, subdomain, registrable }) => {
    expect(splitHost(host)).toEqual({ subdomain, registrable });
  });

  it.each([
    { host: 'login.bank.com.evil.com.tr', subdomain: 'login.bank.com', registrable: 'evil.com.tr' },
    { host: 'evil.github.io', subdomain: '', registrable: 'evil.github.io' },
    { host: 'login.evil.github.io', subdomain: 'login', registrable: 'evil.github.io' },
    { host: 'shop.x.com.tr', subdomain: 'shop', registrable: 'x.com.tr' },
  ])('uses the full public suffix list for $host', ({ host, subdomain, registrable }) => {
    expect(splitHost(host)).toEqual({ subdomain, registrable });
  });
});

describe('hostOfUrl', () => {
  it('returns the hostname and drops query and path', () => {
    expect(hostOfUrl('https://a.example.com:8443/path?q=1')).toBe('a.example.com');
  });

  it('returns undefined for a value that is not a URL', () => {
    expect(hostOfUrl('not a url')).toBeUndefined();
  });
});
