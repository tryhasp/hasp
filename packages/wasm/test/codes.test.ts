import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import {
  extensionPairingCode,
  extensionUnlockCode,
  loadWasm,
  registrableDomain,
} from '../src/client.ts';

const wasmBytes = readFileSync(new URL('../generated/hasp_wasm_bg.wasm', import.meta.url));

await loadWasm({ kind: 'bytes', bytes: wasmBytes }, AbortSignal.timeout(10_000));

const device = '0123456789abcdef0123456789abcdef';
const nonceA = 'AAAAAAAAAAAAAAAAAAAAAA';
const nonceB = 'AQEBAQEBAQEBAQEBAQEBAQ';

describe('registrableDomain uses the full public suffix list', () => {
  it.each([
    { host: 'login.bank.com.evil.com.tr', domain: 'evil.com.tr' },
    { host: 'evil.github.io', domain: 'evil.github.io' },
    { host: 'a.b.example.co.kr', domain: 'example.co.kr' },
    { host: 'www.example.com', domain: 'example.com' },
  ])('$host', ({ host, domain }) => {
    expect(registrableDomain(host)).toBe(domain);
  });

  it('has none for a bare suffix', () => {
    expect(registrableDomain('com')).toBeUndefined();
  });
});

describe('extension codes', () => {
  it('derives a three-three code from the device and the nonce', () => {
    const first = extensionUnlockCode(device, nonceA);
    expect(first.ok && first.value).toMatch(/^\d{3} \d{3}$/);
    expect(extensionUnlockCode(device, nonceA)).toEqual(first);
  });

  it('changes with the nonce', () => {
    const codes = new Set(
      [nonceA, nonceB].map((n) => JSON.stringify(extensionUnlockCode(device, n))),
    );
    expect(codes.size).toBe(2);
  });

  it('refuses to derive a pairing code from bytes that are not an enrol request', () => {
    expect(extensionPairingCode(new Uint8Array([1, 2, 3, 4])).ok).toBe(false);
  });
});
