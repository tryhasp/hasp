import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { loadWasm, normaliseLogin, normalisePassword } from '../src/client.ts';

type TextCase = {
  readonly name: string;
  readonly scalars: readonly number[];
  readonly utf8?: string;
  readonly err?: string;
};

const wasmBytes = readFileSync(new URL('../generated/hasp_wasm_bg.wasm', import.meta.url));
await loadWasm({ kind: 'bytes', bytes: wasmBytes }, AbortSignal.timeout(10_000));

function load(group: 'password' | 'login'): readonly TextCase[] {
  const file = new URL(`../../../testvectors/text/${group}.json`, import.meta.url);
  const parsed: unknown = JSON.parse(readFileSync(file, 'utf8'));
  return (parsed as { cases: TextCase[] }).cases;
}

const hex = (text: string): string =>
  [...new TextEncoder().encode(text)].map((byte) => byte.toString(16).padStart(2, '0')).join('');

const input = (textCase: TextCase): string => String.fromCodePoint(...textCase.scalars);

const rustPassword = (text: string): { utf8: string } => ({
  utf8: hex(normalisePassword(text)),
});

const rustLogin = (text: string): { utf8: string } | { err: string } => {
  const result = normaliseLogin(text);
  return result.ok ? { utf8: hex(result.value) } : { err: result.error.kind };
};

const expected = (textCase: TextCase): { utf8: string } | { err: string } =>
  textCase.err === undefined ? { utf8: textCase.utf8 ?? '' } : { err: textCase.err.toLowerCase() };

const jsPassword = (text: string): string => text.trim().normalize('NFKD');
const jsLogin = (text: string): string => text.trim().normalize('NFKC').toLowerCase();

describe('text normalisation in Rust through WASM', () => {
  it.each([
    { group: 'password' as const, rule: rustPassword },
    { group: 'login' as const, rule: rustLogin },
  ])('$group matches the vectors', ({ group, rule }) => {
    const mismatches = load(group).filter(
      (c) => JSON.stringify(rule(input(c))) !== JSON.stringify(expected(c)),
    );
    expect(mismatches.map((c) => c.name)).toEqual([]);
  });

  it('rejects unassigned code points in a login id with format', () => {
    expect(load('login').filter((c) => c.err === 'Format').length).toBeGreaterThan(0);
    expect(load('password').filter((c) => c.err !== undefined)).toEqual([]);
  });
});

const DIVERGING: Record<'password' | 'login', readonly string[]> = {
  password: ['trim-next-line', 'trim-bom', 'unicode-18-armenian'],
  login: [
    'trim-next-line',
    'trim-zero-width-space',
    'german-sharp-s',
    'german-capital-sharp-s',
    'german-strasse',
    'greek-final-sigma',
    'greek-small-final-sigma',
    'cherokee',
    'emoji-zwj-family',
    'unicode-18-armenian',
    'zero-width-space-inside',
    'soft-hyphen-inside',
    'greek-iota-subscript',
    'greek-iota-subscript-then-mark',
  ],
};

describe('text normalisation with JavaScript built-ins', () => {
  it.each([
    { group: 'password' as const, rule: jsPassword },
    { group: 'login' as const, rule: jsLogin },
  ])('$group diverges from Rust on the listed cases', ({ group, rule }) => {
    const diverging = load(group)
      .filter((c) => c.utf8 !== undefined && hex(rule(input(c))) !== c.utf8)
      .map((c) => c.name);
    expect(diverging).toEqual(DIVERGING[group]);
  });
});
