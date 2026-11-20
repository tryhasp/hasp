import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { groups, loadWasm, replay } from '../src/client.ts';

const vectorsRoot = new URL('../../../testvectors/', import.meta.url);
const wasmBytes = readFileSync(new URL('../generated/hasp_wasm_bg.wasm', import.meta.url));

const read = (group: string): string => readFileSync(new URL(`${group}.json`, vectorsRoot), 'utf8');

await loadWasm({ kind: 'bytes', bytes: wasmBytes }, AbortSignal.timeout(10_000));

describe('shared vectors replay through WASM identically to Rust', () => {
  it.each(groups().map((group) => ({ group })))('$group', ({ group }) => {
    const result = replay(group, read(group));
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.value.length).toBeGreaterThan(0);
    const mismatches = result.value.filter((outcome) => outcome.expected !== outcome.actual);
    expect(mismatches).toEqual([]);
  });

  it('reports an unknown group as a typed error', () => {
    expect(replay('crypto/unknown', '{}')).toEqual({ ok: false, error: { kind: 'internal' } });
  });
});
