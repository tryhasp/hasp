import { describe, expect, it } from 'vitest';

import { backgroundRequestSchema } from './combined.ts';
import { settingsPatchSchema, uiReplySchemas, uiRequestSchema } from './ui.ts';

const hex32 = 'a'.repeat(32);

describe('uiRequestSchema', () => {
  it.each([
    { name: 'state', message: { kind: 'ui-state' } },
    { name: 'search', message: { kind: 'ui-search', text: 'github' } },
    { name: 'copy', message: { kind: 'ui-copy', vault: hex32, item: hex32, field: 'otp' } },
    { name: 'lock', message: { kind: 'ui-lock' } },
  ])('accepts $name', ({ message }) => {
    expect(uiRequestSchema.safeParse(message).success).toBe(true);
  });

  it.each([
    { name: 'unknown kind', message: { kind: 'ui-drop-tables' } },
    { name: 'extra key', message: { kind: 'ui-lock', origin: 'https://evil.example' } },
    { name: 'bad id', message: { kind: 'ui-copy', vault: 'x', item: hex32, field: 'password' } },
    { name: 'bad field', message: { kind: 'ui-copy', vault: hex32, item: hex32, field: 'notes' } },
    { name: 'too long search', message: { kind: 'ui-search', text: 'x'.repeat(201) } },
  ])('rejects $name', ({ message }) => {
    expect(uiRequestSchema.safeParse(message).success).toBe(false);
  });

  it('has a reply schema for every request kind', () => {
    for (const option of uiRequestSchema.options) {
      expect(Object.keys(uiReplySchemas)).toContain(option.shape.kind.value);
    }
  });
});

describe('backgroundRequestSchema', () => {
  it('accepts content, frame and ui requests and nothing else', () => {
    expect(backgroundRequestSchema.safeParse({ kind: 'page-config' }).success).toBe(true);
    expect(
      backgroundRequestSchema.safeParse({ kind: 'frame-hello', nonce: 'n'.repeat(32) }).success,
    ).toBe(true);
    expect(backgroundRequestSchema.safeParse({ kind: 'ui-state' }).success).toBe(true);
    expect(backgroundRequestSchema.safeParse({ kind: 'anything-else' }).success).toBe(false);
  });

  it('carries no origin or url field in any content or ui request', () => {
    const text = JSON.stringify(backgroundRequestSchema.def);
    expect(text).not.toContain('"origin"');
  });
});

describe('settingsPatchSchema', () => {
  it.each([
    { name: 'tag word over 12 chars', patch: { secretTag: { word: 'x'.repeat(13), glyph: 0 } } },
    { name: 'tag glyph out of range', patch: { secretTag: { word: 'ok', glyph: 12 } } },
    { name: 'unknown field', patch: { telemetry: true } },
  ])('rejects $name', ({ patch }) => {
    expect(settingsPatchSchema.safeParse(patch).success).toBe(false);
  });

  it('accepts a 12-character word and glyph 11', () => {
    expect(
      settingsPatchSchema.safeParse({ secretTag: { word: 'x'.repeat(12), glyph: 11 } }).success,
    ).toBe(true);
  });
});
