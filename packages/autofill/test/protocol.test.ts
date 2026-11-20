import { describe, expect, it } from 'vitest';

import { frameKindOf } from '../src/frame-kind.ts';
import { decodeBase64Url, encodeBase64Url } from '../src/passkey/codec.ts';
import { isRpIdSuffixOfHost } from '../src/passkey/rp-id.ts';
import {
  backgroundPushSchema,
  contentRequestSchema,
  frameRequestSchema,
  portToContentSchema,
  replySchemas,
} from '../src/protocol.ts';

const keysOf = (schema: unknown): string[] => {
  const found: string[] = [];
  const walk = (node: unknown): void => {
    if (typeof node !== 'object' || node === null) return;
    const shape: unknown = Reflect.get(node, 'shape');
    if (typeof shape === 'object' && shape !== null) {
      found.push(...Object.keys(shape));
      for (const v of Object.values(shape)) walk(v);
    }
    const options: unknown = Reflect.get(node, 'options');
    if (Array.isArray(options)) for (const o of options as unknown[]) walk(o);
    const element: unknown = Reflect.get(node, 'element');
    walk(element);
  };
  walk(schema);
  return found;
};

describe('message schemas (style: closed unions, no origin or url payloads)', () => {
  it.each([
    ['content requests', contentRequestSchema],
    ['frame requests', frameRequestSchema],
    ['port messages', portToContentSchema],
    ...Object.entries(replySchemas),
  ])('%s declare no origin or url field', (_n, schema) => {
    expect(keysOf(schema).filter((k) => /^(origin|url|frameOrigin|href)$/i.test(k))).toEqual([]);
  });

  it('drops unknown kinds and extra properties', () => {
    expect(contentRequestSchema.safeParse({ kind: 'dump-vault' }).success).toBe(false);
    expect(contentRequestSchema.safeParse({ kind: 'page-config', extra: 1 }).success).toBe(false);
    expect(
      frameRequestSchema.safeParse({ kind: 'frame-hello', origin: 'https://evil.test' }).success,
    ).toBe(false);
  });

  it('rejects a fill request with a short token or a forged check id', () => {
    const good = {
      kind: 'fill-request',
      nonce: 'n'.repeat(24),
      token: 't'.repeat(24),
      itemId: 'item-1',
      formId: 'g1',
      formKind: 'login',
      purposes: ['username', 'password'],
      attestation: { checkedAtMs: 1, passed: ['C1'], isC4Supported: true },
    };
    expect(contentRequestSchema.safeParse(good).success).toBe(true);
    expect(contentRequestSchema.safeParse({ ...good, token: 'x' }).success).toBe(false);
    expect(
      contentRequestSchema.safeParse({
        ...good,
        attestation: { ...good.attestation, passed: ['C99'] },
      }).success,
    ).toBe(false);
  });
});

describe('background push fill-form', () => {
  const push = {
    kind: 'fill-form',
    nonce: 'n'.repeat(24),
    itemId: 'item-1',
    token: 't'.repeat(24),
  };

  it('carries a nonce, an item and a gesture token and no value', () => {
    expect(backgroundPushSchema.safeParse(push).success).toBe(true);
    expect(backgroundPushSchema.safeParse({ ...push, value: 'secret' }).success).toBe(false);
    expect(backgroundPushSchema.safeParse({ ...push, token: 'short' }).success).toBe(false);
  });
});

describe('passkey helpers', () => {
  it.each([
    ['accounts.example.com', 'example.com', true],
    ['example.com', 'example.com', true],
    ['evilexample.com', 'example.com', false],
    ['example.com', 'accounts.example.com', false],
    ['a.example.com', 'com', false],
    ['example.com', 'example.com:443', false],
    ['example.com', '', false],
  ])('rpId %s vs %s -> %s', (host, rp, expected) => {
    expect(isRpIdSuffixOfHost(host, rp)).toBe(expected);
  });

  it('round-trips base64url without padding', () => {
    const bytes = new Uint8Array([251, 255, 254, 1, 2]);
    const text = encodeBase64Url(bytes);
    expect(text).toBe('-__-AQI');
    expect(new Uint8Array(decodeBase64Url(text))).toEqual(bytes);
  });
});

describe('frame policy', () => {
  it.each([
    [{ isTop: true, protocol: 'https:', origin: 'https://a.test', isSameOriginAsTop: true }, 'top'],
    [
      { isTop: false, protocol: 'https:', origin: 'https://a.test', isSameOriginAsTop: true },
      'same-origin',
    ],
    [
      { isTop: false, protocol: 'https:', origin: 'https://b.test', isSameOriginAsTop: false },
      'cross-origin',
    ],
    [{ isTop: false, protocol: 'https:', origin: 'null', isSameOriginAsTop: false }, 'sandboxed'],
    [{ isTop: false, protocol: 'about:', origin: 'null', isSameOriginAsTop: false }, 'blank'],
    [
      { isTop: false, protocol: 'blob:', origin: 'https://a.test', isSameOriginAsTop: true },
      'blob',
    ],
    [{ isTop: true, protocol: 'https:', origin: 'null', isSameOriginAsTop: true }, 'opaque'],
  ] as const)('%j -> %s', (facts, kind) => {
    expect(frameKindOf(facts)).toBe(kind);
  });
});
