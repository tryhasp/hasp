import { describe, expect, it } from 'vitest';

import {
  decodeText,
  encodeText,
  fromBase64,
  fromBase64Url,
  hexToBytes,
  toBase64,
  toBase64Url,
} from './bytes.ts';

describe('bytes', () => {
  it.each([
    { name: 'empty', bytes: [] },
    { name: 'padding of one', bytes: [255] },
    { name: 'padding of two', bytes: [250, 251] },
    { name: 'all values', bytes: Array.from({ length: 256 }, (_unused, index) => index) },
  ])('round-trips $name through base64 and base64url', ({ bytes }) => {
    const input = Uint8Array.from(bytes);
    expect(fromBase64(toBase64(input))).toEqual(input);
    expect(fromBase64Url(toBase64Url(input))).toEqual(input);
  });

  it('writes base64url without padding or the + and / characters', () => {
    expect(toBase64Url(Uint8Array.from([251, 255, 254]))).toBe('-__-');
    expect(toBase64Url(Uint8Array.from([1]))).toBe('AQ');
  });

  it('round-trips Korean text', () => {
    expect(decodeText(encodeText('마스터 비밀번호'))).toBe('마스터 비밀번호');
  });

  it.each([
    { name: 'valid', hex: '00ff10', bytes: [0, 255, 16] },
    { name: 'odd length', hex: 'abc', bytes: undefined },
    { name: 'not hex', hex: 'zz', bytes: undefined },
    { name: 'upper case', hex: 'AB', bytes: undefined },
  ])('parses $name hex', ({ hex, bytes }) => {
    expect(hexToBytes(hex)).toEqual(bytes === undefined ? undefined : Uint8Array.from(bytes));
  });
});
