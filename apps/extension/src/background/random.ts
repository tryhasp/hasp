const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

export const randomHex = (byteLength: number): string =>
  hex(crypto.getRandomValues(new Uint8Array(byteLength)));
