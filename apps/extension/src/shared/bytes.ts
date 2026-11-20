export const encodeText = (text: string): Uint8Array<ArrayBuffer> => new TextEncoder().encode(text);

export const decodeText = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

export const toBase64 = (bytes: Uint8Array): string => {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
};

export const fromBase64 = (text: string): Uint8Array<ArrayBuffer> => {
  const binary = atob(text);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
};

export const toBase64Url = (bytes: Uint8Array): string =>
  toBase64(bytes).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');

export const fromBase64Url = (text: string): Uint8Array<ArrayBuffer> => {
  const padded = text
    .replaceAll('-', '+')
    .replaceAll('_', '/')
    .padEnd(Math.ceil(text.length / 4) * 4, '=');
  return fromBase64(padded);
};

export const hexToBytes = (hex: string): Uint8Array<ArrayBuffer> | undefined => {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/.test(hex)) return undefined;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
};
