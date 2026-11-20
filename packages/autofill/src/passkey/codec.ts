export const encodeBase64Url = (data: ArrayBuffer | ArrayBufferView): string => {
  const bytes =
    data instanceof ArrayBuffer
      ? new Uint8Array(data)
      : new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

export const decodeBase64Url = (text: string): ArrayBuffer => {
  const padded = text
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(Math.ceil(text.length / 4) * 4, '=');
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out.buffer;
};

export const isBufferSource = (v: unknown): v is ArrayBuffer | ArrayBufferView =>
  v instanceof ArrayBuffer || ArrayBuffer.isView(v);

type Descriptor = { type: string; id: string; transports?: readonly string[] };

const describeCredentials = (list: unknown): Descriptor[] => {
  if (!Array.isArray(list)) return [];
  const out: Descriptor[] = [];
  for (const item of list as unknown[]) {
    if (typeof item !== 'object' || item === null) continue;
    const id: unknown = Reflect.get(item, 'id');
    const type: unknown = Reflect.get(item, 'type');
    const transports: unknown = Reflect.get(item, 'transports');
    if (!isBufferSource(id) || typeof type !== 'string') continue;
    out.push({
      type,
      id: encodeBase64Url(id),
      ...(Array.isArray(transports)
        ? {
            transports: (transports as unknown[]).filter((t): t is string => typeof t === 'string'),
          }
        : {}),
    });
  }
  return out;
};

const text = (obj: object, key: string): string | undefined => {
  const v: unknown = Reflect.get(obj, key);
  return typeof v === 'string' ? v : undefined;
};

export const serializeGetOptions = (
  pk: object,
  mediation: string | undefined,
): string | undefined => {
  const challenge: unknown = Reflect.get(pk, 'challenge');
  if (!isBufferSource(challenge)) return undefined;
  return JSON.stringify({
    challenge: encodeBase64Url(challenge),
    rpId: text(pk, 'rpId'),
    userVerification: text(pk, 'userVerification'),
    allowCredentials: describeCredentials(Reflect.get(pk, 'allowCredentials')),
    mediation,
  });
};

export const serializeCreateOptions = (pk: object): string | undefined => {
  const challenge: unknown = Reflect.get(pk, 'challenge');
  const rp: unknown = Reflect.get(pk, 'rp');
  const user: unknown = Reflect.get(pk, 'user');
  if (!isBufferSource(challenge) || typeof rp !== 'object' || rp === null) return undefined;
  if (typeof user !== 'object' || user === null) return undefined;
  const userId: unknown = Reflect.get(user, 'id');
  if (!isBufferSource(userId)) return undefined;
  const params: unknown = Reflect.get(pk, 'pubKeyCredParams');
  const algs = Array.isArray(params)
    ? (params as unknown[]).flatMap((p) => {
        if (typeof p !== 'object' || p === null) return [];
        const alg: unknown = Reflect.get(p, 'alg');
        return typeof alg === 'number' ? [alg] : [];
      })
    : [];
  const selection: unknown = Reflect.get(pk, 'authenticatorSelection');
  return JSON.stringify({
    challenge: encodeBase64Url(challenge),
    rp: { id: text(rp, 'id'), name: text(rp, 'name') ?? '' },
    user: {
      id: encodeBase64Url(userId),
      name: text(user, 'name') ?? '',
      displayName: text(user, 'displayName') ?? '',
    },
    algs,
    excludeCredentials: describeCredentials(Reflect.get(pk, 'excludeCredentials')),
    userVerification:
      typeof selection === 'object' && selection !== null
        ? text(selection, 'userVerification')
        : undefined,
  });
};
