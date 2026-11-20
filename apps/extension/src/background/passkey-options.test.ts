import { describe, expect, it } from 'vitest';

import {
  assertionJson,
  createRequestOf,
  frameOfPasskey,
  getRequestOf,
  isPasskeyFrameAllowed,
  isReauthWanted,
  isUvRequired,
  parsePasskeyRequest,
  registrationJson,
} from './passkey-options.ts';

const create = JSON.stringify({
  challenge: 'Y2hhbGxlbmdl',
  rp: { id: 'example.com', name: 'Example' },
  user: { id: 'dXNlcg', name: 'alice', displayName: 'Alice' },
  algs: [-7, -257],
  excludeCredentials: [{ id: 'ZXhj' }],
  userVerification: 'required',
});

const get = JSON.stringify({
  challenge: 'Y2hhbGxlbmdl',
  rpId: 'example.com',
  allowCredentials: [{ type: 'public-key', id: 'Y3JlZA', transports: ['internal'] }],
  mediation: 'optional',
});

describe('parsePasskeyRequest', () => {
  it('parses a create request', () => {
    const parsed = parsePasskeyRequest('create', create);
    expect(parsed?.op).toBe('create');
    expect(parsed?.options).toMatchObject({ rp: { id: 'example.com' }, algs: [-7, -257] });
  });

  it('parses a get request and keeps allowed credential ids only', () => {
    const parsed = parsePasskeyRequest('get', get);
    expect(parsed?.op === 'get' && parsed.options.allowCredentials).toEqual([{ id: 'Y3JlZA' }]);
  });

  it.each([
    { name: 'not json', op: 'get' as const, raw: '{' },
    { name: 'no challenge', op: 'get' as const, raw: '{"rpId":"example.com"}' },
    {
      name: 'create without a user',
      op: 'create' as const,
      raw: '{"challenge":"a","rp":{"name":"x"}}',
    },
    {
      name: 'bad verification',
      op: 'get' as const,
      raw: '{"challenge":"a","userVerification":"always"}',
    },
  ])('rejects $name', ({ op, raw }) => {
    expect(parsePasskeyRequest(op, raw)).toBeUndefined();
  });
});

describe('requests to the engine', () => {
  it('takes the origin from the caller and only the RP id from the page', () => {
    const parsed = parsePasskeyRequest('create', create);
    if (parsed?.op !== 'create') throw new Error('create expected');
    const request = createRequestOf(
      parsed.options,
      'https://login.example.com',
      { frame: 'top' },
      false,
    );
    expect(request).toMatchObject({
      origin: 'https://login.example.com',
      rpId: 'example.com',
      exclude: ['ZXhj'],
      userVerification: 'required',
      userVerified: false,
      frame: { topFrame: true, crossOriginFrame: false, sandboxed: false },
    });
  });

  it('marks a sub-frame as cross-origin so the engine refuses it', () => {
    const parsed = parsePasskeyRequest('get', get);
    if (parsed?.op !== 'get') throw new Error('get expected');
    const request = getRequestOf(
      parsed.options,
      'https://login.example.com',
      { frame: 'cross-origin' },
      true,
      { vault: 'v', item: 'i', credentialId: 'c' },
    );
    expect(request.frame.crossOriginFrame).toBe(true);
    expect(request).toMatchObject({ userVerification: 'preferred', credentialId: 'c' });
  });

  it.each(['sandboxed', 'opaque', 'blank', 'blob'])(
    'reports a %s document as sandboxed and not allowed',
    (frame) => {
      expect(frameOfPasskey({ frame }).sandboxed).toBe(true);
      expect(isPasskeyFrameAllowed(frame)).toBe(false);
    },
  );

  it('does not mark a same-origin sub-frame as sandboxed or cross-origin', () => {
    expect(frameOfPasskey({ frame: 'same-origin' })).toMatchObject({
      topFrame: false,
      crossOriginFrame: false,
      sandboxed: false,
    });
  });

  it.each([
    { uv: 'required', hasReauth: false, wanted: true },
    { uv: 'required', hasReauth: true, wanted: true },
    { uv: 'preferred', hasReauth: true, wanted: true },
    { uv: undefined, hasReauth: true, wanted: true },
    { uv: 'preferred', hasReauth: false, wanted: false },
    { uv: 'discouraged', hasReauth: true, wanted: false },
  ])('wants re-authentication for uv=$uv with reauth=$hasReauth: $wanted', (c) => {
    expect(isReauthWanted({ userVerification: c.uv }, c.hasReauth)).toBe(c.wanted);
  });

  it('knows when verification is required', () => {
    expect(isUvRequired({ userVerification: 'required' })).toBe(true);
    expect(isUvRequired({ userVerification: 'preferred' })).toBe(false);
    expect(isUvRequired({})).toBe(false);
  });
});

describe('credential json', () => {
  it('builds the registration shape the hook turns into a PublicKeyCredential', () => {
    const json: unknown = JSON.parse(
      registrationJson({
        vault: 'v',
        item: 'i',
        rpId: 'example.com',
        credentialId: 'cred',
        clientDataJson: 'cd',
        attestationObject: 'ao',
        authenticatorData: 'ad',
        publicKey: 'pk',
        publicKeyAlgorithm: -7,
      }),
    );
    expect(json).toEqual({
      id: 'cred',
      rawId: 'cred',
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response: {
        clientDataJSON: 'cd',
        attestationObject: 'ao',
        authenticatorData: 'ad',
        transports: ['internal', 'hybrid'],
        publicKeyAlgorithm: -7,
        publicKey: 'pk',
      },
    });
  });

  it('builds the assertion shape without the private key or item ids', () => {
    const text = assertionJson({
      vault: 'v',
      item: 'i',
      rpId: 'example.com',
      credentialId: 'cred',
      clientDataJson: 'cd',
      authenticatorData: 'ad',
      signature: 'sig',
      userHandle: 'uh',
    });
    expect(JSON.parse(text)).toMatchObject({ response: { signature: 'sig', userHandle: 'uh' } });
    expect(text).not.toContain('"vault"');
    expect(text).not.toContain('"item"');
  });
});
