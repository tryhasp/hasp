import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';
import { type IncomingMessage, type Server, createServer } from 'node:http';

import { z } from 'zod';

import { freePort } from './haspd.ts';

const b64 = (bytes: Buffer): string => bytes.toString('base64url');

const clientDataSchema = z.object({
  type: z.string(),
  challenge: z.string(),
  origin: z.string(),
});

const credentialSchema = z.object({
  id: z.string(),
  response: z.object({
    clientDataJSON: z.string(),
    authenticatorData: z.string(),
    publicKey: z.string().optional(),
    signature: z.string().optional(),
    userHandle: z.string().nullable().optional(),
  }),
});

export type Verified = { credentialId: string; userVerified: boolean };

export type RelyingParty = {
  origin: string;
  registered: Map<string, Buffer>;
  registrations: Verified[];
  assertions: Verified[];
  failures: string[];
  stop: () => void;
};

const page =
  (): string => `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Passkey RP</title></head><body>
<h1>Passkey test relying party</h1>
<button id="register">Register</button>
<button id="login">Sign in</button>
<pre id="result"></pre>
<script>
const enc = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
const dec = (text) => Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
const uv = new URLSearchParams(location.search).get('uv') ?? 'preferred';
const post = async (path, body) => (await fetch(path, { method: 'POST', body: JSON.stringify(body) })).json();
const result = (text) => { document.getElementById('result').textContent = text; };
const pack = (credential) => ({
  id: credential.id,
  response: {
    clientDataJSON: enc(credential.response.clientDataJSON),
    authenticatorData: enc(credential.response.authenticatorData ?? credential.response.getAuthenticatorData()),
    publicKey: credential.response.getPublicKey ? enc(credential.response.getPublicKey()) : undefined,
    signature: credential.response.signature ? enc(credential.response.signature) : undefined,
    userHandle: credential.response.userHandle ? enc(credential.response.userHandle) : null,
  },
});
document.getElementById('register').onclick = async () => {
  try {
    const options = await post('/register/options', {});
    const credential = await navigator.credentials.create({ publicKey: {
      challenge: dec(options.challenge),
      rp: { id: location.hostname, name: 'Passkey test RP' },
      user: { id: dec(options.userId), name: 'alice@rp.test', displayName: 'Alice' },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { userVerification: uv },
      attestation: 'none',
    } });
    const reply = await post('/register/finish', pack(credential));
    result('register:' + JSON.stringify(reply));
  } catch (error) { result('error:' + error.name); }
};
document.getElementById('login').onclick = async () => {
  try {
    const options = await post('/login/options', {});
    const credential = await navigator.credentials.get({ publicKey: {
      challenge: dec(options.challenge),
      rpId: location.hostname,
      userVerification: uv,
      allowCredentials: [],
    } });
    const reply = await post('/login/finish', pack(credential));
    result('login:' + JSON.stringify(reply));
  } catch (error) { result('error:' + error.name); }
};
</script></body></html>`;

const readBody = async (request: IncomingMessage): Promise<string> => {
  request.setEncoding('utf8');
  let body = '';
  for await (const chunk of request) body += String(chunk);
  return body;
};

const COSE_EC2_PREFIX = Buffer.from('a5010203262001215820', 'hex');

const spkiOfCose = (authData: Buffer): Buffer => {
  const at = authData.indexOf(COSE_EC2_PREFIX);
  if (at < 0) throw new Error('no COSE key');
  const x = authData.subarray(at + COSE_EC2_PREFIX.length, at + COSE_EC2_PREFIX.length + 32);
  const y = authData.subarray(at + COSE_EC2_PREFIX.length + 35, at + COSE_EC2_PREFIX.length + 67);
  const header = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');
  return Buffer.concat([header, Buffer.from([0x04]), x, y]);
};

export const startRelyingParty = async (): Promise<RelyingParty> => {
  const port = await freePort();
  const origin = `http://localhost:${port}`;
  const rpIdHash = createHash('sha256').update('localhost').digest();
  const challenges = new Set<string>();
  const registered = new Map<string, Buffer>();
  const registrations: Verified[] = [];
  const assertions: Verified[] = [];
  const failures: string[] = [];

  const checkClientData = (raw: string, type: string): Buffer => {
    const bytes = Buffer.from(raw, 'base64url');
    const data = clientDataSchema.parse(JSON.parse(bytes.toString('utf8')));
    if (data.type !== type) throw new Error('clientData type');
    if (data.origin !== origin) throw new Error(`clientData origin ${data.origin}`);
    if (!challenges.delete(data.challenge)) throw new Error('unknown challenge');
    return bytes;
  };

  const checkAuthData = (authData: Buffer): { flags: number } => {
    if (!authData.subarray(0, 32).equals(rpIdHash)) throw new Error('rpIdHash');
    const flags = authData[32] ?? 0;
    if ((flags & 0x01) === 0) throw new Error('user presence flag');
    return { flags };
  };

  const finishRegistration = (body: unknown): Verified => {
    const credential = credentialSchema.parse(body);
    checkClientData(credential.response.clientDataJSON, 'webauthn.create');
    const authData = Buffer.from(credential.response.authenticatorData, 'base64url');
    const { flags } = checkAuthData(authData);
    if ((flags & 0x40) === 0) throw new Error('attested data flag');
    const spki = spkiOfCose(authData);
    if (credential.response.publicKey !== undefined) {
      if (!Buffer.from(credential.response.publicKey, 'base64url').equals(spki)) {
        throw new Error('getPublicKey differs from the attested key');
      }
    }
    registered.set(credential.id, spki);
    return { credentialId: credential.id, userVerified: (flags & 0x04) !== 0 };
  };

  const finishLogin = (body: unknown): Verified => {
    const credential = credentialSchema.parse(body);
    const clientData = checkClientData(credential.response.clientDataJSON, 'webauthn.get');
    const authData = Buffer.from(credential.response.authenticatorData, 'base64url');
    const { flags } = checkAuthData(authData);
    const spki = registered.get(credential.id);
    if (spki === undefined) throw new Error('unknown credential');
    const signed = Buffer.concat([authData, createHash('sha256').update(clientData).digest()]);
    const key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
    const signature = Buffer.from(credential.response.signature ?? '', 'base64url');
    if (!verify('sha256', signed, key, signature)) throw new Error('bad signature');
    return { credentialId: credential.id, userVerified: (flags & 0x04) !== 0 };
  };

  const server: Server = createServer((request, response) => {
    const url = new URL(request.url ?? '/', origin);
    const respond = async (): Promise<void> => {
      if (request.method !== 'POST') {
        response.setHeader('Content-Type', 'text/html; charset=utf-8');
        response.end(page());
        return;
      }
      response.setHeader('Content-Type', 'application/json');
      const body: unknown = JSON.parse((await readBody(request)) || '{}');
      if (url.pathname === '/register/options' || url.pathname === '/login/options') {
        const challenge = b64(randomBytes(32));
        challenges.add(challenge);
        response.end(JSON.stringify({ challenge, userId: b64(randomBytes(16)) }));
        return;
      }
      try {
        const registration = url.pathname === '/register/finish';
        const verified = registration ? finishRegistration(body) : finishLogin(body);
        (registration ? registrations : assertions).push(verified);
        response.end(JSON.stringify({ ok: true, ...verified }));
      } catch (cause) {
        const message = cause instanceof Error ? cause.message : 'failed';
        failures.push(message);
        response.end(JSON.stringify({ ok: false, message }));
      }
    };
    respond().catch(() => {
      response.statusCode = 500;
      response.end();
    });
  });
  await new Promise<void>((resolve) => {
    server.listen(port, resolve);
  });
  return {
    origin,
    registered,
    registrations,
    assertions,
    failures,
    stop: () => {
      server.close();
    },
  };
};
