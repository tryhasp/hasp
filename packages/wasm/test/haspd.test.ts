import { type ChildProcess, execFileSync, spawn } from 'node:child_process';
import { createPublicKey, verify as verifySignature, createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { HaspClient, loadWasm } from '../src/client.ts';

const binDir =
  process.env['HASP_BIN_DIR'] ?? new URL('../../../target/debug', import.meta.url).pathname;
const wasmBytes = readFileSync(new URL('../generated/hasp_wasm_bg.wasm', import.meta.url));
const password = 'correct horse battery staple';
const encode = (text: string): Uint8Array => new TextEncoder().encode(text);

const freePort = async (): Promise<number> => {
  const port = await new Promise<number>((resolve, reject) => {
    const probe = createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const address = probe.address();
      probe.close(() => {
        resolve(typeof address === 'object' && address ? address.port : 0);
      });
    });
  });
  return port;
};

const sleep = async (ms: number): Promise<void> => {
  await new Promise<void>((resolve) => {
    setTimeout(() => {
      resolve();
    }, ms);
  });
};

let root = '';
let server: ChildProcess | undefined;
let origin = '';
let login = '';
let secretKey = '';
let serverFingerprint = '';

function hasp(args: string[], input: string): string {
  return execFileSync(join(binDir, 'hasp'), ['--data-dir', join(root, 'cli'), '--json', ...args], {
    input,
    encoding: 'utf8',
    stdio: ['pipe', 'pipe', 'ignore'],
  });
}

beforeAll(async () => {
  await loadWasm({ kind: 'bytes', bytes: wasmBytes }, AbortSignal.timeout(10_000));
  root = mkdtempSync(join(tmpdir(), 'hasp-wasm-'));
  const port = await freePort();
  origin = `http://127.0.0.1:${port}`;
  const env = {
    ...process.env,
    HASP_DATA_DIR: join(root, 'data'),
    HASP_PUBLIC_URL: origin,
    HASP_LISTEN: `127.0.0.1:${port}`,
    HASP_LOG: 'warn',
    HASP_LIMIT_LOGIN_PER_PEER: '100000',
    HASP_LIMIT_REGISTER_PER_PEER: '100000',
    HASP_LIMIT_GENERAL_PER_SUBJECT: '10000000',
  };
  const init = execFileSync(join(binDir, 'haspd'), ['init'], { env, encoding: 'utf8' });
  const line = (prefix: string): string => {
    const found = init.split('\n').find((entry) => entry.startsWith(prefix));
    if (found === undefined) {
      throw new Error(`haspd init printed no ${prefix}`);
    }
    return found.slice(prefix.length).trim();
  };
  const code = line('first signup code (makes you the admin): ');
  const fingerprint = line('fingerprint: ');
  serverFingerprint = fingerprint;
  server = spawn(join(binDir, 'haspd'), ['serve'], { env, stdio: 'ignore' });
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const ready = await fetch(`${origin}/healthz`).then(
      (reply) => reply.ok,
      () => false,
    );
    if (ready) {
      break;
    }
    if (attempt === 199) {
      throw new Error('haspd did not become healthy');
    }
    await sleep(50);
  }
  login = 'alice';
  const signup = JSON.parse(
    hasp(
      [
        '--password-stdin',
        '--reveal',
        'signup',
        '--origin',
        origin,
        '--login',
        login,
        '--code-stdin',
        '--server-fingerprint',
        fingerprint,
      ],
      `${code}\n${password}\n`,
    ),
  ) as { data: { secret_key: string } };
  secretKey = signup.data.secret_key;
}, 120_000);

afterAll(() => {
  server?.kill();
  rmSync(root, { recursive: true, force: true });
});

describe('the fetch transport against the real haspd', () => {
  it('maps a refused login to a typed error with nothing stored', async () => {
    using client = new HaspClient(origin, 'chrome', undefined);
    await expect(
      client.signIn({
        origin,
        login,
        secretKey: encode(secretKey),
        password: encode('not the password at all'),
        serverFingerprint,
      }),
    ).rejects.toEqual({ kind: 'auth' });
    expect((await client.status()).state).toBe('empty');
  });

  it('signs in, stores an item, syncs and survives a store round trip', async () => {
    using client = new HaspClient(origin, 'chrome', undefined);
    await client.signIn({
      origin,
      login,
      secretKey: encode(secretKey),
      password: encode(password),
      serverFingerprint,
    });
    const status = await client.status();
    expect(status).toMatchObject({ state: 'unlocked', login, unlockMode: 'password-only' });
    const [vault] = await client.vaults();
    expect(vault?.writable).toBe(true);
    if (vault === undefined) {
      return;
    }
    const draft = client.blankDraft('login');
    for (const section of draft.sections) {
      for (const field of section.fields) {
        if (field.purpose === 'username') {
          field.value = encode('alice@example.com');
        }
        if (field.purpose === 'password') {
          field.value = encode('hunter2-but-longer');
        }
      }
    }
    draft.title = 'Example';
    draft.urls.push({
      id: undefined,
      url: 'https://example.com/login',
      mode: 'domain',
      kind: 'sign-in',
    });
    const created = await client.createItem(vault.id, draft);
    const summary = await client.sync();
    expect(summary.needsAttention).toBe(0);
    const matches = await client.autofillQuery({
      pageUrl: 'https://example.com/login',
      origin: 'https://example.com',
      frame: {
        topFrame: true,
        crossOriginFrame: false,
        sandboxed: false,
        obscured: false,
        visibilityCheckSupported: true,
      },
    });
    expect(matches.candidates).toHaveLength(1);
    expect(matches.candidates[0]).toMatchObject({ tier: 'exact', fill: 'one-click' });
    const payload = await client.fillPayload({
      vault: vault.id,
      item: created.item,
      origin: 'https://example.com',
      pageUrl: 'https://example.com/login',
      kind: 'login',
      frame: {
        topFrame: true,
        crossOriginFrame: false,
        sandboxed: false,
        obscured: false,
        visibilityCheckSupported: true,
      },
      approved: false,
      rememberHost: false,
      inIframeClick: false,
    });
    const filled = payload.values.find((value) => value.purpose === 'password');
    expect(new TextDecoder().decode(filled?.value)).toBe('hunter2-but-longer');
    filled?.value.fill(0);

    const snapshot = client.exportStore();
    expect(client.storeRevision()).toBeGreaterThan(0);
    using restored = new HaspClient(origin, 'chrome', snapshot);
    expect((await restored.status()).state).toBe('locked');
    await restored.unlockPassword(encode(password));
    expect(await restored.items(vault.id)).toHaveLength(1);
  });
});

const frame = {
  topFrame: true,
  crossOriginFrame: false,
  sandboxed: false,
  obscured: false,
  visibilityCheckSupported: true,
};
const base64url = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64url');
const unbase64url = (text: string): Buffer => Buffer.from(text, 'base64url');

describe('the standalone extension session blob and passkeys', () => {
  it('refuses a typed sign-in whose server fingerprint differs, before anything is sent', async () => {
    using client = new HaspClient(origin, 'chrome', undefined);
    await expect(
      client.signIn({
        origin,
        login,
        secretKey: encode(secretKey),
        password: encode(password),
        serverFingerprint: 'AAAA-AAAA-AAAA-AAAA-AAAA-AAAA',
      }),
    ).rejects.toEqual({ kind: 'server-key' });
    expect((await client.status()).state).toBe('empty');
  });

  it('resumes after a worker eviction from a session blob and never stores the password', async () => {
    using client = new HaspClient(origin, 'chrome', undefined);
    await client.signIn({
      origin,
      login,
      secretKey: encode(secretKey),
      password: encode(password),
      serverFingerprint,
    });
    await client.lock();
    const { sessionBlob } = await client.unlockWithPassword(encode(password));
    expect(sessionBlob).toHaveLength(33);
    const snapshot = client.exportStore();
    for (const needle of [Buffer.from(password), Buffer.from(encode(password))]) {
      expect(Buffer.from(snapshot).includes(needle)).toBe(false);
      expect(Buffer.from(sessionBlob).includes(needle)).toBe(false);
    }
    using evicted = new HaspClient(origin, 'chrome', snapshot);
    expect((await evicted.status()).state).toBe('locked');
    await evicted.resumeSession(sessionBlob);
    expect((await evicted.status()).state).toBe('unlocked');
    await evicted.lock();
    const damaged = Uint8Array.from(sessionBlob);
    damaged[5] = (damaged[5] ?? 0) ^ 1;
    await expect(evicted.resumeSession(damaged)).rejects.toMatchObject({ kind: 'auth' });
  });

  it('creates and uses a passkey that Node verifies independently', async () => {
    using client = new HaspClient(origin, 'chrome', undefined);
    await client.signIn({
      origin,
      login,
      secretKey: encode(secretKey),
      password: encode(password),
      serverFingerprint,
    });
    const challenge = base64url(encode('a challenge of enough length'));
    const created = await client.passkeyCreate({
      origin: 'https://login.example.org',
      frame,
      rpId: 'example.org',
      rpName: 'Example',
      challenge,
      userHandle: base64url(encode('user-1')),
      userName: 'alice',
      userDisplayName: 'Alice',
      algorithms: [-7, -257],
      exclude: [],
      userVerification: 'preferred',
      userVerified: true,
      vault: undefined,
      item: undefined,
    });
    expect(created.publicKeyAlgorithm).toBe(-7);
    const key = createPublicKey({
      key: unbase64url(created.publicKey),
      format: 'der',
      type: 'spki',
    });
    expect(key.asymmetricKeyType).toBe('ec');
    const clientData = JSON.parse(unbase64url(created.clientDataJson).toString('utf8')) as {
      type: string;
      origin: string;
      challenge: string;
    };
    expect(clientData).toMatchObject({
      type: 'webauthn.create',
      origin: 'https://login.example.org',
      challenge,
    });

    const assertion = await client.passkeyGet({
      origin: 'https://login.example.org',
      frame,
      rpId: 'example.org',
      challenge,
      allow: [created.credentialId],
      userVerification: 'preferred',
      userVerified: false,
      vault: undefined,
      item: undefined,
      credentialId: undefined,
    });
    const authData = unbase64url(assertion.authenticatorData);
    const signed = Buffer.concat([
      authData,
      createHash('sha256').update(unbase64url(assertion.clientDataJson)).digest(),
    ]);
    expect(verifySignature('sha256', signed, key, unbase64url(assertion.signature))).toBe(true);
    expect(authData.subarray(0, 32)).toEqual(createHash('sha256').update('example.org').digest());
    expect(authData.readUInt32BE(33)).toBe(0);
    expect(authData[32]! & 0x05).toBe(0x01);
    await expect(
      client.passkeyGet({
        origin: 'https://evil.example.com',
        frame,
        rpId: 'example.org',
        challenge,
        allow: [],
        userVerification: 'preferred',
        userVerified: false,
        vault: undefined,
        item: undefined,
        credentialId: undefined,
      }),
    ).rejects.toEqual({ kind: 'refused' });
  });
});
