import { type ChildProcess, execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { z } from 'zod';

const signupSchema = z.object({ data: z.object({ secret_key: z.string() }) });

export type TestServer = {
  origin: string;
  fingerprint: string;
  login: string;
  secretKey: string;
  password: string;
  cli: (args: string[], input: string) => string;
  stop: () => void;
};

const binDir =
  process.env['HASP_E2E_BIN_DIR'] ??
  process.env['HASP_BIN_DIR'] ??
  new URL('../../../../target/debug', import.meta.url).pathname;

export const freePort = async (): Promise<number> => {
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
    setTimeout(resolve, ms);
  });
};

export const startHaspd = async (): Promise<TestServer> => {
  const root = mkdtempSync(join(tmpdir(), 'hasp-ext-'));
  const port = await freePort();
  const origin = `http://127.0.0.1:${port}`;
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
    if (found === undefined) throw new Error(`haspd init printed no ${prefix}`);
    return found.slice(prefix.length).trim();
  };
  const code = line('first signup code (makes you the admin): ');
  const fingerprint = line('fingerprint: ');
  const server: ChildProcess = spawn(join(binDir, 'haspd'), ['serve'], { env, stdio: 'ignore' });
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const ready = await fetch(`${origin}/healthz`).then(
      (reply) => reply.ok,
      () => false,
    );
    if (ready) break;
    if (attempt === 199) throw new Error('haspd did not become healthy');
    await sleep(50);
  }
  const password = 'correct horse battery staple';
  const login = 'alice';
  const cli = (args: string[], input: string): string =>
    execFileSync(join(binDir, 'hasp'), ['--data-dir', join(root, 'cli'), '--json', ...args], {
      input,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'ignore'],
    });
  const signup = signupSchema.parse(
    JSON.parse(
      cli(
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
    ),
  );
  return {
    origin,
    fingerprint,
    login,
    secretKey: signup.data.secret_key,
    password,
    cli: (args, input) => cli(['--password-stdin', ...args], `${password}\n${input}`),
    stop: () => {
      server.kill();
      rmSync(root, { recursive: true, force: true });
    },
  };
};
