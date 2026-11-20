import { type ChildProcess, spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { type Socket, connect } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { firefox } from '@playwright/test';
import { z } from 'zod';

import { freePort } from './haspd.ts';

const EXTENSION_UUID = '5a4f7c1e-0b2d-4c3a-9e11-7d0a1f2b3c4d';
const EXTENSION_ID = 'hasp@hasp.app';

const replySchema = z.tuple([z.literal(1), z.number(), z.unknown(), z.unknown()]);
const errorSchema = z.object({ error: z.string(), message: z.string() });
const handleSchema = z.string();
const valueSchema = z.object({ value: z.unknown() }).catch({ value: undefined });
const unwrap = (out: unknown): unknown => {
  const parsed = valueSchema.parse(out);
  return parsed.value ?? out;
};
const elementSchema = z.record(z.string(), z.string());

type Pending = { resolve: (value: unknown) => void; reject: (cause: Error) => void };

export type FirefoxSession = {
  extensionOrigin: string;
  command: (name: string, parameters?: object) => Promise<unknown>;
  open: (url: string) => Promise<string>;
  switchTo: (handle: string) => Promise<void>;
  closeCurrent: () => Promise<void>;
  find: (selector: string) => Promise<string>;
  waitFor: (selector: string, timeoutMs?: number) => Promise<string>;
  click: (selector: string) => Promise<void>;
  type: (selector: string, text: string) => Promise<void>;
  text: (selector: string) => Promise<string>;
  value: (selector: string) => Promise<string>;
  exists: (selector: string) => Promise<boolean>;
  frameInShadow: (host: string) => Promise<object>;
  sleep: (ms: number) => Promise<void>;
  close: () => Promise<void>;
};

const sleep = async (ms: number): Promise<void> => {
  await new Promise<void>((resolve) => {
    setTimeout(resolve, ms);
  });
};

const frame = (message: object): string => {
  const body = JSON.stringify(message);
  return `${String(Buffer.byteLength(body))}:${body}`;
};

class Wire {
  private readonly socket: Socket;
  private buffer = '';
  private nextId = 1;
  private readonly pending = new Map<number, Pending>();
  private onGreeting: (() => void) | undefined;

  public constructor(socket: Socket) {
    this.socket = socket;
    socket.setEncoding('utf8');
    socket.on('data', (chunk: string) => {
      this.buffer += chunk;
      this.drain();
    });
  }

  public static async dial(port: number): Promise<Wire> {
    for (let attempt = 0; attempt < 100; attempt += 1) {
      const socket = await new Promise<Socket | undefined>((resolve) => {
        const candidate = connect(port, '127.0.0.1');
        candidate.once('connect', () => {
          resolve(candidate);
        });
        candidate.once('error', () => {
          resolve(undefined);
        });
      });
      if (socket !== undefined) {
        const wire = new Wire(socket);
        await new Promise<void>((resolve) => {
          wire.onGreeting = resolve;
        });
        return wire;
      }
      await sleep(200);
    }
    throw new Error('Marionette did not accept connections');
  }

  private drain(): void {
    for (;;) {
      const colon = this.buffer.indexOf(':');
      if (colon < 0) return;
      const length = Number(this.buffer.slice(0, colon));
      const start = colon + 1;
      if (Buffer.byteLength(this.buffer.slice(start)) < length) return;
      const body = Buffer.from(this.buffer.slice(start)).subarray(0, length).toString('utf8');
      this.buffer = Buffer.from(this.buffer.slice(start)).subarray(length).toString('utf8');
      const parsed: unknown = JSON.parse(body);
      if (!Array.isArray(parsed)) {
        this.onGreeting?.();
        continue;
      }
      const reply = replySchema.parse(parsed);
      const waiter = this.pending.get(reply[1]);
      this.pending.delete(reply[1]);
      const failure = errorSchema.safeParse(reply[2]);
      if (failure.success)
        waiter?.reject(new Error(`${failure.data.error}: ${failure.data.message}`));
      else waiter?.resolve(reply[3]);
    }
  }

  public async send(command: string, parameters: object): Promise<unknown> {
    const id = this.nextId;
    this.nextId += 1;
    const answer = new Promise<unknown>((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
    });
    this.socket.write(frame([0, id, command, parameters]));
    const reply = await answer;
    return reply;
  }

  public end(): void {
    this.socket.destroy();
  }
}

export const firefoxPath = (): string => firefox.executablePath();

export const launchFirefox = async (extensionDir: string): Promise<FirefoxSession> => {
  const profile = mkdtempSync(join(tmpdir(), 'hasp-ff-profile-'));
  const port = await freePort();
  writeFileSync(
    join(profile, 'user.js'),
    [
      `user_pref("marionette.port", ${String(port)});`,
      'user_pref("xpinstall.signatures.required", false);',
      'user_pref("extensions.autoDisableScopes", 0);',
      'user_pref("extensions.manifestV3.enabled", true);',
      `user_pref("extensions.webextensions.uuids", ${JSON.stringify(JSON.stringify({ [EXTENSION_ID]: EXTENSION_UUID }))});`,
      'user_pref("browser.shell.checkDefaultBrowser", false);',
      'user_pref("datareporting.policy.dataSubmissionEnabled", false);',
      'user_pref("network.proxy.type", 0);',
    ].join('\n'),
  );
  const child: ChildProcess = spawn(
    firefoxPath(),
    ['--marionette', '--headless', '--no-remote', '-profile', profile],
    { stdio: 'ignore', env: { ...process.env, MOZ_REMOTE_ALLOW_SYSTEM_ACCESS: '1' } },
  );
  const wire = await Wire.dial(port);
  await wire.send('WebDriver:NewSession', {});
  await wire.send('Addon:Install', { path: extensionDir, temporary: true });
  await wire.send('Marionette:SetContext', { value: 'chrome' });
  // Why: permissions.request needs a browser prompt; this grants the host access the user would give
  await wire.send('WebDriver:ExecuteScript', {
    script: `const { ExtensionPermissions } = ChromeUtils.importESModule('resource://gre/modules/ExtensionPermissions.sys.mjs');
      const policy = WebExtensionPolicy.getByID(arguments[0]);
      return ExtensionPermissions.add(arguments[0], { permissions: [], origins: arguments[1] }, policy.extension).then(() => policy.allowedOrigins.patterns.map((p) => p.pattern));`,
    args: [EXTENSION_ID, ['http://127.0.0.1/*', 'http://localhost/*']],
  });
  await wire.send('Marionette:SetContext', { value: 'content' });
  const extensionOrigin = `moz-extension://${EXTENSION_UUID}`;

  const command = async (name: string, parameters: object = {}): Promise<unknown> => {
    const out = await wire.send(name, parameters);
    return out;
  };

  const find = async (selector: string): Promise<string> => {
    const found = await command('WebDriver:FindElement', {
      using: 'css selector',
      value: selector,
    });
    const id = Object.values(elementSchema.parse(unwrap(found)))[0];
    if (id === undefined) throw new Error(`no element ${selector}`);
    return id;
  };
  const waitFor = async (selector: string, timeoutMs = 30_000): Promise<string> => {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      try {
        const found = await find(selector);
        return found;
      } catch (cause) {
        if (Date.now() > deadline) throw cause;
        await sleep(150);
      }
    }
  };
  const script = async (body: string, args: unknown[] = []): Promise<unknown> => {
    const out = await command('WebDriver:ExecuteScript', { script: body, args });
    return valueSchema.parse(out).value;
  };

  const session: FirefoxSession = {
    extensionOrigin,
    command,
    open: async (url) => {
      const before = z.array(handleSchema).parse(await command('WebDriver:GetWindowHandles'));
      if (url.startsWith('moz-extension:')) {
        await command('Marionette:SetContext', { value: 'chrome' });
        await command('WebDriver:ExecuteScript', {
          script:
            'const tab = gBrowser.addTab(arguments[0], { triggeringPrincipal: Services.scriptSecurityManager.getSystemPrincipal() }); gBrowser.selectedTab = tab;',
          args: [url],
        });
        await command('Marionette:SetContext', { value: 'content' });
        await sleep(500);
      } else {
        await command('WebDriver:NewWindow', { type: 'tab' });
      }
      const after = z.array(handleSchema).parse(await command('WebDriver:GetWindowHandles'));
      const handle = after.find((candidate) => !before.includes(candidate));
      if (handle === undefined) throw new Error('no new tab');
      await command('WebDriver:SwitchToWindow', { handle });
      if (!url.startsWith('moz-extension:')) await command('WebDriver:Navigate', { url });
      return handle;
    },
    switchTo: async (handle) => {
      await command('WebDriver:SwitchToWindow', { handle });
    },
    closeCurrent: async () => {
      await command('WebDriver:CloseWindow');
      const handles = z.array(handleSchema).parse(await command('WebDriver:GetWindowHandles'));
      const [first] = handles;
      if (first !== undefined) await command('WebDriver:SwitchToWindow', { handle: first });
    },
    find,
    waitFor,
    click: async (selector) => {
      const id = await waitFor(selector);
      await command('WebDriver:ElementClick', { id });
    },
    type: async (selector, text) => {
      const id = await waitFor(selector);
      await command('WebDriver:ElementClear', { id });
      await command('WebDriver:ElementSendKeys', { id, text });
    },
    text: async (selector) => {
      const id = await waitFor(selector);
      const out = await command('WebDriver:GetElementText', { id });
      return String(unwrap(out));
    },
    value: async (selector) => {
      const id = await waitFor(selector);
      const out = await script('return arguments[0].value', [
        { 'element-6066-11e4-a52e-4f735466cecf': id },
      ]);
      return String(out);
    },
    exists: async (selector) => {
      try {
        await find(selector);
        return true;
      } catch {
        return false;
      }
    },
    frameInShadow: async (host) => {
      const shadow = await command('WebDriver:GetShadowRoot', { id: host });
      const shadowId = Object.values(elementSchema.parse(unwrap(shadow)))[0];
      const found = await command('WebDriver:FindElementFromShadowRoot', {
        shadowRoot: shadowId,
        using: 'css selector',
        value: 'iframe',
      });
      const id = Object.values(elementSchema.parse(unwrap(found)))[0];
      return { 'element-6066-11e4-a52e-4f735466cecf': id };
    },
    sleep,
    close: async () => {
      try {
        await wire.send('Marionette:Quit', {});
      } catch {
        child.kill();
      }
      wire.end();
      child.kill();
      rmSync(profile, { recursive: true, force: true });
    },
  };
  return session;
};
