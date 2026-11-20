// oxlint-disable eslint/no-restricted-globals -- these callbacks run inside the extension worker
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { type BrowserContext, type Page, type Worker, chromium, expect } from '@playwright/test';

const extensionPath = fileURLToPath(new URL('../../.output-e2e/chrome-mv3', import.meta.url));

export type Launched = {
  context: BrowserContext;
  extensionId: string;
  profile: string;
  worker: () => Promise<Worker>;
  popup: () => Promise<Page>;
  evictWorker: () => Promise<void>;
  close: () => Promise<void>;
};

export const sessionSet = async (target: Worker, key: string, value: unknown): Promise<void> => {
  await target.evaluate(
    async ({ name, stored }) => {
      const api: typeof chrome = Reflect.get(globalThis, 'chrome');
      await api.storage.session.set({ [name]: stored });
    },
    { name: key, stored: value },
  );
};

export const localSet = async (target: Worker, key: string, value: unknown): Promise<void> => {
  await target.evaluate(
    async ({ name, stored }) => {
      const api: typeof chrome = Reflect.get(globalThis, 'chrome');
      await api.storage.local.set({ [name]: stored });
    },
    { name: key, stored: value },
  );
};

export const sessionGet = async (worker: Worker, key: string): Promise<unknown> => {
  const value: unknown = await worker.evaluate(async (name) => {
    const api: typeof chrome = Reflect.get(globalThis, 'chrome');
    const stored = await api.storage.session.get(name);
    return stored[name];
  }, key);
  return value;
};

export const storageDump = async (target: Worker): Promise<string> => {
  const dump = await target.evaluate(async () => {
    const api: typeof chrome = Reflect.get(globalThis, 'chrome');
    const [local, session] = await Promise.all([
      api.storage.local.get(null),
      api.storage.session.get(null),
    ]);
    return JSON.stringify({ local, session });
  });
  return dump;
};

export const sessionKeys = async (worker: Worker, prefix: string): Promise<string[]> => {
  const keys = await worker.evaluate(async (start) => {
    const api: typeof chrome = Reflect.get(globalThis, 'chrome');
    return Object.keys(await api.storage.session.get(null)).filter((name) =>
      name.startsWith(start),
    );
  }, prefix);
  return keys;
};

export type LaunchOptions = Pick<
  NonNullable<Parameters<typeof chromium.launchPersistentContext>[1]>,
  'viewport' | 'hasTouch' | 'isMobile' | 'deviceScaleFactor'
> & { isCoarsePointer?: boolean };

// Why: Chromium keeps pointer and hover media queries on the desktop values even with touch emulation, so a touch-only device needs these blink settings.
const COARSE_POINTER_ARG =
  '--blink-settings=primaryPointerType=2,availablePointerTypes=2,primaryHoverType=1,availableHoverTypes=1';

export const launchExtension = async (options: LaunchOptions = {}): Promise<Launched> => {
  const { isCoarsePointer = false, ...launchRest } = options;
  const profile = mkdtempSync(join(tmpdir(), 'hasp-profile-'));
  const context = await chromium.launchPersistentContext(profile, {
    channel: 'chromium',
    headless: true,
    args: [
      `--disable-extensions-except=${extensionPath}`,
      `--load-extension=${extensionPath}`,
      ...(isCoarsePointer ? [COARSE_POINTER_ARG] : []),
      ...(process.env['HASP_E2E_LANG'] === undefined
        ? []
        : [`--lang=${process.env['HASP_E2E_LANG']}`]),
    ],
    viewport: { width: 1100, height: 800 },
    ...launchRest,
  });
  const worker = async (): Promise<Worker> => {
    const [existing] = context.serviceWorkers();
    return existing ?? (await context.waitForEvent('serviceworker'));
  };
  const first = await worker();
  const extensionId = new URL(first.url()).host;
  return {
    context,
    extensionId,
    profile,
    worker,
    popup: async () => {
      const page = await context.newPage();
      await page.goto(`chrome-extension://${extensionId}/popup.html`);
      return page;
    },
    evictWorker: async () => {
      const sentinelAlive = async (): Promise<boolean> => {
        const alive = await Promise.all(
          context.serviceWorkers().map(async (candidate) => {
            try {
              return await candidate.evaluate(
                () => Reflect.get(globalThis, 'hasp-sentinel') === true,
              );
            } catch {
              return false;
            }
          }),
        );
        return alive.includes(true);
      };
      const [before] = context.serviceWorkers();
      await before?.evaluate(() => {
        Reflect.set(globalThis, 'hasp-sentinel', true);
      });
      const page = await context.newPage();
      await page.goto(`chrome-extension://${extensionId}/options.html`);
      const cdp = await context.newCDPSession(page);
      const versions = new Map<string, { scriptURL: string; runningStatus: string }>();
      cdp.on('ServiceWorker.workerVersionUpdated', (event) => {
        for (const version of event.versions) versions.set(version.versionId, version);
      });
      await cdp.send('ServiceWorker.enable');
      await expect
        .poll(
          async () => {
            if (!(await sentinelAlive())) return true;
            for (const [versionId, version] of versions) {
              if (version.scriptURL.includes(extensionId) && version.runningStatus === 'running') {
                await cdp.send('ServiceWorker.stopWorker', { versionId }).catch(() => undefined);
              }
            }
            return false;
          },
          { timeout: 20_000, intervals: [100, 250, 500] },
        )
        .toBe(true);
      await page.close();
    },
    close: async () => {
      await context.close();
      rmSync(profile, { recursive: true, force: true });
    },
  };
};
