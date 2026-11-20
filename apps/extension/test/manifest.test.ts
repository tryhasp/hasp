import { describe, expect, it } from 'vitest';

import config from '../wxt.config.ts';

const manifestFor = async (browser: string): Promise<Record<string, unknown>> => {
  const factory = config.manifest;
  if (typeof factory !== 'function') throw new Error('manifest must be a function');
  const result = await factory({ browser } as Parameters<typeof factory>[0]);
  return result;
};

describe('manifest', () => {
  it('pins the extension page CSP', async () => {
    const manifest = await manifestFor('chrome');
    expect(manifest['content_security_policy']).toEqual({
      extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'",
    });
  });

  it('asks for no broad host permission up front', async () => {
    for (const browser of ['chrome', 'firefox', 'safari']) {
      const manifest = await manifestFor(browser);
      expect(manifest['host_permissions']).toBeUndefined();
      expect(manifest['permissions']).not.toContain('tabs');
      expect(manifest['permissions']).not.toContain('webRequest');
      expect(JSON.stringify(manifest)).not.toContain('<all_urls>');
    }
  });

  it.each([
    {
      browser: 'chrome',
      permissions: [
        'storage',
        'alarms',
        'nativeMessaging',
        'activeTab',
        'idle',
        'offscreen',
        'clipboardWrite',
      ],
    },
    {
      browser: 'firefox',
      permissions: ['storage', 'alarms', 'nativeMessaging', 'activeTab', 'idle', 'clipboardWrite'],
    },
    {
      browser: 'safari',
      permissions: ['storage', 'alarms', 'nativeMessaging', 'activeTab', 'clipboardWrite'],
    },
  ])('lists the permissions of $browser', async ({ browser, permissions }) => {
    expect((await manifestFor(browser))['permissions']).toEqual(permissions);
  });

  it('exposes only the menu frame to pages', async () => {
    const manifest = await manifestFor('chrome');
    expect(manifest['web_accessible_resources']).toEqual([
      { resources: ['menu-frame.html'], matches: ['https://*/*', 'http://localhost/*'] },
    ]);
  });
});
