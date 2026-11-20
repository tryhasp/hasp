import { defineConfig } from 'wxt';

// Why: the wasm-bindgen glue has a parameter named browser that WXT auto-import rewrites into an unresolvable import
const importOptions = { presets: [], exclude: [/\/generated\//, /\/node_modules\//] };

const isE2e = process.env['HASP_E2E'] === '1';

const extensionPagesCsp = "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'";
const pageMatches = ['https://*/*', 'http://localhost/*'];
const e2eHosts = ['http://127.0.0.1/*', 'http://localhost/*'];

export default defineConfig({
  srcDir: 'src',
  outDir: isE2e ? '.output-e2e' : '.output',
  manifestVersion: 3,
  imports: importOptions,
  webExt: { disabled: true },
  manifest: ({ browser }) => ({
    name: 'Hasp',
    description: 'Self-hosted password manager',
    minimum_chrome_version: '116',
    permissions: [
      'storage',
      'alarms',
      'nativeMessaging',
      'activeTab',
      ...(browser === 'safari' ? [] : ['idle']),
      ...(browser === 'chrome' || browser === 'edge' ? ['offscreen'] : []),
      'clipboardWrite',
    ],
    optional_host_permissions: ['https://*/*', 'http://127.0.0.1/*', 'http://localhost/*'],
    ...(isE2e ? { host_permissions: e2eHosts } : {}),
    content_security_policy: { extension_pages: extensionPagesCsp },
    web_accessible_resources: [{ resources: ['menu-frame.html'], matches: pageMatches }],
    action: { default_title: 'Hasp' },
    commands: {
      'open-menu': {
        suggested_key: { default: 'Ctrl+Shift+L', mac: 'Command+Shift+L' },
        description: 'Open the Hasp menu on the page',
      },
    },
    ...(browser === 'firefox'
      ? {
          browser_specific_settings: {
            gecko: {
              id: 'hasp@hasp.app',
              strict_min_version: '128.0',
              data_collection_permissions: { required: ['none'] },
            },
          },
        }
      : {}),
  }),
  vite: () => ({ build: { target: 'es2024', sourcemap: false } }),
});
