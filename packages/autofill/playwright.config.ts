import { defineConfig, devices } from '@playwright/test';

import { PAGE_ORIGIN } from './e2e/ports.ts';

export default defineConfig({
  testDir: './e2e',
  testMatch: '**/*.spec.ts',
  globalSetup: './e2e/setup.config.ts',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 45_000,
  globalTimeout: 20 * 60_000,
  expect: { timeout: 5_000 },
  reporter: [['list']],
  use: { baseURL: PAGE_ORIGIN, actionTimeout: 10_000, navigationTimeout: 15_000 },
  webServer: {
    command: 'node e2e/server.ts',
    url: `${PAGE_ORIGIN}/redteam/ready.html`,
    reuseExistingServer: false,
    timeout: 30_000,
    ignoreHTTPSErrors: true,
    gracefulShutdown: { signal: 'SIGTERM', timeout: 2000 },
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'], viewport: { width: 1280, height: 800 } },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'], viewport: { width: 1280, height: 800 } },
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'], viewport: { width: 1280, height: 800 } },
    },
    {
      name: 'webkit-iphone',
      use: { ...devices['iPhone 15'] },
      testMatch: ['**/corpus.spec.ts', '**/redteam.spec.ts', '**/touch.spec.ts'],
    },
  ],
});
