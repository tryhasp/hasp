import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../..', import.meta.url));

// oxlint-disable-next-line import/no-default-export -- Playwright loads the default export of a global setup file
export default function globalSetup(): void {
  execFileSync('pnpm', ['exec', 'wxt', 'build', '-b', 'chrome'], {
    cwd: root,
    env: { ...process.env, HASP_E2E: '1' },
    stdio: 'inherit',
  });
}
