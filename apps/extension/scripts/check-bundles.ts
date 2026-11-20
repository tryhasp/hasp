import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { z } from 'zod';

const root = fileURLToPath(new URL('..', import.meta.url));
const outputs = ['chrome-mv3', 'firefox-mv3', 'safari-mv3'];
const contentScriptBudgetBytes = 200_000;
const expectedCsp = "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'";
const allowedPermissions = new Set([
  'storage',
  'alarms',
  'nativeMessaging',
  'activeTab',
  'idle',
  'offscreen',
  'clipboardWrite',
]);

const manifestSchema = z.object({
  content_security_policy: z.object({ extension_pages: z.string() }).optional(),
  permissions: z.array(z.string()).optional(),
  host_permissions: z.array(z.string()).optional(),
});

const problems: string[] = [];

const walk = (dir: string): string[] =>
  readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? walk(path) : [path];
  });

for (const output of outputs) {
  const dir = join(root, '.output', output);
  const manifest = manifestSchema.parse(
    JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8')),
  );
  if (manifest.content_security_policy?.extension_pages !== expectedCsp) {
    problems.push(`${output}: extension page CSP differs from the pinned one`);
  }
  for (const permission of manifest.permissions ?? []) {
    if (!allowedPermissions.has(permission))
      problems.push(`${output}: unexpected permission ${permission}`);
  }
  if (manifest.host_permissions !== undefined) problems.push(`${output}: host_permissions present`);
  for (const file of walk(dir).filter((path) => path.endsWith('.js'))) {
    const text = readFileSync(file, 'utf8');
    const name = file.slice(dir.length + 1);
    if (/\beval\s*\(/.test(text) || /new\s+Function\s*\(/.test(text)) {
      problems.push(`${output}/${name}: eval or new Function`);
    }
    if (name.startsWith('content-scripts/')) {
      if (
        /[\uFDD0-\uFDEF\uFFFE\uFFFF\uFFFD]/u.test(text) ||
        /[\u{1FFFE}\u{1FFFF}\u{10FFFE}\u{10FFFF}]/u.test(text)
      ) {
        problems.push(
          `${output}/${name}: Unicode noncharacter or replacement character (wxt #2720)`,
        );
      }
      if (statSync(file).size > contentScriptBudgetBytes) {
        problems.push(
          `${output}/${name}: over the ${String(contentScriptBudgetBytes)} byte budget`,
        );
      }
    }
  }
}

if (problems.length > 0) {
  process.stderr.write(`${problems.join('\n')}\n`);
  process.exit(1);
}
process.stdout.write('bundles ok\n');
