import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const dir = join(here, '..', 'test-results', 'metrics');

export const writeMetrics = (name: string, project: string, data: unknown): void => {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, `${name}-${project}.json`), `${JSON.stringify(data, null, 2)}\n`);
};
