import { fileURLToPath } from 'node:url';

import { build } from 'vite';

const root = fileURLToPath(new URL('.', import.meta.url));

const entries = [
  ['page', 'harness/page.ts'],
  ['frame', 'harness/frame.ts'],
  ['hook', 'harness/hook.ts'],
  ['corpus', 'harness/corpus.ts'],
] as const;

export const buildHarness = async (): Promise<void> => {
  for (const [name, file] of entries) {
    await build({
      root,
      configFile: false,
      logLevel: 'warn',
      build: {
        outDir: 'dist',
        emptyOutDir: name === 'page',
        minify: false,
        target: 'es2024',
        lib: { entry: file, formats: ['iife'], name: `hasp_${name}`, fileName: () => `${name}.js` },
      },
    });
  }
};
