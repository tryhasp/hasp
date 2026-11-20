import { StrictMode } from 'react';
import type { ReactNode } from 'react';
import { createRoot } from 'react-dom/client';

import { spawn } from '../platform/spawn.ts';
import { startWasm } from './wasm-ready.ts';

export const mount = (node: ReactNode): void => {
  const dark = window.matchMedia('(prefers-color-scheme: dark)');
  document.documentElement.classList.toggle('dark', dark.matches);
  const container = document.getElementById('root');
  if (container === null) throw new Error('root element missing');
  createRoot(container).render(<StrictMode>{node}</StrictMode>);
  spawn(startWasm());
};
