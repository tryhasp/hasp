import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import type { Server, ServerResponse } from 'node:http';
import { dirname, extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

import { FRAME_PORT, PAGE_PORT } from './ports.ts';

const here = dirname(fileURLToPath(import.meta.url));
const pkg = join(here, '..');

const types: Readonly<Record<string, string>> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json',
};

const roots: Readonly<Record<string, string>> = {
  '/corpus/': join(pkg, 'corpus', 'pages'),
  '/redteam/': join(pkg, 'redteam', 'pages'),
  '/dist/': join(here, 'dist'),
  '/static/': join(here, 'static'),
  '/tokens/': join(pkg, '..', 'design'),
};

const menuShell =
  '<!doctype html><html><head><meta charset="utf-8"><title>menu</title><link rel="stylesheet" href="/tokens/tokens.css"></head><body><script src="/dist/frame.js"></script></body></html>';

const sendFile = async (res: ServerResponse, file: string, type: string): Promise<void> => {
  try {
    const body = await readFile(file);
    res.setHeader('Content-Type', type);
    res.end(body);
  } catch {
    res.statusCode = 404;
    res.end('not found');
  }
};

const serve = (port: number, isFrame: boolean): Server => {
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://x');
    res.setHeader('Cache-Control', 'no-store');
    if (isFrame && url.pathname === '/menu.html') {
      res.setHeader('Content-Type', types['.html'] ?? 'text/html');
      res.end(menuShell);
      return;
    }
    if (!isFrame && url.pathname.startsWith('/corpus/') && url.searchParams.has('n')) {
      const name = (url.searchParams.get('n') ?? '').replace(/[^a-zA-Z0-9_-]/g, '');
      sendFile(
        res,
        join(pkg, 'corpus', 'pages', `${name}.html`),
        types['.html'] ?? 'text/html',
      ).catch(() => undefined);
      return;
    }
    const prefix = Object.keys(roots).find((p) => url.pathname.startsWith(p));
    const base = prefix === undefined ? undefined : roots[prefix];
    if (
      prefix === undefined ||
      base === undefined ||
      (isFrame && prefix !== '/dist/' && prefix !== '/tokens/')
    ) {
      res.statusCode = 404;
      res.end('not found');
      return;
    }
    const file = normalize(join(base, url.pathname.slice(prefix.length)));
    if (!file.startsWith(base)) {
      res.statusCode = 403;
      res.end('forbidden');
      return;
    }
    sendFile(res, file, types[extname(file)] ?? 'application/octet-stream').catch(() => undefined);
  });
  server.listen(port, '0.0.0.0');
  return server;
};

serve(PAGE_PORT, false);
serve(FRAME_PORT, true);
