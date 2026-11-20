import { type IncomingMessage, type Server, createServer } from 'node:http';

import { freePort } from './haspd.ts';

export type TestSite = {
  origin: string;
  hostname: string;
  signups: { user: string; password: string }[];
  logins: { user: string; password: string }[];
  changes: { current: string; next: string }[];
  stop: () => void;
};

const loginPage = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Sign in</title></head><body>
<h1>Sign in</h1>
<form id="login" method="post" action="/dashboard">
<label>Email <input id="user" name="username" type="text" autocomplete="username"></label>
<label>Password <input id="pass" name="password" type="password" autocomplete="current-password"></label>
<button id="submit" type="submit">Sign in</button>
</form></body></html>`;

const signupPage = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Create account</title></head><body>
<h1>Create account</h1>
<form id="signup" method="post" action="/welcome">
<label>Email <input id="user" name="email" type="email" autocomplete="username"></label>
<label>New password <input id="pass" name="new_password" type="password" autocomplete="new-password"></label>
<label>Confirm password <input id="pass2" name="confirm_password" type="password" autocomplete="new-password"></label>
<button id="submit" type="submit">Create account</button>
</form></body></html>`;

const changePage = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Change password</title></head><body>
<h1>Change password</h1>
<form id="change" method="post" action="/changed">
<label>Email <input id="user" name="username" type="text" autocomplete="username" value="bob@example.com"></label>
<label>Current password <input id="cur" name="current_password" type="password" autocomplete="current-password"></label>
<label>New password <input id="pass" name="new_password" type="password" autocomplete="new-password"></label>
<label>Confirm new password <input id="pass2" name="confirm_password" type="password" autocomplete="new-password"></label>
<button id="submit" type="submit">Change password</button>
</form></body></html>`;

const crossPage = (
  target: string,
): string => `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Sign in</title></head><body>
<h1>Sign in</h1>
<form id="login" method="post" action="${target}/dashboard" onsubmit="event.preventDefault()">
<label>Email <input id="user" name="username" type="text" autocomplete="username"></label>
<label>Password <input id="pass" name="password" type="password" autocomplete="current-password"></label>
<button id="submit" type="submit">Sign in</button>
</form></body></html>`;

const welcomePage = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Welcome</title></head><body><h1 id="welcome">Welcome</h1></body></html>`;

const readBody = async (request: IncomingMessage): Promise<string> => {
  request.setEncoding('utf8');
  let body = '';
  for await (const chunk of request) body += String(chunk);
  return body;
};

export const startSite = async (): Promise<TestSite> => {
  const port = await freePort();
  const signups: { user: string; password: string }[] = [];
  const logins: { user: string; password: string }[] = [];
  const changes: { current: string; next: string }[] = [];
  const server: Server = createServer((request, response) => {
    const url = new URL(request.url ?? '/', 'http://localhost');
    response.setHeader('Content-Type', 'text/html; charset=utf-8');
    const respond = async (): Promise<void> => {
      if (request.method === 'POST') {
        const form = new URLSearchParams(await readBody(request));
        if (url.pathname === '/welcome') {
          signups.push({ user: form.get('email') ?? '', password: form.get('new_password') ?? '' });
        }
        if (url.pathname === '/changed') {
          changes.push({
            current: form.get('current_password') ?? '',
            next: form.get('new_password') ?? '',
          });
        }
        if (url.pathname === '/dashboard') {
          logins.push({ user: form.get('username') ?? '', password: form.get('password') ?? '' });
        }
        response.end(
          url.pathname === '/welcome'
            ? welcomePage
            : url.pathname === '/changed'
              ? '<h1 id="changed">Changed</h1>'
              : '<h1 id="dashboard">Dashboard</h1>',
        );
        return;
      }
      const pages: Record<string, string> = {
        '/signup': signupPage,
        '/welcome': welcomePage,
        '/change': changePage,
        '/cross': crossPage(`http://127.0.0.1:${port}`),
      };
      response.end(pages[url.pathname] ?? loginPage);
    };
    respond().catch(() => {
      response.statusCode = 500;
      response.end();
    });
  });
  await new Promise<void>((resolve) => {
    server.listen(port, resolve);
  });
  return {
    origin: `http://localhost:${port}`,
    hostname: 'localhost',
    signups,
    logins,
    changes,
    stop: () => {
      server.close();
    },
  };
};
