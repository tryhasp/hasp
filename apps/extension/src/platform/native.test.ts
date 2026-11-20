import { err, ok } from '@hasp/autofill';
import { describe, expect, it } from 'vitest';

import { desktopMessageSchema, errorOfCode, serveDesktopMessages } from './native.ts';
import type { DesktopLink, DesktopMessage, ExtensionMessage, FillOutcome } from './native.ts';

describe('desktopMessageSchema', () => {
  it.each([
    { name: 'enrol reply', message: { type: 'enrol_reply', id: 4, data: 'AQID' } },
    {
      name: 'unlock reply',
      message: { type: 'unlock_reply', id: 5, k_ext: 'A'.repeat(43), valid_until: 1_795_000_000 },
    },
    { name: 'lock', message: { type: 'lock' } },
    { name: 'page query', message: { type: 'page_query', id: 7 } },
    {
      name: 'fill request',
      message: { type: 'fill_request', id: 8, vault: 'a'.repeat(32), item: 'b'.repeat(32) },
    },
    { name: 'error', message: { type: 'error', id: null, code: 'declined' } },
  ])('accepts $name', ({ message }) => {
    expect(desktopMessageSchema.safeParse(message).success).toBe(true);
  });

  it.each([
    { name: 'unknown type', message: { type: 'steal_keys' } },
    { name: 'extra field', message: { type: 'lock', note: 'x' } },
    { name: 'missing key', message: { type: 'unlock_reply', id: 5, valid_until: 1 } },
    {
      name: 'fill request with a url',
      message: {
        type: 'fill_request',
        id: 8,
        vault: 'a'.repeat(32),
        item: 'b'.repeat(32),
        url: 'https://x.example',
      },
    },
    {
      name: 'fill request with a bad id',
      message: { type: 'fill_request', id: 8, vault: 'x', item: 'y' },
    },
    { name: 'unknown error code', message: { type: 'error', id: 1, code: 'boom' } },
  ])('rejects $name', ({ message }) => {
    expect(desktopMessageSchema.safeParse(message).success).toBe(false);
  });
});

describe('errorOfCode', () => {
  it.each([
    { code: 'declined', kind: 'declined' },
    { code: 'revoked', kind: 'revoked' },
    { code: 'locked', kind: 'locked' },
    { code: 'malformed', kind: 'refused' },
    { code: 'refused', kind: 'refused' },
    { code: 'unavailable', kind: 'unavailable' },
  ] as const)('maps $code', ({ code, kind }) => {
    expect(errorOfCode(code)).toEqual({ kind });
  });
});

// oxlint-disable typescript/promise-function-async -- test doubles return resolved promises
const fakeLink = (incoming: DesktopMessage[]): { link: DesktopLink; sent: ExtensionMessage[] } => {
  const queue = [...incoming];
  const sent: ExtensionMessage[] = [];
  const link: DesktopLink = {
    send: (message) => {
      sent.push(message);
      return Promise.resolve(ok(null));
    },
    receive: () => {
      const next = queue.shift();
      return Promise.resolve(next === undefined ? err({ kind: 'unavailable' as const }) : ok(next));
    },
    close: () => undefined,
  };
  return { link, sent };
};

const settled = async (): Promise<void> => {
  await new Promise<void>((resolve) => {
    setTimeout(resolve, 0);
  });
};

const idle = {
  onLock: () => undefined,
  onPageQuery: () => Promise.resolve({ host: null, focused: false }),
  onFillRequest: (): Promise<FillOutcome> => Promise.resolve('unavailable'),
};

describe('serveDesktopMessages', () => {
  const vault = 'a'.repeat(32);
  const item = 'b'.repeat(32);

  it('answers page_query and fill_request with the same id and nothing else', async () => {
    const { link, sent } = fakeLink([
      { type: 'page_query', id: 11 },
      { type: 'fill_request', id: 12, vault, item },
    ]);
    const asked: string[] = [];
    await serveDesktopMessages(
      link,
      {
        ...idle,
        onPageQuery: () => Promise.resolve({ host: 'login.example.com', focused: true }),
        onFillRequest: (v, i): Promise<FillOutcome> => {
          asked.push(`${v}/${i}`);
          return Promise.resolve('needs_confirmation');
        },
      },
      new AbortController().signal,
    );
    await settled();
    expect(asked).toEqual([`${vault}/${item}`]);
    expect(sent).toEqual([
      { type: 'page_reply', id: 11, host: 'login.example.com', focused: true },
      { type: 'fill_reply', id: 12, outcome: 'needs_confirmation' },
    ]);
  });

  it('locks on a lock push and sends no reply', async () => {
    const { link, sent } = fakeLink([{ type: 'lock' }]);
    let locks = 0;
    await serveDesktopMessages(
      link,
      {
        ...idle,
        onLock: () => {
          locks += 1;
        },
      },
      new AbortController().signal,
    );
    expect(locks).toBe(1);
    expect(sent).toEqual([]);
  });

  it('reports whether this profile holds the focused window and nothing else', async () => {
    const { link, sent } = fakeLink([{ type: 'page_query', id: 4 }]);
    await serveDesktopMessages(
      link,
      { ...idle, onPageQuery: () => Promise.resolve({ host: 'a.example.com', focused: false }) },
      new AbortController().signal,
    );
    await settled();
    expect(sent).toEqual([{ type: 'page_reply', id: 4, host: 'a.example.com', focused: false }]);
  });

  it('sends host null when there is no web page', async () => {
    const { link, sent } = fakeLink([{ type: 'page_query', id: 1 }]);
    await serveDesktopMessages(link, idle, new AbortController().signal);
    await settled();
    expect(sent).toEqual([{ type: 'page_reply', id: 1, host: null, focused: false }]);
  });
});
