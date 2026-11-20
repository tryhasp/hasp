import { describe, expect, it } from 'vitest';

import type { Sender } from '../platform/messaging.ts';
import { frameOf, isExtensionPage, pageOf } from './page.ts';

const sender = (overrides: Partial<Sender>): Sender => ({
  kind: 'tab-frame',
  tabId: 7,
  frameId: 0,
  origin: 'https://accounts.example.com',
  url: 'https://accounts.example.com/login?next=1',
  ...overrides,
});

describe('pageOf', () => {
  it('takes origin, tab and frame from the browser sender', () => {
    expect(pageOf(sender({}))).toEqual({
      tabId: 7,
      frameId: 0,
      origin: 'https://accounts.example.com',
      url: 'https://accounts.example.com/login?next=1',
      host: 'accounts.example.com',
    });
  });

  it.each([{ origin: 'null' }, { origin: '' }, { origin: undefined }])(
    'does not fall back to the sender url when the origin is $origin',
    ({ origin }) => {
      expect(pageOf(sender({ origin }))).toBeUndefined();
    },
  );

  it.each([
    { name: 'a page without a tab', change: { tabId: undefined } },
    { name: 'an unknown frame', change: { frameId: undefined } },
    { name: 'an extension page', change: { kind: 'extension-page' as const } },
    { name: 'a file origin', change: { origin: 'file://', url: 'file:///x' } },
    { name: 'no url', change: { url: undefined } },
  ])('refuses $name', ({ change }) => {
    expect(pageOf(sender(change))).toBeUndefined();
  });
});

const extensionFrame = (overrides: Partial<Sender>): Sender =>
  sender({ kind: 'extension-page', url: 'chrome-extension://abc/menu-frame.html', ...overrides });

describe('frameOf', () => {
  it('accepts an extension iframe inside a tab', () => {
    expect(frameOf(extensionFrame({ frameId: 3 }))).toEqual({ tabId: 7, frameId: 3 });
  });

  it.each([
    { name: 'the top frame of an extension page', change: { frameId: 0 } },
    { name: 'a page without a tab', change: { tabId: undefined, frameId: 3 } },
    { name: 'a web page', change: { kind: 'tab-frame' as const, frameId: 3 } },
  ])('refuses $name', ({ change }) => {
    expect(frameOf(extensionFrame(change))).toBeUndefined();
  });
});

describe('isExtensionPage', () => {
  it('is true only for extension pages', () => {
    expect(isExtensionPage(sender({ kind: 'extension-page' }))).toBe(true);
    expect(isExtensionPage(sender({}))).toBe(false);
  });
});
