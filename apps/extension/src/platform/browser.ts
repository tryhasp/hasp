import { browser } from 'wxt/browser';

export const api = browser;

export type BrowserFamily = 'chromium' | 'firefox' | 'safari';
export type BrowserName = 'chrome' | 'edge' | 'brave' | 'firefox' | 'safari';

export const targetBrowser = (): BrowserName => {
  const target = import.meta.env['BROWSER'];
  switch (target) {
    case 'firefox':
    case 'safari':
    case 'edge':
      return target;
    default:
      return 'chrome';
  }
};

export const familyOf = (name: BrowserName): BrowserFamily => {
  switch (name) {
    case 'firefox':
      return 'firefox';
    case 'safari':
      return 'safari';
    case 'chrome':
    case 'edge':
    case 'brave':
      return 'chromium';
  }
};
