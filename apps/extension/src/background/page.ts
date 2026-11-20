import type { Sender } from '../platform/messaging.ts';

export type PageSender = {
  tabId: number;
  frameId: number;
  origin: string;
  url: string;
  host: string;
};

const originOf = (sender: Sender): string | undefined =>
  sender.origin === undefined || sender.origin === '' || sender.origin === 'null'
    ? undefined
    : sender.origin;

export const pageOf = (sender: Sender): PageSender | undefined => {
  if (sender.kind !== 'tab-frame') return undefined;
  const origin = originOf(sender);
  if (sender.tabId === undefined || sender.frameId === undefined) return undefined;
  if (origin === undefined || sender.url === undefined) return undefined;
  if (!origin.startsWith('http://') && !origin.startsWith('https://')) return undefined;
  return {
    tabId: sender.tabId,
    frameId: sender.frameId,
    origin,
    url: sender.url,
    host: new URL(origin).hostname,
  };
};

export const frameOf = (sender: Sender): { tabId: number; frameId: number } | undefined => {
  if (sender.kind !== 'extension-page') return undefined;
  if (sender.tabId === undefined || sender.frameId === undefined || sender.frameId === 0) {
    return undefined;
  }
  return { tabId: sender.tabId, frameId: sender.frameId };
};

export const isExtensionPage = (sender: Sender): boolean => sender.kind === 'extension-page';
