import { mintGestureToken } from '@hasp/autofill';
import type { FrameContext } from '@hasp/wasm';

import { pushToFrame } from '../platform/messaging.ts';
import type { FillOutcome, PageAnswer } from '../platform/native.ts';
import { sessionStore, writeKey } from '../platform/storage.ts';
import { activeTab, isLastFocusedWindowFocused } from '../platform/tabs.ts';
import { unlockedClient } from './client.ts';
import { requestConfirm } from './confirm.ts';
import { menuKey } from './keys.ts';
import type { MenuSession } from './keys.ts';
import { randomHex } from './random.ts';

const FILL_WAIT_MS = 6000;
const TOP_FRAME: FrameContext = {
  topFrame: true,
  crossOriginFrame: false,
  sandboxed: false,
  obscured: false,
  visibilityCheckSupported: false,
};

type Waiter = (outcome: FillOutcome) => void;

const waiting = new Map<string, Waiter>();

export const isDesktopFill = (nonce: string): boolean => waiting.has(nonce);

export const settleDesktopFill = (nonce: string, kind: string): void => {
  const waiter = waiting.get(nonce);
  if (waiter === undefined) return;
  waiting.delete(nonce);
  waiter(
    kind === 'payload' ? 'filled' : kind === 'browser-ui' ? 'needs_confirmation' : 'unavailable',
  );
};

const siteOf = (url: string | undefined): { origin: string; host: string } | undefined => {
  if (url === undefined) return undefined;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return undefined;
    return { origin: parsed.origin, host: parsed.hostname };
  } catch {
    return undefined;
  }
};

export const activePageHost = async (): Promise<PageAnswer> => {
  const tab = await activeTab();
  const focused = await isLastFocusedWindowFocused();
  return { host: siteOf(tab?.url)?.host ?? null, focused };
};

const awaitFill = async (nonce: string): Promise<FillOutcome> => {
  const outcome = await new Promise<FillOutcome>((resolve) => {
    waiting.set(nonce, resolve);
    setTimeout(() => {
      if (waiting.delete(nonce)) resolve('unavailable');
    }, FILL_WAIT_MS);
  });
  return outcome;
};

export const fillOnActiveTab = async (vault: string, item: string): Promise<FillOutcome> => {
  const tab = await activeTab();
  const site = siteOf(tab?.url);
  if (tab === undefined || tab.url === undefined || site === undefined) return 'no_matching_page';
  const unlocked = await unlockedClient();
  if (!unlocked.ok) return 'locked';
  const client = unlocked.value;
  const pageUrl = tab.url;
  const decision = await client
    .browserFillDecision({ vault, item, origin: site.origin, pageUrl, frame: TOP_FRAME })
    .catch(() => 'unavailable' as const);
  if (decision === 'locked') return 'locked';
  if (decision === 'no-matching-page') return 'no_matching_page';
  if (decision === 'unavailable') return 'unavailable';
  const query = await client
    .autofillQuery({ pageUrl, origin: site.origin, frame: TOP_FRAME })
    .catch(() => undefined);
  const candidate = query?.candidates.find((c) => c.item === item);
  if (candidate === undefined) return 'no_matching_page';
  if (decision === 'confirm-in-browser') {
    await requestConfirm({
      tabId: tab.id,
      frameId: 0,
      vault,
      item,
      title: candidate.title,
      subtitle: candidate.subtitle,
      savedHost: candidate.hostToConfirm ?? site.host,
      currentHost: site.host,
      origin: site.origin,
    });
    return 'needs_confirmation';
  }
  const nonce = randomHex(16);
  const session: MenuSession = {
    nonce,
    tabId: tab.id,
    frameId: 0,
    origin: site.origin,
    url: pageUrl,
    host: site.host,
    mode: 'menu',
    formKind: 'login',
    frame: 'top',
    createdMs: Date.now(),
    candidates: [
      {
        vault,
        item,
        title: candidate.title,
        username: candidate.subtitle,
        tier: candidate.tier,
        hasTotp: candidate.hasTotp,
      },
    ],
    canGenerate: false,
  };
  await writeKey(menuKey(nonce), session);
  const token = await mintGestureToken(
    sessionStore,
    { tabId: tab.id, frameId: 0, nonce, itemId: item },
    Date.now(),
    randomHex(16),
  );
  if (!token.ok) return 'unavailable';
  const pending = awaitFill(nonce);
  const delivered = await pushToFrame(tab.id, 0, {
    kind: 'fill-form',
    nonce,
    itemId: item,
    token: token.value,
  });
  if (!delivered) {
    waiting.delete(nonce);
    return 'no_matching_page';
  }
  const outcome = await pending;
  return outcome;
};
