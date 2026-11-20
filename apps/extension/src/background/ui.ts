import { listGenerated } from '@hasp/autofill';
import type { HaspClient, ItemRow } from '@hasp/wasm';

import type { ItemView, UiKind, UiRequest } from '../messages/ui.ts';
import { copyText } from '../platform/clipboard.ts';
import type { Envelope, Sender } from '../platform/messaging.ts';
import { denied, errReply, okReply, pushToFrame } from '../platform/messaging.ts';
import { readKey, removeKey, sessionStore } from '../platform/storage.ts';
import { activeTab } from '../platform/tabs.ts';
import { decodeText } from '../shared/bytes.ts';
import {
  appState,
  fetchServerFingerprint,
  lockNow,
  pairWithDesktop,
  readSettings,
  signIn,
  signOut,
  touchActivity,
  unlockWithDesktop,
  unlockWithPassword,
  writeSettings,
} from './account.ts';
import { grantApproval } from './autofill.ts';
import type { CallError } from './client.ts';
import { withUnlocked } from './client.ts';
import { codeView } from './code-window.ts';
import { confirmKey } from './keys.ts';
import { isExtensionPage } from './page.ts';
import { passkeyAnswer, passkeyView } from './passkey.ts';
import { runSync } from './sync.ts';

const RECENT_LIMIT = 8;
const SEARCH_LIMIT = 30;

export type UiDeps = { afterUnlock: () => Promise<void> };

const viewOf = (row: ItemRow): ItemView => ({
  vault: row.vault,
  id: row.id,
  title: row.title,
  subtitle: row.subtitle,
  hasTotp: row.hasTotp,
});

const lockedOr = (error: CallError): Envelope<never> =>
  error.kind === 'locked' || error.kind === 'no-account'
    ? errReply({ kind: 'locked' })
    : denied(error.kind);

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

const search = async (text: string): Promise<Envelope<unknown>> => {
  const tab = await activeTab();
  const result = await withUnlocked(async (client) => {
    const rows = await client.search({
      text,
      vault: undefined,
      kind: undefined,
      tag: undefined,
      favouritesOnly: false,
      status: 'active',
      boostUrl: tab?.url,
      limit: SEARCH_LIMIT,
    });
    return text.trim() === ''
      ? rows.toSorted((a, b) => b.modified - a.modified).slice(0, RECENT_LIMIT)
      : rows;
  });
  return result.ok ? okReply(result.value.map(viewOf)) : lockedOr(result.error);
};

const currentSite = async (): Promise<Envelope<unknown>> => {
  const tab = await activeTab();
  const site = siteOf(tab?.url);
  if (site === undefined || tab?.url === undefined) {
    return okReply({ isRefused: true, items: [] });
  }
  const url = tab.url;
  const result = await withUnlocked(async (client) => {
    const value = await client.autofillQuery({
      pageUrl: url,
      origin: site.origin,
      frame: {
        topFrame: true,
        crossOriginFrame: false,
        sandboxed: false,
        obscured: false,
        visibilityCheckSupported: false,
      },
    });
    return value;
  });
  if (!result.ok) return lockedOr(result.error);
  return okReply({
    host: site.host,
    isRefused: result.value.refusal !== undefined,
    items: result.value.candidates.map((c): ItemView => ({
      vault: c.vault,
      id: c.item,
      title: c.title,
      subtitle: c.subtitle,
      hasTotp: c.hasTotp,
      tier: c.tier,
    })),
  });
};

const secretOf = async (
  client: HaspClient,
  vault: string,
  item: string,
  field: 'username' | 'password' | 'otp',
): Promise<string | undefined> => {
  if (field === 'otp') {
    const code = await client.totp(vault, item, undefined);
    const text = decodeText(code.code);
    code.code.fill(0);
    return text;
  }
  const detail = await client.itemDetail(vault, item);
  const found = detail.sections
    .flatMap((section) => section.fields)
    .find((f) => f.purpose === field);
  if (found === undefined) return undefined;
  if (!found.concealed) return found.value;
  const bytes = await client.revealField(vault, item, found.id);
  const text = decodeText(bytes);
  bytes.fill(0);
  return text;
};

const copy = async (
  message: Extract<UiRequest, { kind: 'ui-copy' }>,
): Promise<Envelope<unknown>> => {
  await touchActivity();
  const result = await withUnlocked(async (client) => {
    const text = await secretOf(client, message.vault, message.item, message.field);
    const settings = await client.settings();
    return { text, seconds: settings.lock.clipboardClearSeconds };
  });
  if (!result.ok) return lockedOr(result.error);
  if (result.value.text === undefined) return denied('not-found');
  await copyText(result.value.text, result.value.seconds);
  return okReply({ clearAfterSeconds: result.value.seconds });
};

const copyGenerated = async (
  message: Extract<UiRequest, { kind: 'ui-copy-generated' }>,
): Promise<Envelope<unknown>> => {
  const entries = await listGenerated(sessionStore, Date.now());
  const entry = entries.find((e) => e.id === message.id);
  if (entry === undefined) return denied('not-found');
  const settings = await withUnlocked(async (client) => {
    const value = await client.settings();
    return value;
  });
  const seconds = settings.ok ? settings.value.lock.clipboardClearSeconds : 30;
  await copyText(entry.value, seconds);
  return okReply({ clearAfterSeconds: seconds });
};

const originOfUrl = (url: string | undefined): string | undefined => {
  try {
    return url === undefined ? undefined : new URL(url).origin;
  } catch {
    return undefined;
  }
};

const fill = async (
  message: Extract<UiRequest, { kind: 'ui-fill' }>,
): Promise<Envelope<unknown>> => {
  const tab = await activeTab();
  if (tab === undefined) return okReply({ kind: 'no-page' });
  await touchActivity();
  const origin = originOfUrl(tab.url);
  if (origin === undefined) return okReply({ kind: 'no-page' });
  await grantApproval(tab.id, 0, message.item, origin);
  const delivered = await pushToFrame(tab.id, 0, { kind: 'open-menu' });
  return okReply({ kind: delivered ? 'menu' : 'no-page' });
};

const generatedList = async (): Promise<Envelope<unknown>> => {
  const entries = await listGenerated(sessionStore, Date.now());
  return okReply(
    entries
      .filter((e) => e.isVerified)
      .map((e) => ({ id: e.id, site: e.site, atMs: e.atMs, isSaved: e.isSaved }))
      .toReversed(),
  );
};

const confirmGet = async (id: string): Promise<Envelope<unknown>> => {
  const stored = await readKey(confirmKey(id));
  const request = stored.ok ? stored.value : undefined;
  if (request === undefined || request.expiresMs < Date.now()) return denied('expired');
  const settings = await withUnlocked(async (client) => {
    const value = await client.settings();
    return value;
  });
  if (!settings.ok) return lockedOr(settings.error);
  return okReply({
    title: request.title,
    subtitle: request.subtitle,
    savedHost: request.savedHost,
    currentHost: request.currentHost,
    isSameHost: request.savedHost === request.currentHost,
    locale: settings.value.language === 'en' ? 'en' : 'ko',
    ...(settings.value.secretTag === undefined ? {} : { secretTag: settings.value.secretTag }),
  });
};

const confirmAnswer = async (id: string, approve: boolean): Promise<Envelope<unknown>> => {
  const stored = await readKey(confirmKey(id));
  const request = stored.ok ? stored.value : undefined;
  if (request === undefined || request.expiresMs < Date.now()) return denied('expired');
  await removeKey(confirmKey(id));
  if (approve) {
    await grantApproval(request.tabId, request.frameId, request.item, request.origin);
    await pushToFrame(request.tabId, request.frameId, { kind: 'open-menu' });
  }
  return okReply({});
};

const unlockReply = async (
  result: Promise<{ kind: string }>,
  deps: UiDeps,
): Promise<Envelope<unknown>> => {
  const value = await result;
  if (value.kind === 'done') await deps.afterUnlock();
  return okReply(value);
};

const guard =
  <M>(run: (message: M) => Promise<Envelope<unknown>>) =>
  async (message: M, sender: Sender): Promise<Envelope<unknown>> => {
    if (!isExtensionPage(sender)) return denied('sender');
    const reply = await run(message);
    return reply;
  };

export const createUiHandlers = (
  deps: UiDeps,
): {
  [K in UiKind]: (
    message: Extract<UiRequest, { kind: K }>,
    sender: Sender,
  ) => Promise<Envelope<unknown>>;
} => {
  return {
    'ui-state': guard(async () => okReply(await appState())),
    'ui-sign-in': guard(async (m) => {
      const value = await unlockReply(
        signIn(m.server, m.login, m.secretKey, m.password, m.serverFingerprint),
        deps,
      );
      return value;
    }),
    'ui-server-fingerprint': guard(async (m) => {
      const fingerprint = await fetchServerFingerprint(m.server);
      return fingerprint === undefined ? denied('fingerprint') : okReply({ fingerprint });
    }),
    'ui-unlock-password': guard(async (m) => {
      const value = await unlockReply(unlockWithPassword(m.password), deps);
      return value;
    }),
    'ui-unlock-desktop': guard(async () => {
      const value = await unlockReply(unlockWithDesktop(), deps);
      return value;
    }),
    'ui-pair-desktop': guard(async (m) => {
      const value = await unlockReply(pairWithDesktop(m.server), deps);
      return value;
    }),
    'ui-lock': guard(async () => {
      await lockNow();
      return okReply({});
    }),
    'ui-sync': guard(async () => okReply({ changed: await runSync() })),
    'ui-search': guard(async (m) => {
      const value = await search(m.text);
      return value;
    }),
    'ui-current-site': guard(async () => {
      const value = await currentSite();
      return value;
    }),
    'ui-copy': guard(copy),
    'ui-copy-generated': guard(copyGenerated),
    'ui-fill': guard(fill),
    'ui-generated': guard(async () => {
      const value = await generatedList();
      return value;
    }),
    'ui-settings': guard(async () => {
      const view = await readSettings();
      return view === undefined ? errReply({ kind: 'locked' }) : okReply(view);
    }),
    'ui-settings-set': guard(async (m) =>
      (await writeSettings(m.patch)) ? okReply({}) : errReply({ kind: 'locked' }),
    ),
    'ui-sign-out': guard(async () => {
      await signOut();
      return okReply({});
    }),
    'passkey-get': guard(async (m) => {
      const value = await Promise.resolve(passkeyView(m.id));
      return value;
    }),
    'passkey-answer': guard(async (m) => {
      const value = await passkeyAnswer(m.id, m.choice, m.credentialId, m.password);
      return value;
    }),
    'code-get': guard(async (m) => {
      const view = await Promise.resolve(codeView(m.id));
      return view === undefined ? denied('expired') : okReply(view);
    }),
    'confirm-get': guard(async (m) => {
      const value = await confirmGet(m.id);
      return value;
    }),
    'confirm-answer': guard(async (m) => {
      const value = await confirmAnswer(m.id, m.approve);
      return value;
    }),
  };
};
