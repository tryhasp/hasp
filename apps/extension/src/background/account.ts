import type { HaspClient } from '@hasp/wasm';
import type { HaspError } from '@hasp/wasm';
import { settleAsync } from '@hasp/wasm';

import type { AppState, SettingsPatch, SettingsView, UnlockResult } from '../messages/ui.ts';
import { targetBrowser } from '../platform/browser.ts';
import { clearClipboardWhenDue } from '../platform/clipboard.ts';
import { report } from '../platform/log.ts';
import {
  isDesktopReachable,
  newRequestId,
  openDesktopLink,
  errorOfCode,
} from '../platform/native.ts';
import type { NativeError } from '../platform/native.ts';
import { clearSession, readKey, removeKey, writeKey } from '../platform/storage.ts';
import { hasOriginPermission, pushToAllTabs, uiLocale } from '../platform/tabs.ts';
import { encodeText, fromBase64Url, hexToBytes, toBase64, toBase64Url } from '../shared/bytes.ts';
import { normalizeServer } from '../shared/server.ts';
import {
  adoptClient,
  createClient,
  dropClient,
  getClient,
  persistIfChanged,
  statusOf,
  unlockedClient,
  withUnlocked,
} from './client.ts';
import { showPairingCode, showUnlockCode } from './code-window.ts';
import type { CodeHandle } from './code-window.ts';
import { activityKey, deviceKey, localeKey, ticketKey } from './keys.ts';

const PAIR_TIMEOUT_MS = 90_000;
const UNLOCK_TIMEOUT_MS = 60_000;
const DEFAULT_DESKTOP_VALID_MS = 600_000;

export const touchActivity = async (): Promise<void> => {
  await writeKey(activityKey, Date.now());
};

export const afterLock = async (): Promise<void> => {
  await clearClipboardWhenDue(true);
  await removeKey(ticketKey);
  await clearSession();
  await pushToAllTabs({ kind: 'lock' });
};

export const lockNow = async (): Promise<void> => {
  const client = await getClient();
  if (client !== undefined) await settleAsync(client.lock());
  await afterLock();
};

const unlockResultOf = async (client: HaspClient, error: HaspError): Promise<UnlockResult> => {
  if (error.kind === 'rate-limited') {
    const status = await statusOf(client);
    return { kind: 'locked-out', retryAfter: status.ok ? status.value.retryAfter : 0 };
  }
  if (error.kind === 'auth') return { kind: 'wrong-password' };
  return { kind: 'failed' };
};

const afterUnlock = async (): Promise<void> => {
  await touchActivity();
};

const syncLocale = async (client: HaspClient): Promise<void> => {
  const settings = await settleAsync(client.settings());
  if (settings.ok) await writeKey(localeKey, settings.value.language === 'en' ? 'en' : 'ko');
};

const storeSession = async (client: HaspClient, password: Uint8Array): Promise<boolean> => {
  const session = await settleAsync(client.unlockWithPassword(password));
  if (!session.ok) return false;
  await writeKey(ticketKey, { kind: 'session', blob: toBase64(session.value.sessionBlob) });
  session.value.sessionBlob.fill(0);
  return true;
};

export const fetchServerFingerprint = async (server: string): Promise<string | undefined> => {
  const origin = normalizeServer(server);
  if (origin === undefined || !(await hasOriginPermission(origin))) return undefined;
  const client = await createClient(origin);
  try {
    const fingerprint = await settleAsync(client.serverFingerprint());
    return fingerprint.ok ? fingerprint.value : undefined;
  } finally {
    client.free();
  }
};

export const signIn = async (
  server: string,
  login: string,
  secretKey: string,
  password: string,
  serverFingerprint: string,
): Promise<UnlockResult> => {
  const origin = normalizeServer(server);
  if (origin === undefined) return { kind: 'failed' };
  if (!(await hasOriginPermission(origin))) return { kind: 'failed' };
  const existing = await getClient();
  if (existing !== undefined) {
    const status = await statusOf(existing);
    if (status.ok && status.value.state !== 'empty') return { kind: 'failed' };
  }
  const client = await createClient(origin);
  const passwordBytes = encodeText(password);
  const opened = await settleAsync(
    client.signIn({
      origin,
      login,
      secretKey: encodeText(secretKey),
      password: passwordBytes,
      serverFingerprint,
    }),
  );
  if (!opened.ok) {
    passwordBytes.fill(0);
    client.free();
    return unlockResultOfPlain(opened.error);
  }
  await adoptClient(client, origin);
  const isSession = await storeSession(client, passwordBytes);
  passwordBytes.fill(0);
  if (!isSession) return { kind: 'failed' };
  await syncLocale(client);
  await afterUnlock();
  return { kind: 'done' };
};

const unlockResultOfPlain = (error: HaspError): UnlockResult => {
  if (error.kind === 'server-key') return { kind: 'wrong-fingerprint' };
  if (error.kind === 'rate-limited') return { kind: 'locked-out', retryAfter: 0 };
  if (error.kind === 'auth') return { kind: 'wrong-password' };
  return { kind: 'failed' };
};

export const unlockWithPassword = async (password: string): Promise<UnlockResult> => {
  const client = await getClient();
  if (client === undefined) return { kind: 'failed' };
  const bytes = encodeText(password);
  const opened = await settleAsync(client.unlockWithPassword(bytes));
  if (!opened.ok) {
    bytes.fill(0);
    return unlockResultOf(client, opened.error);
  }
  await writeKey(ticketKey, { kind: 'session', blob: toBase64(opened.value.sessionBlob) });
  opened.value.sessionBlob.fill(0);
  bytes.fill(0);
  await persistIfChanged(client);
  await syncLocale(client);
  await afterUnlock();
  return { kind: 'done' };
};

export const verifyPassword = async (password: string): Promise<UnlockResult> => {
  const client = await getClient();
  if (client === undefined) return { kind: 'failed' };
  const bytes = encodeText(password);
  const opened = await settleAsync(client.unlockPassword(bytes));
  bytes.fill(0);
  if (!opened.ok) return unlockResultOf(client, opened.error);
  await persistIfChanged(client);
  return { kind: 'done' };
};

const desktopFailure = (error: NativeError): UnlockResult => {
  switch (error.kind) {
    case 'declined':
      return { kind: 'declined' };
    case 'unavailable':
    case 'timeout':
    case 'locked':
      return { kind: 'desktop-unavailable' };
    case 'revoked':
    case 'refused':
      return { kind: 'failed' };
  }
};

const NONCE_BYTES = 16;

const validUntilMs = (seconds: number): number =>
  seconds > 0 ? (seconds < 1e12 ? seconds * 1000 : seconds) : Date.now() + DEFAULT_DESKTOP_VALID_MS;

export const unlockWithDesktop = async (): Promise<UnlockResult> => {
  const client = await getClient();
  const device = await readKey(deviceKey);
  if (client === undefined || !device.ok || device.value === undefined) return { kind: 'failed' };
  const raw = hexToBytes(device.value.hex);
  if (raw === undefined) return { kind: 'failed' };
  const link = openDesktopLink();
  let codeHandle: CodeHandle | undefined;
  try {
    const id = newRequestId();
    const nonce = toBase64Url(crypto.getRandomValues(new Uint8Array(NONCE_BYTES)));
    codeHandle = await showUnlockCode(device.value.hex, nonce);
    const sent = await link.send({ type: 'unlock', id, device_id: toBase64Url(raw), nonce });
    if (!sent.ok) return desktopFailure(sent.error);
    const reply = await link.receive(AbortSignal.timeout(UNLOCK_TIMEOUT_MS));
    await codeHandle.close();
    codeHandle = undefined;
    if (!reply.ok) return desktopFailure(reply.error);
    const message = reply.value;
    if (message.type === 'error') return desktopFailure(errorOfCode(message.code));
    if (message.type !== 'unlock_reply') return { kind: 'failed' };
    const key = fromBase64Url(message.k_ext);
    const opened = await settleAsync(client.unlockExtension(key));
    key.fill(0);
    if (!opened.ok) return { kind: 'failed' };
    await writeKey(ticketKey, {
      kind: 'extension',
      key: toBase64(fromBase64Url(message.k_ext)),
      validUntilMs: validUntilMs(message.valid_until),
    });
    await persistIfChanged(client);
    await syncLocale(client);
    await afterUnlock();
    return { kind: 'done' };
  } finally {
    await codeHandle?.close();
    link.close();
  }
};

export const pairWithDesktop = async (server: string): Promise<UnlockResult> => {
  const origin = normalizeServer(server);
  if (origin === undefined) return { kind: 'failed' };
  if (!(await hasOriginPermission(origin))) return { kind: 'failed' };
  const existing = await getClient();
  if (existing !== undefined) {
    const status = await statusOf(existing);
    if (status.ok && status.value.state !== 'empty') return { kind: 'failed' };
  }
  const client = await createClient(origin);
  const link = openDesktopLink();
  let pairingCode: CodeHandle | undefined;
  try {
    const id = newRequestId();
    const send = async (bytes: Uint8Array): Promise<void> => {
      pairingCode ??= await showPairingCode(bytes);
      const sent = await link.send({ type: 'enrol_request', id, data: toBase64Url(bytes) });
      if (!sent.ok) throw new Error('native-send');
    };
    const receive = async (): Promise<Uint8Array> => {
      const reply = await link.receive(AbortSignal.timeout(PAIR_TIMEOUT_MS));
      if (!reply.ok || reply.value.type !== 'enrol_reply') throw new Error('native-receive');
      return fromBase64Url(reply.value.data);
    };
    const paired = await settleAsync(client.pairWithDesktop(send, receive, targetBrowser()));
    await pairingCode?.close();
    pairingCode = undefined;
    if (!paired.ok) {
      client.free();
      return { kind: 'failed' };
    }
    const kExt = paired.value;
    const opened = await settleAsync(client.unlockExtension(kExt));
    if (!opened.ok) {
      kExt.fill(0);
      client.free();
      return { kind: 'failed' };
    }
    const devices = await settleAsync(client.devices());
    const current = devices.ok ? devices.value.find((d) => d.current) : undefined;
    await adoptClient(client, origin);
    if (current !== undefined) await writeKey(deviceKey, { hex: current.device });
    await writeKey(ticketKey, {
      kind: 'extension',
      key: toBase64(kExt),
      validUntilMs: Date.now() + DEFAULT_DESKTOP_VALID_MS,
    });
    kExt.fill(0);
    await persistIfChanged(client);
    await syncLocale(client);
    await afterUnlock();
    return { kind: 'done' };
  } catch (cause) {
    report(cause instanceof Error ? cause.name : 'pair');
    client.free();
    return { kind: 'desktop-unavailable' };
  } finally {
    await pairingCode?.close();
    link.close();
  }
};

export const signOut = async (): Promise<void> => {
  await lockNow();
  await dropClient();
  await removeKey(deviceKey);
};

export const appState = async (): Promise<AppState> => {
  const stored = await readKey(localeKey);
  const lang = stored.ok && stored.value !== undefined ? stored.value : uiLocale();
  const device = await readKey(deviceKey);
  const isPaired = device.ok && device.value !== undefined;
  const client = await getClient();
  if (client === undefined) {
    return {
      account: 'empty',
      retryAfter: 0,
      locale: lang,
      isPaired: false,
      isDesktopAvailable: false,
    };
  }
  let status = await statusOf(client);
  if (status.ok && status.value.state === 'locked') {
    const resumed = await unlockedClient();
    if (resumed.ok) status = await statusOf(client);
  }
  if (!status.ok) {
    return { account: 'empty', retryAfter: 0, locale: lang, isPaired, isDesktopAvailable: false };
  }
  const s = status.value;
  const base = {
    login: s.login,
    server: s.origin,
    unlockMode: s.unlockMode,
    retryAfter: s.retryAfter,
    locale: lang,
    isPaired,
  };
  const out: AppState = {
    account: s.state,
    retryAfter: s.retryAfter,
    locale: lang,
    isPaired,
    isDesktopAvailable: false,
  };
  if (base.login !== undefined) out.login = base.login;
  if (base.server !== undefined) out.server = base.server;
  if (base.unlockMode !== undefined) out.unlockMode = base.unlockMode;
  if (s.state === 'unlocked') {
    const settings = await settleAsync(client.settings());
    if (settings.ok) {
      out.locale = settings.value.language === 'en' ? 'en' : 'ko';
      if (settings.value.secretTag !== undefined) out.secretTag = settings.value.secretTag;
    }
    const activity = await readKey(activityKey);
    const idle = settings.ok ? settings.value.lock.idleMinutes : 0;
    if (activity.ok && activity.value !== undefined && idle > 0) {
      out.idleDeadlineMs = activity.value + idle * 60_000;
    }
  } else if (isPaired) {
    out.isDesktopAvailable = await isDesktopReachable();
  }
  return out;
};

export const readSettings = async (): Promise<SettingsView | undefined> => {
  const result = await withUnlocked(async (client) => {
    const value = await client.settings();
    return value;
  });
  if (!result.ok) return undefined;
  const s = result.value;
  const view: SettingsView = {
    lock: s.lock,
    language: s.language === 'en' ? 'en' : 'ko',
    inlineMenu: s.inlineMenu,
    askBeforeFilling: s.askBeforeFilling,
    hardenedMode: s.hardenedMode,
    autoSubmit: s.autoSubmit,
  };
  if (s.secretTag !== undefined) view.secretTag = s.secretTag;
  return view;
};

export const writeSettings = async (patch: SettingsPatch): Promise<boolean> => {
  const result = await withUnlocked(async (client) => {
    const current = await client.settings();
    await client.setSettings({
      ...current,
      ...(patch.lock === undefined ? {} : { lock: patch.lock }),
      ...(patch.secretTag === undefined ? {} : { secretTag: patch.secretTag }),
      ...(patch.language === undefined ? {} : { language: patch.language }),
      ...(patch.inlineMenu === undefined ? {} : { inlineMenu: patch.inlineMenu }),
      ...(patch.askBeforeFilling === undefined ? {} : { askBeforeFilling: patch.askBeforeFilling }),
      ...(patch.hardenedMode === undefined ? {} : { hardenedMode: patch.hardenedMode }),
      ...(patch.autoSubmit === undefined ? {} : { autoSubmit: patch.autoSubmit }),
    });
    if (patch.language !== undefined) await writeKey(localeKey, patch.language);
  });
  return result.ok;
};

export const idleTick = async (): Promise<void> => {
  const client = await getClient();
  if (client === undefined) return;
  const status = await statusOf(client);
  if (!status.ok || status.value.state !== 'unlocked') return;
  const ticket = await readKey(ticketKey);
  if (
    ticket.ok &&
    ticket.value !== undefined &&
    ticket.value.kind === 'extension' &&
    Date.now() >= ticket.value.validUntilMs
  ) {
    await lockNow();
    return;
  }
  if (ticket.ok && ticket.value?.kind === 'extension') return;
  const activity = await readKey(activityKey);
  if (!activity.ok || activity.value === undefined) return;
  const elapsed = Math.floor((Date.now() - activity.value) / 1000);
  const locked = await settleAsync(client.applyLockTrigger('idle', elapsed));
  if (locked.ok && locked.value) await afterLock();
};

export const lockOnTrigger = async (
  trigger: 'screen-lock' | 'user-switch' | 'sleep',
): Promise<void> => {
  const client = await getClient();
  if (client === undefined) return;
  const locked = await settleAsync(client.applyLockTrigger(trigger, 0));
  if (locked.ok && locked.value) await afterLock();
};
