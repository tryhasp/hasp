import type { PasskeyCandidate } from '@hasp/wasm';

import type { PasskeyView } from '../messages/ui.ts';
import type { Envelope, Sender } from '../platform/messaging.ts';
import { denied, okReply } from '../platform/messaging.ts';
import { onWindowClosed, openPasskeyWindow } from '../platform/tabs.ts';
import { touchActivity, unlockWithDesktop, verifyPassword } from './account.ts';
import { statusOf, unlockedClient, withUnlocked } from './client.ts';
import { pageOf } from './page.ts';
import type { PageSender } from './page.ts';
import {
  assertionJson,
  createRequestOf,
  frameOfPasskey,
  getRequestOf,
  isPasskeyFrameAllowed,
  isReauthWanted,
  parsePasskeyRequest,
  registrationJson,
} from './passkey-options.ts';
import type { ParsedRequest } from './passkey-options.ts';
import { randomHex } from './random.ts';

const PROMPT_TTL_MS = 120_000;
const MAX_ACTIVE_TABS = 3;

type Choice =
  | { kind: 'decline' }
  | {
      kind: 'use';
      candidate: Pick<PasskeyCandidate, 'vault' | 'item' | 'credentialId'> | undefined;
      userVerified: boolean;
    };

type Pending = {
  view: PasskeyView;
  candidates: PasskeyCandidate[];
  tabId: number;
  expiresMs: number;
  resolve: (choice: Choice) => void;
};

const pending = new Map<string, Pending>();
const activeTabs = new Set<number>();

export type AnswerStatus =
  | 'ok'
  | 'wrong-password'
  | 'locked-out'
  | 'declined'
  | 'unavailable'
  | 'expired';

const settleChoice = (id: string, choice: Choice): void => {
  const entry = pending.get(id);
  if (entry === undefined) return;
  pending.delete(id);
  entry.resolve(choice);
};

const askUser = async (
  id: string,
  entry: Omit<Pending, 'resolve' | 'expiresMs'>,
): Promise<Choice> => {
  const choice = await new Promise<Choice>((resolve) => {
    pending.set(id, { ...entry, expiresMs: Date.now() + PROMPT_TTL_MS, resolve });
    const timer = setTimeout(() => {
      settleChoice(id, { kind: 'decline' });
    }, PROMPT_TTL_MS);
    const opened = async (): Promise<void> => {
      const windowId = await openPasskeyWindow(id);
      if (windowId === undefined) {
        clearTimeout(timer);
        settleChoice(id, { kind: 'decline' });
        return;
      }
      const stop = onWindowClosed(windowId, () => {
        clearTimeout(timer);
        stop();
        settleChoice(id, { kind: 'decline' });
      });
    };
    void opened();
  });
  return choice;
};

const reauthOf = (mode: string | undefined): PasskeyView['reauth'] =>
  mode === 'password-only'
    ? 'password'
    : mode === 'extension' || mode === 'hardware'
      ? 'desktop'
      : 'none';

const viewOf = (
  parsed: ParsedRequest,
  page: PageSender,
  candidates: PasskeyCandidate[],
  reauth: PasskeyView['reauth'],
  settings: { language: string; tag: PasskeyView['secretTag'] },
): PasskeyView => {
  const rpId =
    parsed.op === 'create'
      ? (parsed.options.rp.id ?? page.host)
      : (parsed.options.rpId ?? page.host);
  return {
    op: parsed.op,
    host: page.host,
    rpId,
    rpName: parsed.op === 'create' ? parsed.options.rp.name : '',
    userName: parsed.op === 'create' ? parsed.options.user.name : '',
    isReauthNeeded: isReauthWanted(parsed.options, reauth !== 'none'),
    reauth,
    candidates: candidates.map((c) => ({
      credentialId: c.credentialId,
      title: c.title,
      userName: c.userName,
      displayName: c.displayName,
    })),
    ...(settings.tag === undefined ? {} : { secretTag: settings.tag }),
    locale: settings.language === 'en' ? 'en' : 'ko',
  };
};

export const passkeyRequest = async (
  op: 'create' | 'get',
  rawOptions: string,
  frame: string,
  sender: Sender,
): Promise<Envelope<unknown>> => {
  const page = pageOf(sender);
  if (page === undefined || !isPasskeyFrameAllowed(frame)) return denied('sender');
  const parsed = parsePasskeyRequest(op, rawOptions);
  if (parsed === undefined) return denied('options');
  if (parsed.op === 'get' && parsed.options.mediation === 'conditional')
    return denied('conditional');
  if (activeTabs.has(page.tabId) || activeTabs.size >= MAX_ACTIVE_TABS) return denied('busy');
  activeTabs.add(page.tabId);
  try {
    const reply = await passkeyCeremony(parsed, page, frame);
    return reply;
  } finally {
    activeTabs.delete(page.tabId);
  }
};

const passkeyCeremony = async (
  parsed: ParsedRequest,
  page: PageSender,
  frame: string,
): Promise<Envelope<unknown>> => {
  const facts = { frame };
  const unlocked = await unlockedClient();
  if (!unlocked.ok) return denied('locked');
  const client = unlocked.value;
  await touchActivity();
  const info = await statusOf(client);
  if (!info.ok) return denied('status');
  const settings = await withUnlocked(async (c) => c.settings());
  if (!settings.ok) return denied('settings');
  let candidates: PasskeyCandidate[] = [];
  if (parsed.op === 'get') {
    const found = await withUnlocked(async (c) =>
      c.passkeyCandidates({
        origin: page.origin,
        frame: frameOfPasskey(facts),
        rpId: parsed.options.rpId,
        allow: parsed.options.allowCredentials.map((entry) => entry.id),
      }),
    );
    if (!found.ok || found.value.length === 0) return denied('no-passkey');
    candidates = found.value;
  }
  const view = viewOf(parsed, page, candidates, reauthOf(info.value.unlockMode), {
    language: settings.value.language,
    tag: settings.value.secretTag,
  });
  const id = randomHex(16);
  const choice = await askUser(id, { view, candidates, tabId: page.tabId });
  if (choice.kind === 'decline') return denied('declined');
  if (parsed.op === 'create') {
    const created = await withUnlocked(async (c) =>
      c.passkeyCreate(createRequestOf(parsed.options, page.origin, facts, choice.userVerified)),
    );
    return created.ok
      ? okReply({ payload: registrationJson(created.value) })
      : denied(created.error.kind);
  }
  if (choice.candidate === undefined) return denied('no-pick');
  const pick = choice.candidate;
  const asserted = await withUnlocked(async (c) =>
    c.passkeyGet(getRequestOf(parsed.options, page.origin, facts, choice.userVerified, pick)),
  );
  return asserted.ok
    ? okReply({ payload: assertionJson(asserted.value) })
    : denied(asserted.error.kind);
};

export const passkeyView = (id: string): Envelope<unknown> => {
  const entry = pending.get(id);
  if (entry === undefined || entry.expiresMs < Date.now()) return denied('expired');
  return okReply(entry.view);
};

type Verification = { status: AnswerStatus; isVerified: boolean };

const verify = async (entry: Pending, password: string | undefined): Promise<Verification> => {
  if (!entry.view.isReauthNeeded) return { status: 'ok', isVerified: false };
  if (entry.view.reauth === 'password') {
    if (password === undefined) return { status: 'wrong-password', isVerified: false };
    const result = await verifyPassword(password);
    if (result.kind === 'done') return { status: 'ok', isVerified: true };
    return {
      status: result.kind === 'locked-out' ? 'locked-out' : 'wrong-password',
      isVerified: false,
    };
  }
  if (entry.view.reauth === 'desktop') {
    const result = await unlockWithDesktop();
    if (result.kind === 'done') return { status: 'ok', isVerified: true };
    return { status: result.kind === 'declined' ? 'declined' : 'unavailable', isVerified: false };
  }
  return { status: 'unavailable', isVerified: false };
};

export const passkeyAnswer = async (
  id: string,
  choice: 'use' | 'decline',
  credentialId: string | undefined,
  password: string | undefined,
): Promise<Envelope<unknown>> => {
  const entry = pending.get(id);
  if (entry === undefined || entry.expiresMs < Date.now()) return okReply({ status: 'expired' });
  if (choice === 'decline') {
    settleChoice(id, { kind: 'decline' });
    return okReply({ status: 'ok' });
  }
  const picked = entry.candidates.find((c) => c.credentialId === credentialId);
  if (entry.view.op === 'get' && picked === undefined) return denied('no-pick');
  const verification = await verify(entry, password);
  if (verification.status !== 'ok') return okReply({ status: verification.status });
  settleChoice(id, {
    kind: 'use',
    candidate:
      picked === undefined
        ? undefined
        : { vault: picked.vault, item: picked.item, credentialId: picked.credentialId },
    userVerified: verification.isVerified,
  });
  return okReply({ status: 'ok' });
};
