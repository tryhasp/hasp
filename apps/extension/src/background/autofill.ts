import type {
  Attestation,
  Candidate as MenuCandidate,
  ContentRequest,
  FrameRequest,
  PageConfig,
} from '@hasp/autofill';
import {
  capturePending,
  clearPending,
  consumeGestureToken,
  listGenerated,
  markGeneratedSaved,
  markGeneratedUnverified,
  markSubmitted,
  mintGestureToken,
  readPending,
  submittedPassword,
  recordGenerated,
  verifyFillRequest,
} from '@hasp/autofill';
import type { FieldPurpose } from '@hasp/autofill';
import type { AutofillResult, Candidate, FrameContext } from '@hasp/wasm';

import type { Envelope, Sender } from '../platform/messaging.ts';
import { denied, errReply, okReply } from '../platform/messaging.ts';
import { spawn } from '../platform/spawn.ts';
import { readKey, removeKey, sessionStore, writeKey } from '../platform/storage.ts';
import { tabFacts } from '../platform/tabs.ts';
import { decodeText, encodeText } from '../shared/bytes.ts';
import { splitHost } from '../shared/host.ts';
import { fillKindOf, pagePurposeOf } from '../shared/purpose.ts';
import type { EngineFillKind } from '../shared/purpose.ts';
import { translate } from '../shared/strings.ts';
import { touchActivity } from './account.ts';
import type { CallError } from './client.ts';
import { unlockedClient, withUnlocked } from './client.ts';
import { requestConfirm } from './confirm.ts';
import { isDesktopFill, settleDesktopFill } from './desktop.ts';
import { approvalKey, flowKey, menuKey, neverSaveKey, userSelectorsKey } from './keys.ts';
import type { MenuSession } from './keys.ts';
import { frameOf, pageOf } from './page.ts';
import type { PageSender } from './page.ts';
import { passkeyRequest } from './passkey.ts';
import { randomHex } from './random.ts';
import { runSync } from './sync.ts';

const APPROVAL_TTL_MS = 60_000;
const FLOW_TTL_MS = 10 * 60_000;
const LABEL_MAX = 60;

type ContentKinds = ContentRequest['kind'];
type FrameKinds = FrameRequest['kind'];

const fail = (error: CallError): Envelope<never> =>
  error.kind === 'locked' || error.kind === 'no-account'
    ? errReply({ kind: 'locked' })
    : denied(error.kind);

const frameContextOf = (
  frame: string,
  isObscured: boolean,
  isC4Supported: boolean,
): FrameContext => ({
  topFrame: frame === 'top',
  crossOriginFrame: frame === 'cross-origin',
  sandboxed: frame === 'sandboxed' || frame === 'opaque' || frame === 'blank' || frame === 'blob',
  obscured: isObscured,
  visibilityCheckSupported: isC4Supported,
});

const settle = <T>(run: () => T): { ok: true; value: T } | { ok: false } => {
  try {
    return { ok: true, value: run() };
  } catch {
    return { ok: false };
  }
};

const asString = (secret: Uint8Array): string => {
  const text = decodeText(secret);
  secret.fill(0);
  return text;
};

const siteQuirks = (q: AutofillResult['quirks']): PageConfig['quirks'] => ({
  ...(q.append2fa ? { append_2fa: true } : {}),
  ...(q.noAutosubmit ? { no_autosubmit: true } : {}),
  ...(q.perCharEvents ? { per_char_events: true } : {}),
  ...(q.skipSave ? { skip_save: true } : {}),
  ...(q.iframeLogin ? { iframe_login: true } : {}),
});

const userSelectorsFor = async (host: string): Promise<PageConfig['userSelectors']> => {
  const stored = await readKey(userSelectorsKey);
  const entry = stored.ok ? stored.value?.[host] : undefined;
  return entry ?? {};
};

const readSession = async (nonce: string): Promise<MenuSession | undefined> => {
  const stored = await readKey(menuKey(nonce));
  return stored.ok ? stored.value : undefined;
};

const labelOf = (name: string): string => name.slice(0, LABEL_MAX);

const isApproved = async (
  tabId: number,
  frameId: number,
  item: string,
  origin: string,
): Promise<boolean> => {
  const stored = await readKey(approvalKey(tabId, frameId, item));
  return (
    stored.ok &&
    stored.value !== undefined &&
    stored.value.expiresMs > Date.now() &&
    stored.value.origin === origin
  );
};

export const grantApproval = async (
  tabId: number,
  frameId: number,
  item: string,
  origin: string,
): Promise<void> => {
  await writeKey(approvalKey(tabId, frameId, item), {
    expiresMs: Date.now() + APPROVAL_TTL_MS,
    origin,
  });
};

const toMenuCandidate = (c: Candidate): MenuSession['candidates'][number] => ({
  vault: c.vault,
  item: c.item,
  title: c.title,
  username: c.subtitle,
  tier: c.tier,
  hasTotp: c.hasTotp,
  ...(c.hostToConfirm === undefined ? {} : { hostToConfirm: c.hostToConfirm }),
});

const menuOpen = async (
  m: Extract<ContentRequest, { kind: 'menu-open' }>,
  sender: Sender,
): Promise<Envelope<unknown>> => {
  const page = pageOf(sender);
  if (page === undefined) return denied('sender');
  await touchActivity();
  const frame = frameContextOf(m.frame, m.isObscured, m.isC4Supported);
  const result = await withUnlocked(async (client) => {
    const query = await client.autofillQuery({ pageUrl: page.url, origin: page.origin, frame });
    const settings = await client.settings();
    return { query, settings };
  });
  if (!result.ok) {
    return okReply({
      decision: 'none',
      reason: result.error.kind === 'locked' ? 'locked' : 'error',
    });
  }
  const { query, settings } = result.value;
  if (query.refusal !== undefined) return okReply({ decision: 'none', reason: 'refused' });
  if (!settings.inlineMenu || settings.hardenedMode) {
    return okReply({ decision: 'none', reason: 'disabled' });
  }
  const kind = fillKindOf(m.formKind);
  if (kind === undefined || kind === 'card' || kind === 'identity') {
    return okReply({ decision: 'none', reason: 'kind' });
  }
  const isGenerating = m.formKind === 'signup' || m.formKind === 'change-password';
  const candidates = query.candidates.filter((c) => c.fill !== 'never');
  const first = candidates[0];
  if (first === undefined && !isGenerating)
    return okReply({ decision: 'none', reason: 'no-match' });
  if (first !== undefined && !isGenerating) {
    const plan = await withUnlocked(async (client) => {
      const value = await client.fillPlan({
        vault: first.vault,
        item: first.item,
        origin: page.origin,
        pageUrl: page.url,
        kind,
        frame,
        approved: false,
        rememberHost: false,
        inIframeClick: false,
      });
      return value;
    });
    if (
      plan.ok &&
      plan.value.stepUp === 'browser-ui' &&
      !(await isApproved(page.tabId, page.frameId, first.item, page.origin))
    ) {
      await requestConfirm({
        tabId: page.tabId,
        frameId: page.frameId,
        vault: first.vault,
        item: first.item,
        title: first.title,
        subtitle: first.subtitle,
        savedHost: first.hostToConfirm ?? page.host,
        currentHost: page.host,
        origin: page.origin,
      });
      return okReply({ decision: 'browser-ui' });
    }
  }
  const nonce = randomHex(16);
  const session: MenuSession = {
    nonce,
    tabId: page.tabId,
    frameId: page.frameId,
    origin: page.origin,
    url: page.url,
    host: page.host,
    mode: 'menu',
    formKind: m.formKind,
    frame: m.frame,
    createdMs: Date.now(),
    candidates: candidates.map(toMenuCandidate),
    canGenerate: isGenerating || m.formKind === 'login',
  };
  await writeKey(menuKey(nonce), session);
  return okReply({ decision: 'inline', nonce });
};

const isReplyKind = (reply: Envelope<unknown>, kind: string): boolean => {
  if (!reply.ok || typeof reply.value !== 'object' || reply.value === null) return false;
  return Reflect.get(reply.value, 'kind') === kind;
};

const fillWithEngine = async (
  page: PageSender,
  vault: string,
  item: string,
  kind: EngineFillKind,
  frame: FrameContext,
  requested: readonly FieldPurpose[],
  options: { isBrowserApproved: boolean; isInlineAnswered: boolean; isClick: boolean },
): Promise<Envelope<unknown>> => {
  const payload = await withUnlocked(async (client) => {
    const request = {
      vault,
      item,
      origin: page.origin,
      pageUrl: page.url,
      kind,
      frame,
      approved: false,
      rememberHost: false,
      inIframeClick: options.isClick,
    };
    const plan = await client.fillPlan(request);
    if (plan.stepUp === 'allow') return client.fillPayload(request);
    const isAnswered =
      plan.stepUp === 'browser-ui'
        ? options.isBrowserApproved
        : options.isInlineAnswered || options.isBrowserApproved;
    if (!isAnswered) return 'browser-ui' as const;
    return client.fillPayload({ ...request, approved: true, rememberHost: true });
  });
  if (!payload.ok) {
    return payload.error.kind === 'refused' || payload.error.kind === 'unconfirmed'
      ? okReply({ kind: 'refused', reason: payload.error.kind })
      : fail(payload.error);
  }
  if (payload.value === 'browser-ui') return okReply({ kind: 'browser-ui' });
  const fields = payload.value.values.flatMap((entry) => {
    const purpose = pagePurposeOf(entry.purpose, requested);
    const value = asString(entry.value);
    return purpose === undefined ? [] : [{ purpose, value }];
  });
  return okReply({
    kind: 'payload',
    fields,
    isAutosubmit: payload.value.autosubmitAllowed && kind === 'login',
    isPerCharEvents: false,
  });
};

const attestationOk = async (
  sender: PageSender,
  attestation: Attestation,
  isTokenAccepted: boolean,
): Promise<string | undefined> => {
  const facts = await tabFacts(sender.tabId);
  const isFocusOk = facts !== undefined && facts.isActive && facts.isWindowFocused;
  const gate = verifyFillRequest({
    isUnlocked: true,
    isTabActiveAndFocused: isFocusOk,
    isSenderBoundFrame: true,
    isTokenAccepted,
    attestation,
    nowMs: Date.now(),
  });
  return gate.ok ? undefined : gate.error;
};

const fillRequest = async (
  m: Extract<ContentRequest, { kind: 'fill-request' }>,
  sender: Sender,
): Promise<Envelope<unknown>> => {
  const page = pageOf(sender);
  if (page === undefined) return denied('sender');
  const session = await readSession(m.nonce);
  if (
    session === undefined ||
    session.tabId !== page.tabId ||
    session.frameId !== page.frameId ||
    session.origin !== page.origin
  ) {
    return denied('no-session');
  }
  const consumed = await consumeGestureToken(
    sessionStore,
    m.token,
    { tabId: page.tabId, frameId: page.frameId, nonce: m.nonce, itemId: m.itemId },
    Date.now(),
  );
  const isDesktop = isDesktopFill(m.nonce);
  const refusal = await attestationOk(page, m.attestation, consumed.ok);
  if (refusal !== undefined) {
    settleDesktopFill(m.nonce, 'refused');
    return okReply({ kind: 'refused', reason: refusal });
  }
  const candidate = session.candidates.find((c) => c.item === m.itemId);
  const kind = fillKindOf(m.formKind);
  if (candidate === undefined || kind === undefined) return denied('no-item');
  const frame = frameContextOf(session.frame, false, m.attestation.isC4Supported);
  const approved = await isApproved(page.tabId, page.frameId, candidate.item, page.origin);
  const reply = await fillWithEngine(
    page,
    candidate.vault,
    candidate.item,
    kind,
    frame,
    m.purposes,
    {
      isBrowserApproved: approved,
      isInlineAnswered: !isDesktop && session.mode === 'menu',
      isClick: true,
    },
  );
  if (approved) await removeKey(approvalKey(page.tabId, page.frameId, candidate.item));
  if (isReplyKind(reply, 'browser-ui')) {
    await requestConfirm({
      tabId: page.tabId,
      frameId: page.frameId,
      vault: candidate.vault,
      item: candidate.item,
      title: candidate.title,
      subtitle: candidate.username,
      savedHost: candidate.hostToConfirm ?? page.host,
      currentHost: page.host,
      origin: page.origin,
    });
  }
  if (isReplyKind(reply, 'payload')) {
    await writeKey(flowKey(page.tabId), {
      vault: candidate.vault,
      item: candidate.item,
      origin: page.origin,
      frame: session.frame,
      atMs: Date.now(),
      isAnswered: approved || (!isDesktop && session.mode === 'menu'),
    });
  }
  await removeKey(menuKey(m.nonce));
  for (const outcome of ['payload', 'browser-ui', 'refused']) {
    if (isReplyKind(reply, outcome)) settleDesktopFill(m.nonce, outcome);
  }
  return reply;
};

const fillContinue = async (
  m: Extract<ContentRequest, { kind: 'fill-continue' }>,
  sender: Sender,
): Promise<Envelope<unknown>> => {
  const page = pageOf(sender);
  if (page === undefined) return denied('sender');
  const stored = await readKey(flowKey(page.tabId));
  const flow = stored.ok ? stored.value : undefined;
  if (flow === undefined || Date.now() - flow.atMs > FLOW_TTL_MS) {
    return okReply({ kind: 'refused', reason: 'left-match-set' });
  }
  if (flow.origin !== page.origin) {
    await removeKey(flowKey(page.tabId));
    return okReply({ kind: 'refused', reason: 'left-match-set' });
  }
  const kind = fillKindOf(m.formKind);
  if (kind === undefined) return denied('kind');
  const frame = frameContextOf(flow.frame, false, m.attestation.isC4Supported);
  const matches = await withUnlocked(async (client) => {
    const value = await client.autofillQuery({ pageUrl: page.url, origin: page.origin, frame });
    return value;
  });
  if (!matches.ok) return fail(matches.error);
  if (!matches.value.candidates.some((c) => c.item === flow.item)) {
    await removeKey(flowKey(page.tabId));
    return okReply({ kind: 'refused', reason: 'left-match-set' });
  }
  const refusal = await attestationOk(page, m.attestation, true);
  if (refusal !== undefined) return okReply({ kind: 'refused', reason: refusal });
  return fillWithEngine(page, flow.vault, flow.item, kind, frame, m.purposes, {
    isBrowserApproved: false,
    isInlineAnswered: flow.isAnswered,
    isClick: false,
  });
};

const capture = async (
  m: Extract<ContentRequest, { kind: 'capture' }>,
  sender: Sender,
): Promise<Envelope<unknown>> => {
  const page = pageOf(sender);
  if (page === undefined) return denied('sender');
  await capturePending(
    sessionStore,
    { tabId: page.tabId, site: page.host },
    {
      ...(m.values.username === undefined ? {} : { username: m.values.username }),
      ...(m.values.password === undefined ? {} : { password: m.values.password }),
      ...(m.values.newPassword === undefined ? {} : { newPassword: m.values.newPassword }),
      ...(m.source === 'generated' ? { isGenerated: true } : {}),
    },
    Date.now(),
  );
  return okReply({});
};

const submitSignal = async (
  m: Extract<ContentRequest, { kind: 'submit-signal' }>,
  sender: Sender,
): Promise<Envelope<unknown>> => {
  const page = pageOf(sender);
  if (page === undefined) return denied('sender');
  const key = { tabId: page.tabId, site: page.host };
  if (m.outcome === 'pending') {
    await markSubmitted(sessionStore, key, Date.now(), m.formKind);
    return okReply({ kind: 'none' });
  }
  if (m.wasSubmitted === true) {
    if (m.handoff !== undefined) await capturePending(sessionStore, key, m.handoff, Date.now());
    await markSubmitted(sessionStore, key, Date.now(), m.formKind);
  }
  const pending = await readPending(sessionStore, key, Date.now());
  if (
    m.outcome === 'error-text' ||
    m.outcome === 'rerendered' ||
    pending === undefined ||
    !pending.isSubmitted
  ) {
    await clearPending(sessionStore, key);
    return okReply({ kind: 'none' });
  }
  const password = submittedPassword(pending);
  if (password === undefined) return okReply({ kind: 'none' });
  const never = await readKey(neverSaveKey);
  if (never.ok && never.value?.includes(splitHost(page.host).registrable) === true) {
    await clearPending(sessionStore, key);
    return okReply({ kind: 'none' });
  }
  const proposal = await withUnlocked(async (client) => {
    const bytes = encodeText(password);
    const result = await client.proposeSave({
      origin: page.origin,
      pageUrl: page.url,
      username: pending.username ?? '',
      password: bytes,
      generated: pending.isGenerated,
    });
    bytes.fill(0);
    return result;
  });
  if (!proposal.ok) return okReply({ kind: 'none' });
  const kind = proposal.value.kind;
  if (kind !== 'new' && kind !== 'update') {
    await clearPending(sessionStore, key);
    return okReply({ kind: 'none' });
  }
  const nonce = randomHex(16);
  const session: MenuSession = {
    nonce,
    tabId: page.tabId,
    frameId: page.frameId,
    origin: page.origin,
    url: page.url,
    host: page.host,
    mode: 'save',
    formKind: 'login',
    frame: 'top',
    createdMs: Date.now(),
    candidates: [],
    canGenerate: false,
    saveKind: kind,
    saveTitle: proposal.value.suggestedTitle,
    saveUsername: proposal.value.username,
    ...(proposal.value.vault === undefined ? {} : { saveVault: proposal.value.vault }),
    ...(proposal.value.item === undefined ? {} : { saveItem: proposal.value.item }),
  };
  await writeKey(menuKey(nonce), session);
  return okReply({ kind: 'prompt', nonce });
};

const generate = async (
  m: Extract<ContentRequest, { kind: 'generate' }>,
  sender: Sender,
): Promise<Envelope<unknown>> => {
  const page = pageOf(sender);
  if (page === undefined) return denied('sender');
  await touchActivity();
  const unlocked = await unlockedClient();
  if (!unlocked.ok) return fail(unlocked.error);
  const generated = settle(() =>
    unlocked.value.generate({
      kind: m.preset === 'korean-safe' ? 'korean-safe' : 'random',
      length: 20,
      lower: true,
      upper: true,
      digits: true,
      symbols: undefined,
      excludeAmbiguous: true,
      words: 4,
      separator: '-',
      capitalize: true,
      appendDigit: false,
      origin: page.origin,
      siteRules: m.rules.passwordRules,
      fieldMinLength: m.rules.minlength,
      fieldMaxLength: m.rules.maxlength,
    }),
  );
  if (!generated.ok) return denied('generate');
  const value = asString(generated.value.value);
  const stored = await recordGenerated(
    sessionStore,
    { id: randomHex(8), value, site: page.host, atMs: Date.now() },
    Date.now(),
  );
  if (!stored.ok) return denied('storage');
  await capturePending(
    sessionStore,
    { tabId: page.tabId, site: page.host },
    { newPassword: value, isGenerated: true },
    Date.now(),
  );
  return okReply({ value, length: generated.value.length });
};

const generatedVerified = async (
  m: Extract<ContentRequest, { kind: 'generated-verified' }>,
): Promise<Envelope<unknown>> => {
  if (!m.isMatch) {
    const list = await listGenerated(sessionStore, Date.now());
    const last = list.at(-1);
    if (last !== undefined) await markGeneratedUnverified(sessionStore, last.id, Date.now());
  }
  return okReply({});
};

const teach = async (
  m: Extract<ContentRequest, { kind: 'teach' }>,
  sender: Sender,
): Promise<Envelope<unknown>> => {
  const page = pageOf(sender);
  if (page === undefined) return denied('sender');
  const stored = await readKey(userSelectorsKey);
  const all = stored.ok && stored.value !== undefined ? stored.value : {};
  await writeKey(userSelectorsKey, {
    ...all,
    [page.host]: { ...all[page.host], [m.purpose]: m.selector },
  });
  return okReply({});
};

const pageConfig = async (sender: Sender): Promise<Envelope<unknown>> => {
  const page = pageOf(sender);
  if (page === undefined) return denied('sender');
  const userSelectors = await userSelectorsFor(page.host);
  const query = await withUnlocked(async (client) => {
    const value = await client.autofillQuery({
      pageUrl: page.url,
      origin: page.origin,
      frame: frameContextOf('top', false, false),
    });
    return value;
  });
  const config: PageConfig = {
    quirks: query.ok ? siteQuirks(query.value.quirks) : {},
    selectors: {},
    userSelectors,
    relatedDomains: [],
    ...(query.ok && query.value.passwordRules !== undefined
      ? { passwordRules: query.value.passwordRules }
      : {}),
  };
  return okReply(config);
};

export const contentHandlers: {
  [K in ContentKinds]: (
    message: Extract<ContentRequest, { kind: K }>,
    sender: Sender,
  ) => Promise<Envelope<unknown>>;
} = {
  'page-config': async (_m, sender) => {
    const value = await pageConfig(sender);
    return value;
  },
  'menu-open': menuOpen,
  'fill-request': fillRequest,
  'fill-continue': fillContinue,
  capture,
  'submit-signal': submitSignal,
  generate,
  'generated-verified': async (m) => {
    const value = await generatedVerified(m);
    return value;
  },
  teach,
  strike: async () => {
    const value = await Promise.resolve(okReply({}));
    return value;
  },
  'passkey-request': async (m, sender) => {
    const value = await passkeyRequest(m.op, m.options, m.frame, sender);
    return value;
  },
};

const frameHello = async (nonce: string, sender: Sender): Promise<Envelope<unknown>> => {
  const frame = frameOf(sender);
  if (frame === undefined) return denied('sender');
  const latest = await readSession(nonce);
  if (latest === undefined || latest.tabId !== frame.tabId) return denied('no-session');
  const info = await withUnlocked(async (client) => {
    const settings = await client.settings();
    const vaults = await client.vaults();
    return { settings, vaults };
  });
  if (!info.ok) return fail(info.error);
  const lang = info.value.settings.language === 'en' ? 'en' : 'ko';
  const names = new Map(
    info.value.vaults.map((v) => [
      v.id,
      v.kind === 'private' && v.name === 'Private'
        ? translate(lang, 'vault.personal')
        : labelOf(v.name),
    ]),
  );
  const split = splitHost(latest.host);
  const isOtp = latest.formKind === 'otp' || latest.formKind === 'otp-split';
  const view =
    latest.mode === 'save'
      ? {
          mode: 'save' as const,
          saveKind: latest.saveKind ?? 'new',
          title: (latest.saveTitle ?? latest.host).slice(0, 200),
          username: (latest.saveUsername ?? '').slice(0, 200),
          vaultLabel: names.get(latest.saveVault ?? '') ?? '',
        }
      : {
          mode: 'menu' as const,
          primary: isOtp ? ('otp' as const) : ('fill' as const),
          canGenerate: latest.canGenerate,
          isFillBlocked: false,
          candidates: latest.candidates.map((c): MenuCandidate => ({
            itemId: c.item,
            title: c.title.slice(0, 200),
            username: c.username.slice(0, 200),
            vaultLabel: names.get(c.vault) ?? '',
            level: c.tier,
            hasOtp: c.hasTotp,
            ...(c.hostToConfirm === undefined ? {} : { hostToConfirm: c.hostToConfirm }),
          })),
        };
  return okReply({
    nonce: latest.nonce,
    originSubdomain: split.subdomain,
    originRegistrable: split.registrable,
    secretTag: info.value.settings.secretTag?.word ?? null,
    secretGlyph: info.value.settings.secretTag?.glyph ?? 0,
    locale: info.value.settings.language === 'en' ? 'en' : 'ko',
    view,
  });
};

const menuPick = async (
  m: Extract<FrameRequest, { kind: 'menu-pick' }>,
  sender: Sender,
): Promise<Envelope<unknown>> => {
  const frame = frameOf(sender);
  if (frame === undefined) return denied('sender');
  const session = await readSession(m.nonce);
  if (session === undefined || session.tabId !== frame.tabId) return denied('no-session');
  const minted = await mintGestureToken(
    sessionStore,
    { tabId: session.tabId, frameId: session.frameId, nonce: m.nonce, itemId: m.itemId },
    Date.now(),
    randomHex(16),
  );
  return minted.ok ? okReply({ token: minted.value }) : denied('storage');
};

const menuDismiss = async (
  m: Extract<FrameRequest, { kind: 'menu-dismiss' }>,
  sender: Sender,
): Promise<Envelope<unknown>> => {
  const frame = frameOf(sender);
  if (frame === undefined) return denied('sender');
  const session = await readSession(m.nonce);
  if (session !== undefined && session.tabId === frame.tabId) await removeKey(menuKey(m.nonce));
  return okReply({});
};

const saveAnswer = async (
  m: Extract<FrameRequest, { kind: 'save-answer' }>,
  sender: Sender,
): Promise<Envelope<unknown>> => {
  const frame = frameOf(sender);
  if (frame === undefined) return denied('sender');
  const session = await readSession(m.nonce);
  if (session === undefined || session.tabId !== frame.tabId || session.mode !== 'save') {
    return denied('no-session');
  }
  await removeKey(menuKey(m.nonce));
  const key = { tabId: session.tabId, site: session.host };
  if (m.answer === 'never') {
    const stored = await readKey(neverSaveKey);
    const list = stored.ok && stored.value !== undefined ? stored.value : [];
    await writeKey(neverSaveKey, [...list, splitHost(session.host).registrable]);
    await clearPending(sessionStore, key);
    return okReply({});
  }
  if (m.answer === 'dismiss') return okReply({});
  const pending = await readPending(sessionStore, key, Date.now());
  const password = pending === undefined ? undefined : submittedPassword(pending);
  if (pending === undefined || password === undefined || session.saveKind === undefined) {
    return denied('no-pending');
  }
  const committed = await withUnlocked(async (client) => {
    const vaults = await client.vaults();
    const vault = session.saveVault ?? vaults.find((v) => v.writable)?.id;
    if (vault === undefined) throw new Error('no-writable-vault');
    const bytes = encodeText(password);
    const ref = await client.commitSave({
      draft: {
        origin: session.origin,
        pageUrl: session.url,
        username: pending.username ?? '',
        password: bytes,
        generated: pending.isGenerated,
      },
      kind: session.saveKind ?? 'new',
      vault,
      item: session.saveItem,
      title: session.saveTitle ?? session.host,
    });
    bytes.fill(0);
    return ref;
  });
  if (!committed.ok) return fail(committed.error);
  await clearPending(sessionStore, key);
  spawn(runSync());
  const generated = await listGenerated(sessionStore, Date.now());
  const match = generated.find((e) => e.value === password && e.site === session.host);
  if (match !== undefined) await markGeneratedSaved(sessionStore, match.id, Date.now());
  return okReply({});
};

export const frameHandlers: {
  [K in FrameKinds]: (
    message: Extract<FrameRequest, { kind: K }>,
    sender: Sender,
  ) => Promise<Envelope<unknown>>;
} = {
  'frame-hello': async (m, sender) => {
    const value = await frameHello(m.nonce, sender);
    return value;
  },
  'menu-pick': menuPick,
  'menu-dismiss': menuDismiss,
  'save-answer': saveAnswer,
};
