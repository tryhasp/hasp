import type { Frame, Page } from '@playwright/test';

import {
  capturePending,
  clearPending,
  consumeGestureToken,
  contentRequestSchema,
  decideSaveKind,
  frameRequestSchema,
  markGeneratedUnverified,
  markGeneratedSaved,
  markSubmitted,
  mintGestureToken,
  readPending,
  submittedPassword,
  recordGenerated,
  verifyFillRequest,
} from '../src/index.ts';
import type { ContentRequest, FrameRequest, PageConfig, SessionStore } from '../src/index.ts';
import { decideStepUp } from '../src/policy/step-up.ts';
import type { StepUp } from '../src/policy/step-up.ts';
import type { FieldPurpose, FormKind } from '../src/types.ts';

export type BindingSource = { frame: Frame; page: Page };

export type VaultItem = {
  itemId: string;
  title: string;
  username: string;
  password: string;
  host: string;
  relatedHosts?: string[];
  otp?: string;
  card?: { number: string; month: string; year: string; csc: string; name: string };
  confirmedHost?: boolean;
};

export type FillRecord = { itemId: string; purposes: FieldPurpose[]; host: string };

export type FakeBackground = {
  handle: (source: BindingSource, raw: string) => Promise<string>;
  fills: FillRecord[];
  strikes: { count: number; check: string }[];
  refusals: string[];
  saved: { username: string; password: string }[];
  stepUps: StepUp[];
  captures: number;
  handoff: unknown;
  config: { value: PageConfig };
  options: {
    isAutosubmit: boolean;
    isTabFocused: boolean;
    isUnlocked: boolean;
    isC4Forced: boolean | undefined;
    isSubmitMessageLost: boolean;
  };
  items: VaultItem[];
  store: SessionStore;
  clock: { nowMs: number };
  requests: string[];
  hooks: { beforeFillReply: (() => Promise<void>) | undefined };
  armPush: (
    page: Page,
    itemId: string,
  ) => Promise<{ nonce: string; itemId: string; token: string }>;
};

type MenuSession = {
  nonce: string;
  frameKey: string;
  host: string;
  origin: string;
  formKind: FormKind;
  candidates: { item: VaultItem; level: 'exact' | 'domain' | 'related' }[];
  mode: 'menu' | 'save';
  saveKind?: 'new' | 'update';
};

const memoryStore = (): SessionStore => {
  const data = new Map<string, unknown>();
  return {
    get: async (key) => {
      await Promise.resolve();
      return data.get(key);
    },
    set: async (key, value) => {
      await Promise.resolve();
      data.set(key, structuredClone(value));
      return { ok: true as const, value: null };
    },
    remove: async (key) => {
      await Promise.resolve();
      data.delete(key);
    },
  };
};

const ok = (value: unknown): string => JSON.stringify({ ok: true, value });
const denied = (reason: string): string =>
  JSON.stringify({ ok: false, error: { kind: 'denied', reason } });

let counter = 0;
const randomToken = (): string => {
  counter += 1;
  return `tok-${counter.toString().padStart(6, '0')}-${Math.random().toString(36).slice(2, 12)}`;
};

const lastTwo = (host: string): string => host.split('.').slice(-2).join('.');

const frameKey = (source: BindingSource): string =>
  source.frame.url() + '#' + String(source.page.frames().indexOf(source.frame));
const hostOf = (source: BindingSource): string => new URL(source.frame.url()).hostname;
const isTop = (source: BindingSource): boolean => source.frame.parentFrame() === null;

const frameKindOf = (source: BindingSource): 'top' | 'same-origin' | 'cross-origin' => {
  if (isTop(source)) return 'top';
  const top = source.page.mainFrame();
  return new URL(top.url()).origin === new URL(source.frame.url()).origin
    ? 'same-origin'
    : 'cross-origin';
};

export const createFakeBackground = (items: VaultItem[]): FakeBackground => {
  const sessions = new Map<string, MenuSession>();
  const store = memoryStore();
  const flow: { itemId?: string; host?: string } = {};
  const state: FakeBackground = {
    handle: async () => {
      await Promise.resolve();
      return '';
    },
    fills: [],
    strikes: [],
    refusals: [],
    saved: [],
    stepUps: [],
    captures: 0,
    handoff: undefined,
    config: { value: { quirks: {}, selectors: {}, userSelectors: {}, relatedDomains: [] } },
    options: {
      isAutosubmit: false,
      isTabFocused: true,
      isUnlocked: true,
      isC4Forced: undefined,
      isSubmitMessageLost: false,
    },
    items,
    store,
    clock: { nowMs: 0 },
    requests: [],
    hooks: { beforeFillReply: undefined },
    armPush: async (page, itemId) => {
      const nonce = randomToken();
      const token = randomToken();
      const url = new URL(page.mainFrame().url());
      sessions.set(nonce, {
        nonce,
        frameKey: frameKey({ frame: page.mainFrame(), page }),
        host: url.hostname,
        origin: url.origin,
        formKind: 'login',
        candidates: candidatesFor(url.hostname),
        mode: 'menu',
      });
      await mintGestureToken(store, { tabId: 1, frameId: 0, nonce, itemId }, now(), token);
      return { nonce, itemId, token };
    },
  };
  const now = (): number => (state.clock.nowMs > 0 ? state.clock.nowMs : Date.now());
  const candidatesFor = (host: string): MenuSession['candidates'] =>
    state.items.flatMap((item): MenuSession['candidates'] => {
      if (item.host === host) return [{ item, level: 'exact' as const }];
      if (item.relatedHosts?.includes(host) === true) return [{ item, level: 'related' as const }];
      if (lastTwo(item.host) === lastTwo(host)) return [{ item, level: 'domain' as const }];
      return [];
    });

  const handleContent = async (source: BindingSource, msg: ContentRequest): Promise<string> => {
    const host = hostOf(source);
    state.requests.push(msg.kind);
    if (
      state.options.isSubmitMessageLost &&
      (msg.kind === 'capture' || (msg.kind === 'submit-signal' && msg.outcome === 'pending'))
    ) {
      throw new Error('message lost');
    }
    switch (msg.kind) {
      case 'page-config':
        return ok(state.config.value);
      case 'menu-open': {
        const cands = candidatesFor(host);
        const isLogin =
          msg.formKind === 'login' ||
          msg.formKind === 'username-only' ||
          msg.formKind === 'password-only';
        const isOtp = msg.formKind === 'otp' || msg.formKind === 'otp-split';
        const isCard = msg.formKind === 'card';
        const isGen = msg.formKind === 'signup' || msg.formKind === 'change-password';
        if (!state.options.isUnlocked) return ok({ decision: 'none', reason: 'locked' });
        if (cands.length === 0 && !isGen) return ok({ decision: 'none', reason: 'no-match' });
        const first = cands[0];
        const stepUp = decideStepUp({
          fill: isCard ? 'card' : isOtp ? 'otp' : 'password',
          frame: frameKindOf(source),
          level: first?.level ?? 'exact',
          isHostConfirmed: first?.item.confirmedHost === true,
          isCardHostRemembered: false,
          isObscured: msg.isObscured,
          isC4Supported: state.options.isC4Forced ?? msg.isC4Supported,
          settings: { isAskBeforeFilling: false },
        });
        state.stepUps.push(stepUp);
        if (!isLogin && !isOtp && !isCard && !isGen)
          return ok({ decision: 'none', reason: 'kind' });
        if (stepUp.kind === 'refuse') return ok({ decision: 'none', reason: stepUp.reason });
        if (stepUp.kind === 'browser-ui') return ok({ decision: 'browser-ui' });
        const nonce = randomToken();
        sessions.set(nonce, {
          nonce,
          frameKey: frameKey(source),
          host,
          origin: new URL(source.frame.url()).origin,
          formKind: msg.formKind,
          candidates: cands,
          mode: 'menu',
        });
        return ok({ decision: 'inline', nonce });
      }
      case 'fill-request': {
        const session = sessions.get(msg.nonce);
        if (session === undefined) return denied('no-session');
        if (session.origin !== new URL(source.frame.url()).origin) {
          state.refusals.push('origin-changed');
          return denied('no-session');
        }
        const consumed = await consumeGestureToken(
          store,
          msg.token,
          { tabId: 1, frameId: 0, nonce: msg.nonce, itemId: msg.itemId },
          now(),
        );
        const gate = verifyFillRequest({
          isUnlocked: state.options.isUnlocked,
          isTabActiveAndFocused: state.options.isTabFocused,
          isSenderBoundFrame: frameKey(source) === session.frameKey,
          isTokenAccepted: consumed.ok,
          attestation: msg.attestation,
          nowMs: now(),
        });
        if (!gate.ok) {
          state.refusals.push(gate.error);
          return ok({ kind: 'refused', reason: gate.error });
        }
        const cand = session.candidates.find((c) => c.item.itemId === msg.itemId);
        if (cand === undefined) return denied('no-item');
        const fields = fieldsFor(cand.item, msg.purposes);
        state.fills.push({ itemId: cand.item.itemId, purposes: msg.purposes, host });
        flow.itemId = cand.item.itemId;
        flow.host = host;
        await state.hooks.beforeFillReply?.();
        return ok({
          kind: 'payload',
          fields,
          isAutosubmit: state.options.isAutosubmit,
          isPerCharEvents: false,
        });
      }
      case 'fill-continue': {
        if (
          flow.itemId === undefined ||
          flow.host === undefined ||
          lastTwo(flow.host) !== lastTwo(host)
        ) {
          state.refusals.push('left-match-set');
          return ok({ kind: 'refused', reason: 'left-match-set' });
        }
        const item = state.items.find((i) => i.itemId === flow.itemId);
        if (item === undefined) return denied('no-item');
        state.fills.push({ itemId: item.itemId, purposes: msg.purposes, host });
        return ok({
          kind: 'payload',
          fields: fieldsFor(item, msg.purposes),
          isAutosubmit: false,
          isPerCharEvents: false,
        });
      }
      case 'capture': {
        state.captures += 1;
        await capturePending(
          store,
          { tabId: 1, site: host },
          {
            ...(msg.values.username === undefined ? {} : { username: msg.values.username }),
            ...(msg.values.password === undefined ? {} : { password: msg.values.password }),
            ...(msg.values.newPassword === undefined
              ? {}
              : { newPassword: msg.values.newPassword }),
          },
          now(),
        );
        return ok({});
      }
      case 'submit-signal': {
        const key = { tabId: 1, site: host };
        if (msg.outcome === 'pending') {
          await markSubmitted(store, key, now(), msg.formKind);
          return ok({ kind: 'none' });
        }
        if (msg.wasSubmitted === true) {
          if (msg.handoff !== undefined) await capturePending(store, key, msg.handoff, now());
          await markSubmitted(store, key, now(), msg.formKind);
        }
        const pending = await readPending(store, key, now());
        if (msg.outcome === 'error-text' || pending === undefined || !pending.isSubmitted) {
          await clearPending(store, key);
          return ok({ kind: 'none' });
        }
        const username = pending.username;
        const saveKind = decideSaveKind({
          username,
          isChangeForm: false,
          matches: candidatesFor(host).map((c) => ({
            username: c.item.username,
            isSamePassword: c.item.password === submittedPassword(pending),
          })),
          suppression: state.config.value.quirks.skip_save === true ? 'skip-save-quirk' : undefined,
        });
        if (saveKind === 'none') return ok({ kind: 'none' });
        const nonce = randomToken();
        sessions.set(nonce, {
          nonce,
          frameKey: frameKey(source),
          host,
          origin: new URL(source.frame.url()).origin,
          formKind: 'login',
          candidates: [],
          mode: 'save',
          saveKind,
        });
        return ok({ kind: 'prompt', nonce });
      }
      case 'generate': {
        const value = 'Qx7!kM2-pR9#vT4s'.slice(0, msg.rules.maxlength ?? 16);
        await recordGenerated(store, { id: randomToken(), value, site: host, atMs: now() }, now());
        return ok({ value, length: value.length });
      }
      case 'generated-verified': {
        if (!msg.isMatch) {
          const list = await store.get('generated');
          if (Array.isArray(list)) {
            const last: unknown = list.at(-1);
            if (typeof last === 'object' && last !== null) {
              const id: unknown = Reflect.get(last, 'id');
              if (typeof id === 'string') await markGeneratedUnverified(store, id, now());
            }
          }
        }
        return ok({});
      }
      case 'strike':
        state.strikes.push({ count: msg.count, check: msg.check });
        return ok({});
      case 'teach':
        return ok({});
      case 'passkey-request':
        return ok({
          payload: JSON.stringify({
            id: 'AQID',
            rawId: 'AQID',
            response: { clientDataJSON: 'e30', authenticatorData: 'AQID', signature: 'AQID' },
          }),
        });
    }
  };

  const fieldsFor = (
    item: VaultItem,
    purposes: readonly FieldPurpose[],
  ): { purpose: FieldPurpose; value: string }[] => {
    const out: { purpose: FieldPurpose; value: string }[] = [];
    for (const p of purposes) {
      if (p === 'username') out.push({ purpose: p, value: item.username });
      if (p === 'password') out.push({ purpose: p, value: item.password });
      if (p === 'otp' && item.otp !== undefined) out.push({ purpose: p, value: item.otp });
      if (item.card !== undefined) {
        if (p === 'cc-number') out.push({ purpose: p, value: item.card.number });
        if (p === 'cc-exp-month') out.push({ purpose: p, value: item.card.month });
        if (p === 'cc-exp-year') out.push({ purpose: p, value: item.card.year });
        if (p === 'cc-csc') out.push({ purpose: p, value: item.card.csc });
        if (p === 'cc-name') out.push({ purpose: p, value: item.card.name });
      }
    }
    return out;
  };

  const handleFrame = async (source: BindingSource, msg: FrameRequest): Promise<string> => {
    const parent = source.frame.parentFrame();
    if (parent === null) return denied('not-a-frame');
    const parentKey = parent.url() + '#' + String(source.page.frames().indexOf(parent));
    const sessionsList = [...sessions.values()].filter((s) => s.frameKey === parentKey);
    const latest =
      msg.kind === 'frame-hello'
        ? sessionsList.find((s) => s.nonce === msg.nonce)
        : sessionsList.at(-1);
    switch (msg.kind) {
      case 'frame-hello': {
        if (latest === undefined) return denied('no-session');
        const labels = latest.host.split('.');
        const registrable = labels.length > 2 ? labels.slice(-2).join('.') : latest.host;
        const sub = labels.length > 2 ? labels.slice(0, -2).join('.') : '';
        const view =
          latest.mode === 'save'
            ? {
                mode: 'save',
                saveKind: latest.saveKind ?? 'new',
                title: latest.host,
                username: 'user',
                vaultLabel: '개인',
              }
            : {
                mode: 'menu',
                primary:
                  latest.formKind === 'otp' || latest.formKind === 'otp-split' ? 'otp' : 'fill',
                canGenerate: true,
                isFillBlocked: false,
                candidates: latest.candidates.map((c) => ({
                  itemId: c.item.itemId,
                  title: c.item.title,
                  username: c.item.username,
                  vaultLabel: '개인',
                  level: c.level,
                  ...(c.level === 'exact' ? {} : { hostToConfirm: latest.host }),
                  hasOtp: c.item.otp !== undefined,
                })),
              };
        return ok({
          nonce: latest.nonce,
          originSubdomain: sub,
          originRegistrable: registrable,
          secretTag: '등대',
          secretGlyph: 5,
          locale: 'ko',
          view,
        });
      }
      case 'menu-pick': {
        const s = sessions.get(msg.nonce);
        if (s === undefined || s.frameKey !== parentKey) return denied('no-session');
        const minted = await mintGestureToken(
          store,
          { tabId: 1, frameId: 0, nonce: msg.nonce, itemId: msg.itemId },
          now(),
          randomToken(),
        );
        return minted.ok ? ok({ token: minted.value }) : denied('storage');
      }
      case 'menu-dismiss':
        sessions.delete(msg.nonce);
        return ok({});
      case 'save-answer': {
        const s = sessions.get(msg.nonce);
        if (s === undefined) return denied('no-session');
        if (msg.answer === 'save' || msg.answer === 'update') {
          const pending = await readPending(store, { tabId: 1, site: s.host }, now());
          state.saved.push({
            username: pending?.username ?? '',
            password: pending?.newPassword ?? pending?.password ?? '',
          });
          await clearPending(store, { tabId: 1, site: s.host });
          await markGeneratedSaved(store, 'none', now());
        }
        return ok({});
      }
    }
  };

  state.handle = async (source, raw) => {
    let parsedJson: unknown;
    try {
      parsedJson = JSON.parse(raw);
    } catch {
      return denied('json');
    }
    const fromFrame = !isTop(source) && source.frame.url().startsWith('http://127.0.0.1:4174');
    if (fromFrame) {
      const m = frameRequestSchema.safeParse(parsedJson);
      const reply = m.success ? await handleFrame(source, m.data) : denied('schema');
      return reply;
    }
    const m = contentRequestSchema.safeParse(parsedJson);
    const reply = m.success ? await handleContent(source, m.data) : denied('schema');
    return reply;
  };
  return state;
};
