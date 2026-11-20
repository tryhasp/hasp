import type { FieldPurpose, FormClass, FormKind } from '../types.ts';
import { isLoginClass } from '../types.ts';

export const MAX_FLOW_STEPS = 5;
export const AWAIT_NAV_TIMEOUT_MS = 10_000;
export const NEEDS_HUMAN_HOLD_MS = 60_000;

export type NeedsHumanReason = 'captcha' | 'error-text' | 'timeout' | 'unknown-field';
export type AbortReason =
  | 'user'
  | 'left-match-set'
  | 'step-limit'
  | 'tab-closed'
  | 'locked'
  | 'fill-refused';

export type FlowState =
  | { kind: 'idle' }
  | { kind: 'detected'; formKind: FormKind }
  | { kind: 'offered'; formKind: FormKind }
  | { kind: 'filling'; step: number; formKind: FormKind }
  | { kind: 'await-nav'; step: number; from: FormKind; deadlineMs: number }
  | { kind: 'needs-human'; reason: NeedsHumanReason; untilMs: number }
  | { kind: 'done' }
  | { kind: 'aborted'; reason: AbortReason };

export type FlowEvent =
  | { kind: 'classified'; formKind: FormKind; hasMatch: boolean }
  | { kind: 'interact' }
  | { kind: 'picked' }
  | { kind: 'escape' }
  | { kind: 'filled'; isAutosubmit: boolean; nowMs: number }
  | { kind: 'fill-failed' }
  | {
      kind: 'snapshot';
      formKind: FormKind;
      hasErrorText: boolean;
      hasCaptcha: boolean;
      isInMatchSet: boolean;
      nowMs: number;
    }
  | { kind: 'tick'; nowMs: number }
  | { kind: 'abort'; reason: AbortReason }
  | { kind: 'completed-manually' };

export const idle: FlowState = { kind: 'idle' };

export const isNextStep = (from: FormKind, to: FormKind): boolean => {
  if (from === 'username-only') return to === 'password-only' || to === 'login';
  if (from === 'login' || from === 'password-only') return to === 'otp' || to === 'otp-split';
  return false;
};

const hasLoginForm = (kind: FormKind): boolean =>
  isLoginClass(kind) || kind === 'otp' || kind === 'otp-split';

export const reduceFlow = (state: FlowState, event: FlowEvent): FlowState => {
  if (event.kind === 'abort') return { kind: 'aborted', reason: event.reason };
  switch (state.kind) {
    case 'idle':
    case 'detected':
      if (event.kind === 'classified') {
        const eligible =
          event.hasMatch && (hasLoginForm(event.formKind) || event.formKind === 'card');
        return eligible ? { kind: 'detected', formKind: event.formKind } : idle;
      }
      if (event.kind === 'interact' && state.kind === 'detected') {
        return { kind: 'offered', formKind: state.formKind };
      }
      return state;
    case 'offered':
      if (event.kind === 'picked') return { kind: 'filling', step: 1, formKind: state.formKind };
      if (event.kind === 'escape') return idle;
      if (event.kind === 'classified' && !event.hasMatch) return idle;
      return state;
    case 'filling':
      if (event.kind === 'filled') {
        return event.isAutosubmit
          ? {
              kind: 'await-nav',
              step: state.step,
              from: state.formKind,
              deadlineMs: event.nowMs + AWAIT_NAV_TIMEOUT_MS,
            }
          : idle;
      }
      if (event.kind === 'fill-failed') return { kind: 'aborted', reason: 'fill-refused' };
      return state;
    case 'await-nav':
      return reduceAwaitNav(state, event);
    case 'needs-human':
      if (event.kind === 'completed-manually') return { kind: 'done' };
      if (event.kind === 'tick' && event.nowMs >= state.untilMs) return idle;
      if (event.kind === 'snapshot' && !hasLoginForm(event.formKind)) return { kind: 'done' };
      return state;
    case 'done':
    case 'aborted':
      return event.kind === 'classified' && state.kind === 'done' ? reduceFlow(idle, event) : state;
  }
};

const reduceAwaitNav = (
  state: Extract<FlowState, { kind: 'await-nav' }>,
  event: FlowEvent,
): FlowState => {
  if (event.kind === 'tick' && event.nowMs >= state.deadlineMs) {
    return { kind: 'needs-human', reason: 'timeout', untilMs: event.nowMs + NEEDS_HUMAN_HOLD_MS };
  }
  if (event.kind !== 'snapshot') return state;
  if (!event.isInMatchSet) return { kind: 'aborted', reason: 'left-match-set' };
  const hold = (reason: NeedsHumanReason): FlowState => ({
    kind: 'needs-human',
    reason,
    untilMs: event.nowMs + NEEDS_HUMAN_HOLD_MS,
  });
  if (event.hasCaptcha) return hold('captcha');
  if (event.hasErrorText) return hold('error-text');
  if (isNextStep(state.from, event.formKind)) {
    const step = state.step + 1;
    if (step > MAX_FLOW_STEPS) return { kind: 'aborted', reason: 'step-limit' };
    return { kind: 'filling', step, formKind: event.formKind };
  }
  if (!hasLoginForm(event.formKind)) return { kind: 'done' };
  return state;
};

export const requestPurposes = (form: FormClass): FieldPurpose[] => {
  const out = new Set<FieldPurpose>();
  for (const a of form.fields) {
    switch (a.purpose) {
      case 'username':
      case 'email':
        out.add('username');
        break;
      case 'password':
      case 'current-password':
        out.add('password');
        break;
      case 'otp':
      case 'otp-cell':
        out.add('otp');
        break;
      case 'cc-number':
      case 'cc-number-part':
        out.add('cc-number');
        break;
      case 'cc-exp':
      case 'cc-exp-month':
      case 'cc-exp-year':
        out.add('cc-exp-month');
        out.add('cc-exp-year');
        break;
      case 'cc-csc':
      case 'cc-name':
      case 'cc-type':
      case 'name':
      case 'given-name':
      case 'family-name':
      case 'tel':
      case 'street-address':
      case 'address-line1':
      case 'address-line2':
      case 'postal-code':
      case 'country':
        out.add(a.purpose);
        break;
      case 'new-password':
      case 'confirm-password':
      case 'submit':
      case 'none':
        break;
    }
  }
  return [...out];
};
