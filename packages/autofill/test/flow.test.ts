import { describe, expect, it } from 'vitest';

import {
  AWAIT_NAV_TIMEOUT_MS,
  MAX_FLOW_STEPS,
  NEEDS_HUMAN_HOLD_MS,
  idle,
  isNextStep,
  reduceFlow,
} from '../src/flow/flow.ts';
import type { FlowEvent, FlowState } from '../src/flow/flow.ts';

const run = (events: FlowEvent[], from: FlowState = idle): FlowState =>
  events.reduce(reduceFlow, from);

const snapshot = (over: Partial<Extract<FlowEvent, { kind: 'snapshot' }>> = {}): FlowEvent => ({
  kind: 'snapshot',
  formKind: 'none',
  hasErrorText: false,
  hasCaptcha: false,
  isInMatchSet: true,
  nowMs: 1000,
  ...over,
});

describe('flow states', () => {
  it('detects a login form only when a match exists', () => {
    expect(run([{ kind: 'classified', formKind: 'login', hasMatch: false }])).toEqual(idle);
    expect(run([{ kind: 'classified', formKind: 'login', hasMatch: true }]).kind).toBe('detected');
  });

  it('goes detected -> offered -> filling -> idle without autosubmit', () => {
    const s = run([
      { kind: 'classified', formKind: 'login', hasMatch: true },
      { kind: 'interact' },
      { kind: 'picked' },
      { kind: 'filled', isAutosubmit: false, nowMs: 0 },
    ]);
    expect(s).toEqual(idle);
  });

  it('escape from offered returns to idle', () => {
    expect(
      run([
        { kind: 'classified', formKind: 'login', hasMatch: true },
        { kind: 'interact' },
        { kind: 'escape' },
      ]),
    ).toEqual(idle);
  });

  it('username-first: autosubmit awaits navigation and continues with password-only', () => {
    const s = run([
      { kind: 'classified', formKind: 'username-only', hasMatch: true },
      { kind: 'interact' },
      { kind: 'picked' },
      { kind: 'filled', isAutosubmit: true, nowMs: 0 },
      snapshot({ formKind: 'password-only' }),
    ]);
    expect(s).toEqual({ kind: 'filling', step: 2, formKind: 'password-only' });
  });

  it('password then otp shares the flow', () => {
    const s = run([
      { kind: 'classified', formKind: 'login', hasMatch: true },
      { kind: 'interact' },
      { kind: 'picked' },
      { kind: 'filled', isAutosubmit: true, nowMs: 0 },
      snapshot({ formKind: 'otp-split' }),
    ]);
    expect(s).toEqual({ kind: 'filling', step: 2, formKind: 'otp-split' });
  });

  it('times out into needs-human after 10 s and holds 60 s', () => {
    const waiting: FlowState = {
      kind: 'await-nav',
      step: 1,
      from: 'login',
      deadlineMs: AWAIT_NAV_TIMEOUT_MS,
    };
    const held = reduceFlow(waiting, { kind: 'tick', nowMs: AWAIT_NAV_TIMEOUT_MS });
    expect(held).toEqual({
      kind: 'needs-human',
      reason: 'timeout',
      untilMs: AWAIT_NAV_TIMEOUT_MS + NEEDS_HUMAN_HOLD_MS,
    });
    expect(
      reduceFlow(held, { kind: 'tick', nowMs: AWAIT_NAV_TIMEOUT_MS + NEEDS_HUMAN_HOLD_MS }),
    ).toEqual(idle);
  });

  it.each([
    ['captcha', snapshot({ hasCaptcha: true }), 'captcha'],
    ['error text', snapshot({ hasErrorText: true }), 'error-text'],
  ] as const)('%s needs a human', (_n, event, reason) => {
    const waiting: FlowState = { kind: 'await-nav', step: 1, from: 'login', deadlineMs: 99999 };
    expect(reduceFlow(waiting, event)).toMatchObject({ kind: 'needs-human', reason });
  });

  it('manual completion resumes to done', () => {
    const held: FlowState = { kind: 'needs-human', reason: 'captcha', untilMs: 99999 };
    expect(reduceFlow(held, { kind: 'completed-manually' })).toEqual({ kind: 'done' });
    expect(reduceFlow(held, snapshot({ formKind: 'none' }))).toEqual({ kind: 'done' });
  });

  it('login form gone after submit is done', () => {
    const waiting: FlowState = { kind: 'await-nav', step: 1, from: 'login', deadlineMs: 99999 };
    expect(reduceFlow(waiting, snapshot({ formKind: 'none' }))).toEqual({ kind: 'done' });
  });

  it('aborts when the origin leaves the match set', () => {
    const waiting: FlowState = { kind: 'await-nav', step: 1, from: 'login', deadlineMs: 99999 };
    expect(reduceFlow(waiting, snapshot({ isInMatchSet: false }))).toEqual({
      kind: 'aborted',
      reason: 'left-match-set',
    });
  });

  it('aborts after the fifth step', () => {
    const waiting: FlowState = {
      kind: 'await-nav',
      step: MAX_FLOW_STEPS,
      from: 'username-only',
      deadlineMs: 99999,
    };
    expect(reduceFlow(waiting, snapshot({ formKind: 'password-only' }))).toEqual({
      kind: 'aborted',
      reason: 'step-limit',
    });
  });

  it.each(['user', 'locked', 'tab-closed'] as const)('abort %s clears from any state', (reason) => {
    expect(
      reduceFlow({ kind: 'filling', step: 1, formKind: 'login' }, { kind: 'abort', reason }),
    ).toEqual({ kind: 'aborted', reason });
  });

  it('a refused fill aborts the flow', () => {
    expect(
      reduceFlow({ kind: 'filling', step: 1, formKind: 'login' }, { kind: 'fill-failed' }),
    ).toEqual({ kind: 'aborted', reason: 'fill-refused' });
  });

  it.each([
    ['username-only', 'password-only', true],
    ['login', 'otp', true],
    ['login', 'password-only', false],
    ['card', 'otp', false],
  ] as const)('next step %s -> %s is %s', (from, to, expected) => {
    expect(isNextStep(from, to)).toBe(expected);
  });
});
