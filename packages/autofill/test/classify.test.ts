import { beforeEach, describe, expect, it } from 'vitest';

import { classifyPage } from '../src/classify/classify.ts';
import { findOtpGroups } from '../src/classify/otp-group.ts';
import type { FormKind } from '../src/types.ts';
import { field, page, resetFixtures } from './fixtures.ts';

beforeEach(resetFixtures);

const kindOf = (
  fields: ReturnType<typeof field>[],
  texts: string[] = [],
  path: 'none' | 'login' | 'signup' = 'none',
): FormKind => classifyPage(page(fields, { pathHint: path }, texts), {})[0]?.kind ?? 'none';

describe('classifier rules', () => {
  it.each([
    ['username and password', [field({ name: 'username' }), field({ type: 'password' })], 'login'],
    ['password only', [field({ type: 'password', name: 'pw' })], 'password-only'],
    [
      'css masked text as password',
      [field({ name: 'id', label: '아이디' }), field({ name: 'pw', textSecurity: true })],
      'login',
    ],
    [
      'two password fields with confirm',
      [
        field({ name: 'email', type: 'email' }),
        field({ type: 'password', autocomplete: ['new-password'] }),
        field({ type: 'password', placeholder: 'Confirm password' }),
      ],
      'signup',
    ],
    [
      'current and new password',
      [
        field({ type: 'password', autocomplete: ['current-password'] }),
        field({ type: 'password', autocomplete: ['new-password'] }),
      ],
      'change-password',
    ],
    ['search box', [field({ type: 'search', name: 'q' })], 'none'],
    ['one-time-code token', [field({ autocomplete: ['one-time-code'] })], 'otp'],
    [
      'card number',
      [field({ autocomplete: ['cc-number'] }), field({ autocomplete: ['cc-exp'] })],
      'card',
    ],
  ] as const)('%s', (_name, fields, expected) => {
    expect(kindOf([...fields])).toBe(expected);
  });

  it('does not treat a bare email box as username-only without sign-in evidence', () => {
    expect(kindOf([field({ type: 'email', name: 'email' })], ['Subscribe'])).toBe('none');
  });

  it('treats an email box with a continue button as username-only', () => {
    expect(kindOf([field({ type: 'email', name: 'email' })], ['Continue'])).toBe('username-only');
  });

  it('ignores hidden and disabled password fields', () => {
    expect(
      kindOf([
        field({ name: 'username' }),
        field({ type: 'password', visible: false }),
        field({ type: 'password', disabled: true }),
      ]),
    ).toBe('none');
  });

  it('applies a per-site override to a field the rules would skip', () => {
    const user = field({ name: 'x1' });
    const pass = field({ name: 'x2', type: 'text' });
    const classes = classifyPage(page([user, pass]), { username: user.id, password: pass.id });
    expect(classes[0]?.kind).toBe('login');
    expect(classes[0]?.fields.map((f) => f.purpose).toSorted()).toEqual(['password', 'username']);
  });

  it('uses the signup path to classify a single password field as signup', () => {
    expect(
      kindOf(
        [field({ name: 'email', type: 'email' }), field({ type: 'password' })],
        ['Create'],
        'signup',
      ),
    ).toBe('signup');
  });

  it('records evidence for the inspector', () => {
    const classes = classifyPage(
      page([field({ name: 'username' }), field({ type: 'password' })]),
      {},
    );
    expect(classes[0]?.evidence.length).toBeGreaterThan(0);
  });
});

const cells = (n: number, width = 40): ReturnType<typeof field>[] =>
  Array.from({ length: n }, (_, i) =>
    field({ maxlength: 1, rect: { x: 10 + i * 48, y: 100, w: width, h: 44 } }),
  );

describe('split otp detection', () => {
  it.each([4, 6, 8])('finds a %i cell group', (n) => {
    expect(findOtpGroups(cells(n))).toHaveLength(1);
    expect(findOtpGroups(cells(n))[0]).toHaveLength(n);
  });

  it('rejects 3 cells and 9 cells', () => {
    expect(findOtpGroups(cells(3))).toHaveLength(0);
    expect(findOtpGroups(cells(9))).toHaveLength(0);
  });

  it('rejects cells on different rows', () => {
    const fields = cells(6).map((f, i) => ({ ...f, rect: { ...f.rect, y: 100 + i * 40 } }));
    expect(findOtpGroups(fields)).toHaveLength(0);
  });

  it('classifies a group as otp-split and password-typed pin cells as not otp', () => {
    expect(kindOf(cells(6))).toBe('otp-split');
    const pin = cells(4).map((f) => ({ ...f, type: 'password' }));
    expect(kindOf(pin)).not.toBe('otp-split');
  });
});
