import { describe, expect, it } from 'vitest';

import { fillKindOf, pagePurposeOf } from './purpose.ts';

describe('pagePurposeOf', () => {
  it.each([
    { engine: 'username', requested: ['username'], expected: 'username' },
    { engine: 'username', requested: ['email'], expected: 'email' },
    { engine: 'password', requested: ['password'], expected: 'password' },
    { engine: 'password', requested: ['current-password'], expected: 'current-password' },
    { engine: 'totp', requested: ['otp'], expected: 'otp' },
    { engine: 'card-cvc', requested: ['cc-csc'], expected: 'cc-csc' },
    { engine: 'card-number', requested: ['cc-number'], expected: 'cc-number' },
    { engine: 'password', requested: ['username'], expected: undefined },
    { engine: 'ssh-private-key', requested: ['password'], expected: undefined },
  ] as const)('maps $engine into $requested', ({ engine, requested, expected }) => {
    expect(pagePurposeOf(engine, requested)).toBe(expected);
  });
});

describe('fillKindOf', () => {
  it.each([
    { form: 'login', kind: 'login' },
    { form: 'signup', kind: 'login' },
    { form: 'otp-split', kind: 'otp' },
    { form: 'card', kind: 'card' },
    { form: 'address', kind: 'identity' },
    { form: 'none', kind: undefined },
  ])('maps the form $form', ({ form, kind }) => {
    expect(fillKindOf(form)).toBe(kind);
  });
});
