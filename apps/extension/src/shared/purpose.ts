import type { FieldPurpose } from '@hasp/autofill';

const enginePurposes = {
  username: 'username',
  password: 'password',
  totp: 'otp',
  'new-password': 'new-password',
  'card-holder': 'cc-name',
  'card-number': 'cc-number',
  'card-expiry': 'cc-exp',
  'card-expiry-month': 'cc-exp-month',
  'card-expiry-year': 'cc-exp-year',
  'card-cvc': 'cc-csc',
  'card-type': 'cc-type',
  name: 'name',
  'given-name': 'given-name',
  'family-name': 'family-name',
  email: 'email',
  phone: 'tel',
  'street-address': 'street-address',
  'address-line1': 'address-line1',
  'address-line2': 'address-line2',
  'postal-code': 'postal-code',
  country: 'country',
} as const satisfies Record<string, FieldPurpose>;

const purposeLookup: ReadonlyMap<string, FieldPurpose> = new Map(Object.entries(enginePurposes));

export const pagePurposeOf = (
  enginePurpose: string,
  requested: readonly FieldPurpose[],
): FieldPurpose | undefined => {
  const mapped = purposeLookup.get(enginePurpose);
  if (mapped === undefined) return undefined;
  if (requested.includes(mapped)) return mapped;
  if (mapped === 'username' && requested.includes('email')) return 'email';
  if (mapped === 'password' && requested.includes('current-password')) return 'current-password';
  return undefined;
};

export type EngineFillKind = 'login' | 'otp' | 'card' | 'identity';

export const fillKindOf = (formKind: string): EngineFillKind | undefined => {
  switch (formKind) {
    case 'login':
    case 'username-only':
    case 'password-only':
    case 'signup':
    case 'change-password':
      return 'login';
    case 'otp':
    case 'otp-split':
      return 'otp';
    case 'card':
      return 'card';
    case 'identity':
    case 'address':
      return 'identity';
    default:
      return undefined;
  }
};
