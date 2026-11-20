import { fieldPurposes } from '../types.ts';
import type { FieldPurpose, FieldSnap } from '../types.ts';
import {
  AUTOCOMPLETE_WEIGHT,
  NEARBY_FACTOR,
  TYPE_WEIGHT,
  autocompletePurposes,
  textRules,
} from './rules.ts';

export type FieldScore = {
  scores: Partial<Record<FieldPurpose, number>>;
  why: Partial<Record<FieldPurpose, string[]>>;
};

const textInputTypes: ReadonlySet<string> = new Set([
  '',
  'text',
  'email',
  'tel',
  'password',
  'number',
  'url',
  'search',
]);
const selectPurposes: ReadonlySet<FieldPurpose> = new Set([
  'cc-exp-month',
  'cc-exp-year',
  'cc-exp',
  'cc-type',
  'country',
  'none',
]);

export const normalizeText = (text: string): string =>
  text
    .normalize('NFC')
    .toLowerCase()
    .replace(/[_\-.[\]:/]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

export const isFillableInput = (f: FieldSnap): boolean => {
  if (f.tag === 'button' || !f.visible || f.disabled) return false;
  if (f.tag === 'textarea') return false;
  if (f.tag === 'select') return true;
  return textInputTypes.has(f.type);
};

export const isPasswordLike = (f: FieldSnap): boolean =>
  f.tag === 'input' &&
  (f.type === 'password' ||
    f.textSecurity ||
    f.autocomplete.includes('current-password') ||
    f.autocomplete.includes('new-password'));

const add = (r: FieldScore, purpose: FieldPurpose, weight: number, why: string): void => {
  r.scores[purpose] = (r.scores[purpose] ?? 0) + weight;
  (r.why[purpose] ??= []).push(why);
};

export const scoreField = (f: FieldSnap): FieldScore => {
  const r: FieldScore = { scores: {}, why: {} };
  for (const token of f.autocomplete) {
    const purpose = autocompletePurposes[token];
    if (purpose !== undefined) add(r, purpose, AUTOCOMPLETE_WEIGHT, `autocomplete:${token}`);
    if (token === 'webauthn') add(r, 'username', 4, 'autocomplete:webauthn');
  }
  if (f.type === 'password') add(r, 'password', TYPE_WEIGHT, 'type:password');
  if (f.type === 'email') add(r, 'email', TYPE_WEIGHT, 'type:email');
  if (f.type === 'tel') add(r, 'tel', 6, 'type:tel');
  if (f.type === 'search') add(r, 'none', 14, 'type:search');
  if (f.textSecurity && f.type !== 'password') add(r, 'password', 7, 'text-security');
  const own = [f.name, f.domId, f.label, f.placeholder, f.ariaLabel].map(normalizeText);
  const nearby = normalizeText(f.nearbyText);
  for (const rule of textRules) {
    let hit = 0;
    for (const text of own) if (text !== '' && rule.pattern.test(text)) hit += rule.weight;
    if (nearby !== '' && rule.pattern.test(nearby)) hit += rule.weight * NEARBY_FACTOR;
    if (hit > 0) add(r, rule.purpose, Math.min(hit, rule.weight * 2), 'text');
  }
  if (f.tag === 'select') {
    for (const purpose of fieldPurposes) {
      if (!selectPurposes.has(purpose)) delete r.scores[purpose];
    }
  }
  return r;
};

export const best = (
  s: FieldScore,
  purposes: readonly FieldPurpose[],
): { purpose: FieldPurpose; score: number } | undefined => {
  let top: { purpose: FieldPurpose; score: number } | undefined;
  for (const purpose of purposes) {
    const score = s.scores[purpose] ?? 0;
    if (score > (top?.score ?? 0)) top = { purpose, score };
  }
  return top;
};
