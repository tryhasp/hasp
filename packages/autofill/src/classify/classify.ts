import type { FieldId } from '../brand.ts';
import type {
  FieldAssignment,
  FieldPurpose,
  FieldSnap,
  FormClass,
  FormKind,
  FormSnap,
  PageSnap,
} from '../types.ts';
import { findOtpGroups } from './otp-group.ts';
import {
  pathChange,
  submitChange,
  submitContinue,
  submitLogin,
  submitSignup,
  submitSubscribe,
} from './rules.ts';
import {
  best,
  isFillableInput,
  isPasswordLike,
  normalizeText,
  scoreField,
  type FieldScore,
} from './score.ts';

export type PurposeOverrides = {
  username?: FieldId;
  password?: FieldId;
  otp?: FieldId;
};

const MIN_SCORE = 5;
const STRONG_SCORE = 7;
const OVERRIDE_SCORE = 99;
const MAX_POSITIONAL_TEXT_FIELDS = 3;
const identityPurposes: readonly FieldPurpose[] = [
  'name',
  'given-name',
  'family-name',
  'tel',
  'email',
];
const addressPurposes: readonly FieldPurpose[] = [
  'street-address',
  'address-line1',
  'address-line2',
  'postal-code',
  'country',
];
const cardPurposes: readonly FieldPurpose[] = [
  'cc-number',
  'cc-exp',
  'cc-exp-month',
  'cc-exp-year',
  'cc-csc',
  'cc-name',
];

type Scored = { field: FieldSnap; score: FieldScore };

const hasText = (texts: readonly string[], pattern: RegExp): boolean =>
  texts.some((t) => pattern.test(normalizeText(t)));

const applyOverrides = (
  scored: Scored[],
  overrides: PurposeOverrides,
): { forcedPasswords: Set<FieldId>; forced: boolean } => {
  const forcedPasswords = new Set<FieldId>();
  let forced = false;
  for (const s of scored) {
    const id = s.field.id;
    if (overrides.username === id) {
      s.score.scores.username = OVERRIDE_SCORE;
      s.score.why.username = ['override'];
      forced = true;
    }
    if (overrides.password === id) {
      s.score.scores.password = OVERRIDE_SCORE;
      s.score.why.password = ['override'];
      forcedPasswords.add(id);
      forced = true;
    }
    if (overrides.otp === id) {
      s.score.scores.otp = OVERRIDE_SCORE;
      s.score.why.otp = ['override'];
      forced = true;
    }
  }
  return { forcedPasswords, forced };
};

const pickSubmit = (form: FormSnap, fields: readonly FieldSnap[]): FieldId | undefined => {
  const buttons = fields.filter((f) => f.tag === 'button' && f.visible && !f.disabled);
  const preferred = buttons.find((b) => b.type === 'submit' || b.type === '');
  return (preferred ?? buttons[0])?.id ?? (form.submitTexts.length > 0 ? undefined : undefined);
};

const assignment = (id: FieldId, purpose: FieldPurpose, score: number): FieldAssignment => ({
  id,
  purpose,
  score,
});

export const classifyForm = (
  form: FormSnap,
  page: PageSnap,
  overrides: PurposeOverrides,
): FormClass => {
  const fields = form.fieldIds
    .map((id) => page.fields.find((f) => f.id === id))
    .filter((f): f is FieldSnap => f !== undefined);
  const inputs = fields.filter(isFillableInput);
  const scored: Scored[] = inputs.map((field) => ({ field, score: scoreField(field) }));
  const { forcedPasswords, forced } = applyOverrides(scored, overrides);
  const submit = pickSubmit(form, fields);
  const evidence: string[] = [];
  const base = { formId: form.id, ...(submit === undefined ? {} : { submit }) };
  const done = (kind: FormKind, confidence: number, assigned: FieldAssignment[]): FormClass => ({
    ...base,
    kind,
    confidence,
    fields: assigned,
    evidence,
  });
  const none = (why: string): FormClass => {
    evidence.push(why);
    return done('none', 0, []);
  };

  const submitTexts = form.submitTexts;
  const isSignupText = hasText(submitTexts, submitSignup);
  const isLoginText = hasText(submitTexts, submitLogin);
  const isChangeText = hasText(submitTexts, submitChange);
  const isContinueText = hasText(submitTexts, submitContinue);
  const isSubscribeText = hasText(submitTexts, submitSubscribe);

  const noneScore = (s: Scored): number => s.score.scores.none ?? 0;
  const live = scored.filter((s) => noneScore(s) < 12 || forced);
  const passwordFields = live.filter(
    (s) =>
      forcedPasswords.has(s.field.id) ||
      (isPasswordLike(s.field) &&
        (s.field.type === 'password' || (s.score.scores.password ?? 0) >= MIN_SCORE)),
  );

  const groups = findOtpGroups(inputs).filter((g) => g.every((id) => form.fieldIds.includes(id)));
  const cardParts = findCardParts(inputs, scored);
  const cardFields = live.filter(
    (s) => (best(s.score, cardPurposes)?.score ?? 0) >= MIN_SCORE && !isPasswordLike(s.field),
  );
  const cardNumber = cardFields.find((s) => best(s.score, ['cc-number'])?.score);
  if ((cardNumber !== undefined || cardParts.length > 0) && passwordFields.length === 0) {
    const assigned: FieldAssignment[] = [];
    for (const s of cardFields) {
      if (cardParts.includes(s.field.id)) continue;
      const top = best(s.score, cardPurposes);
      if (top !== undefined) assigned.push(assignment(s.field.id, top.purpose, top.score));
    }
    for (const part of cardParts) assigned.push(assignment(part, 'cc-number-part', STRONG_SCORE));
    const strongNumber = (cardNumber?.score.scores['cc-number'] ?? 0) >= STRONG_SCORE;
    if (assigned.length >= 2 || strongNumber) {
      evidence.push('card-fields');
      return done('card', 0.9, assigned);
    }
  }

  if (passwordFields.length === 0 && groups.length > 0) {
    const first = groups[0];
    const cellsLookLikePin = first !== undefined && cellsAreSecretPin(first, scored);
    if (first !== undefined && !cellsLookLikePin) {
      evidence.push('otp-cell-group');
      return done(
        'otp-split',
        0.9,
        first.map((id) => assignment(id, 'otp-cell', STRONG_SCORE)),
      );
    }
  }

  if (passwordFields.length === 0) {
    const otp = live
      .filter((s) => (s.score.scores.otp ?? 0) >= MIN_SCORE)
      .toSorted((a, b) => (b.score.scores.otp ?? 0) - (a.score.scores.otp ?? 0))[0];
    if (otp !== undefined) {
      evidence.push(...(otp.score.why.otp ?? []));
      return done('otp', 0.9, [assignment(otp.field.id, 'otp', otp.score.scores.otp ?? 0)]);
    }
  }

  if (passwordFields.length >= 1 && passwordFields.length <= 3) {
    return classifyPasswordForm({
      page,
      live,
      passwordFields,
      flags: { isSignupText, isLoginText, isChangeText },
      done,
      evidence,
    });
  }
  if (passwordFields.length > 3) return none('too-many-password-fields');

  const addressScored = live
    .map((s) => ({ s, top: best(s.score, addressPurposes) }))
    .filter((x) => (x.top?.score ?? 0) >= MIN_SCORE);
  const identityScored = live
    .map((s) => ({ s, top: best(s.score, identityPurposes) }))
    .filter((x) => (x.top?.score ?? 0) >= MIN_SCORE);
  if (addressScored.length >= 2) {
    evidence.push('address-fields');
    const assigned: FieldAssignment[] = [];
    for (const x of [...addressScored, ...identityScored]) {
      if (x.top !== undefined && !assigned.some((a) => a.id === x.s.field.id)) {
        assigned.push(assignment(x.s.field.id, x.top.purpose, x.top.score));
      }
    }
    return done('address', 0.8, assigned);
  }

  const usernameField = live
    .filter((s) => !isPasswordLike(s.field) && s.field.tag === 'input')
    .map((s) => ({ s, top: best(s.score, ['username', 'email']) }))
    .filter((x) => (x.top?.score ?? 0) >= MIN_SCORE)
    .toSorted((a, b) => (b.top?.score ?? 0) - (a.top?.score ?? 0))[0];
  const textFieldCount = live.filter((s) => s.field.tag === 'input').length;
  const loginish =
    page.pathHint === 'login' ||
    isLoginText ||
    isContinueText ||
    usernameField?.s.score.why.username?.includes('autocomplete:username') === true ||
    usernameField?.s.score.why.username?.includes('autocomplete:webauthn') === true ||
    usernameField?.s.score.why.username?.includes('override') === true;
  if (
    usernameField?.top !== undefined &&
    textFieldCount <= 2 &&
    page.pathHint !== 'signup' &&
    !isSignupText &&
    !isSubscribeText &&
    loginish &&
    identityScored.length < 3
  ) {
    evidence.push('username-only', ...(usernameField.s.score.why[usernameField.top.purpose] ?? []));
    return done('username-only', 0.8, [
      assignment(usernameField.s.field.id, 'username', usernameField.top.score),
    ]);
  }
  if (identityScored.length >= 2) {
    evidence.push('identity-fields');
    return done(
      'identity',
      0.75,
      identityScored.flatMap((x) =>
        x.top === undefined ? [] : [assignment(x.s.field.id, x.top.purpose, x.top.score)],
      ),
    );
  }
  return none('no-signal');
};

type PasswordFormInput = {
  page: PageSnap;
  live: readonly Scored[];
  passwordFields: readonly Scored[];
  flags: { isSignupText: boolean; isLoginText: boolean; isChangeText: boolean };
  done: (kind: FormKind, confidence: number, assigned: FieldAssignment[]) => FormClass;
  evidence: string[];
};

const roleOf = (s: Scored): FieldPurpose => {
  const sc = s.score.scores;
  if ((sc['confirm-password'] ?? 0) >= 9) return 'confirm-password';
  if ((sc['current-password'] ?? 0) >= STRONG_SCORE) return 'current-password';
  if ((sc['new-password'] ?? 0) >= STRONG_SCORE) return 'new-password';
  return 'password';
};

const classifyPasswordForm = (input: PasswordFormInput): FormClass => {
  const { page, live, passwordFields, flags, done, evidence } = input;
  const roles = passwordFields.map(roleOf);
  const n = passwordFields.length;
  const hasNew = roles.includes('new-password');
  const hasCurrent = roles.includes('current-password');
  const hasConfirm = roles.includes('confirm-password');
  const changePath = page.pathHint === 'change-password';
  const signupPath = page.pathHint === 'signup';

  let kind: FormKind;
  if ((hasCurrent && (hasNew || n >= 2)) || n === 3) kind = 'change-password';
  else if (changePath && (n >= 2 || hasNew)) kind = 'change-password';
  else if (n >= 2 && flags.isChangeText && !flags.isSignupText) kind = 'change-password';
  else if (hasNew || hasConfirm || n === 2) kind = 'signup';
  else if (n === 1 && !signupPath && !flags.isSignupText) kind = 'login';
  else if (n === 1 && flags.isLoginText && !flags.isSignupText) kind = 'login';
  else if (n === 1) kind = 'signup';
  else kind = 'none';

  const assigned: FieldAssignment[] = passwordFields.map((s, i) => {
    let purpose: FieldPurpose = roles[i] ?? 'password';
    if (kind === 'signup' && purpose === 'password')
      purpose = i === 0 ? 'new-password' : 'confirm-password';
    if (kind === 'change-password' && purpose === 'password') {
      purpose =
        i === 0 && !hasCurrent
          ? 'current-password'
          : i === n - 1
            ? 'confirm-password'
            : 'new-password';
    }
    if (kind === 'login') purpose = 'password';
    return assignment(
      s.field.id,
      purpose,
      s.score.scores.password ?? s.score.scores[purpose] ?? STRONG_SCORE,
    );
  });
  evidence.push(`password-fields:${n}`, `kind:${kind}`);

  const firstPassword = passwordFields[0]?.field;
  const candidates = live.filter(
    (s) => !passwordFields.includes(s) && s.field.tag === 'input' && !isPasswordLike(s.field),
  );
  const named = candidates
    .map((s) => ({ s, top: best(s.score, ['username', 'email']) }))
    .filter((x) => (x.top?.score ?? 0) >= MIN_SCORE)
    .toSorted((a, b) => (b.top?.score ?? 0) - (a.top?.score ?? 0))[0];
  if (named?.top !== undefined) {
    assigned.push(
      assignment(
        named.s.field.id,
        named.top.purpose === 'email' ? 'email' : 'username',
        named.top.score,
      ),
    );
    if (named.top.purpose === 'email' && kind === 'login') {
      assigned[assigned.length - 1] = assignment(named.s.field.id, 'username', named.top.score);
    }
  } else if (kind === 'login' && firstPassword !== undefined) {
    const preceding = candidates.filter(
      (s) => page.fields.indexOf(s.field) < page.fields.indexOf(firstPassword),
    );
    const prev = preceding.at(-1);
    const otherStrong =
      prev !== undefined &&
      Object.entries(prev.score.scores).some(
        ([k, v]) => k !== 'username' && k !== 'email' && k !== 'none' && v >= STRONG_SCORE,
      );
    if (prev !== undefined && !otherStrong && candidates.length <= MAX_POSITIONAL_TEXT_FIELDS) {
      assigned.push(assignment(prev.field.id, 'username', 3));
      evidence.push('username:positional');
    }
  }
  if (kind === 'signup' || kind === 'change-password') {
    for (const s of candidates) {
      if (assigned.some((a) => a.id === s.field.id)) continue;
      const top = best(s.score, [...identityPurposes, ...addressPurposes]);
      if (top !== undefined && top.score >= MIN_SCORE)
        assigned.push(assignment(s.field.id, top.purpose, top.score));
    }
  }
  const hasUsername = assigned.some((a) => a.purpose === 'username' || a.purpose === 'email');
  if (kind === 'login' && !hasUsername) {
    evidence.push('kind:password-only');
    return done('password-only', 0.85, assigned);
  }
  return done(kind, kind === 'none' ? 0 : 0.9, assigned);
};

const cellsAreSecretPin = (cells: readonly FieldId[], scored: readonly Scored[]): boolean => {
  const members = scored.filter((s) => cells.includes(s.field.id));
  const passwordish = members.filter((s) => s.field.type === 'password' || s.field.textSecurity);
  const otpish = members.some((s) => (s.score.scores.otp ?? 0) >= MIN_SCORE);
  return passwordish.length === members.length && !otpish;
};

const findCardParts = (inputs: readonly FieldSnap[], scored: readonly Scored[]): FieldId[] => {
  for (let i = 0; i + 3 < inputs.length; i += 1) {
    const run = inputs.slice(i, i + 4);
    const aligned = run.every((f, j) => {
      const prev = run[j - 1];
      return (
        f.tag === 'input' &&
        f.maxlength === 4 &&
        (prev === undefined || (Math.abs(prev.rect.y - f.rect.y) <= 4 && f.rect.x > prev.rect.x))
      );
    });
    if (!aligned) continue;
    const first = scored.find((s) => s.field.id === run[0]?.id);
    const cue =
      (first?.score.scores['cc-number'] ?? 0) >= MIN_SCORE ||
      run.some((f) => f.autocomplete.includes('cc-number'));
    if (cue) return run.map((f) => f.id);
  }
  return [];
};

export const classifyPage = (page: PageSnap, overrides: PurposeOverrides): FormClass[] =>
  page.forms.map((form) => classifyForm(form, page, overrides));

export const matchesChangePath = (pathname: string): boolean => pathChange.test(pathname);
