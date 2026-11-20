import type { FieldId, FormId } from './brand.ts';

export type Rect = { x: number; y: number; w: number; h: number };

export const fieldTags = ['input', 'select', 'textarea', 'button'] as const;
export type FieldTag = (typeof fieldTags)[number];

export type SelectOption = { value: string; label: string };

export type FieldSnap = {
  id: FieldId;
  tag: FieldTag;
  type: string;
  name: string;
  domId: string;
  autocomplete: readonly string[];
  inputmode: string;
  label: string;
  placeholder: string;
  ariaLabel: string;
  nearbyText: string;
  rect: Rect;
  visible: boolean;
  occluded: boolean;
  disabled: boolean;
  readonly: boolean;
  textSecurity: boolean;
  formId: FormId;
  frameOrigin: string;
  valueLen: number;
  maxlength?: number;
  minlength?: number;
  pattern?: string;
  options?: readonly SelectOption[];
};

export type FormSnap = {
  id: FormId;
  isSynthetic: boolean;
  fieldIds: readonly FieldId[];
  submitTexts: readonly string[];
};

export const pathHints = ['login', 'signup', 'change-password', 'none'] as const;
export type PathHint = (typeof pathHints)[number];

export const frameKinds = [
  'top',
  'same-origin',
  'cross-origin',
  'sandboxed',
  'opaque',
  'blank',
  'blob',
] as const;
export type FrameKind = (typeof frameKinds)[number];

export type PageSnap = {
  forms: readonly FormSnap[];
  fields: readonly FieldSnap[];
  pathHint: PathHint;
  frame: FrameKind;
  hasCaptcha: boolean;
  hasErrorText: boolean;
  lang: string;
};

export const formKinds = [
  'login',
  'username-only',
  'password-only',
  'signup',
  'change-password',
  'otp',
  'otp-split',
  'card',
  'identity',
  'address',
  'none',
] as const;
export type FormKind = (typeof formKinds)[number];

export const fieldPurposes = [
  'username',
  'email',
  'password',
  'new-password',
  'current-password',
  'confirm-password',
  'otp',
  'otp-cell',
  'cc-number',
  'cc-number-part',
  'cc-exp',
  'cc-exp-month',
  'cc-exp-year',
  'cc-csc',
  'cc-name',
  'cc-type',
  'name',
  'given-name',
  'family-name',
  'tel',
  'street-address',
  'address-line1',
  'address-line2',
  'postal-code',
  'country',
  'submit',
  'none',
] as const;
export type FieldPurpose = (typeof fieldPurposes)[number];

export type FieldAssignment = { id: FieldId; purpose: FieldPurpose; score: number };

export type FormClass = {
  formId: FormId;
  kind: FormKind;
  confidence: number;
  fields: readonly FieldAssignment[];
  submit?: FieldId;
  evidence: readonly string[];
};

export const isLoginClass = (kind: FormKind): boolean =>
  kind === 'login' || kind === 'username-only' || kind === 'password-only';
