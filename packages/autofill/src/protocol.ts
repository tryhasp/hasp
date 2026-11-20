import { z } from 'zod';

import { submitKinds } from './save/pending-store.ts';
import { pageConfigSchema } from './sites/site-rule.ts';
import { fieldPurposes, formKinds, frameKinds } from './types.ts';

export const checkIds = ['C1', 'C2', 'C3', 'C4', 'C5'] as const;
export type CheckId = (typeof checkIds)[number];

export const attestationSchema = z.strictObject({
  checkedAtMs: z.number(),
  passed: z.array(z.enum(checkIds)).max(5),
  isC4Supported: z.boolean(),
});
export type Attestation = z.infer<typeof attestationSchema>;

export const fieldRulesSchema = z.strictObject({
  maxlength: z.number().int().positive().optional(),
  minlength: z.number().int().positive().optional(),
  pattern: z.string().max(500).optional(),
  passwordRules: z.string().max(1000).optional(),
});
export type FieldRules = z.infer<typeof fieldRulesSchema>;

const formKindSchema = z.enum(formKinds);
const frameKindSchema = z.enum(frameKinds);
const purposeSchema = z.enum(fieldPurposes);
const idSchema = z.string().min(1).max(64);
const nonceSchema = z.string().min(16).max(128);
const gestureSchema = z.string().min(16).max(128);

export const captureValuesSchema = z.strictObject({
  username: z.string().max(1024).optional(),
  password: z.string().max(4096).optional(),
  newPassword: z.string().max(4096).optional(),
});

export type CaptureValues = z.infer<typeof captureValuesSchema>;

export const submitTriggers = ['submit', 'enter', 'click', 'navigation', 'form-gone'] as const;
export const submitOutcomes = ['pending', 'error-text', 'rerendered', 'gone'] as const;

export const teachPurposes = ['username', 'password', 'otp'] as const;

export const contentRequestSchema = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('page-config') }),
  z.strictObject({
    kind: z.literal('menu-open'),
    formId: idSchema,
    formKind: formKindSchema,
    frame: frameKindSchema,
    isC4Supported: z.boolean(),
    isObscured: z.boolean(),
  }),
  z.strictObject({
    kind: z.literal('fill-request'),
    nonce: nonceSchema,
    token: gestureSchema,
    itemId: idSchema,
    formId: idSchema,
    formKind: formKindSchema,
    purposes: z.array(purposeSchema).max(12),
    attestation: attestationSchema,
  }),
  z.strictObject({
    kind: z.literal('fill-continue'),
    formId: idSchema,
    formKind: formKindSchema,
    purposes: z.array(purposeSchema).max(12),
    attestation: attestationSchema,
  }),
  z.strictObject({
    kind: z.literal('capture'),
    formId: idSchema,
    values: captureValuesSchema,
    source: z.enum(['typed', 'generated']),
  }),
  z.strictObject({
    kind: z.literal('submit-signal'),
    formId: idSchema,
    trigger: z.enum(submitTriggers),
    outcome: z.enum(submitOutcomes),
    formKind: z.enum(submitKinds).optional(),
    wasSubmitted: z.boolean().optional(),
    handoff: captureValuesSchema.optional(),
  }),
  z.strictObject({
    kind: z.literal('generate'),
    rules: fieldRulesSchema,
    preset: z.enum(['default', 'korean-safe']),
  }),
  z.strictObject({
    kind: z.literal('generated-verified'),
    isMatch: z.boolean(),
    expectedLength: z.number().int().nonnegative(),
    actualLength: z.number().int().nonnegative(),
  }),
  z.strictObject({
    kind: z.literal('teach'),
    purpose: z.enum(teachPurposes),
    selector: z.string().min(1).max(300),
  }),
  z.strictObject({
    kind: z.literal('strike'),
    count: z.number().int().min(1).max(3),
    check: z.string().max(8),
  }),
  z.strictObject({
    kind: z.literal('passkey-request'),
    op: z.enum(['create', 'get']),
    frame: frameKindSchema,
    options: z.string().max(65536),
  }),
]);
export type ContentRequest = z.infer<typeof contentRequestSchema>;
export type ContentKind = ContentRequest['kind'];

export const frameRequestSchema = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('frame-hello'), nonce: nonceSchema }),
  z.strictObject({
    kind: z.literal('menu-pick'),
    nonce: nonceSchema,
    itemId: idSchema,
    action: z.enum(['fill', 'otp', 'generate']),
  }),
  z.strictObject({ kind: z.literal('menu-dismiss'), nonce: nonceSchema }),
  z.strictObject({
    kind: z.literal('save-answer'),
    nonce: nonceSchema,
    answer: z.enum(['save', 'update', 'never', 'dismiss']),
  }),
]);
export type FrameRequest = z.infer<typeof frameRequestSchema>;

export const matchLevels = ['exact', 'domain', 'related'] as const;

export const candidateSchema = z.strictObject({
  itemId: idSchema,
  title: z.string().max(200),
  username: z.string().max(200),
  vaultLabel: z.string().max(60),
  level: z.enum(matchLevels),
  hostToConfirm: z.string().max(253).optional(),
  hasOtp: z.boolean(),
});
export type Candidate = z.infer<typeof candidateSchema>;

const frameViewSchema = z.discriminatedUnion('mode', [
  z.strictObject({
    mode: z.literal('menu'),
    primary: z.enum(['fill', 'otp']),
    candidates: z.array(candidateSchema).max(50),
    canGenerate: z.boolean(),
    isFillBlocked: z.boolean(),
  }),
  z.strictObject({
    mode: z.literal('save'),
    saveKind: z.enum(['new', 'update']),
    title: z.string().max(200),
    username: z.string().max(200),
    vaultLabel: z.string().max(60),
  }),
]);

export const frameHelloReplySchema = z.strictObject({
  nonce: nonceSchema,
  originSubdomain: z.string().max(253),
  originRegistrable: z.string().max(253),
  secretTag: z.string().max(40).nullable(),
  secretGlyph: z.number().int().min(0).max(11),
  locale: z.enum(['ko', 'en']),
  view: frameViewSchema,
});
export type FrameHelloReply = z.infer<typeof frameHelloReplySchema>;

export const menuOpenReplySchema = z.discriminatedUnion('decision', [
  z.strictObject({ decision: z.literal('inline'), nonce: nonceSchema }),
  z.strictObject({ decision: z.literal('browser-ui') }),
  z.strictObject({ decision: z.literal('none'), reason: z.string().max(40) }),
]);
export type MenuOpenReply = z.infer<typeof menuOpenReplySchema>;

export const fillValueSchema = z.strictObject({
  purpose: purposeSchema,
  value: z.string().max(4096),
});

export const fillReplySchema = z.discriminatedUnion('kind', [
  z.strictObject({
    kind: z.literal('payload'),
    fields: z.array(fillValueSchema).max(12),
    isAutosubmit: z.boolean(),
    isPerCharEvents: z.boolean(),
  }),
  z.strictObject({ kind: z.literal('browser-ui') }),
  z.strictObject({ kind: z.literal('refused'), reason: z.string().max(40) }),
]);
export type FillReply = z.infer<typeof fillReplySchema>;

export const submitReplySchema = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('none') }),
  z.strictObject({ kind: z.literal('prompt'), nonce: nonceSchema }),
]);

export const passkeyReplySchema = z.strictObject({ payload: z.string().max(65536) });

export const replySchemas = {
  'page-config': pageConfigSchema,
  'menu-open': menuOpenReplySchema,
  'fill-request': fillReplySchema,
  'fill-continue': fillReplySchema,
  capture: z.strictObject({}),
  'submit-signal': submitReplySchema,
  generate: z.strictObject({ value: z.string().max(4096), length: z.number().int().positive() }),
  'generated-verified': z.strictObject({}),
  teach: z.strictObject({}),
  strike: z.strictObject({}),
  'passkey-request': passkeyReplySchema,
} as const satisfies Record<ContentKind, z.ZodType>;

export type ReplyOf<K extends ContentKind> = z.infer<(typeof replySchemas)[K]>;

export const frameReplySchemas = {
  'frame-hello': frameHelloReplySchema,
  'menu-pick': z.strictObject({ token: gestureSchema }),
  'menu-dismiss': z.strictObject({}),
  'save-answer': z.strictObject({}),
} as const satisfies Record<FrameRequest['kind'], z.ZodType>;

export type FrameReplyOf<K extends FrameRequest['kind']> = z.infer<(typeof frameReplySchemas)[K]>;

export const backgroundPushSchema = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('open-menu') }),
  z.strictObject({
    kind: z.literal('fill-focused'),
    purpose: z.enum(teachPurposes),
    value: z.string().max(4096),
  }),
  z.strictObject({
    kind: z.literal('fill-form'),
    nonce: nonceSchema,
    itemId: idSchema,
    token: gestureSchema,
  }),
  z.strictObject({ kind: z.literal('teach-start'), purpose: z.enum(teachPurposes) }),
  z.strictObject({ kind: z.literal('abort-flow') }),
  z.strictObject({ kind: z.literal('lock') }),
]);
export type BackgroundPush = z.infer<typeof backgroundPushSchema>;

export type ProtocolError =
  | { kind: 'locked' }
  | { kind: 'denied'; reason: string }
  | { kind: 'internal' }
  | { kind: 'timeout' };

export const portToContentSchema = z.discriminatedUnion('kind', [
  z.strictObject({
    kind: z.literal('picked'),
    itemId: idSchema,
    action: z.enum(['fill', 'otp', 'generate']),
    token: gestureSchema,
  }),
  z.strictObject({ kind: z.literal('dismiss') }),
  z.strictObject({
    kind: z.literal('ready'),
    width: z.number().min(1).max(640),
    height: z.number().min(1).max(600),
  }),
  z.strictObject({
    kind: z.literal('size'),
    width: z.number().min(1).max(640),
    height: z.number().min(1).max(600),
  }),
]);
export type PortToContent = z.infer<typeof portToContentSchema>;

export const portToFrameSchema = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('shown') }),
  z.strictObject({ kind: z.literal('moved') }),
  z.strictObject({ kind: z.literal('hidden') }),
  z.strictObject({
    kind: z.literal('key'),
    key: z.enum(['ArrowDown', 'ArrowUp', 'Enter', 'Home', 'End', 'g']),
  }),
]);
export type PortToFrame = z.infer<typeof portToFrameSchema>;
