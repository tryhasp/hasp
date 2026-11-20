import { z } from 'zod';

const idSchema = z.string().regex(/^[0-9a-f]{32}$/);
const textSchema = z.string().max(4096);

export const secretTagSchema = z.strictObject({
  word: z.string().min(1).max(12),
  glyph: z.number().int().min(0).max(11),
});
export type SecretTagView = z.infer<typeof secretTagSchema>;

export const lockPolicySchema = z.strictObject({
  idleMinutes: z.number().int().min(0).max(1440),
  lockOnSleep: z.boolean(),
  lockOnScreenLock: z.boolean(),
  lockOnUserSwitch: z.boolean(),
  lockOnQuit: z.boolean(),
  backgroundSeconds: z.number().int().min(0).max(900),
  passwordEveryDays: z.number().int().min(0).max(365),
  clipboardClearSeconds: z.number().int().min(0).max(600),
});

export const settingsPatchSchema = z.strictObject({
  lock: lockPolicySchema.optional(),
  secretTag: secretTagSchema.optional(),
  language: z.enum(['ko', 'en']).optional(),
  inlineMenu: z.boolean().optional(),
  askBeforeFilling: z.boolean().optional(),
  hardenedMode: z.boolean().optional(),
  autoSubmit: z.boolean().optional(),
});
export type SettingsPatch = z.infer<typeof settingsPatchSchema>;

export const uiRequestSchema = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('ui-state') }),
  z.strictObject({
    kind: z.literal('ui-sign-in'),
    server: z.string().max(300),
    login: z.string().min(1).max(256),
    secretKey: textSchema,
    password: textSchema,
    serverFingerprint: z.string().min(1).max(256),
  }),
  z.strictObject({ kind: z.literal('ui-server-fingerprint'), server: z.string().max(300) }),
  z.strictObject({ kind: z.literal('ui-unlock-password'), password: textSchema }),
  z.strictObject({ kind: z.literal('ui-unlock-desktop') }),
  z.strictObject({ kind: z.literal('ui-pair-desktop'), server: z.string().max(300) }),
  z.strictObject({ kind: z.literal('ui-lock') }),
  z.strictObject({ kind: z.literal('ui-sync') }),
  z.strictObject({ kind: z.literal('ui-search'), text: z.string().max(200) }),
  z.strictObject({ kind: z.literal('ui-current-site') }),
  z.strictObject({
    kind: z.literal('ui-copy'),
    vault: idSchema,
    item: idSchema,
    field: z.enum(['username', 'password', 'otp']),
  }),
  z.strictObject({ kind: z.literal('ui-copy-generated'), id: z.string().max(64) }),
  z.strictObject({ kind: z.literal('ui-fill'), vault: idSchema, item: idSchema }),
  z.strictObject({ kind: z.literal('ui-generated') }),
  z.strictObject({ kind: z.literal('ui-settings') }),
  z.strictObject({ kind: z.literal('ui-settings-set'), patch: settingsPatchSchema }),
  z.strictObject({ kind: z.literal('ui-sign-out') }),
  z.strictObject({ kind: z.literal('passkey-get'), id: z.string().min(8).max(64) }),
  z.strictObject({
    kind: z.literal('passkey-answer'),
    id: z.string().min(8).max(64),
    choice: z.enum(['use', 'decline']),
    credentialId: z.string().max(512).optional(),
    password: textSchema.optional(),
  }),
  z.strictObject({ kind: z.literal('code-get'), id: z.string().min(8).max(64) }),
  z.strictObject({ kind: z.literal('confirm-get'), id: z.string().min(8).max(64) }),
  z.strictObject({
    kind: z.literal('confirm-answer'),
    id: z.string().min(8).max(64),
    approve: z.boolean(),
  }),
]);
export type UiRequest = z.infer<typeof uiRequestSchema>;
export type UiKind = UiRequest['kind'];

export const accountStates = ['empty', 'locked', 'unlocked'] as const;

export const appStateSchema = z.strictObject({
  account: z.enum(accountStates),
  login: z.string().optional(),
  server: z.string().optional(),
  unlockMode: z.enum(['hardware', 'password-only', 'extension']).optional(),
  retryAfter: z.number(),
  secretTag: secretTagSchema.optional(),
  locale: z.enum(['ko', 'en']),
  isPaired: z.boolean(),
  isDesktopAvailable: z.boolean(),
  idleDeadlineMs: z.number().optional(),
});
export type AppState = z.infer<typeof appStateSchema>;

export const itemViewSchema = z.strictObject({
  vault: idSchema,
  id: idSchema,
  title: z.string(),
  subtitle: z.string(),
  hasTotp: z.boolean(),
  tier: z.enum(['exact', 'domain', 'related']).optional(),
});
export type ItemView = z.infer<typeof itemViewSchema>;

export const currentSiteSchema = z.strictObject({
  host: z.string().optional(),
  isRefused: z.boolean(),
  items: z.array(itemViewSchema),
});
export type CurrentSite = z.infer<typeof currentSiteSchema>;

export const generatedViewSchema = z.strictObject({
  id: z.string(),
  site: z.string(),
  atMs: z.number(),
  isSaved: z.boolean(),
});
export type GeneratedView = z.infer<typeof generatedViewSchema>;

export const settingsViewSchema = z.strictObject({
  lock: lockPolicySchema,
  secretTag: secretTagSchema.optional(),
  language: z.enum(['ko', 'en']),
  inlineMenu: z.boolean(),
  askBeforeFilling: z.boolean(),
  hardenedMode: z.boolean(),
  autoSubmit: z.boolean(),
});
export type SettingsView = z.infer<typeof settingsViewSchema>;

export const confirmViewSchema = z.strictObject({
  title: z.string(),
  subtitle: z.string(),
  savedHost: z.string(),
  currentHost: z.string(),
  isSameHost: z.boolean(),
  secretTag: secretTagSchema.optional(),
  locale: z.enum(['ko', 'en']),
});
export type ConfirmView = z.infer<typeof confirmViewSchema>;

export const codeViewSchema = z.strictObject({
  kind: z.enum(['unlock', 'pair']),
  code: z.string().regex(/^\d{3} \d{3}$/),
  locale: z.enum(['ko', 'en']),
});
export type CodeView = z.infer<typeof codeViewSchema>;

export const passkeyViewSchema = z.strictObject({
  op: z.enum(['create', 'get']),
  host: z.string(),
  rpId: z.string(),
  rpName: z.string(),
  userName: z.string(),
  isReauthNeeded: z.boolean(),
  reauth: z.enum(['password', 'desktop', 'none']),
  candidates: z.array(
    z.strictObject({
      credentialId: z.string(),
      title: z.string(),
      userName: z.string(),
      displayName: z.string(),
    }),
  ),
  secretTag: secretTagSchema.optional(),
  locale: z.enum(['ko', 'en']),
});
export type PasskeyView = z.infer<typeof passkeyViewSchema>;

export const passkeyAnswerSchema = z.strictObject({
  status: z.enum(['ok', 'wrong-password', 'locked-out', 'declined', 'unavailable', 'expired']),
});

export const copyResultSchema = z.strictObject({ clearAfterSeconds: z.number() });
export const unlockResultSchema = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('done') }),
  z.strictObject({ kind: z.literal('wrong-password') }),
  z.strictObject({ kind: z.literal('wrong-fingerprint') }),
  z.strictObject({ kind: z.literal('locked-out'), retryAfter: z.number() }),
  z.strictObject({ kind: z.literal('desktop-unavailable') }),
  z.strictObject({ kind: z.literal('declined') }),
  z.strictObject({ kind: z.literal('failed') }),
]);
export type UnlockResult = z.infer<typeof unlockResultSchema>;

export const uiReplySchemas = {
  'ui-state': appStateSchema,
  'ui-sign-in': unlockResultSchema,
  'ui-server-fingerprint': z.strictObject({ fingerprint: z.string() }),
  'ui-unlock-password': unlockResultSchema,
  'ui-unlock-desktop': unlockResultSchema,
  'ui-pair-desktop': unlockResultSchema,
  'ui-lock': z.strictObject({}),
  'ui-sync': z.strictObject({ changed: z.number() }),
  'ui-search': z.array(itemViewSchema),
  'ui-current-site': currentSiteSchema,
  'ui-copy': copyResultSchema,
  'ui-copy-generated': copyResultSchema,
  'ui-fill': z.strictObject({ kind: z.enum(['menu', 'confirm', 'no-page']) }),
  'ui-generated': z.array(generatedViewSchema),
  'ui-settings': settingsViewSchema,
  'ui-settings-set': z.strictObject({}),
  'ui-sign-out': z.strictObject({}),
  'passkey-get': passkeyViewSchema,
  'passkey-answer': passkeyAnswerSchema,
  'code-get': codeViewSchema,
  'confirm-get': confirmViewSchema,
  'confirm-answer': z.strictObject({}),
} as const satisfies Record<UiKind, z.ZodType>;

export type UiReply<K extends UiKind> = z.infer<(typeof uiReplySchemas)[K]>;
