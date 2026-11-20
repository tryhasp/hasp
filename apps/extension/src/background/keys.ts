import { z } from 'zod';

import { defineKey } from '../platform/storage.ts';

export const accountKey = defineKey(
  'local',
  'hasp:account',
  z.strictObject({ origin: z.string() }),
);
export const storeKey = defineKey('local', 'hasp:store', z.string());
export const deviceKey = defineKey(
  'local',
  'hasp:desktop-device',
  z.strictObject({ hex: z.string().regex(/^[0-9a-f]{32}$/) }),
);
export const userSelectorsKey = defineKey(
  'local',
  'hasp:user-selectors',
  z.record(
    z.string(),
    z.strictObject({
      username: z.string().optional(),
      password: z.string().optional(),
      otp: z.string().optional(),
    }),
  ),
);
export const neverSaveKey = defineKey('local', 'hasp:never-save', z.array(z.string()));

export const ticketKey = defineKey(
  'session',
  'hasp:ticket',
  z.discriminatedUnion('kind', [
    z.strictObject({ kind: z.literal('extension'), key: z.string(), validUntilMs: z.number() }),
    z.strictObject({ kind: z.literal('session'), blob: z.string() }),
  ]),
);
export const activityKey = defineKey('session', 'hasp:activity', z.number());
export const tickCountKey = defineKey('session', 'hasp:ticks', z.number());

export const menuSessionSchema = z.strictObject({
  nonce: z.string(),
  tabId: z.number().int(),
  frameId: z.number().int(),
  origin: z.string(),
  url: z.string(),
  host: z.string(),
  mode: z.enum(['menu', 'save']),
  formKind: z.string(),
  frame: z.string(),
  createdMs: z.number(),
  candidates: z.array(
    z.strictObject({
      vault: z.string(),
      item: z.string(),
      title: z.string(),
      username: z.string(),
      tier: z.enum(['exact', 'domain', 'related']),
      hostToConfirm: z.string().optional(),
      hasTotp: z.boolean(),
    }),
  ),
  canGenerate: z.boolean(),
  saveKind: z.enum(['new', 'update']).optional(),
  saveTitle: z.string().optional(),
  saveUsername: z.string().optional(),
  saveVault: z.string().optional(),
  saveItem: z.string().optional(),
});
export type MenuSession = z.infer<typeof menuSessionSchema>;

export const menuKey = (nonce: string) =>
  defineKey('session', `hasp:menu:${nonce}`, menuSessionSchema);

export const flowSchema = z.strictObject({
  vault: z.string(),
  item: z.string(),
  origin: z.string(),
  frame: z.string(),
  atMs: z.number(),
  isAnswered: z.boolean(),
});
export const flowKey = (tabId: number) =>
  defineKey('session', `hasp:flow:${String(tabId)}`, flowSchema);

export const approvalSchema = z.strictObject({ expiresMs: z.number(), origin: z.string() });
export const approvalKey = (tabId: number, frameId: number, item: string) =>
  defineKey('session', `hasp:approval:${String(tabId)}:${String(frameId)}:${item}`, approvalSchema);

export const confirmSchema = z.strictObject({
  tabId: z.number().int(),
  frameId: z.number().int(),
  vault: z.string(),
  item: z.string(),
  title: z.string(),
  subtitle: z.string(),
  savedHost: z.string(),
  currentHost: z.string(),
  origin: z.string(),
  expiresMs: z.number(),
});
export type ConfirmRequest = z.infer<typeof confirmSchema>;
export const confirmKey = (id: string) => defineKey('session', `hasp:confirm:${id}`, confirmSchema);
export const confirmCooldownKey = (tabId: number) =>
  defineKey('session', `hasp:confirm-cooldown:${String(tabId)}`, z.number());

export const localeKey = defineKey('local', 'hasp:locale', z.enum(['ko', 'en']));
