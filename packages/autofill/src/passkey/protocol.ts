import { z } from 'zod';

export const HOOK_HELLO = 'hasp-passkey-hello';
export const BRIDGE_READY = 'hasp-passkey-bridge-ready';
export const MAX_PAYLOAD_CHARS = 65536;

export const hookRequestSchema = z.strictObject({
  id: z.number().int().nonnegative(),
  op: z.enum(['create', 'get']),
  options: z.string().max(MAX_PAYLOAD_CHARS),
});
export type HookRequest = z.infer<typeof hookRequestSchema>;

export const bridgeReplySchema = z.discriminatedUnion('outcome', [
  z.strictObject({
    id: z.number().int(),
    outcome: z.literal('handled'),
    payload: z.string().max(MAX_PAYLOAD_CHARS),
  }),
  z.strictObject({ id: z.number().int(), outcome: z.literal('fallback') }),
]);
export type BridgeReply = z.infer<typeof bridgeReplySchema>;

export const hookNoticeSchema = z.strictObject({
  id: z.literal(-1),
  op: z.literal('create'),
  options: z.literal('conflict'),
});
