import { z } from 'zod';

import type { ContentBackground } from './engine.ts';
import type { FrameBackground } from './menu/menu-frame.ts';
import { frameReplySchemas, replySchemas } from './protocol.ts';
import type { ContentKind, ContentRequest, FrameRequest, ProtocolError } from './protocol.ts';
import { err, ok } from './result.ts';
import type { Result } from './result.ts';

export type Transport<M> = (message: M) => Promise<unknown>;

const errorSchema = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('locked') }),
  z.strictObject({ kind: z.literal('denied'), reason: z.string() }),
  z.strictObject({ kind: z.literal('internal') }),
  z.strictObject({ kind: z.literal('timeout') }),
]);

const envelopeSchema = z.union([
  z.strictObject({ ok: z.literal(true), value: z.unknown() }),
  z.strictObject({ ok: z.literal(false), error: errorSchema }),
]);

const internal: ProtocolError = { kind: 'internal' };

const unwrap = (raw: unknown, schema: z.ZodType): Result<unknown, ProtocolError> => {
  const envelope = envelopeSchema.safeParse(raw);
  if (!envelope.success) return err(internal);
  if (!envelope.data.ok) return err(envelope.data.error);
  const value = schema.safeParse(envelope.data.value);
  return value.success ? ok(value.data) : err(internal);
};

export const createContentBackground = (send: Transport<ContentRequest>): ContentBackground => ({
  request: async <K extends ContentKind>(message: Extract<ContentRequest, { kind: K }>) => {
    const raw = await send(message);
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the reply schema is selected by message.kind, so the parsed value is ReplyOf<K>
    return unwrap(raw, replySchemas[message.kind]) as Result<
      z.infer<(typeof replySchemas)[K]>,
      ProtocolError
    >;
  },
});

export const createFrameBackground = (send: Transport<FrameRequest>): FrameBackground => {
  const call = async (message: FrameRequest): Promise<Result<unknown, ProtocolError>> =>
    unwrap(await send(message), frameReplySchemas[message.kind]);
  return {
    hello: async (nonce) => {
      const r = await call({ kind: 'frame-hello', nonce });
      const parsed = frameReplySchemas['frame-hello'].safeParse(r.ok ? r.value : undefined);
      return parsed.success ? ok(parsed.data) : err(r.ok ? internal : r.error);
    },
    pick: async (nonce, itemId, action) => {
      const r = await call({ kind: 'menu-pick', nonce, itemId, action });
      const parsed = frameReplySchemas['menu-pick'].safeParse(r.ok ? r.value : undefined);
      return parsed.success ? ok(parsed.data) : err(r.ok ? internal : r.error);
    },
    saveAnswer: async (nonce, answer) => {
      const r = await call({ kind: 'save-answer', nonce, answer });
      return r.ok ? ok({}) : r;
    },
    dismiss: async (nonce) => {
      const r = await call({ kind: 'menu-dismiss', nonce });
      return r.ok ? ok({}) : r;
    },
  };
};
