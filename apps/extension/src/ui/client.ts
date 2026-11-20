import { err, ok } from '@hasp/autofill';
import type { Result } from '@hasp/autofill';
import { z } from 'zod';

import { uiReplySchemas } from '../messages/ui.ts';
import type { UiKind, UiReply, UiRequest } from '../messages/ui.ts';
import type { ErrorBody } from '../platform/messaging.ts';
import { request } from '../platform/messaging.ts';

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

export const callUi = async <K extends UiKind>(
  message: Extract<UiRequest, { kind: K }>,
): Promise<Result<UiReply<K>, ErrorBody>> => {
  let raw: unknown;
  try {
    raw = await request(message);
  } catch {
    return err({ kind: 'timeout' });
  }
  const envelope = envelopeSchema.safeParse(raw);
  if (!envelope.success) return err({ kind: 'internal' });
  if (!envelope.data.ok) return err(envelope.data.error);
  const value = uiReplySchemas[message.kind].safeParse(envelope.data.value);
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the reply schema is selected by message.kind, so the parsed value is UiReply<K>
  return value.success ? ok(value.data as UiReply<K>) : err({ kind: 'internal' });
};
