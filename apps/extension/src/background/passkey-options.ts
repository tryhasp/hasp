import type {
  PasskeyAssertion,
  PasskeyCandidate,
  PasskeyCreateRequest,
  PasskeyCreated,
  PasskeyGetRequest,
} from '@hasp/wasm';
import { z } from 'zod';

const idText = z.string().max(2048);
const verification = z.enum(['required', 'preferred', 'discouraged']);

export const getOptionsSchema = z.object({
  challenge: idText,
  rpId: z.string().max(253).optional(),
  userVerification: verification.optional(),
  allowCredentials: z
    .array(z.object({ id: idText }))
    .max(64)
    .default([]),
  mediation: z.string().optional(),
});
export type GetOptions = z.infer<typeof getOptionsSchema>;

export const createOptionsSchema = z.object({
  challenge: idText,
  rp: z.object({ id: z.string().max(253).optional(), name: z.string().max(256) }),
  user: z.object({
    id: idText,
    name: z.string().max(256),
    displayName: z.string().max(256),
  }),
  algs: z.array(z.number().int()).max(32).default([]),
  excludeCredentials: z
    .array(z.object({ id: idText }))
    .max(64)
    .default([]),
  userVerification: verification.optional(),
});
export type CreateOptions = z.infer<typeof createOptionsSchema>;

export type ParsedRequest =
  | { op: 'get'; options: GetOptions }
  | { op: 'create'; options: CreateOptions };

export const parsePasskeyRequest = (
  op: 'create' | 'get',
  raw: string,
): ParsedRequest | undefined => {
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    return undefined;
  }
  if (op === 'get') {
    const parsed = getOptionsSchema.safeParse(json);
    return parsed.success ? { op, options: parsed.data } : undefined;
  }
  const parsed = createOptionsSchema.safeParse(json);
  return parsed.success ? { op, options: parsed.data } : undefined;
};

export const isUvRequired = (options: { userVerification?: string | undefined }): boolean =>
  options.userVerification === 'required';

export const isReauthWanted = (
  options: { userVerification?: string | undefined },
  hasReauth: boolean,
): boolean => isUvRequired(options) || (options.userVerification !== 'discouraged' && hasReauth);

export type FrameFacts = { frame: string };

const sandboxedFrames: ReadonlySet<string> = new Set(['sandboxed', 'opaque', 'blank', 'blob']);

export const isPasskeyFrameAllowed = (frame: string): boolean => !sandboxedFrames.has(frame);

export const frameOfPasskey = (facts: FrameFacts) => ({
  topFrame: facts.frame === 'top',
  crossOriginFrame: facts.frame === 'cross-origin',
  sandboxed: sandboxedFrames.has(facts.frame),
  obscured: false,
  visibilityCheckSupported: false,
});

export const createRequestOf = (
  options: CreateOptions,
  origin: string,
  facts: FrameFacts,
  userVerified: boolean,
): PasskeyCreateRequest => ({
  origin,
  frame: frameOfPasskey(facts),
  rpId: options.rp.id,
  rpName: options.rp.name,
  challenge: options.challenge,
  userHandle: options.user.id,
  userName: options.user.name,
  userDisplayName: options.user.displayName,
  algorithms: options.algs,
  exclude: options.excludeCredentials.map((entry) => entry.id),
  userVerification: options.userVerification ?? 'preferred',
  userVerified,
  vault: undefined,
  item: undefined,
});

export const getRequestOf = (
  options: GetOptions,
  origin: string,
  facts: FrameFacts,
  userVerified: boolean,
  pick: Pick<PasskeyCandidate, 'vault' | 'item' | 'credentialId'>,
): PasskeyGetRequest => ({
  origin,
  frame: frameOfPasskey(facts),
  rpId: options.rpId,
  challenge: options.challenge,
  allow: options.allowCredentials.map((entry) => entry.id),
  userVerification: options.userVerification ?? 'preferred',
  userVerified,
  vault: pick.vault,
  item: pick.item,
  credentialId: pick.credentialId,
});

export const registrationJson = (created: PasskeyCreated): string =>
  JSON.stringify({
    id: created.credentialId,
    rawId: created.credentialId,
    type: 'public-key',
    authenticatorAttachment: 'platform',
    response: {
      clientDataJSON: created.clientDataJson,
      attestationObject: created.attestationObject,
      authenticatorData: created.authenticatorData,
      transports: ['internal', 'hybrid'],
      publicKeyAlgorithm: created.publicKeyAlgorithm,
      publicKey: created.publicKey,
    },
  });

export const assertionJson = (assertion: PasskeyAssertion): string =>
  JSON.stringify({
    id: assertion.credentialId,
    rawId: assertion.credentialId,
    type: 'public-key',
    authenticatorAttachment: 'platform',
    response: {
      clientDataJSON: assertion.clientDataJson,
      authenticatorData: assertion.authenticatorData,
      signature: assertion.signature,
      userHandle: assertion.userHandle,
    },
  });
