import type { Attestation } from '../protocol.ts';
import type { Result } from '../result.ts';
import { err, ok } from '../result.ts';
import { ATTESTATION_MAX_AGE_MS } from './gesture.ts';

const CLOCK_SKEW_MS = 50;

export type FillGateRefusal =
  | 'locked'
  | 'tab-not-active'
  | 'sender-mismatch'
  | 'token-rejected'
  | 'attestation-stale'
  | 'attestation-incomplete';

export type FillGateInput = {
  isUnlocked: boolean;
  isTabActiveAndFocused: boolean;
  isSenderBoundFrame: boolean;
  isTokenAccepted: boolean;
  attestation: Attestation;
  nowMs: number;
};

export const verifyFillRequest = (i: FillGateInput): Result<null, FillGateRefusal> => {
  if (!i.isUnlocked) return err('locked');
  if (!i.isSenderBoundFrame) return err('sender-mismatch');
  if (!i.isTabActiveAndFocused) return err('tab-not-active');
  if (!i.isTokenAccepted) return err('token-rejected');
  const age = i.nowMs - i.attestation.checkedAtMs;
  if (age < -CLOCK_SKEW_MS || age > ATTESTATION_MAX_AGE_MS) return err('attestation-stale');
  const required = i.attestation.isC4Supported
    ? ['C1', 'C2', 'C3', 'C4', 'C5']
    : ['C1', 'C2', 'C3', 'C5'];
  const hasAll = required.every((c) => i.attestation.passed.some((p) => p === c));
  return hasAll ? ok(null) : err('attestation-incomplete');
};
