import type { FrameKind } from '../types.ts';

export type FillKind =
  | 'password'
  | 'otp'
  | 'passkey-sign-in'
  | 'card'
  | 'identity'
  | 'passkey-create';
export type MatchLevelKind = 'exact' | 'domain' | 'related';

export type StepUpInput = {
  fill: FillKind;
  frame: FrameKind;
  level: MatchLevelKind;
  isHostConfirmed: boolean;
  isCardHostRemembered: boolean;
  isObscured: boolean;
  isC4Supported: boolean;
  settings: { isAskBeforeFilling: boolean };
};

export type StepUpReason =
  | 'cross-origin-frame'
  | 'obscured'
  | 'first-cross-host'
  | 'card'
  | 'identity'
  | 'passkey-create'
  | 'ask-always'
  | 'visibility-unsupported';

export type StepUp =
  | { kind: 'none' }
  | { kind: 'inline-confirm'; reason: StepUpReason }
  | { kind: 'browser-ui'; reason: StepUpReason }
  | { kind: 'refuse'; reason: 'frame-not-allowed' };

export const decideStepUp = (i: StepUpInput): StepUp => {
  switch (i.frame) {
    case 'sandboxed':
    case 'opaque':
    case 'blank':
    case 'blob':
      return { kind: 'refuse', reason: 'frame-not-allowed' };
    case 'cross-origin':
      return { kind: 'browser-ui', reason: 'cross-origin-frame' };
    case 'top':
    case 'same-origin':
      break;
  }
  if (i.isObscured) return { kind: 'browser-ui', reason: 'obscured' };
  const sensitive = i.fill === 'card' || i.fill === 'identity';
  if (sensitive) {
    if (!i.isC4Supported) return { kind: 'browser-ui', reason: 'visibility-unsupported' };
    return i.isCardHostRemembered
      ? { kind: 'none' }
      : { kind: 'inline-confirm', reason: i.fill === 'card' ? 'card' : 'identity' };
  }
  if (i.fill === 'passkey-create') return { kind: 'inline-confirm', reason: 'passkey-create' };
  if (i.level !== 'exact' && !i.isHostConfirmed) {
    return i.isC4Supported
      ? { kind: 'inline-confirm', reason: 'first-cross-host' }
      : { kind: 'browser-ui', reason: 'visibility-unsupported' };
  }
  if (i.settings.isAskBeforeFilling) return { kind: 'inline-confirm', reason: 'ask-always' };
  return { kind: 'none' };
};
