import { DWELL_AFTER_SHOW_MS } from './dwell.ts';
import type { DwellState } from './dwell.ts';

export const TAP_MAX_MS = 1000;
export const ARM_MAX_MS = 10_000;

export type TouchGate = {
  armed: { atMs: number; key: string } | undefined;
  confirm: { downAtMs: number } | undefined;
};

export const noTouch: TouchGate = { armed: undefined, confirm: undefined };

// Why: a finger has no hover, so nothing proves the user saw the menu; the first trusted touch-down inside the frame only arms the row (the decoy-button timing attack ends here), and a second tap on the same row at least DWELL_AFTER_SHOW_MS later, with no layout move in between, confirms.
export const touchDown = (
  gate: TouchGate,
  dwell: DwellState,
  nowMs: number,
  key: string | undefined,
): TouchGate => {
  if (key === undefined || dwell.shownAtMs === undefined) return noTouch;
  const armed = gate.armed;
  const isConfirming =
    armed !== undefined &&
    armed.key === key &&
    armed.atMs >= dwell.shownAtMs &&
    nowMs - armed.atMs >= DWELL_AFTER_SHOW_MS &&
    nowMs - armed.atMs <= ARM_MAX_MS &&
    (dwell.lastMoveMs === undefined || dwell.lastMoveMs <= armed.atMs);
  return isConfirming
    ? { armed, confirm: { downAtMs: nowMs } }
    : { armed: { atMs: nowMs, key }, confirm: undefined };
};

export const isTapAllowed = (gate: TouchGate, dwell: DwellState, nowMs: number): boolean => {
  if (gate.armed === undefined || gate.confirm === undefined || dwell.shownAtMs === undefined) {
    return false;
  }
  if (nowMs - gate.confirm.downAtMs > TAP_MAX_MS) return false;
  if (nowMs - dwell.shownAtMs < DWELL_AFTER_SHOW_MS) return false;
  return dwell.lastMoveMs === undefined || dwell.lastMoveMs <= gate.armed.atMs;
};
