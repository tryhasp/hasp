export const DWELL_AFTER_SHOW_MS = 400;
export const DWELL_AFTER_MOVE_MS = 150;

export type DwellState = {
  shownAtMs: number | undefined;
  lastMoveMs: number | undefined;
  hasPointerMovedInside: boolean;
};

export const initialDwell: DwellState = {
  shownAtMs: undefined,
  lastMoveMs: undefined,
  hasPointerMovedInside: false,
};

export const dwellShown = (nowMs: number): DwellState => ({
  shownAtMs: nowMs,
  lastMoveMs: undefined,
  hasPointerMovedInside: false,
});

export const dwellMoved = (s: DwellState, nowMs: number): DwellState => ({
  ...s,
  lastMoveMs: nowMs,
});

export const dwellPointer = (s: DwellState): DwellState => ({ ...s, hasPointerMovedInside: true });

export const isDwellSatisfied = (s: DwellState, nowMs: number): boolean => {
  if (s.shownAtMs === undefined) return false;
  if (nowMs - s.shownAtMs < DWELL_AFTER_SHOW_MS) return false;
  if (s.lastMoveMs !== undefined && nowMs - s.lastMoveMs < DWELL_AFTER_MOVE_MS) return false;
  return s.hasPointerMovedInside;
};
