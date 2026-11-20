import { describe, expect, it } from 'vitest';

import { DWELL_AFTER_SHOW_MS, dwellMoved, dwellShown } from '../src/guard/dwell.ts';
import type { TouchGate } from '../src/guard/touch.ts';
import { ARM_MAX_MS, TAP_MAX_MS, isTapAllowed, noTouch, touchDown } from '../src/guard/touch.ts';
import { CORNER_PX, GAP_PX, placeMenu, visibleBounds } from '../src/menu/placement.ts';

const T0 = 10_000;

const armAt = (shown: ReturnType<typeof dwellShown>, at: number, key = 'c0'): TouchGate =>
  touchDown(noTouch, shown, at, key);

describe('touch dwell (C6 on a touchscreen)', () => {
  it('never confirms on a single tap, even long after the show dwell', () => {
    const dwell = dwellShown(T0);
    const down = T0 + DWELL_AFTER_SHOW_MS + 500;
    expect(isTapAllowed(armAt(dwell, down), dwell, down + 60)).toBe(false);
  });

  it('confirms a second tap on the same row after the dwell has passed since the first', () => {
    const dwell = dwellShown(T0);
    const first = T0 + 100;
    const second = first + DWELL_AFTER_SHOW_MS + 10;
    const gate = touchDown(armAt(dwell, first), dwell, second, 'c0');
    expect(isTapAllowed(gate, dwell, second + 60)).toBe(true);
  });

  it('refuses a second tap that follows the first by less than the dwell', () => {
    const dwell = dwellShown(T0);
    const first = T0 + 100;
    const second = first + DWELL_AFTER_SHOW_MS - 1;
    const gate = touchDown(armAt(dwell, first), dwell, second, 'c0');
    expect(isTapAllowed(gate, dwell, second + 60)).toBe(false);
  });

  it('refuses a second tap on a different row and re-arms that row', () => {
    const dwell = dwellShown(T0);
    const first = T0 + 100;
    const second = first + 1000;
    const gate = touchDown(armAt(dwell, first), dwell, second, 'c1');
    expect(isTapAllowed(gate, dwell, second + 60)).toBe(false);
    expect(gate.armed).toEqual({ atMs: second, key: 'c1' });
  });

  it('refuses when the page moved, scrolled or resized after the first tap', () => {
    const shown = dwellShown(T0);
    const first = T0 + 100;
    const gate = armAt(shown, first);
    const moved = dwellMoved(shown, first + 50);
    const second = first + 1000;
    const confirmed = touchDown(gate, moved, second, 'c0');
    expect(isTapAllowed(confirmed, moved, second + 60)).toBe(false);
  });

  it('refuses a stale arm, a held touch and a tap with no touch-down inside the frame', () => {
    const dwell = dwellShown(T0);
    const first = T0 + 100;
    const stale = touchDown(armAt(dwell, first), dwell, first + ARM_MAX_MS + 1, 'c0');
    expect(stale.confirm).toBeUndefined();
    const second = first + 1000;
    const held = touchDown(armAt(dwell, first), dwell, second, 'c0');
    expect(isTapAllowed(held, dwell, second + TAP_MAX_MS + 1)).toBe(false);
    expect(isTapAllowed(noTouch, dwell, T0 + 5000)).toBe(false);
  });

  it('ignores a touch-down outside any row and while the menu is not shown', () => {
    const dwell = dwellShown(T0);
    expect(touchDown(armAt(dwell, T0 + 100), dwell, T0 + 900, undefined)).toEqual(noTouch);
    const hidden = { shownAtMs: undefined, lastMoveMs: undefined, hasPointerMovedInside: false };
    expect(touchDown(noTouch, hidden, T0, 'c0')).toEqual(noTouch);
  });

  it('does not let a decoy tap that landed before the menu was shown arm the row', () => {
    const dwell = dwellShown(T0 + 1000);
    const early = touchDown(
      { armed: { atMs: T0, key: 'c0' }, confirm: undefined },
      dwell,
      T0 + 1600,
      'c0',
    );
    expect(early.confirm).toBeUndefined();
  });
});

describe('menu placement in the visual viewport', () => {
  const size = { width: 340, height: 140 };
  const target = { x: 20, y: 300, w: 300, h: 40 };

  it('opens below the field when it fits', () => {
    const spot = placeMenu(target, size, { x: 0, y: 0, w: 393, h: 659 });
    expect(spot).toEqual({ x: 20, y: 300 + 40 + GAP_PX, w: 340, h: 140 });
  });

  it('opens above the field when the keyboard leaves no room below', () => {
    const spot = placeMenu(target, size, { x: 0, y: 0, w: 393, h: 400 });
    expect(spot.y).toBe(300 - GAP_PX - 140);
  });

  it('keeps the menu inside a panned and zoomed visual viewport', () => {
    const spot = placeMenu(target, size, { x: 100, y: 250, w: 300, h: 500 });
    expect(spot.x).toBe(100);
    expect(spot.x + spot.w).toBeGreaterThanOrEqual(400);
    expect(spot.y).toBeGreaterThanOrEqual(250);
  });

  it('pins to the top corner without a target', () => {
    const spot = placeMenu(undefined, size, { x: 0, y: 50, w: 393, h: 600 });
    expect(spot).toEqual({ x: 393 - 340 - CORNER_PX, y: 50 + CORNER_PX, w: 340, h: 140 });
  });

  it('reads the visual viewport and falls back to the layout viewport', () => {
    const visual = { offsetLeft: 5, offsetTop: 7, width: 300, height: 400 };
    expect(visibleBounds({ innerWidth: 393, innerHeight: 659, visualViewport: visual })).toEqual({
      x: 5,
      y: 7,
      w: 300,
      h: 400,
    });
    expect(visibleBounds({ innerWidth: 393, innerHeight: 659, visualViewport: null })).toEqual({
      x: 0,
      y: 0,
      w: 393,
      h: 659,
    });
  });
});
