import type { Rect } from '../types.ts';

export const GAP_PX = 4;
export const CORNER_PX = 12;

export type VisualViewportLike = {
  offsetLeft: number;
  offsetTop: number;
  width: number;
  height: number;
};

export type ViewportSource = {
  innerWidth: number;
  innerHeight: number;
  visualViewport: VisualViewportLike | null;
};

// Why: the on-screen keyboard and pinch zoom shrink the visual viewport on iOS without changing the layout viewport, so the menu is kept inside the visual one.
export const visibleBounds = (win: ViewportSource): Rect => {
  const v = win.visualViewport;
  if (v === null || v.width <= 0 || v.height <= 0) {
    return { x: 0, y: 0, w: win.innerWidth, h: win.innerHeight };
  }
  return { x: v.offsetLeft, y: v.offsetTop, w: v.width, h: v.height };
};

export const placeMenu = (
  target: Rect | undefined,
  size: { width: number; height: number },
  bounds: Rect,
): Rect => {
  const right = bounds.x + bounds.w;
  const bottom = bounds.y + bounds.h;
  const left =
    target === undefined
      ? Math.max(bounds.x, right - size.width - CORNER_PX)
      : Math.max(bounds.x, Math.min(target.x, right - size.width));
  const below = target === undefined ? bounds.y + CORNER_PX : target.y + target.h + GAP_PX;
  const top =
    target === undefined || below + size.height <= bottom
      ? below
      : Math.max(bounds.y, target.y - GAP_PX - size.height);
  return { x: left, y: top, w: size.width, h: size.height };
};
