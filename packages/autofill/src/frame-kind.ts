import type { FrameKind } from './types.ts';

export type FrameFacts = {
  isTop: boolean;
  protocol: string;
  origin: string;
  isSameOriginAsTop: boolean;
};

export const frameKindOf = (f: FrameFacts): FrameKind => {
  if (f.protocol === 'about:') return 'blank';
  if (f.protocol === 'blob:') return 'blob';
  if (f.origin === 'null' || f.origin === '') return f.isTop ? 'opaque' : 'sandboxed';
  if (f.isTop) return 'top';
  return f.isSameOriginAsTop ? 'same-origin' : 'cross-origin';
};

export const detectFrameKind = (win: Window): FrameKind => {
  const isTop = win.top === win;
  let isSameOriginAsTop = isTop;
  if (!isTop) {
    try {
      isSameOriginAsTop = win.top?.location.origin === win.location.origin;
    } catch {
      isSameOriginAsTop = false;
    }
  }
  return frameKindOf({
    isTop,
    protocol: win.location.protocol,
    origin: win.location.origin,
    isSameOriginAsTop,
  });
};

export const canFillIn = (kind: FrameKind): boolean =>
  kind === 'top' || kind === 'same-origin' || kind === 'cross-origin';
