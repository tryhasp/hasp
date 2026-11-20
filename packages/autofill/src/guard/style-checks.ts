import type { Rect } from '../types.ts';

export type StyleFacts = {
  display: string;
  visibility: string;
  opacity: number;
  pointerEvents: string;
  filter: string;
  backdropFilter: string;
  mixBlendMode: string;
  clipPath: string;
  mask: string;
  transform: string;
  contain: string;
  isolation: string;
  zoom: string;
  contentVisibility: string;
};

export type Viewport = { w: number; h: number };

export type CheckFailure =
  | 'display'
  | 'visibility'
  | 'opacity'
  | 'pointer-events'
  | 'filter'
  | 'backdrop-filter'
  | 'blend-mode'
  | 'clip-path'
  | 'mask'
  | 'transform'
  | 'contain'
  | 'isolation'
  | 'zoom'
  | 'content-visibility'
  | 'size'
  | 'off-viewport'
  | 'moved';

export type CheckResult = { ok: true } | { ok: false; failure: CheckFailure };

export const MIN_TARGET_WIDTH_PX = 20;
export const MIN_TARGET_HEIGHT_PX = 10;
const SCALE_EPSILON = 0.001;
const OPACITY_EPSILON = 0.001;
const MOVE_TOLERANCE_PX = 1;

const pass: CheckResult = { ok: true };
const fail = (failure: CheckFailure): CheckResult => ({ ok: false, failure });
const isNone = (value: string): boolean => value === '' || value === 'none';

export const isTransformSafe = (transform: string): boolean => {
  if (isNone(transform)) return true;
  const match = /^matrix(3d)?\(([^)]*)\)$/.exec(transform.trim());
  const body = match?.[2];
  if (body === undefined) return false;
  const v = body.split(',').map((p) => Number.parseFloat(p));
  if (v.some((n) => !Number.isFinite(n))) return false;
  const is3d = match?.[1] === '3d';
  const [a, b, c, d] = is3d ? [v[0], v[1], v[4], v[5]] : [v[0], v[1], v[2], v[3]];
  if (a === undefined || b === undefined || c === undefined || d === undefined) return false;
  if (Math.abs(b) > SCALE_EPSILON || Math.abs(c) > SCALE_EPSILON) return false;
  return a >= 1 - SCALE_EPSILON && d >= 1 - SCALE_EPSILON;
};

const checkVisualFacts = (f: StyleFacts): CheckResult => {
  if (f.display === 'none') return fail('display');
  if (f.visibility !== 'visible') return fail('visibility');
  if (f.opacity < 1 - OPACITY_EPSILON) return fail('opacity');
  if (f.pointerEvents === 'none') return fail('pointer-events');
  if (!isNone(f.filter)) return fail('filter');
  if (!isNone(f.backdropFilter)) return fail('backdrop-filter');
  if (f.mixBlendMode !== 'normal') return fail('blend-mode');
  if (!isNone(f.clipPath)) return fail('clip-path');
  if (!isNone(f.mask)) return fail('mask');
  if (!isTransformSafe(f.transform)) return fail('transform');
  if (f.contentVisibility === 'hidden') return fail('content-visibility');
  return pass;
};

const intersectsViewport = (r: Rect, v: Viewport): boolean =>
  r.x < v.w && r.y < v.h && r.x + r.w > 0 && r.y + r.h > 0;

export const checkC1 = (
  chain: readonly StyleFacts[],
  rect: Rect,
  viewport: Viewport,
): CheckResult => {
  for (const facts of chain) {
    const r = checkVisualFacts(facts);
    if (!r.ok) return r;
  }
  if (rect.w < MIN_TARGET_WIDTH_PX || rect.h < MIN_TARGET_HEIGHT_PX) return fail('size');
  if (!intersectsViewport(rect, viewport)) return fail('off-viewport');
  return pass;
};

export const checkC2 = (
  chain: readonly StyleFacts[],
  rect: Rect,
  expected: Rect,
  viewport: Viewport,
): CheckResult => {
  for (const facts of chain) {
    const r = checkVisualFacts(facts);
    if (!r.ok) return r;
    if (facts.contain !== '' && facts.contain !== 'none') return fail('contain');
    if (facts.isolation !== '' && facts.isolation !== 'auto') return fail('isolation');
    if (facts.zoom !== '' && facts.zoom !== '1' && facts.zoom !== 'normal') return fail('zoom');
  }
  const moved =
    Math.abs(rect.x - expected.x) > MOVE_TOLERANCE_PX ||
    Math.abs(rect.y - expected.y) > MOVE_TOLERANCE_PX ||
    Math.abs(rect.w - expected.w) > MOVE_TOLERANCE_PX ||
    Math.abs(rect.h - expected.h) > MOVE_TOLERANCE_PX;
  if (moved) return fail('moved');
  if (!intersectsViewport(rect, viewport)) return fail('off-viewport');
  return pass;
};

export type Point = { x: number; y: number };

export const hitPoints = (rect: Rect): Point[] => {
  const inset = Math.max(1, Math.min(4, rect.w / 4, rect.h / 4));
  const left = rect.x + inset;
  const right = rect.x + rect.w - inset;
  const top = rect.y + inset;
  const bottom = rect.y + rect.h - inset;
  return [
    { x: rect.x + rect.w / 2, y: rect.y + rect.h / 2 },
    { x: left, y: top },
    { x: right, y: top },
    { x: left, y: bottom },
    { x: right, y: bottom },
  ];
};

export const checkC3 = (
  targetHits: readonly boolean[],
  clickHitIsOurs: boolean | undefined,
): CheckResult => {
  if (targetHits.length === 0 || targetHits.some((hit) => !hit)) return fail('off-viewport');
  if (clickHitIsOurs === false) return fail('pointer-events');
  return pass;
};

export type VisibilityObservation = {
  isSupported: boolean;
  isVisible: boolean;
};

export const checkC4 = (o: VisibilityObservation): { ok: boolean; isSupported: boolean } =>
  o.isSupported ? { ok: o.isVisible, isSupported: true } : { ok: true, isSupported: false };

export const isTrustedGesture = (event: { isTrusted: boolean }): boolean => event.isTrusted;
