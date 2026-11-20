import type { Attestation, CheckId } from '../protocol.ts';
import { collectRoots } from '../snapshot/snapshot.ts';
import type { SnapshotContext } from '../snapshot/snapshot.ts';
import type { Rect } from '../types.ts';
import { checkC1, checkC2, checkC3, hitPoints } from './style-checks.ts';
import type { CheckFailure, CheckResult, StyleFacts, Viewport } from './style-checks.ts';

export type MeasureContext = Pick<SnapshotContext, 'win' | 'natives' | 'getShadowRoot'>;

const toRect = (r: DOMRect): Rect => ({ x: r.x, y: r.y, w: r.width, h: r.height });

export const factsOf = (ctx: MeasureContext, el: Element): StyleFacts => {
  const s = ctx.natives.getComputedStyle(el);
  const get = (key: string): string => {
    const v: unknown = Reflect.get(s, key);
    return typeof v === 'string' ? v : '';
  };
  const maskImage = get('maskImage') === '' ? get('webkitMaskImage') : get('maskImage');
  return {
    display: s.display,
    visibility: s.visibility,
    opacity: Number.parseFloat(s.opacity),
    pointerEvents: s.pointerEvents,
    filter: s.filter,
    backdropFilter:
      get('backdropFilter') === '' ? get('webkitBackdropFilter') : get('backdropFilter'),
    mixBlendMode: s.mixBlendMode,
    clipPath: get('clipPath'),
    mask: maskImage,
    transform: s.transform,
    contain: get('contain'),
    isolation: s.isolation,
    zoom: get('zoom'),
    contentVisibility: get('contentVisibility'),
  };
};

export const chainOf = (ctx: MeasureContext, el: Element): StyleFacts[] => {
  const chain: StyleFacts[] = [];
  let node: Element | null = el;
  while (node !== null && chain.length < 64) {
    chain.push(factsOf(ctx, node));
    const parent: Element | null = node.parentElement;
    if (parent !== null) {
      node = parent;
      continue;
    }
    const root = node.getRootNode();
    node = root instanceof ShadowRoot ? root.host : null;
  }
  return chain;
};

export const viewportOf = (ctx: MeasureContext): Viewport => ({
  w: ctx.win.innerWidth,
  h: ctx.win.innerHeight,
});

const hitsTarget = (hit: Element | null, target: Element): boolean =>
  hit !== null &&
  (hit === target ||
    target.contains(hit) ||
    (hit.contains(target) && hit instanceof HTMLLabelElement));

const rootOf = (ctx: MeasureContext, el: Element): Document | ShadowRoot => {
  const root = el.getRootNode();
  return root instanceof ShadowRoot ? root : ctx.win.document;
};

export type TargetMeasure = { c1: CheckResult; c3: CheckResult; rect: Rect };

export const measureTarget = (ctx: MeasureContext, target: Element): TargetMeasure => {
  const rect = toRect(ctx.natives.getBoundingClientRect(target));
  const c1 = checkC1(chainOf(ctx, target), rect, viewportOf(ctx));
  const root = rootOf(ctx, target);
  const hits = hitPoints(rect).map((p) =>
    hitsTarget(ctx.natives.elementFromPoint(root, p.x, p.y), target),
  );
  return { c1, c3: checkC3(hits, undefined), rect };
};

export type HostMeasure = { c2: CheckResult; c3: CheckResult };

export const measureHost = (ctx: MeasureContext, host: Element, expected: Rect): HostMeasure => {
  const rect = toRect(ctx.natives.getBoundingClientRect(host));
  const c2 = checkC2(chainOf(ctx, host), rect, expected, viewportOf(ctx));
  const clickHits = hitPoints(rect).map(
    (p) => ctx.natives.elementFromPoint(ctx.win.document, p.x, p.y) === host,
  );
  const c3 = clickHits.every((h) => h)
    ? { ok: true as const }
    : { ok: false as const, failure: 'pointer-events' as CheckFailure };
  return { c2, c3 };
};

const isMatch = (ctx: MeasureContext, el: Element, selector: string): boolean => {
  try {
    return ctx.natives.matches(el, selector);
  } catch {
    return false;
  }
};

export const findForeignTopLayer = (ctx: MeasureContext, ours: Element): Element | undefined => {
  for (const root of collectRoots(ctx)) {
    for (const el of ctx.natives.querySelectorAll(root, '[popover],dialog')) {
      if (el === ours) continue;
      if (isMatch(ctx, el, ':popover-open') || isMatch(ctx, el, ':modal')) return el;
    }
  }
  const fullscreen = ctx.win.document.fullscreenElement;
  return fullscreen !== null && fullscreen !== ours ? fullscreen : undefined;
};

export type AttestInput = {
  c1: CheckResult;
  c2: CheckResult;
  c3: CheckResult;
  c4: { ok: boolean; isSupported: boolean };
  isTampered: boolean;
  nowMs: number;
};

export type AttestOutcome = { ok: true; attestation: Attestation } | { ok: false; failed: CheckId };

export const attest = (i: AttestInput): AttestOutcome => {
  if (!i.c1.ok) return { ok: false, failed: 'C1' };
  if (!i.c2.ok) return { ok: false, failed: 'C2' };
  if (!i.c3.ok) return { ok: false, failed: 'C3' };
  if (!i.c4.ok) return { ok: false, failed: 'C4' };
  if (i.isTampered) return { ok: false, failed: 'C5' };
  const passed: CheckId[] = ['C1', 'C2', 'C3', 'C5'];
  if (i.c4.isSupported) passed.push('C4');
  return {
    ok: true,
    attestation: { checkedAtMs: i.nowMs, passed, isC4Supported: i.c4.isSupported },
  };
};
