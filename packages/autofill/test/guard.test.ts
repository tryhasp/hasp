import { describe, expect, it } from 'vitest';

import {
  dwellMoved,
  dwellPointer,
  dwellShown,
  initialDwell,
  isDwellSatisfied,
} from '../src/guard/dwell.ts';
import { MAX_STRIKES, addStrike, noStrikes } from '../src/guard/strikes.ts';
import {
  checkC1,
  checkC2,
  checkC3,
  checkC4,
  hitPoints,
  isTransformSafe,
} from '../src/guard/style-checks.ts';
import type { StyleFacts } from '../src/guard/style-checks.ts';

const clean: StyleFacts = {
  display: 'block',
  visibility: 'visible',
  opacity: 1,
  pointerEvents: 'auto',
  filter: 'none',
  backdropFilter: 'none',
  mixBlendMode: 'normal',
  clipPath: 'none',
  mask: 'none',
  transform: 'none',
  contain: 'none',
  isolation: 'auto',
  zoom: '1',
  contentVisibility: 'visible',
};
const viewport = { w: 1280, h: 800 };
const rect = { x: 100, y: 100, w: 240, h: 32 };

describe('C1: target and ancestors', () => {
  it('passes a clean chain', () => {
    expect(checkC1([clean, clean], rect, viewport)).toEqual({ ok: true });
  });

  it.each([
    ['display', { display: 'none' }],
    ['visibility', { visibility: 'hidden' }],
    ['opacity', { opacity: 0.99 }],
    ['pointer-events', { pointerEvents: 'none' }],
    ['filter', { filter: 'opacity(0)' }],
    ['backdrop-filter', { backdropFilter: 'blur(2px)' }],
    ['blend-mode', { mixBlendMode: 'screen' }],
    ['clip-path', { clipPath: 'inset(100%)' }],
    ['mask', { mask: 'linear-gradient(red, blue)' }],
    ['transform', { transform: 'matrix(0.5, 0, 0, 0.5, 0, 0)' }],
    ['content-visibility', { contentVisibility: 'hidden' }],
  ] as const)('fails on %s of an ancestor', (failure, over) => {
    expect(checkC1([clean, { ...clean, ...over }], rect, viewport)).toEqual({ ok: false, failure });
  });

  it('fails on a target smaller than 20x10 and on an off-viewport target', () => {
    expect(checkC1([clean], { ...rect, w: 19 }, viewport)).toEqual({ ok: false, failure: 'size' });
    expect(checkC1([clean], { ...rect, h: 9 }, viewport)).toEqual({ ok: false, failure: 'size' });
    expect(checkC1([clean], { ...rect, x: -5000 }, viewport)).toEqual({
      ok: false,
      failure: 'off-viewport',
    });
  });

  it.each([
    ['none', true],
    ['matrix(1, 0, 0, 1, 0, 40)', true],
    ['matrix(2, 0, 0, 2, 0, 0)', true],
    ['matrix(0.01, 0, 0, 0.01, 0, 0)', false],
    ['matrix(1, 0.2, -0.2, 1, 0, 0)', false],
    ['perspective(100px)', false],
  ])('transform %s safe=%s', (transform, safe) => {
    expect(isTransformSafe(transform)).toBe(safe);
  });
});

describe('C2: overlay host', () => {
  const expected = { x: 10, y: 10, w: 340, h: 100 };
  it('passes when the host sits where we put it', () => {
    expect(checkC2([clean], expected, expected, viewport)).toEqual({ ok: true });
  });

  it.each([
    ['contain', { contain: 'layout' }],
    ['isolation', { isolation: 'isolate' }],
    ['zoom', { zoom: '0.1' }],
    ['opacity', { opacity: 0.5 }],
  ] as const)('fails on %s of an ancestor', (failure, over) => {
    expect(checkC2([clean, { ...clean, ...over }], expected, expected, viewport)).toEqual({
      ok: false,
      failure,
    });
  });

  it('fails when the host was moved or resized by the page', () => {
    expect(checkC2([clean], { ...expected, x: 50 }, expected, viewport)).toEqual({
      ok: false,
      failure: 'moved',
    });
  });
});

describe('C3: hit tests', () => {
  it('uses the centre and four inset corners', () => {
    expect(hitPoints(rect)).toHaveLength(5);
  });
  it('requires every point to resolve to the target', () => {
    expect(checkC3([true, true, true, true, true], undefined)).toEqual({ ok: true });
    expect(checkC3([true, true, false, true, true], undefined)).toEqual({
      ok: false,
      failure: 'off-viewport',
    });
    expect(checkC3([true], false)).toEqual({ ok: false, failure: 'pointer-events' });
  });
});

describe('C4: visibility observer', () => {
  it.each([
    [
      { isSupported: true, isVisible: true },
      { ok: true, isSupported: true },
    ],
    [
      { isSupported: true, isVisible: false },
      { ok: false, isSupported: true },
    ],
    [
      { isSupported: false, isVisible: false },
      { ok: true, isSupported: false },
    ],
  ])('%j', (input, expected) => {
    expect(checkC4(input)).toEqual(expected);
  });
});

describe('C6: dwell', () => {
  it('ignores input for 400 ms after show and requires a pointer move', () => {
    const shown = dwellShown(1000);
    expect(isDwellSatisfied(dwellPointer(shown), 1399)).toBe(false);
    expect(isDwellSatisfied(dwellPointer(shown), 1400)).toBe(true);
    expect(isDwellSatisfied(shown, 5000)).toBe(false);
  });

  it('ignores input for 150 ms after a move or resize', () => {
    const s = dwellMoved(dwellPointer(dwellShown(1000)), 2000);
    expect(isDwellSatisfied(s, 2149)).toBe(false);
    expect(isDwellSatisfied(s, 2150)).toBe(true);
  });

  it('is never satisfied before show', () => {
    expect(isDwellSatisfied(dwellPointer(initialDwell), 9999)).toBe(false);
  });
});

describe('C10: strikes', () => {
  it('disables on the third strike and announces once', () => {
    const one = addStrike(noStrikes);
    const two = addStrike(one);
    const three = addStrike(two);
    const four = addStrike(three);
    expect([one.isDisabled, two.isDisabled, three.isDisabled]).toEqual([false, false, true]);
    expect([three.isNoticeDue, four.isNoticeDue]).toEqual([true, false]);
    expect(four.count).toBe(MAX_STRIKES);
  });
});
