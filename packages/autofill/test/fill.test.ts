import { beforeEach, describe, expect, it } from 'vitest';

import { classifyPage } from '../src/classify/classify.ts';
import { planFill } from '../src/fill/plan.ts';
import { formatExpiry, matchOptionIndex } from '../src/fill/select-match.ts';
import { Redacted } from '../src/redacted.ts';
import { field, page, resetFixtures } from './fixtures.ts';

beforeEach(resetFixtures);

describe('expiry formats', () => {
  it.each([
    ['MM/YY default', { maxlength: undefined, placeholder: '' }, '07/29'],
    ['maxlength 5', { maxlength: 5, placeholder: '' }, '07/29'],
    ['maxlength 4', { maxlength: 4, placeholder: '' }, '0729'],
    ['maxlength 6', { maxlength: 6, placeholder: '' }, '072029'],
    ['MM / YYYY placeholder', { maxlength: 7, placeholder: 'MM / YYYY' }, '07 / 2029'],
    ['MM/YYYY placeholder', { maxlength: undefined, placeholder: 'MM/YYYY' }, '07/2029'],
  ])('%s', (_n, hint, expected) => {
    expect(formatExpiry('7', '2029', hint)).toBe(expected);
  });
});

describe('select matching', () => {
  const months = Array.from({ length: 12 }, (_, i) => ({
    value: String(i + 1).padStart(2, '0'),
    label: `${i + 1}월`,
  }));
  it.each([
    ['07', 6],
    ['7', 6],
    ['12', 11],
  ])('month %s -> index %i', (m, index) => {
    expect(matchOptionIndex(months, m, 'month')).toBe(index);
  });

  it('matches 2 and 4 digit years by value then label', () => {
    const years = [
      { value: '2028', label: '2028' },
      { value: '2029', label: '2029' },
    ];
    expect(matchOptionIndex(years, '29', 'year')).toBe(1);
    expect(matchOptionIndex(years, '2028', 'year')).toBe(0);
    expect(matchOptionIndex([{ value: 'a', label: '29' }], '2029', 'year')).toBe(0);
  });

  it('matches a country by ISO code then by localised name', () => {
    const countries = [
      { value: 'US', label: 'United States' },
      { value: 'KR', label: '대한민국' },
    ];
    expect(matchOptionIndex(countries, 'KR', 'text')).toBe(1);
    expect(matchOptionIndex(countries, '대한민국', 'text')).toBe(1);
    expect(matchOptionIndex(countries, 'FR', 'text')).toBe(-1);
  });
});

describe('fill planning', () => {
  it('maps login fields to the username and password values', () => {
    const fields = [field({ name: 'username' }), field({ type: 'password' })];
    const form = classifyPage(page(fields), {})[0];
    if (form === undefined) throw new Error('no form');
    const { steps } = planFill(form, fields, [
      { purpose: 'username', value: 'mino01' },
      { purpose: 'password', value: 'pw' },
    ]);
    expect(steps.map((s) => (s.kind === 'text' ? s.purpose : s.kind))).toEqual([
      'password',
      'username',
    ]);
  });

  it('splits an otp code over cells and refuses a count mismatch', () => {
    const cells = Array.from({ length: 6 }, (_, i) =>
      field({ maxlength: 1, rect: { x: 10 + i * 48, y: 100, w: 40, h: 44 } }),
    );
    const form = classifyPage(page(cells), {})[0];
    if (form === undefined) throw new Error('no form');
    expect(planFill(form, cells, [{ purpose: 'otp', value: '123456' }]).steps).toMatchObject([
      { kind: 'cells' },
    ]);
    expect(planFill(form, cells, [{ purpose: 'otp', value: '12345678' }]).errors).toEqual([
      { kind: 'otp-count-mismatch', cells: 6, digits: 8 },
    ]);
  });

  it('splits a card number over four parts and combines month and year for a single expiry field', () => {
    const parts = Array.from({ length: 4 }, (_, i) =>
      field({
        maxlength: 4,
        autocomplete: i === 0 ? ['cc-number'] : [],
        rect: { x: 10 + i * 80, y: 100, w: 70, h: 32 },
      }),
    );
    const exp = field({ autocomplete: ['cc-exp'] });
    const fields = [...parts, exp];
    const form = classifyPage(page(fields), {})[0];
    if (form === undefined) throw new Error('no form');
    const { steps } = planFill(form, fields, [
      { purpose: 'cc-number', value: '4111111111111111' },
      { purpose: 'cc-exp-month', value: '07' },
      { purpose: 'cc-exp-year', value: '2029' },
    ]);
    expect(steps.flatMap((s) => (s.kind === 'text' ? [s.value.reveal()] : []))).toEqual([
      '4111',
      '1111',
      '1111',
      '1111',
    ]);
    expect(steps.some((s) => s.kind === 'expiry')).toBe(true);
  });
});

describe('Redacted', () => {
  it('never prints its value', () => {
    const r = new Redacted('hunter2');
    expect(JSON.stringify({ r })).toBe('{"r":"[redacted]"}');
    expect(String(r)).toBe('[redacted]');
    expect(r.reveal()).toBe('hunter2');
  });
});
