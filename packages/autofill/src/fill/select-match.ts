import type { SelectOption } from '../types.ts';

const stripZeros = (s: string): string => s.replace(/^0+(?=\d)/, '');

const yearForms = (year: string): string[] => {
  const full = year.length === 2 ? `20${year}` : year;
  return [full, full.slice(-2)];
};

const normalize = (s: string): string => s.normalize('NFC').trim().toLowerCase();

export const matchOptionIndex = (
  options: readonly SelectOption[],
  wanted: string,
  mode: 'text' | 'month' | 'year',
): number => {
  const candidates =
    mode === 'year'
      ? yearForms(wanted)
      : mode === 'month'
        ? [wanted, stripZeros(wanted), wanted.padStart(2, '0')]
        : [wanted];
  const norm = candidates.map(normalize);
  const byValue = options.findIndex((o) => norm.includes(normalize(o.value)));
  if (byValue >= 0) return byValue;
  const byLabel = options.findIndex((o) => norm.includes(normalize(o.label)));
  if (byLabel >= 0) return byLabel;
  const first = norm[0];
  if (mode === 'text') {
    return first === undefined ? -1 : options.findIndex((o) => normalize(o.label).includes(first));
  }
  const digits = (s: string): string => stripZeros(s.replace(/\D/g, ''));
  const targets = candidates.map(digits);
  return options.findIndex(
    (o) => targets.includes(digits(o.label)) || targets.includes(digits(o.value)),
  );
};

export const formatExpiry = (
  month: string,
  year: string,
  hint: { maxlength: number | undefined; placeholder: string },
): string => {
  const mm = month.padStart(2, '0');
  const full = year.length === 2 ? `20${year}` : year;
  const yy = full.slice(-2);
  const p = hint.placeholder.toLowerCase();
  const spaced = / \/ /.test(p);
  const sep = p.includes('/') ? (spaced ? ' / ' : '/') : p.includes('-') ? '-' : '';
  if (hint.maxlength === 4) return `${mm}${yy}`;
  if (hint.maxlength === 6) return `${mm}${full}`;
  if (hint.maxlength === 7 || p.includes('yyyy')) return `${mm}${sep === '' ? '/' : sep}${full}`;
  if (hint.maxlength === 5) return `${mm}/${yy}`;
  return `${mm}${sep === '' ? '/' : sep}${yy}`;
};
