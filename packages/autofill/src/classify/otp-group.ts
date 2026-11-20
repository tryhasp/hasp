import type { FieldId } from '../brand.ts';
import type { FieldSnap } from '../types.ts';

const MIN_CELLS = 4;
const MAX_CELLS = 8;
const ROW_TOLERANCE_PX = 4;
const MAX_CELL_WIDTH_PX = 56;
const MAX_GAP_PX = 48;
const cellTypes: ReadonlySet<string> = new Set(['text', 'tel', 'number', 'password', '']);

const isCell = (f: FieldSnap): boolean => {
  if (f.tag !== 'input' || !f.visible || f.disabled || f.readonly) return false;
  if (!cellTypes.has(f.type)) return false;
  if (f.maxlength === 1) return true;
  return f.maxlength === undefined && f.rect.w > 0 && f.rect.w <= MAX_CELL_WIDTH_PX;
};

const continuesRow = (prev: FieldSnap, next: FieldSnap): boolean => {
  if (prev.formId !== next.formId) return false;
  if (Math.abs(prev.rect.y - next.rect.y) > ROW_TOLERANCE_PX) return false;
  const gap = next.rect.x - (prev.rect.x + prev.rect.w);
  return gap >= -1 && gap <= MAX_GAP_PX;
};

export const findOtpGroups = (fields: readonly FieldSnap[]): FieldId[][] => {
  const groups: FieldSnap[][] = [];
  let run: FieldSnap[] = [];
  const flush = (): void => {
    if (run.length >= MIN_CELLS && run.length <= MAX_CELLS) groups.push(run);
    run = [];
  };
  for (const f of fields) {
    if (!isCell(f)) {
      if (f.tag !== 'button') flush();
      continue;
    }
    const last = run.at(-1);
    if (last !== undefined && !continuesRow(last, f)) flush();
    run.push(f);
  }
  flush();
  return groups.map((g) => g.map((f) => f.id));
};
