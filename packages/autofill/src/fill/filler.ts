import type { FieldId } from '../brand.ts';
import { measureTarget } from '../guard/measure.ts';
import type { MeasureContext } from '../guard/measure.ts';
import { err, ok } from '../result.ts';
import type { Result } from '../result.ts';
import type { Natives } from '../snapshot/natives.ts';
import type { ElementRegistry } from '../snapshot/registry.ts';
import type { FieldPurpose } from '../types.ts';
import type { PlannedStep } from './plan.ts';
import { formatExpiry, matchOptionIndex } from './select-match.ts';

export type FillFailure = 'gone' | 'not-fillable' | 'obscured' | 'rejected' | 'select-no-match';

export type FillError = { kind: FillFailure; purpose: FieldPurpose };

export type FillContext = MeasureContext & {
  win: Window & typeof globalThis;
  registry: ElementRegistry;
  natives: Natives;
};

export type FillOptions = { isPerCharEvents: boolean };

type Input = HTMLInputElement | HTMLTextAreaElement;

const asInput = (el: Element | undefined): Input | undefined =>
  el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement ? el : undefined;

const fire = (ctx: FillContext, target: EventTarget, event: Event): void => {
  ctx.natives.dispatch(target, event);
};

const keyEvent = (ctx: FillContext, type: string, key: string): KeyboardEvent =>
  new ctx.win.KeyboardEvent(type, { key, bubbles: true, cancelable: true, composed: true });

const inputEvent = (ctx: FillContext, type: string, data: string): InputEvent =>
  new ctx.win.InputEvent(type, {
    data,
    inputType: 'insertText',
    bubbles: true,
    cancelable: type === 'beforeinput',
    composed: true,
  });

const setPlain = (ctx: FillContext, el: Input, value: string): void => {
  ctx.natives.focus(el);
  ctx.natives.setValue(el, value);
  fire(ctx, el, inputEvent(ctx, 'input', value));
  fire(ctx, el, new ctx.win.Event('change', { bubbles: true }));
};

const setPerChar = (ctx: FillContext, el: Input, value: string): void => {
  ctx.natives.focus(el);
  ctx.natives.setValue(el, '');
  let typed = '';
  for (const ch of value) {
    fire(ctx, el, keyEvent(ctx, 'keydown', ch));
    fire(ctx, el, keyEvent(ctx, 'keypress', ch));
    fire(ctx, el, inputEvent(ctx, 'beforeinput', ch));
    typed += ch;
    ctx.natives.setValue(el, typed);
    fire(ctx, el, inputEvent(ctx, 'input', ch));
    fire(ctx, el, keyEvent(ctx, 'keyup', ch));
  }
  fire(ctx, el, new ctx.win.Event('change', { bubbles: true }));
};

const setCell = (ctx: FillContext, el: Input, ch: string): void => {
  ctx.natives.focus(el);
  fire(ctx, el, keyEvent(ctx, 'keydown', ch));
  fire(ctx, el, inputEvent(ctx, 'beforeinput', ch));
  ctx.natives.setValue(el, ch);
  fire(ctx, el, inputEvent(ctx, 'input', ch));
  fire(ctx, el, keyEvent(ctx, 'keyup', ch));
  fire(ctx, el, new ctx.win.Event('change', { bubbles: true }));
};

const pasteCode = (ctx: FillContext, first: Input, code: string): void => {
  try {
    const data = new ctx.win.DataTransfer();
    data.setData('text/plain', code);
    ctx.natives.focus(first);
    fire(
      ctx,
      first,
      new ctx.win.ClipboardEvent('paste', {
        clipboardData: data,
        bubbles: true,
        cancelable: true,
        composed: true,
      }),
    );
  } catch {
    return;
  }
};

const isWritable = (el: Input): boolean => !el.disabled && !el.readOnly;

const fillCells = (ctx: FillContext, cells: readonly Input[], code: string): boolean => {
  const first = cells[0];
  if (first === undefined) return false;
  pasteCode(ctx, first, code);
  if (cells.every((c, i) => c.value === code[i])) return true;
  for (const [i, cell] of cells.entries()) {
    const ch = code[i];
    if (ch === undefined) return false;
    setCell(ctx, cell, ch);
    if (cell.value !== ch) return false;
  }
  return true;
};

export const fillSteps = (
  ctx: FillContext,
  steps: readonly PlannedStep[],
  options: FillOptions,
): Result<{ filled: number }, FillError> => {
  const resolved: { step: PlannedStep; els: Element[] }[] = [];
  for (const step of steps) {
    const ids: readonly FieldId[] = step.kind === 'cells' ? step.ids : [step.id];
    const els: Element[] = [];
    const purpose: FieldPurpose =
      step.kind === 'cells' ? 'otp-cell' : step.kind === 'expiry' ? 'cc-exp' : step.purpose;
    for (const id of ids) {
      const el = ctx.registry.element(id);
      if (el === undefined || !el.isConnected) return err({ kind: 'gone', purpose });
      els.push(el);
    }
    resolved.push({ step, els });
  }
  for (const { step, els } of resolved) {
    const purpose: FieldPurpose =
      step.kind === 'cells' ? 'otp-cell' : step.kind === 'expiry' ? 'cc-exp' : step.purpose;
    for (const el of els) {
      const m = measureTarget(ctx, el);
      if (!m.c1.ok || !m.c3.ok) return err({ kind: 'obscured', purpose });
    }
  }
  let filled = 0;
  for (const { step, els } of resolved) {
    const purpose: FieldPurpose =
      step.kind === 'cells' ? 'otp-cell' : step.kind === 'expiry' ? 'cc-exp' : step.purpose;
    if (step.kind === 'cells') {
      const cells = els.map(asInput);
      if (cells.some((c) => c === undefined || !isWritable(c)))
        return err({ kind: 'not-fillable', purpose });
      const writable = cells.filter((c): c is Input => c !== undefined);
      if (!fillCells(ctx, writable, step.code.reveal())) return err({ kind: 'rejected', purpose });
      filled += writable.length;
      continue;
    }
    const el = els[0];
    if (el instanceof HTMLSelectElement) {
      const wanted = step.kind === 'expiry' ? undefined : step.value.reveal();
      const mode =
        step.kind === 'expiry'
          ? 'text'
          : step.purpose === 'cc-exp-month'
            ? 'month'
            : step.purpose === 'cc-exp-year'
              ? 'year'
              : 'text';
      const available = Array.from(el.options, (o) => ({ value: o.value, label: o.label }));
      const index = wanted === undefined ? -1 : matchOptionIndex(available, wanted, mode);
      if (index < 0) return err({ kind: 'select-no-match', purpose });
      const option = el.options[index];
      if (option === undefined) return err({ kind: 'select-no-match', purpose });
      ctx.natives.setValue(el, option.value);
      fire(ctx, el, new ctx.win.Event('input', { bubbles: true }));
      fire(ctx, el, new ctx.win.Event('change', { bubbles: true }));
      filled += 1;
      continue;
    }
    const input = asInput(el);
    if (input === undefined || !isWritable(input)) return err({ kind: 'not-fillable', purpose });
    const value =
      step.kind === 'expiry'
        ? formatExpiry(step.month.reveal(), step.year.reveal(), {
            maxlength: input.maxLength > 0 ? input.maxLength : undefined,
            placeholder: input.placeholder,
          })
        : step.kind === 'text'
          ? step.value.reveal()
          : '';
    if (options.isPerCharEvents) setPerChar(ctx, input, value);
    else setPlain(ctx, input, value);
    if (input.value !== value) return err({ kind: 'rejected', purpose });
    filled += 1;
  }
  return ok({ filled });
};

export const fillFocused = (
  ctx: FillContext,
  value: string,
  options: FillOptions,
): Result<null, FillError> => {
  const active = ctx.win.document.activeElement;
  const input = asInput(active ?? undefined);
  if (input === undefined || !isWritable(input))
    return err({ kind: 'not-fillable', purpose: 'none' });
  if (options.isPerCharEvents) setPerChar(ctx, input, value);
  else setPlain(ctx, input, value);
  return input.value === value ? ok(null) : err({ kind: 'rejected', purpose: 'none' });
};
