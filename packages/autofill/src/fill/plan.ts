import type { FieldId } from '../brand.ts';
import { Redacted } from '../redacted.ts';
import type { FieldPurpose, FieldSnap, FormClass } from '../types.ts';

export type FillInput = { purpose: FieldPurpose; value: string };

export type PlannedStep =
  | { kind: 'text'; id: FieldId; purpose: FieldPurpose; value: Redacted<string> }
  | { kind: 'select'; id: FieldId; purpose: FieldPurpose; value: Redacted<string> }
  | { kind: 'expiry'; id: FieldId; month: Redacted<string>; year: Redacted<string> }
  | { kind: 'cells'; ids: readonly FieldId[]; code: Redacted<string> };

export type PlanError = { kind: 'otp-count-mismatch'; cells: number; digits: number };

const CARD_PART_LENGTH = 4;

const lookup = (inputs: readonly FillInput[], purpose: FieldPurpose): string | undefined =>
  inputs.find((i) => i.purpose === purpose)?.value;

const sourceFor = (purpose: FieldPurpose): FieldPurpose | undefined => {
  switch (purpose) {
    case 'username':
    case 'email':
      return 'username';
    case 'password':
    case 'current-password':
      return 'password';
    case 'new-password':
    case 'confirm-password':
      return 'new-password';
    case 'otp':
    case 'cc-number':
    case 'cc-csc':
    case 'cc-name':
    case 'cc-type':
    case 'cc-exp-month':
    case 'cc-exp-year':
    case 'name':
    case 'given-name':
    case 'family-name':
    case 'tel':
    case 'street-address':
    case 'address-line1':
    case 'address-line2':
    case 'postal-code':
    case 'country':
      return purpose;
    case 'cc-exp':
    case 'cc-number-part':
    case 'otp-cell':
    case 'submit':
    case 'none':
      return undefined;
  }
};

export const planFill = (
  form: FormClass,
  fields: readonly FieldSnap[],
  inputs: readonly FillInput[],
): { steps: PlannedStep[]; errors: PlanError[] } => {
  const steps: PlannedStep[] = [];
  const errors: PlanError[] = [];
  const cells = form.fields.filter((a) => a.purpose === 'otp-cell').map((a) => a.id);
  const code = lookup(inputs, 'otp');
  if (cells.length > 0 && code !== undefined) {
    if (cells.length === code.length)
      steps.push({ kind: 'cells', ids: cells, code: new Redacted(code) });
    else errors.push({ kind: 'otp-count-mismatch', cells: cells.length, digits: code.length });
  }
  const parts = form.fields.filter((a) => a.purpose === 'cc-number-part').map((a) => a.id);
  const cardNumber = lookup(inputs, 'cc-number');
  if (parts.length > 0 && cardNumber !== undefined) {
    parts.forEach((id, i) => {
      steps.push({
        kind: 'text',
        id,
        purpose: 'cc-number-part',
        value: new Redacted(cardNumber.slice(i * CARD_PART_LENGTH, (i + 1) * CARD_PART_LENGTH)),
      });
    });
  }
  const month = lookup(inputs, 'cc-exp-month');
  const year = lookup(inputs, 'cc-exp-year');
  for (const a of form.fields) {
    if (a.purpose === 'cc-exp' && month !== undefined && year !== undefined) {
      steps.push({
        kind: 'expiry',
        id: a.id,
        month: new Redacted(month),
        year: new Redacted(year),
      });
      continue;
    }
    const source = sourceFor(a.purpose);
    const value = source === undefined ? undefined : lookup(inputs, source);
    if (value === undefined) continue;
    const field = fields.find((f) => f.id === a.id);
    steps.push({
      kind: field?.tag === 'select' ? 'select' : 'text',
      id: a.id,
      purpose: a.purpose,
      value: new Redacted(value),
    });
  }
  return { steps, errors };
};
