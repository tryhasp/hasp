import { fieldId, formId } from '../src/brand.ts';
import type { FieldSnap, FormSnap, PageSnap } from '../src/types.ts';

let counter = 0;

export const resetFixtures = (): void => {
  counter = 0;
};

export const field = (over: Partial<FieldSnap> = {}): FieldSnap => {
  counter += 1;
  return {
    id: fieldId(counter),
    tag: 'input',
    type: 'text',
    name: '',
    domId: '',
    autocomplete: [],
    inputmode: '',
    label: '',
    placeholder: '',
    ariaLabel: '',
    nearbyText: '',
    rect: { x: 10, y: 10 * counter, w: 240, h: 32 },
    visible: true,
    occluded: false,
    disabled: false,
    readonly: false,
    textSecurity: false,
    formId: formId(1),
    frameOrigin: 'https://example.test',
    valueLen: 0,
    ...over,
  };
};

export const page = (
  fields: FieldSnap[],
  over: Partial<PageSnap> = {},
  submitTexts: string[] = [],
): PageSnap => {
  const form: FormSnap = {
    id: formId(1),
    isSynthetic: false,
    fieldIds: fields.map((f) => f.id),
    submitTexts,
  };
  return {
    forms: [form],
    fields,
    pathHint: 'none',
    frame: 'top',
    hasCaptcha: false,
    hasErrorText: false,
    lang: 'en',
    ...over,
  };
};
