declare const brand: unique symbol;

export type Brand<T, B extends string> = T & { readonly [brand]: B };

export type FieldId = Brand<string, 'field-id'>;
export type FormId = Brand<string, 'form-id'>;
export type ItemId = Brand<string, 'item-id'>;
export type RegistrableDomain = Brand<string, 'registrable-domain'>;

// oxlint-disable-next-line typescript/no-unsafe-type-assertion -- brand constructor; the number cannot collide with a hand-written id
export const fieldId = (n: number): FieldId => `f${n}` as FieldId;
// oxlint-disable-next-line typescript/no-unsafe-type-assertion -- brand constructor; ids come from the snapshotter only
export const formId = (n: number): FormId => `g${n}` as FormId;
// oxlint-disable-next-line typescript/no-unsafe-type-assertion -- brand constructor for ids parsed by a schema
export const itemId = (value: string): ItemId => value as ItemId;
// oxlint-disable-next-line typescript/no-unsafe-type-assertion -- brand constructor for domains produced by the registrable-domain helper
export const registrableDomain = (value: string): RegistrableDomain => value as RegistrableDomain;
