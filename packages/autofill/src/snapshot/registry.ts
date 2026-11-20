import { fieldId, formId } from '../brand.ts';
import type { FieldId, FormId } from '../brand.ts';

export type ElementRegistry = {
  idOf: (el: Element) => FieldId;
  knownId: (el: Element) => FieldId | undefined;
  formIdOf: (container: Element) => FormId;
  element: (id: FieldId) => Element | undefined;
  container: (id: FormId) => Element | undefined;
};

export const createRegistry = (): ElementRegistry => {
  let nextField = 1;
  let nextForm = 1;
  const fieldIds = new WeakMap<Element, FieldId>();
  const formIds = new WeakMap<Element, FormId>();
  const fields = new Map<FieldId, WeakRef<Element>>();
  const forms = new Map<FormId, WeakRef<Element>>();
  return {
    idOf: (el) => {
      const known = fieldIds.get(el);
      if (known !== undefined) return known;
      const id = fieldId(nextField);
      nextField += 1;
      fieldIds.set(el, id);
      fields.set(id, new WeakRef(el));
      return id;
    },
    knownId: (el) => fieldIds.get(el),
    formIdOf: (container) => {
      const known = formIds.get(container);
      if (known !== undefined) return known;
      const id = formId(nextForm);
      nextForm += 1;
      formIds.set(container, id);
      forms.set(id, new WeakRef(container));
      return id;
    },
    element: (id) => fields.get(id)?.deref(),
    container: (id) => forms.get(id)?.deref(),
  };
};
