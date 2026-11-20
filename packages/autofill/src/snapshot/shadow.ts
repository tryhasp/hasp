export type ShadowRootGetter = (el: Element) => ShadowRoot | null;

export const defaultShadowRootGetter: ShadowRootGetter = (el) => {
  const maybe: unknown = Reflect.get(el, 'openOrClosedShadowRoot');
  if (maybe instanceof ShadowRoot) return maybe;
  return el.shadowRoot;
};

export const withOpenOrClosed =
  (get: (el: Element) => ShadowRoot | null): ShadowRootGetter =>
  (el) =>
    get(el) ?? el.shadowRoot;
