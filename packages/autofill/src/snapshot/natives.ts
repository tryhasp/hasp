export type Natives = {
  getComputedStyle: (el: Element) => CSSStyleDeclaration;
  getBoundingClientRect: (el: Element) => DOMRect;
  elementFromPoint: (root: Document | ShadowRoot, x: number, y: number) => Element | null;
  getAttribute: (el: Element, name: string) => string | null;
  matches: (el: Element, selector: string) => boolean;
  querySelectorAll: (root: ParentNode, selector: string) => Element[];
  dispatch: (target: EventTarget, event: Event) => boolean;
  focus: (el: HTMLElement) => void;
  setValue: (el: HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement, value: string) => void;
  now: () => number;
};

type Method = (self: object, ...args: unknown[]) => unknown;

const apply = Reflect.apply;

const method = (proto: object, key: string): Method => {
  const fn: unknown = Reflect.get(proto, key);
  if (typeof fn !== 'function') throw new Error(`native ${key} missing`);
  return (self, ...args) => {
    const result: unknown = apply(fn, self, args);
    return result;
  };
};

const valueSetter = (proto: object): Method => {
  const descriptor = Object.getOwnPropertyDescriptor(proto, 'value');
  const setter: unknown = descriptor === undefined ? undefined : Reflect.get(descriptor, 'set');
  if (typeof setter !== 'function') throw new Error('value setter missing');
  return (self, ...args) => {
    const result: unknown = apply(setter, self, args);
    return result;
  };
};

export const captureNatives = (win: Window & typeof globalThis): Natives => {
  const gcs = win.getComputedStyle.bind(win);
  const rect = method(win.Element.prototype, 'getBoundingClientRect');
  const getAttr = method(win.Element.prototype, 'getAttribute');
  const matches = method(win.Element.prototype, 'matches');
  const qsa = method(win.Element.prototype, 'querySelectorAll');
  const docQsa = method(win.Document.prototype, 'querySelectorAll');
  const fragmentQsa = method(win.DocumentFragment.prototype, 'querySelectorAll');
  const dispatch = method(win.EventTarget.prototype, 'dispatchEvent');
  const focus = method(win.HTMLElement.prototype, 'focus');
  const docEfp = method(win.Document.prototype, 'elementFromPoint');
  const rootEfp = method(win.ShadowRoot.prototype, 'elementFromPoint');
  const inputSet = valueSetter(win.HTMLInputElement.prototype);
  const areaSet = valueSetter(win.HTMLTextAreaElement.prototype);
  const selectSet = valueSetter(win.HTMLSelectElement.prototype);
  const clock = win.Date;
  return {
    getComputedStyle: (el) => gcs(el),
    getBoundingClientRect: (el) => {
      const r = rect(el);
      if (!(r instanceof win.DOMRect)) throw new Error('rect');
      return r;
    },
    elementFromPoint: (root, x, y) => {
      const r = root instanceof win.Document ? docEfp(root, x, y) : rootEfp(root, x, y);
      return r instanceof win.Element ? r : null;
    },
    getAttribute: (el, name) => {
      const r = getAttr(el, name);
      return typeof r === 'string' ? r : null;
    },
    matches: (el, selector) => Boolean(matches(el, selector)),
    querySelectorAll: (root, selector) => {
      const list =
        root instanceof win.Document
          ? docQsa(root, selector)
          : root instanceof win.DocumentFragment
            ? fragmentQsa(root, selector)
            : qsa(root, selector);
      return list instanceof win.NodeList
        ? Array.from(list).filter((n): n is Element => n instanceof win.Element)
        : [];
    },
    dispatch: (target, event) => Boolean(dispatch(target, event)),
    focus: (el) => {
      focus(el);
    },
    setValue: (el, value) => {
      if (el instanceof win.HTMLInputElement) inputSet(el, value);
      else if (el instanceof win.HTMLTextAreaElement) areaSet(el, value);
      else selectSet(el, value);
    },
    now: () => clock.now(),
  };
};
