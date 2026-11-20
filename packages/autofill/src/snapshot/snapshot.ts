import type { FormId } from '../brand.ts';
import { errorText, pathChange, pathLogin, pathSignup } from '../classify/rules.ts';
import type {
  FieldSnap,
  FieldTag,
  FormSnap,
  FrameKind,
  PageSnap,
  PathHint,
  Rect,
  SelectOption,
} from '../types.ts';
import type { Natives } from './natives.ts';
import type { ElementRegistry } from './registry.ts';
import type { ShadowRootGetter } from './shadow.ts';

export type SnapshotContext = {
  win: Window & typeof globalThis;
  natives: Natives;
  registry: ElementRegistry;
  getShadowRoot: ShadowRootGetter;
  frame: FrameKind;
};

const MAX_FIELDS = 400;
const MAX_LABEL_CHARS = 80;
const MAX_OPTIONS = 80;
const skippedInputTypes: ReadonlySet<string> = new Set([
  'hidden',
  'checkbox',
  'radio',
  'file',
  'image',
  'range',
  'color',
  'reset',
  'date',
  'datetime-local',
  'month',
  'week',
  'time',
]);
const containerSelector = '[role="form"],[role="dialog"],dialog,fieldset,section,article,main';
const captchaSelector =
  'iframe[src*="recaptcha"],iframe[src*="hcaptcha"],iframe[src*="captcha"],.g-recaptcha,.h-captcha,[data-sitekey],[class*="captcha" i],[id*="captcha" i]';
const errorSelector =
  '[role="alert"],[aria-live="assertive"],[class*="error" i],[class*="invalid" i],[id*="error" i]';

const clip = (text: string): string => text.replace(/\s+/g, ' ').trim().slice(0, MAX_LABEL_CHARS);

const parsePositive = (raw: string | null): number | undefined => {
  if (raw === null) return undefined;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : undefined;
};

const roundRect = (r: DOMRect): Rect => ({
  x: Math.round(r.x),
  y: Math.round(r.y),
  w: Math.round(r.width),
  h: Math.round(r.height),
});

export const pathHintOf = (pathname: string): PathHint => {
  const p = pathname.toLowerCase();
  if (pathChange.test(p)) return 'change-password';
  if (pathSignup.test(p)) return 'signup';
  if (pathLogin.test(p)) return 'login';
  return 'none';
};

export const collectRoots = (
  ctx: Pick<SnapshotContext, 'win' | 'natives' | 'getShadowRoot'>,
): (Document | ShadowRoot)[] => {
  const roots: (Document | ShadowRoot)[] = [ctx.win.document];
  for (let i = 0; i < roots.length; i += 1) {
    const root = roots[i];
    if (root === undefined) continue;
    for (const el of ctx.natives.querySelectorAll(root, '*')) {
      const shadow = ctx.getShadowRoot(el);
      if (shadow !== null && !roots.includes(shadow)) roots.push(shadow);
    }
    if (roots.length > 64) break;
  }
  return roots;
};

const isVisible = (ctx: SnapshotContext, el: Element, rect: Rect): boolean => {
  if (rect.w <= 0 || rect.h <= 0) return false;
  const check: unknown = Reflect.get(el, 'checkVisibility');
  if (typeof check === 'function') {
    return (
      Reflect.apply(check, el, [{ visibilityProperty: true, contentVisibilityAuto: true }]) === true
    );
  }
  const style = ctx.natives.getComputedStyle(el);
  return style.display !== 'none' && style.visibility !== 'hidden';
};

const isOccluded = (ctx: SnapshotContext, el: Element, rect: Rect): boolean => {
  const x = rect.x + rect.w / 2;
  const y = rect.y + rect.h / 2;
  if (x < 0 || y < 0 || x > ctx.win.innerWidth || y > ctx.win.innerHeight) return false;
  const root = el.getRootNode();
  const scope = root instanceof ShadowRoot ? root : ctx.win.document;
  const hit = ctx.natives.elementFromPoint(scope, x, y);
  if (hit === null || hit === el || el.contains(hit)) return false;
  const label = el instanceof HTMLInputElement ? el.labels : null;
  return !(label !== null && Array.from(label).some((l) => l.contains(hit)));
};

const labelOf = (el: Element): string => {
  if (el instanceof HTMLInputElement || el instanceof HTMLSelectElement) {
    const labels = el.labels === null ? [] : Array.from(el.labels);
    if (labels.length > 0) return clip(labels.map((l) => l.textContent).join(' '));
  }
  const by = el.getAttribute('aria-labelledby');
  if (by !== null) {
    const root = el.getRootNode();
    const texts = by
      .split(/\s+/)
      .map((id) =>
        root instanceof Document || root instanceof ShadowRoot
          ? root.getElementById(id)?.textContent
          : null,
      )
      .filter((t): t is string => typeof t === 'string');
    if (texts.length > 0) return clip(texts.join(' '));
  }
  return '';
};

const nearbyTextOf = (el: Element): string => {
  const prev = el.previousElementSibling;
  if (prev !== null && prev.querySelector('input,select,textarea') === null) {
    const t = clip(prev.textContent);
    if (t !== '') return t;
  }
  const parent = el.parentElement;
  if (parent === null) return '';
  const own = Array.from(parent.childNodes)
    .filter((n) => n.nodeType === Node.TEXT_NODE)
    .map((n) => n.textContent)
    .join(' ');
  if (clip(own) !== '') return clip(own);
  const parentPrev = parent.previousElementSibling;
  if (parentPrev !== null && parentPrev.querySelector('input,select,textarea') === null) {
    return clip(parentPrev.textContent);
  }
  return '';
};

const optionsOf = (el: HTMLSelectElement): SelectOption[] =>
  Array.from(el.options)
    .slice(0, MAX_OPTIONS)
    .map((o) => ({ value: o.value, label: clip(o.label) }));

const tagOf = (el: Element): FieldTag | undefined => {
  if (el instanceof HTMLInputElement) {
    if (skippedInputTypes.has(el.type)) {
      return el.type === 'image' ? 'button' : undefined;
    }
    return el.type === 'submit' || el.type === 'button' ? 'button' : 'input';
  }
  if (el instanceof HTMLSelectElement) return 'select';
  if (el instanceof HTMLButtonElement) return 'button';
  if (el.getAttribute('role') === 'button') return 'button';
  return undefined;
};

const containerOf = (el: Element, root: Document | ShadowRoot): Element => {
  const form = el instanceof HTMLElement && 'form' in el ? el.form : null;
  if (form instanceof HTMLFormElement) return form;
  const closest = el.closest(containerSelector);
  if (closest !== null) return closest;
  return root instanceof Document ? root.documentElement : root.host;
};

export const takeSnapshot = (ctx: SnapshotContext): PageSnap => {
  const { natives, registry, win } = ctx;
  const fields: FieldSnap[] = [];
  const formMap = new Map<
    FormId,
    { fieldIds: FieldSnap['id'][]; submitTexts: string[]; synthetic: boolean }
  >();
  for (const root of collectRoots(ctx)) {
    for (const el of natives.querySelectorAll(root, 'input,select,button,[role="button"]')) {
      if (fields.length >= MAX_FIELDS) break;
      const tag = tagOf(el);
      if (tag === undefined) continue;
      const rect = roundRect(natives.getBoundingClientRect(el));
      const container = containerOf(el, root);
      const id = registry.formIdOf(container);
      const visible = isVisible(ctx, el, rect);
      const style = tag === 'input' ? natives.getComputedStyle(el) : undefined;
      const maskSource: unknown =
        style === undefined
          ? ''
          : (Reflect.get(style, 'webkitTextSecurity') ?? Reflect.get(style, 'textSecurity') ?? '');
      const type =
        el instanceof HTMLButtonElement
          ? (natives.getAttribute(el, 'type') ?? 'submit').toLowerCase()
          : el instanceof HTMLInputElement
            ? el.type
            : el instanceof HTMLSelectElement
              ? 'select'
              : 'button';
      const valueOf = el instanceof HTMLInputElement ? el.value : '';
      const label =
        tag === 'button'
          ? clip(el instanceof HTMLInputElement ? el.value : el.textContent)
          : labelOf(el);
      const maxlength = parsePositive(natives.getAttribute(el, 'maxlength'));
      const minlength = parsePositive(natives.getAttribute(el, 'minlength'));
      const pattern = natives.getAttribute(el, 'pattern');
      const snap: FieldSnap = {
        id: registry.idOf(el),
        tag,
        type,
        name: natives.getAttribute(el, 'name') ?? '',
        domId: natives.getAttribute(el, 'id') ?? '',
        autocomplete: (natives.getAttribute(el, 'autocomplete') ?? '')
          .toLowerCase()
          .split(/\s+/)
          .filter((t) => t !== ''),
        inputmode: natives.getAttribute(el, 'inputmode') ?? '',
        label,
        placeholder: tag === 'button' ? '' : clip(natives.getAttribute(el, 'placeholder') ?? ''),
        ariaLabel: clip(natives.getAttribute(el, 'aria-label') ?? ''),
        nearbyText: tag === 'button' ? '' : nearbyTextOf(el),
        rect,
        visible,
        occluded: visible && tag !== 'button' && isOccluded(ctx, el, rect),
        disabled: el instanceof HTMLElement && 'disabled' in el && el.disabled === true,
        readonly: el instanceof HTMLInputElement && el.readOnly,
        textSecurity: typeof maskSource === 'string' && maskSource !== '' && maskSource !== 'none',
        formId: id,
        frameOrigin: win.location.origin,
        valueLen: valueOf.length,
        ...(maxlength === undefined ? {} : { maxlength }),
        ...(minlength === undefined ? {} : { minlength }),
        ...(pattern === null ? {} : { pattern }),
        ...(el instanceof HTMLSelectElement ? { options: optionsOf(el) } : {}),
      };
      fields.push(snap);
      const entry = formMap.get(id) ?? {
        fieldIds: [],
        submitTexts: [],
        synthetic: !(container instanceof HTMLFormElement),
      };
      entry.fieldIds.push(snap.id);
      if (tag === 'button' && visible && snap.label !== '') entry.submitTexts.push(snap.label);
      formMap.set(id, entry);
    }
  }
  const forms: FormSnap[] = Array.from(formMap, ([id, f]) => ({
    id,
    isSynthetic: f.synthetic,
    fieldIds: f.fieldIds,
    submitTexts: f.submitTexts,
  }));
  const hasErrorText = natives
    .querySelectorAll(win.document, errorSelector)
    .slice(0, 20)
    .some(
      (e) =>
        e instanceof HTMLElement &&
        e.checkVisibility() &&
        errorText.test(clip(e.textContent).toLowerCase()),
    );
  return {
    forms,
    fields,
    pathHint: pathHintOf(win.location.pathname),
    frame: ctx.frame,
    hasCaptcha: natives.querySelectorAll(win.document, captchaSelector).length > 0,
    hasErrorText,
    lang: win.document.documentElement.lang,
  };
};
