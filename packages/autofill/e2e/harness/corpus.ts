import { classifyPage } from '../../src/classify/classify.ts';
import { captureNatives } from '../../src/snapshot/natives.ts';
import { createRegistry } from '../../src/snapshot/registry.ts';
import { defaultShadowRootGetter } from '../../src/snapshot/shadow.ts';
import { takeSnapshot } from '../../src/snapshot/snapshot.ts';
import type { FormClass } from '../../src/types.ts';

export type GoldForm = { selector: string; kind: string; fields: Record<string, string> };
export type CorpusResult = {
  forms: { selector: string; expected: string; predicted: string }[];
  fields: { selector: string; expected: string; predicted: string; predictedKind: string }[];
  strays: { purpose: string; kind: string }[];
};

declare global {
  // oxlint-disable-next-line typescript/consistent-type-definitions -- global augmentation must be an interface
  interface Window {
    haspCorpus: (gold: { forms: GoldForm[] }) => CorpusResult;
  }
}

const natives = captureNatives(window);

window.haspCorpus = (gold) => {
  const registry = createRegistry();
  const page = takeSnapshot({
    win: window,
    natives,
    registry,
    getShadowRoot: defaultShadowRootGetter,
    frame: 'top',
  });
  const classes = classifyPage(page, {});
  const containerOf = (c: FormClass): Element | undefined => registry.container(c.formId);
  const classOfElement = (el: Element): { form: FormClass; purpose: string } | undefined => {
    const id = registry.knownId(el);
    if (id === undefined) return undefined;
    for (const form of classes) {
      const a = form.fields.find((f) => f.id === id);
      if (a !== undefined) return { form, purpose: a.purpose };
    }
    return undefined;
  };
  const result: CorpusResult = { forms: [], fields: [], strays: [] };
  const claimed = new Set<FormClass>();
  for (const g of gold.forms) {
    const container = document.querySelector(g.selector);
    const related = classes
      .filter((c) => {
        const el = containerOf(c);
        return (
          container !== null &&
          el !== undefined &&
          (el === container || container.contains(el) || el.contains(container))
        );
      })
      .toSorted(
        (a, b) =>
          (containerOf(a)?.querySelectorAll('*').length ?? 0) -
          (containerOf(b)?.querySelectorAll('*').length ?? 0),
      );
    const predictedClass = related.find((c) => c.kind !== 'none') ?? related[0];
    if (predictedClass !== undefined) claimed.add(predictedClass);
    result.forms.push({
      selector: g.selector,
      expected: g.kind,
      predicted: predictedClass?.kind ?? 'none',
    });
    for (const [selector, expected] of Object.entries(g.fields)) {
      const el = document.querySelector(selector);
      const hit = el === null ? undefined : classOfElement(el);
      result.fields.push({
        selector,
        expected,
        predicted: hit?.purpose ?? 'none',
        predictedKind: hit?.form.kind ?? 'none',
      });
    }
  }
  const goldElements = new Set<Element>();
  for (const g of gold.forms) {
    for (const selector of Object.keys(g.fields)) {
      const el = document.querySelector(selector);
      if (el !== null) goldElements.add(el);
    }
  }
  for (const form of classes) {
    if (form.kind === 'none') continue;
    if (!claimed.has(form)) result.strays.push({ purpose: 'form', kind: form.kind });
    for (const a of form.fields) {
      const el = registry.element(a.id);
      if (
        el !== undefined &&
        !goldElements.has(el) &&
        (a.purpose === 'username' || a.purpose === 'password')
      ) {
        result.strays.push({ purpose: a.purpose, kind: form.kind });
      }
    }
  }
  return result;
};
