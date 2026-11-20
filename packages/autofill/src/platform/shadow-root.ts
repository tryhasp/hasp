import { defaultShadowRootGetter, withOpenOrClosed } from '../snapshot/shadow.ts';
import type { ShadowRootGetter } from '../snapshot/shadow.ts';

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null;

export const platformShadowRootGetter = (): ShadowRootGetter => {
  const chromeGlobal: unknown = Reflect.get(globalThis, 'chrome');
  const dom = isRecord(chromeGlobal) ? chromeGlobal['dom'] : undefined;
  const fn = isRecord(dom) ? dom['openOrClosedShadowRoot'] : undefined;
  if (typeof fn !== 'function') return defaultShadowRootGetter;
  return withOpenOrClosed((el) => {
    const root: unknown = Reflect.apply(fn, dom, [el]);
    return root instanceof ShadowRoot ? root : null;
  });
};
