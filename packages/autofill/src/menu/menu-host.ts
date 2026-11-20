import { attest, findForeignTopLayer, measureHost, measureTarget } from '../guard/measure.ts';
import type { AttestOutcome, MeasureContext } from '../guard/measure.ts';
import { checkC4 } from '../guard/style-checks.ts';
import { handoverPort } from '../platform/frame-channel.ts';
import type { ContentEnd } from '../platform/frame-channel.ts';
import type { CheckId, PortToContent } from '../protocol.ts';
import { err, ok } from '../result.ts';
import type { Result } from '../result.ts';
import type { Report } from '../spawn.ts';
import type { Rect } from '../types.ts';
import { placeMenu, visibleBounds } from './placement.ts';

export type ShowFailure =
  | { kind: 'unsupported' }
  | { kind: 'foreign-top-layer' }
  | { kind: 'check-failed'; check: CheckId }
  | { kind: 'handshake-timeout' };

export type MenuHostDeps = MeasureContext & {
  frameUrl: string;
  nowMs: () => number;
  report: Report;
  signal: AbortSignal;
  onFrameMessage: (m: PortToContent) => void;
  onTampered: (check: CheckId) => void;
};

export type MenuHost = {
  show: (target: Element | undefined, nonce: string) => Promise<Result<null, ShowFailure>>;
  hide: () => void;
  attest: (target: Element | undefined) => AttestOutcome;
  relayKey: (key: 'ArrowDown' | 'ArrowUp' | 'Enter' | 'Home' | 'End' | 'g') => void;
  isOpen: () => boolean;
};

const HANDSHAKE_TIMEOUT_MS = 3000;
const SCROLL_SETTLE_MS = 150;
const POLL_MS = 100;
const INITIAL_SIZE_PX = 1;
const VISIBILITY_DELAY_MS = 100;

const hostStyle: Readonly<Record<string, string>> = {
  position: 'fixed',
  margin: '0',
  padding: '0',
  border: '0',
  background: 'none',
  overflow: 'visible',
  inset: 'auto',
  display: 'block',
  opacity: '1',
  visibility: 'visible',
  'pointer-events': 'auto',
  transform: 'none',
  filter: 'none',
  'z-index': '2147483647',
  'color-scheme': 'normal',
};

type Open = {
  host: HTMLElement;
  iframe: HTMLIFrameElement;
  target: Element | undefined;
  end: ContentEnd;
  expected: Rect;
  controller: AbortController;
  isReady: boolean;
  isSettled: boolean;
  isTampered: boolean;
  visibility: { isSupported: boolean; isVisible: boolean };
};

const supportsVisibilityTracking = (win: Window & typeof globalThis): boolean =>
  'isVisible' in win.IntersectionObserverEntry.prototype;

export const createMenuHost = (deps: MenuHostDeps): MenuHost => {
  const { win, natives } = deps;
  let open: Open | undefined;

  const place = (o: Open, width: number, height: number): void => {
    const t = o.target === undefined ? undefined : natives.getBoundingClientRect(o.target);
    const target = t === undefined ? undefined : { x: t.left, y: t.top, w: t.width, h: t.height };
    const spot = placeMenu(target, { width, height }, visibleBounds(win));
    o.host.style.setProperty('left', `${spot.x}px`, 'important');
    o.host.style.setProperty('top', `${spot.y}px`, 'important');
    o.host.style.setProperty('width', `${width}px`, 'important');
    o.host.style.setProperty('height', `${height}px`, 'important');
    o.expected = spot;
  };

  const close = (): void => {
    const o = open;
    if (o === undefined) return;
    open = undefined;
    o.end.send({ kind: 'hidden' });
    o.controller.abort();
    o.end.close();
    if (o.host.matches(':popover-open')) o.host.hidePopover();
    o.host.remove();
  };

  const evaluate = (o: Open): AttestOutcome => {
    const target =
      o.target === undefined
        ? { c1: { ok: true as const }, c3: { ok: true as const } }
        : measureTarget(deps, o.target);
    const hostM = measureHost(deps, o.host, o.expected);
    const c4 = checkC4(o.visibility);
    const foreign = findForeignTopLayer(deps, o.host) !== undefined;
    return attest({
      c1: target.c1,
      c2: hostM.c2,
      c3: target.c3.ok ? hostM.c3 : target.c3,
      c4,
      isTampered: o.isTampered || foreign,
      nowMs: deps.nowMs(),
    });
  };

  const recheck = (o: Open): void => {
    if (!o.isSettled) return;
    const outcome = evaluate(o);
    if (outcome.ok) return;
    close();
    deps.onTampered(outcome.failed);
  };

  const observe = (o: Open): void => {
    const { signal } = o.controller;
    const mutations = new win.MutationObserver(() => {
      recheck(o);
    });
    const watched = new Set<Element>(o.target === undefined ? [o.host] : [o.host, o.target]);
    for (const start of o.target === undefined ? [o.host] : [o.target, o.host]) {
      let node: Element | null = start.parentElement;
      while (node !== null) {
        watched.add(node);
        node = node.parentElement;
      }
    }
    for (const el of watched) {
      mutations.observe(el, {
        attributes: true,
        attributeFilter: ['style', 'class', 'hidden', 'popover', 'open'],
      });
    }
    mutations.observe(win.document.documentElement, { childList: true });
    signal.addEventListener('abort', () => {
      mutations.disconnect();
    });
    if (o.visibility.isSupported) {
      const init: IntersectionObserverInit & { trackVisibility: boolean; delay: number } = {
        threshold: [0.99],
        trackVisibility: true,
        delay: VISIBILITY_DELAY_MS,
      };
      const io = new win.IntersectionObserver((entries) => {
        const last = entries.at(-1);
        if (last === undefined) return;
        o.visibility.isVisible =
          Reflect.get(last, 'isVisible') === true && last.intersectionRatio >= 0.99;
        if (!o.visibility.isVisible) recheck(o);
      }, init);
      io.observe(o.host);
      signal.addEventListener('abort', () => {
        io.disconnect();
      });
    }
    let settle: number | undefined;
    const onMove = (): void => {
      o.end.send({ kind: 'moved' });
      place(o, o.expected.w, o.expected.h);
      if (settle !== undefined) win.clearTimeout(settle);
      settle = win.setTimeout(() => {
        recheck(o);
      }, SCROLL_SETTLE_MS);
    };
    win.addEventListener('scroll', onMove, { capture: true, passive: true, signal });
    win.addEventListener('resize', onMove, { passive: true, signal });
    win.visualViewport?.addEventListener('resize', onMove, { passive: true, signal });
    win.visualViewport?.addEventListener('scroll', onMove, { passive: true, signal });
    const doc = win.document;
    doc.addEventListener(
      'toggle',
      () => {
        recheck(o);
      },
      { capture: true, signal },
    );
    doc.addEventListener(
      'fullscreenchange',
      () => {
        recheck(o);
      },
      { signal },
    );
    const poll = win.setInterval(() => {
      recheck(o);
    }, POLL_MS);
    signal.addEventListener('abort', () => {
      win.clearInterval(poll);
    });
  };

  const show = async (
    target: Element | undefined,
    nonce: string,
  ): Promise<Result<null, ShowFailure>> => {
    close();
    const doc = win.document;
    if (typeof doc.documentElement.showPopover !== 'function') return err({ kind: 'unsupported' });
    const probe = doc.createElement('div');
    if (findForeignTopLayer(deps, probe) !== undefined) return err({ kind: 'foreign-top-layer' });
    const host = doc.createElement('div');
    host.setAttribute('popover', 'manual');
    for (const [k, v] of Object.entries(hostStyle)) host.style.setProperty(k, v, 'important');
    const shadow = host.attachShadow({ mode: 'closed' });
    // oxlint-disable-next-line react/iframe-missing-sandbox -- the sandbox attribute is set on the next line
    const iframe = doc.createElement('iframe');
    iframe.setAttribute('title', 'Hasp');
    iframe.setAttribute('sandbox', 'allow-scripts allow-same-origin');
    iframe.setAttribute('referrerpolicy', 'no-referrer');
    iframe.style.cssText =
      'width:100%;height:100%;border:0;display:block;background:none;color-scheme:normal';
    iframe.src = deps.frameUrl;
    shadow.append(iframe);
    const controller = new AbortController();
    const abort = AbortSignal.any([controller.signal, deps.signal]);
    doc.documentElement.append(host);
    const loaded = new Promise<void>((resolve) => {
      iframe.addEventListener(
        'load',
        () => {
          resolve();
        },
        { once: true, signal: abort },
      );
    });
    await Promise.race([
      loaded,
      new Promise<void>((resolve) => {
        win.setTimeout(resolve, HANDSHAKE_TIMEOUT_MS);
      }),
    ]);
    const end = handoverPort(iframe, new URL(deps.frameUrl).origin, nonce);
    if (end === undefined) {
      host.remove();
      return err({ kind: 'handshake-timeout' });
    }
    const o: Open = {
      host,
      iframe,
      target,
      end,
      expected: { x: 0, y: 0, w: INITIAL_SIZE_PX, h: INITIAL_SIZE_PX },
      controller,
      isReady: false,
      isSettled: false,
      isTampered: false,
      visibility: { isSupported: supportsVisibilityTracking(win), isVisible: false },
    };
    open = o;
    place(o, INITIAL_SIZE_PX, INITIAL_SIZE_PX);
    const ready = new Promise<boolean>((resolve) => {
      const timer = win.setTimeout(() => {
        resolve(false);
      }, HANDSHAKE_TIMEOUT_MS);
      end.listen((m) => {
        if (m.kind === 'ready') {
          win.clearTimeout(timer);
          place(o, m.width, m.height);
          resolve(true);
        } else if (m.kind === 'size') {
          place(o, m.width, m.height);
        } else {
          deps.onFrameMessage(m);
        }
      }, abort);
    });
    if (!(await ready)) {
      close();
      return err({ kind: 'handshake-timeout' });
    }
    if (findForeignTopLayer(deps, host) !== undefined) {
      close();
      return err({ kind: 'foreign-top-layer' });
    }
    host.showPopover();
    observe(o);
    o.isReady = true;
    end.send({ kind: 'shown' });
    await new Promise<void>((resolve) => {
      win.setTimeout(resolve, o.visibility.isSupported ? VISIBILITY_DELAY_MS * 2 : 0);
    });
    if (open !== o) return err({ kind: 'check-failed', check: 'C5' });
    o.isSettled = true;
    const first = evaluate(o);
    if (!first.ok) {
      close();
      return err({ kind: 'check-failed', check: first.failed });
    }
    return ok(null);
  };

  return {
    show,
    hide: close,
    attest: (target) => {
      const o = open;
      if (o === undefined || o.target !== target || !o.isReady) return { ok: false, failed: 'C5' };
      return evaluate(o);
    },
    relayKey: (key) => {
      open?.end.send({ kind: 'key', key });
    },
    isOpen: () => open !== undefined,
  };
};
