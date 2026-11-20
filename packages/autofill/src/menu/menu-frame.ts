import {
  dwellMoved,
  dwellPointer,
  dwellShown,
  initialDwell,
  isDwellSatisfied,
} from '../guard/dwell.ts';
import type { DwellState } from '../guard/dwell.ts';
import { isTapAllowed, noTouch, touchDown } from '../guard/touch.ts';
import type { TouchGate } from '../guard/touch.ts';
import { collectHandovers } from '../platform/frame-channel.ts';
import type { FrameEnd, HandoverInbox } from '../platform/frame-channel.ts';
import type { Candidate, FrameHelloReply, ProtocolError } from '../protocol.ts';
import { err } from '../result.ts';
import type { Result } from '../result.ts';
import { spawn } from '../spawn.ts';
import type { Report } from '../spawn.ts';
import { frameCss } from './frame-css.ts';
import { glyphPaths } from './glyphs.ts';
import { strings } from './strings.ts';
import type { Strings } from './strings.ts';

export type FrameBackground = {
  hello: (nonce: string) => Promise<Result<FrameHelloReply, ProtocolError>>;
  pick: (
    nonce: string,
    itemId: string,
    action: 'fill' | 'otp' | 'generate',
  ) => Promise<Result<{ token: string }, ProtocolError>>;
  saveAnswer: (
    nonce: string,
    answer: 'save' | 'update' | 'never' | 'dismiss',
  ) => Promise<Result<object, ProtocolError>>;
  dismiss: (nonce: string) => Promise<Result<object, ProtocolError>>;
};

export type FrameDeps = {
  win: Window & typeof globalThis;
  background: FrameBackground;
  nowMs: () => number;
  report: Report;
  signal: AbortSignal;
};

type Choice = { el: HTMLButtonElement; action: 'fill' | 'otp' | 'generate'; itemId: string };

const READY_FRAMES_MAX = 60;

const SVG_NS = 'http://www.w3.org/2000/svg';

const el = <K extends keyof HTMLElementTagNameMap>(
  doc: Document,
  tag: K,
  className?: string,
  text?: string,
): HTMLElementTagNameMap[K] => {
  const node = doc.createElement(tag);
  if (className !== undefined) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
};

const glyphIcon = (doc: Document, glyph: number): SVGElement => {
  const svg = doc.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 12 12');
  svg.setAttribute('aria-hidden', 'true');
  const path = doc.createElementNS(SVG_NS, 'path');
  path.setAttribute('d', glyphPaths[glyph] ?? glyphPaths[0] ?? '');
  path.setAttribute('fill-rule', 'evenodd');
  svg.append(path);
  return svg;
};

const header = (doc: Document, s: Strings, hello: FrameHelloReply): HTMLElement => {
  const head = el(doc, 'div', 'head');
  if (hello.secretTag !== null) {
    const tag = el(doc, 'span', 'tag');
    tag.title = s.tagTitle;
    tag.append(glyphIcon(doc, hello.secretGlyph), doc.createTextNode(hello.secretTag));
    head.append(tag);
  }
  const org = el(doc, 'span', 'org');
  if (hello.originSubdomain !== '') org.append(el(doc, 'span', 'd', `${hello.originSubdomain}.`));
  org.append(el(doc, 'b', undefined, hello.originRegistrable));
  head.append(org);
  return head;
};

const candidateRow = (doc: Document, s: Strings, c: Candidate): HTMLButtonElement => {
  const row = el(doc, 'button', 'row');
  row.type = 'button';
  row.setAttribute('role', 'menuitem');
  const first = Array.from(c.title)[0] ?? '?';
  const tile = el(doc, 'span', 'tile', first);
  tile.setAttribute('aria-hidden', 'true');
  const text = el(doc, 'span', 't');
  text.append(el(doc, 'div', 'n', c.title), el(doc, 'div', 's', c.username));
  row.append(tile, text);
  const side =
    c.hostToConfirm !== undefined
      ? s.fillOnHost(c.hostToConfirm)
      : c.level === 'related'
        ? s.relatedSite
        : c.vaultLabel;
  row.append(el(doc, 'span', 'v', side));
  return row;
};

const HANDOVER_TRIES = 8;

const helloWithHandover = async (
  inbox: HandoverInbox,
  background: FrameBackground,
): Promise<Result<FrameHelloReply, ProtocolError>> => {
  let last: Result<FrameHelloReply, ProtocolError> = err({ kind: 'internal' });
  for (let index = 0; index < HANDOVER_TRIES; index += 1) {
    const nonce = await inbox.nonceAt(index);
    if (nonce === undefined) return last;
    last = await background.hello(nonce);
    if (last.ok) return last;
  }
  return last;
};

export const mountMenuFrame = async (deps: FrameDeps): Promise<void> => {
  const { win, background, signal } = deps;
  const doc = win.document;
  const inbox = collectHandovers(win, signal);
  const sheet = new win.CSSStyleSheet();
  sheet.replaceSync(frameCss());
  doc.adoptedStyleSheets = [sheet];
  const hello = await helloWithHandover(inbox, background);
  if (!hello.ok) return;
  const reply = hello.value;
  const s = strings[reply.locale];
  doc.documentElement.lang = reply.locale;
  const menu = el(doc, 'div', 'menu');
  menu.setAttribute('role', 'menu');
  menu.setAttribute('aria-label', s.menuLabel);
  const choices: Choice[] = [];
  let index = 0;
  let dwell: DwellState = initialDwell;
  let touch: TouchGate = noTouch;
  let isTouching = false;
  const link: { end: FrameEnd | undefined } = { end: undefined };

  const mark = (): void => {
    choices.forEach((c, i) => {
      c.el.setAttribute('aria-current', i === index ? 'true' : 'false');
    });
  };
  const measure = (): { width: number; height: number } => {
    const r = menu.getBoundingClientRect();
    return { width: Math.ceil(r.width), height: Math.ceil(r.height) };
  };
  const choose = async (choice: Choice | undefined): Promise<void> => {
    if (choice === undefined) return;
    const picked = await background.pick(reply.nonce, choice.itemId, choice.action);
    if (!picked.ok) return;
    link.end?.send({
      kind: 'picked',
      itemId: choice.itemId,
      action: choice.action,
      token: picked.value.token,
    });
  };
  const gateKeyOf = (target: EventTarget | null): string | undefined =>
    target instanceof win.Element
      ? (target.closest<HTMLElement>('[data-gate]')?.dataset['gate'] ?? undefined)
      : undefined;
  const isPointerReady = (): boolean =>
    isTouching ? isTapAllowed(touch, dwell, deps.nowMs()) : isDwellSatisfied(dwell, deps.nowMs());
  const activate = (fromPointer: boolean, choice: Choice | undefined): void => {
    const ready = fromPointer
      ? isPointerReady()
      : isDwellSatisfied(dwellPointer(dwell), deps.nowMs());
    if (!ready) return;
    spawn(choose(choice), deps.report);
  };

  menu.append(header(doc, s, reply));
  if (reply.view.mode === 'menu') {
    const { view } = reply;
    if (view.isFillBlocked) menu.append(el(doc, 'div', 'note', s.blocked));
    if (view.candidates.length === 0) menu.append(el(doc, 'div', 'note', s.empty));
    for (const c of view.candidates) {
      const row = candidateRow(doc, s, c);
      row.dataset['gate'] = `c${choices.length}`;
      choices.push({ el: row, action: view.primary, itemId: c.itemId });
      menu.append(row);
    }
    if (view.canGenerate) {
      menu.append(el(doc, 'div', 'sepl'));
      const gen = el(doc, 'button', 'act');
      gen.type = 'button';
      gen.setAttribute('role', 'menuitem');
      gen.append(doc.createTextNode(s.generate), el(doc, 'kbd', undefined, '⌘G'));
      gen.dataset['gate'] = `c${choices.length}`;
      choices.push({ el: gen, action: 'generate', itemId: '-' });
      menu.append(gen);
    }
  } else {
    const { view } = reply;
    const box = el(doc, 'div', 'save');
    box.append(
      el(doc, 'h1', undefined, view.saveKind === 'new' ? s.saveNew : s.saveUpdate),
      el(doc, 'div', 'u', `${view.title} · ${view.username}`),
    );
    const btns = el(doc, 'div', 'btns');
    const answers: ['save' | 'update' | 'never' | 'dismiss', string, boolean][] = [
      [
        view.saveKind === 'new' ? 'save' : 'update',
        view.saveKind === 'new' ? s.save : s.update,
        true,
      ],
      ['dismiss', s.notNow, false],
      ['never', s.never, false],
    ];
    for (const [answer, label, isPrimary] of answers) {
      const b = el(doc, 'button', isPrimary ? 'btn pri' : 'btn', label);
      b.type = 'button';
      b.dataset['gate'] = `a:${answer}`;
      b.addEventListener(
        'click',
        (e) => {
          const ready = isTouching
            ? isTapAllowed(touch, dwell, deps.nowMs())
            : isDwellSatisfied(dwellPointer(dwell), deps.nowMs());
          if (!e.isTrusted || !ready) return;
          spawn(background.saveAnswer(reply.nonce, answer), deps.report);
        },
        { signal },
      );
      btns.append(b);
    }
    box.append(btns);
    menu.append(box);
  }
  doc.body.replaceChildren(menu);
  mark();

  choices.forEach((choice, i) => {
    choice.el.addEventListener(
      'pointerenter',
      () => {
        index = i;
        mark();
      },
      { signal },
    );
    choice.el.addEventListener(
      'click',
      (e) => {
        if (!e.isTrusted) return;
        activate(true, choice);
      },
      { signal },
    );
  });
  doc.addEventListener(
    'pointerdown',
    (e) => {
      if (!e.isTrusted) return;
      isTouching = e.pointerType === 'touch';
      touch = isTouching ? touchDown(touch, dwell, deps.nowMs(), gateKeyOf(e.target)) : noTouch;
      if (!isTouching) return;
      const target = e.target;
      const hit = choices.findIndex((c) => target instanceof win.Node && c.el.contains(target));
      if (hit >= 0) {
        index = hit;
        mark();
      }
    },
    { signal },
  );
  doc.addEventListener(
    'pointercancel',
    () => {
      touch = noTouch;
    },
    { signal },
  );
  doc.addEventListener(
    'pointermove',
    (e) => {
      if (e.isTrusted) dwell = dwellPointer(dwell);
    },
    { signal },
  );
  const move = (delta: number): void => {
    if (choices.length === 0) return;
    index = (index + delta + choices.length) % choices.length;
    mark();
  };
  const key = (name: string, isTrusted: boolean, isMeta: boolean): void => {
    if (!isTrusted) return;
    if (name === 'ArrowDown') move(1);
    else if (name === 'ArrowUp') move(-1);
    else if (name === 'Home') move(-index);
    else if (name === 'End') move(choices.length - 1 - index);
    else if (name === 'Enter') activate(false, choices[index]);
    else if (name === 'Escape') spawn(background.dismiss(reply.nonce), deps.report);
    else if (name.toLowerCase() === 'g' && isMeta) {
      const generate = choices.find((c) => c.action === 'generate');
      activate(false, generate);
    }
  };
  doc.addEventListener(
    'keydown',
    (e) => {
      key(e.key, e.isTrusted, e.metaKey || e.ctrlKey);
    },
    { signal },
  );

  const end = await inbox.claim(reply.nonce);
  if (end === undefined) return;
  link.end = end;
  end.listen((m) => {
    if (m.kind === 'shown') dwell = dwellShown(deps.nowMs());
    else if (m.kind === 'moved') dwell = dwellMoved(dwell, deps.nowMs());
    else if (m.kind === 'hidden') dwell = initialDwell;
    else if (m.key === 'g') key('g', true, true);
    else key(m.key, true, false);
  }, signal);
  const sized = async (): Promise<{ width: number; height: number }> => {
    for (let attempt = 0; attempt < READY_FRAMES_MAX; attempt += 1) {
      const m = measure();
      if (m.width > 0 && m.height > 0) return m;
      await new Promise<void>((resolve) => {
        win.requestAnimationFrame(() => {
          resolve();
        });
      });
    }
    return measure();
  };
  end.send({ kind: 'ready', ...(await sized()) });
};
