import { z } from 'zod';

import { formId } from './brand.ts';
import type { FieldId } from './brand.ts';
import { classifyPage } from './classify/classify.ts';
import { fillFocused, fillSteps } from './fill/filler.ts';
import type { FillContext } from './fill/filler.ts';
import { planFill } from './fill/plan.ts';
import type { PlannedStep } from './fill/plan.ts';
import { reduceFlow, requestPurposes, idle } from './flow/flow.ts';
import type { FlowEvent, FlowState } from './flow/flow.ts';
import { detectFrameKind, canFillIn } from './frame-kind.ts';
import { attest, findForeignTopLayer, measureTarget } from './guard/measure.ts';
import type { AttestOutcome } from './guard/measure.ts';
import { addStrike, noStrikes } from './guard/strikes.ts';
import type { Strikes } from './guard/strikes.ts';
import { buildProblemReport } from './inspector.ts';
import type { ProblemReport } from './inspector.ts';
import { createMenuHost } from './menu/menu-host.ts';
import type { MenuHost } from './menu/menu-host.ts';
import type {
  BackgroundPush,
  CaptureValues,
  ContentKind,
  ContentRequest,
  PortToContent,
  ProtocolError,
  ReplyOf,
} from './protocol.ts';
import { captureValuesSchema } from './protocol.ts';
import type { Result } from './result.ts';
import { submitKinds } from './save/pending-store.ts';
import type { SubmitKind } from './save/pending-store.ts';
import { selectorFor } from './sites/selector.ts';
import { emptyPageConfig, resolveOverrides } from './sites/site-rule.ts';
import type { PageConfig } from './sites/site-rule.ts';
import type { Natives } from './snapshot/natives.ts';
import { createRegistry } from './snapshot/registry.ts';
import type { ShadowRootGetter } from './snapshot/shadow.ts';
import { takeSnapshot } from './snapshot/snapshot.ts';
import type { SnapshotContext } from './snapshot/snapshot.ts';
import { spawn } from './spawn.ts';
import type { Report } from './spawn.ts';
import type { FieldPurpose, FormClass, FormKind, PageSnap } from './types.ts';
import { isLoginClass } from './types.ts';

export type ContentBackground = {
  request: <K extends ContentKind>(
    message: Extract<ContentRequest, { kind: K }>,
  ) => Promise<Result<ReplyOf<K>, ProtocolError>>;
};

export type EngineNotice =
  | 'strike-limit'
  | 'fill-rejected'
  | 'fill-refused'
  | 'needs-human'
  | 'save-unverified-length';

export type HandoffStore = {
  put: (record: unknown) => Promise<void>;
  take: () => Promise<unknown>;
  clear: () => Promise<void>;
};

export type EngineDeps = {
  win: Window & typeof globalThis;
  natives: Natives;
  getShadowRoot: ShadowRootGetter;
  background: ContentBackground;
  frameUrl: string;
  nowMs: () => number;
  handoff: HandoffStore;
  report: Report;
  notify: (notice: EngineNotice) => void;
  signal: AbortSignal;
};

export type Engine = {
  push: (message: BackgroundPush) => void;
  flow: () => FlowState;
  report: () => ProblemReport;
  refresh: () => void;
};

const DEBOUNCE_MS = 150;
const TICK_MS = 1000;
const SUBMIT_WATCH_MS = 15_000;
const HANDOFF_TTL_MS = 60_000;
type HandoffRead = { values: CaptureValues | undefined; formKind: SubmitKind | undefined };

const submitKindOf = (kind: FormKind): SubmitKind | undefined =>
  submitKinds.find((k) => k === kind);

const kindField = (kind: SubmitKind | undefined): { formKind?: SubmitKind } =>
  kind === undefined ? {} : { formKind: kind };

const handoffFields = (
  handoff: HandoffRead | undefined,
): { wasSubmitted?: boolean; handoff?: CaptureValues; formKind?: SubmitKind } =>
  handoff === undefined
    ? {}
    : {
        wasSubmitted: true,
        ...(handoff.values === undefined ? {} : { handoff: handoff.values }),
        ...(handoff.formKind === undefined ? {} : { formKind: handoff.formKind }),
      };

const handoffSchema = z.strictObject({
  atMs: z.number(),
  origin: z.string(),
  values: captureValuesSchema.optional(),
  formKind: z.enum(submitKinds).optional(),
});
const menuKinds: ReadonlySet<FormKind> = new Set([
  'login',
  'username-only',
  'password-only',
  'otp',
  'otp-split',
  'card',
  'identity',
  'address',
  'signup',
  'change-password',
]);
const captureKinds: ReadonlySet<FormKind> = new Set([
  'login',
  'signup',
  'change-password',
  'password-only',
]);

type Session = { nonce: string; form: FormClass; target: Element | undefined };

type Snapshot = { origin: string; elements: ReadonlySet<Element> };

const targetOf = (e: Event): Element | undefined => {
  const first = e.composedPath()[0];
  return first instanceof Element ? first : e.target instanceof Element ? e.target : undefined;
};

export const startEngine = async (deps: EngineDeps): Promise<Engine> => {
  const { win, natives, background, signal } = deps;
  const frame = detectFrameKind(win);
  const registry = createRegistry();
  const ctx: SnapshotContext = { win, natives, registry, getShadowRoot: deps.getShadowRoot, frame };
  const fillCtx: FillContext = { ...ctx };
  let page: PageSnap = takeSnapshot(ctx);
  let classes: FormClass[] = [];
  let config: PageConfig = emptyPageConfig;
  let flow: FlowState = idle;
  let strikes: Strikes = noStrikes;
  let session: Session | undefined;
  let teach: 'username' | 'password' | 'otp' | undefined;
  let isOpening = false;
  let isFilling = false;
  let submitted: { formId: string; atMs: number; kind: SubmitKind | undefined } | undefined;
  const filledElements = new WeakSet<Element>();
  const boundRoots = new WeakSet<Document | ShadowRoot>();

  const menu: MenuHost = createMenuHost({
    win,
    natives,
    getShadowRoot: deps.getShadowRoot,
    frameUrl: deps.frameUrl,
    nowMs: deps.nowMs,
    report: deps.report,
    signal,
    onFrameMessage: (m) => {
      spawn(handleFrameMessage(m), deps.report);
    },
    onTampered: (check) => {
      recordStrike(check);
    },
  });

  const dispatch = (event: FlowEvent): void => {
    flow = reduceFlow(flow, event);
  };

  const recordStrike = (check: string): void => {
    strikes = addStrike(strikes);
    spawn(background.request({ kind: 'strike', count: strikes.count, check }), deps.report);
    if (strikes.isNoticeDue) deps.notify('strike-limit');
  };

  const primaryClass = (): FormClass | undefined =>
    classes.find((c) => isLoginClass(c.kind)) ?? classes.find((c) => c.kind !== 'none');

  const classify = (): void => {
    page = takeSnapshot(ctx);
    classes = classifyPage(page, resolveOverrides(natives, registry, win.document, config));
  };

  const loadConfig = async (): Promise<void> => {
    const reply = await background.request({ kind: 'page-config' });
    if (reply.ok) config = reply.value;
  };

  const fieldOf = (id: FieldId): Element | undefined => registry.element(id);

  const formEntryField = (form: FormClass): Element | undefined => {
    const first = form.fields.find((a) => a.purpose !== 'submit' && a.purpose !== 'none');
    return first === undefined ? undefined : fieldOf(first.id);
  };

  const closeSession = (): void => {
    menu.hide();
    session = undefined;
  };

  const openMenu = async (form: FormClass, target: Element | undefined): Promise<void> => {
    if (strikes.isDisabled || !menuKinds.has(form.kind) || !canFillIn(frame) || isOpening) return;
    isOpening = true;
    try {
      await openMenuChecked(form, target);
    } finally {
      isOpening = false;
    }
  };

  const openMenuChecked = async (form: FormClass, target: Element | undefined): Promise<void> => {
    const snap = page.fields.find((f) => f.id === form.fields[0]?.id);
    const reply = await background.request({
      kind: 'menu-open',
      formId: form.formId,
      formKind: form.kind,
      frame,
      isC4Supported: 'isVisible' in win.IntersectionObserverEntry.prototype,
      isObscured: snap?.occluded === true,
    });
    if (!reply.ok || reply.value.decision !== 'inline') {
      dispatch({ kind: 'classified', formKind: form.kind, hasMatch: false });
      return;
    }
    dispatch({ kind: 'classified', formKind: form.kind, hasMatch: true });
    dispatch({ kind: 'interact' });
    session = { nonce: reply.value.nonce, form, target };
    const shown = await menu.show(target, reply.value.nonce);
    if (!shown.ok) {
      if (shown.error.kind === 'check-failed') recordStrike(shown.error.check);
      session = undefined;
    }
  };

  const formElements = (form: FormClass): Element[] =>
    form.fields.flatMap((a) => {
      if (a.purpose === 'submit' || a.purpose === 'none') return [];
      const el = fieldOf(a.id);
      return el === undefined ? [] : [el];
    });

  const snapshotOf = (form: FormClass): Snapshot => ({
    origin: win.location.origin,
    elements: new Set(formElements(form)),
  });

  const matchesDecision = (
    steps: readonly PlannedStep[],
    decided: Snapshot | undefined,
  ): boolean => {
    if (decided === undefined) return true;
    if (win.location.origin !== decided.origin) return false;
    return steps.every((step) =>
      (step.kind === 'cells' ? step.ids : [step.id]).every((id) => {
        const el = fieldOf(id);
        return el !== undefined && decided.elements.has(el);
      }),
    );
  };

  const measureForm = (form: FormClass): AttestOutcome => {
    const elements = formElements(form);
    if (elements.length === 0) return { ok: false, failed: 'C1' };
    for (const el of elements) {
      const m = measureTarget(ctx, el);
      if (!m.c1.ok) return { ok: false, failed: 'C1' };
      if (!m.c3.ok) return { ok: false, failed: 'C3' };
    }
    // Why: a background-initiated fill has no menu frame, so C2 and C4 do not apply; C5 is the foreign top layer check
    return attest({
      c1: { ok: true },
      c2: { ok: true },
      c3: { ok: true },
      c4: { ok: true, isSupported: false },
      isTampered: findForeignTopLayer(ctx, win.document.documentElement) !== undefined,
      nowMs: deps.nowMs(),
    });
  };

  const executeFill = (
    form: FormClass,
    values: readonly { purpose: FieldPurpose; value: string }[],
    options: { isAutosubmit: boolean; isPerCharEvents: boolean },
    decided: Snapshot | undefined,
  ): void => {
    classify();
    const fresh = classes.find((c) => c.formId === form.formId) ?? form;
    const { steps, errors } = planFill(fresh, page.fields, values);
    if (errors.length > 0 || steps.length === 0 || !matchesDecision(steps, decided)) {
      deps.notify('fill-refused');
      dispatch({ kind: 'fill-failed' });
      return;
    }
    isFilling = true;
    const result = fillSteps(fillCtx, steps, {
      isPerCharEvents: options.isPerCharEvents || config.quirks.per_char_events === true,
    });
    isFilling = false;
    if (!result.ok) {
      if (result.error.kind === 'obscured') recordStrike('C9');
      deps.notify(result.error.kind === 'rejected' ? 'fill-rejected' : 'fill-refused');
      dispatch({ kind: 'fill-failed' });
      return;
    }
    for (const step of steps) {
      const ids = step.kind === 'cells' ? step.ids : [step.id];
      for (const id of ids) {
        const el = fieldOf(id);
        if (el !== undefined) filledElements.add(el);
      }
    }
    const autosubmit =
      options.isAutosubmit &&
      config.quirks.no_autosubmit !== true &&
      config.quirks.append_2fa !== true;
    dispatch({ kind: 'filled', isAutosubmit: autosubmit, nowMs: deps.nowMs() });
    if (autosubmit && fresh.submit !== undefined) {
      const button = fieldOf(fresh.submit);
      if (button instanceof HTMLElement) button.click();
    }
  };

  const applyReply = (
    form: FormClass,
    reply: Result<ReplyOf<'fill-request'>, ProtocolError>,
    decided: Snapshot | undefined,
  ): void => {
    if (!reply.ok) {
      dispatch({
        kind: 'abort',
        reason: reply.error.kind === 'locked' ? 'locked' : 'fill-refused',
      });
      return;
    }
    const r = reply.value;
    if (r.kind === 'payload') {
      executeFill(
        form,
        r.fields,
        { isAutosubmit: r.isAutosubmit, isPerCharEvents: r.isPerCharEvents },
        decided,
      );
    } else {
      dispatch({
        kind: 'abort',
        reason:
          r.kind === 'refused' && r.reason === 'left-match-set' ? 'left-match-set' : 'fill-refused',
      });
      if (r.kind === 'refused') deps.notify('fill-refused');
    }
  };

  const generate = async (form: FormClass): Promise<void> => {
    const targets = form.fields.filter(
      (a) =>
        a.purpose === 'new-password' ||
        a.purpose === 'confirm-password' ||
        (form.kind === 'login' && a.purpose === 'password'),
    );
    const firstSnap = page.fields.find((f) => f.id === targets[0]?.id);
    if (firstSnap === undefined) return;
    const rules = {
      ...(firstSnap.maxlength === undefined ? {} : { maxlength: firstSnap.maxlength }),
      ...(firstSnap.minlength === undefined ? {} : { minlength: firstSnap.minlength }),
      ...(firstSnap.pattern === undefined ? {} : { pattern: firstSnap.pattern }),
      ...(config.passwordRules === undefined ? {} : { passwordRules: config.passwordRules }),
    };
    const reply = await background.request({
      kind: 'generate',
      rules,
      preset: win.document.documentElement.lang.startsWith('ko') ? 'korean-safe' : 'default',
    });
    if (!reply.ok) return;
    const generated = reply.value;
    const asNewPassword = {
      ...form,
      fields: form.fields.map((a) =>
        a.purpose === 'password' ? { ...a, purpose: 'new-password' as const } : a,
      ),
    };
    const { steps } = planFill(asNewPassword, page.fields, [
      { purpose: 'new-password', value: generated.value },
    ]);
    isFilling = true;
    const result = fillSteps(fillCtx, steps, { isPerCharEvents: false });
    isFilling = false;
    let isMatch = result.ok;
    if (result.ok) {
      for (const step of steps) {
        const el = step.kind === 'cells' ? undefined : fieldOf(step.id);
        if (el instanceof HTMLInputElement) {
          filledElements.add(el);
          if (el.value.length !== generated.length) isMatch = false;
        }
      }
    }
    if (!isMatch) deps.notify('save-unverified-length');
    await background.request({
      kind: 'generated-verified',
      isMatch,
      expectedLength: generated.length,
      actualLength: isMatch ? generated.length : 0,
    });
  };

  async function handleFrameMessage(m: PortToContent): Promise<void> {
    const current = session;
    if (current === undefined) return;
    if (m.kind === 'dismiss') {
      closeSession();
      dispatch({ kind: 'escape' });
      return;
    }
    if (m.kind !== 'picked') return;
    const outcome = menu.attest(current.target);
    if (!outcome.ok) {
      closeSession();
      recordStrike(outcome.failed);
      return;
    }
    dispatch({ kind: 'picked' });
    const decided = snapshotOf(current.form);
    if (m.action === 'generate') {
      closeSession();
      await generate(current.form);
      return;
    }
    const reply = await background.request({
      kind: 'fill-request',
      nonce: current.nonce,
      token: m.token,
      itemId: m.itemId,
      formId: current.form.formId,
      formKind: current.form.kind,
      purposes: requestPurposes(current.form),
      attestation: outcome.attestation,
    });
    closeSession();
    applyReply(current.form, reply, decided);
  }

  const requestWithMeasure = async (
    form: FormClass,
    send: (
      attestation: Extract<AttestOutcome, { ok: true }>['attestation'],
    ) => Promise<Result<ReplyOf<'fill-request'>, ProtocolError>>,
  ): Promise<void> => {
    const outcome = measureForm(form);
    if (!outcome.ok) {
      recordStrike(outcome.failed);
      deps.notify('fill-refused');
      dispatch({ kind: 'fill-failed' });
      return;
    }
    const decided = snapshotOf(form);
    const reply = await send(outcome.attestation);
    applyReply(form, reply, decided);
  };

  const fillFromPush = async (m: Extract<BackgroundPush, { kind: 'fill-form' }>): Promise<void> => {
    classify();
    const form = primaryClass();
    if (form === undefined || !canFillIn(frame) || strikes.isDisabled) return;
    dispatch({ kind: 'picked' });
    await requestWithMeasure(form, async (attestation) =>
      background.request({
        kind: 'fill-request',
        nonce: m.nonce,
        token: m.token,
        itemId: m.itemId,
        formId: form.formId,
        formKind: form.kind,
        purposes: requestPurposes(form),
        attestation,
      }),
    );
  };

  const continueFlow = async (): Promise<void> => {
    if (flow.kind !== 'filling' || flow.step < 2) return;
    const form = primaryClass();
    if (form === undefined) return;
    await requestWithMeasure(form, async (attestation) =>
      background.request({
        kind: 'fill-continue',
        formId: form.formId,
        formKind: form.kind,
        purposes: requestPurposes(form),
        attestation,
      }),
    );
  };

  const captureValues = (form: FormClass): CaptureValues | undefined => {
    if (!captureKinds.has(form.kind)) return undefined;
    const values: CaptureValues = {};
    for (const a of form.fields) {
      const el = fieldOf(a.id);
      if (!(el instanceof HTMLInputElement) || filledElements.has(el) || el.value === '') continue;
      if (a.purpose === 'username' || a.purpose === 'email') values.username = el.value;
      else if (a.purpose === 'password' || a.purpose === 'current-password')
        values.password = el.value;
      else if (a.purpose === 'new-password') values.newPassword = el.value;
    }
    if (Object.keys(values).length === 0) return undefined;
    spawn(
      background.request({ kind: 'capture', formId: form.formId, values, source: 'typed' }),
      deps.report,
    );
    return values;
  };

  const submitsToOtherOrigin = (form: FormClass): boolean => {
    const field = form.fields[0];
    const owner = field === undefined ? null : (fieldOf(field.id)?.closest('form') ?? null);
    if (owner === null) return false;
    try {
      return new URL(owner.action, win.location.href).origin !== win.location.origin;
    } catch {
      return true;
    }
  };

  const formOfElement = (el: Element): FormClass | undefined => {
    const id = registry.knownId(el);
    return id === undefined
      ? undefined
      : classes.find((c) => c.fields.some((a) => a.id === id) || c.submit === id);
  };

  const onSubmitSignal = (form: FormClass, trigger: 'submit' | 'enter' | 'click'): void => {
    if (!captureKinds.has(form.kind) || config.quirks.skip_save === true) return;
    const values = captureValues(form);
    submitted = { formId: form.formId, atMs: deps.nowMs(), kind: submitKindOf(form.kind) };
    writeHandoff(
      deps.nowMs(),
      frame === 'top' && values !== undefined && !submitsToOtherOrigin(form) ? values : undefined,
      submitKindOf(form.kind),
    );
    spawn(
      background.request({
        kind: 'submit-signal',
        formId: form.formId,
        trigger,
        outcome: 'pending',
        ...kindField(submitKindOf(form.kind)),
      }),
      deps.report,
    );
  };

  const evaluateSubmit = async (): Promise<void> => {
    const s = submitted;
    if (s === undefined) return;
    if (deps.nowMs() - s.atMs > SUBMIT_WATCH_MS) {
      submitted = undefined;
      return;
    }
    classify();
    const still = classes.find((c) => c.formId === s.formId && captureKinds.has(c.kind));
    const outcome = page.hasErrorText ? 'error-text' : still === undefined ? 'gone' : undefined;
    if (outcome === undefined) return;
    submitted = undefined;
    const handoff = await readHandoff();
    const reply = await background.request({
      kind: 'submit-signal',
      formId: s.formId,
      trigger: outcome === 'gone' ? 'form-gone' : 'navigation',
      outcome,
      ...kindField(s.kind),
      ...handoffFields(handoff),
    });
    if (reply.ok) spawn(deps.handoff.clear(), deps.report);
    if (reply.ok && reply.value.kind === 'prompt') {
      const shown = await menu.show(undefined, reply.value.nonce);
      if (shown.ok)
        session = { nonce: reply.value.nonce, form: classes[0] ?? emptyForm(), target: undefined };
    }
  };

  // Why: the page unloads right after submit, which can cancel a message that has to wake an evicted worker; the handoff sits in extension-private storage (never page-readable) so the next same-origin page can replay the submit, and it is consumed on first read or after HANDOFF_TTL_MS.
  const writeHandoff = (
    atMs: number,
    values: CaptureValues | undefined,
    formKind: SubmitKind | undefined,
  ): void => {
    spawn(deps.handoff.put({ atMs, origin: win.location.origin, values, formKind }), deps.report);
  };

  const readHandoff = async (): Promise<HandoffRead | undefined> => {
    try {
      const raw = await deps.handoff.take();
      if (raw === undefined || raw === null) return undefined;
      const parsed = handoffSchema.safeParse(raw);
      if (
        !parsed.success ||
        parsed.data.origin !== win.location.origin ||
        deps.nowMs() - parsed.data.atMs > HANDOFF_TTL_MS ||
        deps.nowMs() < parsed.data.atMs
      ) {
        spawn(deps.handoff.clear(), deps.report);
        return undefined;
      }
      return { values: parsed.data.values, formKind: parsed.data.formKind };
    } catch {
      return undefined;
    }
  };

  const resumeSubmit = async (): Promise<void> => {
    if (win.document.readyState !== 'complete') {
      await new Promise<void>((resolve) => {
        win.addEventListener(
          'load',
          () => {
            resolve();
          },
          { once: true, signal },
        );
      });
    }
    const handoff = await readHandoff();
    classify();
    const still = classes.some((c) => captureKinds.has(c.kind));
    const outcome = page.hasErrorText ? 'error-text' : still ? 'rerendered' : 'gone';
    const reply = await background.request({
      kind: 'submit-signal',
      formId: 'resume',
      trigger: 'navigation',
      outcome,
      ...handoffFields(handoff),
    });
    if (reply.ok) spawn(deps.handoff.clear(), deps.report);
    if (reply.ok && reply.value.kind === 'prompt') {
      const shown = await menu.show(undefined, reply.value.nonce);
      if (shown.ok)
        session = { nonce: reply.value.nonce, form: classes[0] ?? emptyForm(), target: undefined };
    }
  };

  const emptyForm = (): FormClass => ({
    formId: page.forms[0]?.id ?? formId(0),
    kind: 'none',
    confidence: 0,
    fields: [],
    evidence: [],
  });

  const refresh = (): void => {
    classify();
    const primary = primaryClass();
    if (primary !== undefined) {
      dispatch({
        kind: 'snapshot',
        formKind: primary.kind,
        hasErrorText: page.hasErrorText,
        hasCaptcha: page.hasCaptcha,
        isInMatchSet: true,
        nowMs: deps.nowMs(),
      });
    } else {
      dispatch({
        kind: 'snapshot',
        formKind: 'none',
        hasErrorText: page.hasErrorText,
        hasCaptcha: page.hasCaptcha,
        isInMatchSet: true,
        nowMs: deps.nowMs(),
      });
    }
    spawn(continueFlow(), deps.report);
    spawn(evaluateSubmit(), deps.report);
    bindRoots();
  };

  const teachAndReload = async (
    purpose: 'username' | 'password' | 'otp',
    selector: string,
  ): Promise<void> => {
    await background.request({ kind: 'teach', purpose, selector });
    await loadConfig();
    refresh();
  };

  const onInteract = (e: Event): void => {
    if (!e.isTrusted || isFilling) return;
    const el = targetOf(e);
    if (el === undefined) return;
    if (teach !== undefined && el instanceof HTMLInputElement) {
      const selector = selectorFor(el);
      const purpose = teach;
      teach = undefined;
      if (selector !== undefined) {
        spawn(teachAndReload(purpose, selector), deps.report);
      }
      return;
    }
    if (menu.isOpen()) return;
    classify();
    const form = formOfElement(el);
    if (form === undefined || !(el instanceof HTMLInputElement || el instanceof HTMLSelectElement))
      return;
    spawn(openMenu(form, el), deps.report);
  };

  const onKeydown = (e: KeyboardEvent): void => {
    if (!e.isTrusted) return;
    const el = targetOf(e);
    if (menu.isOpen()) {
      if (
        e.key === 'ArrowDown' ||
        e.key === 'ArrowUp' ||
        e.key === 'Enter' ||
        e.key === 'Home' ||
        e.key === 'End'
      ) {
        e.preventDefault();
        e.stopImmediatePropagation();
        menu.relayKey(e.key);
      } else if (e.key === 'Escape') {
        closeSession();
        dispatch({ kind: 'escape' });
      } else if ((e.key === 'g' || e.key === 'G') && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        menu.relayKey('g');
      }
      return;
    }
    if (e.key === 'Enter' && el !== undefined) {
      const form = formOfElement(el);
      if (form !== undefined) onSubmitSignal(form, 'enter');
    }
  };

  const onSubmit = (e: Event): void => {
    if (!e.isTrusted) return;
    const el = targetOf(e);
    if (el === undefined) return;
    const form =
      formOfElement(el) ??
      classes.find((c) => c.fields.some((a) => fieldOf(a.id)?.closest('form') === el));
    if (form !== undefined) onSubmitSignal(form, 'submit');
  };

  const onClick = (e: MouseEvent): void => {
    if (!e.isTrusted) return;
    const el = targetOf(e);
    const button = el?.closest('button,input[type="submit"],[role="button"]');
    if (button === null || button === undefined) return;
    const form = formOfElement(button);
    if (form !== undefined && form.submit === registry.knownId(button))
      onSubmitSignal(form, 'click');
  };

  const onChange = (e: Event): void => {
    if (!e.isTrusted) return;
    const el = targetOf(e);
    if (el === undefined) return;
    const id = registry.knownId(el);
    if (id !== undefined) filledElements.delete(el);
  };

  const bindRoot = (root: Document | ShadowRoot): void => {
    if (boundRoots.has(root)) return;
    boundRoots.add(root);
    const opts = { capture: true, signal };
    root.addEventListener('focusin', onInteract, opts);
    root.addEventListener(
      'click',
      (e) => {
        if (e instanceof MouseEvent) {
          onClick(e);
          onInteract(e);
        }
      },
      opts,
    );
    root.addEventListener(
      'keydown',
      (e) => {
        if (e instanceof KeyboardEvent) onKeydown(e);
      },
      opts,
    );
    root.addEventListener('submit', onSubmit, opts);
    root.addEventListener('input', onChange, opts);
    root.addEventListener('change', onChange, opts);
  };

  const bindRoots = (): void => {
    bindRoot(win.document);
    for (const el of natives.querySelectorAll(win.document, '*')) {
      const shadow = deps.getShadowRoot(el);
      if (shadow !== null) bindRoot(shadow);
    }
  };

  const reloadConfig = async (): Promise<void> => {
    await loadConfig();
    refresh();
  };

  await reloadConfig();
  if (frame === 'top') spawn(resumeSubmit(), deps.report);

  let timer: number | undefined;
  const schedule = (): void => {
    if (timer !== undefined) win.clearTimeout(timer);
    timer = win.setTimeout(refresh, DEBOUNCE_MS);
  };
  const observer = new win.MutationObserver(schedule);
  observer.observe(win.document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['type', 'style', 'class', 'hidden', 'disabled'],
  });
  const navigation: unknown = Reflect.get(win, 'navigation');
  if (navigation instanceof EventTarget) {
    navigation.addEventListener(
      'navigatesuccess',
      () => {
        spawn(reloadConfig(), deps.report);
      },
      { signal },
    );
  }
  win.addEventListener('popstate', schedule, { signal });
  win.addEventListener('hashchange', schedule, { signal });
  const tick = win.setInterval(() => {
    dispatch({ kind: 'tick', nowMs: deps.nowMs() });
    if (flow.kind === 'needs-human') deps.notify('needs-human');
  }, TICK_MS);
  signal.addEventListener('abort', () => {
    observer.disconnect();
    win.clearInterval(tick);
    if (timer !== undefined) win.clearTimeout(timer);
    menu.hide();
  });

  return {
    push: (message) => {
      switch (message.kind) {
        case 'open-menu': {
          classify();
          const form = primaryClass();
          if (form !== undefined) spawn(openMenu(form, formEntryField(form)), deps.report);
          break;
        }
        case 'fill-focused': {
          isFilling = true;
          const result = fillFocused(fillCtx, message.value, {
            isPerCharEvents: config.quirks.per_char_events === true,
          });
          isFilling = false;
          if (!result.ok) deps.notify('fill-rejected');
          break;
        }
        case 'fill-form':
          spawn(fillFromPush(message), deps.report);
          break;
        case 'teach-start':
          teach = message.purpose;
          break;
        case 'abort-flow':
          closeSession();
          dispatch({ kind: 'abort', reason: 'user' });
          break;
        case 'lock':
          closeSession();
          dispatch({ kind: 'abort', reason: 'locked' });
          break;
      }
    },
    flow: () => flow,
    report: () => buildProblemReport(page, classes),
    refresh,
  };
};
