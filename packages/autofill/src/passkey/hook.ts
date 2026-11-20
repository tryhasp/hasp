import { connectHook } from '../platform/passkey-channel.ts';
import type { HookPort } from '../platform/passkey-channel.ts';
import { decodeBase64Url, serializeCreateOptions, serializeGetOptions } from './codec.ts';
import { fallbackWaitMs, shouldAsk } from './gate.ts';

const REPLY_TIMEOUT_MS = 120_000;

const readReply = (data: unknown): { id: number; payload: string | undefined } | undefined => {
  if (typeof data !== 'object' || data === null) return undefined;
  const id: unknown = Reflect.get(data, 'id');
  const outcome: unknown = Reflect.get(data, 'outcome');
  const payload: unknown = Reflect.get(data, 'payload');
  if (typeof id !== 'number') return undefined;
  if (outcome === 'handled' && typeof payload === 'string') return { id, payload };
  if (outcome === 'fallback') return { id, payload: undefined };
  return undefined;
};

const text = (obj: object, key: string): string | undefined => {
  const v: unknown = Reflect.get(obj, key);
  return typeof v === 'string' ? v : undefined;
};

const buffer = (obj: object, key: string): ArrayBuffer | undefined => {
  const v = text(obj, key);
  return v === undefined ? undefined : decodeBase64Url(v);
};

const defineAll = (target: object, props: Readonly<Record<string, unknown>>): void => {
  for (const [key, value] of Object.entries(props)) {
    Object.defineProperty(target, key, { value, enumerable: true, configurable: true });
  }
};

const toCredential = (payload: string): Credential | undefined => {
  const parsed: unknown = JSON.parse(payload);
  if (typeof parsed !== 'object' || parsed === null) return undefined;
  const response: unknown = Reflect.get(parsed, 'response');
  const rawId = buffer(parsed, 'rawId');
  const id = text(parsed, 'id');
  if (
    typeof response !== 'object' ||
    response === null ||
    rawId === undefined ||
    id === undefined
  ) {
    return undefined;
  }
  const isAssertion = text(response, 'signature') !== undefined;
  const responseProto = isAssertion
    ? AuthenticatorAssertionResponse.prototype
    : AuthenticatorAttestationResponse.prototype;
  const res: unknown = Object.create(responseProto);
  const credential: unknown = Object.create(PublicKeyCredential.prototype);
  if (typeof res !== 'object' || res === null || !(credential instanceof PublicKeyCredential)) {
    return undefined;
  }
  defineAll(res, { clientDataJSON: buffer(response, 'clientDataJSON') });
  if (isAssertion) {
    defineAll(res, {
      authenticatorData: buffer(response, 'authenticatorData'),
      signature: buffer(response, 'signature'),
      userHandle: buffer(response, 'userHandle') ?? null,
    });
  } else {
    defineAll(res, {
      attestationObject: buffer(response, 'attestationObject'),
      getTransports: () => ['internal', 'hybrid'],
      getAuthenticatorData: () => buffer(response, 'authenticatorData'),
      getPublicKey: () => buffer(response, 'publicKey') ?? null,
      getPublicKeyAlgorithm: () => -7,
    });
  }
  defineAll(credential, {
    id,
    rawId,
    type: 'public-key',
    authenticatorAttachment: 'platform',
    response: res,
    getClientExtensionResults: () => ({}),
    toJSON: () => ({ id, type: 'public-key' }),
  });
  return credential;
};

export type HookHandles = { get: unknown; create: unknown };

export const installPasskeyHook = (win: Window & typeof globalThis): HookHandles => {
  const proto = win.CredentialsContainer.prototype;
  const nativeGet = Reflect.get(proto, 'get');
  const nativeCreate = Reflect.get(proto, 'create');
  if (typeof nativeGet !== 'function' || typeof nativeCreate !== 'function') {
    return { get: undefined, create: undefined };
  }
  const pending = new Map<number, (payload: string | undefined) => void>();
  const link: { port: HookPort | undefined; next: number; inFlight: number } = {
    port: undefined,
    next: 1,
    inFlight: 0,
  };
  connectHook(win, (port) => {
    link.port = port;
    port.listen((data) => {
      const reply = readReply(data);
      if (reply === undefined) return;
      const resolve = pending.get(reply.id);
      if (resolve === undefined) return;
      pending.delete(reply.id);
      resolve(reply.payload);
    });
  });

  const ask = async (
    op: 'create' | 'get',
    options: string,
    signal: AbortSignal | undefined,
  ): Promise<string | undefined> => {
    const port = link.port;
    if (port === undefined) return undefined;
    const id = link.next;
    link.next += 1;
    const startedAt = win.performance.now();
    link.inFlight += 1;
    const answer = await new Promise<string | undefined>((resolve, reject) => {
      const timer = win.setTimeout(() => {
        pending.delete(id);
        resolve(undefined);
      }, REPLY_TIMEOUT_MS);
      signal?.addEventListener(
        'abort',
        () => {
          win.clearTimeout(timer);
          pending.delete(id);
          reject(new DOMException('The operation was aborted.', 'AbortError'));
        },
        { once: true },
      );
      pending.set(id, (payload) => {
        win.clearTimeout(timer);
        resolve(payload);
      });
      port.post({ id, op, options });
    }).finally(() => {
      link.inFlight -= 1;
    });
    if (answer === undefined) {
      // Why: a page must not learn from the reply time whether a passkey exists
      await new Promise<void>((resolve) => {
        win.setTimeout(resolve, fallbackWaitMs(win.performance.now() - startedAt));
      });
    }
    return answer;
  };

  const intercept = async (
    op: 'create' | 'get',
    self: unknown,
    options: unknown,
    call: (self: unknown, options: unknown) => Promise<unknown>,
  ): Promise<unknown> => {
    const fallback = async (): Promise<unknown> => {
      const result = await call(self, options);
      return result;
    };
    const opts = typeof options === 'object' && options !== null ? options : undefined;
    const pk: unknown = opts === undefined ? undefined : Reflect.get(opts, 'publicKey');
    if (opts === undefined || typeof pk !== 'object' || pk === null) return fallback();
    const mediation: unknown = Reflect.get(opts, 'mediation');
    const serialized =
      op === 'get'
        ? serializeGetOptions(pk, typeof mediation === 'string' ? mediation : undefined)
        : serializeCreateOptions(pk);
    if (serialized === undefined) return fallback();
    const activation: unknown = Reflect.get(win.navigator, 'userActivation');
    const isActive =
      typeof activation === 'object' &&
      activation !== null &&
      Reflect.get(activation, 'isActive') === true;
    const mediationText = typeof mediation === 'string' ? mediation : undefined;
    if (
      !shouldAsk({
        op,
        mediation: mediationText,
        isActivationActive: isActive,
        inFlight: link.inFlight,
      })
    )
      return fallback();
    const signal: unknown = Reflect.get(opts, 'signal');
    const payload = await ask(op, serialized, signal instanceof AbortSignal ? signal : undefined);
    if (payload === undefined) return fallback();
    const credential = toCredential(payload);
    return credential ?? fallback();
  };

  const callGet = async (self: unknown, options: unknown): Promise<unknown> => {
    const result: unknown = await Reflect.apply(nativeGet, self, [options]);
    return result;
  };
  const callCreate = async (self: unknown, options: unknown): Promise<unknown> => {
    const result: unknown = await Reflect.apply(nativeCreate, self, [options]);
    return result;
  };
  const get = async function (this: unknown, options?: unknown): Promise<unknown> {
    const result = await intercept('get', this, options, callGet);
    return result;
  };
  const create = async function (this: unknown, options?: unknown): Promise<unknown> {
    const result = await intercept('create', this, options, callCreate);
    return result;
  };
  const descriptor = { configurable: true, writable: true, enumerable: true };
  Object.defineProperty(proto, 'get', { ...descriptor, value: get });
  Object.defineProperty(proto, 'create', { ...descriptor, value: create });
  return { get, create };
};

export const isAnotherManagerActive = (
  win: Window & typeof globalThis,
  ours: HookHandles,
): boolean => {
  const proto = win.CredentialsContainer.prototype;
  return Reflect.get(proto, 'get') !== ours.get || Reflect.get(proto, 'create') !== ours.create;
};
