# TypeScript style

Rules for all TypeScript in the browser extension: `apps/extension` (WXT, React popup, background, content scripts) and `packages/autofill`. Shared rules (comments, secrets, errors, tests, dependencies, commits) are in [README.md](README.md). The Rust core and its WASM crate follow `rust.md`.

## Principles

- Code explains itself. Use names, types and structure, not comments.
- Treat every byte from a page, a message, storage or WASM as untrusted until a schema or a type guard says otherwise.
- Make invalid states unrepresentable: discriminated unions, branded types, `exactOptionalPropertyTypes`.
- Secrets live in WASM memory. TypeScript holds plaintext only in the background, in the smallest scope, and in a content script for one synchronous fill. The popup never holds key material.

## Comments

| Allowed | Example |
|---|---|
| Directives the toolchain reads | `// @ts-expect-error <reason>`, `// oxlint-disable-next-line typescript/no-unsafe-type-assertion -- <reason>` `[U: -- syntax]`, `/// <reference types="..." />` in generated files |
| Why-comment | `// Why: Chrome rejects 'wasm-unsafe-eval' in worker-src (<doc URL>)` |
| Licence header a vendored file requires | `// SPDX-License-Identifier: MIT` |

- **Exported symbols get no `/** */`** unless the signature leaves out something a caller must know (ownership, single use, zeroing, which context it runs in).
- **`@ts-ignore` and `@ts-nocheck` are banned.** `@ts-expect-error` needs a description (`ban-ts-comment`). Unused suppressions fail the build (`reportUnusedDisableDirectives`).

## Formatting and tooling

- **Oxfmt formats everything,** pinned exactly (0.x output can change between releases). Config in the appendix. Prettier 3 is the fallback if churn hurts.
- **`tsc --noEmit` (TypeScript 7) is the type gate.**
- **Oxlint runs with `options.typeAware` and `options.typeCheck` set in `.oxlintrc.json`,** so plain `oxlint` is the command. Correctness and suspicious categories are errors, plus the type-aware promise, `no-unsafe-*` and exhaustiveness rules. Pin `oxlint` and `oxlint-tsgolint` together.
- **typescript-eslint and ESLint are not used.** typescript-eslint cannot load TypeScript 7 until the 7.1 JS API ships `[U: planned 2026-11-24]`. A narrow untyped ESLint pass for security plugins needs maintainer approval and only if Oxlint has no equivalent.
- **Tools are pinned in `mise.toml` and run through `mise run check`.** No ad-hoc `npx`.

## Naming

- **Files:** `kebab-case.ts`. A React component file is `kebab-case.tsx` and exports one component of the same name in PascalCase. Tests are `name.test.ts` next to the file.
- **Acronyms are words** (Google): `FormSnap`, `loadHttpUrl`, `totpCode`. Never `HTTPUrl`.
- **Limits and timings are `SCREAMING_SNAKE` with a unit suffix:** `GESTURE_TOKEN_TTL_MS`. Other constants are `camelCase`. Units live in names (`delayMs`), booleans read as questions (`isVisible`).
- **No `I` prefix, no `Type` or `Enum` suffix.** Props types are `XProps`. Handlers are `onX` in props and `handleX` when defined.

## Modules, files and exports

- **Named exports only** (Google, `import/no-default-export`), except files WXT requires to default-export (`entrypoints/**`, `*.config.ts`).
- **No barrel files** except the single `index.ts` that is a package's public surface (`packages/autofill`). No path aliases: workspace package names across packages, relative imports inside one.
- **No cycles** (`import/no-cycle`). Direction: `apps/extension` to `packages/autofill` to nothing. The content script never imports popup code and the popup never imports content-script code.
- **One concept per file, grouped by feature** (FSD-style slices are for the popup only). Order: types, constants, exported functions, private helpers in call order.
- **No `export let`** (Google). No mutable module-level state in the background except a memoized initialisation promise (the service worker is evicted).
- **Layout of `apps/extension/src`:** `entrypoints/` (WXT, thin), `platform/` (the only code that touches `browser` or `chrome`: `messaging.ts`, `storage.ts`, `tabs.ts`, `log.ts`), `wasm/` (client wrapper, generated types in `generated/`), `background/`, `popup/`, `content/`.

## Types

- **`strict` plus the appendix flags are on everywhere.** The ones that carry weight:
  - `noUncheckedIndexedAccess`: `items[0]` is `T | undefined`. Handle it, do not assert it.
  - `exactOptionalPropertyTypes`: `a?: string` means absent, not `undefined`.
  - `erasableSyntaxOnly`: no `enum`, no `namespace`, no parameter properties, so output stays runnable by type stripping.
- **No `any`.** Data from `JSON.parse`, messages, `storage.get`, `postMessage` and `event.data` is `unknown` and goes through a zod schema or a type guard at the edge.
- **No `!` and no `as` that narrows** (`no-non-null-assertion`, `no-unsafe-type-assertion`). `as const` and `satisfies` are fine. A cast is allowed in a test, or with a suppression that names the invariant.
- **`type` for everything, not `interface`.** Google prefers `interface` for object shapes `[V]`; we choose one keyword for unions, intersections and mapped types, and declaration merging is a bug here (`consistent-type-definitions`).
- **No enums.** Use string-literal unions, or an `as const` object when you need the values at runtime.

```ts
export const formKinds = ['login', 'signup', 'otp', 'card'] as const;
export type FormKind = (typeof formKinds)[number];
```

- **Model states as discriminated unions with a `kind` tag, and switch exhaustively** (`switch-exhaustiveness-check`; no `default` that swallows new cases), e.g. `{ kind: 'idle' } | { kind: 'offered'; formId: FormId }`.

- **Brand identifiers and units that must not mix.** Brands are erased at runtime and constructed only by a validating function.

```ts
declare const brand: unique symbol;
export type Brand<T, B extends string> = T & { readonly [brand]: B };
export type Origin = Brand<string, 'origin'>;
```

- **Secrets are wrapped, never bare strings.** `Redacted<T>` has a private `#value`, `reveal()`, and `toJSON`, `toString` and `inspect` that return `'[redacted]'`. A `string` cannot be zeroed, so prefer `Uint8Array` and `fill(0)` after use when the core hands bytes. `[U: the wrapper is a proposal; check the first WASM release for what the core returns]`
- **`undefined` for absent, `null` only where a platform API returns it;** convert at the edge. Known keys use a union key type, not `Record<string, T>`.
- **Types generated by tsify live in `wasm/generated/` and are committed.** Do not hand-edit or re-declare them; derive with `Pick` and `Omit`.

## Functions

- **Exported functions have explicit parameter and return types.** Required inputs are parameters. Three or more, or any boolean unclear at the call site, become one options object.
- **No defaults that hide security-relevant choices.** A parameter such as `allowCrossHost` has no default.
- **No classes except where an object owns a resource or must hide state** (`Redacted`, an observer wrapper with `dispose`). No inheritance. Dependencies are passed as arguments, not imported singletons.

## Errors

- **Expected failures are values, bugs are throws.** A function whose failure the caller must handle returns `Result<T, E>`. A broken invariant throws an `Error` subclass that nothing catches except a boundary that reports and aborts.

```ts
export type Result<T, E> = { ok: true; value: T } | { ok: false; error: E };
export const ok = <T>(value: T): Result<T, never> => ({ ok: true, value });
export const err = <E>(error: E): Result<never, E> => ({ ok: false, error });
```

- **`E` is a discriminated union of `kind` codes, never a string and never an `Error` across a message.** Core failures keep the `HaspError` names in kebab-case (`'locked'`, `'aead'`, `'kdf-params'`, `'cancelled'`, `'internal'`). Checks that run only here add their own kinds, such as `{ kind: 'origin-denied'; origin: Origin }`.
- **The WASM wrapper is the one place that catches values thrown by the core** and converts them into `Result`. Callers never see a raw `JsValue`.
- **Message replies are `Result`.** Handlers never throw to the sender; an unexpected throw is caught in the messaging module, logged without payload, and returned as `{ kind: 'internal' }`.
- **`catch (e)` binds `unknown`.** Throw only `Error` instances, with `cause` when wrapping (`only-throw-error`). An empty `catch` is banned: a catch returns a `Result`, rethrows, or reports and aborts.
- **Messages and logs never contain secrets, field values, URLs with query, or page text.** Log codes and registrable domains through `platform/log.ts` (`no-console`).
- **Fail closed.** A failed check (`C1` to `C9`, origin mismatch, schema failure) releases nothing and aborts the flow.

## Async and promises

- **Every promise is awaited, returned, or handed to `spawn(promise)`,** which catches and reports. No bare `void promise`. `no-floating-promises` and `no-misused-promises` are errors.
- **`async`/`await`, not `.then` chains** (`.then(...).catch(...)` only inside `spawn`). Use `return await` inside `try`.
- **Every wait has a bound.** Messages, WASM initialisation and native-messaging calls take an `AbortSignal` (`AbortSignal.timeout(ms)`). Timers, observers and listeners are tied to an `AbortController` or the WXT content-script `ctx` so they stop when the extension context is invalidated.
- **No `setTimeout` or `setInterval` for state in the background.** Timers die with the service worker; use `browser.alarms` and persist deadlines in session storage.

## React

- **Function components and hooks only,** except an error boundary. Follow the Rules of React. `react/exhaustive-deps` is an error and is never suppressed; restructure instead.
- **Effects only for synchronising with something outside React** (a port, a timer, an observer). Derive values during render, handle events in handlers, reset with `key` (You Might Not Need an Effect).
- **The popup is a view over the background.** It sends intents and renders; it keeps no copy of the vault. `useSyncExternalStore` for background state, no state library.
- **A revealed secret is held in state only while shown,** cleared on blur, timeout, route change, unmount and lock. Never in a key, a `data-*` attribute, `title`, an `id`, a URL, or `localStorage`.
- **Accessibility:** native elements first, labelled inputs, focus restored on close, keyboard operable. A hard-coded user-visible string fails CI.

## Extension rules

### Messaging

- **One typed module (`platform/messaging.ts`) is the only code that calls `runtime.onMessage`, `runtime.onConnect`, `sendMessage` or `postMessage`.** Raw use elsewhere is a lint error. `[U: Oxlint's no-restricted-properties matches the property name only, so the ban is by property name]`
- **The message set is a closed zod discriminated union** keyed by `kind`, with `.strict()` objects. The handler map is `Record<Message['kind'], Handler>`, so a kind without a handler fails to compile. Unknown kinds are dropped without a reply.
- **Every received message is parsed before use.** Content-script messages are attacker-influenced input (Chrome messaging docs).
- **Origin, frame and tab come from `sender`, never from the payload.** Check `sender.id === browser.runtime.id`, `sender.frameId`, `sender.tab`, and match on `sender.origin` or `sender.url`. No schema has a payload field named `origin` or `url`.
- **Reply through one wrapper that calls `sendResponse` and returns the literal `true`.** Chrome 148 supports returning a promise but is rolling it out gradually and not in extensions with a DevTools page, so the wrapper does not depend on it.
- **Release messages are single use.** A fill approval carries a `GestureToken` bound to tab and frame with a 2 s TTL; the handler verifies and consumes it.
- **Responses to content scripts carry only what that step needs.** Never a vault, never a key. Assume anything sent to a content script can reach the page.

### Content scripts and the page

- **The page is hostile.** The content script runs in the isolated world and never uses `world: 'MAIN'` except for the one passkey hook script, which has no extension API, no secrets and no approval tokens, and talks to the isolated script through one validated channel.
- **Never put secrets in the DOM, the page world, `postMessage`, `CustomEvent.detail`, an attribute, or storage the page can reach.** Plaintext reaches an input in one synchronous pass from one approved message, using the native value setter, then the reference is dropped.
- **Do not read values.** Snapshots hold lengths, not values.
- **`window.postMessage` is banned.** If the passkey hook needs a channel, it is a `MessageChannel` port handed over once, checked with `event.source === window` and a schema.
- **`event.isTrusted` is checked on every gesture that can release a secret.**
- **Trust browser APIs, not page globals.** Capture `Element.prototype` methods and native setters at startup (`run_at: document_start`) before page scripts run; never call functions or read properties the page defined.
- **No `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `srcdoc`, or `DOMParser` on page data.** Build with `createElement`, `textContent`, `setAttribute` of known names and `replaceChildren`. Never set `on*` attributes. `textContent` is the only way page text enters our UI.
- **Listeners use `addEventListener(type, fn, { signal })`,** `capture: true` for the clickjacking checks, and one `MutationObserver` per concern with a disconnect on abort.
- **Inline menu:** one host element with a **closed** shadow root holding one extension-origin `<iframe src>`; all interactive UI is in the iframe. Mount it with WXT `createShadowRootUi` (`cssInjectionMode: 'ui'`, `isolateEvents`). Checks C1 to C10 are pure functions in `packages/autofill` with fixtures in the red-team suite.

### Background and storage

- **The background is the only context that holds secrets, and only in WASM memory and `storage.session`.** Never `storage.local`, `storage.sync`, IndexedDB, `localStorage`, cookies, the clipboard (except the timed copy), `console`, error reports or file names. `storage.local` is ciphertext and non-secret settings only. `[U: whether Chrome encrypts storage.local at rest; assume it does not]`
- **`storage.session`:** call `setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' })` at startup so content scripts cannot read it. It is in-memory, cleared on browser restart, reload and update, and capped at 10 MB. Every key has a TTL; lock and browser exit clear it. Handle quota rejections.
- **All storage access goes through `platform/storage.ts`,** which exposes typed keys, zod-parses on read, and returns `Result`.
- **The service worker is evicted when idle.** Register every listener synchronously at the top level of the entry `[U: Chrome service-worker docs not fetched]`. Keep no state in module variables except memoised initialisation; re-derive the rest from session storage and WASM. Test eviction.
- **Write for the stricter of service worker (Chromium) and event page (Firefox, Safari)** and gate differences behind `platform/`.

### CSP and manifest

- **Extension-page CSP is `script-src 'self' 'wasm-unsafe-eval'; object-src 'self'`** (MDN: MV3 allows only `'none'`, `'self'`, `'wasm-unsafe-eval'` in script directives). Never loosen it, add a remote origin, `'unsafe-inline'` or `'unsafe-eval'`. Chrome rejects `wasm-unsafe-eval` in `worker-src`.
- **Content scripts do not run WASM.** The core lives in the background or an offscreen document; a content script that needs core logic sends a message.
- **Permissions are the minimum.** Host permissions `https://*/*` and `http://localhost/*` for content scripts only; no `<all_urls>`, `webRequest`, or `tabs` unless proven needed. Every manifest change goes through review and a manifest snapshot test.
- **`web_accessible_resources` lists only what the iframe and passkey hook need,** scoped by `matches`. Anything listed is reachable by page scripts.

### WASM boundary

- **One wrapper, `wasm/client.ts`, imports the generated `hasp-wasm` package** (`no-restricted-imports`).
- **Initialise lazily and memoise the promise,** with a timeout; a failed init is retried on the next call. Re-instantiate after eviction.
- **CI fails on a tsify regeneration diff.** tsify types describe shape, not trust: inputs from messages are zod-parsed before they reach the core.
- **Pass bytes as `Uint8Array`, copy at the boundary when you keep them,** and free every wasm object you own (`free()` or `Symbol.dispose` `[U: confirm the pinned wasm-bindgen emits it]`). Never serialise a core object to JSON for storage or logging.
- **No logic that the core owns:** matching, generation, OTP, URL normalisation.

## Testing

- **Vitest is the one runner.** Node environment for pure logic; **browser mode with the Playwright provider** for anything that touches the DOM (classifier, snapshotter, filler, clickjacking checks). jsdom and happy-dom are not used for content-script tests. Playwright e2e loads the built extension in Chromium. Safari is manual and Xcode UI tests.
- **Table tests use `it.each` with named cases;** the body does not branch on the case.
- **The typed `platform/` module has an in-memory fake.** Do not stub `chrome.*` globals. Time and randomness are injected; use `vi.useFakeTimers()` for TTLs.

## Dependencies

- **The runtime allowlist is `react`, `react-dom`, `zod`, and the generated wasm package.** WXT, Vite, TypeScript, Vitest, Playwright, Oxlint and Oxfmt are dev-only. Anything else needs maintainer approval with the reason and a size and audit note.
- **Versions are exact and shared through the pnpm catalog.** CI installs with `pnpm install --frozen-lockfile`.
- **pnpm 11 supply-chain settings are mandatory** (appendix): `minimumReleaseAge` 7 days with `minimumReleaseAgeStrict`, `trustPolicy: no-downgrade`, `blockExoticSubdeps`, `strictDepBuilds`, and an explicit `allowBuilds` map. Native tools (wasm-bindgen CLI, Rust) come from `mise`, not npm.

## CI gates

`mise run check` runs these, and CI calls the same task.

```sh
pnpm install --frozen-lockfile
oxfmt --check
pnpm -r typecheck
oxlint
vitest run
wxt build -b chrome && wxt build -b firefox
wxt build -b safari
node scripts/check-bundles.ts
```

`check-bundles` fails on `eval` or `new Function` in output, non-ASCII bytes in content-script bundles, a manifest CSP different from the pinned one, unexpected permissions, and a content-script bundle over its size budget `[U: script not written yet]`. The tsify regeneration check and the red-team and corpus gates are separate jobs.

## Sources

TypeScript handbook and TSConfig reference; Google TypeScript Style Guide (google.github.io/styleguide/tsguide.html, interfaces vs type aliases fetched `[V]`); typescript-eslint rule docs; Oxc docs and `configuration_schema.json` of the pinned versions; react.dev (Rules of React, You Might Not Need an Effect); developer.chrome.com extensions docs; MDN `content_security_policy`; wxt.dev; pnpm.io/supply-chain-security.

## Where this file departs from the sources, and why

| Topic | Sources say | This file | Reason |
|---|---|---|---|
| `interface` vs `type` | Google and the TS handbook: `interface` for object types | `type` always | One keyword; no declaration merging; unions and mapped types need `type` anyway |
| Enums | Google: plain `enum` | No enums | `erasableSyntaxOnly`; literal unions check exhaustively and erase cleanly |
| Errors | TS handbook: throw | `Result` for expected failures, throw for bugs | Messages and WASM need failures as data; a throw cannot cross a message |
| Lint engine | typescript-eslint is the reference | Oxlint with tsgolint | typescript-eslint cannot load TypeScript 7 yet; 12 to 18x faster per the Oxc benchmark `[S]` |

## Validation record

Run 2026-11-18 in `run/style-scratch/ts/` (pnpm workspace, sample files that deliberately break rules): Node 24.20.0, pnpm 11.25.0, TypeScript 7.0.2, oxlint 1.93.0, oxlint-tsgolint 7.0.2006, oxfmt 0.78.0, `@types/chrome` 0.3.7.

- The 7-day cooldown rejected `oxlint@1.94.0` (published 2026-11-16), so 1.93.0 and 0.78.0 are pinned. `strictDepBuilds` failed `esbuild` with `ERR_PNPM_IGNORED_BUILDS` until `allowBuilds` listed it.
- Every rule category fired on its sample, and an unknown rule name fails config parsing, so every appendix rule exists in 1.93.0.
- Not validated: WXT build, Vitest browser mode, the `.wxt/tsconfig.json` merge.

## Appendix: configuration files

### `pnpm-workspace.yaml`

```yaml
packages:
  - apps/*
  - packages/*
minimumReleaseAge: 10080
minimumReleaseAgeStrict: true
trustPolicy: no-downgrade
blockExoticSubdeps: true
strictDepBuilds: true
allowBuilds: {}
```

### `tsconfig.base.json`

```json
{
  "compilerOptions": {
    "target": "ES2024",
    "lib": ["ES2024", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "moduleDetection": "force",
    "jsx": "react-jsx",
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true,
    "noImplicitOverride": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true,
    "noPropertyAccessFromIndexSignature": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "useUnknownInCatchVariables": true,
    "verbatimModuleSyntax": true,
    "isolatedModules": true,
    "erasableSyntaxOnly": true,
    "resolveJsonModule": true,
    "allowImportingTsExtensions": true,
    "noEmit": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "types": []
  }
}
```

### `apps/extension/tsconfig.json`

```json
{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": { "types": ["chrome"] },
  "include": ["src"]
}
```

`[U: WXT generates .wxt/tsconfig.json; extend it from this file and keep the flags above]`

### `packages/autofill/tsconfig.json`

```json
{ "extends": "../../tsconfig.base.json", "include": ["src"] }
```

### `.oxlintrc.json`

```json
{
  "$schema": "./node_modules/oxlint/configuration_schema.json",
  "plugins": ["typescript", "oxc", "import", "unicorn", "promise", "react", "vitest"],
  "options": { "typeAware": true, "typeCheck": true, "reportUnusedDisableDirectives": "error" },
  "categories": { "correctness": "error", "suspicious": "error" },
  "env": { "browser": true, "es2024": true, "webextensions": true },
  "rules": {
    "typescript/no-floating-promises": "error",
    "typescript/no-misused-promises": "error",
    "typescript/await-thenable": "error",
    "typescript/promise-function-async": "error",
    "typescript/require-await": "error",
    "typescript/return-await": ["error", "in-try-catch"],
    "typescript/no-unsafe-argument": "error",
    "typescript/no-unsafe-assignment": "error",
    "typescript/no-unsafe-call": "error",
    "typescript/no-unsafe-member-access": "error",
    "typescript/no-unsafe-return": "error",
    "typescript/no-unsafe-type-assertion": "error",
    "typescript/no-unnecessary-condition": "error",
    "typescript/no-unnecessary-type-assertion": "error",
    "typescript/strict-void-return": "error",
    "typescript/switch-exhaustiveness-check": "error",
    "typescript/only-throw-error": "error",
    "typescript/prefer-promise-reject-errors": "error",
    "typescript/no-base-to-string": "error",
    "typescript/restrict-template-expressions": "error",
    "typescript/no-deprecated": "error",
    "typescript/no-explicit-any": "error",
    "typescript/no-non-null-assertion": "error",
    "typescript/ban-ts-comment": ["error", { "ts-expect-error": "allow-with-description", "ts-ignore": true, "ts-nocheck": true }],
    "typescript/consistent-type-imports": "error",
    "typescript/consistent-type-definitions": ["error", "type"],
    "typescript/no-import-type-side-effects": "error",
    "typescript/no-namespace": "error",
    "typescript/no-unsafe-enum-comparison": "error",
    "eslint/no-eval": "error",
    "eslint/no-implied-eval": "error",
    "eslint/no-new-func": "error",
    "eslint/no-script-url": "error",
    "eslint/no-console": "error",
    "eslint/no-inline-comments": "error",
    "eslint/no-warning-comments": "error",
    "eslint/eqeqeq": "error",
    "typescript/consistent-return": "off",
    "eslint/no-var": "error",
    "eslint/prefer-const": "error",
    "eslint/no-param-reassign": "error",
    "eslint/no-restricted-globals": ["error", "chrome", "browser", "name", "event", "localStorage", "sessionStorage"],
    "eslint/no-restricted-imports": [
      "error",
      {
        "paths": [
          { "name": "webextension-polyfill", "message": "Use the platform module." },
          { "name": "wxt/browser", "message": "Use the platform module." }
        ],
        "patterns": [{ "group": ["**/hasp-wasm/pkg/*"], "message": "Import the wasm client wrapper." }]
      }
    ],
    "eslint/no-restricted-properties": [
      "error",
      { "property": "onMessage", "message": "Use the typed messaging module." },
      { "property": "onConnect", "message": "Use the typed messaging module." },
      { "property": "sendMessage", "message": "Use the typed messaging module." },
      { "object": "window", "property": "postMessage", "message": "Never post to the page." },
      { "property": "innerHTML", "message": "Build nodes with the DOM API." },
      { "property": "outerHTML", "message": "Build nodes with the DOM API." },
      { "property": "insertAdjacentHTML", "message": "Build nodes with the DOM API." },
      { "property": "srcdoc", "message": "Use an extension-origin iframe src." }
    ],
    "import/no-cycle": "error",
    "import/no-default-export": "error",
    "react/rules-of-hooks": "error",
    "react/exhaustive-deps": "error",
    "react/no-danger": "error",
    "react/jsx-no-target-blank": "error",
    "react/no-array-index-key": "error",
    "promise/no-multiple-resolved": "error"
  },
  "overrides": [
    {
      "files": ["**/*.config.ts", "**/*.d.ts", "**/entrypoints/**"],
      "rules": { "import/no-default-export": "off" }
    },
    {
      "files": ["**/src/platform/**"],
      "rules": {
        "eslint/no-restricted-globals": "off",
        "eslint/no-restricted-imports": "off",
        "eslint/no-restricted-properties": ["error", { "property": "innerHTML", "message": "Build nodes with the DOM API." }]
      }
    },
    {
      "files": ["**/*.test.ts", "**/*.test.tsx", "**/*.spec.ts"],
      "rules": {
        "typescript/no-unsafe-type-assertion": "off",
        "typescript/no-non-null-assertion": "off"
      }
    }
  ],
  "ignorePatterns": ["dist", ".output", ".wxt", "**/generated/**", "node_modules"]
}
```

### `.oxfmtrc.json`

Only non-default options. Verified identical to the explicit full config on sample `.tsx`.

```json
{
  "$schema": "./node_modules/oxfmt/configuration_schema.json",
  "printWidth": 100,
  "singleQuote": true,
  "sortImports": {},
  "sortPackageJson": true,
  "ignorePatterns": ["dist", ".output", ".wxt", "**/generated/**", "pnpm-lock.yaml"]
}
```
