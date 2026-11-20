# Style guides

Rules for all code in the vault monorepo: [Rust](rust.md), [TypeScript](typescript.md), [Swift](swift.md). Where the sources disagree, a guide picks one option and that option is binding. Tooling enforces every rule it can, review enforces the rest. Marks: `[V]` verified (source fetched or run in `run/style-scratch`), `[S]` secondary source, `[U]` unverified.

## All languages

- **English everywhere:** code, docs, commits, identifiers. User-visible strings live in the string catalogs (`ko`, `en`).
- **Comments are banned,** except:
  - directives a tool reads (lint and type suppressions, `SAFETY`, `swift-tools-version`, `@ts-expect-error`), each naming its rule and a reason;
  - a doc comment on public API that adds what the signature cannot say (zero value, ownership, secret lifetime, what an error means): one or two sentences, never the name restated;
  - one line `// Why: <reason> (<source>)` for a fact the code cannot express, citing an RFC, vendor doc or issue. An internal reason becomes a name or a type.
- **No** what-comments, section dividers, commented-out code, TODOs or changelogs in code. Open an issue.
- **Secrets stay in Rust.** Swift and TypeScript hold handles, ids and non-secret overviews. Plaintext that must cross is a copy in the smallest scope (Swift `SecretBuffer`, TypeScript `Uint8Array` zeroed with `fill(0)`), dropped on lock, on timeout and when its screen closes. Never in logs, errors, argv, environment, file names or persisted UI state.
- **One error vocabulary across FFI and WASM:** `HaspError` is defined in `rust.md` (Errors). Swift mirrors it case for case (`lowerCamelCase`), TypeScript as `kind` strings (`kebab-case`).
- **Shared names:** vault, item, record, roster, epoch, device, session follow `docs/protocol.md` in every language. Casing follows each language.
- **Tests:** every bug fix lands with a regression test, every autofill fix with a corpus or red-team case, every wire change as protocol.md, then code, then a vector in `testvectors/`. No real sleeps, no network, injected clocks, real in-memory fakes instead of mocks.
- **Gates:** `mise run check-all` runs every gate in the three guides (`check`, `ts-check`, `apple-check`) and `mise run test` runs the tests. CI calls the same tasks. Tool versions are pinned in `mise.toml`.
- **Dependencies:** a new one is justified in the PR and passes `cargo deny` or its language equivalent. Versions are exact, lockfiles are committed and reviewed, installs use the lockfile, and nothing younger than 7 days is accepted.
- **Commits:** atomic, imperative subject, no co-author or assistant trailers.
