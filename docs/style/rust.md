# Rust style

Rules for all Rust in the vault workspace (`hasp-crypto`, `hasp-proto`, `hasp-core`, `hasp-uniffi`, `hasp-wasm`, `hasp-nmh`, `hasp-adversary`, `hasp-server`, `hasp-cli`). Shared rules (comments, secrets, tests, dependencies, commits) are in [README.md](README.md).

## Principles

- Code explains itself. Use names, types and structure, not comments.
- Make invalid states unrepresentable. A value that exists is valid.
- A secret is a type, not a convention. The compiler stops the leak, not the reviewer.
- A library path reachable from FFI never panics. It returns an error.

## Comments

| Allowed | Example |
|---|---|
| `SAFETY` justification on every `unsafe` block (clippy requires it) | `// SAFETY: ptr came from Box::into_raw above and is freed once.` |
| Lint suppression with a reason, through the attribute | `#[expect(clippy::print_stdout, reason = "CLI output")]` |
| Doc comment on public API, with one runnable doctest on `hasp-crypto` and `hasp-proto` entry points | `/// Rejects a record whose re-encoding differs from its input bytes.` |
| Why-comment | `// Why: map keys sort by encoded bytes, not by text (RFC 8949 4.2.1).` |

- **Suppress lints only with `#[expect(..., reason = "...")]`.** `#[allow]` is denied by `clippy::allow_attributes`. An expectation that stops firing becomes a warning, so stale suppressions cannot accumulate.
- **Docs:** write one for zero-value meaning, ownership, what an error means, or a constant-time guarantee. A crate has no `//!` comment, internal code has no doc comments, and `missing_docs`, `missing_errors_doc` and `missing_panics_doc` are off.

## Formatting and tooling

- `rustfmt` on stable with `rustfmt.toml` from the appendix. Width 100.
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` passes with zero issues. Lint levels live in `[workspace.lints]`, not in scattered attributes.
- The toolchain is pinned in `rust-toolchain.toml` and `rust-version` equals the pin. Nightly runs Miri, `cargo-careful` and fuzzing only, never required checks.
- Import order by hand, because grouping options are nightly-only: `std`, third-party, then `vault_*` and `crate`. Prefer `use crate::x` to `super::`, except `use super::*` in a test module. No other glob imports.
- Edition 2024.

## Naming

- **Acronyms are words:** `Hkdf`, `Cbor`, `Aead`, `Opaque`. Other casing is RFC 430.
- **No stutter.** `record::Id`, not `record::RecordId`. Error enums are `CryptoError`, `ProtoError`, `CoreError`, `ServerError`, not `Error`, because `hasp-core` imports several.
- **Accessors have no `get_` prefix.** A field with an invariant is private with a borrowing getter, a field without one is `pub`.
- **Reading a secret is `expose`**, never `get`, `as_bytes` or `inner`. Every call site shows up in a grep.
- **Tests are behaviour sentences**, no prefix: `rejects_duplicate_map_keys`, `debug_is_redacted`.
- **Crate directories drop the `hasp-` prefix.** Package names keep it.

## Modules and files

- **One module owns one concept.** `hasp-core` modules (`model`, `store`, `sync`, `client`, `platform`, `matcher`, `generator`, `otp`) replace crate boundaries, so their dependency arrows stay one-way.
- **`foo.rs` plus `foo/`, never `mod.rs`** (`clippy::mod_module_files`).
- **Order in a file:** types, constants, constructors, trait impls, methods by receiver, private helpers in call order.
- **Visibility is as narrow as possible.** `unreachable_pub` is denied. No `pub use` re-exports except the crate root's deliberate API.
- **Only `hasp-crypto` and `hasp-proto` depend on primitive crates.** `deny.toml` bans them with `wrappers`. `hasp-server` never depends on `hasp-core`.
- **No `build.rs` and no proc-macro crates of our own** without maintainer approval.
- **No mutable statics, no `lazy_static`, no global state.** `OnceLock` only for process-wide immutable config built once at startup.

## Types and values

- **Newtypes for every identifier and every secret** (C-NEWTYPE): `AccountId([u8; 16])`, never a bare `[u8; 16]` or `Vec<u8>` in a signature.
- **Enums are exhaustive.** `wildcard_enum_match_arm` is denied in `crypto` and `proto`: a new variant must break every match. No `#[non_exhaustive]` inside the workspace, because we want that break.
- **Parse, do not validate.** A decoder returns a typed value that cannot be invalid. `Uint53(u64)` holds the CBOR integer range 0 to 2^53-1; its constructor checks and nothing else constructs it.
- **Replace `bool` and `Option` parameters with an enum or a split function.** Preconditions go in parameter types: take a `VaultKey`, not `Option<VaultKey>`.
- **Derive `Debug` on every type** (`missing_debug_implementations` is denied). A type that holds a secret gets a hand-written redacting `Debug`.
- **No `Default` on types with required fields or secrets.** Many optional inputs are a plain request struct with public fields and no `Default`. Builders only where construction has invariants.
- **Take `&[u8]`, `&str`, `&Path`; return owned values.** Copy at an FFI boundary, never lend across it.
- **Time is `std::time::Duration` and an injected clock trait** in `hasp-core`. Library code never calls `SystemTime::now`. Protocol timestamps are informational and never gate a decision.
- **No floats** in `crypto` and `proto` (`float_arithmetic` is denied). CBOR forbids them.
- **Collections that are encoded, hashed or compared use `BTreeMap` and `BTreeSet`.** `clippy.toml` disallows `HashMap` and `HashSet`.

## Secret types

Applies to every key, password, Secret Key, recovery code, token, plaintext item and derived value.

```rust
pub struct VaultKey(SecretBox<[u8; KEY_LEN]>);

impl fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultKey(..)")
    }
}

impl ConstantTimeEq for VaultKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.expose_secret().as_slice().ct_eq(other.0.expose_secret().as_slice())
    }
}
```

- **Wrap the bytes in `secrecy::SecretBox<T>`** (heap-allocated, zeroized on drop, `Debug` redacted). Use `SecretString` and `SecretSlice<u8>` for variable length. The heap box avoids the stack copies that moving a plain array makes, which `zeroize` documents as a limit.
- **Zeroize on drop is mandatory.** A struct that owns a secret field derives `Zeroize` and `ZeroizeOnDrop`, or holds `SecretBox`. Transient buffers are `Zeroizing<Vec<u8>>`.
- **No `Clone`, `Copy`, `Display`, `PartialEq`, `Eq`, `Hash` or `Ord`.** Adding `Clone` needs maintainer approval. `Copy` types are not zeroized on drop.
- **No `Serialize`, no `serde` derive.** Only a sealed value (ciphertext `Sealed`) serializes. `Deserialize` into a secret goes through a function that zeroizes the input buffer.
- **Compare with `subtle` only:** implement `ConstantTimeEq`, call `bool::from(a.ct_eq(&b))` at the last moment. `==` on secret-derived bytes, MACs or tags is a review block.
- **Do not branch, index or early-return on a secret.** Use `Choice`, `CtOption` and `ConditionallySelectable`. Constant-time is best effort in `subtle`, so primitives come from audited crates and `hasp-crypto` adds no bespoke arithmetic.
- **Expose in the smallest scope.** `expose_secret()` is an argument or a temporary, never a long-lived `let`. Never `.to_vec()`, `.clone()` or `format!` an exposed secret.
- **Grow buffers once.** `Vec::with_capacity(n)` for secret data, because reallocation leaves copies that `zeroize` cannot reach.
- **No secrets in logs, errors, panic messages, `argv`, environment variables or file names.** `mem::forget` is denied (it skips `Drop`). A cancelled future is dropped, which zeroizes its secrets.

## Functions and APIs

- **Return `Result<T, CrateError>`.** No `Box<dyn Error>` or `anyhow::Error` from a library. More than five parameters fails clippy.
- **No `unwrap`, `expect`, `panic!`, `unreachable!`, `todo!`, `unimplemented!`** in non-test code of any crate (denied workspace-wide). Index with `get`, `split_first_chunk` and `chunks_exact`, and convert with `try_into`. A true invariant is encoded in a type or returned as `Internal(&'static str)`.
- **`#[must_use]` on any type whose ignoring is a bug** (a verification result, a `Choice`). `let_underscore_must_use` is denied.
- **No dynamic dispatch on crypto paths.** Use `dyn` only for platform callbacks (`SecureStore`, `Biometric`).
- **Traits are defined by the consumer, small, and sealed when downstream impls would break an invariant** (C-SEALED). No trait made only for mocking.
- **Public API follows the Rust API Guidelines** for naming, interoperability and future proofing, except C-COMMON-TRAITS for secrets.

## Integer arithmetic

- **In `crypto` and `proto`, plain `+ - * / %` and `<<` on integers are denied** (`arithmetic_side_effects`), and so is `as` (`as_conversions`). Write the intent: `checked_add`, `saturating_sub`, `wrapping_*` (only for hash and cipher internals), `u32::from`, `usize::try_from`.
- **Everywhere else the pedantic cast lints are denied.** Prefer `From` and `TryFrom`.
- **`overflow-checks = true` in release.** A missed overflow aborts the call. It does not wrap silently.
- **Lengths from the wire are untrusted.** Check against the protocol limits (nesting 8, array 65536, text 4096 bytes, record 16 MiB) before allocating.
- **A lint that fires is fixed in the code.** `#[expect(clippy::arithmetic_side_effects, reason = ...)]` needs a reason a reviewer can verify, such as a loop bound proven by the type.

## Errors

- **One root `thiserror` enum per crate** (`CryptoError`, `ProtoError`, `CoreError`, `ServerError`). A module with a standalone public API (generator, otp, matcher, import, export) may keep its own small enum, which the root wraps with `#[from]`; no other module defines one. Causes use `#[from]` or `#[source]`. Variants name the failure, carry typed data, and never carry a secret.
- **Display strings are lowercase, have no trailing period and no "failed to".** Context is added by the layer that has it.
- **`anyhow` only in binaries** (`hasp-server`, `hasp-cli`, `hasp-nmh`) at the outermost layer. A library never exposes it, so callers can match.
- **Crypto failures do not distinguish the cause when the cause is an oracle.** One `Aead` variant for tag, padding and key mismatch.
- **The boundary vocabulary is one flat `HaspError`,** defined identically in `hasp-uniffi` and `hasp-wasm` and mapped from `CoreError` with an explicit `From`. Its variants are the protocol.md error codes without the `E_` prefix (`Format`, `Version`, `Sig`, `Aead`, `Pin`, `Rollback`, `Fork`, `Roster`, `KdfParams`, `Epoch`, `Root`, `Auth`, `ServerKey`, `Authz`, `Invite`) plus `Locked`, `Cancelled`, `Internal` and the client states the apps branch on: `Offline`, `NotFound`, `Refused`, `Pending`, `ReadOnly`, `RateLimited`, `Conflict`, `Quarantined`, `Unconfirmed`, `DeviceRevoked`. Variants carry at most ids and counts, never a secret, and foreign code never sees a Rust `Debug` string. Swift and TypeScript mirror the names (README).
- **Handle each error once.** A function either returns the error or logs it, never both. Never discard with `let _ =`; ignore an error only with a reason and a named binding.

## Panics, unsafe and FFI

- **No panic reaches a boundary.** Panic freedom in `core`, `crypto` and `proto` is enforced by lints, and `hasp-uniffi` and `hasp-wasm` return `Result` from every exported function.
- **Keep `panic = "unwind"` (the default).** UniFFI turns a caught panic into a foreign exception only with unwinding `[U: third-party source]`, and `panic = "abort"` would kill the host app. Never `catch_unwind` to continue after a panic in library code (Microsoft M-PANIC-CONTINUATION).
- **`unsafe_code = "forbid"` in every crate except `hasp-uniffi` and `hasp-wasm`.** Those two declare their own `[lints]` tables with `deny`, and every `unsafe` is a `#[expect(unsafe_code, reason = "...")]` on the smallest item with a `// SAFETY:` comment. Generated scaffolding may need a module-level expectation `[U: not compiled against UniFFI here]`.
- **Binding crates contain no logic.** They convert types, call `Client`, and map errors. They are the only crates that name `uniffi` or `wasm-bindgen`.
- **`hasp-wasm` returns `Result<T, HaspError>`,** which wasm-bindgen turns into a thrown JS exception `[V]`. Secrets cross as `Uint8Array` copies that the TypeScript side zeroes.
- **Miri and `cargo-careful` run nightly on the binding crates and anything with `unsafe`.** Miri cannot run FFI, so it covers the Rust side only.

## Concurrency and async

- **Cancellation is explicit.** UniFFI has no cancellation. Every long call takes or owns a `tokio_util::sync::CancellationToken` and checks it at each await. `Client::cancel()` cancels the token. A cancelled call returns `Cancelled`, not a partial success.
- **Race with `token.run_until_cancelled(fut)` or `select!` on `token.cancelled()`.** Futures raced in `select!` must be cancel safe, checked in review.
- **Libraries are runtime-agnostic.** `crypto` and `proto` are synchronous with no `tokio`. `core` runs on a runtime supplied by the host or by the binding crate. Do not call `tokio::runtime::Runtime::new` below a binding crate.
- **Every spawned task has an owner and a stop path:** a `JoinSet` or `TaskTracker`, plus a child token. No detached `tokio::spawn`.
- **Blocking work leaves the executor.** Argon2id and large hashing use `spawn_blocking` (server) or a dedicated thread.
- **Never hold a lock across `.await`.** A `std::sync::Mutex` guards short critical sections only.
- **Channels are bounded** (`mpsc::channel(n)`), and a full channel is handled. Tests with time use `tokio::time::pause`.

## Server (axum and sqlx)

- **Handlers are thin:** extract, call a function in a plain module, map the result. State is a small `Clone` struct of `Arc`s and pool handles behind `State<AppState>`; the body extractor is last.
- **`ServerError` implements `IntoResponse`** with a stable body and status. It never prints a cause chain, a SQL string or any wire bytes to the client.
- **Layers set body-size, request timeout and concurrency limits** with `tower` and `tower-http`. No default is left implicit.
- **sqlx uses the `query!` and `query_as!` macros only,** with `.sqlx` committed and CI running `cargo sqlx prepare --check`. SQLite nullability inference is fragile, so every column that can be NULL through a join is annotated (`"col?"`), and bind-parameter nullability is not checked at compile time, so tests insert NULL.
- **Migrations are forward-only files** run by `sqlx::migrate!` at startup.
- **The server stores ciphertext, verifiers and public keys only.**

## Logging

- **`hasp-crypto`, `hasp-proto`, `hasp-uniffi` and `hasp-wasm` do not log.** `hasp-core`, the server and the CLI use `tracing`.
- **`#[instrument]` always has `skip_all`** and an explicit `fields(...)` allowlist of ids and counts.
- **Never log a request body or a `Debug` of a struct holding a secret.** `print_stdout` and `print_stderr` are denied. The CLI's output module carries the one `#[expect]`.

## Serialization

- **Deterministic CBOR is produced and parsed only in `hasp-proto`.** No other crate imports a CBOR crate, which `deny.toml` bans with `wrappers = ["hasp-proto"]` (add the entry when the codec crate is chosen; `minicbor` is the candidate in protocol.md 2.2).
- **Wire types use the codec's derive,** not `serde`. `serde` is for local configuration and JSON test vectors only.
- **Decode, re-encode, compare bytes, reject any difference** (protocol.md 3.1). The decoder is fuzzed with `bolero`, and CI diffs it against Python `cbor2`.
- **Hash and sign only bytes that came from the encoder.** Never hash a re-serialization of a parsed value.

## Features and dependencies

- **Features are additive and never weaken security.** A feature may add an optional binding or a test hook, never remove a check or change an algorithm. `cfg(debug_assertions)` never changes security behaviour.
- **`default-features = false` on workspace dependencies,** enabled per crate. A `testing` feature exposes test hooks, is never enabled by a non-dev dependency, and is absent from release builds.
- **Dependencies are declared once in `[workspace.dependencies]`** and inherited. Order of preference: standard library, RustCrypto and `dalek` crates in `hasp-crypto`, then others. Builds use `--locked` and `registry.global-min-publish-age = 7 days`.
- **`cargo-deny` runs advisories, bans, licenses and sources.** Advisory ignores carry an expiry date in the PR.

## Testing

- **`cargo nextest run` plus `cargo test --doc`.** Unit tests live in `#[cfg(test)] mod tests` in the same file. Black-box tests of public API live in `tests/`.
- **Tests may `unwrap`, `expect` and index** via the `clippy.toml` allowances. They may not use `#[should_panic]`: assert the `Err`. `#[ignore]` needs an issue.
- **`proptest` for model and parser properties.** Commit `proptest-regressions/`. Use `bolero::check!` targets for the strict CBOR decoder and the record verifier, bounded per PR and long nightly `[U: harness not built]`.
- **Known-answer vectors from `testvectors/`** cover every primitive wrapper and every record type.
- **`cargo-mutants` on PR diffs and nightly on `crypto` and `proto`.** A removed check that no test fails on is a missing test.
- **Test the secret rules:** `Debug` output is redacted, a secret has no `Clone` (a `trybuild` compile-fail test `[U: not run]`), and a wrong tag returns `Aead`.

## CI gates

`mise run check` runs these, and CI calls the same task.

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo nextest run --workspace --locked
cargo test --doc --workspace --locked
cargo deny check
cargo sqlx prepare --workspace --check   # [U: not run here]
cargo mutants --in-diff pr.diff --package hasp-crypto --package hasp-proto
```

Nightly (non-blocking except fuzz crashes): Miri, `cargo-careful`, long `bolero`, dudect-style timing checks.

## Sources

- Rust API Guidelines: rust-lang.github.io/api-guidelines/checklist.html. Rust Style Guide and rustfmt: doc.rust-lang.org/style-guide, rust-lang.github.io/rustfmt
- Clippy lints and configuration: doc.rust-lang.org/clippy (lint names also run locally). Cargo `[workspace.lints]`: doc.rust-lang.org/cargo/reference/workspaces.html
- Microsoft Pragmatic Rust Guidelines (M-LINT-OVERRIDE-EXPECT, M-PANIC-IS-STOP, M-PANIC-CONTINUATION): microsoft.github.io/rust-guidelines. rust-analyzer style guide
- docs.rs: `zeroize`, `secrecy`, `subtle`, `thiserror`, `tokio-util`, `sqlx` (`query!`, offline mode). cargo-deny book. wasm-bindgen reference (`Result` returns). UniFFI manual (futures: no cancellation)

## Where this file departs from the sources, and why

| Topic | Sources say | This file | Reason |
|---|---|---|---|
| Doc comments | API Guidelines C-EXAMPLE, C-FAILURE: document everything with examples | Docs only where the signature leaves something out | No-comment rule. Failure modes live in typed errors, and there are no panics to document |
| Panics | Microsoft M-PANIC-IS-STOP, rust-analyzer "assert liberally": panic on a bug | No panic in non-test code. Bugs become `Internal` | A panic reachable from FFI crashes the host app or stops the WASM module with secrets live |
| `anyhow` | rust-analyzer uses it throughout | `thiserror` in libraries, `anyhow` in binaries | Callers and FFI mappers must match on error kinds |
| Lint suppression | Clippy docs allow `#[allow]` | `#[expect]` with a reason | M-LINT-OVERRIDE-EXPECT. Stale suppressions surface |
| Line width | rust-analyzer: `use_small_heuristics = "Max"` | rustfmt default, width 100 | One tool-enforced style, no nightly |
| `non_exhaustive` | API Guidelines future proofing | Not used | Internal crates want matches to break on new variants |
| `PartialEq` on secrets | C-COMMON-TRAITS: implement eagerly | `ConstantTimeEq` only | `==` on secrets is a timing leak. Absence forces `subtle` |
| `unsafe_code` per crate | Inherited lints cannot be overridden | Binding crates carry their own `[lints]` table with `deny` | Cargo rejects `workspace = true` mixed with overrides `[V]` |

## Appendix: validation record

Validated 2026-11-18 in `run/style-scratch/rust/` (two crates: `hasp-crypto` with the strict extras and `hasp-uniffi` with its own `[lints]` table; real `secrecy`, `zeroize`, `subtle`, `thiserror`, `sha2`, `tokio-util` dependencies). Results: `cargo fmt --check` clean, `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean, `cargo nextest` 2 passed, `cargo test --doc` ran, `cargo build --release` ok, `cargo deny check` all four ok. Negative tests: `unwrap`, indexing, `x + 1`, `dbg!`, `#[allow]`, `HashMap` and `mem::forget` each failed the build as intended, and a `sha2` dependency from `hasp-uniffi` failed the `wrappers` ban. Mixing `[lints] workspace = true` with `[lints.clippy]` is a Cargo error.

Not validated: `sqlx`, `cargo-mutants`, `bolero`, `proptest`, UniFFI and wasm-bindgen compilation, Miri.

| Tool | Version |
|---|---|
| rustc / cargo | 1.98.0 (2026-08-18) |
| clippy | 0.1.98 |
| rustfmt | 1.9.0-stable |
| cargo-deny | 0.20.2 |
| cargo-nextest | 0.9.143 |
| secrecy / zeroize / subtle | 0.10.3 / 1.9.2 / 2.6.1 |
| thiserror / tokio-util / sha2 | 2.0.21 / 0.7.20 / 0.10.9 |

### `rust-toolchain.toml`

```toml
[toolchain]
channel = "1.98.0"
components = ["clippy", "rustfmt"]
profile = "minimal"
```

### Workspace `Cargo.toml` lints and profile

Crates opt in with `[lints] workspace = true`. Edition, `rust-version`, license and dependencies are inherited the usual way.

```toml
[workspace.lints.rust]
unsafe_code = "forbid"
missing_debug_implementations = "deny"
unreachable_pub = "deny"
unused_qualifications = "deny"
rust_2018_idioms = { level = "deny", priority = -1 }

[workspace.lints.clippy]
all = { level = "deny", priority = -1 }
pedantic = { level = "deny", priority = -1 }
missing_errors_doc = "allow"
missing_panics_doc = "allow"
must_use_candidate = "allow"
module_name_repetitions = "allow"
allow_attributes = "deny"
allow_attributes_without_reason = "deny"
dbg_macro = "deny"
exit = "deny"
expect_used = "deny"
let_underscore_must_use = "deny"
mem_forget = "deny"
mod_module_files = "deny"
multiple_unsafe_ops_per_block = "deny"
panic = "deny"
panic_in_result_fn = "deny"
print_stderr = "deny"
print_stdout = "deny"
todo = "deny"
undocumented_unsafe_blocks = "deny"
unimplemented = "deny"
unreachable = "deny"
unwrap_in_result = "deny"
unwrap_used = "deny"

[profile.release]
codegen-units = 1
lto = "fat"
overflow-checks = true
debug-assertions = false
strip = "symbols"
```

### Per-crate overrides

Cargo cannot extend an inherited table, so overrides are of three kinds.

- **`hasp-crypto` and `hasp-proto`** add the strict extras at the crate root. Tests are exempt for lints with a `clippy.toml` key. `arithmetic_side_effects` has none, so test code uses checked helpers or `#[expect]`.

```rust
#![deny(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::float_arithmetic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::wildcard_enum_match_arm
)]
```

- **`hasp-uniffi` and `hasp-wasm`** do not inherit. Copy the `[workspace.lints.*]` tables into `[lints.*]` and change one line: `unsafe_code = "deny"`. Each `unsafe` then carries `#[expect(unsafe_code, reason = "...")]`.
- **Binaries** (`hasp-server`, `hasp-cli`, `hasp-nmh`) inherit and use `#[expect(clippy::print_stdout, reason = "...")]` or `expect_used` in `main` only.

### `rustfmt.toml`

```toml
edition = "2024"
style_edition = "2024"
newline_style = "Unix"
use_field_init_shorthand = true
use_try_shorthand = true
```

### `clippy.toml`

```toml
msrv = "1.98"
allow-unwrap-in-tests = true
allow-expect-in-tests = true
allow-panic-in-tests = true
allow-indexing-slicing-in-tests = true
allow-dbg-in-tests = true
allow-print-in-tests = true
too-many-arguments-threshold = 5
doc-valid-idents = ["..", "UniFFI", "XChaCha20", "XChaCha20Poly1305", "Argon2id", "WebAssembly"]
disallowed-methods = [
    { path = "std::mem::forget", reason = "skips Drop, so secrets are never zeroized" },
    { path = "std::thread::sleep", reason = "blocks the executor; use tokio::time or an injected clock" },
]
disallowed-types = [
    { path = "std::collections::HashMap", reason = "iteration order is random; use BTreeMap for anything encoded or hashed" },
    { path = "std::collections::HashSet", reason = "iteration order is random; use BTreeSet for anything encoded or hashed" },
]
```

### `deny.toml`

```toml
[graph]
all-features = true

[advisories]
unmaintained = "workspace"
yanked = "deny"
ignore = []

[licenses]
confidence-threshold = 0.9
allow = [
    "Apache-2.0",
    "MIT",
    "BSD-3-Clause",
    "ISC",
    "Unicode-3.0",
    "Zlib",
]

[bans]
multiple-versions = "deny"
wildcards = "deny"
allow-wildcard-paths = true
highlight = "all"
skip = [
    { crate = "syn@2", reason = "zeroize_derive still on syn 2; drop when it moves" },
]
deny = [
    { crate = "sha2", wrappers = ["hasp-crypto"], reason = "primitives are imported only by hasp-crypto" },
    { crate = "openssl", reason = "no C TLS stack" },
    { crate = "native-tls", reason = "rustls only" },
]

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
allow-git = []
```

`ISC` and `Zlib` raise a `license-not-encountered` warning in the scratch tree and are kept for the full workspace. Add the primitive crates and `wrappers = ["hasp-proto"]` for the CBOR crate as they are introduced.
