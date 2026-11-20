# Agent rules

Read before changing code: `docs/style/` (README.md and the guide for your language), `docs/protocol.md` (authoritative wire and crypto spec).

Maintainers keep design notes outside the repository.

- A wire-format change starts in `docs/protocol.md`, then code, then a vector in `testvectors/`.
- Primitive crates are imported only by `hasp-crypto`. CBOR is parsed and produced only by `hasp-proto`. `deny.toml` enforces both.
- `hasp-server` never depends on `hasp-core`.
- Binding crates (`hasp-uniffi`, `hasp-wasm`) contain no logic.
- Secrets stay in Rust and are never logged.
- Every fix lands with a regression test or a corpus case.
- No comments except those the style guide allows.
- Gates: `mise run check-all` (Rust `check`, `ts-check`, `apple-check`) and `mise run test`. Do not commit generated code by hand.
