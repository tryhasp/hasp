# Hasp

Self-hosted password manager with end-to-end encryption. Specification: [docs/protocol.md](docs/protocol.md). Style: [docs/style/](docs/style/README.md).

## Status

Pre-release (0.1.0). Not yet independently security-reviewed. Do not use it for real secrets yet.

## Layout

- `crates/`: `crypto`, `proto`, `core`, `uniffi`, `wasm`, `replay`, `nmh`, `adversary`, `testsupport` (packages are named `hasp-<dir>`)
- `apps/`: `server` (`haspd`, with its `Dockerfile`), `cli` (`hasp`), `extension`, `apple`
- `packages/`: TypeScript packages over `hasp-wasm`
- `testvectors/`: shared vectors replayed by Rust, WASM and Swift
- `scripts/`: build and gate scripts behind the mise tasks
- `docs/`: protocol and style guides

## Build and test

Install [mise](https://mise.jdx.dev), then:

```sh
mise install
mise run setup
mise run check-all
```

The Apple targets need Xcode and an `APPLE_TEAM_ID` for signed device builds; Simulator builds are unsigned.

Build the server image with `docker build -f apps/server/Dockerfile .` from the repository root.

## License

Apache-2.0 for crates and clients (`LICENSE-APACHE`), AGPL-3.0-only for `apps/server` (`LICENSE-AGPL`). See `NOTICE`.
