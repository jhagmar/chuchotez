# Chuchotez

Chuchotez is a communications library the app author does not operate. A host
depends on this crate, keeps a `v1::Engine` and `v1::EngineState`, and supplies
cryptographic randomness and a DEK. The library compiles for
`wasm32-unknown-unknown` with the Rust standard library.

The complete guide is [docs/book.md](docs/book.md). API reference is rustdoc.

[![CI](https://github.com/jhagmar/chuchotez/actions/workflows/ci.yml/badge.svg)](https://github.com/jhagmar/chuchotez/actions/workflows/ci.yml)
[![CodeQL](https://github.com/jhagmar/chuchotez/actions/workflows/codeql.yml/badge.svg)](https://github.com/jhagmar/chuchotez/actions/workflows/codeql.yml)
[![codecov](https://codecov.io/gh/jhagmar/chuchotez/graph/badge.svg)](https://codecov.io/gh/jhagmar/chuchotez)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/jhagmar/chuchotez/badge)](https://scorecard.dev/viewer/?uri=github.com/jhagmar/chuchotez)
[![REUSE status](https://api.reuse.software/badge/github.com/jhagmar/chuchotez)](https://api.reuse.software/info/github.com/jhagmar/chuchotez)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)

## Depend

```toml
chuchotez = { git = "https://github.com/jhagmar/chuchotez" }
```

Construct a `v1::Engine` with `v1::std_engine(Policy)`. Pass `&dyn Rng`
whenever the protocol needs entropy. The crate doctest is the sketch:
originate methods return the drawn id; write `PersistOk`, then Engine getters.
Fill `Random32` from a CSPRNG in a real host.

## Workspace

Rust 1.98, including the `wasm32-unknown-unknown` target. From a clone:

```bash
cargo test --workspace --locked
git config core.hooksPath .githooks
```

The hook runs `cargo fmt --all`. Line coverage on measured crates is 100%.
`crates/chuchotez-domain` has no crates.io dependencies.
`scripts/layering.py` is the CI gate that keeps the domain free of third-party
crates and of host IO.

| Crate | Role |
| --- | --- |
| `crates/chuchotez` | Facade hosts depend on (`v1::std_engine`, re-exports) |
| `crates/chuchotez-domain` | Protocol, ports, `v1::Suite` / `v1::Engine` |
| `crates/chuchotez-adapters` | Shipped pure adapters |

## Security

See [SECURITY.md](SECURITY.md).

## License

MIT. Copyright (c) 2026 Jonas Hagmar.
