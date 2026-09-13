# Chuchotez

Chuchotez is a WASM-first communications backend the app author does not operate. Pairwise streams, a group mesh, Hold (billboard and mailbox), and a live ladder are one library. Chat and turn-based games map onto the same envelopes. Crypto is a policy suite.

[![CI](https://github.com/jhagmar/chuchotez/actions/workflows/ci.yml/badge.svg)](https://github.com/jhagmar/chuchotez/actions/workflows/ci.yml)
[![CodeQL](https://github.com/jhagmar/chuchotez/actions/workflows/codeql.yml/badge.svg)](https://github.com/jhagmar/chuchotez/actions/workflows/codeql.yml)
[![codecov](https://codecov.io/gh/jhagmar/chuchotez/graph/badge.svg)](https://codecov.io/gh/jhagmar/chuchotez)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/jhagmar/chuchotez/badge)](https://scorecard.dev/viewer/?uri=github.com/jhagmar/chuchotez)
[![REUSE status](https://api.reuse.software/badge/github.com/jhagmar/chuchotez)](https://api.reuse.software/info/github.com/jhagmar/chuchotez)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)

## Bootstrap

Rust 1.98, including the `wasm32-unknown-unknown` target. From a clone:

```bash
cargo test --workspace --locked
git config core.hooksPath .githooks
```

That is the default test command. `git config core.hooksPath .githooks` enables the pre-commit hook that runs `cargo fmt --all`. Line coverage on measured crates is 100%. `crates/chuchotez-domain` has no crates.io dependencies and compiles for `wasm32-unknown-unknown`. Hosts depend on `crates/chuchotez`, hold an `Engine`, and supply `Rng`.

## Layout

The Cargo workspace is the repository root.

- `crates/chuchotez` — facade hosts depend on (`std_engine`, re-exports)
- `crates/chuchotez-domain` — protocol, ports, `Suite`, `Engine`
- `crates/chuchotez-adapters` — shipped pure adapters (HMAC-SHA-256)
- `scripts/layering.py` — CI gate: domain stays free of third-party crates and host IO

The host holds an `Engine` bound to a suite (`std_engine()` or `Engine::new(suite)`). `Rng` is an argument on every call that needs entropy.

## Security

See [SECURITY.md](SECURITY.md).

## License

MIT. Copyright (c) 2026 Jonas Hagmar.
