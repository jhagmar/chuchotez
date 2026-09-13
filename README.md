# Chuchotez

Chuchotez is a communications library the app author does not operate. A host
(chat, a turn-based game, or another mapping) depends on this crate, keeps an
`Engine`, and supplies cryptographic randomness. The library compiles for
`wasm32-unknown-unknown` with the Rust standard library.

Two Channel kinds are locked:

- A **Billboard** is a Channel A shares with B so A has at least write and B
  has at least read. Notices (the first is PublicInvite) pin at a **Tag**, which
  is a coordinate on that Billboard.
- A **Mailbox** is a Channel A shares with B so A has at least read and B has
  at least write. A Message stream is identified by a **Tag Key**. Message bins
  are that Tag Key keyed by binned time.

v1 currently derives the Billboard Tag and the Mailbox Tag Key from an
`InviteSecret`. Pairwise streams, a group mesh, and a live ladder use the same
envelopes in later slices.

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

Construct an `Engine` with `std_engine()` (HMAC-SHA-256) or `Engine::new(suite)`.
Pass `&impl Rng` whenever the protocol needs entropy.

```rust
use chuchotez::{InviteSecret, RANDOM32_LEN, Random32, Rng, std_engine};

struct HostRng;

impl Rng for HostRng {
    fn random32(&self) -> Random32 {
        Random32::from_bytes([1; RANDOM32_LEN])
    }
}

let engine = std_engine();
let secret = InviteSecret::v1_from_rng(&HostRng);
let tag = engine.tag(&secret);
let tag_key = engine.mailbox_tag_key(&secret);
let _ = (tag, tag_key);
```

`tag` is the Billboard Tag for the PublicInvite Notice. `tag_key` is the
Mailbox Tag Key for the Message stream. The host CSPRNG must fill `Random32`
with fresh bytes; the array of ones above is only a compile-checked sketch.
The same sketch is the crate doctest.

## Workspace

Rust 1.98, including the `wasm32-unknown-unknown` target. From a clone:

```bash
cargo test --workspace --locked
git config core.hooksPath .githooks
```

`cargo test --workspace --locked` is the default test command. The hook runs
`cargo fmt --all`. Line coverage on measured crates is 100%.
`crates/chuchotez-domain` has no crates.io dependencies.

| Crate | Role |
| --- | --- |
| `crates/chuchotez` | Facade hosts depend on (`std_engine`, re-exports) |
| `crates/chuchotez-domain` | Protocol, ports, `Suite`, `Engine` |
| `crates/chuchotez-adapters` | Shipped pure adapters (HMAC-SHA-256) |

`scripts/layering.py` is the CI gate that keeps the domain free of third-party
crates and of host IO.

## Security

See [SECURITY.md](SECURITY.md).

## License

MIT. Copyright (c) 2026 Jonas Hagmar.
