# Chuchotez

Chuchotez is a communications library the app author does not operate. A host
(chat, a turn-based game, or another mapping) depends on this crate, keeps a
`v1::Engine`, and supplies cryptographic randomness. The library compiles for
`wasm32-unknown-unknown` with the Rust standard library.

Two Channel kinds are locked:

- A **Billboard** is a Channel A shares with B so A has at least write and B
  has at least read. Notices (the first is PublicInvite) pin at a **Tag**, which
  is a coordinate on that Billboard.
- A **Mailbox** is a Channel A shares with B so A has at least read and B has
  at least write. A Message stream is identified by a **Tag Key**. Message bins
  are that Tag Key keyed by binned time.

`InviteSecret` is the QR capability: secret bytes plus an explicit Billboard
list (`kind` + `address`). v1 derives the Billboard Tag and the Mailbox Tag Key
from those bytes. Pairwise streams, a group mesh, and a live ladder use the same
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

Construct a `v1::Engine` with `v1::std_engine(Policy)` (HMAC-SHA-256, raw
Deflate, unpadded base64url). Pass `&impl Rng` whenever the protocol needs
entropy. The secret is bound to that engine: `secret.billboard_tag()`.

```rust
use chuchotez::v1;
use chuchotez::{RANDOM32_LEN, Random32, Rng};

struct HostRng;

impl Rng for HostRng {
    fn random32(&self) -> Random32 {
        Random32::from_bytes([1; RANDOM32_LEN])
    }
}

let engine: v1::Engine = v1::std_engine(v1::Policy::Hybrid);
let board = engine.new_billboard(
    engine.try_new_billboard_kind("nostr").expect("kind"),
    engine
        .try_new_billboard_address("wss://relay.example")
        .expect("addr"),
);
let secret = engine
    .try_new_invite_secret(&HostRng, &[board])
    .expect("secret");
let tag = secret.billboard_tag();
let tag_key = secret.mailbox_tag_key();
let blob = secret.serialize();
let _ = (tag, tag_key, blob);
```

`tag` is the Billboard Tag for the PublicInvite Notice. `tag_key` is the
Mailbox Tag Key for the Message stream. `blob` is the compact DM invite
(`b64u(version || kind || raw_deflate(payload))` with `kind = 0x01`). The host
CSPRNG must fill `Random32` with fresh bytes; the array of ones above is only a
compile-checked sketch. The same sketch is the crate doctest.

A host looks up a mapper by Billboard `kind` and passes `address` plus the Tag.
Mapping libraries (Nostr, …) live beside `chuchotez`; this crate does not fetch.

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
| `crates/chuchotez` | Facade hosts depend on (`v1::std_engine`, re-exports) |
| `crates/chuchotez-domain` | Protocol, ports, `v1::Suite` / `v1::Engine` |
| `crates/chuchotez-adapters` | Shipped pure adapters (HMAC-SHA-256, raw Deflate, unpadded base64url) |

`scripts/layering.py` is the CI gate that keeps the domain free of third-party
crates and of host IO.

## Security

See [SECURITY.md](SECURITY.md).

## License

MIT. Copyright (c) 2026 Jonas Hagmar.
