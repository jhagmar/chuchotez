# Chuchotez

This book is the guide to the locked library. Types and methods named here exist
in the crates unless a section says the work is a later slice. rustdoc is the
API reference. The [README](../README.md) is the short entry.

Chuchotez is a communications backend the person shipping the app does not
operate. A **host** is the application that depends on the `chuchotez` crate:
a messenger, a turn-based game, or another mapping onto the same envelopes.
The host keeps an `Engine`, supplies a CSPRNG, and talks to the network. The
library compiles for `wasm32-unknown-unknown` with the Rust standard library.

Crypto is a policy suite: `hybrid` for a messenger host, `classical` when a
game asks for it. v1 pins HMAC-SHA-256 as the expand function. The host may
bind a different HMAC implementation through `Suite`.

## Channels

A **Channel** is a place two parties share, with a direction for who writes and
who reads. Each party may have more access than the minimum for that kind.

### Billboard

A **Billboard** is a Channel A shares with B so that A has at least write and B
has at least read. A writes a **Notice** and B reads it. A Notice stays pinned
until A replaces it. The first Notice is **PublicInvite**, the invite document
B fetches after learning the Tag.

A **Tag** is a coordinate on a Billboard. Together, the Billboard and the Tag
name one Notice. v1 derives that Tag from `InviteSecret` (`InviteTag` in code).

### Mailbox

A **Mailbox** is a Channel A shares with B so that A has at least read and B
has at least write. B writes **Messages**. A reads them.

A **Tag Key** identifies the Message stream on that Mailbox (`MailboxTagKey` in
code). v1 derives the Tag Key from the same `InviteSecret` as the Billboard
Tag, with a different expand info string, so the Tag and the Tag Key are
distinct values.

A **Message bin** is one slot in that stream. v1 names a bin by the Tag Key
keyed by binned time (one-hour bins). The Tag Key is stable for the stream;
the bin coordinate changes when the clock crosses a bin boundary. Expanding a
bin coordinate from the Tag Key is a later slice.

## Invite secret

`InviteSecret` is the shared secret the host carries to the peer. v1 is
`v1::SECRET_LEN` cryptographically random bytes (32, the HMAC-SHA-256 output
size). Those bytes are the input keying material for one-block HKDF-Expand
(RFC 5869 `T(1)`): HMAC-SHA-256 of the secret as key, over `info` plus the
counter `0x01`.

Two infos are locked:

| Role | Info | Type |
| --- | --- | --- |
| Billboard Tag for PublicInvite | `chuchotez/1/invite-tag` | `InviteTag` |
| Mailbox Tag Key for the Message stream | `chuchotez/1/mailbox-tag-key` | `MailboxTagKey` |

Version lives on closed enums (`InviteSecret::V1`, `InviteTag::V1`,
`MailboxTagKey::V1`). A later layout is a new variant and a sibling module
`v2`. Call sites `match`.

## Engine, Suite, and Rng

A **Suite** is the bundle of pure cryptographic ports the protocol needs. v1
needs HMAC-SHA-256. AEAD and signatures join the same struct later.

An **Engine** is the host-owned handle bound to one Suite. The host constructs
it once per process or test (`std_engine()` or `Engine::new(suite)`) and passes
it into protocol methods. Chuchotez stores no suite of its own. There is no
process-wide default.

**Rng** is a host port. Every call that needs entropy takes `&impl Rng`. This
workspace never implements `Rng`. Tests inject a seed. `Random32` is
`RANDOM32_LEN` (32) branded CSPRNG bytes. `InviteSecret::v1_from_rng` assigns
that output the invite-secret role.

`std_suite()` / `std_engine()` ship HMAC-SHA-256 over RustCrypto `hmac` and
`sha2`. A host may build `Suite::new(Arc::new(hmac))` with its own
`HmacSha256`.

## Call the library

The facade crate is `chuchotez`. This example matches the crate doctest. Fill
`Random32` from a CSPRNG in a real host.

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

`engine.tag` is HKDF-Expand with `chuchotez/1/invite-tag`.
`engine.mailbox_tag_key` is HKDF-Expand with `chuchotez/1/mailbox-tag-key`.
Debug formatting of secrets, tags, and keys omits the raw bytes.

## Workspace

Three crates:

| Crate | Role |
| --- | --- |
| `chuchotez` | Package hosts depend on. Re-exports the domain. `std_engine`. |
| `chuchotez-domain` | Types, ports, protocol, `Suite`, `Engine`. Zero crates.io dependencies. |
| `chuchotez-adapters` | Shipped pure adapters. First: HMAC-SHA-256. |

Importing `chuchotez` starts no threads, timers, or network. Side effects stay
in the host. `wasm32-unknown-unknown` is a first-class target: a change that
compiles only on the desktop host is unfinished.

MSRV is 1.98, edition 2024. Default test command: `cargo test --workspace
--locked`. Line coverage on measured crates is 100%. `scripts/layering.py`
forbids third-party crates and host IO (`std::fs`, `std::net`, threads,
`SystemTime`, `Instant`) in `chuchotez-domain`.

## Later slices

These names are locked. Their methods join the `Engine` as they ship.

- Pinning and fetching a Notice at a Billboard Tag (PublicInvite first).
- Expanding a Message-bin coordinate from a Tag Key and a time bin, then
  reading and writing that bin on a Mailbox.
- Pairwise streams, a group mesh, and a live ladder of faster hops first.

Chat and turn-based games remain host mappings onto these Channels.
