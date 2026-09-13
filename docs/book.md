# Chuchotez

This book is the guide to the locked library. Types and methods named here exist
in the crates unless a section says the work is a later slice. rustdoc is the
API reference. The [README](../README.md) is the short entry.

Chuchotez is a communications backend the person shipping the app does not
operate. A **host** is the application that depends on the `chuchotez` crate:
a messenger, a turn-based game, or another mapping onto the same envelopes.
The host keeps a `v1::Engine`, supplies a CSPRNG, and talks to the network. The
library compiles for `wasm32-unknown-unknown` with the Rust standard library.

Crypto is a policy: `Hybrid` for a messenger host, `Classic` when a game asks
for it. v1 pins HMAC-SHA-256 as the expand function, raw Deflate as compress,
and unpadded base64url as the QR alphabet. The host may bind different
implementations through `v1::Suite`. Every v1 engine honors every `Policy`
variant.

## Channels

A **Channel** is a place two parties share, with a direction for who writes and
who reads. Each party may have more access than the minimum for that kind.

### Billboard

A **Billboard** is a Channel A shares with B so that A has at least write and B
has at least read. A writes a **Notice** and B reads it. A Notice stays pinned
until A replaces it. The first Notice is **PublicInvite**, the invite document
B fetches after learning the Tag.

In this crate a Billboard is opaque `{ kind, address }`. `kind` is the host
mapper registry key (`"nostr"` is valid). `address` is UTF-8 the mapper
interprets (relay URL, path, …). Chuchotez does not fetch and does not contain
a closed set of Channel implementations. Mapping libraries live beside this
crate.

A **Tag** is a coordinate on a Billboard. Together, the Billboard and the Tag
name one Notice. v1 derives that Tag from the `InviteSecret` bytes (`InviteTag`
in code).

### Mailbox

A **Mailbox** is a Channel A shares with B so that A has at least read and B
has at least write. B writes **Messages**. A reads them.

A **Tag Key** identifies the Message stream on that Mailbox (`MailboxTagKey` in
code). v1 derives the Tag Key from the same `InviteSecret` bytes as the
Billboard Tag, with a different expand info string, so the Tag and the Tag Key
are distinct values.

A **Message bin** is one slot in that stream. v1 names a bin by the Tag Key
keyed by binned time (one-hour bins). The Tag Key is stable for the stream;
the bin coordinate changes when the clock crosses a bin boundary. Expanding a
bin coordinate from the Tag Key is a later slice.

## Invite secret

`InviteSecret` is the QR capability the host carries to the peer: secret bytes
plus at least one Billboard. v1 secret bytes are `v1::SECRET_LEN`
cryptographically random bytes (32, the HMAC-SHA-256 output size). Those bytes
are the input keying material for one-block HKDF-Expand (RFC 5869 `T(1)`):
HMAC-SHA-256 of the secret as key, over `info` plus the counter `0x01`. Tag and
Tag Key expand from the bytes alone; the Billboard list is how the invitee
finds the Notice.

Two infos are locked:

| Role | Info | Type |
| --- | --- | --- |
| Billboard Tag for PublicInvite | `chuchotez/1/invite-tag` | `InviteTag` |
| Mailbox Tag Key for the Message stream | `chuchotez/1/mailbox-tag-key` | `MailboxTagKey` |

The host string is unpadded base64url of envelope version (`0xC1`), invite kind
(`INVITE_KIND_DM = 0x01` for a DM invite), and raw Deflate (RFC 1951) of the
canonical payload (inner version, secret bytes, Billboard count and strings).
Always compress. Named caps (`MAX_UNCOMPRESSED`, `MAX_COMPRESSED`,
`MAX_B64U_LEN`) fail closed on oversize input. Unknown envelope version or kind
fails closed.

Layout version is the module (`v1` today, a sibling `v2` later). Each layout
has its own `Engine` contract. A `v1::InviteSecret` is bound to the
`v1::Engine` that created or parsed it.

## Engine, Suite, and Rng

A **Suite** is the bundle of injected primitives for one protocol version. v1
holds HMAC-SHA-256, raw Deflate (`Compress`), and unpadded base64url
(`Base64Url`). AEAD and signatures join a later version’s suite.

An **Engine** is the host-owned handle for one layout, bound to one Suite and
one `Policy`. v1 accessors are capabilities: `hmac`, `compress`, `b64u`. How
those map onto a Tag or a QR blob lives on the bound `InviteSecret`. The host
constructs the engine once per process or test with `v1::std_engine(Policy)`.
Chuchotez stores no suite of its own. There is no process-wide default.

**Rng** is a host port. Every call that needs entropy takes `&impl Rng`. This
workspace never implements `Rng`. Tests inject a seed. `Random32` is
`RANDOM32_LEN` (32) branded CSPRNG bytes. `engine.try_new_invite_secret`
assigns that output the invite-secret role and requires a nonempty Billboard
list.

`v1::std_suite()` / `v1::std_engine(Policy)` ship HMAC-SHA-256 over RustCrypto
`hmac` and `sha2`, raw Deflate over `flate2` (`miniz_oxide`,
`Compression::best()`), and unpadded base64url over
`base64ct::Base64UrlUnpadded`. A host may build `v1::Suite::new` with its own
adapters and `v1::Engine::new(suite, policy)`.

## Call the library

The facade crate is `chuchotez`. This example matches the crate doctest. Fill
`Random32` from a CSPRNG in a real host.

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

`secret.billboard_tag` is HKDF-Expand with `chuchotez/1/invite-tag`.
`secret.mailbox_tag_key` is HKDF-Expand with `chuchotez/1/mailbox-tag-key`.
`secret.serialize` / `engine.try_parse_invite_secret` are the compact DM
envelope. Debug formatting of secrets, tags, and keys omits the raw bytes.

The host shows `blob` as a QR or link. The invitee parses it, derives the Tag,
and for each Billboard in list order looks up a mapper by `kind` and fetches
at `address`. Unknown `kind` skips to the next entry. Chuchotez does not ship
a registry.

## Workspace

Three crates:

| Crate | Role |
| --- | --- |
| `chuchotez` | Package hosts depend on. Re-exports the domain. `v1::std_engine`. |
| `chuchotez-domain` | Types, ports, protocol, `v1::Suite` / `v1::Engine`. Zero crates.io dependencies. |
| `chuchotez-adapters` | Shipped pure adapters: HMAC-SHA-256, raw Deflate, unpadded base64url. |

Importing `chuchotez` starts no threads, timers, or network. Side effects stay
in the host. `wasm32-unknown-unknown` is a first-class target: a change that
compiles only on the desktop host is unfinished.

MSRV is 1.98, edition 2024. Default test command: `cargo test --workspace
--locked`. Line coverage on measured crates is 100%. `scripts/layering.py`
forbids third-party crates and host IO (`std::fs`, `std::net`, threads,
`SystemTime`, `Instant`) in `chuchotez-domain`.

## Later slices

These names are locked.

- Pinning and fetching a Notice at a Billboard Tag (PublicInvite first), with
  a MAC or AEAD keyed from `InviteSecret` so the Billboard cannot substitute
  an intake public key.
- An explicit Mailbox list on PublicInvite (`{ kind, address }`, branded
  `Mailbox`).
- Expanding a Message-bin coordinate from a Tag Key and a time bin, then
  reading and writing that bin on a Mailbox.
- Pairwise streams, a group mesh, and a live ladder of faster hops first.
- Group and Sync invite kinds (a Sync invite uses the compact envelope with a
  different kind byte).

Chat and turn-based games remain host mappings onto these Channels.
