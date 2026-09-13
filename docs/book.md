# Chuchotez

This book is the guide to the locked library. Types and methods named here exist
in the crates unless a section says the work is a later slice. rustdoc is the
API reference. The [README](../README.md) is depend and bootstrap.

Chuchotez is a communications backend the person shipping the app does not
operate. A **host** is the application that depends on the `chuchotez` crate:
a messenger, a turn-based game, or another mapping onto the same envelopes.
The host keeps a `v1::Engine`, supplies a CSPRNG, and talks to the network. The
library compiles for `wasm32-unknown-unknown` with the Rust standard library.

Crypto is a policy: `Hybrid` for a messenger host, `Classic` when a game asks
for it. v1 pins HMAC-SHA-256 as the expand function, raw Deflate as compress,
unpadded base64url as the QR alphabet, AES-256-GCM as the Notice AEAD, RFC 8785
as canonical JSON, and the Intake KEM in `std_suite`: Classic X25519,
PostQuantum ML-KEM-768, Hybrid X-Wing. The host may bind different
implementations through `v1::Suite`. `try_new_invite` fails closed when the
suite cannot generate the engine’s `Policy`.

## Channels

A **Channel** is a place two parties share, with a direction for who writes and
who reads. Each party may have more access than the minimum for that kind.
Coordinates are opaque `{ kind, address }`. `kind` is the host mapper registry
key (`"nostr"` and `"webrtc"` are valid). `address` is nonempty UTF-8 the mapper
interprets, NFC-or-precomposed, capped at `ADDRESS_MAX_LEN`. Chuchotez does not
fetch. Mapping libraries live beside this crate.

### Billboard

A **Billboard** is a Channel A shares with B so that A has at least write and B
has at least read. A writes a **Notice** and B reads it. A Notice stays pinned
until A replaces it.

A **Tag** is a coordinate on a Billboard (`BillboardTag` in code). Together, the
Billboard and the Tag name one Notice. v1 derives that Tag from the Ticket
secret with info `chuchotez/1/invite-tag`.

### Mailbox

A **Mailbox** is a Channel A shares with B so that A has at least read and B
has at least write. B writes **Messages**. A reads them. Intake requires at
least one Mailbox (`MAILBOX_MAX_COUNT` is 8).

A **Tag Key** identifies the Message stream (`MailboxTagKey`). v1 derives it
from the Ticket secret with info `chuchotez/1/mailbox-tag-key`.

A **Message bin** is one slot in that stream. v1 names a bin by the Tag Key
keyed by binned time (one-hour bins). Expanding a bin coordinate from the Tag
Key is a later slice.

### Wire

A **Wire** is a Channel both sides read and write, with no persistence. The
Notice Wire list MAY be empty (hold-only). `WIRE_MAX_COUNT` is 8. The doctest
uses `"webrtc"` / `"stun:stun.example"`.

## Invite

`Invite` is the mint bundle: **Ticket** plus **Intake**.
`Engine::try_new_invite` draws a `TicketSecret` (`Random32`) and a 64-byte
`KemSeed` (two `Random32`) from `&impl Rng`. `Kem::generate` maps that seed to
an `IntakeKeypair`. Equality compares Ticket and Intake. The Intake secret is
redacted in `Debug`.

### Ticket

**Ticket** is the QR capability: `SECRET_LEN` (32) cryptographically random
bytes plus at least one Billboard (`BILLBOARD_MAX_COUNT` is 8). `serialize`,
`billboard_tag`, and `mailbox_tag_key` take `&Engine`.

```
b64u(version || INVITE_KIND_DM || raw_deflate(secret || billboards))
```

`version` is `ENVELOPE_VERSION` (`0xC1`). `INVITE_KIND_DM` is `0x01`. Always
compress (RFC 1951). Caps `TICKET_MAX_UNCOMPRESSED`, `TICKET_MAX_COMPRESSED`,
`TICKET_MAX_B64U_LEN` fail closed on oversize. Unknown envelope version or kind
fails closed. Layout version is the module (`v1` today).

### Notice

**Notice** is the Billboard body at the Tag. JSON members are `policy`,
`intake_pk` (unpadded base64url), `mailboxes`, `wires`. Each mailbox and wire is
`{ "kind", "address" }`. Unknown or missing members fail closed.
`engine.serialize_notice(ticket, intake)` seals the blob.
`engine.try_parse_notice(ticket, blob)` requires `policy` to match the engine
and `intake_pk` length to match that Policy (32 / 1184 / 1216).

```
key   = HKDF-Expand(Ticket bytes, info = "chuchotez/1/notice-aead-key")     // 32 bytes
nonce = first 12 bytes of HKDF-Expand(Ticket bytes, info = "chuchotez/1/notice-aead-nonce")
aad   = Ticket envelope version || Ticket invite kind
plain = raw_deflate(jcs(notice_json))
ct    = AES-256-GCM(key, nonce, aad, plain)
blob  = b64u(ct)
```

Canonical JSON is RFC 8785. Anyone who knows the Ticket can publish a substitute
Notice at the same Tag. Signatures and `MemberId` are a later slice.

### Intake

**Intake** is the calling-card receiver: `IntakeKeypair`, Mailboxes, and Wires.
The inviter-only secret stays here.

## Engine, Suite, and Rng

A **Suite** is HMAC-SHA-256, raw Deflate, unpadded base64url, AES-256-GCM,
RFC 8785, and the Intake KEM. An **Engine** is bound to one Suite and one
`Policy`. The host constructs it with `v1::std_engine(Policy)` or
`v1::Engine::new(suite, policy)`. Chuchotez stores no suite of its own.

**Rng** is a host port. Engine methods that need entropy take `&impl Rng`.
Cryptographic adapters take seeds. This workspace never implements `Rng`. Tests
inject a seed. `Random32` is `RANDOM32_LEN` (32) branded CSPRNG bytes.
`KemSeed` is `KEM_SEED_LEN` (64) bytes from two `Random32` draws.

`v1::std_suite` ships HMAC-SHA-256 over `libcrux-hmac` (`LibcruxHmac`), raw
Deflate over `flate2` (`miniz_oxide`, `Compression::best()`), unpadded base64url
over `base64ct::Base64UrlUnpadded`, AES-256-GCM over `libcrux-aes`, RFC 8785 in
`Rfc8785`, and Intake over `libcrux-kem` (`LibcruxKem`).

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

let engine: v1::Engine = v1::std_engine(v1::Policy::Classic);
let board = engine.new_billboard(
    engine.try_new_billboard_kind("nostr").expect("kind"),
    engine
        .try_new_billboard_address("wss://relay.example")
        .expect("addr"),
);
let mailbox = engine.new_mailbox(
    engine.try_new_mailbox_kind("nostr").expect("kind"),
    engine
        .try_new_mailbox_address("wss://mailbox.example")
        .expect("addr"),
);
let wire = engine.new_wire(
    engine.try_new_wire_kind("webrtc").expect("kind"),
    engine
        .try_new_wire_address("stun:stun.example")
        .expect("addr"),
);
let invite = engine
    .try_new_invite(&HostRng, &[board], &[mailbox], &[wire])
    .expect("invite");
let ticket = invite.ticket();
let intake = invite.intake();
let tag = ticket.billboard_tag(&engine);
let tag_key = ticket.mailbox_tag_key(&engine);
let ticket_blob = ticket.serialize(&engine);
let notice_blob = engine.serialize_notice(ticket, intake);
let _ = (tag, tag_key, ticket_blob, notice_blob);
```

The host shows `ticket_blob` as a QR or link. The invitee parses it, derives the
Tag, looks up a mapper by Billboard `kind`, and fetches `notice_blob` at
`address`. `engine.try_parse_notice(ticket, blob)` opens the Notice. Unknown
`kind` skips to the next Billboard. Debug formatting of secrets, tags, keys, and
Intake omits the raw bytes.

## Workspace

Three crates:

| Crate | Role |
| --- | --- |
| `chuchotez` | Package hosts depend on. Re-exports the domain. `v1::std_engine`. |
| `chuchotez-domain` | Types, ports, protocol, `v1::Suite` / `v1::Engine`. Zero crates.io dependencies. |
| `chuchotez-adapters` | Shipped pure adapters. |

Importing `chuchotez` starts no threads, timers, or network. Side effects stay
in the host. `wasm32-unknown-unknown` is a first-class target: a change that
compiles only on the desktop host is unfinished.

MSRV is 1.98, edition 2024. Default test command: `cargo test --workspace
--locked`. Line coverage on measured crates is 100%. `scripts/layering.py`
forbids third-party crates and host IO (`std::fs`, `std::net`, threads,
`SystemTime`, `Instant`) in `chuchotez-domain`.

## Later slices

- Fetching a Notice at a Billboard Tag over a mapper.
- Expanding a Message-bin coordinate from a Tag Key and a time bin.
- Pairwise streams, a group mesh, and Wire hop order after `Welcome`.
- Group and Sync invite kinds (a Sync invite uses the compact envelope with a
  different kind byte).
- Signed `FullInvite` and `MemberId`.

Chat and turn-based games remain host mappings onto these Channels.
