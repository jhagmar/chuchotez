# Chuchotez

This book is the guide to the locked library. Types and methods named here exist
in the crates unless a section says the work is a later slice. rustdoc is the
API reference. The [README](../README.md) is depend and bootstrap. The
information model, encodings, and library operations are
[protocol.md](protocol.md).

Chuchotez is a communications backend the person shipping the app does not
operate. A **host** is the application that depends on the `chuchotez` crate:
a messenger, a turn-based game, or another mapping onto the same envelopes.
The host keeps a `v1::Engine` bound to `v1::Defaults`, supplies a CSPRNG, and
talks to the network. The library compiles for `wasm32-unknown-unknown` with
the Rust standard library.

Crypto is a **Policy** per identity: `Hybrid` for a messenger host, `Classic`
when a game asks for it. v1 pins HMAC-SHA-256 as the expand function, raw
Deflate as compress, unpadded base64url as the text alphabet, AES-256-GCM as
the AEAD, RFC 8785 as canonical JSON, SHA-256, Argon2id (`m` 19456, `t` 2,
`p` 1), the Intake KEM in `std_suite` (Classic X25519, PostQuantum ML-KEM-768,
Hybrid X-Wing), and Sign (Classic Ed25519, PostQuantum ML-DSA-65, Hybrid both
concatenated). The host may bind different implementations through `v1::Suite`.

## Channels

A **DurableChannel** is a mapper destination that stores posted packets for
`list`. An **EphemeralChannel** delivers live packets on `listen`. Coordinates
are `{ kind, address }`. `kind` is the host mapper registry key (`"nostr"` and
`"webrtc"` are valid). `address` is nonempty UTF-8 the mapper interprets,
NFC-or-precomposed, capped at `ADDRESS_MAX_LEN` (256). Chuchotez does not
fetch. Mapping libraries live beside this crate. Persistence lists are length
1..=4; ephemeral lists are length 0..=4. Uniqueness is `kind`+`address` within
each list (`ChannelBounds`).

`poll` returns DurableChannel / EphemeralChannel locators and 512-byte write
bodies plus blob GET/PUT rows. The host starts and stops mapper work by
set-diff of those lists.

## PacketPlain

`PacketPlain` is the sealed packet contents, padded to `PACKET_PAD_LEN`
(484). HandshakeDm and HandshakeSync carry empty `actor_id`. DirectMessage
and Group carry `SigningPublicKey`. Synchronization carries `DeviceId`.
Alternatives are `PacketTxFragMore`, `PacketTxFragLast`,
`PacketXorAck`, `PacketHealHalfXor`, `PacketHealWant`, `PacketHealHave`,
`PacketTyping`, `PacketTypingActive`, `PacketPresence`, and
`PacketPresenceActive`. JSON `"type"` strings are the `v1-packet-*`
discriminators. `J⁻¹` refuses extra members, missing members, and an unknown
`"type"`. `packed(PacketPlain)` that exceeds 484 is `BodyTooLarge`. Heal
`hi` of all-`0xff` bytes is +∞.

## Ticket and Notice

**Ticket** is the QR capability: a 32-byte secret, the inviter’s persistent
channels, and `expires`. The host string is `text(packed(Ticket))` with JSON
type `"v1-handshake-ticket"`. `create_invite` omitted persistents copies
`Defaults.persistents`. `expires` MUST be greater than the ticked now.

**TxNotice** is the handshake advertisement (policy, intake public key,
persistents, ephemerals, expires). Invite packets list at
`expand(secret, "chuchotez/1/handshake-invite" || time_bin)`.
`create_invite` and `create_sync_invite` post 512-byte sealed fragments of
that notice. Handshake sending-chain join omits `actor_id`. Group invites
use an Established DM and have no Ticket, InviteTag, or intake KEM.

## Engine, Suite, Rng, and EngineState

A **Suite** is HMAC-SHA-256, raw Deflate, unpadded base64url, AES-256-GCM,
RFC 8785, SHA-256, Argon2id, the Intake KEM (generate, wrap, unwrap), and Sign
(generate, sign, verify). An **Engine** is bound to one Suite and one
`Defaults`: `let engine = v1::std_engine(defaults);` or
`v1::Engine::new(suite, defaults)`. Policy is chosen at `create_identity` and
at `create_sync_invite`. Chuchotez stores no suite of its own.

**EngineState** is a CRDT of durable transactions keyed by `tx_id`. Named
mutators mint payloads, persist `nonce || lock(DEK, DurableBody)` with empty
AAD (persist version 1 in the nonce high four bytes), and return `MutateOk`
(`state`, persist records, Wake pings). Methods that mint an id also return
that id. `tick` is the clock; a first successful `tick` is required before
`poll` and mints. `tick` with `now` less than the last ticked now is
`ClockWentBackwards`. Equal now is ok.

`wrap_dek` returns a packed `VaultHeader` wrapping the held DEK (minted from
`Rng` when absent) under a passphrase (UTF-8 length 8..=1024) or a 32-byte
PRF secret. `unlock` holds that DEK. `lock` drops it. `fold` writes a sealed
snapshot (fold version 2 in the nonce). Reload is `apply_folded` then `apply`
of remaining persist records.

**Rng** is a host port. Engine methods that need entropy take `&dyn Rng`.
Cryptographic adapters take seeds. This workspace never implements `Rng`.
`Random32` is `RANDOM32_LEN` (32) branded CSPRNG bytes. `KemSeed` /
`SignSeed` are 64 bytes from two `Random32` draws.

Query `get_conversation` returns a `Conversation` enum: `Handshake`
(`HandshakeInviter`, `HandshakeInvitee`, `FailedReason`), `DirectMessageQuery`,
`GroupQuery`, or `SynchronizationQuery`. `list_conversations` rows carry that
same `Conversation`. Ticket secret, DEK, and secret keys stay out of that
query.

## Call the library

The facade crate is `chuchotez`. The crate doctest is the host sketch: wrap a
DEK, `tick`, `create_user`, `create_identity` with a Policy, `create_invite`,
`ticket_host_string`. Fill `Random32` from a CSPRNG in a real host. After
`receive_ticket`, the invitee lists the invite tag. `create_invite` posts
sealed 512-byte `PacketTxFrag` bodies on the handshake sending chain.
`ingest_list` / `ingest_packet` open those bodies with skip-ahead `mk`,
reassemble fragments, and merge `DurableBody`. A full durable list completes
that TimeBin in `BinProgress`. Empty invite-tag snapshot leaves Invitee
`TicketReceived`; a valid `TxNotice` is `InviteReceived`. A valid notice
plus `DisplayName` mints `TxInviteeIntro`. Inviter ingest of that intro mints
`TxInviterIntro` and consumes the ticket. `writeAck` of the intro set is
Inviter `Confirming` / Invitee `IntroductionSent`. Invitee ingest of inviter
intro is `Confirming`. Policy mismatch, unlock failure, Notice conflict, intro
unlock/verify failure, and duplicate intro store `FailedReason` overlays.
`tick` past `expires` pre-confirm stores `InviteExpired`. Heal, live-path
XOR-acks, confirmation digest bytes, and spawning a child DM secret from
intros wait on later slices; `confirmation_digest` is an empty string until
that slice.

`std_suite` ships HMAC-SHA-256 over `libcrux-hmac` (`LibcruxHmac`), raw
Deflate over `flate2` (`miniz_oxide`, `Compression::best()`), unpadded
base64url over `base64ct::Base64UrlUnpadded`, AES-256-GCM over `libcrux-aes`,
RFC 8785 in `Rfc8785`, SHA-256 over `libcrux-sha2` (`LibcruxSha256`), Argon2id
over `argon2` (`RustcryptoArgon2id`), Intake over `libcrux-kem`
(`LibcruxKem`), and Sign over `libcrux-ed25519` / `libcrux-ml-dsa`
(`LibcruxSign`).

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
--locked`. Line coverage on measured crates is 100%. With Docker, run the
required checks as [`ci/README.md`](../ci/README.md). `scripts/layering.py`
forbids third-party crates and host IO (`std::fs`, `std::net`, threads,
`SystemTime`, `Instant`) in `chuchotez-domain`.

## Later slices

- Heal half-xor / want / have.
- Live path (ephemeral first, persistent after 3 ticked seconds).
- Confirmation digest and child DM / Sync spawn from intros.
- `create_group` from Established DMs (member cap 32, parallel `TxGroupInvite`).
- Cover traffic.

Chat and turn-based games remain host mappings onto DurableChannel and
EphemeralChannel.
