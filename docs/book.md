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
snapshot of watermark txs (fold version 1 in the nonce). The snapshot is the
state tree: users, identities, and conversation phases, with Sync
conversations on the device. Query `Conversation` is a projection of that
phase. `WrongPhase` when a
persist seq's tx is outside the watermark. Fold MAY omit txs with
`expire_at` ≤ ticked now. When the sets differ, heal binary-searches
sorted `tx_id`s with half-range XORs until one id, then want/have, and
retransmits the missing tx under the current sending-chain keys. While the
conversation is live, heal packets go out on Ephemeral; after 3 ticked
seconds without an answer they continue on Persistent. Reload is
`apply_folded` then `apply` of remaining persist records. When 50 durable packets have been sent since the last
`TxAdvertise`, `TxWrap`, or `TxAck`, the next send mints the one still owed.
Wrap uses an `encaps_pk` whose advertise tx is in the watermark. A shared
enters the mix FIFO after a watermarked `ratchet_ack` of that `kem_ct`. Every
8th durable packet mixes when that FIFO holds 8 agreed shareds; otherwise
`packet_seq` increments on the current epoch. At most 8 unused advertised
secret keys are kept.

Established DM and Sync sends with a nonempty `ephemerals` list enqueue on
every EphemeralChannel first, sealed with `eph_mk`. A matching ephemeral
`PacketXorAck` omits Persistent. `tick` three seconds later enqueues that
512-byte body on every DurableChannel. `TxAdvertise`, `TxWrap`, and `TxAck`
are Persistent immediately and may also copy on Ephemeral. An empty
`ephemerals` list and Group sends are Persistent only. The first such send
while idle may post `PacketPresenceActive` when `online_visible` is on,
otherwise `PacketPresence`. The conversation stays live for 30 ticked seconds
after an ephemeral packet from the other party. On this pairwise Sync, that
party is the other device.

`sendText`, `editMessage`, `removeMessage`, `sendReaction`, `sendRead`,
`sendDelivered`, `setConversationPrefs`, and conversation `TxName` /
`TxPhoto` require an established DM (`WrongPhase` on a handshake).
`sendTyping` and `sendPresence` are also legal on established Sync. Body
and caption are NFC, with UTF-8 length 1..=16384 and at most 4096
characters. `expire_at` is ticked now plus the conversation’s
`disappear_after`, or nil when that duration is nil. Query `messages` on
the established DM is the newest 1000 chat transactions after
`(hlc, tx_id)` sort. Handshake, ratchet, name, photo, prefs, group, and
engine payloads are omitted, as are txs with `expire_at` ≤ ticked now.
Typing clears 6 ticked seconds after the signal. Reload has empty typing
and presence. A durable DM send pings the peer `Wake` when that
subscription is set.

`sendMedia` takes 1..=4 attachments on an established DM. `media_key` is
`expand(conversation_secret, "chuchotez/1/media" || hash)`. `poll.blob_put`
carries `nonce || seal(media_key, media_bytes)` until `write_blob_ack`.
`poll.blob_get` lists `TxMedia` locators that are not still being put.
`open_media` opens that body and checks `hash`.

`create_group` takes 1..=31 established DMs on that identity. The owner is
`GroupEstablished`, and each of those DMs carries `TxGroupInvite`.
`group_secret_ct` is the KEM ciphertext, a 12-byte nonce, and an AEAD of
`group_secret` under `expand(shared, "chuchotez/1/group-secret")`.
`accept_group` posts `TxGroupAccept`; the owner posts `TxGroupRoster` and one
`TxGroupWrap` per other member. A roster that omits the local signing key
stores `Kicked`. `reject_group` stores `OfferRejected`. Leave and delete post
`TxGroupLeave` and store `Left`. Name, photo, and `disappear_after` are
owner-only. A durable group transaction pings every member whose latest
`TxPrefs.wake` is set. The folded snapshot of a live group keeps the secret,
name, owner, and epoch.

`create_sync_invite` keeps at most 4 peers besides this device. On confirm
the inviter seals the DEK to the invitee device encryption key as KEM
ciphertext, a 12-byte nonce, and an AEAD under
`expand(shared, "chuchotez/1/sync-dek")`. On confirm that sealed key is a
body in `poll`. The other device opens it from the body it ingests and then
holds that key. `kick_device` of this device is `WrongPhase`. Kicking
another device drops that device's link and makes new sending keys for the
Sync conversations that remain.
`leave_sync` clears this device's Sync rows. Once a Synchronization exists,
engine transactions also post on that live path.

`get_conversation` fills handshake, DM, group, and sync rows. The DM, group,
and sync views omit ticket secrets, the DEK, secret keys, tag keys, and Wake
`p256dh` / `auth`. `list_conversations` includes those rows for the identity,
including Sync on this device. `Engine::ping_posts` keeps `https:` rows and
gives each an empty body for RFC 8291. `nfc` normalizes display names,
addresses, ticket text, passphrases, and chat text before the engine gates.
A host cycle is `tick`, then `poll`, then mapper post, list, listen, and blob
transfer, then `ingest_packet` / `ingest_list`, `write_ack`, and
`write_blob_ack`.

Group chat, the member list, and each wrap of the group secret are sealed
512-byte bodies on the group's durable channels. They appear in `poll`. A
member list whose signature does not check is not applied. Invites stay on
the direct message.

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
reassemble fragments, and merge `DurableBody`. Durable `PacketTxFragLast` or
`PacketXorAck` matching `set_xor` after merge stores that actor's last
Persistent ack. A `PacketXorAck` from an EphemeralChannel with a matching
`set_xor` is a live ack only. The watermark is the intersection of last
Persistent acks from members who have Persistent-acked at least once. A full
durable list completes that TimeBin in `BinProgress`. Handshake catch-up
lists incomplete bins from `list_from` (the TimeBin at `create_invite` /
`receive_ticket`) or `watermark + 1` through `W+1`, union `[W-1, W, W+1]`.
Mapper `list` / `listen` MAY omit TimeBin < `W-71`. Packet chains, skip-ahead
`mk`s, and last Persistent acks live on the conversation row. Empty invite-tag
snapshot leaves Invitee `TicketReceived`; a valid `TxNotice` is
`InviteReceived`. A valid notice plus `DisplayName` mints `TxInviteeIntro`.
Inviter ingest of that intro mints `TxInviterIntro` and consumes the ticket.
`writeAck` of the intro set is Inviter `Confirming` / Invitee
`IntroductionSent`. Invitee ingest of inviter intro is `Confirming`. Policy
mismatch, unlock failure, Notice conflict, intro unlock/verify failure, and
duplicate intro store `FailedReason` overlays. `tick` past `expires`
pre-confirm stores `InviteExpired`. `confirmation_digest` is
`text(fingerprint)`. `confirmEstablished` inserts a child DM or Sync
conversation. Invite-tag list continues until that intro is watermarked.
Live-path sends and group mint wait on later slices.

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

- Cover traffic.

Chat and turn-based games remain host mappings onto DurableChannel and
EphemeralChannel.
