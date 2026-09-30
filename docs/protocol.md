# Chuchotez

This page is the Chuchotez protocol: the information model, encodings, and
interfaces. A library, host, or mapper in any language implements this page.
The [book](book.md) documents the locked Rust crate. rustdoc is that crate’s
API reference.

**Shipped** work is in the crates. **Planned** work is decided and waiting on a
slice. Heal and live path wait on a later slice.

The **host** is the app. It supplies `random32`, stores the local log, and talks
to the network. Chuchotez builds the envelopes.

## Roles

A **conversation** is parties, a shared secret, and a CRDT: a set of
**transactions** keyed by `tx_id`. The conversation **sort** names the allowed
payloads and how the secret may evolve. Sorts are handshake, DM, Group, Sync,
and engine.

The **inviter** starts a handshake. The **invitee** joins it. After both confirm
a fingerprint, the library mints a child DM or Sync conversation with a new
secret. Handshake conversations exist because the invitee has `Ticket.secret`
and does not yet have a peer public key. Group invites are DM transactions on
an Established DM (a **contact**). That conversation already has peer
`SigningPublicKey` values, so Group has no Ticket, InviteTag, or intake KEM.

A **`Policy`** is `Classic`, `PostQuantum`, or `Hybrid`. It chooses the
public-key algorithms in [Algorithms](#algorithms). Policy is per identity.
`createSyncInvite` takes a Policy for the Synchronization and device keys.

The **library** is the handle bound to `Defaults` (`Engine` in the reference
crate). **`EngineState`** is the host’s CRDT: one set of engine transactions.
A conversation query filters that set and folds a presentation.

A **mapper** talks to one `Kind` of `DurableChannel` or `EphemeralChannel`,
or to a blob store. The host chooses mappers by `kind`. Examples of kind
strings: `nostr`, `webrtc`, `blossom`. A `DurableChannel` maps to stored
events. An `EphemeralChannel` maps to live events (a `nostr` ephemeral event,
a `webrtc` path). A blob mapper GET/PUTs ciphertext at `kind`, `address`, and
`tag`. Cover traffic is later.

## Notation

Byte strings, concatenation, and algorithms:

```
||              concatenation
refuse          input rejected
x[0..k]         first k bytes of x
be<n>u(x)       n-bit big-endian unsigned encoding of x
```

`n` in `be<n>u` is a multiple of 8. The output is `n/8` bytes. `x` MUST satisfy
`0 ≤ x < 2^n`.

A **shared secret** is 32 bytes both sides hold.

A **public key** (`pk`) may be copied. The matching **secret key** (`sk`) stays
with one party.

`seal` uses a shared secret. `wrap` uses someone’s `pk`. `sign` uses a signing
`sk`.

Information-model types use **CDDL** (RFC 8610). On this page:

```
Name = Type              named sort
{ field: Type }          record (map with those keys)
[n*m Type]               list of Type, length n..=m
[Type]                   list of Type, length unconstrained here
A / B                    alternative
bool                     boolean
nil                      empty alternative (JSON `null`)
bstr .size n             exactly n bytes
tstr .size (a..b)        Unicode string, UTF-8 byte length a..=b
```

Two names with the same CDDL shape are distinct sorts (`UserId` and `Secret`
are both 32-byte strings). Constraints CDDL does not express (Unicode
Normalization Form C, Policy-dependent key lengths) sit in the prose under the
type.

[Serialization](#serialization) maps those values to bytes.

### Functions

```
be<n>u(integer) → n/8 bytes
```

Conversion of an integer to an `n`-bit big-endian unsigned encoding. The
integer MUST fit that width.

```
random32() → 32 bytes
```

Cryptographically strong randomness.

```
time_bin(unix_seconds) → integer
```

Mapping from a Unix time in seconds to the corresponding integer bin.

```
mac(key, data) → 32 bytes
```

A 32-byte fingerprint of `data` that only a holder of `key` can produce. Same
`key` and `data` always give the same output.

```
expand(key, label) = mac(key, label || 0x01) → 32 bytes
```

Turns one secret and a byte string into a new 32-byte secret. Different labels
give independent values. Quoted ASCII in a formula is that string as UTF-8.

```
compress(bytes) → bytes
decompress(bytes, max) → bytes | refuse
```

`compress` shrinks bytes. `decompress` restores them and refuses if the output
would exceed `max`. Bytes after the Deflate stream MUST be `0x00`.

```
hash(bytes) → 32 bytes
```

A 32-byte fingerprint of `bytes`. Same input always gives the same output.

```
pad(bytes, n) → n bytes | refuse
```

`bytes` with trailing `0x00` to length `n`. Refuses when `bytes` is longer
than `n`.

```
text(bytes) → string
untext(string) → bytes | refuse
```

`text` writes bytes as a Unicode string. `untext` restores the bytes and
refuses a malformed string.

```
canonical(value) → bytes
parse(bytes) → value | refuse
```

`canonical` is the unique byte spelling of a domain value, via the JSON
mapping `J` in Serialization. `parse` inverts that spelling.

```
seal(key, nonce, plaintext) → bytes
open(key, nonce, ciphertext) → bytes | refuse
```

`seal` hides `plaintext`. `open` returns it when `key` and `nonce` match. A
change to the ciphertext makes `open` refuse. `nonce` MUST be unique for that
`key`.

```
argon2id(passphrase, salt, m, t, p) → 32 bytes | refuse
```

Passphrase stretching. `m` is memory in kibibytes, `t` is iterations, `p` is
lanes. Output is 32 bytes.

```
keygen(policy, seed) → (pk, sk) | refuse
wrap(policy, pk, seed) → (shared, kem_ct) | refuse
unwrap(policy, sk, kem_ct) → shared | refuse
```

`keygen` makes a `policy`-algorithm public-key encryption key pair with public
key `pk` and secret key `sk`. `wrap` uses `pk` to mint a one-time `shared` and
a blob `kem_ct` only `sk` can open. `unwrap` recovers `shared`.

```
sign_keygen(policy, seed) → (pk, sk) | refuse
sign(policy, sk, message, seed) → sig | refuse
verify(policy, pk, message, sig) → ok | refuse
```

`sign_keygen` makes a `policy`-algorithm signing pair. `sign` produces
the signature `sig` for `message` using the secret key `sk`. `verify` accepts
when `sig` matches the public key `pk` and `message`.

## Algorithms

v1 bindings for the functions above.

| Function | v1 |
| --- | --- |
| `random32` | host `random32` |
| `time_bin` | `floor(unix_seconds / 3600)` |
| `mac` | HMAC-SHA-256 |
| `hash` | SHA-256 |
| `expand` | RFC 5869 `T(1)` via `mac` |
| `compress` / `decompress` | raw Deflate (RFC 1951) |
| `text` / `untext` | unpadded base64url (RFC 4648 §5) |
| `canonical` / `parse` | `J` then RFC 8785 |
| `seal` / `open` | AES-256-GCM; `key` 32; `nonce` 12; associated data empty; output body then 16-byte tag |
| `argon2id` | RFC 9106 Argon2id; output 32 |
| `keygen` / `wrap` / `unwrap` | Classic X25519; PostQuantum ML-KEM-768; Hybrid X-Wing |
| `sign_keygen` / `sign` / `verify` | Classic Ed25519; PostQuantum ML-DSA-65; Hybrid both concatenated (Ed25519 then ML-DSA-65) |

`keygen` and `wrap` take a 64-byte seed (`random32() || random32()`). Classic
and Hybrid `keygen` consume the first 32 bytes. PostQuantum `keygen` consumes
64. `wrap` matches that split. `sign_keygen` takes a 64-byte seed; Classic and
PostQuantum consume the first 32; Hybrid consumes 64. `sign` takes a 32-byte
seed; Classic ignores it; PostQuantum and Hybrid feed it to ML-DSA-65.

| Policy | `pk` from `keygen` | `sk` from `keygen` | `kem_ct` from `wrap` | `pk` from `sign_keygen` | `sk` from `sign_keygen` | `sig` from `sign` |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Classic | 32 | 32 | 32 | 32 | 32 | 64 |
| PostQuantum | 1184 | 2400 | 1088 | 1952 | 4032 | 3309 |
| Hybrid | 1216 | 32 | 1120 | 1984 | 4064 | 3373 |

Lengths are in bytes. Hybrid signing `pk`, `sk`, and `sig` are Classic then
PostQuantum concatenation.

A mapper **packet** is 512 bytes: a 12-byte nonce then 500 bytes of `seal`
output. The sealed plaintext is `pad(packed(PacketPlain), 484)`.

---

## Information model

### General types

#### Policy

Chooses the KEM and signature algorithms.

```
Policy = "Classic" / "PostQuantum" / "Hybrid"
```

#### Kind

A mapper registry key. Hosts pick the strings their mappers understand
(examples: `nostr`, `webrtc`, `blossom`).

```
Kind = tstr .size (1..32) .regexp "[a-z][a-z0-9-]*"
```

#### Address

A mapper coordinate. Unicode Normalization Form C, no NUL, no combining mark.

```
Address = tstr .size (1..256)
```

#### DurableChannel

A mapper destination that stores posted packets for `list`. Two
`DurableChannel` values are equal when `kind` and `address` match.

```
DurableChannel = {
  kind: Kind,
  address: Address,
}
```

#### EphemeralChannel

A mapper destination that delivers live packets on `listen`. Bodies MAY be
dropped. Two `EphemeralChannel` values are equal when `kind` and `address`
match.

```
EphemeralChannel = {
  kind: Kind,
  address: Address,
}
```

#### DisplayName

A name shown for a user or device. Unicode Normalization Form C, no NUL, no
combining mark.

```
DisplayName = tstr .size (1..64)
```

#### ProfilePic

Static WebP avatar bytes.

```
ProfilePic = bstr .size (1..4096)
```

Bytes `[0..4]` are `RIFF` and `[8..12]` are `WEBP`.

#### UserId

Identifies a user.

```
UserId = bstr .size 32
```

#### IdentityId

Identifies an identity under a user.

```
IdentityId = bstr .size 32
```

#### ConversationId

Identifies a conversation.

```
ConversationId = bstr .size 32
```

#### DeviceId

Identifies a linked device in a Synchronization.

```
DeviceId = bstr .size 32
```

#### Secret

32-byte secret. Ticket capabilities, expand keys, conversation secrets, and
other 32-byte secrets use this sort.

```
Secret = bstr .size 32
```

#### Tag

32-byte locator. Durable bins, ephemeral bins, invite locators, `tx_id`
values, and XOR fingerprints use tags.

```
Tag = bstr .size 32
```

#### TagKey

32-byte key from which tags are derived with `expand`.

```
TagKey = bstr .size 32
```

#### UnixSeconds

Unix time in seconds, the same unit `time_bin` takes.

```
UnixSeconds = uint
```

#### UnixMillis

Unix time in milliseconds, used in `Hlc`.

```
UnixMillis = uint
```

#### TimeBin

Hour index of Unix time.

```
TimeBin = uint
```

```
TimeBin = time_bin(unix_seconds)
```

`unix_seconds` is a `UnixSeconds` value. At `W = TimeBin`, the live listen
window is `W-1`, `W`, and `W+1`. Mapper `list` / `listen` MAY omit bodies
whose TimeBin is less than `W - 71` (72 hour bins). Engine catch-up lists
incomplete bins from handshake `list_from` or `watermark + 1` through `W+1`,
union the live listen window. `list_from` is the TimeBin of `createInvite` or
`receiveTicket`.

#### Hlc

Presentation timestamp. Merge ignores `Hlc`. Query `messages` sorts by
`(wall_ms, counter, tx_id)`.

```
Hlc = {
  wall_ms: UnixMillis,
  counter: uint,
}
```

On mint, `wall_ms` is `1000 *` the ticked `UnixSeconds` and `counter` is 0
when that wall is strictly greater than the local HLC, else `counter + 1` at
the same wall. On ingest of a peer `Hlc`, local HLC becomes
`max(local, peer)` with `counter + 1` when the maxima are equal.

#### PublicKey

Public key for `wrap`. Length is the `keygen` `pk` length for the Policy that
applies.

```
PublicKey = bstr
```

#### SecretKey

Secret key for `unwrap`. Length is the `keygen` `sk` length for that Policy.

```
SecretKey = bstr
```

#### KeyPair

A `wrap` key pair.

```
KeyPair = {
  pk: PublicKey,
  sk: SecretKey,
}
```

#### SigningPublicKey

Public key for `verify`. Length is the `sign_keygen` `pk` length for the Policy
that applies.

```
SigningPublicKey = bstr
```

#### SigningSecretKey

Secret key for `sign`. Length is the `sign_keygen` `sk` length for that Policy.

```
SigningSecretKey = bstr
```

#### SigningKeyPair

A `sign` key pair.

```
SigningKeyPair = {
  pk: SigningPublicKey,
  sk: SigningSecretKey,
}
```

#### Signature

Output of `sign`. Length is the Policy `sig` length.

```
Signature = bstr
```

#### KemCiphertext

Output of `wrap`. Length is the Policy `kem_ct` length.

```
KemCiphertext = bstr
```

#### NotificationPrivacy

How a notification names the chat and whether it includes a preview.

```
NotificationPrivacy = "name" / "preview" / "silent"
```

#### Wake

Web Push subscription the peer’s host POSTs to in order to wake this device.

```
Wake = {
  endpoint: tstr .size (1..2048),
  p256dh: bstr .size 65,
  auth: bstr .size 16,
  vapid_pk: bstr / nil,
}
```

`endpoint` is an `https:` URL, printable ASCII, no space, Unicode
Normalization Form C. `vapid_pk` when present is the VAPID public key the
posting host uses for the JWT.

#### OnWirePrefs

Preference snapshot that travels on handshake intros and on `TxPrefs`.

```
OnWirePrefs = {
  read_receipts: bool,
  online_visible: bool,
  send_typing: bool,
  disappear_after: UnixSeconds / nil,
  wake: Wake / nil,
}
```

`disappear_after` `nil` is never. A positive duration is seconds. `wake` `nil`
is unpublished or revoked.

#### Defaults

Host-chosen factory for a new `EngineState`.

```
Defaults = {
  persistents: [1*4 DurableChannel],
  ephemerals: [*4 EphemeralChannel],
  read_receipts: bool,
  online_visible: bool,
  send_typing: bool,
  disappear_after: UnixSeconds / nil,
  publish_wake: bool,
  notification_privacy: NotificationPrivacy,
}
```

`ephemerals` length is 0..=4. `kind`+`address` is unique within each list.
The same `kind`+`address` MAY appear once on `persistents` and once on
`ephemerals`. `publish_wake` is copied into new conversations; `wake` stays
`nil` until `setConversationPrefs` supplies a `Wake`. Channel lists on a
Ticket, `TxNotice`, group genesis, and spawned conversations are copies at
mint. Later `setDefaults` does not change those lists. Identity `Policy` and
key pairs are lifetime of that identity.

#### ConversationSort

Which allowed payloads and secret-evolution rules apply.

```
ConversationSort = "HandshakeDm" / "HandshakeSync" / "DirectMessage"
                 / "Group" / "Synchronization" / "Engine"
```

#### BinProgress

EngineState listing progress for one `DurableChannel` and TagKey.
`watermark` is the greatest bin such that every bin in `[list_from, watermark]`
has been listed in full. `completed` is fully listed bins greater than
`watermark`.

```
BinProgress = {
  channel: DurableChannel,
  tag_key: TagKey,
  watermark: TimeBin,
  completed: [TimeBin],
}
```

#### Poll

Query of mapper work for the ticked now. `list` and `listen_durable` arrays
are ordered by `kind`, then `address`, then tag bytes. `listen_ephemeral` and
the write arrays use the same order on their channel type.

```
DurableLocator = { channel: DurableChannel, tag: Tag }
EphemeralLocator = { channel: EphemeralChannel, tag: Tag }
DurableWrite = { channel: DurableChannel, tag: Tag, body: bstr .size 512 }
EphemeralWrite = { channel: EphemeralChannel, tag: Tag, body: bstr .size 512 }
BlobPut = { kind: Kind, address: Address, tag: Tag, body: bstr }
BlobGet = { kind: Kind, address: Address, tag: Tag }
BlockedMissing = "DisplayName"
BlockedIdentity = {
  user_id: UserId,
  identity_id: IdentityId,
  missing: BlockedMissing,
}

Poll = {
  list: [DurableLocator],
  listen_durable: [DurableLocator],
  listen_ephemeral: [EphemeralLocator],
  write_durable: [DurableWrite],
  write_ephemeral: [EphemeralWrite],
  blob_put: [BlobPut],
  blob_get: [BlobGet],
  blocked: [BlockedIdentity],
}
```

Write `body` is the 512-byte packet. `list` tags are incomplete catch-up bins
from `list_from` or `watermark + 1` through `W+1`, union `[W-1, W, W+1]`, for
every handshake InviteTag this device lists. `listen_durable` is `[W-1, W, W+1]` on
handshake locators and on Established persist bins. `listen_ephemeral` is
`[W-1, W, W+1]` on every Established DM, Group, and Synchronization so a
peer’s live send can land; ephemeral writes use `W`. Handshake conversations
omit `listen_ephemeral` and `write_ephemeral`. `blob_put` / `blob_get` are
blob-mapper locators. `blob_put.body` is mapper-native ciphertext.

#### Ticket

Capability that locates a handshake. The host shows `text(packed(Ticket))` as
a QR or other medium.

```
Ticket = {
  secret: Secret,
  persistents: [1*4 DurableChannel],
  expires: UnixSeconds,
}
```

`persistents` are the inviter’s `DurableChannel` values for the invite locator.
The list is frozen at `createInvite` / `createSyncInvite`.

The first valid `TxInviteeIntro` consumes the ticket. The inviter stops
notice writes. List of the invite tag continues until that intro is in the
watermark. A later intro from that role is `DuplicateIntro`.

#### InviteTag

Public Persistent locator derived from a ticket secret.

```
InviteTag = Tag
```

```
InviteTag = expand(secret, "chuchotez/1/handshake-invite" || be<64>u(TimeBin))
```

`secret` is `Ticket.secret`. The inviter posts handshake packets at this tag
on every ticket `DurableChannel`. The invitee lists and listens there until
intros exchange `send_tag_key` values.

#### PersistTag

Per-actor Persistent locator for a time bin.

```
PersistTag = Tag
```

```
PersistTag = expand(send_tag_key, persist_label || be<64>u(TimeBin))
```

| Conversation sort | `persist_label` |
| --- | --- |
| HandshakeDm | `"chuchotez/1/handshake-dm-persist-bin"` |
| HandshakeSync | `"chuchotez/1/handshake-sync-persist-bin"` |
| DirectMessage | `"chuchotez/1/dm-persist-bin"` |
| Group | `"chuchotez/1/group-persist-bin"` |
| Synchronization | `"chuchotez/1/sync-persist-bin"` |

#### EphTag

Per-actor Ephemeral locator for a time bin.

```
EphTag = Tag
```

```
EphTag = expand(eph_send_tag_key, eph_label || be<64>u(TimeBin))
```

| Conversation sort | `eph_label` |
| --- | --- |
| HandshakeDm | `"chuchotez/1/handshake-dm-eph-bin"` |
| HandshakeSync | `"chuchotez/1/handshake-sync-eph-bin"` |
| DirectMessage | `"chuchotez/1/dm-eph-bin"` |
| Group | `"chuchotez/1/group-eph-bin"` |
| Synchronization | `"chuchotez/1/sync-eph-bin"` |

#### PacketPlain

Sealed packet contents, padded to 484 bytes. HandshakeDm and HandshakeSync
carry empty `actor_id`. DirectMessage and Group carry the sender
`SigningPublicKey`. Synchronization carries `DeviceId`.

```
PacketPlain = PacketTxFragMore / PacketTxFragLast / PacketXorAck
            / PacketHealHalfXor / PacketHealWant / PacketHealHave
            / PacketTyping / PacketTypingActive
            / PacketPresence / PacketPresenceActive
```

#### PacketTxFragMore

A non-final slice of `packed(DurableBody)`. `frag_i` is 0-based, 0..=62.

```
PacketTxFragMore = {
  version: 1,
  actor_id: bstr,
  packet_seq: uint,
  tx_id: Tag,
  frag_i: uint,
  frag: bstr,
}
```

#### PacketTxFragLast

The final slice of `packed(DurableBody)`. `frag_i` is 0-based. The fragment
count is `frag_i + 1`, in 1..=64. `set_xor` is the sender’s set XOR after
including this `tx_id`.

```
PacketTxFragLast = {
  version: 1,
  actor_id: bstr,
  packet_seq: uint,
  tx_id: Tag,
  frag_i: uint,
  frag: bstr,
  set_xor: Tag,
}
```

#### PacketXorAck

The sender’s set XOR and no transaction fragment.

```
PacketXorAck = {
  version: 1,
  actor_id: bstr,
  packet_seq: uint,
  set_xor: Tag,
}
```

#### PacketHealHalfXor

XOR of `tx_id`s in `[lo, hi)` for mismatch recovery. Heal packets are
conversation packets and are not CRDT transactions.

```
PacketHealHalfXor = {
  version: 1,
  actor_id: bstr,
  packet_seq: uint,
  lo: Tag,
  hi: Tag,
  xor: Tag,
}
```

`hi` is exclusive. `hi` of all-`0xff` bytes is +∞. Ids in the range are in
sorted id order.

#### PacketHealWant

`tx_id` values the sender wants in `[lo, hi)`.

```
PacketHealWant = {
  version: 1,
  actor_id: bstr,
  packet_seq: uint,
  lo: Tag,
  hi: Tag,
  ids: [*32 Tag],
}
```

#### PacketHealHave

`tx_id` values the sender has in `[lo, hi)`.

```
PacketHealHave = {
  version: 1,
  actor_id: bstr,
  packet_seq: uint,
  lo: Tag,
  hi: Tag,
  ids: [*32 Tag],
}
```

Binary search on the sorted id list until ranges are a single id, then
`PacketHealHave` / `PacketHealWant` those ids. Retransmit missing txs with
the same `tx_id` and `canonical(payload)` under current sending-chain keys.
Heal MAY use an `EphemeralChannel` while the peer is live; if no heal answer
arrives within 3 ticked seconds, heal continues on a `DurableChannel`.

#### PacketTyping

Ephemeral composing signal.

```
PacketTyping = {
  version: 1,
  actor_id: bstr,
  packet_seq: uint,
  conversation_id: ConversationId,
  composing: bool,
}
```

#### PacketTypingActive

Ephemeral composing signal with a visible last-active time (`online_visible`
on).

```
PacketTypingActive = {
  version: 1,
  actor_id: bstr,
  packet_seq: uint,
  conversation_id: ConversationId,
  last_active: UnixSeconds,
  composing: bool,
}
```

#### PacketPresence

Ephemeral liveness signal.

```
PacketPresence = {
  version: 1,
  actor_id: bstr,
  packet_seq: uint,
  conversation_id: ConversationId,
}
```

#### PacketPresenceActive

Ephemeral liveness signal with a visible last-active time (`online_visible`
on).

```
PacketPresenceActive = {
  version: 1,
  actor_id: bstr,
  packet_seq: uint,
  conversation_id: ConversationId,
  last_active: UnixSeconds,
}
```

The CRDT set, `set_xor`, and XOR-ack ignore these four sorts. Query typing
`lastActive` is the latest `last_active` on `PacketTypingActive` or
`PacketPresenceActive`. Query typing clears when `tick` `now` is at least 6
seconds after that time; when the latest composing packet is `PacketTyping`,
it clears 6 ticked seconds after ingest of that packet. Reload has empty
typing and presence.

#### DurableBody

Reassembled durable transaction. `tx_id` covers `payload` only.

```
DurableBody = {
  conversation_id: ConversationId,
  hlc: Hlc,
  payload: TxPayload,
}
```

```
tx_id = mac(expand(conversation_secret, "chuchotez/1/tx-id"), canonical(payload))
```

`conversation_secret` is `Ticket.secret` on a handshake, the spawned secret
on DM or Sync, `group_secret` on a Group, and
`expand(dek, "chuchotez/1/engine")` on engine txs. A complete `DurableBody`
enters the CRDT set. Same `tx_id` and same `payload` is one tx. Same
`tx_id` and a different `payload` is Equivocation.

`set_xor` is the XOR of every complete `tx_id` in the conversation set
(engine set on Synchronization and for engine txs). `PacketTxFragLast`
carries the sender’s `set_xor` after including this tx. `PacketTxFragMore`
omits it.

On ingest from a `DurableChannel`, when local `set_xor` equals the packet
`set_xor` after merge, the library stores that actor’s last ack as a copy of
the local tx set. A `PacketXorAck` from an `EphemeralChannel` with a matching
`set_xor` is a **live ack** only: it does not update last ack for the
watermark. The **watermark** is the intersection of last **Persistent** acks
from members who have Persistent-acked at least once. A silent member keeps
their last Persistent ack. Fold and use-or-delete of sending-chain skip keys
and advertise, wrap, and ack artifacts cover only txs in the watermark. Wrap
and mix use an `encaps_pk` / `kem_ct` only when that artifact’s durable tx is
in the watermark.

Engine txs live on disk under the DEK until a Synchronization exists, then
the same txs also travel on the Sync live path.

#### TxPayload

Sort-constrained inner value.

```
TxPayload = TxNotice / TxInviterIntro / TxInviteeIntro / TxConfirm / TxReject
          / TxText / TxEdit / TxRemove / TxReaction
          / TxRead / TxDelivered / TxMedia
          / TxAdvertise / TxWrap / TxAck
          / TxName / TxPhoto / TxPrefs
          / TxGroupInvite / TxGroupAccept / TxGroupReject
          / TxGroupRoster / TxGroupWrap / TxGroupLeave / TxGroupKick
          / TxEngineInit / TxEngineSetDefaults / TxEngineCreateUser
          / TxEngineCreateIdentity / TxEngineDeleteUser / TxEngineDeleteIdentity
          / TxEngineSetDisplayName / TxEngineUnsetDisplayName
          / TxEngineSetProfilePic / TxEngineSetDeviceName / TxEngineKickDevice
```

Handshake durable payloads: `TxNotice`, `TxInviterIntro`, `TxInviteeIntro`,
`TxConfirm`, `TxReject`.
DM durable payloads: `TxText`, `TxEdit`, `TxRemove`, `TxReaction`, `TxRead`,
`TxDelivered`, `TxMedia`, `TxAdvertise`, `TxWrap`, `TxAck`, `TxName`,
`TxPhoto`, `TxPrefs`, `TxGroupInvite`, `TxGroupAccept`, `TxGroupReject`. Group
durable payloads: `TxText`, `TxEdit`, `TxRemove`, `TxReaction`, `TxRead`,
`TxDelivered`, `TxMedia`, `TxAdvertise`, `TxWrap`, `TxAck`, `TxName`,
`TxPhoto`, `TxPrefs`, `TxGroupRoster`, `TxGroupWrap`, `TxGroupLeave`,
`TxGroupKick`. Sync handshake
uses the handshake payloads. Synchronization durable payloads are engine
payloads and device `TxName`. Engine payloads are the `TxEngine*` sorts.

#### TxNotice

Handshake advertisement. Policy is the inviter identity Policy (DM) or the
`createSyncInvite` Policy (Sync).

```
TxNotice = {
  policy: Policy,
  intake_pk: PublicKey,
  persistents: [1*4 DurableChannel],
  ephemerals: [*4 EphemeralChannel],
  expires: UnixSeconds,
}
```

#### TxInviterIntro

Inviter calling information and a KEM seed wrap to the invitee `intake_pk`.

```
TxInviterIntro = {
  name: DisplayName,
  profile_pic: ProfilePic / nil,
  send_tag_key: TagKey,
  eph_send_tag_key: TagKey,
  encryption_pk: PublicKey,
  signing_pk: SigningPublicKey,
  seed_ct: KemCiphertext,
  prefs: OnWirePrefs,
}
```

#### TxInviteeIntro

Invitee calling information, invitee intake public key, and a KEM seed wrap
to the inviter notice `intake_pk`.

```
TxInviteeIntro = {
  name: DisplayName,
  profile_pic: ProfilePic / nil,
  send_tag_key: TagKey,
  eph_send_tag_key: TagKey,
  encryption_pk: PublicKey,
  signing_pk: SigningPublicKey,
  intake_pk: PublicKey,
  seed_ct: KemCiphertext,
  prefs: OnWirePrefs,
}
```

`seed_ct` is `wrap` to the peer intake `pk` of a `random32()` seed. `shared`
is `unwrap` of that `kem_ct`. Spawn secret:

```
spawn_secret = mac(ticket.secret,
  "chuchotez/1/spawn-secret" || sort32(shared_inviter, shared_invitee))
```

`sort32` concatenates the two 32-byte values in lexicographic order.
`shared_inviter` is the wrap the invitee sent to the inviter notice intake.
`shared_invitee` is the wrap the inviter sent to the invitee intro intake.

Fingerprint:

```
fingerprint = mac(expand(ticket.secret, established_label),
  canonical(intro_lo) || canonical(intro_hi) || spawn_secret)
```

`intro_lo` / `intro_hi` are the inviter and invitee intro values ordered by
`signing_pk` bytes. `established_label` is `"chuchotez/1/handshake-dm-established"` or
`"chuchotez/1/handshake-sync-established"`. `confirmationDigest` is
`text(fingerprint)`.

Spawned `conversation_id`:

```
child_id = mac(spawn_secret, "chuchotez/1/spawn-conversation-id")
```

The child DM or Sync conversation secret is `spawn_secret`. The handshake row
stays in `Confirming` until `confirmEstablished` / `rejectEstablished`; on
confirm it becomes a completed handshake and the child row is `Established`.

#### TxConfirm / TxReject

Handshake confirmation.

```
TxConfirm = {}
TxReject = {}
```

#### Chat payloads

```
TxText = {
  body: tstr .size (1..16384),
  reply_to: Tag / nil,
  expire_at: UnixSeconds / nil,
}

TxEdit = {
  target: Tag,
  body: tstr .size (1..16384),
}

TxRemove = {
  target: Tag,
}

TxReaction = {
  target: Tag,
  emoji: tstr .size (1..32),
  add: bool,
}

TxRead = { up_to: Tag }
TxDelivered = { up_to: Tag }

TxMedia = {
  mime: tstr .size (1..128),
  filename: tstr .size (1..256),
  hash: Tag,
  kind: Kind,
  address: Address,
  tag: Tag,
  caption: tstr .size (1..16384) / nil,
  reply_to: Tag / nil,
  expire_at: UnixSeconds / nil,
}
```

`body` in `TxText` and `TxEdit` is Unicode Normalization Form C. UTF-8 length
1..=16384; display length 1..=4096 characters; the bound that hits first
applies. `caption` uses the same bounds. `emoji` and `filename` are NFC.
`add` true inserts the reaction for `(sender signing_pk, target, emoji)`;
`add` false removes it. `expire_at` on a send is `nil` when local
`disappear_after` is `nil`, and ticked `now` plus that duration otherwise.
Query omits txs with `expire_at` ≤ ticked now. Fold MAY drop those txs from
the snapshot. Sync gossips unexpired txs. Relays follow the 72-bin TTL.
`reply_to` / `target` / `up_to` are `tx_id` values.

`TxMedia` locates sealed bytes at a blob mapper. `hash` is `hash` of the
plaintext. `kind`, `address`, and `tag` are the GET/PUT locator (example Kind
`blossom`). Mime allowlist is host UI. `sendMedia` mints one `TxMedia` per
attachment (length 1..=4). EngineState holds the pointer. Host cache holds
plaintext after `open`.

```
media_key = expand(conversation_secret, "chuchotez/1/media" || hash)
blob      = nonce || seal(media_key, nonce, media_bytes)
```

`nonce` is `random32()[0..12]`. After GET, `open` and check `hash`. Blob
bodies are mapper-native.

#### Sending-chain payloads

`TxAdvertise` publishes an encaps public key. `TxWrap` is `wrap` to a peer
`encaps_pk`. `TxAck.ratchet_ack` is `hash(encaps_pk)` or `hash(kem_ct)`.
These three sorts are always posted Persistent.

```
TxAdvertise = {
  encaps_pk: PublicKey,
}

TxWrap = {
  kem_ct: KemCiphertext,
}

TxAck = {
  ratchet_ack: Tag,
}
```

#### Name, photo, prefs

```
TxName = { name: DisplayName }
TxPhoto = { profile_pic: ProfilePic / nil }
TxPrefs = OnWirePrefs
```

#### Group membership payloads

```
TxGroupInvite = {
  group_id: ConversationId,
  owner_signing_pk: SigningPublicKey,
  persistents: [1*4 DurableChannel],
  ephemerals: [*4 EphemeralChannel],
  name: DisplayName,
  photo: ProfilePic / nil,
  invitee_signing_pk: SigningPublicKey,
  group_secret_ct: KemCiphertext,
}

TxGroupAccept = {
  group_id: ConversationId,
}

TxGroupReject = {
  group_id: ConversationId,
}

TxGroupRoster = {
  epoch: uint,
  members: [1*32 GroupMember],
  sig: Signature,
}

TxGroupLeave = {}
TxGroupKick = { signing_pk: SigningPublicKey }

TxGroupWrap = {
  to: SigningPublicKey,
  from: SigningPublicKey,
  kem_ct: KemCiphertext,
}

GroupMember = {
  signing_pk: SigningPublicKey,
  encryption_pk: PublicKey,
  send_tag_key: TagKey,
  eph_send_tag_key: TagKey,
}
```

`group_secret_ct` is `wrap` of `group_secret` to the invitee
`encryption_pk`. `TxGroupRoster.sig` is `sign(owner_sk, canonical(roster_body))`
where `roster_body` is `TxGroupRoster` with `sig` empty bytes of the Policy
`sig` length. Creator mints `group_secret` and `group_id` with `random32()`, genesis
Persistent/Ephemeral lists (omitted copies `Defaults`), and the creator
`send_tag_key` / `eph_send_tag_key`. On `acceptGroup` the invitee mints their
tag keys. `TxGroupRoster.members` carries every accepted member’s keys.

`TxGroupInvite` is small: no wrap list. After `TxGroupAccept` on that DM, the
owner posts `TxGroupRoster` on the Group Persistent and on each remaining
member’s DM, then one `TxGroupWrap` per remaining member `encryption_pk`.
Kick: owner signs a new `TxGroupRoster` without that `signing_pk`; survivors
mint new sending chains and one `TxGroupWrap` per remaining `encryption_pk`.

#### TxEngine records

Mutation of users, identities, Defaults, devices, and vault metadata. Engine
`conversation_id` is
`expand(expand(dek, "chuchotez/1/engine"), "chuchotez/1/engine-id")`. The DEK
stays in the vault header.

```
TxEngineInit = {}

TxEngineSetDefaults = {
  defaults: Defaults,
}

TxEngineCreateUser = {
  user_id: UserId,
}

TxEngineCreateIdentity = {
  user_id: UserId,
  identity_id: IdentityId,
  policy: Policy,
  encryption: KeyPair,
  signing: SigningKeyPair,
}

TxEngineDeleteUser = {
  user_id: UserId,
}

TxEngineDeleteIdentity = {
  user_id: UserId,
  identity_id: IdentityId,
}

TxEngineSetDisplayName = {
  user_id: UserId,
  identity_id: IdentityId,
  name: DisplayName,
}

TxEngineUnsetDisplayName = {
  user_id: UserId,
  identity_id: IdentityId,
}

TxEngineSetProfilePic = {
  user_id: UserId,
  identity_id: IdentityId,
  profile_pic: ProfilePic / nil,
}

TxEngineSetDeviceName = {
  name: DisplayName,
}

TxEngineKickDevice = {
  device_id: DeviceId,
}
```

An empty `EngineState` (no engine txs) accepts `createUser`, `setDefaults`,
and `receiveSyncTicket`. `createUser` and `setDefaults` mint `TxEngineInit`
if absent, then their payload. `TxEngineInit` is minted once.

#### HistoryItem

One durable row in query `messages`.

```
HistoryItem = {
  tx_id: Tag,
  sender: bstr,
  hlc: Hlc,
  payload: TxPayload,
  expire_at: UnixSeconds / nil,
}
```

`sender` is `SigningPublicKey` or `DeviceId`. `messages` is the most recent
1000 durable items after `(hlc, tx_id)` sort. Handshake payloads,
`TxAdvertise`, `TxWrap`, `TxAck`, `TxName`, `TxPhoto`, `TxPrefs`, `TxGroupInvite`,
`TxGroupAccept`, `TxGroupReject`, `TxGroupRoster`, `TxGroupWrap`, and engine
payloads are omitted from `messages`.

#### Sending chain

Each actor has a packet sending chain on a conversation: `root`, `C`,
`epoch`, `packet_seq`. HandshakeDm and HandshakeSync omit `actor_id` so the
invitee can derive `mk` from `Ticket.secret` alone:

```
root = expand(conversation_secret, chain_root_label)
C    = expand(root, chain_c_label)
epoch = 0
packet_seq = 0
```

DirectMessage, Group, and Synchronization mix `actor_id` (`SigningPublicKey`
or `DeviceId`):

```
root = expand(conversation_secret, chain_root_label || actor_id)
C    = expand(root, chain_c_label)
epoch = 0
packet_seq = 0
```

| Sort | `chain_root_label` | `chain_c_label` | `mix_label` |
| --- | --- | --- | --- |
| HandshakeDm | `"chuchotez/1/handshake-dm-chain-root"` | `"chuchotez/1/handshake-dm-chain-c"` | `"chuchotez/1/handshake-dm-kem-mix"` |
| HandshakeSync | `"chuchotez/1/handshake-sync-chain-root"` | `"chuchotez/1/handshake-sync-chain-c"` | `"chuchotez/1/handshake-sync-kem-mix"` |
| DirectMessage | `"chuchotez/1/dm-chain-root"` | `"chuchotez/1/dm-chain-c"` | `"chuchotez/1/dm-kem-mix"` |
| Group | `"chuchotez/1/group-chain-root"` | `"chuchotez/1/group-chain-c"` | `"chuchotez/1/group-kem-mix"` |
| Synchronization | `"chuchotez/1/sync-chain-root"` | `"chuchotez/1/sync-chain-c"` | `"chuchotez/1/sync-kem-mix"` |

```
mk = expand(C, mk_label || be<64>u(epoch) || be<64>u(packet_seq))
```

`mk_label` is `"chuchotez/1/packet-mk"`. After a durable packet, `C` becomes
`expand(C, "chuchotez/1/packet-step" || be<64>u(epoch) || be<64>u(packet_seq))`
and `packet_seq` becomes `packet_seq + 1`. Receive tries `mk` at the expected
`(epoch, packet_seq)`, then `packet_seq + 1` through `+ 50`, then up to 8
later epochs at `packet_seq` 0 through 50. Cache skipped `mk` values for
172800 ticked seconds. Delete a cached `mk` when every tx carried on that
packet is in the watermark.

Mix: when the FIFO holds 8 agreed `shared` values (wrap sent and
`ratchet_ack` received, and the wrap’s durable tx is in the watermark), every
8th durable packet is a mix: `root' = expand(root, mix_label || shared)`,
`epoch + 1`, `packet_seq` 0, and that mix’s `kem_ct` is omitted (consumed).
When a mix is due and the FIFO is empty, the send increments `packet_seq` on
the current epoch. EngineState keeps at most 8 unused advertised `sk` values
and drops the oldest unused when a ninth is advertised. Wrap only to an
`encaps_pk` whose advertise tx is in the watermark. A `shared` enters the
FIFO after a durable `ratchet_ack` of that `kem_ct` whose tx is in the
watermark. When durable packets since the last advertise, wrap, or ack still
owed reach 50, the Engine mints `TxAdvertise`, `TxWrap`, or `TxAck` as owed.

Ephemeral packets use
`eph_mk = expand(C, "chuchotez/1/eph-mk" || be<64>u(epoch) || be<64>u(packet_seq))`
with the next durable `packet_seq` and do not increment the durable chain.
A live durable packet (CRDT tx on Ephemeral) uses `eph_mk` the same way.

`poll.write_durable` and `poll.write_ephemeral` for a packet are only on the
device that minted it. Apply of a retransmitted or Sync-ingested tx updates
EngineState and does not enqueue that write. `PacketTyping`,
`PacketTypingActive`, `PacketPresence`, and `PacketPresenceActive`: every
`EphemeralChannel` in `ephemerals`. Handshake durable packets: every
`DurableChannel` in `persistents`. Group durable packets (including
`TxAdvertise`, `TxWrap`, and `TxAck`): every `DurableChannel` in
`persistents`. The 512-byte `body` is identical on every destination in that
write set.

#### Live path

DirectMessage and Synchronization durable txs (except `TxAdvertise`,
`TxWrap`, and `TxAck`, which are always Persistent and MAY also copy on
Ephemeral) use a live path when the conversation’s `ephemerals` list is
nonempty.

Coming online, the Engine MAY mint `PacketPresence` or `PacketPresenceActive`
on Ephemeral as a liveness probe. After a matching live ack from the required
peers, the conversation is **live** until 30 ticked seconds with no Ephemeral
packet from those peers. While live, and on the first durable send after idle,
the Engine enqueues the tx on every `EphemeralChannel` in `ephemerals`
immediately. A matching live ack is a `PacketXorAck` on an `EphemeralChannel`
whose `set_xor` equals the local set after this tx.

DM: the required peer is the other party. If that live ack arrives, the
Engine does not enqueue Persistent for that tx. If 3 ticked seconds pass
without it, `poll.write_durable` gains the same 512-byte packet on every
`DurableChannel` in `persistents`.

Synchronization: if every other linked device live-acks within 3 ticked
seconds, Persistent is omitted. Otherwise Persistent is enqueued (covers
devices that did not ack).

An empty `ephemerals` list skips the wait: durable sends are Persistent-only.
XOR mismatch heal MAY use Ephemeral while live; after 3 ticked seconds
without a heal answer, heal packets go to Persistent. A later has/wants
round recovers a tx that skipped Persistent (both parties still hold it on
disk).

```
body = nonce || seal(mk, nonce, pad(packed(PacketPlain), 484))
```

`nonce` is `random32()[0..12]`. For Ephemeral mapper bodies, `mk` is `eph_mk`.

---

## Serialization

A domain value is encoded to bytes in layers. `J` maps a domain value to a JSON
value. `canonical` is RFC 8785 of `J`. `parse` inverts `canonical`. Other
layers (`compress`, `text`, `seal`, `be<n>u`, `pad`, `hash`) map bytes to bytes,
or bytes to Unicode strings.

```
packed(value)           = compress(canonical(value))
wire(bytes)             = text(bytes)
lock(key, nonce, value) = seal(key, nonce, packed(value))
unlock(key, nonce, ct)  = parse(decompress(open(key, nonce, ct), max))
```

`max` is the uncompressed cap for that artifact. `unlock` refuses if `open`,
`decompress`, or `parse` refuses. `max` for `PacketPlain` / `DurableBody` is
65536. `max` for `Ticket` is 4096. `max` for
`VaultHeader` is 4096. `max` for a persist tx record is 1048576.

### JSON mapping `J`

`J` is defined on domain values. `J⁻¹` refuses extra object members, missing
members, and members whose JSON sort does not match this table.

| Domain | `J` |
| --- | --- |
| `Policy` | JSON string `"Classic"`, `"PostQuantum"`, or `"Hybrid"` |
| `ConversationSort` | JSON string of the enumerant |
| CDDL `uint` | JSON number of that integer |
| CDDL `bool` | JSON boolean |
| CDDL `nil` | JSON `null` |
| CDDL `tstr` | JSON string of that Unicode value |
| CDDL `bstr` | JSON string `text(bytes)` |
| CDDL array | JSON array of `J(T)` in list order |
| CDDL map `{ … }` | JSON object: one member per field, name = field name, value = `J(field)` |

Top-level artifacts that travel as a JSON document also carry a discriminator
member `"type"` with a constant string. Nested maps (`DurableChannel`,
`EphemeralChannel`, Wake, OnWirePrefs, Defaults, Hlc, GroupMember, KeyPair,
SigningKeyPair, and fields inside `DurableBody`) omit
`"type"`. `J⁻¹`
refuses an unknown `"type"`.

| Domain sort | `"type"` |
| --- | --- |
| Ticket | `"v1-handshake-ticket"` |
| PacketTxFragMore | `"v1-packet-tx-frag-more"` |
| PacketTxFragLast | `"v1-packet-tx-frag-last"` |
| PacketXorAck | `"v1-packet-xor-ack"` |
| PacketHealHalfXor | `"v1-packet-heal-half-xor"` |
| PacketHealWant | `"v1-packet-heal-want"` |
| PacketHealHave | `"v1-packet-heal-have"` |
| PacketTyping | `"v1-packet-typing"` |
| PacketTypingActive | `"v1-packet-typing-active"` |
| PacketPresence | `"v1-packet-presence"` |
| PacketPresenceActive | `"v1-packet-presence-active"` |
| DurableBody | `"v1-durable-body"` |
| TxNotice | `"v1-handshake-notice"` |
| TxInviterIntro | `"v1-handshake-inviter-intro"` |
| TxInviteeIntro | `"v1-handshake-invitee-intro"` |
| TxConfirm | `"v1-handshake-confirm"` |
| TxReject | `"v1-handshake-reject"` |
| TxText | `"v1-text"` |
| TxEdit | `"v1-edit"` |
| TxRemove | `"v1-remove"` |
| TxReaction | `"v1-reaction"` |
| TxRead | `"v1-read"` |
| TxDelivered | `"v1-delivered"` |
| TxMedia | `"v1-media"` |
| TxAdvertise | `"v1-advertise"` |
| TxWrap | `"v1-wrap"` |
| TxAck | `"v1-ack"` |
| TxName | `"v1-name"` |
| TxPhoto | `"v1-photo"` |
| TxPrefs | `"v1-prefs"` |
| TxGroupInvite | `"v1-group-invite"` |
| TxGroupAccept | `"v1-group-accept"` |
| TxGroupReject | `"v1-group-reject"` |
| TxGroupRoster | `"v1-group-roster"` |
| TxGroupWrap | `"v1-group-wrap"` |
| TxGroupLeave | `"v1-group-leave"` |
| TxGroupKick | `"v1-group-kick"` |
| TxEngineInit | `"v1-engine-init"` |
| TxEngineSetDefaults | `"v1-engine-set-defaults"` |
| TxEngineCreateUser | `"v1-engine-create-user"` |
| TxEngineCreateIdentity | `"v1-engine-create-identity"` |
| TxEngineDeleteUser | `"v1-engine-delete-user"` |
| TxEngineDeleteIdentity | `"v1-engine-delete-identity"` |
| TxEngineSetDisplayName | `"v1-engine-set-display-name"` |
| TxEngineUnsetDisplayName | `"v1-engine-unset-display-name"` |
| TxEngineSetProfilePic | `"v1-engine-set-profile-pic"` |
| TxEngineSetDeviceName | `"v1-engine-set-device-name"` |
| TxEngineKickDevice | `"v1-engine-kick-device"` |
| VaultHeader | `"v1-vault-header"` |

**Packet.** Mapper body:

```
nonce   byte[12]
body    = nonce || seal(mk, nonce, pad(packed(PacketPlain), 484))
```

Length is 512.

**Ticket host string.** `text(packed(Ticket))`.

**Persist tx record.** The host appends raw bytes. `key` is the unlocked DEK.

```
seq     integer    0 ≤ seq < 2^64 − 1
nonce   byte[12]   be<32>u(1) || be<64>u(seq)
record  = nonce || lock(key, nonce, DurableBody)
```

`1` in the high four bytes is persist format version. `seq` is unique for that
DEK. Fold includes only watermark txs. The command log holds durable txs not
in the watermark plus persist seqs of engine txs still unfolder.

---

## Library

The library is bound to `Defaults`. Named operations mint transactions with
host `Rng` when they need entropy. `ingestPacket` / merge of a complete
`DurableBody` is deterministic. Mutators return persist records (`nonce ||
lock` with the unlocked DEK) for new durable txs in merge order, plus
`poll.write_durable` and `poll.write_ephemeral` packets on the minting
device, plus `poll.blob_put` when `sendMedia` minted pointers. Reload is `applyFolded` of the folded snapshot, then `apply` of each
log record. `tick` is the clock. `poll` is the `DurableChannel` / `EphemeralChannel` / blob and Tag query for
that ticked now. Query `Conversation` omits
ticket secret, DEK, intake `sk`, identity `sk`, `send_tag_key`,
`eph_send_tag_key`, `BinProgress`, sending-chain secrets, encaps `sk`s, FIFO,
skip-ahead `mk`s, and Wake `p256dh` and `auth`. TypeScript field names are
camelCase of the CDDL names.

```ts
declare const brand: unique symbol
type Brand<T, B extends string> = T & { readonly [brand]: B }

type Random32 = Brand<Uint8Array, "Random32">
type UserId = Brand<Uint8Array, "UserId">
type IdentityId = Brand<Uint8Array, "IdentityId">
type ConversationId = Brand<Uint8Array, "ConversationId">
type DeviceId = Brand<Uint8Array, "DeviceId">
type Tag = Brand<Uint8Array, "Tag">
type PublicKey = Brand<Uint8Array, "PublicKey">
type SigningPublicKey = Brand<Uint8Array, "SigningPublicKey">
type UnixSeconds = number
type PersistBytes = Uint8Array
type Policy = "Classic" | "PostQuantum" | "Hybrid"
type Kind = string
type Address = string
type DisplayName = string
type DurableChannel = Brand<{ kind: Kind; address: Address }, "DurableChannel">
type EphemeralChannel = Brand<{ kind: Kind; address: Address }, "EphemeralChannel">
type EngineState = Brand<object, "EngineState">

type Rng = { random32(): Random32 }

type Result<T, E = EngineError> =
  | { ok: true; value: T }
  | { ok: false; error: E }

type EngineError =
  | { code: "WrongPhase" }
  | { code: "MalformedTicket" }
  | { code: "ExpiresNotAfterNow" }
  | { code: "UnknownIds" }
  | { code: "MalformedDisplayName" }
  | { code: "ChannelBounds" }
  | { code: "MalformedPersist" }
  | { code: "NotTicked" }
  | { code: "ClockWentBackwards" }
  | { code: "UnknownTag" }
  | { code: "UnknownWrite" }
  | { code: "BodyTooLarge" }
  | { code: "MalformedPayload" }
  | { code: "UnlockFailed" }
  | { code: "Locked" }
  | { code: "MalformedWake" }
  | { code: "EmptyEngineRequired" }
  | { code: "NotOwner" }
  | { code: "MemberCap" }
  | { code: "DuplicateMember" }
  | { code: "Equivocation" }

type NotificationPrivacy = "name" | "preview" | "silent"
type Wake = {
  endpoint: string
  p256dh: Uint8Array
  auth: Uint8Array
  vapidPk: Uint8Array | null
}
type OnWirePrefs = {
  readReceipts: boolean
  onlineVisible: boolean
  sendTyping: boolean
  disappearAfter: UnixSeconds | null
  wake: Wake | null
}
type Defaults = {
  persistents: DurableChannel[]
  ephemerals: EphemeralChannel[]
  readReceipts: boolean
  onlineVisible: boolean
  sendTyping: boolean
  disappearAfter: UnixSeconds | null
  publishWake: boolean
  notificationPrivacy: NotificationPrivacy
}
type ConversationPrefs = {
  readReceipts: boolean
  onlineVisible: boolean
  sendTyping: boolean
  disappearAfter: UnixSeconds | null
  notificationPrivacy: NotificationPrivacy
  wake: Wake | null
}
type QueryPeerPrefs = {
  readReceipts: boolean
  onlineVisible: boolean
  sendTyping: boolean
  disappearAfter: UnixSeconds | null
  wakeEndpoint: string | null
  vapidPk: Uint8Array | null
}
type QueryLocalPrefs = QueryPeerPrefs & {
  notificationPrivacy: NotificationPrivacy
}
type PingTarget = {
  endpoint: string
  p256dh: Uint8Array
  auth: Uint8Array
  vapidPk: Uint8Array | null
}
type UnlockSecret =
  | { kind: "passphrase"; value: string }
  | { kind: "prf"; value: Uint8Array }

type ConversationRef = {
  userId: UserId
  identityId: IdentityId
  conversationId: ConversationId
}

type MutateOk = {
  state: EngineState
  persist: PersistBytes[]
  pings: PingTarget[]
}
type CreateUserOk = MutateOk & { userId: UserId }
type CreateIdentityOk = MutateOk & { identityId: IdentityId }
type CreateInviteOk = MutateOk & { conversationId: ConversationId }
type ReceiveTicketOk = MutateOk & { conversationId: ConversationId }
type CreateGroupOk = MutateOk & { conversationId: ConversationId }
type CreateSyncOk = MutateOk & { conversationId: ConversationId }
type FoldOk = MutateOk & { snapshot: PersistBytes; seq: number }
type WrapDekOk = { header: Uint8Array }

type DurableLocator = { channel: DurableChannel; tag: Tag }
type EphemeralLocator = { channel: EphemeralChannel; tag: Tag }
type DurableWrite = { channel: DurableChannel; tag: Tag; body: Uint8Array }
type EphemeralWrite = { channel: EphemeralChannel; tag: Tag; body: Uint8Array }
type BlobPut = { kind: Kind; address: Address; tag: Tag; body: Uint8Array }
type BlobGet = { kind: Kind; address: Address; tag: Tag }
type BlockedMissing = "DisplayName"
type BlockedIdentity = {
  userId: UserId
  identityId: IdentityId
  missing: BlockedMissing
}
type Poll = {
  list: DurableLocator[]
  listenDurable: DurableLocator[]
  listenEphemeral: EphemeralLocator[]
  writeDurable: DurableWrite[]
  writeEphemeral: EphemeralWrite[]
  blobPut: BlobPut[]
  blobGet: BlobGet[]
  blocked: BlockedIdentity[]
}

type MediaDraft = {
  mediaBytes: Uint8Array
  mime: string
  filename: string
}

type HistoryItem = {
  txId: Uint8Array
  sender: Uint8Array
  hlc: { wallMs: number; counter: number }
  payload: unknown
  expireAt: UnixSeconds | null
}

type ConversationListRow = {
  conversationId: ConversationId
  conversation: Conversation
}

type ConversationSort =
  | "HandshakeDm"
  | "HandshakeSync"
  | "DirectMessage"
  | "Group"
  | "Synchronization"
  | "Engine"

type HandshakeInviter =
  | { phase: "InviteCreated"; expires: UnixSeconds }
  | { phase: "NoticePinned"; expires: UnixSeconds }
  | { phase: "IntroductionMinted"; expires: UnixSeconds }
  | { phase: "Confirming"; expires: UnixSeconds; confirmationDigest: string }

type HandshakeInvitee =
  | { phase: "TicketReceived" }
  | { phase: "InviteReceived"; policy: Policy; expires: UnixSeconds }
  | { phase: "IntroductionMinted"; policy: Policy; expires: UnixSeconds }
  | { phase: "IntroductionSent"; policy: Policy; expires: UnixSeconds }
  | { phase: "Confirming"; policy: Policy; expires: UnixSeconds; confirmationDigest: string }

type DmEstablished = {
  name: DisplayName
  profilePic: Uint8Array | null
  encryptionPk: PublicKey
  signingPk: SigningPublicKey
  persistents: DurableChannel[]
  ephemerals: EphemeralChannel[]
  confirmationDigest: string
  lastActive: UnixSeconds | null
  typing: { composing: boolean; lastActive: UnixSeconds } | null
  presence: { lastActive: UnixSeconds } | null
  readUpTo: Uint8Array | null
  deliveredUpTo: Uint8Array | null
  localPrefs: QueryLocalPrefs
  peerPrefs: QueryPeerPrefs
  messages: HistoryItem[]
}

type GroupMemberQuery = {
  signingPk: SigningPublicKey
  encryptionPk: PublicKey
  name: DisplayName
  photo: Uint8Array | null
  typing: { composing: boolean; lastActive: UnixSeconds } | null
  presence: { lastActive: UnixSeconds } | null
}

type GroupPending = {
  signingPk: SigningPublicKey
  fromConversationId: ConversationId
  name: DisplayName
  photo: Uint8Array | null
}

type GroupEstablished = {
  name: DisplayName
  photo: Uint8Array | null
  ownerSigningPk: SigningPublicKey
  members: GroupMemberQuery[]
  pending: GroupPending[]
  persistents: DurableChannel[]
  ephemerals: EphemeralChannel[]
  lastActive: UnixSeconds | null
  localPrefs: QueryLocalPrefs
  messages: HistoryItem[]
}

type GroupOffer = {
  name: DisplayName
  photo: Uint8Array | null
  ownerSigningPk: SigningPublicKey
  fromConversationId: ConversationId
}

type SyncMemberQuery = {
  deviceId: DeviceId
  signingPk: SigningPublicKey
  encryptionPk: PublicKey
  name: DisplayName
  lastActive: UnixSeconds | null
}

type SyncEstablished = {
  deviceName: DisplayName
  members: SyncMemberQuery[]
  persistents: DurableChannel[]
  ephemerals: EphemeralChannel[]
  lastActive: UnixSeconds | null
}

type FailedReason =
  | { reason: "PolicyNotAccepted"; policy: Policy }
  | { reason: "InviteExpired"; expires: UnixSeconds }
  | { reason: "NoticeUnlockFailed" }
  | { reason: "NoticeConflict" }
  | { reason: "IntroUnlockFailed" }
  | { reason: "IntroVerifyFailed" }
  | { reason: "DuplicateIntro" }
  | { reason: "ConfirmationRejected" }
  | { reason: "Equivocation" }
  | { reason: "OfferRejected" }
  | { reason: "Kicked" }
  | { reason: "Left" }

type Handshake =
  | ({ role: "Inviter" } & HandshakeInviter)
  | ({ role: "Invitee" } & HandshakeInvitee)
  | ({ role: "Failed" } & FailedReason)

type DirectMessageQuery =
  | { phase: "Established"; value: DmEstablished }
  | { phase: "Failed"; value: FailedReason }

type GroupQuery =
  | { phase: "GroupOffer"; value: GroupOffer }
  | { phase: "GroupEstablished"; value: GroupEstablished }
  | { phase: "GroupFailed"; value: FailedReason }

type SynchronizationQuery =
  | { phase: "Handshake"; value: Handshake }
  | { phase: "SyncEstablished"; value: SyncEstablished }
  | { phase: "Failed"; value: FailedReason }

type Conversation =
  | { sort: "HandshakeDm"; value: Handshake }
  | { sort: "HandshakeSync"; value: Handshake }
  | { sort: "DirectMessage"; value: DirectMessageQuery }
  | { sort: "Group"; value: GroupQuery }
  | { sort: "Synchronization"; value: SynchronizationQuery }

declare class Engine {
  constructor(defaults: Defaults)
  unlock(header: Uint8Array, secret: UnlockSecret): Result<void>
  lock(): void
  wrapDek(secret: UnlockSecret): Result<WrapDekOk>
  fold(state: EngineState): Result<FoldOk>
  getDefaults(state: EngineState): Result<Defaults>
  setDefaults(state: EngineState, defaults: Defaults): Result<MutateOk>
  createUser(state: EngineState, rng: Rng): Result<CreateUserOk>
  createIdentity(
    state: EngineState,
    rng: Rng,
    userId: UserId,
    policy: Policy,
  ): Result<CreateIdentityOk>
  deleteUser(state: EngineState, userId: UserId): Result<MutateOk>
  deleteIdentity(
    state: EngineState,
    userId: UserId,
    identityId: IdentityId,
  ): Result<MutateOk>
  deleteConversation(state: EngineState, ids: ConversationRef): Result<MutateOk>
  tick(state: EngineState, now: UnixSeconds): Result<MutateOk>
  poll(state: EngineState): Result<Poll>
  ingestList(
    state: EngineState,
    rng: Rng,
    channel: DurableChannel,
    tag: Tag,
    bodies: Uint8Array[],
  ): Result<MutateOk>
  ingestPacket(
    state: EngineState,
    rng: Rng,
    channel: DurableChannel | EphemeralChannel,
    tag: Tag,
    body: Uint8Array,
  ): Result<MutateOk>
  writeAck(
    state: EngineState,
    channel: DurableChannel | EphemeralChannel,
    tag: Tag,
    body: Uint8Array,
  ): Result<MutateOk>
  writeBlobAck(
    state: EngineState,
    kind: Kind,
    address: Address,
    tag: Tag,
    body: Uint8Array,
  ): Result<MutateOk>
  createInvite(
    state: EngineState,
    rng: Rng,
    userId: UserId,
    identityId: IdentityId,
    expires: UnixSeconds,
    persistents?: DurableChannel[],
  ): Result<CreateInviteOk>
  receiveTicket(
    state: EngineState,
    rng: Rng,
    userId: UserId,
    identityId: IdentityId,
    ticketHostString: string,
  ): Result<ReceiveTicketOk>
  createSyncInvite(
    state: EngineState,
    rng: Rng,
    policy: Policy,
    expires: UnixSeconds,
    deviceName: string,
    persistents?: DurableChannel[],
  ): Result<CreateSyncOk>
  receiveSyncTicket(
    state: EngineState,
    rng: Rng,
    ticketHostString: string,
  ): Result<ReceiveTicketOk>
  setDeviceName(state: EngineState, rng: Rng, name: string): Result<MutateOk>
  kickDevice(state: EngineState, rng: Rng, deviceId: DeviceId): Result<MutateOk>
  leaveSync(state: EngineState, rng: Rng): Result<MutateOk>
  setDisplayName(
    state: EngineState,
    rng: Rng,
    userId: UserId,
    identityId: IdentityId,
    name: string,
  ): Result<MutateOk>
  unsetDisplayName(
    state: EngineState,
    userId: UserId,
    identityId: IdentityId,
  ): Result<MutateOk>
  setProfilePic(
    state: EngineState,
    rng: Rng,
    userId: UserId,
    identityId: IdentityId,
    profilePic: Uint8Array | null,
  ): Result<MutateOk>
  setConversationPrefs(
    state: EngineState,
    rng: Rng,
    ids: ConversationRef,
    prefs: ConversationPrefs,
  ): Result<MutateOk>
  confirmEstablished(state: EngineState, rng: Rng, ids: ConversationRef): Result<MutateOk>
  rejectEstablished(state: EngineState, rng: Rng, ids: ConversationRef): Result<MutateOk>
  createGroup(
    state: EngineState,
    rng: Rng,
    userId: UserId,
    identityId: IdentityId,
    contactConversationIds: ConversationId[],
    name: string,
    photo: Uint8Array | null,
  ): Result<CreateGroupOk>
  addGroupMember(
    state: EngineState,
    rng: Rng,
    ids: ConversationRef,
    contactConversationId: ConversationId,
  ): Result<MutateOk>
  acceptGroup(state: EngineState, rng: Rng, ids: ConversationRef): Result<MutateOk>
  rejectGroup(state: EngineState, rng: Rng, ids: ConversationRef): Result<MutateOk>
  kickGroupMember(
    state: EngineState,
    rng: Rng,
    ids: ConversationRef,
    signingPk: SigningPublicKey,
  ): Result<MutateOk>
  leaveGroup(state: EngineState, rng: Rng, ids: ConversationRef): Result<MutateOk>
  setGroupName(
    state: EngineState,
    rng: Rng,
    ids: ConversationRef,
    name: string,
  ): Result<MutateOk>
  setGroupPhoto(
    state: EngineState,
    rng: Rng,
    ids: ConversationRef,
    photo: Uint8Array | null,
  ): Result<MutateOk>
  sendText(
    state: EngineState,
    rng: Rng,
    ids: ConversationRef,
    body: string,
    replyTo: Uint8Array | null,
  ): Result<MutateOk>
  sendMedia(
    state: EngineState,
    rng: Rng,
    ids: ConversationRef,
    attachments: MediaDraft[],
    replyTo: Uint8Array | null,
    caption: string | null,
  ): Result<MutateOk>
  editMessage(
    state: EngineState,
    rng: Rng,
    ids: ConversationRef,
    target: Uint8Array,
    body: string,
  ): Result<MutateOk>
  removeMessage(
    state: EngineState,
    rng: Rng,
    ids: ConversationRef,
    target: Uint8Array,
  ): Result<MutateOk>
  sendReaction(
    state: EngineState,
    rng: Rng,
    ids: ConversationRef,
    target: Uint8Array,
    emoji: string,
    add: boolean,
  ): Result<MutateOk>
  sendTyping(
    state: EngineState,
    rng: Rng,
    ids: ConversationRef,
    composing: boolean,
  ): Result<MutateOk>
  sendRead(
    state: EngineState,
    rng: Rng,
    ids: ConversationRef,
    upTo: Uint8Array,
  ): Result<MutateOk>
  sendDelivered(
    state: EngineState,
    rng: Rng,
    ids: ConversationRef,
    upTo: Uint8Array,
  ): Result<MutateOk>
  sendPresence(state: EngineState, rng: Rng, ids: ConversationRef): Result<MutateOk>
  listUsers(state: EngineState): Result<UserId[]>
  listIdentities(state: EngineState, userId: UserId): Result<IdentityId[]>
  listConversations(
    state: EngineState,
    userId: UserId,
    identityId: IdentityId,
  ): Result<ConversationListRow[]>
  getConversation(
    state: EngineState,
    userId: UserId,
    identityId: IdentityId,
    conversationId: ConversationId,
  ): Result<Conversation>
  ticketHostString(state: EngineState, ids: ConversationRef): Result<string>
  confirmationDigest(state: EngineState, ids: ConversationRef): Result<string>
  applyFolded(snapshot: PersistBytes): Result<EngineState>
  apply(state: EngineState, persist: PersistBytes): Result<EngineState>
}
```

`listConversations` includes that identity’s handshake, DM, and Group rows
and, when present, the engine HandshakeSync / Synchronization rows (same ids
for every identity). `phase` is the query variant name (`InviteCreated`,
`GroupOffer`, `GroupEstablished`, `SyncEstablished`, …). Handshake and spawned
DM are two rows. `createSyncInvite` mints `DeviceId` with `random32()` on the
first call and device encryption/signing keygen for that Policy. `sendMedia` attachments length is 1..=4; each attachment is one `TxMedia`
pointer. `packed(DurableBody)` that
cannot split into ≤ 64 fragments of packet `frag` is `BodyTooLarge`.
`createInvite` omitted `persistents` copies `Defaults.persistents`.
Channel lists freeze at mint. `createInvite` MUST refuse when `expires` is less than or equal to the ticked
now. `createIdentity` keygen uses that identity’s `Policy` for the lifetime
of the identity. `createInvite` and
`createGroup` use the identity Policy. `createSyncInvite` uses its Policy
argument for device keygen and Sync packets. A `TxNotice.policy` that differs
from the receiving identity Policy (DM) or the Sync Policy (Sync handshake)
stores `PolicyNotAccepted`. `kind`+`address` uniqueness within `persistents`
and within `ephemerals`, `persistents` length 1..=4, and `ephemerals` length
0..=4, are `ChannelBounds`. A first successful `tick` is required before
`poll` and mints. `tick` with `now` less than the last ticked now is
`ClockWentBackwards`. Equal now is ok. `MalformedPayload` is a `body`, `caption`, `emoji`,
`filename`, `mime`, or profile WebP that fails its bounds or RIFF/WEBP header.
`MalformedWake` is a `Wake` whose `endpoint` fails `https:`, printable ASCII,
NFC, or length 1..=2048, or whose `p256dh` / `auth` lengths differ from 65
and 16. Intro, `createGroup`, `acceptGroup`, and `createSyncInvite` require a
`DisplayName` (`poll.blocked`). `createGroup` `contactConversationIds` length
is 1..=31 Established DMs on that identity with unique peer `signing_pk`.
Owner is in the roster immediately (`GroupEstablished`). Parallel
`TxGroupInvite` on each named DM. Member cap 32 including owner. Device cap 5
including the inviter. `addGroupMember` of a pending invitee is `WrongPhase`.
`kickGroupMember` on a `GroupOffer` contact drops the offer. `kickDevice` of
this device is `WrongPhase`; `leaveSync` unlinks this device. Last remaining
device after leave/kick is legal. `receiveSyncTicket` is `EmptyEngineRequired`
unless EngineState has no users. Until an engine `TxEngineCreateUser` tx is merged,
`getConversation` and `listConversations` for that Sync handshake use `userId`
and `identityId` of 32 zero bytes. `setDeviceName` is required after
`TicketReceived` before intro mint. `fold` is `WrongPhase` when `seq` includes
a persist record whose tx is outside the watermark. Fold MAY drop txs with
`expire_at` ≤ ticked now from the snapshot. `wrapDek` returns a
`VaultHeader` wrapping the held DEK. `setConversationPrefs` on a Group:
receipts, typing, online, and wake are this member’s `TxPrefs`;
`disappear_after` is owner-only group-wide; `notification_privacy` is
local-only. `setGroupName` / `setGroupPhoto` are owner-only. `deleteIdentity`
posts `TxGroupLeave` on every Group that identity is in, then drops DMs and
the identity. `deleteUser` does that for every identity. `deleteConversation`
on Group Established posts `TxGroupLeave` then drops the row; on `GroupOffer`
it is `rejectGroup`; on DM Established it drops the local row; on a handshake
it drops the pin. Kick of a Sync device drops Sync membership and rekeys Sync
sending chains. Identity keys in the CRDT stay. `MutateOk.pings` for a durable
DM tx is the peer `Wake` when set; for a Group durable tx, every member whose
last `TxPrefs.wake` is set.

`sendText` and the other session send methods require DM `Established` or
Group `GroupEstablished` (`WrongPhase`). `sendPresence` / `sendTyping` are
also legal on Synchronization `SyncEstablished`. `sendTyping` mints
`PacketTypingActive` when local `online_visible` is on, else `PacketTyping`.
`sendPresence` mints `PacketPresenceActive` or `PacketPresence` the same way.
DM and Sync durable sends follow the live path: Ephemeral first, Persistent
after 3 ticked seconds without the required live XOR-acks, omitted Persistent
when those acks arrive (`TxAdvertise`, `TxWrap`, and `TxAck` always
Persistent). Group durable sends are Persistent only. Host retries `post` /
`send` / blob PUT until success, then `writeAck` / `writeBlobAck`. Mapper
credentials stay with the host adapter.

---

## Mappers

A mapper implements one `Kind`. Packet mappers take `DurableChannel` or
`EphemeralChannel` and Tag from `poll`. Blob mappers take `kind`, `address`,
and `tag` from `poll.blob_put` / `poll.blob_get`. Credentials stay with the
host adapter.

```ts
interface DurableMapper {
  post(channel: DurableChannel, tag: Tag, body: Uint8Array): Promise<void>
  list(channel: DurableChannel, tag: Tag): Promise<Uint8Array[]>
  listen(channel: DurableChannel, tag: Tag): AsyncIterable<Uint8Array>
}

interface EphemeralMapper {
  send(channel: EphemeralChannel, tag: Tag, body: Uint8Array): Promise<void>
  listen(channel: EphemeralChannel, tag: Tag): AsyncIterable<Uint8Array>
}

interface BlobMapper {
  put(kind: Kind, address: Address, tag: Tag, body: Uint8Array): Promise<void>
  get(kind: Kind, address: Address, tag: Tag): Promise<Uint8Array>
}
```

`list` returns the complete stored snapshot for that `DurableChannel` and Tag
(pagination stays inside the mapper). Bodies whose TimeBin is less than
`W - 71` MAY be omitted. The host calls `ingestList` only after that snapshot
is in hand. A full list completes that bin in `BinProgress`. `listen` yields
512-byte bodies as they arrive. The host starts and stops durable `listen` by
set-diff of `poll.listen_durable`, and ephemeral `listen` by set-diff of
`poll.listen_ephemeral`. Durable `post` and ephemeral `send` take the
512-byte packet. The host retries `post` / `send` / `put` until success, then
`writeAck` / `writeBlobAck`. Packet flooding is a host/mapper concern.

---

## State machine

Query `Conversation` is library state. It has no on-wire `"type"`
discriminator.

`tick` stores `Failed` `InviteExpired` when the ticked `now` is greater than
`expires` and the handshake is still pre-confirm. Later ingest / confirm /
reject on that handshake is `WrongPhase`.

| From | Method | To |
| --- | --- | --- |
| (none) | `createInvite` / `createSyncInvite` | Inviter `InviteCreated` |
| `InviteCreated` | `writeAck` of the full invite-tag packet set | `NoticePinned` |
| `NoticePinned` | `ingestList` / `ingestPacket` of a valid `TxInviteeIntro` | `IntroductionMinted` |
| `IntroductionMinted` | `writeAck` of the full intro packet set | Inviter `Confirming` |
| (none) | `receiveTicket` / `receiveSyncTicket` | Invitee `TicketReceived` |
| `TicketReceived` | valid `TxNotice` | `InviteReceived` |
| `InviteReceived` | ingest or `setDisplayName` / `setDeviceName` mint | `IntroductionMinted` |
| Invitee `IntroductionMinted` | `writeAck` of the full intro set | `IntroductionSent` |
| `IntroductionSent` | valid `TxInviterIntro` | Invitee `Confirming` |
| `Confirming` | `confirmEstablished` | child `Established` / `SyncEstablished`; handshake complete |
| `Confirming` | `rejectEstablished` | `Failed` `ConfirmationRejected` |

A valid `TxInviteeIntro` also mints the inviter `TxInviterIntro` and consumes
the ticket (notice writes stop; invite-tag list continues until that intro is
watermarked). A valid
`TxInviterIntro` also computes `fingerprint`. An empty invite-tag snapshot leaves
`TicketReceived`. `createGroup` → `GroupEstablished` with `pending` offers.
`acceptGroup` on `GroupOffer` posts `TxGroupAccept`; owner then posts
`TxGroupRoster` and `TxGroupWrap` txs. `rejectGroup` stores `OfferRejected` on the invitee. Ingest
of a roster that omits local `signing_pk` stores `Kicked`. Ingest of
`TxGroupLeave` for self after local delete stores `Left`.

| Ingest | Failure stored |
| --- | --- |
| Notice | `PolicyNotAccepted` when `TxNotice.policy` disagrees with the identity or Sync Policy |
| Notice | `NoticeUnlockFailed` when `open`, `decompress`, or `parse` refuses |
| Notice | `NoticeConflict` when a second well-formed Notice disagrees with the stored one |
| Intro | `IntroUnlockFailed` or `IntroVerifyFailed` |
| Intro | `DuplicateIntro` when a second valid intro from that role arrives |
| Any durable | `Equivocation` when `tx_id` matches a stored payload that disagrees |

A wrong-phase call is `EngineError` `WrongPhase`; the conversation is
unchanged. A malformed ticket is `MalformedTicket`; no conversation row is
created. `packed(PacketPlain)` that exceeds 484 is `BodyTooLarge`.

---

## Vault

The host keeps three files: a vault header, a folded `EngineState` snapshot,
and a log of durable txs not in the watermark.

```
VaultHeader = {
  salt: bstr .size 16,
  m: uint,
  t: uint,
  p: uint,
  passphrase_nonce: bstr .size 12 / nil,
  passphrase_wrapped_dek: bstr / nil,
  prf_nonce: bstr .size 12 / nil,
  prf_wrapped_dek: bstr / nil,
}
```

v1 `m` is 19456 (19 MiB), `t` is 2, `p` is 1. At least one wrap is present.
The DEK is 32 bytes and seals every persist record and the folded snapshot.
Passphrase is Unicode Normalization Form C, UTF-8 length 8..=1024.

```
kek_passphrase = argon2id(passphrase, salt, m, t, p)
kek_prf        = 32-byte host secret
passphrase_wrapped_dek = seal(kek_passphrase, passphrase_nonce, dek)
prf_wrapped_dek        = seal(kek_prf, prf_nonce, dek)
```

`kek_prf` is a WebAuthn PRF output. The host prefers the PRF wrap when the
platform supplies it. Changing the passphrase or PRF re-wraps the same DEK
and writes a new header (`salt` is fresh). Header bytes:

```
header file = packed(VaultHeader)
```

The host mints `dek` with `random32()`, builds `VaultHeader`, writes the
header file, then `unlock`s. `Engine.unlock` derives the matching KEK, `open`s
the wrap, and holds the DEK. After Sync dump-by-heal, `wrapDek` returns a
header for that held DEK. `Engine.lock` zeros the DEK. `fold` writes a
snapshot sealed with the DEK; the host stores those bytes as the folded file
and drops log records whose txs are in the watermark. Folded file:

```
fold_nonce   byte[12]   be<32>u(1) || be<64>u(seq)
snapshot     = fold_nonce || seal(dek, fold_nonce, folded_bytes)
```

`folded_bytes` is the Engine snapshot of watermark txs through `seq`. Fold MAY
omit txs with `expire_at` ≤ ticked now. `1` in
the high four bytes is folded-snapshot format version. Reload is `unlock`,
`applyFolded` of the snapshot, then `apply` of remaining log records.

The inviter wraps DEK to the invitee device `encryption_pk` (from the invitee
intro) as part of Sync handshake completion so the invitee can `open` persist
and packets after spawn.

---

## Host

The host supplies `Rng.random32`, writes the vault header, folded snapshot,
and tx log, and talks to packet and blob mappers. It chooses the medium for
the `Ticket` host string. It supplies
`expires` at `createInvite` / `createSyncInvite`. Each cycle is `tick` with
the current `UnixSeconds`, then `poll`, then mapper `list` / `listen` /
`post` / `send` / blob GET/PUT, then `ingestList` /
`ingestPacket` / `writeAck` / `writeBlobAck`. Named local
calls MAY run at any time the Engine accepts them. A durable packet’s 512
bytes are the same on every destination `DurableChannel` in that
`poll.write_durable` set, or every `EphemeralChannel` in
`poll.write_ephemeral`, per the live path. An ephemeral typing or presence
packet’s 512 bytes are the same on every destination `EphemeralChannel`. For
each `MutateOk.pings` row the host POSTs to `endpoint` with
RFC 8291 of an empty plaintext body. Optional VAPID JWT uses `vapid_pk` when
present. `https:` only. Before `receiveSyncTicket` on a device that already
has a vault, the host warns that pairing replaces that vault and uses a fresh
Engine.
