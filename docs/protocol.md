# Chuchotez

This page is the Chuchotez protocol: the information model, encodings, and
interfaces. A library, host, or mapper in any language implements this page.
The [book](book.md) documents the locked Rust crate. rustdoc is that crate’s
API reference.

**Shipped** work is in the crates. **Planned** work is decided and waiting on a
slice. This page is ahead of the crates: a later slice will propagate it.

The **host** is the app. It supplies `random32`, stores the local log, and talks
to the network. Chuchotez builds the envelopes.

## Roles

The **inviter** starts a direct-message conversation. The **invitee** joins it.

A **`Policy`** is `Classic`, `PostQuantum`, or `Hybrid`. It chooses the
public-key algorithms in [Algorithms](#algorithms).

The **library** is the handle bound to one Policy (`Engine` in the reference
crate) and the functions below. **`EngineState`** is the host’s saved users,
identities, and conversations. The library derives tags and time bins. The
host and each mapper see Channel, Tag, and bodies.

A **mapper** talks to one kind of Channel (Billboard, Mailbox, or Wire). The
host chooses mappers. Examples of kind strings: `nostr`, `webrtc`.

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
would exceed `max`.

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
| `expand` | RFC 5869 `T(1)` via `mac` |
| `compress` / `decompress` | raw Deflate (RFC 1951) |
| `text` / `untext` | unpadded base64url (RFC 4648 §5) |
| `canonical` / `parse` | `J` then RFC 8785 |
| `seal` / `open` | AES-256-GCM; `key` 32; `nonce` 12; associated data empty; output body then 16-byte tag |
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
(examples: `nostr`, `webrtc`).

```
Kind = tstr .size (1..32) .regexp "[a-z][a-z0-9-]*"

BillboardKind = Kind
MailboxKind   = Kind
WireKind      = Kind
```

#### Address

A mapper coordinate. Unicode Normalization Form C, no NUL, no combining mark.

```
Address = tstr .size (1..256)

BillboardAddress = Address
MailboxAddress   = Address
WireAddress      = Address
```

#### Billboard

Place an actor A can publish information so that a given actor B can read it.

```
Billboard = {
  kind: BillboardKind,
  address: BillboardAddress,
}
```

#### Mailbox

Place an actor A can read information that a given actor B can write.

```
Mailbox = {
  kind: MailboxKind,
  address: MailboxAddress,
}
```

#### Wire

Live path where A can transmit information to B and vice versa, with no store.
`address` is mapper config (relays, transport, protocol id). The rendezvous
locator is a WireTag.

```
Wire = {
  kind: WireKind,
  address: WireAddress,
}
```

#### DisplayName

A name shown for a user. Unicode Normalization Form C, no NUL, no combining
mark.

```
DisplayName = tstr .size (1..64)
```

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

Identifies a conversation under an identity.

```
ConversationId = bstr .size 32
```

#### Secret

32-byte secret. Ticket capabilities, expand keys, and other 32-byte secrets use
this sort.

```
Secret = bstr .size 32
```

#### Tag

32-byte locator. Billboard pins, Mailbox bins, and Wire rendezvous use tags.

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

#### TimeBin

Hour index of Unix time.

```
TimeBin = uint
```

```
TimeBin = time_bin(unix_seconds)
```

`unix_seconds` is a `UnixSeconds` value. At `W = TimeBin`, the library listen
window is `W-1`, `W`, and `W+1`.

#### MailboxTag

A Mailbox locator for a time bin.

```
MailboxTag = Tag
```

```
MailboxTag = expand(tag_key, "chuchotez/1/dm-mailbox-bin" || be<64>u(TimeBin))
```

#### WireTag

Rendezvous locator on a Wire for a time bin. `tag_key` is the TagKey of the
mailbox interest this listen or send pairs with.

```
WireTag = Tag
```

```
WireTag = expand(tag_key, "chuchotez/1/dm-wire-bin" || be<64>u(TimeBin))
```

#### Channel

A Billboard, Mailbox, or Wire together with which role it plays. Two Channels
are equal when `sort`, `kind`, and `address` match.

```
Channel = BillboardChannel / MailboxChannel / WireChannel

BillboardChannel = { sort: "Billboard", billboard: Billboard }
MailboxChannel   = { sort: "Mailbox", mailbox: Mailbox }
WireChannel      = { sort: "Wire", wire: Wire }
```

#### MailboxBinProgress

EngineState listing progress for one Mailbox and TagKey. `watermark` is the
greatest bin such that every bin ≤ that value has been listed in full.
`completed` is fully listed bins greater than `watermark`.

```
MailboxBinProgress = {
  mailbox: Mailbox,
  tag_key: TagKey,
  watermark: TimeBin,
  completed: [TimeBin],
}
```

#### Poll

Query of Channel work for the ticked now. Arrays are ordered by Channel
`sort` (`Billboard`, `Mailbox`, `Wire`), then `kind`, then `address`, then
tag bytes.

```
ChannelTag = { channel: Channel, tag: Tag }
ChannelWrite = { channel: Channel, tag: Tag, body: bstr }
BlockedIdentity = {
  user_id: UserId,
  identity_id: IdentityId,
  missing: "DisplayName",
}

Poll = {
  list: [ChannelTag],
  listen: [ChannelTag],
  write: [ChannelWrite],
  blocked: [BlockedIdentity],
}
```

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

Output of `sign`. Length is the `sig` length for the Policy that applies.

```
Signature = bstr
```

#### KemCiphertext

`kem_ct` from `wrap`. Length is the `kem_ct` length for the Policy that applies.

```
KemCiphertext = bstr
```

#### Command

A mutation of EngineState. `CommandOp` is which mutation. `apply` folds a
Command into EngineState with no extra randomness.

```
CommandOp = "create_user" / "create_identity" / "delete_user"
          / "delete_identity" / "delete_conversation"
          / "set_display_name" / "unset_display_name"
          / "set_local_channels" / "tick"
          / "create_invite" / "mark_notice_pinned"
          / "receive_ticket" / "receive_notice"
          / "create_introduction" / "receive_invitee_introduction"
          / "receive_inviter_introduction" / "introduction_sent"
          / "confirm_established" / "reject_established"
          / "fail_conversation" / "write_ack" / "complete_mailbox_bin"

FailReason = "policy_not_accepted" / "invite_expired"
           / "notice_unlock_failed" / "notice_conflict"
           / "invitee_introduction_unlock_failed"
           / "invitee_introduction_verify_failed"
           / "inviter_introduction_unlock_failed"
           / "inviter_introduction_verify_failed"
           / "duplicate_invitee_introduction"
           / "duplicate_inviter_introduction"
           / "digest_rejected"

Command = { op: CommandOp }
```

The remaining fields are exactly those for `op`. `ticket` is a DMTicket.
`notice` is a DMNotice. `now` is `UnixSeconds`. `channel` is a Channel.
`tag` is a Tag. `body` is bytes. Handshake commands that carry `now` copy
the ticked now at construction.

| `op` | Other fields |
| --- | --- |
| `create_user` | `user_id` |
| `create_identity` | `user_id`, `identity_id`, `encryption_pk`, `encryption_sk`, `signing_pk`, `signing_sk`, `mailboxes`, `wires` |
| `delete_user` | `user_id` |
| `delete_identity` | `user_id`, `identity_id` |
| `delete_conversation` | `user_id`, `identity_id`, `conversation_id` |
| `set_display_name` | `user_id`, `identity_id`, `name` |
| `unset_display_name` | `user_id`, `identity_id` |
| `set_local_channels` | `user_id`, `identity_id`, `mailboxes`, `wires` |
| `tick` | `now` |
| `create_invite` | `user_id`, `identity_id`, `conversation_id`, `ticket`, `intake_pk`, `intake_sk`, `mailboxes`, `wires`, `expires` |
| `mark_notice_pinned` | `user_id`, `identity_id`, `conversation_id`, `now` |
| `receive_ticket` | `user_id`, `identity_id`, `conversation_id`, `ticket` |
| `receive_notice` | `user_id`, `identity_id`, `conversation_id`, `notice`, `now` |
| `create_introduction` | `user_id`, `identity_id`, `conversation_id`, `name`, `encryption_pk`, `signing_pk`, `mailbox_tag_key`, `mailboxes`, `wires`, `intake_pk`, `intake_sk`, `intake_tag_key`, `sig`, `kem_ct`, `mailbox_blob`, `now` |
| `receive_invitee_introduction` | `user_id`, `identity_id`, `conversation_id`, `invitee_introduction`, `name`, `encryption_pk`, `signing_pk`, `mailbox_tag_key`, `mailboxes`, `wires`, `sig`, `kem_ct`, `mailbox_blob`, `now` |
| `receive_inviter_introduction` | `user_id`, `identity_id`, `conversation_id`, `inviter_introduction`, `now` |
| `introduction_sent` | `user_id`, `identity_id`, `conversation_id`, `now` |
| `confirm_established` | `user_id`, `identity_id`, `conversation_id`, `now` |
| `reject_established` | `user_id`, `identity_id`, `conversation_id`, `now` |
| `fail_conversation` | `user_id`, `identity_id`, `conversation_id`, `reason`, `now` |
| `write_ack` | `channel`, `tag`, `body` |
| `complete_mailbox_bin` | `user_id`, `identity_id`, `conversation_id`, `mailbox`, `tag` |

`invitee_introduction` is a `DMSignedInviteeIntroduction`.
`inviter_introduction` is a `DMSignedInviterIntroduction`. `reason` is a
`FailReason`. `fail_conversation` with `policy_not_accepted` also holds
`policy`. `fail_conversation` with `invite_expired` also holds `expires`.
`Failed.reason` is the PascalCase of that `FailReason`
(`"policy_not_accepted"` → `"PolicyNotAccepted"`).

### Direct-message types

#### DMInvite

A ticket plus the Notice the inviter pins.

```
DMInvite = {
  ticket: DMTicket,
  notice: DMNotice,
}
```

#### DMTicket

Information the inviter shares with the invitee to start the handshake. The
host carries the ticket’s host string over a medium it chooses.

```
DMTicket = {
  secret: Secret,
  billboards: [1*4 Billboard],
}
```

#### DMInviteTag

Locator for a DMNotice on a Billboard.

```
DMInviteTag = Tag
```

```
DMInviteTag = expand(DMTicket.secret, "chuchotez/1/dm-invite-billboard-tag")
```

#### DMInviterIntakeTagKey

Locator key for the first DMSignedInviteeIntroduction on the inviter Mailboxes.

```
DMInviterIntakeTagKey = TagKey
```

```
DMInviterIntakeTagKey = expand(DMTicket.secret, "chuchotez/1/dm-inviter-intake-tag-key")
```

In this handshake, `MailboxTag` uses `DMInviterIntakeTagKey` for the first post
to the inviter, then `DMInviteeIntakeTagKey` for posts to the invitee.

#### DMNotice

Billboard body. `intake_pk` is the wrap target for the invitee’s
DMSignedInviteeIntroduction. `mailboxes` are where that blob is posted.
`expires` is the last `UnixSeconds` at which a handshake operation on this
invite MAY succeed.

```
DMNotice = {
  policy: Policy,
  intake_pk: PublicKey,
  mailboxes: [1*4 Mailbox],
  wires: [*4 Wire],
  expires: UnixSeconds,
}
```

`intake_pk` length MUST match `policy`. `wires` length is 0..=4.

#### CallingCard

One party’s name, keys, Mailboxes, and Wires. The conversation Policy is
`DMNotice.policy`. Key and signature lengths MUST match that Policy.

```
CallingCard = {
  name: DisplayName,
  encryption_pk: PublicKey,
  signing_pk: SigningPublicKey,
  mailbox_tag_key: TagKey,
  mailboxes: [1*4 Mailbox],
  wires: [*4 Wire],
}
```

`mailbox_tag_key` is `random32()`. `wires` length is 0..=4.

#### DMInviteeIntakeTagKey

Locator key for later Messages on the invitee’s Mailboxes.

```
DMInviteeIntakeTagKey = TagKey
```

```
DMInviteeIntakeTagKey = random32()
```

#### DMInviteeIntroduction  (planned)

Inner value the invitee posts. `intake_pk` is the wrap target for the inviter’s
later card. `intake_tag_key` locates that card on the invitee’s Mailboxes.

```
DMInviteeIntroduction = {
  calling_card: CallingCard,
  intake_pk: PublicKey,
  intake_tag_key: DMInviteeIntakeTagKey,
}
```

`intake_pk` length MUST match `DMNotice.policy`. Conversation Intake is
`keygen(DMNotice.policy, random32() || random32())`. The Intake secret stays on
the invitee tree.

#### DMSignedInviteeIntroduction  (planned)

Signed introduction. The Engine stores `mailbox_blob` at mint. `poll` write
work posts it to every DMNotice Mailbox at `MailboxTag` and every DMNotice
Wire at `WireTag` for `time_bin(ticked now)` and `DMInviterIntakeTagKey`.

```
DMSignedInviteeIntroduction = {
  introduction: DMInviteeIntroduction,
  sig: Signature,
}
```

```
body       = introduction
message    = canonical(body)
signature  = sign(DMNotice.policy, identity signing sk, message, random32())
```

Set `sig` to `signature`. ML-DSA-65 context =
`"chuchotez/1/dm-invitee-introduction"`.

```
(shared, kem_ct) = wrap(DMNotice.policy, DMNotice.intake_pk, random32() || random32())

key        = expand(shared, "chuchotez/1/dm-invitee-introduction-key")
nonce      = expand(shared, "chuchotez/1/dm-invitee-introduction-nonce")[0..12]
ciphertext = lock(key, nonce, DMSignedInviteeIntroduction)
```

`kem_ct` length MUST match `DMNotice.policy`.

Inviter open (planned):

```
shared                       = unwrap(DMNotice.policy, Intake sk, kem_ct)
key                          = expand(shared, "chuchotez/1/dm-invitee-introduction-key")
nonce                        = expand(shared, "chuchotez/1/dm-invitee-introduction-nonce")[0..12]
DMSignedInviteeIntroduction  = unlock(key, nonce, ciphertext)
ok                           = verify(DMNotice.policy, introduction.calling_card.signing_pk, canonical(introduction), sig)
```

`Intake sk` is the inviter’s Intake secret (matching `DMNotice.intake_pk`). One
valid DMSignedInviteeIntroduction per conversation.

#### DMInviterIntroduction  (planned)

Inner value the inviter posts.

```
DMInviterIntroduction = {
  calling_card: CallingCard,
}
```

#### DMSignedInviterIntroduction  (planned)

Signed introduction. The Engine stores `mailbox_blob` at mint. `poll` write
work posts it to every `DMInviteeIntroduction.calling_card` Mailbox at
`MailboxTag` and every such Wire at `WireTag` for `time_bin(ticked now)` and
`DMInviteeIntakeTagKey`.

```
DMSignedInviterIntroduction = {
  introduction: DMInviterIntroduction,
  sig: Signature,
}
```

```
body       = introduction
message    = canonical(body)
signature  = sign(DMNotice.policy, identity signing sk, message, random32())
```

Set `sig` to `signature`. ML-DSA-65 context =
`"chuchotez/1/dm-inviter-introduction"`.

```
(shared, kem_ct) = wrap(DMNotice.policy, DMInviteeIntroduction.intake_pk, random32() || random32())

key        = expand(shared, "chuchotez/1/dm-inviter-introduction-key")
nonce      = expand(shared, "chuchotez/1/dm-inviter-introduction-nonce")[0..12]
ciphertext = lock(key, nonce, DMSignedInviterIntroduction)
```

`kem_ct` length MUST match `DMNotice.policy`.

Invitee open (planned):

```
shared                       = unwrap(DMNotice.policy, Intake sk, kem_ct)
key                          = expand(shared, "chuchotez/1/dm-inviter-introduction-key")
nonce                        = expand(shared, "chuchotez/1/dm-inviter-introduction-nonce")[0..12]
DMSignedInviterIntroduction  = unlock(key, nonce, ciphertext)
ok                           = verify(DMNotice.policy, introduction.calling_card.signing_pk, canonical(introduction), sig)
```

`Intake sk` is the invitee’s conversation Intake secret (matching
`DMInviteeIntroduction.intake_pk`). One valid DMSignedInviterIntroduction per
conversation.

#### EstablishedDigest  (planned)

32-byte tagged hash of both signed introductions. Both sides compute it after
they hold `DMSignedInviterIntroduction` and `DMSignedInviteeIntroduction`. The
`tag` is a public domain-separation string.

```
EstablishedDigest = bstr .size 32
```

```
tag                = UTF-8 "chuchotez/1/dm-established"
EstablishedDigest  = mac(tag, canonical(DMSignedInviterIntroduction) || canonical(DMSignedInviteeIntroduction))
```

The concatenation order is inviter then invitee. `confirmEstablished` moves
that party from `Confirming` to `Established`. `rejectEstablished` moves
`Confirming` to `Failed` with `DigestRejected`.

### Other conversations

Pairwise streams after `Established`. Those tickets are domain records of a
different sort. Types and encodings for those streams are later work.

---

## Serialization

A domain value is encoded to bytes in layers. `J` maps a domain value to a JSON
value. `canonical` is RFC 8785 of `J`. `parse` inverts `canonical`. Other
layers (`compress`, `text`, `seal`, `be<n>u`) map bytes to bytes, or bytes to
Unicode strings.

```
packed(value)           = compress(canonical(value))
wire(bytes)             = text(bytes)
lock(key, nonce, value) = seal(key, nonce, packed(value))
unlock(key, nonce, ct)  = parse(decompress(open(key, nonce, ct), max))
```

`max` is the uncompressed cap for that artifact. `unlock` refuses if `open`,
`decompress`, or `parse` refuses.

### JSON mapping `J`

`J` is defined on domain values. `J⁻¹` refuses extra object members, missing
members, and members whose JSON sort does not match this table.

| Domain | `J` |
| --- | --- |
| `Policy` | JSON string `"Classic"`, `"PostQuantum"`, or `"Hybrid"` |
| `CommandOp` | JSON string of the enumerant name (`"create_user"`, …) |
| `FailReason` | JSON string of the enumerant name (`"policy_not_accepted"`, …) |
| CDDL `uint` | JSON number of that integer |
| CDDL `tstr` | JSON string of that Unicode value |
| CDDL `bstr` | JSON string `text(bytes)` |
| CDDL array | JSON array of `J(T)` in list order |
| CDDL map `{ … }` | JSON object: one member per field, name = field name, value = `J(field)` |

Top-level artifacts that travel as a JSON document also carry a discriminator
member `"type"` with a constant string. Nested maps (Billboard, Mailbox, Wire,
Channel, and fields inside Command) omit `"type"`. `J⁻¹` refuses an unknown
`"type"`. Channel `sort` is the JSON string `"Billboard"`, `"Mailbox"`, or
`"Wire"`.

| Domain sort | `"type"` |
| --- | --- |
| DMTicket | `"v1-dm-ticket"` |
| DMNotice | `"v1-dm-notice"` |
| CallingCard | `"v1-calling-card"` |
| DMInviteeIntroduction | `"v1-dm-invitee-introduction"` |
| DMSignedInviteeIntroduction | `"v1-dm-signed-invitee-introduction"` |
| DMInviterIntroduction | `"v1-dm-inviter-introduction"` |
| DMSignedInviterIntroduction | `"v1-dm-signed-inviter-introduction"` |
| Command | `"v1-command"` |

`J(DMInviteeIntroduction)` and `J(DMInviterIntroduction)` are the signed
`message` values. Each signed record includes `"type"` and `sig`.

### Host encodings

**DMTicket.** Encoded string the host transmits. The host chooses the medium.

```
host string = wire(packed(DMTicket))
```

**DMNotice.** Locked with a nonce both sides derive. The host string is the
seal output only.

```
key         = expand(DMTicket.secret, "chuchotez/1/dm-notice-key")
nonce       = expand(DMTicket.secret, "chuchotez/1/dm-notice-nonce")[0..12]
host string = wire(lock(key, nonce, DMNotice))
```

Uncompressed `canonical` ≤ 8192. `packed` body ≤ 8208. Host string UTF-8 length
≤ 10966.

**DMSignedInviteeIntroduction** (planned). `kem_ct` length is fixed by
`DMNotice.policy`. Size cap later (Hybrid-sized; pad the whole body).

```
host string = wire(kem_ct || lock(key, nonce, DMSignedInviteeIntroduction))
```

**DMSignedInviterIntroduction** (planned). `kem_ct` length is fixed by
`DMNotice.policy`. Size cap later (Hybrid-sized; pad the whole body).

```
host string = wire(kem_ct || lock(key, nonce, DMSignedInviterIntroduction))
```

**Command.** Carried nonce, then lock. The host appends raw bytes (no `wire`).
`key` is 32 bytes the host keeps.

```
seq     integer    0 ≤ seq < 2^64 − 1
nonce   byte[12]   be<32>u(1) || be<64>u(seq)
record  = nonce || lock(key, nonce, Command)
```

`1` in the high four bytes is persist format version. `seq` is unique for that
host `key`. Uncompressed `canonical` ≤ 16384. `packed` body ≤ 16400. Record
length ≤ 16668.

---

## Library

The library is bound to one `Policy`. Named operations drive `EngineState`.
`apply` folds a `Command` with no extra randomness. Operations that need
entropy take `random32` from a host `Rng`. Mutators return zero or more sealed
persist records (`nonce || lock` with the host DEK), in `apply` order.
`EngineState` is an opaque handle the host holds in memory. Reload is `apply`
of each persist record in order. `tick` is the clock. `poll` is the Channel
and Tag query for that ticked now. `ingestList`, `ingestItem`, and `writeAck`
fold mapper results. The query `Conversation` omits ticket secret, DEK, intake
`sk`, identity `sk`, `mailbox_tag_key`, and `MailboxBinProgress`. TypeScript
field names are camelCase of the CDDL names.

```ts
declare const brand: unique symbol
type Brand<T, B extends string> = T & { readonly [brand]: B }

type Random32 = Brand<Uint8Array, "Random32">
type AeadKey = Brand<Uint8Array, "AeadKey">
type UserId = Brand<Uint8Array, "UserId">
type IdentityId = Brand<Uint8Array, "IdentityId">
type ConversationId = Brand<Uint8Array, "ConversationId">
type Tag = Brand<Uint8Array, "Tag">
type PublicKey = Brand<Uint8Array, "PublicKey">
type SigningPublicKey = Brand<Uint8Array, "SigningPublicKey">
type UnixSeconds = number
type PersistBytes = Uint8Array
type Policy = "Classic" | "PostQuantum" | "Hybrid"
type Kind = string
type Address = string
type DisplayName = string
type Billboard = { kind: Kind; address: Address }
type Mailbox = { kind: Kind; address: Address }
type Wire = { kind: Kind; address: Address }
type Channel =
  | { sort: "Billboard"; billboard: Billboard }
  | { sort: "Mailbox"; mailbox: Mailbox }
  | { sort: "Wire"; wire: Wire }
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
  | { code: "SnapshotTooLarge" }

type ConversationRef = {
  userId: UserId
  identityId: IdentityId
  conversationId: ConversationId
}

type MutateOk = { state: EngineState; persist: PersistBytes[] }
type CreateUserOk = MutateOk & { userId: UserId }
type CreateIdentityOk = MutateOk & { identityId: IdentityId }
type CreateInviteOk = MutateOk & { conversationId: ConversationId }
type ReceiveTicketOk = MutateOk & { conversationId: ConversationId }

type ChannelTag = { channel: Channel; tag: Tag }
type ChannelWrite = { channel: Channel; tag: Tag; body: Uint8Array }
type BlockedIdentity = {
  userId: UserId
  identityId: IdentityId
  missing: "DisplayName"
}
type Poll = {
  list: ChannelTag[]
  listen: ChannelTag[]
  write: ChannelWrite[]
  blocked: BlockedIdentity[]
}

type Inviter =
  | { phase: "InviteCreated"; expires: UnixSeconds }
  | { phase: "NoticePinned"; expires: UnixSeconds }
  | { phase: "IntroductionMinted"; expires: UnixSeconds }
  | { phase: "Confirming"; expires: UnixSeconds; digest: string }

type Invitee =
  | { phase: "TicketReceived" }
  | { phase: "InviteReceived"; policy: Policy; expires: UnixSeconds }
  | { phase: "IntroductionMinted"; policy: Policy; expires: UnixSeconds }
  | { phase: "IntroductionSent"; policy: Policy; expires: UnixSeconds }
  | { phase: "Confirming"; policy: Policy; expires: UnixSeconds; digest: string }

type Established = {
  name: DisplayName
  encryptionPk: PublicKey
  signingPk: SigningPublicKey
  mailboxes: Mailbox[]
  wires: Wire[]
  localMailboxes: Mailbox[]
  localWires: Wire[]
  digest: string
}

type Failed =
  | { reason: "PolicyNotAccepted"; policy: Policy }
  | { reason: "InviteExpired"; expires: UnixSeconds }
  | { reason: "NoticeUnlockFailed" }
  | { reason: "NoticeConflict" }
  | { reason: "InviteeIntroductionUnlockFailed" }
  | { reason: "InviteeIntroductionVerifyFailed" }
  | { reason: "InviterIntroductionUnlockFailed" }
  | { reason: "InviterIntroductionVerifyFailed" }
  | { reason: "DuplicateInviteeIntroduction" }
  | { reason: "DuplicateInviterIntroduction" }
  | { reason: "DigestRejected" }

type DirectMessage =
  | { sort: "Inviter"; value: Inviter }
  | { sort: "Invitee"; value: Invitee }
  | { sort: "Established"; value: Established }
  | { sort: "Failed"; value: Failed }

type Conversation =
  | { sort: "DirectMessage"; value: DirectMessage }
  | { sort: "Group" }
  | { sort: "Synchronization" }

declare class Engine {
  constructor(policy: Policy)
  createUser(state: EngineState, rng: Rng, dek: AeadKey): Result<CreateUserOk>
  createIdentity(
    state: EngineState,
    rng: Rng,
    dek: AeadKey,
    userId: UserId,
    mailboxes: Mailbox[],
    wires: Wire[],
  ): Result<CreateIdentityOk>
  deleteUser(state: EngineState, dek: AeadKey, userId: UserId): Result<MutateOk>
  deleteIdentity(
    state: EngineState,
    dek: AeadKey,
    userId: UserId,
    identityId: IdentityId,
  ): Result<MutateOk>
  deleteConversation(
    state: EngineState,
    dek: AeadKey,
    ids: ConversationRef,
  ): Result<MutateOk>
  setLocalChannels(
    state: EngineState,
    rng: Rng,
    dek: AeadKey,
    userId: UserId,
    identityId: IdentityId,
    mailboxes: Mailbox[],
    wires: Wire[],
  ): Result<MutateOk>
  tick(state: EngineState, dek: AeadKey, now: UnixSeconds): Result<MutateOk>
  poll(state: EngineState): Result<Poll>
  ingestList(
    state: EngineState,
    rng: Rng,
    dek: AeadKey,
    channel: Channel,
    tag: Tag,
    bodies: Uint8Array[],
  ): Result<MutateOk>
  ingestItem(
    state: EngineState,
    rng: Rng,
    dek: AeadKey,
    channel: Channel,
    tag: Tag,
    body: Uint8Array,
  ): Result<MutateOk>
  writeAck(
    state: EngineState,
    dek: AeadKey,
    channel: Channel,
    tag: Tag,
    body: Uint8Array,
  ): Result<MutateOk>
  createInvite(
    state: EngineState,
    rng: Rng,
    dek: AeadKey,
    userId: UserId,
    identityId: IdentityId,
    billboards: Billboard[],
    expires: UnixSeconds,
  ): Result<CreateInviteOk>
  receiveTicket(
    state: EngineState,
    rng: Rng,
    dek: AeadKey,
    userId: UserId,
    identityId: IdentityId,
    ticketHostString: string,
  ): Result<ReceiveTicketOk>
  setDisplayName(
    state: EngineState,
    rng: Rng,
    dek: AeadKey,
    userId: UserId,
    identityId: IdentityId,
    name: string,
  ): Result<MutateOk>
  unsetDisplayName(
    state: EngineState,
    dek: AeadKey,
    userId: UserId,
    identityId: IdentityId,
  ): Result<MutateOk>
  confirmEstablished(
    state: EngineState,
    dek: AeadKey,
    ids: ConversationRef,
  ): Result<MutateOk>
  rejectEstablished(
    state: EngineState,
    dek: AeadKey,
    ids: ConversationRef,
  ): Result<MutateOk>
  getConversation(
    state: EngineState,
    userId: UserId,
    identityId: IdentityId,
    conversationId: ConversationId,
  ): Result<Conversation>
  ticketHostString(state: EngineState, ids: ConversationRef): Result<string>
  establishedDigest(state: EngineState, ids: ConversationRef): Result<string>
  apply(
    state: EngineState,
    persist: PersistBytes,
    dek: AeadKey,
  ): Result<EngineState>
}
```

`digest` and `establishedDigest` are `text(EstablishedDigest)`. `poll` write
`body` is UTF-8 of the Notice or signed-introduction host string. `createInvite`
MUST refuse when `expires` is less than or equal to the ticked now. Identity
mailboxes length is 1..=4 and wires length is 0..=4; `kind`+`address` is unique
within each list (`ChannelBounds`). `createInvite` copies those identity
channels into `DMNotice`. `setLocalChannels` stores identity defaults. A mint
copies the current identity channels into the card.

`tick` is the only operation that takes `now`. `now` less than the last ticked
value is `ClockWentBackwards`. Equal `now` is success. Last ticked `now` lives
in memory. `tick` appends persist when it stores `InviteExpired` or
initializes a `watermark`. Reload is `NotTicked` until the host `tick`s
again. A first successful `tick` is required before `poll`, `createInvite`,
`ingestList`, `ingestItem`, `writeAck`, `confirmEstablished`, and
`rejectEstablished` (`NotTicked`). `createUser`, `createIdentity`,
`receiveTicket`, `setDisplayName`, `unsetDisplayName`, `setLocalChannels`,
and deletes MAY run before that tick. When `now` is greater than a still
pre-`Established` invite `expires`, `tick` stores `Failed` `InviteExpired`.

`ingestList` with `bodies.length > 512` is `SnapshotTooLarge`. `ingestList` is
valid for a `(channel, tag)` in the current `poll` list set; `ingestItem` for
the listen set; `writeAck` for a current pending write (`UnknownTag` /
`UnknownWrite`). Per body, the library parses, unlocks, and verifies; a
malformed body is skipped. A Notice whose `policy` differs from the Engine
`Policy` stores `Failed` `PolicyNotAccepted`. Empty or all-junk mailbox
`ingestList` still completes that bin (`complete_mailbox_bin`). A Billboard
`ingestList` that matches stored state, or an `ingestItem` of a body already
folded, appends no persist.

Mint of a signed introduction runs inside ingest when the identity has a
`DisplayName` and local channels. Otherwise `poll.blocked` lists that identity
(`missing: "DisplayName"`). `setDisplayName` and `setLocalChannels` mint every
waiting introduction on that identity. `unsetDisplayName` before mint returns
the identity to `blocked`; a minted card keeps its name.

At `W = time_bin(ticked now)`, each live `(Mailbox, TagKey)` has a
`MailboxBinProgress`. `createInvite` and each mint set `watermark` to `W-3`
for new pairs. `tick` does the same for a live pair still unset. Mailbox
**list** tags are `MailboxTag` for bins in `(watermark, W-2] ∪ [W-1, W, W+1]`
that are not yet fully listed. Mailbox **listen** tags are `MailboxTag` for
`[W-1, W, W+1]`. After `ingestList`, that tag leaves `list` and stays on
`listen` while its bin is in the window. Completing bin `B` records it in
`completed` (or raises `watermark`); `watermark` is the greatest `k` with
every bin `≤ k` fully listed, and at most `W-2`. Completing `W-1` leaves
`watermark` at `W-2` until every bin `≤ W-2` is done. A body stored after
`ingestList` completed that bin is missed.

Wire **listen** tags are `WireTag` on local Wires for the same TagKey and
window. Handshake **write** tags on Mailbox and Wire use bin `W` only, one
destination Channel each. Billboard pins use `DMInviteTag`. `writeAck` of
every member of a mint’s write set moves `InviteCreated` to `NoticePinned` and
`IntroductionMinted` to Sent or Confirming. `poll` re-emits unacked writes.

Handshake locators stay in `poll` until `Established` or `Failed`: invitee
list and listen of `DMInviteTag` on ticket Billboards; inviter list and listen
of local Mailboxes at `DMInviterIntakeTagKey`; invitee list and listen of
local Mailboxes at `DMInviteeIntakeTagKey` once that key exists. Session list
and listen of local Mailboxes at each `CallingCard.mailbox_tag_key` starts
when that key exists and continues in `Established`. Failed and deleted
conversations contribute no `poll` rows; their pending writes drop. Ingest of
bodies on Established session tags is success with no conversation change
until pairwise message types ship.

---

## Mappers

A mapper implements one `Kind` of Channel. The host selects mappers by
`BillboardKind`, `MailboxKind`, and `WireKind`, and calls them with Channel
and Tag from `poll`.

```ts
interface BillboardMapper {
  pin(billboard: Billboard, tag: Tag, body: Uint8Array): Promise<void>
  list(billboard: Billboard, tag: Tag): Promise<Uint8Array[]>
  listen(billboard: Billboard, tag: Tag): AsyncIterable<Uint8Array>
}

interface MailboxMapper {
  post(mailbox: Mailbox, tag: Tag, body: Uint8Array): Promise<void>
  list(mailbox: Mailbox, tag: Tag): Promise<Uint8Array[]>
  listen(mailbox: Mailbox, tag: Tag): AsyncIterable<Uint8Array>
}

interface WireMapper {
  send(wire: Wire, tag: Tag, body: Uint8Array): Promise<void>
  listen(wire: Wire, tag: Tag): AsyncIterable<Uint8Array>
}
```

`list` returns the complete stored snapshot for that Channel and Tag
(pagination stays inside the mapper). The host calls `ingestList` only after
that snapshot is in hand. `listen` yields bodies as they arrive. The host
starts and stops `listen` by set-diff of `poll().listen`.

---

## State machine

Query `Conversation` is library state. It has no on-wire `"type"`
discriminator.

```
Conversation = DirectMessage / Group / Synchronization

Group = {}
Synchronization = {}

DirectMessage = Inviter / Invitee / Established / Failed

Inviter = InviterInviteCreated
        / InviterNoticePinned
        / InviterIntroductionMinted
        / InviterConfirming

InviterInviteCreated = { expires: UnixSeconds }
InviterNoticePinned = { expires: UnixSeconds }
InviterIntroductionMinted = { expires: UnixSeconds }
InviterConfirming = { expires: UnixSeconds, digest: tstr }

Invitee = InviteeTicketReceived
        / InviteeInviteReceived
        / InviteeIntroductionMinted
        / InviteeIntroductionSent
        / InviteeConfirming

InviteeTicketReceived = {}
InviteeInviteReceived = { policy: Policy, expires: UnixSeconds }
InviteeIntroductionMinted = { policy: Policy, expires: UnixSeconds }
InviteeIntroductionSent = { policy: Policy, expires: UnixSeconds }
InviteeConfirming = { policy: Policy, expires: UnixSeconds, digest: tstr }

Established = {
  name: DisplayName,
  encryption_pk: PublicKey,
  signing_pk: SigningPublicKey,
  mailboxes: [1*4 Mailbox],
  wires: [*4 Wire],
  local_mailboxes: [1*4 Mailbox],
  local_wires: [*4 Wire],
  digest: tstr,
}

Failed = FailedPolicyNotAccepted
       / FailedInviteExpired
       / FailedNoticeUnlockFailed
       / FailedNoticeConflict
       / FailedInviteeIntroductionUnlockFailed
       / FailedInviteeIntroductionVerifyFailed
       / FailedInviterIntroductionUnlockFailed
       / FailedInviterIntroductionVerifyFailed
       / FailedDuplicateInviteeIntroduction
       / FailedDuplicateInviterIntroduction
       / FailedDigestRejected

FailedPolicyNotAccepted = { reason: "PolicyNotAccepted", policy: Policy }
FailedInviteExpired = { reason: "InviteExpired", expires: UnixSeconds }
FailedNoticeUnlockFailed = { reason: "NoticeUnlockFailed" }
FailedNoticeConflict = { reason: "NoticeConflict" }
FailedInviteeIntroductionUnlockFailed = {
  reason: "InviteeIntroductionUnlockFailed",
}
FailedInviteeIntroductionVerifyFailed = {
  reason: "InviteeIntroductionVerifyFailed",
}
FailedInviterIntroductionUnlockFailed = {
  reason: "InviterIntroductionUnlockFailed",
}
FailedInviterIntroductionVerifyFailed = {
  reason: "InviterIntroductionVerifyFailed",
}
FailedDuplicateInviteeIntroduction = {
  reason: "DuplicateInviteeIntroduction",
}
FailedDuplicateInviterIntroduction = {
  reason: "DuplicateInviterIntroduction",
}
FailedDigestRejected = { reason: "DigestRejected" }
```

Query `Established` is the peer `CallingCard` (`mailbox_tag_key` omitted) plus
`local_mailboxes` and `local_wires`. EngineState also keeps both
`mailbox_tag_key` values and `MailboxBinProgress` rows. Anyone who has the
`DMTicket` can pin a `DMNotice` at the `DMInviteTag`.

`tick` stores `Failed` `InviteExpired` when the ticked `now` is greater than
`expires` and the conversation is still pre-`Established`. Later
`ingestList` / `ingestItem` / `writeAck` / `confirmEstablished` /
`rejectEstablished` on that conversation is `WrongPhase`.

| From | Method | To |
| --- | --- | --- |
| (none) | `createInvite` | `Inviter` `InviteCreated` |
| `InviteCreated` | `writeAck` of the full pin set | `NoticePinned` |
| `NoticePinned` | `ingestList` / `ingestItem` of a valid invitee introduction | `Inviter` `IntroductionMinted` |
| `Inviter` `IntroductionMinted` | `writeAck` of the full post set | `Inviter` `Confirming` |
| (none) | `receiveTicket` | `Invitee` `TicketReceived` |
| `TicketReceived` | `ingestList` / `ingestItem` of a valid Notice | `InviteReceived` |
| `InviteReceived` | ingest or `setDisplayName` / `setLocalChannels` mint | `Invitee` `IntroductionMinted` |
| `Invitee` `IntroductionMinted` | `writeAck` of the full post set | `IntroductionSent` |
| `IntroductionSent` | `ingestList` / `ingestItem` of a valid inviter introduction | `Invitee` `Confirming` |
| `Inviter` `Confirming` or `Invitee` `Confirming` | `confirmEstablished` | `Established` |
| `Inviter` `Confirming` or `Invitee` `Confirming` | `rejectEstablished` | `Failed` `DigestRejected` |

A valid invitee introduction also mints the inviter’s signed introduction. A
valid inviter introduction also computes `EstablishedDigest`. An empty
Billboard snapshot leaves `TicketReceived`. `confirmEstablished` and
`rejectEstablished` use the ticked now.

| Ingest | Failure stored |
| --- | --- |
| Notice | `PolicyNotAccepted` when `DMNotice.policy` differs from Engine `Policy` |
| Notice | `NoticeUnlockFailed` when the blob fails `unlock` |
| Notice | `NoticeConflict` when a second well-formed Notice disagrees with the stored one |
| Invitee introduction | `InviteeIntroductionUnlockFailed` or `InviteeIntroductionVerifyFailed` |
| Invitee introduction | `DuplicateInviteeIntroduction` when a second valid invitee intro arrives |
| Inviter introduction | `InviterIntroductionUnlockFailed` or `InviterIntroductionVerifyFailed` |
| Inviter introduction | `DuplicateInviterIntroduction` when a second valid inviter intro arrives |

A wrong-phase call is `EngineError` `WrongPhase`; the conversation is
unchanged. A malformed ticket at `receiveTicket` is `MalformedTicket`; no
conversation row is created.

---

## Vault

The host keeps a 32-byte key used to lock Command records. A passphrase vault
for that key is later work.

---

## Host

The host supplies `Rng.random32`, appends and reads persist bytes, and talks
to mappers with Channel and Tag. It chooses the medium for the `DMTicket`
host string. It supplies `expires` at `createInvite`. Each cycle is `tick`
with the current `UnixSeconds`, then `poll`, then mapper `list` / `listen` /
`pin` / `post` / `send`, then `ingestList` / `ingestItem` / `writeAck`. Named
local and out-of-band calls (`createUser`, `createIdentity`, `receiveTicket`,
`setDisplayName`, `unsetDisplayName`, `setLocalChannels`,
`confirmEstablished`, `rejectEstablished`, deletes) MAY run at any time the
Engine accepts them.
