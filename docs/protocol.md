# Direct-message handshake

This page is the v1 handshake contract: the information domain, and the
mappings from those values onto serialized bytes. Names here are protocol
names. The [book](book.md) is the locked library API. rustdoc is the reference.

**Shipped** work is in the crates. **Planned** work is decided and waiting on a
slice. This page is ahead of the crates: a later slice will propagate it.

The **host** is the app. It supplies `random32`, stores the local log, and talks
to the network. Chuchotez builds the envelopes.

The **inviter** starts a conversation. The **invitee** joins it.

A **`Policy`** is `Classic`, `PostQuantum`, or `Hybrid`. It chooses the public-key
algorithms in v1 algorithms.

The **`Engine`** is the library handle bound to one Policy and the functions
below.

**`EngineState`** is the host’s saved users, identities, and conversations.

A **`DMInvite`** is a `DMTicket` and a `DMNotice`.

A **`DMTicket`** is the information the inviter shares with the invitee to start
the handshake. The host carries the ticket’s host string over a medium it
chooses.

A **`Billboard`** is a Channel the inviter writes and the invitee reads. A
**`Tag`** is a locator. A **`DMInviteTag`** is the Tag for the Notice on those
Billboards.

The `DMTicket` contains a secret and a list of `Billboard`s. The `DMNotice` is
pinned using a `DMInviteTag` derived from the secret.

A **`Mailbox`** is a Channel the invitee writes and the inviter reads.

A **`Wire`** is a Channel both sides use, with no store.

A **`CallingCard`** is one party’s name, keys, Mailboxes, and Wires.

## Handshake

1. The inviter calls `create_user`, `create_identity`, and `create_invite`, and
   receives a `DMInvite`.
2. The inviter pins the `DMNotice` at each Billboard under the `DMInviteTag`, and
   shares the `DMTicket` with the invitee.
3. The invitee calls `receive_ticket`. The host fetches the `DMNotice`. The
   invitee calls `receive_notice`.
4. The invitee calls `set_display_name` and `create_calling_card`, and stores a
   local `CallingCard` (shipped).
5. Planned: the invitee builds a `DMInviteeIntroduction`, signs it, and `wrap`s
   the `DMSignedInviteeIntroduction` to the inviter’s Intake `pk`. The host
   posts it on the inviter Mailboxes at the `DMInviterIntakeTagKey`.
6. Planned: the inviter opens that blob (one valid signed introduction per
   conversation), builds a `DMInviterIntroduction`, signs it, and `wrap`s the
   `DMSignedInviterIntroduction` to `DMInviteeIntroduction.intake_pk`. The host
   posts it on the invitee Mailboxes at the `DMInviteeIntakeTagKey`.
7. Planned: each side computes `EstablishedDigest`. When a party confirms the
   two digests match, that party’s conversation becomes `Established`.

A well-formed DMNotice whose Policy is outside the host `accepted` list becomes
`Failed::PolicyNotAccepted`. Anyone who has the DMTicket can pin a DMNotice at
the DMInviteTag.

## Notation

```
||              concatenation
byte            8-bit value
byte[n]         exactly n bytes
byte[]          bytes of length given beside the field
string          Unicode string
List<T>         ordered sequence of T
T | U           alternative
record          value with named fields
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

Types below are values in the information domain. [Serialization](#serialization)
maps those values to bytes.

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

Turns one secret and a short name into a new 32-byte secret. Different labels
give independent values. `label` is the UTF-8 bytes of the quoted ASCII string.

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
`key`. Associated data is empty.

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

## v1 algorithms

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

## Domain

### Policy

Chooses the KEM and signature algorithms.

```
type Policy   Classic | PostQuantum | Hybrid
```

### Kind

A mapper registry key. Hosts pick the strings their mappers understand
(examples: `nostr`, `webrtc`).

```
type Kind   string   [a-z][a-z0-9-]*    UTF-8 byte length 1..=32
```

```
type BillboardKind  Kind
type MailboxKind    Kind
type WireKind       Kind
```

### Address

A mapper coordinate.

```
type Address   string   nonempty     UTF-8 byte length 1..=256
                            Unicode Normalization Form C
                            no NUL, no combining mark
```

```
type BillboardAddress  Address
type MailboxAddress    Address
type WireAddress       Address
```

### Billboard

Place an actor A can publish information so that a given actor B can read it.

```
record Billboard {
    kind     BillboardKind
    address  BillboardAddress
}
```

### Mailbox

Place an actor A can read information that a given actor B can write.

```
record Mailbox {
    kind     MailboxKind
    address  MailboxAddress
}
```

### Wire

Live path where A can transmit information to B and vice versa, with no store.

```
record Wire {
    kind     WireKind
    address  WireAddress
}
```

### DisplayName

A name shown for a user.

```
type DisplayName   string   nonempty     UTF-8 byte length 1..=64
                            Unicode Normalization Form C
                            no NUL, no combining mark
```

### UserId

Identifies a user.

```
type UserId   byte[32]
```

### IdentityId

Identifies an identity under a user.

```
type IdentityId   byte[32]
```

### ConversationId

Identifies a conversation under an identity.

```
type ConversationId   byte[32]
```

### Secret

32-byte secret. Ticket capabilities, expand keys, and other 32-byte secrets use
this sort.

```
type Secret   byte[32]
```

### Tag

32-byte locator. Billboard pins and Mailbox bins use tags.

```
type Tag   byte[32]
```

### TagKey

32-byte key from which tags are derived with `expand`.

```
type TagKey   byte[32]
```

### PublicKey

Public key for `wrap`. Length is the `keygen` `pk` length for the Policy that
applies.

```
type PublicKey   byte[]
```

### SecretKey

Secret key for `unwrap`. Length is the `keygen` `sk` length for that Policy.

```
type SecretKey   byte[]
```

### KeyPair

A `wrap` key pair.

```
record KeyPair {
    pk  PublicKey
    sk  SecretKey
}
```

### SigningPublicKey

Public key for `verify`. Length is the `sign_keygen` `pk` length for the Policy
that applies.

```
type SigningPublicKey   byte[]
```

### SigningSecretKey

Secret key for `sign`. Length is the `sign_keygen` `sk` length for that Policy.

```
type SigningSecretKey   byte[]
```

### SigningKeyPair

A `sign` key pair.

```
record SigningKeyPair {
    pk  SigningPublicKey
    sk  SigningSecretKey
}
```

### Signature

Output of `sign`. Length is the `sig` length for the Policy that applies.

```
type Signature   byte[]
```

### KemCiphertext

`kem_ct` from `wrap`. Length is the `kem_ct` length for the Policy that applies.

```
type KemCiphertext   byte[]
```

### DMInvite

A ticket plus the Notice the inviter pins.

```
record DMInvite {
    ticket  DMTicket
    notice  DMNotice
}
```

### DMTicket

Information the inviter shares with the invitee to start the handshake.

```
record DMTicket {
    secret      Secret
    billboards  List<Billboard>    length 1..=4
}
```

### DMInviteTag

Locator for a DMNotice on a Billboard.

```
type DMInviteTag   Tag
```

```
DMInviteTag = expand(DMTicket.secret, "chuchotez/1/dm-invite-billboard-tag")
```

### DMInviterIntakeTagKey

Locator key for the first DMSignedInviteeIntroduction on the inviter Mailboxes.

```
type DMInviterIntakeTagKey   TagKey
```

```
DMInviterIntakeTagKey = expand(DMTicket.secret, "chuchotez/1/dm-inviter-intake-tag-key")
```

### MailboxTag  (planned)

A Mailbox locator for a time bin of Messages.

```
type TimeBin       integer
type MailboxTag    Tag
```

```
TimeBin = time_bin(unix_seconds)
MailboxTag = expand(tag_key, label || be<64>u(TimeBin))
             label encoding later
```

`unix_seconds` is a Unix time in seconds. The host watches `TimeBin-1`,
`TimeBin`, and `TimeBin+1`. `tag_key` is the DMInviterIntakeTagKey for the first
post to the inviter, then the DMInviteeIntakeTagKey for posts to the invitee.

### DMNotice

Billboard body. `intake_pk` is the wrap target for the invitee’s
DMSignedInviteeIntroduction. `mailboxes` are where that blob is posted.

```
record DMNotice {
    policy      Policy
    intake_pk   PublicKey
    mailboxes   List<Mailbox>    length 1..=4
    wires       List<Wire>       length 0..=4
}
```

`intake_pk` length MUST match `policy`.

### CallingCard

The conversation Policy is `DMNotice.policy`. Key and signature lengths MUST
match that Policy.

```
record CallingCard {
    name              DisplayName
    encryption_pk     PublicKey
    signing_pk        SigningPublicKey
    mailbox_tag_key   TagKey
    mailboxes         List<Mailbox>    length 1..=4
    wires             List<Wire>       length 0..=4
}
```

`mailbox_tag_key` is `random32()`.

### DMInviteeIntakeTagKey

Locator key for later Messages on the invitee’s Mailboxes.

```
type DMInviteeIntakeTagKey   TagKey
```

```
DMInviteeIntakeTagKey = random32()
```

### DMInviteeIntroduction  (planned)

Inner value the invitee posts. `intake_pk` is the wrap target for the inviter’s
later card. `intake_tag_key` locates that card on the invitee’s Mailboxes.

```
record DMInviteeIntroduction {
    calling_card     CallingCard
    intake_pk        PublicKey
    intake_tag_key   DMInviteeIntakeTagKey
}
```

`intake_pk` length MUST match `DMNotice.policy`. Conversation Intake is
`keygen(DMNotice.policy, random32() || random32())`. The Intake secret stays on
the invitee tree.

### DMSignedInviteeIntroduction (planned)

Signed introduction. The host posts `mailbox_blob` to every DMNotice Mailbox at
the DMInviterIntakeTagKey. The Engine stores `mailbox_blob` at mint.

```
record DMSignedInviteeIntroduction {
    introduction  DMInviteeIntroduction
    sig           Signature
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

### DMInviterIntroduction  (planned)

Inner value the inviter posts.

```
record DMInviterIntroduction {
    calling_card     CallingCard
}
```

### DMSignedInviterIntroduction  (planned)

Signed introduction. The host posts `mailbox_blob` to every
`DMInviteeIntroduction.calling_card` Mailbox at the `DMInviteeIntakeTagKey`.
The Engine stores `mailbox_blob` at mint.

```
record DMSignedInviterIntroduction {
    introduction  DMInviterIntroduction
    sig           Signature
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

### EstablishedDigest  (planned)

32-byte tagged hash of both signed introductions. Both sides compute it after
they hold `DMSignedInviterIntroduction` and `DMSignedInviteeIntroduction`. The
`tag` is a public domain-separation string.

```
type EstablishedDigest   byte[32]
```

```
tag                = UTF-8 "chuchotez/1/dm-established"
EstablishedDigest  = mac(tag, canonical(DMSignedInviterIntroduction) || canonical(DMSignedInviteeIntroduction))
```

The concatenation order is inviter then invitee. When a party confirms the
peer’s digest equals its own, that party’s conversation becomes `Established`.

### Command

A mutation of EngineState. `CommandOp` is which mutation.

```
type CommandOp   create_user | create_identity | delete_user | delete_identity
               | delete_conversation | set_display_name | unset_display_name
               | create_invite | mark_notices_pinned | receive_ticket
               | receive_notice | fail_conversation | create_calling_card
```

```
record Command {
    op  CommandOp
}
```

The remaining fields are exactly those for `op`. `ticket` is a DMTicket.
`notice` is a DMNotice. `apply` folds a Command into EngineState with no extra
randomness.

| `op` | Other fields |
| --- | --- |
| `create_user` | `user_id` |
| `create_identity` | `user_id`, `identity_id`, `encryption_pk`, `encryption_sk`, `signing_pk`, `signing_sk` |
| `delete_user` | `user_id` |
| `delete_identity` | `user_id`, `identity_id` |
| `delete_conversation` | `user_id`, `identity_id`, `conversation_id` |
| `set_display_name` | `user_id`, `identity_id`, `name` |
| `unset_display_name` | `user_id`, `identity_id` |
| `create_invite` | `user_id`, `identity_id`, `conversation_id`, `ticket`, `intake_pk`, `intake_sk`, `mailboxes`, `wires` |
| `mark_notices_pinned` | `user_id`, `identity_id`, `conversation_id` |
| `receive_ticket` | `user_id`, `identity_id`, `conversation_id`, `ticket` |
| `receive_notice` | `user_id`, `identity_id`, `conversation_id`, `notice` |
| `fail_conversation` | `user_id`, `identity_id`, `conversation_id`, `reason` = `policy_not_accepted`, `ticket`, `notice` |
| `create_calling_card` | `user_id`, `identity_id`, `conversation_id`, `name`, `encryption_pk`, `signing_pk`, `mailbox_tag_key`, `mailboxes`, `wires` |

Planned `create_calling_card` fields: `intake_pk`, `intake_sk`, `intake_tag_key`,
`sig`, `mailbox_blob`.

### Later conversations

`Group` and `Synchronization` conversations. Pairwise streams after
`Established`. Those tickets are domain records of a different sort.

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
| `policy_not_accepted` | JSON string `"policy_not_accepted"` |
| `string` (`Kind`, `Address`, `DisplayName`, …) | JSON string of that Unicode value |
| `byte[n]` / `byte[]` | JSON string `text(bytes)` |
| `List<T>` | JSON array of `J(T)` in list order |
| record | JSON object: one member per field, name = field name, value = `J(field)` |

Top-level artifacts that travel as a JSON document also carry a discriminator
member `"type"` with a constant string. Nested records (Billboard, Mailbox,
Wire, and fields inside Command) omit `"type"`. `J⁻¹` refuses an unknown
`"type"`.

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

A passphrase vault for the host `key` is later work.
