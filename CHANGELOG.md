# Changelog

Published versions of this repository.

## Unreleased

`v1::Engine` is bound to `Defaults`. Policy is per identity. `EngineState` is
a CRDT of durable transactions keyed by `tx_id`. Mutators return persist
records `nonce || lock(DEK, DurableBody)` with empty AAD. `wrap_dek` /
`unlock` / `lock` hold the DEK under Argon2id or a PRF wrap. `tick` is
required before `poll` and mints. Ticket host strings are
`text(packed(Ticket))`. Query `Conversation` / `Handshake` are enums
(`HandshakeInviter`, `HandshakeInvitee`, `FailedReason`, `DirectMessageQuery`,
`GroupQuery`, `SynchronizationQuery`); `ConversationListRow` carries
`Conversation`. The stored row is that phase. Fold version 1 writes users,
identities, and those conversations, with Sync on the device. `std_suite` adds SHA-256 (`LibcruxSha256`) and
Argon2id (`RustcryptoArgon2id`). Kem wrap/unwrap and Sign sign/verify ship
for Classic, PostQuantum, and Hybrid. `ADDRESS_MAX_LEN` is 256. Persistent
channel lists are length 1..=4; ephemeral lists are 0..=4. `PacketPlain`
alternatives map through `J` / `J⁻¹`. `packed(PacketPlain)` that exceeds
`PACKET_PAD_LEN` (484) is `BodyTooLarge`. Handshake sending-chain join omits
`actor_id`; `create_invite` and `create_sync_invite` post 512-byte sealed
`PacketTxFrag` bodies of `TxNotice` at InviteTag. `ingest_list` /
`ingest_packet` open those bodies with skip-ahead `mk`, reassemble by `tx_id`
and `frag_i`, and merge. A full durable list completes that TimeBin in
`BinProgress`. Empty invite-tag snapshot leaves Invitee `TicketReceived`. A
valid `TxNotice` is Invitee `InviteReceived`. A valid notice plus DisplayName
mints `TxInviteeIntro`. Inviter ingest of that intro mints `TxInviterIntro`
and consumes the ticket. `writeAck` of the intro set is Inviter `Confirming`
/ Invitee `IntroductionSent`. Invitee ingest of inviter intro is `Confirming`.
Policy mismatch, unlock failure, Notice conflict, intro unlock/verify
failure, and duplicate intro store `FailedReason` overlays. `tick` past
`expires` pre-confirm stores `InviteExpired`. `confirmation_digest` is
`text(fingerprint)`. `confirmEstablished` posts `TxConfirm` and inserts a
child DM or Sync whose `conversation_id` is
`mac(spawn_secret, "chuchotez/1/spawn-conversation-id")` and whose secret is
`spawn_secret`. `rejectEstablished` stores `ConfirmationRejected`. Handshake
and spawned DM are two `listConversations` rows. Group invites use an
Established DM and have no Ticket, InviteTag, or intake KEM. Durable
`PacketTxFragLast` / `PacketXorAck` matching `set_xor` after merge stores
last Persistent ack. Watermark is the intersection of last Persistent acks
from members who have Persistent-acked at least once. `fold` is `WrongPhase`
when a persist seq's tx is outside the watermark. Fold MAY drop txs with
`expire_at` ≤ ticked now. Cached `mk` is deleted when every tx on that packet
is watermarked. Invite-tag list continues until that intro is watermarked.
Handshake catch-up lists incomplete bins from `list_from` (the TimeBin at
`create_invite` / `receive_ticket`) or `watermark + 1` through `W+1`, union
`[W-1, W, W+1]`. Mapper `list` / `listen` MAY omit TimeBin < `W-71`. Packet
chains, skip-ahead `mk`s, and last Persistent acks live on the conversation
row. `PersistSeq`, `UnixSeconds`, `TimeBin`, `PacketSeq`, `PacketEpoch`,
`FragIndex`, and `ActorId` are branded. When 50 durable packets have been
sent since the last `TxAdvertise`, `TxWrap`, or `TxAck`, the next send mints
the one still owed. Every 8th durable packet mixes when the FIFO holds 8
agreed shareds. At most 8 unused advertised secret keys are kept. A set-XOR mismatch binary-searches `tx_id`s until one
id, then want/have, and retransmits the missing tx. While live, heal uses
Ephemeral; after 3 ticked seconds without an answer it continues on
Persistent. Established DM and Sync sends with a nonempty ephemerals list
enqueue on Ephemeral first. A matching ephemeral `PacketXorAck` omits
Persistent; `tick` after 3 seconds enqueues it. `TxAdvertise`, `TxWrap`, and
`TxAck` stay Persistent. Empty ephemerals and Group sends are Persistent
only. `sendText` and the other DM chat mutators require an established DM.
`sendTyping` and `sendPresence` are also legal on established Sync. Query
`messages` is the newest 1000 chat items. Typing clears after 6 ticked
seconds. A durable DM tx pings the peer Wake when set.
