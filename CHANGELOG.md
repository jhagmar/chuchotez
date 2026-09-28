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
`Conversation`. `std_suite` adds SHA-256 (`LibcruxSha256`) and
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
`expires` pre-confirm stores `InviteExpired`. `confirmation_digest` is an
empty string. Group invites use an
Established DM and have no Ticket, InviteTag, or intake KEM.
