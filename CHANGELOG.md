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
channel lists are length 1..=4; ephemeral lists are 0..=4.
