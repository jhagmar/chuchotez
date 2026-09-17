# Changelog

Published versions of this repository.

## Unreleased

`create_identity` stores Policy-matched encryption and signing keypairs
(`Kem::generate` plus `Sign::generate`: Classic Ed25519, PostQuantum
ML-DSA-65, Hybrid both concatenated). After `InviteReceived`,
`create_calling_card` mints a local `CallingCard` and logs
`CallingCardCreated`. Named mutators return `PersistOk`. `create_user`,
`create_identity`, `create_invite`, and `receive_ticket` also return the drawn
id. Ticket and Notice blobs, Billboard tags, and the CallingCard are Engine
getters. `std_suite` Sign is `LibcruxSign`. Wrap, sign, and send of a
CallingCard are a later slice.

`EngineState` is the host-owned ADT: `User` / `Identity` / `Conversation`
(`DirectMessage` Inviter `InviteCreated` and `NoticePinned`, Invitee
`TicketReceived`, `InviteReceived`, and `CallingCardCreated`,
`Failed::PolicyNotAccepted`). Named Engine methods construct a deterministic
`Command` and return `aead(deflate(RFC 8785))` sealed with the host DEK.
`apply` and `try_open_command` hydrate the log. Public Engine methods drive or
query `EngineState`. `Invite` is Ticket plus Intake. `Ticket` is the compact
DM QR (`b64u(version || INVITE_KIND_DM || raw_deflate(secret || billboards))`);
serialize and `BillboardTag` take `&Engine`. `Intake` is `IntakeKeypair` plus
Mailboxes and Wires. Notice plaintext is `{ policy, intake_pk, mailboxes,
wires }` sealed from the Ticket. `AeadKey` and `AeadNonce` are newtypes.
`std_suite` HMAC is `LibcruxHmac`; Intake is Classic X25519, PostQuantum
ML-KEM-768, and Hybrid X-Wing.
