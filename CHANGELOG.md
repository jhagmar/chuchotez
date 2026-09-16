# Changelog

Published versions of this repository.

## Unreleased

`EngineState` is the host-owned ADT: `User` / `Identity` / `Conversation`
(`DirectMessage` Inviter `InviteCreated` and `NoticePinned`, Invitee
`TicketReceived` and `InviteReceived`, `Failed::PolicyNotAccepted`). Named
Engine methods construct a deterministic `Command` and return
`aead(deflate(RFC 8785))` sealed with the host DEK. `apply` and
`try_open_command` hydrate the log. `create_invite` Ok carries the compact
Ticket blob, Notice blob, and Billboard Tag. Public Engine methods drive or
query `EngineState`. `Invite` is Ticket plus Intake. `Ticket` is the compact
DM QR (`b64u(version || INVITE_KIND_DM || raw_deflate(secret || billboards))`);
serialize and `BillboardTag` take `&Engine`. `Intake` is `IntakeKeypair` plus
Mailboxes and Wires. Notice plaintext is `{ policy, intake_pk, mailboxes,
wires }` sealed from the Ticket. `AeadKey` and `AeadNonce` are newtypes.
`std_suite` HMAC is `LibcruxHmac`; Intake is Classic X25519, PostQuantum
ML-KEM-768, and Hybrid X-Wing.
