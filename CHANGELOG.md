# Changelog

Published versions of this repository.

## Unreleased

`Invite` is Ticket plus Intake. `Ticket` is the compact DM QR (`b64u(version || INVITE_KIND_DM || raw_deflate(secret || billboards))`); serialize and `BillboardTag` take `&Engine`. `Intake` is `IntakeKeypair` plus Mailboxes and Wires. `Engine::try_new_invite` draws a `TicketSecret` and a 64-byte `KemSeed` (two `Random32`) from `&impl Rng`; `Kem::generate` returns `IntakeKeypair`. `Engine::serialize_notice` / `try_parse_notice` seal Billboard plaintext `{ policy, intake_pk, mailboxes, wires }` with AEAD key and nonce expanded from the Ticket (`chuchotez/1/notice-aead-key`, `chuchotez/1/notice-aead-nonce`); AAD is Ticket `version || kind`; parse requires `policy` to match the engine and `intake_pk` length to match that Policy. `AeadKey` and `AeadNonce` are newtypes. `std_suite` HMAC is `LibcruxHmac`; Intake is Classic X25519, PostQuantum ML-KEM-768, and Hybrid X-Wing.
