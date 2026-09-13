# Changelog

Published versions of this repository.

## Unreleased

Workspace: domain crate `chuchotez-domain`, adapters crate `chuchotez-adapters`, facade crate `chuchotez`, `wasm32-unknown-unknown` as a first-class target, CI gates, and a pre-commit hook that runs `cargo fmt --all`.

Protocol types: `v1::InviteSecret` (secret bytes plus a nonempty Billboard list of opaque `kind`+`address`, bound to a `v1::Engine`), Billboard `InviteTag`, Mailbox `MailboxTagKey`, host-supplied `Rng`, and HKDF-Expand over an `HmacSha256` port (`HmacSha256Key` / `HmacSha256Mac`). Layout version is the module (`v1::Engine`, `v1::Suite`). `v1::std_engine(Policy)` constructs a v1 engine; every engine honors `Classic`, `PostQuantum`, and `Hybrid`. Tag, Tag Key, and the compact DM envelope (`b64u(version || kind || raw Deflate)` with `INVITE_KIND_DM = 0x01`) live on the bound secret (`billboard_tag`, `mailbox_tag_key`, `serialize`). Entropy stays a host `Rng` argument. No process-global suite. A Billboard is a Channel A shares with B so A has at least write and B has at least read (Notices pin at a Tag). A Mailbox is a Channel A shares with B so A has at least read and B has at least write (a Message stream is a Tag Key; bins are that key and binned time). Mapping libraries live beside this crate.
