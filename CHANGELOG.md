# Changelog

Published versions of this repository.

## Unreleased

Workspace: domain crate `chuchotez-domain`, adapters crate `chuchotez-adapters`, facade crate `chuchotez`, `wasm32-unknown-unknown` as a first-class target, CI gates, and a pre-commit hook that runs `cargo fmt --all`.

Protocol types: versioned `InviteSecret`, `InviteTag`, `MailboxTagKey`, host-supplied `Rng`, and HKDF-Expand over an `HmacSha256` port (`HmacSha256Key` / `HmacSha256Mac`). The host holds an `Engine` bound to a suite (`std_engine` ships HMAC-SHA-256). Entropy stays a host `Rng` argument. No process-global suite.
