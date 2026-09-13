//! Chuchotez is a communications backend the app author does not operate.
//!
//! A Billboard is a Channel A shares with B so A has at least write and B has
//! at least read. Notices such as PublicInvite pin at a Tag (a coordinate on
//! that Billboard). A Mailbox is a Channel A shares with B so A has at least
//! read and B has at least write. A Message stream is identified by a Tag Key;
//! Message bins by that key and binned time. Pairwise streams, a group mesh, and a live ladder compile for
//! `wasm32-unknown-unknown` with the Rust standard library. Chat and turn-based
//! games are application mappings. Crypto policy is [`Policy::Hybrid`] for a
//! messenger host, [`Policy::Classic`] when a game asks for it.
//!
//! This crate is the package hosts depend on. Construct a [`v1::Engine`] with
//! [`v1::std_engine`]. Supply [`Rng`] on every call that needs entropy. A DM
//! [`v1::InviteSecret`] is the QR capability (secret bytes plus Billboards);
//! Tag, Tag Key, and the compact envelope are bound to that secret.
//!
//! ```
//! use chuchotez::v1;
//! use chuchotez::{RANDOM32_LEN, Random32, Rng};
//!
//! struct HostRng;
//!
//! impl Rng for HostRng {
//!     fn random32(&self) -> Random32 {
//!         Random32::from_bytes([1; RANDOM32_LEN])
//!     }
//! }
//!
//! let engine: v1::Engine = v1::std_engine(v1::Policy::Hybrid);
//! let board = engine.new_billboard(
//!     engine.try_new_billboard_kind("nostr").expect("kind"),
//!     engine
//!         .try_new_billboard_address("wss://relay.example")
//!         .expect("addr"),
//! );
//! let secret = engine
//!     .try_new_invite_secret(&HostRng, &[board])
//!     .expect("secret");
//! let tag = secret.billboard_tag();
//! let tag_key = secret.mailbox_tag_key();
//! let blob = secret.serialize();
//! let _ = (tag, tag_key, blob);
//! ```

pub use chuchotez_adapters::{Base64Ct, Deflate, Sha2};
pub use chuchotez_domain::{Policy, RANDOM32_LEN, Random32, Random32Bytes, Rng, VERSION, protocol};

/// First on-wire layout: engine, invite secret, and portable adapters.
pub mod v1 {
    pub use chuchotez_adapters::v1::{std_engine, std_suite};
    pub use chuchotez_domain::v1::*;
}

#[cfg(test)]
mod tests {
    use super::v1;
    use super::{Policy, RANDOM32_LEN, Random32, Rng};

    struct SeedRng([u8; RANDOM32_LEN]);

    impl Rng for SeedRng {
        fn random32(&self) -> Random32 {
            Random32::from_bytes(self.0)
        }
    }

    fn fill(byte: u8) -> [u8; RANDOM32_LEN] {
        [byte; RANDOM32_LEN]
    }

    #[test]
    fn host_keeps_engine_and_supplies_rng() {
        let engine: v1::Engine = v1::std_engine(v1::Policy::Hybrid);
        let board = engine.new_billboard(
            engine.try_new_billboard_kind("nostr").expect("kind"),
            engine
                .try_new_billboard_address("wss://relay.example")
                .expect("addr"),
        );
        let secret = engine
            .try_new_invite_secret(&SeedRng(fill(0x11)), std::slice::from_ref(&board))
            .expect("secret");
        assert_eq!(secret.billboards().len(), 1);
        let tag = secret.billboard_tag();
        let again = secret.billboard_tag();
        assert_eq!(tag, again);
        let key = secret.mailbox_tag_key();
        assert_ne!(tag.as_bytes(), key.as_bytes());
        assert_eq!(format!("{secret:?}"), "InviteSecret(..)");
        let other = engine
            .try_new_invite_secret(&SeedRng(fill(0x22)), std::slice::from_ref(&board))
            .expect("other");
        assert_ne!(secret, other);
        assert_eq!(
            secret,
            engine
                .try_new_invite_secret(&SeedRng(fill(0x11)), std::slice::from_ref(&board))
                .expect("again")
        );
        let other_engine = v1::std_engine(Policy::Classic);
        let blob = secret.serialize();
        let parsed = other_engine.try_parse_invite_secret(&blob).expect("parse");
        assert_eq!(parsed, secret);
        assert_eq!(parsed.billboard_tag(), secret.billboard_tag());
        assert!(!blob.contains('='));
        assert!(matches!(
            engine.try_parse_invite_secret("!!!!").unwrap_err(),
            v1::EnvelopeError::Base64(_)
        ));
        let _ = v1::std_suite();
        assert_eq!(
            v1::std_engine(Policy::PostQuantum).policy(),
            Policy::PostQuantum
        );
    }
}
