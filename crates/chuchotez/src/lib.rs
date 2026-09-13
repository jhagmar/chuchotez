//! Chuchotez is a communications backend the app author does not operate.
//!
//! A Billboard is a Channel A shares with B so A has at least write and B has
//! at least read. Notices such as PublicInvite pin at a Tag (a coordinate on
//! that Billboard). A Mailbox is a Channel A shares with B so A has at least
//! read and B has at least write. A Message stream is identified by a Tag Key;
//! Message bins by that key and binned time. Pairwise streams, a group mesh, and a live ladder compile for
//! `wasm32-unknown-unknown` with the Rust standard library. Chat and turn-based
//! games are application mappings. Crypto suite is policy: `hybrid` for a
//! messenger host, `classical` when a game asks for it.
//!
//! This crate is the package hosts depend on. Keep an [`Engine`] bound to a
//! suite. Supply [`Rng`] on every call that needs entropy.
//!
//! ```
//! use chuchotez::{InviteSecret, RANDOM32_LEN, Random32, Rng, std_engine};
//!
//! struct HostRng;
//!
//! impl Rng for HostRng {
//!     fn random32(&self) -> Random32 {
//!         Random32::from_bytes([1; RANDOM32_LEN])
//!     }
//! }
//!
//! let engine = std_engine();
//! let secret = InviteSecret::v1_from_rng(&HostRng);
//! let tag = engine.tag(&secret);
//! let tag_key = engine.mailbox_tag_key(&secret);
//! let _ = (tag, tag_key);
//! ```

pub use chuchotez_adapters::Sha2;
pub use chuchotez_domain::{
    EXPAND_LEN, Engine, HmacSha256, HmacSha256Key, HmacSha256Mac, InviteSecret, InviteTag,
    MailboxTagKey, RANDOM32_LEN, Random32, Random32Bytes, Rng, Suite, VERSION, protocol, v1,
};

/// Default portable suite (HMAC-SHA-256 over RustCrypto).
#[must_use]
pub fn std_suite() -> Suite {
    chuchotez_adapters::std_suite()
}

/// [`Engine`] bound to [`std_suite`].
#[must_use]
pub fn std_engine() -> Engine {
    Engine::new(std_suite())
}

#[cfg(test)]
mod tests {
    use super::{
        InviteSecret, InviteTag, MailboxTagKey, RANDOM32_LEN, Random32, Rng, Sha2, std_engine,
    };

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
        let engine = std_engine();
        let secret = InviteSecret::v1_from_rng(&SeedRng(fill(0x11)));
        match &secret {
            InviteSecret::V1(inner) => assert_eq!(inner.as_bytes(), &fill(0x11)),
        }
        let tag = engine.tag(&secret);
        let again = engine.tag(&secret);
        assert_eq!(tag, again);
        let key = engine.mailbox_tag_key(&secret);
        match (&tag, &key) {
            (InviteTag::V1(tag), MailboxTagKey::V1(key)) => {
                assert_ne!(tag.as_bytes(), key.as_bytes());
            }
        }
        assert_eq!(tag, secret.tag_with(&Sha2));
        assert_eq!(key, secret.mailbox_tag_key_with(&Sha2));
        assert_eq!(format!("{secret:?}"), "InviteSecret::V1(..)");
        let other = InviteSecret::v1_from_rng(&SeedRng(fill(0x22)));
        assert_ne!(secret, other);
        assert_eq!(secret, InviteSecret::v1_from_rng(&SeedRng(fill(0x11))));
        let other_engine = std_engine();
        assert_eq!(engine.tag(&secret), other_engine.tag(&secret));
    }
}
