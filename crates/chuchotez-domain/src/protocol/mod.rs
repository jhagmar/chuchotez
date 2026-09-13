//! Wire objects and pure transforms.
//!
//! Version lives on closed enums (`InviteSecret::V1`, …). A new protocol
//! revision is a new variant plus a sibling module (`v2`, …). Call sites `match`,
//! so a missed upgrade is a compile error. Types inside [`v1`] use ordinary
//! names (`InviteSecret`, `InviteTag`); the module is the version.

pub mod v1;

mod bytes32;
mod hkdf;

pub use hkdf::{EXPAND_LEN, HmacSha256, HmacSha256Key, HmacSha256Mac};

/// Length of [`Random32`] CSPRNG output.
pub const RANDOM32_LEN: usize = 32;

/// [`RANDOM32_LEN`] bytes as an array.
pub type Random32Bytes = [u8; RANDOM32_LEN];

/// [`RANDOM32_LEN`] cryptographically random bytes from [`Rng`].
///
/// Branded so a hash digest or a key cannot be passed where fresh entropy is
/// required. [`v1::InviteSecret::from_bytes`] is the step that assigns those
/// bytes the invite-secret role.
#[derive(Clone, Eq)]
pub struct Random32(Random32Bytes);

impl Random32 {
    /// Wrap output that is already [`RANDOM32_LEN`] cryptographically random bytes.
    #[must_use]
    pub const fn from_bytes(bytes: Random32Bytes) -> Self {
        Self(bytes)
    }

    /// Raw bytes for a constructor that consumes entropy.
    #[must_use]
    pub const fn as_bytes(&self) -> &Random32Bytes {
        &self.0
    }

    /// Consume the wrapper and return the array.
    #[must_use]
    pub const fn into_bytes(self) -> Random32Bytes {
        self.0
    }
}

impl PartialEq for Random32 {
    fn eq(&self, other: &Self) -> bool {
        bytes32::ct_eq(&self.0, &other.0)
    }
}

impl core::fmt::Debug for Random32 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Entropy is about to become a secret; keep it out of logs.
        f.write_str("Random32(..)")
    }
}

/// Cryptographic randomness. The host supplies a CSPRNG on every call that
/// needs entropy. Tests inject a seed.
pub trait Rng {
    /// [`RANDOM32_LEN`] cryptographically random bytes.
    fn random32(&self) -> Random32;
}

/// Shared secret from which invite locators and mailbox keys are derived.
///
/// v1 is [`v1::SECRET_LEN`] random bytes used as the HKDF-Expand PRK. Hosts carry
/// this value to the peer; the domain only sees the bytes and the version.
#[derive(Clone, Eq)]
pub enum InviteSecret {
    /// First layout: HMAC-SHA-256 Expand with `chuchotez/1/` infos.
    V1(v1::InviteSecret),
}

impl InviteSecret {
    /// Assign host RNG output the v1 invite-secret role.
    #[must_use]
    pub fn v1_from_rng<R: Rng + ?Sized>(rng: &R) -> Self {
        Self::V1(v1::InviteSecret::from_bytes(rng.random32().into_bytes()))
    }

    /// Invite-document locator tag (HKDF-Expand, [`v1::INFO_INVITE_TAG`]).
    #[must_use]
    pub fn tag_with<H: HmacSha256 + ?Sized>(&self, hmac: &H) -> InviteTag {
        match self {
            Self::V1(secret) => InviteTag::V1(v1::InviteTag::from_mac(hkdf::expand(
                hmac,
                secret.as_prk(),
                v1::INFO_INVITE_TAG,
            ))),
        }
    }

    /// Mailbox tag key (HKDF-Expand, [`v1::INFO_MAILBOX_TAG_KEY`]).
    #[must_use]
    pub fn mailbox_tag_key_with<H: HmacSha256 + ?Sized>(&self, hmac: &H) -> MailboxTagKey {
        match self {
            Self::V1(secret) => MailboxTagKey::V1(v1::MailboxTagKey::from_mac(hkdf::expand(
                hmac,
                secret.as_prk(),
                v1::INFO_MAILBOX_TAG_KEY,
            ))),
        }
    }
}

impl PartialEq for InviteSecret {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::V1(a), Self::V1(b)) => a == b,
        }
    }
}

impl core::fmt::Debug for InviteSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::V1(_) => f.write_str("InviteSecret::V1(..)"),
        }
    }
}

/// Locator tag for the invite document, derived from [`InviteSecret`].
#[derive(Clone, Eq)]
pub enum InviteTag {
    /// Tag derived with [`v1::INFO_INVITE_TAG`].
    V1(v1::InviteTag),
}

impl PartialEq for InviteTag {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::V1(a), Self::V1(b)) => a == b,
        }
    }
}

impl core::fmt::Debug for InviteTag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::V1(_) => f.write_str("InviteTag::V1(..)"),
        }
    }
}

/// Key from which time-binned mailbox tags are derived.
#[derive(Clone, Eq)]
pub enum MailboxTagKey {
    /// Key derived with [`v1::INFO_MAILBOX_TAG_KEY`].
    V1(v1::MailboxTagKey),
}

impl PartialEq for MailboxTagKey {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::V1(a), Self::V1(b)) => a == b,
        }
    }
}

impl core::fmt::Debug for MailboxTagKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::V1(_) => f.write_str("MailboxTagKey::V1(..)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::hkdf::EXPAND_T1_COUNTER;
    use super::{
        HmacSha256, HmacSha256Key, HmacSha256Mac, InviteSecret, InviteTag, MailboxTagKey, Random32,
        Rng, v1,
    };
    use std::cell::RefCell;

    const SECRET_LEN: usize = v1::SECRET_LEN;

    fn fill(byte: u8) -> [u8; SECRET_LEN] {
        [byte; SECRET_LEN]
    }

    struct SeedRng([u8; SECRET_LEN]);

    impl Rng for SeedRng {
        fn random32(&self) -> Random32 {
            Random32::from_bytes(self.0)
        }
    }

    /// Mixes `key` and `data` so distinct infos yield distinct outputs.
    struct XorHmac;

    impl HmacSha256 for XorHmac {
        fn mac(&self, key: &HmacSha256Key, data: &[u8]) -> HmacSha256Mac {
            let mut out = *key.as_bytes();
            for (i, byte) in data.iter().enumerate() {
                let slot = i % out.len();
                out[slot] ^= byte;
            }
            HmacSha256Mac::from_bytes(out)
        }
    }

    #[test]
    fn v1_from_rng_uses_entropy() {
        let rng = SeedRng(fill(0x11));
        let secret = InviteSecret::v1_from_rng(&rng);
        match &secret {
            InviteSecret::V1(inner) => assert_eq!(inner.as_bytes(), &fill(0x11)),
        }
    }

    #[test]
    fn tag_passes_invite_tag_info_and_counter() {
        struct Record {
            data: RefCell<Vec<u8>>,
        }
        impl HmacSha256 for Record {
            fn mac(&self, _key: &HmacSha256Key, data: &[u8]) -> HmacSha256Mac {
                self.data.replace(data.to_vec());
                HmacSha256Mac::from_bytes(fill(0))
            }
        }
        let hmac = Record {
            data: RefCell::new(Vec::new()),
        };
        let secret = InviteSecret::V1(v1::InviteSecret::from_bytes(fill(0x22)));
        let _ = secret.tag_with(&hmac);
        let recorded = hmac.data.borrow();
        assert_eq!(&recorded[..v1::INFO_INVITE_TAG.len()], v1::INFO_INVITE_TAG);
        assert_eq!(recorded[v1::INFO_INVITE_TAG.len()], EXPAND_T1_COUNTER);
    }

    #[test]
    fn mailbox_key_passes_mailbox_info_and_counter() {
        struct Record {
            data: RefCell<Vec<u8>>,
        }
        impl HmacSha256 for Record {
            fn mac(&self, _key: &HmacSha256Key, data: &[u8]) -> HmacSha256Mac {
                self.data.replace(data.to_vec());
                HmacSha256Mac::from_bytes(fill(0))
            }
        }
        let hmac = Record {
            data: RefCell::new(Vec::new()),
        };
        let secret = InviteSecret::V1(v1::InviteSecret::from_bytes(fill(0x22)));
        let _ = secret.mailbox_tag_key_with(&hmac);
        let recorded = hmac.data.borrow();
        assert_eq!(
            &recorded[..v1::INFO_MAILBOX_TAG_KEY.len()],
            v1::INFO_MAILBOX_TAG_KEY
        );
        assert_eq!(recorded[v1::INFO_MAILBOX_TAG_KEY.len()], EXPAND_T1_COUNTER);
    }

    #[test]
    fn tag_and_mailbox_key_use_distinct_infos() {
        let secret = InviteSecret::V1(v1::InviteSecret::from_bytes(fill(0x22)));
        let tag = secret.tag_with(&XorHmac);
        let mailbox_key = secret.mailbox_tag_key_with(&XorHmac);
        match (&tag, &mailbox_key) {
            (InviteTag::V1(tag), MailboxTagKey::V1(key)) => {
                assert_ne!(tag.as_bytes(), key.as_bytes());
                assert_ne!(tag.as_bytes(), &fill(0x22));
            }
        }
    }

    #[test]
    fn equal_secrets_compare_equal() {
        let a = InviteSecret::V1(v1::InviteSecret::from_bytes(fill(7)));
        let b = InviteSecret::V1(v1::InviteSecret::from_bytes(fill(7)));
        let c = InviteSecret::V1(v1::InviteSecret::from_bytes(fill(8)));
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn equal_tags_compare_equal() {
        let a = InviteTag::V1(v1::InviteTag::from_bytes(fill(7)));
        let b = InviteTag::V1(v1::InviteTag::from_bytes(fill(7)));
        let c = InviteTag::V1(v1::InviteTag::from_bytes(fill(8)));
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn equal_mailbox_keys_compare_equal() {
        let a = MailboxTagKey::V1(v1::MailboxTagKey::from_bytes(fill(7)));
        let b = MailboxTagKey::V1(v1::MailboxTagKey::from_bytes(fill(7)));
        let c = MailboxTagKey::V1(v1::MailboxTagKey::from_bytes(fill(8)));
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn debug_omits_secret_bytes() {
        let secret = InviteSecret::V1(v1::InviteSecret::from_bytes(fill(0xde)));
        assert_eq!(format!("{secret:?}"), "InviteSecret::V1(..)");
        assert!(!format!("{secret:?}").contains("dead"));
    }

    #[test]
    fn debug_omits_tag_bytes() {
        let tag = InviteTag::V1(v1::InviteTag::from_bytes(fill(0xca)));
        assert_eq!(format!("{tag:?}"), "InviteTag::V1(..)");
        assert!(!format!("{tag:?}").contains("cafe"));
    }

    #[test]
    fn debug_omits_mailbox_key_bytes() {
        let key = MailboxTagKey::V1(v1::MailboxTagKey::from_bytes(fill(0xca)));
        assert_eq!(format!("{key:?}"), "MailboxTagKey::V1(..)");
        assert!(!format!("{key:?}").contains("cafe"));
    }

    #[test]
    fn random32_eq_and_debug() {
        let a = Random32::from_bytes(fill(0xab));
        let b = Random32::from_bytes(fill(0xab));
        let c = Random32::from_bytes(fill(0xcd));
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.as_bytes(), &fill(0xab));
        assert_eq!(a.clone().into_bytes(), fill(0xab));
        assert_eq!(format!("{a:?}"), "Random32(..)");
        assert!(!format!("{a:?}").contains("ab"));
    }
}
