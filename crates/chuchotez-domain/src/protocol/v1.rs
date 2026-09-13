//! First on-wire layout.
//!
//! Pins [`SECRET_LEN`] secrets, HMAC-SHA-256 as the HKDF PRF, one-hour mailbox
//! bins, and the closed billboard / mailbox / live unions. A later layout is a
//! sibling module and a new enum variant on the crate-level types.

use super::hkdf::{DIGEST_LEN, HmacSha256Key, HmacSha256Mac};

/// Length of v1 secrets, tags, and derived keys. Same as HMAC-SHA-256 output.
pub const SECRET_LEN: usize = DIGEST_LEN;

/// HKDF-Expand `info` for [`InviteTag`](super::InviteTag).
pub const INFO_INVITE_TAG: &[u8] = b"chuchotez/1/invite-tag";

/// HKDF-Expand `info` for [`MailboxTagKey`](super::MailboxTagKey).
pub const INFO_MAILBOX_TAG_KEY: &[u8] = b"chuchotez/1/mailbox-tag-key";

/// Shared secret bytes for the first layout.
///
/// This value is the PRK for HKDF-Expand. [`InviteTag`](super::InviteTag) and
/// [`MailboxTagKey`](super::MailboxTagKey) are derived from it with distinct
/// info strings so those roles cannot be swapped.
#[derive(Clone, Eq)]
pub struct InviteSecret {
    prk: HmacSha256Key,
}

impl InviteSecret {
    /// Wrap [`SECRET_LEN`] bytes that already have the invite-secret role (RNG output).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SECRET_LEN]) -> Self {
        Self {
            prk: HmacSha256Key::from_bytes(bytes),
        }
    }

    /// Invite-secret bytes for hosts and codecs.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SECRET_LEN] {
        self.prk.as_bytes()
    }

    pub(super) const fn as_prk(&self) -> &HmacSha256Key {
        &self.prk
    }
}

impl PartialEq for InviteSecret {
    fn eq(&self, other: &Self) -> bool {
        self.prk == other.prk
    }
}

impl core::fmt::Debug for InviteSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("InviteSecret(..)")
    }
}

/// Locator tag for the invite document, derived from [`InviteSecret`].
#[derive(Clone, Eq)]
pub struct InviteTag {
    mac: HmacSha256Mac,
}

impl InviteTag {
    /// Wrap a derived (or round-tripped) tag.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SECRET_LEN]) -> Self {
        Self {
            mac: HmacSha256Mac::from_bytes(bytes),
        }
    }

    pub(super) const fn from_mac(mac: HmacSha256Mac) -> Self {
        Self { mac }
    }

    /// Derived tag bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SECRET_LEN] {
        self.mac.as_bytes()
    }
}

impl PartialEq for InviteTag {
    fn eq(&self, other: &Self) -> bool {
        self.mac == other.mac
    }
}

impl core::fmt::Debug for InviteTag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("InviteTag(..)")
    }
}

/// Key from which time-binned mailbox tags are derived.
#[derive(Clone, Eq)]
pub struct MailboxTagKey {
    mac: HmacSha256Mac,
}

impl MailboxTagKey {
    /// Wrap a derived mailbox tag key.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SECRET_LEN]) -> Self {
        Self {
            mac: HmacSha256Mac::from_bytes(bytes),
        }
    }

    pub(super) const fn from_mac(mac: HmacSha256Mac) -> Self {
        Self { mac }
    }

    /// PRK bytes for later per-bin mailbox tag Expand.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SECRET_LEN] {
        self.mac.as_bytes()
    }
}

impl PartialEq for MailboxTagKey {
    fn eq(&self, other: &Self) -> bool {
        self.mac == other.mac
    }
}

impl core::fmt::Debug for MailboxTagKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MailboxTagKey(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::{InviteSecret, InviteTag, MailboxTagKey, SECRET_LEN};

    #[test]
    fn debug_redacts_payloads() {
        let secret = InviteSecret::from_bytes([0xab; SECRET_LEN]);
        let tag = InviteTag::from_bytes([0xcd; SECRET_LEN]);
        let key = MailboxTagKey::from_bytes([0xef; SECRET_LEN]);
        assert_eq!(format!("{secret:?}"), "InviteSecret(..)");
        assert_eq!(format!("{tag:?}"), "InviteTag(..)");
        assert_eq!(format!("{key:?}"), "MailboxTagKey(..)");
        assert!(!format!("{secret:?}").contains("ab"));
        assert!(!format!("{tag:?}").contains("cd"));
        assert!(!format!("{key:?}").contains("ef"));
    }

    #[test]
    fn mailbox_tag_key_eq() {
        let a = MailboxTagKey::from_bytes([1; SECRET_LEN]);
        let b = MailboxTagKey::from_bytes([1; SECRET_LEN]);
        let c = MailboxTagKey::from_bytes([2; SECRET_LEN]);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.as_bytes(), &[1; SECRET_LEN]);
    }
}
