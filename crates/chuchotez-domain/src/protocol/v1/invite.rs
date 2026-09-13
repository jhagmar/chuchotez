//! Invite secret, Billboard Tag, and Mailbox Tag Key.

use super::{
    BILLBOARD_MAX_COUNT, Billboard, Engine, HmacSha256Key, HmacSha256Mac, INFO_INVITE_TAG,
    INFO_MAILBOX_TAG_KEY, SECRET_LEN, hkdf,
};

/// Why constructing an [`InviteSecret`] rejected the Billboard list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InviteSecretError {
    /// No Billboard (hosts must pass at least one).
    EmptyBillboards,
    /// More than [`BILLBOARD_MAX_COUNT`].
    TooManyBillboards,
}

impl core::fmt::Display for InviteSecretError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyBillboards => f.write_str("invite secret needs at least one Billboard"),
            Self::TooManyBillboards => {
                write!(
                    f,
                    "invite secret has more than {BILLBOARD_MAX_COUNT} Billboards"
                )
            }
        }
    }
}

impl std::error::Error for InviteSecretError {}

/// Shared secret bytes plus the Billboards the invitee should fetch.
///
/// Bound to the [`Engine`] that created or parsed it. Secret bytes are the
/// HMAC-SHA-256 key for HKDF-Expand. The Billboard [`InviteTag`] and the
/// Mailbox [`MailboxTagKey`] are derived from those bytes with distinct info
/// strings so those roles cannot be swapped. Equality compares secret bytes
/// and Billboards only.
#[derive(Clone)]
pub struct InviteSecret {
    engine: Engine,
    secret: HmacSha256Key,
    billboards: Vec<Billboard>,
}

impl InviteSecret {
    /// Wrap an engine, [`SECRET_LEN`] bytes, and a nonempty Billboard list.
    pub(crate) fn from_parts(
        engine: Engine,
        bytes: [u8; SECRET_LEN],
        billboards: Vec<Billboard>,
    ) -> Result<Self, InviteSecretError> {
        if billboards.is_empty() {
            return Err(InviteSecretError::EmptyBillboards);
        }
        if billboards.len() > BILLBOARD_MAX_COUNT {
            return Err(InviteSecretError::TooManyBillboards);
        }
        Ok(Self {
            engine,
            secret: HmacSha256Key::from_bytes(bytes),
            billboards,
        })
    }

    pub(crate) const fn secret_bytes(&self) -> &[u8; SECRET_LEN] {
        self.secret.as_bytes()
    }

    pub(crate) fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Billboards the invitee tries in list order.
    #[must_use]
    pub fn billboards(&self) -> &[Billboard] {
        &self.billboards
    }

    /// Billboard Tag via the bound engine.
    #[must_use]
    pub fn billboard_tag(&self) -> InviteTag {
        InviteTag::from_mac(hkdf::expand(
            self.engine.hmac(),
            &self.secret,
            INFO_INVITE_TAG,
        ))
    }

    /// Mailbox Tag Key via the bound engine.
    #[must_use]
    pub fn mailbox_tag_key(&self) -> MailboxTagKey {
        MailboxTagKey::from_mac(hkdf::expand(
            self.engine.hmac(),
            &self.secret,
            INFO_MAILBOX_TAG_KEY,
        ))
    }
}

impl PartialEq for InviteSecret {
    fn eq(&self, other: &Self) -> bool {
        self.secret == other.secret && self.billboards == other.billboards
    }
}

impl Eq for InviteSecret {}

impl core::fmt::Debug for InviteSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("InviteSecret(..)")
    }
}

/// Billboard Tag for the PublicInvite Notice, derived from [`InviteSecret`].
#[derive(Clone, Eq)]
pub struct InviteTag {
    mac: HmacSha256Mac,
}

impl InviteTag {
    /// Wrap a derived (or round-tripped) Billboard Tag.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SECRET_LEN]) -> Self {
        Self {
            mac: HmacSha256Mac::from_bytes(bytes),
        }
    }

    pub(crate) const fn from_mac(mac: HmacSha256Mac) -> Self {
        Self { mac }
    }

    /// Billboard Tag bytes.
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

/// Mailbox Tag Key: identifies a Message stream. Bins are this key and binned time.
#[derive(Clone, Eq)]
pub struct MailboxTagKey {
    mac: HmacSha256Mac,
}

impl MailboxTagKey {
    /// Wrap a derived Mailbox Tag Key.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SECRET_LEN]) -> Self {
        Self {
            mac: HmacSha256Mac::from_bytes(bytes),
        }
    }

    pub(crate) const fn from_mac(mac: HmacSha256Mac) -> Self {
        Self { mac }
    }

    /// Tag Key bytes for later per-bin Message-bin Expand.
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
    use super::{InviteSecret, InviteSecretError, InviteTag, MailboxTagKey};
    use crate::protocol::v1::{
        BILLBOARD_MAX_COUNT, Base64Url, Compress, CompressError, SECRET_LEN, fixtures,
    };

    #[test]
    fn from_parts_requires_billboards() {
        assert_eq!(
            InviteSecret::from_parts(fixtures::test_engine(), fixtures::fill(1), Vec::new())
                .unwrap_err(),
            InviteSecretError::EmptyBillboards
        );
        let too_many = vec![fixtures::sample_board(); BILLBOARD_MAX_COUNT + 1];
        assert_eq!(
            InviteSecret::from_parts(fixtures::test_engine(), fixtures::fill(1), too_many)
                .unwrap_err(),
            InviteSecretError::TooManyBillboards
        );
        let secret = InviteSecret::from_parts(
            fixtures::test_engine(),
            fixtures::fill(0xab),
            vec![fixtures::sample_board()],
        )
        .expect("secret");
        assert_eq!(secret.secret_bytes(), &fixtures::fill(0xab));
        assert_eq!(secret.billboards().len(), 1);
        assert_eq!(format!("{secret:?}"), "InviteSecret(..)");
        assert!(!format!("{secret:?}").contains("ab"));
        assert_eq!(
            format!("{}", InviteSecretError::EmptyBillboards),
            "invite secret needs at least one Billboard"
        );
        assert_eq!(
            format!("{}", InviteSecretError::TooManyBillboards),
            format!("invite secret has more than {BILLBOARD_MAX_COUNT} Billboards")
        );
        let _ = &InviteSecretError::EmptyBillboards as &dyn std::error::Error;
        let _ = secret.clone();
        let blob = secret.serialize();
        assert_eq!(
            secret
                .engine()
                .try_parse_invite_secret(&blob)
                .expect("parse"),
            secret
        );
        assert!(fixtures::HexB64.decode("a").is_err());
        assert!(fixtures::HexB64.decode("0g").is_err());
        assert_eq!(
            fixtures::IdentityCompress
                .decompress(&[0; 8], 1)
                .unwrap_err(),
            CompressError::Oversize
        );
    }

    #[test]
    fn debug_redacts_payloads() {
        let secret = InviteSecret::from_parts(
            fixtures::test_engine(),
            fixtures::fill(0xab),
            vec![fixtures::sample_board()],
        )
        .expect("secret");
        let tag = InviteTag::from_bytes(fixtures::fill(0xcd));
        let key = MailboxTagKey::from_bytes(fixtures::fill(0xef));
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
        let _ = a.clone();
        let tag_a = InviteTag::from_bytes([1; SECRET_LEN]);
        let tag_b = InviteTag::from_bytes([1; SECRET_LEN]);
        let tag_c = InviteTag::from_bytes([2; SECRET_LEN]);
        assert_eq!(tag_a, tag_b);
        assert_ne!(tag_a, tag_c);
        assert_eq!(tag_a.as_bytes(), &[1; SECRET_LEN]);
        let _ = tag_a.clone();
    }
}
