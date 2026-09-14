//! Opaque Mailbox coordinates: mapper `kind` plus `address`.

use super::channel::{parse_address, parse_kind};

/// Mapper registry key error for a Mailbox.
pub type MailboxKindError = super::channel::KindError;

/// Opaque UTF-8 Mailbox coordinate error.
pub type MailboxAddressError = super::channel::AddressError;

/// Mapper registry key (`"nostr"`, …).
#[derive(Clone, Eq, PartialEq)]
pub struct MailboxKind(String);

impl MailboxKind {
    /// Kind string for the host mapper registry.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for MailboxKind {
    type Error = MailboxKindError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Self(parse_kind(value)?))
    }
}

impl core::fmt::Debug for MailboxKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("MailboxKind").field(&self.0).finish()
    }
}

/// Opaque UTF-8 Mailbox coordinate. NFC-or-precomposed; the mapper parses it.
#[derive(Clone, Eq, PartialEq)]
pub struct MailboxAddress(String);

impl MailboxAddress {
    /// Address bytes as UTF-8.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for MailboxAddress {
    type Error = MailboxAddressError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Self(parse_address(value)?))
    }
}

impl core::fmt::Debug for MailboxAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MailboxAddress(..)")
    }
}

/// One Mailbox: mapper `kind` plus opaque `address`.
#[derive(Clone, Eq, PartialEq)]
pub struct Mailbox {
    kind: MailboxKind,
    address: MailboxAddress,
}

impl Mailbox {
    /// Bind a validated kind to a validated address.
    #[must_use]
    pub const fn new(kind: MailboxKind, address: MailboxAddress) -> Self {
        Self { kind, address }
    }

    /// Mapper registry key.
    #[must_use]
    pub const fn kind(&self) -> &MailboxKind {
        &self.kind
    }

    /// Opaque address for that mapper.
    #[must_use]
    pub const fn address(&self) -> &MailboxAddress {
        &self.address
    }
}

impl core::fmt::Debug for Mailbox {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Mailbox")
            .field("kind", &self.kind)
            .field("address", &self.address)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{Mailbox, MailboxAddress, MailboxKind};

    #[test]
    fn mailbox_roundtrip() {
        let kind = MailboxKind::try_from("nostr").expect("kind");
        let address = MailboxAddress::try_from("wss://mailbox.example").expect("addr");
        let box_ = Mailbox::new(kind, address);
        assert_eq!(box_.kind().as_str(), "nostr");
        assert_eq!(box_.address().as_str(), "wss://mailbox.example");
        assert_eq!(format!("{:?}", box_.kind()), "MailboxKind(\"nostr\")");
        assert_eq!(format!("{:?}", box_.address()), "MailboxAddress(..)");
        assert!(format!("{box_:?}").contains("nostr"));
        assert_eq!(box_, box_.clone());
        assert!(MailboxKind::try_from("").is_err());
        assert!(MailboxAddress::try_from("").is_err());
    }
}
