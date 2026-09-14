//! Opaque Billboard coordinates: mapper `kind` plus `address`.

use super::channel::{parse_address, parse_kind};

/// Mapper registry key (`"nostr"`, …).
pub type BillboardKindError = super::channel::KindError;

/// Opaque UTF-8 Billboard coordinate error.
pub type BillboardAddressError = super::channel::AddressError;

/// Mapper registry key (`"nostr"`, …).
#[derive(Clone, Eq, PartialEq)]
pub struct BillboardKind(String);

impl BillboardKind {
    /// Kind string for the host mapper registry.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for BillboardKind {
    type Error = BillboardKindError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Self(parse_kind(value)?))
    }
}

impl core::fmt::Debug for BillboardKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("BillboardKind").field(&self.0).finish()
    }
}

/// Opaque UTF-8 Billboard coordinate. NFC-or-precomposed; the mapper parses it.
#[derive(Clone, Eq, PartialEq)]
pub struct BillboardAddress(String);

impl BillboardAddress {
    /// Address bytes as UTF-8.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for BillboardAddress {
    type Error = BillboardAddressError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Self(parse_address(value)?))
    }
}

impl core::fmt::Debug for BillboardAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("BillboardAddress(..)")
    }
}

/// One Billboard: mapper `kind` plus opaque `address`.
#[derive(Clone, Eq, PartialEq)]
pub struct Billboard {
    kind: BillboardKind,
    address: BillboardAddress,
}

impl Billboard {
    /// Bind a validated kind to a validated address.
    #[must_use]
    pub const fn new(kind: BillboardKind, address: BillboardAddress) -> Self {
        Self { kind, address }
    }

    /// Mapper registry key.
    #[must_use]
    pub const fn kind(&self) -> &BillboardKind {
        &self.kind
    }

    /// Opaque address for that mapper.
    #[must_use]
    pub const fn address(&self) -> &BillboardAddress {
        &self.address
    }
}

impl core::fmt::Debug for Billboard {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Billboard")
            .field("kind", &self.kind)
            .field("address", &self.address)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{Billboard, BillboardAddress, BillboardKind};

    #[test]
    fn kind_accepts_nostr() {
        let kind = BillboardKind::try_from("nostr").expect("kind");
        assert_eq!(kind.as_str(), "nostr");
        assert_eq!(format!("{kind:?}"), "BillboardKind(\"nostr\")");
        assert_eq!(kind, BillboardKind::try_from("nostr").expect("kind"));
        let _ = kind.clone();
    }

    #[test]
    fn address_redacts_debug() {
        let addr = BillboardAddress::try_from("wss://relay.example").expect("addr");
        assert_eq!(addr.as_str(), "wss://relay.example");
        assert_eq!(format!("{addr:?}"), "BillboardAddress(..)");
        assert!(!format!("{addr:?}").contains("relay"));
        let _ = addr.clone();
    }

    #[test]
    fn billboard_debug_shows_kind() {
        let board = Billboard::new(
            BillboardKind::try_from("nostr").expect("kind"),
            BillboardAddress::try_from("wss://relay.example").expect("addr"),
        );
        let text = format!("{board:?}");
        assert!(text.contains("nostr"));
        assert!(text.contains("BillboardAddress(..)"));
        assert_eq!(board.kind().as_str(), "nostr");
        assert_eq!(board.address().as_str(), "wss://relay.example");
        assert_eq!(board, board.clone());
    }
}
