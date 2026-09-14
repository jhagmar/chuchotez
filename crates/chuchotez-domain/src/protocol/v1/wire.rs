//! Opaque Wire coordinates: mapper `kind` plus `address`.

use super::channel::{parse_address, parse_kind};

/// Mapper registry key error for a Wire.
pub type WireKindError = super::channel::KindError;

/// Opaque UTF-8 Wire coordinate error.
pub type WireAddressError = super::channel::AddressError;

/// Mapper registry key (`"webrtc"`, …).
#[derive(Clone, Eq, PartialEq)]
pub struct WireKind(String);

impl WireKind {
    /// Kind string for the host mapper registry.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for WireKind {
    type Error = WireKindError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Self(parse_kind(value)?))
    }
}

impl core::fmt::Debug for WireKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("WireKind").field(&self.0).finish()
    }
}

/// Opaque UTF-8 Wire coordinate. NFC-or-precomposed; the mapper parses it.
#[derive(Clone, Eq, PartialEq)]
pub struct WireAddress(String);

impl WireAddress {
    /// Address bytes as UTF-8.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for WireAddress {
    type Error = WireAddressError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Self(parse_address(value)?))
    }
}

impl core::fmt::Debug for WireAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("WireAddress(..)")
    }
}

/// One Wire: mapper `kind` plus opaque `address`.
#[derive(Clone, Eq, PartialEq)]
pub struct Wire {
    kind: WireKind,
    address: WireAddress,
}

impl Wire {
    /// Bind a validated kind to a validated address.
    #[must_use]
    pub const fn new(kind: WireKind, address: WireAddress) -> Self {
        Self { kind, address }
    }

    /// Mapper registry key.
    #[must_use]
    pub const fn kind(&self) -> &WireKind {
        &self.kind
    }

    /// Opaque address for that mapper.
    #[must_use]
    pub const fn address(&self) -> &WireAddress {
        &self.address
    }
}

impl core::fmt::Debug for Wire {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Wire")
            .field("kind", &self.kind)
            .field("address", &self.address)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{Wire, WireAddress, WireKind};

    #[test]
    fn wire_roundtrip() {
        let kind = WireKind::try_from("webrtc").expect("kind");
        let address = WireAddress::try_from("stun:stun.example").expect("addr");
        let wire = Wire::new(kind, address);
        assert_eq!(wire.kind().as_str(), "webrtc");
        assert_eq!(wire.address().as_str(), "stun:stun.example");
        assert_eq!(format!("{:?}", wire.kind()), "WireKind(\"webrtc\")");
        assert_eq!(format!("{:?}", wire.address()), "WireAddress(..)");
        assert!(format!("{wire:?}").contains("webrtc"));
        assert_eq!(wire, wire.clone());
        assert!(WireKind::try_from("").is_err());
        assert!(WireAddress::try_from("").is_err());
    }
}
