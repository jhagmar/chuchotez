//! Mapper kind, address, DurableChannel, and EphemeralChannel.

use super::unicode::is_combining;
use super::{ADDRESS_MAX_LEN, KIND_MAX_LEN};

/// Why a mapper kind string was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KindError {
    /// Empty string.
    Empty,
    /// Longer than [`KIND_MAX_LEN`].
    TooLong,
    /// Outside `^[a-z][a-z0-9-]*$`.
    InvalidChar,
}

impl core::fmt::Display for KindError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => f.write_str("kind is empty"),
            Self::TooLong => write!(f, "kind longer than {KIND_MAX_LEN} bytes"),
            Self::InvalidChar => f.write_str("kind must match [a-z][a-z0-9-]*"),
        }
    }
}

impl std::error::Error for KindError {}

/// Why an address string was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressError {
    /// Empty string.
    Empty,
    /// Longer than [`ADDRESS_MAX_LEN`] UTF-8 bytes.
    TooLong,
    /// Contains a NUL scalar.
    Nul,
    /// Contains a combining mark.
    CombiningMark,
    /// Bytes were not UTF-8 (codec path).
    InvalidUtf8,
}

impl core::fmt::Display for AddressError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => f.write_str("address is empty"),
            Self::TooLong => write!(f, "address longer than {ADDRESS_MAX_LEN} bytes"),
            Self::Nul => f.write_str("address contains NUL"),
            Self::CombiningMark => f.write_str("address contains a combining mark"),
            Self::InvalidUtf8 => f.write_str("address is not UTF-8"),
        }
    }
}

impl std::error::Error for AddressError {}

pub(crate) fn parse_kind(value: &str) -> Result<String, KindError> {
    if value.is_empty() {
        return Err(KindError::Empty);
    }
    if value.len() > KIND_MAX_LEN {
        return Err(KindError::TooLong);
    }
    let mut chars = value.chars();
    let first = chars.next().expect("nonempty");
    if !first.is_ascii_lowercase() {
        return Err(KindError::InvalidChar);
    }
    if !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return Err(KindError::InvalidChar);
    }
    Ok(value.to_owned())
}

pub(crate) fn parse_address(value: &str) -> Result<String, AddressError> {
    if value.is_empty() {
        return Err(AddressError::Empty);
    }
    if value.len() > ADDRESS_MAX_LEN {
        return Err(AddressError::TooLong);
    }
    if value.chars().any(|c| c == '\0') {
        return Err(AddressError::Nul);
    }
    if value.chars().any(is_combining) {
        return Err(AddressError::CombiningMark);
    }
    Ok(value.to_owned())
}

/// Mapper registry key.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct Kind(String);

impl Kind {
    /// Kind string for the host mapper registry.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for Kind {
    type Error = KindError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Self(parse_kind(value)?))
    }
}

impl core::fmt::Debug for Kind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Kind").field(&self.0).finish()
    }
}

/// Mapper coordinate. Unicode Normalization Form C, no NUL, no combining mark.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct Address(String);

impl Address {
    /// Address bytes as UTF-8.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for Address {
    type Error = AddressError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Self(parse_address(value)?))
    }
}

impl core::fmt::Debug for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Address(..)")
    }
}

/// A mapper destination that stores posted packets for `list`.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct DurableChannel {
    kind: Kind,
    address: Address,
}

impl DurableChannel {
    /// Bind a validated kind to a validated address.
    #[must_use]
    pub const fn new(kind: Kind, address: Address) -> Self {
        Self { kind, address }
    }

    /// Mapper registry key.
    #[must_use]
    pub const fn kind(&self) -> &Kind {
        &self.kind
    }

    /// Mapper coordinate.
    #[must_use]
    pub const fn address(&self) -> &Address {
        &self.address
    }
}

impl core::fmt::Debug for DurableChannel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DurableChannel")
            .field("kind", &self.kind)
            .field("address", &self.address)
            .finish()
    }
}

/// A mapper destination that delivers live packets on `listen`.
#[derive(Clone, Eq, PartialEq)]
pub struct EphemeralChannel {
    kind: Kind,
    address: Address,
}

impl EphemeralChannel {
    /// Bind a validated kind to a validated address.
    #[must_use]
    pub const fn new(kind: Kind, address: Address) -> Self {
        Self { kind, address }
    }

    /// Mapper registry key.
    #[must_use]
    pub const fn kind(&self) -> &Kind {
        &self.kind
    }

    /// Mapper coordinate.
    #[must_use]
    pub const fn address(&self) -> &Address {
        &self.address
    }
}

impl core::fmt::Debug for EphemeralChannel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EphemeralChannel")
            .field("kind", &self.kind)
            .field("address", &self.address)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Address, AddressError, DurableChannel, EphemeralChannel, Kind, KindError, parse_address,
        parse_kind,
    };
    use crate::protocol::v1::{ADDRESS_MAX_LEN, KIND_MAX_LEN};

    #[test]
    fn kind_grammar() {
        assert_eq!(parse_kind("nostr").expect("kind"), "nostr");
        assert_eq!(parse_kind("").unwrap_err(), KindError::Empty);
        let long = "a".repeat(KIND_MAX_LEN + 1);
        assert_eq!(parse_kind(long.as_str()).unwrap_err(), KindError::TooLong);
        assert_eq!(parse_kind("Nostr").unwrap_err(), KindError::InvalidChar);
        assert_eq!(parse_kind("1nostr").unwrap_err(), KindError::InvalidChar);
        assert_eq!(parse_kind("no_str").unwrap_err(), KindError::InvalidChar);
        assert!(parse_kind("a").is_ok());
        assert!(parse_kind("a1-b").is_ok());
        let max = "a".repeat(KIND_MAX_LEN);
        assert!(parse_kind(max.as_str()).is_ok());
        assert_eq!(format!("{}", KindError::Empty), "kind is empty");
        assert_eq!(
            format!("{}", KindError::TooLong),
            format!("kind longer than {KIND_MAX_LEN} bytes")
        );
        assert_eq!(
            format!("{}", KindError::InvalidChar),
            "kind must match [a-z][a-z0-9-]*"
        );
        let _ = &KindError::Empty as &dyn std::error::Error;
        let kind = Kind::try_from("nostr").expect("k");
        assert_eq!(kind.as_str(), "nostr");
        assert_eq!(format!("{kind:?}"), "Kind(\"nostr\")");
        assert_eq!(kind, kind.clone());
    }

    #[test]
    fn address_grammar() {
        assert_eq!(
            parse_address("wss://relay.example").expect("addr"),
            "wss://relay.example"
        );
        assert_eq!(parse_address("café").expect("nfc"), "café");
        assert_eq!(
            parse_address("cafe\u{0301}").unwrap_err(),
            AddressError::CombiningMark
        );
        assert_eq!(parse_address("").unwrap_err(), AddressError::Empty);
        let long = "a".repeat(ADDRESS_MAX_LEN + 1);
        assert_eq!(
            parse_address(long.as_str()).unwrap_err(),
            AddressError::TooLong
        );
        let max = "a".repeat(ADDRESS_MAX_LEN);
        assert!(parse_address(max.as_str()).is_ok());
        assert_eq!(parse_address("a\0b").unwrap_err(), AddressError::Nul);
        assert_eq!(format!("{}", AddressError::Empty), "address is empty");
        assert_eq!(
            format!("{}", AddressError::TooLong),
            format!("address longer than {ADDRESS_MAX_LEN} bytes")
        );
        assert_eq!(format!("{}", AddressError::Nul), "address contains NUL");
        assert_eq!(
            format!("{}", AddressError::CombiningMark),
            "address contains a combining mark"
        );
        assert_eq!(
            format!("{}", AddressError::InvalidUtf8),
            "address is not UTF-8"
        );
        let _ = &AddressError::Empty as &dyn std::error::Error;
        assert_ne!(AddressError::InvalidUtf8, AddressError::Nul);
        let addr = Address::try_from("wss://relay.example").expect("a");
        assert_eq!(addr.as_str(), "wss://relay.example");
        assert_eq!(format!("{addr:?}"), "Address(..)");
        let d = DurableChannel::new(Kind::try_from("nostr").expect("k"), addr.clone());
        assert_eq!(d.kind().as_str(), "nostr");
        assert_eq!(d.address().as_str(), "wss://relay.example");
        assert_eq!(d, d.clone());
        assert!(format!("{d:?}").contains("DurableChannel"));
        let e = EphemeralChannel::new(
            Kind::try_from("webrtc").expect("k"),
            Address::try_from("stun:stun.example").expect("a"),
        );
        assert_eq!(e.kind().as_str(), "webrtc");
        assert_eq!(e, e.clone());
        assert!(format!("{e:?}").contains("EphemeralChannel"));
    }
}
