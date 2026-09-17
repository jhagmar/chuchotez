//! Shared kind and address grammar for Billboard, Mailbox, and Wire.

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

#[cfg(test)]
mod tests {
    use super::{AddressError, KindError, parse_address, parse_kind};
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
    }
}
