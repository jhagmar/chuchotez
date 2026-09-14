//! Shared kind and address grammar for Billboard, Mailbox, and Wire.

use super::{ADDRESS_MAX_LEN, KIND_MAX_LEN};

/// Combining-mark ranges (canonical combining class greater than zero).
const COMBINING_RANGES: &[(u32, u32)] = &[
    (0x0300, 0x036F),
    (0x0483, 0x0489),
    (0x0591, 0x05BD),
    (0x05BF, 0x05BF),
    (0x05C1, 0x05C2),
    (0x05C4, 0x05C5),
    (0x05C7, 0x05C7),
    (0x0610, 0x061A),
    (0x064B, 0x065F),
    (0x0670, 0x0670),
    (0x06D6, 0x06DC),
    (0x06DF, 0x06E4),
    (0x06E7, 0x06E8),
    (0x06EA, 0x06ED),
    (0x0711, 0x0711),
    (0x0730, 0x074A),
    (0x07A6, 0x07B0),
    (0x07EB, 0x07F3),
    (0x0816, 0x0819),
    (0x081B, 0x0823),
    (0x0825, 0x0827),
    (0x0829, 0x082D),
    (0x0859, 0x085B),
    (0x08D3, 0x08E1),
    (0x08E3, 0x0903),
    (0x093A, 0x094F),
    (0x0951, 0x0957),
    (0x0962, 0x0963),
    (0x1AB0, 0x1ACE),
    (0x1DC0, 0x1DFF),
    (0x20D0, 0x20F0),
    (0xFE20, 0xFE2F),
];

pub(crate) fn is_combining(c: char) -> bool {
    let u = u32::from(c);
    COMBINING_RANGES.iter().any(|&(lo, hi)| u >= lo && u <= hi)
}

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
    use super::{AddressError, KindError, is_combining, parse_address, parse_kind};
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
        assert!(is_combining('\u{0301}'));
        assert!(!is_combining('é'));
        assert!(!is_combining('a'));
        assert!(is_combining('\u{05BF}'));
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
