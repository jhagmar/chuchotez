//! Opaque Billboard coordinates: mapper `kind` plus `address`.

use super::{ADDRESS_MAX_LEN, KIND_MAX_LEN};

/// Combining-mark ranges (canonical combining class greater than zero).
///
/// [`BillboardAddress`] requires NFC-or-precomposed Unicode: combining marks
/// fail closed so NFD cannot enter the QR payload.
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

fn is_combining(c: char) -> bool {
    let u = u32::from(c);
    COMBINING_RANGES.iter().any(|&(lo, hi)| u >= lo && u <= hi)
}

/// Why a [`BillboardKind`] string was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BillboardKindError {
    /// Empty string.
    Empty,
    /// Longer than [`KIND_MAX_LEN`].
    TooLong,
    /// Outside `^[a-z][a-z0-9-]*$`.
    InvalidChar,
}

impl core::fmt::Display for BillboardKindError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => f.write_str("billboard kind is empty"),
            Self::TooLong => write!(f, "billboard kind longer than {KIND_MAX_LEN} bytes"),
            Self::InvalidChar => f.write_str("billboard kind must match [a-z][a-z0-9-]*"),
        }
    }
}

impl std::error::Error for BillboardKindError {}

/// Mapper registry key (`"nostr"`, …). Chuchotez does not interpret it.
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
        if value.is_empty() {
            return Err(BillboardKindError::Empty);
        }
        if value.len() > KIND_MAX_LEN {
            return Err(BillboardKindError::TooLong);
        }
        let mut chars = value.chars();
        let first = chars.next().expect("nonempty");
        if !first.is_ascii_lowercase() {
            return Err(BillboardKindError::InvalidChar);
        }
        if !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
            return Err(BillboardKindError::InvalidChar);
        }
        Ok(Self(value.to_owned()))
    }
}

impl core::fmt::Debug for BillboardKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("BillboardKind").field(&self.0).finish()
    }
}

/// Why a [`BillboardAddress`] string was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BillboardAddressError {
    /// Empty string.
    Empty,
    /// Longer than [`ADDRESS_MAX_LEN`] UTF-8 bytes.
    TooLong,
    /// Contains a NUL scalar.
    Nul,
    /// Contains a combining mark (NFD / non-precomposed).
    CombiningMark,
    /// Bytes were not UTF-8 (codec path).
    InvalidUtf8,
}

impl core::fmt::Display for BillboardAddressError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => f.write_str("billboard address is empty"),
            Self::TooLong => {
                write!(f, "billboard address longer than {ADDRESS_MAX_LEN} bytes")
            }
            Self::Nul => f.write_str("billboard address contains NUL"),
            Self::CombiningMark => f.write_str("billboard address contains a combining mark"),
            Self::InvalidUtf8 => f.write_str("billboard address is not UTF-8"),
        }
    }
}

impl std::error::Error for BillboardAddressError {}

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
        if value.is_empty() {
            return Err(BillboardAddressError::Empty);
        }
        if value.len() > ADDRESS_MAX_LEN {
            return Err(BillboardAddressError::TooLong);
        }
        if value.chars().any(|c| c == '\0') {
            return Err(BillboardAddressError::Nul);
        }
        if value.chars().any(is_combining) {
            return Err(BillboardAddressError::CombiningMark);
        }
        Ok(Self(value.to_owned()))
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
    use super::{
        Billboard, BillboardAddress, BillboardAddressError, BillboardKind, BillboardKindError,
        is_combining,
    };
    use crate::protocol::v1::{ADDRESS_MAX_LEN, KIND_MAX_LEN};

    #[test]
    fn kind_accepts_nostr() {
        let kind = BillboardKind::try_from("nostr").expect("kind");
        assert_eq!(kind.as_str(), "nostr");
        assert_eq!(format!("{kind:?}"), "BillboardKind(\"nostr\")");
        assert_eq!(kind, BillboardKind::try_from("nostr").expect("kind"));
        let _ = kind.clone();
    }

    #[test]
    fn kind_rejects_empty_long_and_grammar() {
        assert_eq!(
            BillboardKind::try_from("").unwrap_err(),
            BillboardKindError::Empty
        );
        let long = "a".repeat(KIND_MAX_LEN + 1);
        assert_eq!(
            BillboardKind::try_from(long.as_str()).unwrap_err(),
            BillboardKindError::TooLong
        );
        assert_eq!(
            BillboardKind::try_from("Nostr").unwrap_err(),
            BillboardKindError::InvalidChar
        );
        assert_eq!(
            BillboardKind::try_from("1nostr").unwrap_err(),
            BillboardKindError::InvalidChar
        );
        assert_eq!(
            BillboardKind::try_from("no_str").unwrap_err(),
            BillboardKindError::InvalidChar
        );
        assert!(BillboardKind::try_from("a").is_ok());
        assert!(BillboardKind::try_from("a1-b").is_ok());
        assert_eq!(BillboardKind::try_from("a").expect("a").as_str().len(), 1);
        let max = "a".repeat(KIND_MAX_LEN);
        assert!(BillboardKind::try_from(max.as_str()).is_ok());
        assert_eq!(
            format!("{}", BillboardKindError::Empty),
            "billboard kind is empty"
        );
        assert_eq!(
            format!("{}", BillboardKindError::TooLong),
            format!("billboard kind longer than {KIND_MAX_LEN} bytes")
        );
        assert_eq!(
            format!("{}", BillboardKindError::InvalidChar),
            "billboard kind must match [a-z][a-z0-9-]*"
        );
        let _ = &BillboardKindError::Empty as &dyn std::error::Error;
    }

    #[test]
    fn address_accepts_precomposed_and_rejects_nfd() {
        let addr = BillboardAddress::try_from("wss://relay.example").expect("addr");
        assert_eq!(addr.as_str(), "wss://relay.example");
        assert_eq!(format!("{addr:?}"), "BillboardAddress(..)");
        assert!(!format!("{addr:?}").contains("relay"));
        let cafe = BillboardAddress::try_from("café").expect("nfc");
        assert_eq!(cafe.as_str(), "café");
        assert_eq!(
            BillboardAddress::try_from("cafe\u{0301}").unwrap_err(),
            BillboardAddressError::CombiningMark
        );
        assert!(is_combining('\u{0301}'));
        assert!(!is_combining('é'));
        assert!(!is_combining('a'));
        assert!(is_combining('\u{05BF}'));
        let _ = addr.clone();
    }

    #[test]
    fn address_rejects_empty_long_and_nul() {
        assert_eq!(
            BillboardAddress::try_from("").unwrap_err(),
            BillboardAddressError::Empty
        );
        let long = "a".repeat(ADDRESS_MAX_LEN + 1);
        assert_eq!(
            BillboardAddress::try_from(long.as_str()).unwrap_err(),
            BillboardAddressError::TooLong
        );
        let max = "a".repeat(ADDRESS_MAX_LEN);
        assert!(BillboardAddress::try_from(max.as_str()).is_ok());
        assert_eq!(
            BillboardAddress::try_from("a\0b").unwrap_err(),
            BillboardAddressError::Nul
        );
        assert_eq!(
            format!("{}", BillboardAddressError::Empty),
            "billboard address is empty"
        );
        assert_eq!(
            format!("{}", BillboardAddressError::TooLong),
            format!("billboard address longer than {ADDRESS_MAX_LEN} bytes")
        );
        assert_eq!(
            format!("{}", BillboardAddressError::Nul),
            "billboard address contains NUL"
        );
        assert_eq!(
            format!("{}", BillboardAddressError::CombiningMark),
            "billboard address contains a combining mark"
        );
        assert_eq!(
            format!("{}", BillboardAddressError::InvalidUtf8),
            "billboard address is not UTF-8"
        );
        let _ = &BillboardAddressError::Empty as &dyn std::error::Error;
        assert_ne!(
            BillboardAddressError::InvalidUtf8,
            BillboardAddressError::Nul
        );
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
