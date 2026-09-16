//! Preferred display name on an [`super::Identity`].

use super::DISPLAY_NAME_MAX_LEN;
use crate::protocol::v1::channel;

/// Why a display-name string was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisplayNameError {
    /// Empty string.
    Empty,
    /// Longer than [`DISPLAY_NAME_MAX_LEN`] UTF-8 bytes.
    TooLong,
    /// Contains a NUL scalar.
    Nul,
    /// Contains a combining mark.
    CombiningMark,
}

impl core::fmt::Display for DisplayNameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => f.write_str("display name is empty"),
            Self::TooLong => {
                write!(f, "display name longer than {DISPLAY_NAME_MAX_LEN} bytes")
            }
            Self::Nul => f.write_str("display name contains NUL"),
            Self::CombiningMark => f.write_str("display name contains a combining mark"),
        }
    }
}

impl std::error::Error for DisplayNameError {}

/// Nonempty NFC-or-precomposed preferred name. Empty at Identity create.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayName(String);

impl DisplayName {
    /// UTF-8 bytes.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for DisplayName {
    type Error = DisplayNameError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(DisplayNameError::Empty);
        }
        if value.len() > DISPLAY_NAME_MAX_LEN {
            return Err(DisplayNameError::TooLong);
        }
        if value.chars().any(|c| c == '\0') {
            return Err(DisplayNameError::Nul);
        }
        if value.chars().any(channel::is_combining) {
            return Err(DisplayNameError::CombiningMark);
        }
        Ok(Self(value.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::super::DISPLAY_NAME_MAX_LEN;
    use super::{DisplayName, DisplayNameError};

    #[test]
    fn display_name_gate() {
        assert_eq!(
            DisplayName::try_from("Ada Lovelace").expect("ok").as_str(),
            "Ada Lovelace"
        );
        assert_eq!(
            DisplayName::try_from("").unwrap_err(),
            DisplayNameError::Empty
        );
        let long = "a".repeat(DISPLAY_NAME_MAX_LEN + 1);
        assert_eq!(
            DisplayName::try_from(long.as_str()).unwrap_err(),
            DisplayNameError::TooLong
        );
        let max = "a".repeat(DISPLAY_NAME_MAX_LEN);
        assert!(DisplayName::try_from(max.as_str()).is_ok());
        assert_eq!(
            DisplayName::try_from("a\0b").unwrap_err(),
            DisplayNameError::Nul
        );
        assert_eq!(
            DisplayName::try_from("cafe\u{0301}").unwrap_err(),
            DisplayNameError::CombiningMark
        );
        assert_eq!(
            format!("{}", DisplayNameError::Empty),
            "display name is empty"
        );
        assert_eq!(
            format!("{}", DisplayNameError::TooLong),
            format!("display name longer than {DISPLAY_NAME_MAX_LEN} bytes")
        );
        assert_eq!(
            format!("{}", DisplayNameError::Nul),
            "display name contains NUL"
        );
        assert_eq!(
            format!("{}", DisplayNameError::CombiningMark),
            "display name contains a combining mark"
        );
        let _ = &DisplayNameError::Empty as &dyn std::error::Error;
        let name = DisplayName::try_from("Ada").expect("ok");
        assert_eq!(name, name.clone());
        assert!(format!("{name:?}").contains("Ada"));
    }
}
