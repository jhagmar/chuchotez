//! Unpadded base64url capability (RFC 4648 §5). Adapters supply the primitive.

/// Failure from [`Base64Url::decode`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Base64UrlError {
    /// Character outside the unpadded URL alphabet, or bad length.
    Invalid,
}

impl core::fmt::Display for Base64UrlError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("invalid unpadded base64url")
    }
}

impl std::error::Error for Base64UrlError {}

/// Unpadded base64url (`A-Za-z0-9-_`).
pub trait Base64Url {
    /// Encode `src` without padding.
    fn encode(&self, src: &[u8]) -> String;

    /// Decode an unpadded base64url string.
    fn decode(&self, src: &str) -> Result<Vec<u8>, Base64UrlError>;
}

#[cfg(test)]
mod tests {
    use super::Base64UrlError;

    #[test]
    fn base64url_error_display() {
        assert_eq!(
            format!("{}", Base64UrlError::Invalid),
            "invalid unpadded base64url"
        );
        assert_eq!(Base64UrlError::Invalid, Base64UrlError::Invalid);
        let _ = Base64UrlError::Invalid;
        let _ = &Base64UrlError::Invalid as &dyn std::error::Error;
    }
}
