//! Raw Deflate capability (RFC 1951). Adapters supply the primitive.

/// Failure from [`Compress`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompressError {
    /// The stream was corrupt or the adapter could not finish.
    Codec,
    /// Decompress would exceed the caller-supplied uncompressed cap.
    Oversize,
}

impl core::fmt::Display for CompressError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Codec => f.write_str("deflate codec error"),
            Self::Oversize => f.write_str("uncompressed payload exceeds cap"),
        }
    }
}

impl std::error::Error for CompressError {}

/// Raw DEFLATE compress / decompress. v1 pins RFC 1951 (no zlib/gzip wrapper).
pub trait Compress {
    /// Compress `src` with the adapter's v1 defaults.
    ///
    /// Adapters honor this contract for any finite `src`.
    fn compress(&self, src: &[u8]) -> Vec<u8>;

    /// Inflate `src`, stopping at `max_uncompressed` output bytes.
    fn decompress(&self, src: &[u8], max_uncompressed: usize) -> Result<Vec<u8>, CompressError>;
}

#[cfg(test)]
mod tests {
    use super::CompressError;

    #[test]
    fn compress_error_display() {
        assert_eq!(format!("{}", CompressError::Codec), "deflate codec error");
        assert_eq!(
            format!("{}", CompressError::Oversize),
            "uncompressed payload exceeds cap"
        );
        assert_eq!(CompressError::Codec, CompressError::Codec);
        assert_ne!(CompressError::Codec, CompressError::Oversize);
        let _ = CompressError::Codec;
        let _ = &CompressError::Codec as &dyn std::error::Error;
    }
}
