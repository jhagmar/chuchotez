//! SHA-256 port.

use super::SECRET_LEN;

/// SHA-256 digest bytes.
pub type HashBytes = [u8; SECRET_LEN];

/// SHA-256. Adapters supply the primitive.
pub trait Sha256 {
    /// `SHA-256(data)`.
    fn hash(&self, data: &[u8]) -> HashBytes;
}

#[cfg(test)]
mod tests {
    use super::Sha256;

    struct ConstHash;

    impl Sha256 for ConstHash {
        fn hash(&self, _data: &[u8]) -> super::HashBytes {
            [9; super::SECRET_LEN]
        }
    }

    #[test]
    fn hash_port() {
        assert_eq!(ConstHash.hash(b"x")[0], 9);
    }
}
