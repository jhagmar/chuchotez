//! SHA-256 over `libcrux-sha2`.

use chuchotez_domain::v1::Sha256;

/// SHA-256.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LibcruxSha256;

impl Sha256 for LibcruxSha256 {
    fn hash(&self, data: &[u8]) -> [u8; 32] {
        libcrux_sha2::sha256(data)
    }
}

#[cfg(test)]
mod tests {
    use super::LibcruxSha256;
    use chuchotez_domain::v1::Sha256;

    #[test]
    fn sha256_empty() {
        let port = LibcruxSha256;
        let d = port.hash(b"");
        assert_eq!(
            d,
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55
            ]
        );
        assert_eq!(port, LibcruxSha256);
        assert_eq!(format!("{port:?}"), "LibcruxSha256");
    }
}
