//! HMAC-SHA-256 over `libcrux-hmac` (SHA-2).

use chuchotez_domain::v1::{HmacSha256, HmacSha256Key, HmacSha256Mac};

/// HMAC-SHA-256.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LibcruxHmac;

impl HmacSha256 for LibcruxHmac {
    fn mac(&self, key: &HmacSha256Key, data: &[u8]) -> HmacSha256Mac {
        let mut dst = [0u8; 32];
        libcrux_hmac::hmac_sha2_256(&mut dst, key.as_bytes(), data);
        HmacSha256Mac::from_bytes(dst)
    }
}

#[cfg(test)]
mod tests {
    use super::LibcruxHmac;
    use chuchotez_domain::v1::{HmacSha256, HmacSha256Key, HmacSha256Mac};

    #[test]
    fn hmac_matches_rfc_vector() {
        let key = HmacSha256Key::from_bytes([0x0b; 32]);
        let data = b"Hi There";
        let expected = [
            0x19, 0x8a, 0x60, 0x7e, 0xb4, 0x4b, 0xfb, 0xc6, 0x99, 0x03, 0xa0, 0xf1, 0xcf, 0x2b,
            0xbd, 0xc5, 0xba, 0x0a, 0xa3, 0xf3, 0xd9, 0xae, 0x3c, 0x1c, 0x7a, 0x3b, 0x16, 0x96,
            0xa0, 0xb6, 0x8c, 0xf7,
        ];
        let port = LibcruxHmac;
        assert_eq!(port.mac(&key, data), HmacSha256Mac::from_bytes(expected));
        assert_eq!(port.mac(&key, data), LibcruxHmac.mac(&key, data));
        assert_eq!(port, LibcruxHmac);
        assert_eq!(format!("{port:?}"), "LibcruxHmac");
    }
}
