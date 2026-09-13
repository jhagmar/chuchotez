//! Unpadded base64url over RustCrypto `base64ct`.

use base64ct::{Base64UrlUnpadded, Encoding};
use chuchotez_domain::v1::{Base64Url, Base64UrlError};

/// Unpadded base64url.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Base64Ct;

impl Base64Url for Base64Ct {
    fn encode(&self, src: &[u8]) -> String {
        Base64UrlUnpadded::encode_string(src)
    }

    fn decode(&self, src: &str) -> Result<Vec<u8>, Base64UrlError> {
        Base64UrlUnpadded::decode_vec(src).map_err(|_| Base64UrlError::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::Base64Ct;
    use chuchotez_domain::v1::{Base64Url, Base64UrlError};

    #[test]
    fn b64ct_roundtrip_and_errors() {
        let port = Base64Ct;
        let src = [0xC1, 1, 2, 255];
        let encoded = port.encode(&src);
        assert!(!encoded.contains('='));
        assert_eq!(port.decode(&encoded).expect("decode"), src);
        assert_eq!(port.decode("%").unwrap_err(), Base64UrlError::Invalid);
        assert_eq!(port, Base64Ct);
        assert_eq!(format!("{port:?}"), "Base64Ct");
        assert_eq!(port.encode(&[]), "");
        assert_eq!(port.decode("").expect("empty"), Vec::<u8>::new());
    }
}
