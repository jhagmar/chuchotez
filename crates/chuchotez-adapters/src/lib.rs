//! Pure cryptographic adapters for [`chuchotez_domain`].
//!
//! Side effects (`Rng`, clocks, IO) stay in the host.

use chuchotez_domain::{HmacSha256, HmacSha256Key, HmacSha256Mac, Random32Bytes, Suite};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::Arc;

/// HMAC-SHA-256 over RustCrypto `hmac` + `sha2`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sha2;

impl HmacSha256 for Sha2 {
    fn mac(&self, key: &HmacSha256Key, data: &[u8]) -> HmacSha256Mac {
        let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
            .expect("HMAC-SHA-256 accepts any key length");
        mac.update(data);
        let digest = mac.finalize().into_bytes();
        let bytes: Random32Bytes = digest.into();
        HmacSha256Mac::from_bytes(bytes)
    }
}

/// Default portable suite: [`Sha2`] HMAC-SHA-256.
#[must_use]
pub fn std_suite() -> Suite {
    Suite::new(Arc::new(Sha2))
}

#[cfg(test)]
mod tests {
    use super::{Sha2, std_suite};
    use chuchotez_domain::{HmacSha256, HmacSha256Key, HmacSha256Mac};
    use hmac::{Hmac, Mac};

    #[test]
    fn sha2_matches_hmac_crate() {
        let key = HmacSha256Key::from_bytes([0x0b; 32]);
        let data = b"Hi There";
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key.as_bytes()).expect("key");
        mac.update(data);
        let expected: [u8; 32] = mac.finalize().into_bytes().into();
        let port = Sha2;
        assert_eq!(port.mac(&key, data), HmacSha256Mac::from_bytes(expected));
        assert_eq!(port.mac(&key, data), Sha2.mac(&key, data));
        assert_eq!(port, Sha2);
        assert_eq!(format!("{port:?}"), "Sha2");
        let _ = std_suite();
    }
}
