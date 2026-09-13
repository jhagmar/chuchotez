//! Pure cryptographic adapter bundle (HMAC now; AEAD and signatures later).
//!
//! [`Rng`](crate::Rng) is a host port. It is not stored here. Every method that
//! needs entropy takes `&impl Rng` from the caller.

use crate::protocol::HmacSha256;
use std::sync::Arc;

/// HMAC (and later AEAD, signatures) a host binds to an [`Engine`](crate::Engine).
#[derive(Clone)]
pub struct Suite {
    hmac: Arc<dyn HmacSha256 + Send + Sync>,
}

impl Suite {
    /// Build a suite from a library- or host-supplied HMAC.
    #[must_use]
    pub fn new(hmac: Arc<dyn HmacSha256 + Send + Sync>) -> Self {
        Self { hmac }
    }

    /// HMAC-SHA-256 for HKDF-Expand.
    #[must_use]
    pub fn hmac(&self) -> &dyn HmacSha256 {
        &*self.hmac
    }
}

impl core::fmt::Debug for Suite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Suite { hmac: .. }")
    }
}

#[cfg(test)]
mod tests {
    use super::Suite;
    use crate::protocol::{HmacSha256, HmacSha256Key, HmacSha256Mac, v1};
    use std::sync::Arc;

    struct ConstHmac(u8);

    impl HmacSha256 for ConstHmac {
        fn mac(&self, _key: &HmacSha256Key, _data: &[u8]) -> HmacSha256Mac {
            HmacSha256Mac::from_bytes([self.0; v1::SECRET_LEN])
        }
    }

    #[test]
    fn debug_redacts_hmac() {
        let suite = Suite::new(Arc::new(ConstHmac(1)));
        assert_eq!(format!("{suite:?}"), "Suite { hmac: .. }");
        assert_eq!(
            suite
                .hmac()
                .mac(&HmacSha256Key::from_bytes([0; v1::SECRET_LEN]), b"")
                .as_bytes()[0],
            1
        );
    }
}
