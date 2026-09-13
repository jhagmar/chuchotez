//! v1 capability bag and host handle.

use super::{
    Base64Url, Billboard, BillboardAddress, BillboardAddressError, BillboardKind,
    BillboardKindError, Compress, EnvelopeError, HmacSha256, InviteSecret, InviteSecretError,
};
use crate::protocol::{Policy, Rng};
use std::sync::Arc;

/// HMAC, compress, and b64u a host binds to a v1 [`Engine`].
#[derive(Clone)]
pub struct Suite {
    hmac: Arc<dyn HmacSha256 + Send + Sync>,
    compress: Arc<dyn Compress + Send + Sync>,
    b64u: Arc<dyn Base64Url + Send + Sync>,
}

impl Suite {
    /// Build a v1 suite from library- or host-supplied adapters.
    #[must_use]
    pub fn new(
        hmac: Arc<dyn HmacSha256 + Send + Sync>,
        compress: Arc<dyn Compress + Send + Sync>,
        b64u: Arc<dyn Base64Url + Send + Sync>,
    ) -> Self {
        Self {
            hmac,
            compress,
            b64u,
        }
    }

    /// HMAC-SHA-256 for HKDF-Expand.
    #[must_use]
    pub(crate) fn hmac(&self) -> &dyn HmacSha256 {
        &*self.hmac
    }

    /// Raw DEFLATE.
    #[must_use]
    pub(crate) fn compress(&self) -> &dyn Compress {
        &*self.compress
    }

    /// Unpadded base64url.
    #[must_use]
    pub(crate) fn b64u(&self) -> &dyn Base64Url {
        &*self.b64u
    }
}

impl core::fmt::Debug for Suite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Suite { hmac: .., compress: .., b64u: .. }")
    }
}

/// Host-owned handle bound to a v1 [`Suite`] and a [`Policy`].
///
/// Construction of Billboards and invite secrets lives here. Tag and envelope
/// mapping live on [`InviteSecret`].
#[derive(Clone)]
pub struct Engine {
    suite: Suite,
    policy: Policy,
}

impl Engine {
    /// Bind this engine to `suite` and `policy`. The caller keeps the engine.
    #[must_use]
    pub fn new(suite: Suite, policy: Policy) -> Self {
        Self { suite, policy }
    }

    /// Crypto policy this engine was constructed with.
    #[must_use]
    pub fn policy(&self) -> Policy {
        self.policy
    }

    /// HMAC-SHA-256 capability.
    #[must_use]
    pub(crate) fn hmac(&self) -> &dyn HmacSha256 {
        self.suite.hmac()
    }

    /// Raw DEFLATE capability.
    #[must_use]
    pub(crate) fn compress(&self) -> &dyn Compress {
        self.suite.compress()
    }

    /// Unpadded base64url capability.
    #[must_use]
    pub(crate) fn b64u(&self) -> &dyn Base64Url {
        self.suite.b64u()
    }

    /// Parse and brand a Billboard mapper key.
    pub fn try_new_billboard_kind(&self, kind: &str) -> Result<BillboardKind, BillboardKindError> {
        BillboardKind::try_from(kind)
    }

    /// Parse and brand a Billboard address.
    pub fn try_new_billboard_address(
        &self,
        address: &str,
    ) -> Result<BillboardAddress, BillboardAddressError> {
        BillboardAddress::try_from(address)
    }

    /// Bind a validated kind to a validated address.
    #[must_use]
    pub fn new_billboard(&self, kind: BillboardKind, address: BillboardAddress) -> Billboard {
        Billboard::new(kind, address)
    }

    /// Assign host RNG output the v1 invite-secret role.
    pub fn try_new_invite_secret<R: Rng + ?Sized>(
        &self,
        rng: &R,
        billboards: &[Billboard],
    ) -> Result<InviteSecret, InviteSecretError> {
        InviteSecret::from_parts(
            self.clone(),
            rng.random32().into_bytes(),
            billboards.to_vec(),
        )
    }

    /// Parse a compact DM invite blob and bind it to this engine.
    pub fn try_parse_invite_secret(&self, s: &str) -> Result<InviteSecret, EnvelopeError> {
        InviteSecret::try_parse(self, s)
    }
}

impl core::fmt::Debug for Engine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Engine { suite: .. }")
    }
}

#[cfg(test)]
mod tests {
    use super::{Engine, Suite};
    use crate::protocol::v1::{
        Base64Url, Base64UrlError, BillboardAddressError, BillboardKindError, Compress,
        CompressError, HmacSha256, HmacSha256Key, HmacSha256Mac, SECRET_LEN,
    };
    use crate::protocol::{Policy, Random32, Rng};
    use std::sync::Arc;

    struct ConstHmac(u8);

    impl HmacSha256 for ConstHmac {
        fn mac(&self, _key: &HmacSha256Key, _data: &[u8]) -> HmacSha256Mac {
            HmacSha256Mac::from_bytes([self.0; SECRET_LEN])
        }
    }

    struct EmptyCompress;

    impl Compress for EmptyCompress {
        fn compress(&self, _src: &[u8]) -> Vec<u8> {
            Vec::new()
        }

        fn decompress(
            &self,
            _src: &[u8],
            _max_uncompressed: usize,
        ) -> Result<Vec<u8>, CompressError> {
            Ok(Vec::new())
        }
    }

    struct EmptyB64;

    impl Base64Url for EmptyB64 {
        fn encode(&self, _src: &[u8]) -> String {
            String::new()
        }

        fn decode(&self, _src: &str) -> Result<Vec<u8>, Base64UrlError> {
            Ok(Vec::new())
        }
    }

    fn suite() -> Suite {
        Suite::new(
            Arc::new(ConstHmac(1)),
            Arc::new(EmptyCompress),
            Arc::new(EmptyB64),
        )
    }

    struct SeedRng([u8; SECRET_LEN]);

    impl Rng for SeedRng {
        fn random32(&self) -> Random32 {
            Random32::from_bytes(self.0)
        }
    }

    #[test]
    fn debug_redacts_capabilities() {
        let suite = suite();
        assert_eq!(
            format!("{suite:?}"),
            "Suite { hmac: .., compress: .., b64u: .. }"
        );
        assert_eq!(
            suite
                .hmac()
                .mac(&HmacSha256Key::from_bytes([0; SECRET_LEN]), b"")
                .as_bytes()[0],
            1
        );
        assert!(suite.compress().compress(b"x").is_empty());
        assert!(suite.b64u().encode(b"x").is_empty());
        assert!(
            suite
                .compress()
                .decompress(b"x", 8)
                .expect("inflate")
                .is_empty()
        );
        assert!(suite.b64u().decode("x").expect("b64").is_empty());
        let engine = Engine::new(suite, Policy::Hybrid);
        assert_eq!(format!("{engine:?}"), "Engine { suite: .. }");
        assert_eq!(engine.policy(), Policy::Hybrid);
        assert_eq!(
            engine
                .hmac()
                .mac(&HmacSha256Key::from_bytes([0; SECRET_LEN]), b"")
                .as_bytes()[0],
            1
        );
        assert!(engine.compress().compress(b"").is_empty());
        assert!(engine.b64u().encode(b"").is_empty());
        let _ = engine.clone();
    }

    #[test]
    fn factory_brands_billboard_parts() {
        let engine = Engine::new(suite(), Policy::Classic);
        let kind = engine.try_new_billboard_kind("nostr").expect("kind");
        let address = engine
            .try_new_billboard_address("wss://relay.example")
            .expect("addr");
        let board = engine.new_billboard(kind, address);
        assert_eq!(board.kind().as_str(), "nostr");
        assert_eq!(
            engine.try_new_billboard_kind("").unwrap_err(),
            BillboardKindError::Empty
        );
        assert_eq!(
            engine.try_new_billboard_address("").unwrap_err(),
            BillboardAddressError::Empty
        );
        assert_eq!(
            engine
                .try_new_invite_secret(&SeedRng([3; SECRET_LEN]), &[])
                .unwrap_err(),
            super::InviteSecretError::EmptyBillboards
        );
    }
}
