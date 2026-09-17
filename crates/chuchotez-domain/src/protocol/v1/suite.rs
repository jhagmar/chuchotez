//! v1 capability bag.

use super::{Aead, Base64Url, CanonicalJson, Compress, HmacSha256, Kem, Sign};
use std::sync::Arc;

/// HMAC, compress, b64u, AEAD, canonical JSON, KEM, and Sign a host binds to a v1 [`super::Engine`].
#[derive(Clone)]
pub struct Suite {
    hmac: Arc<dyn HmacSha256 + Send + Sync>,
    compress: Arc<dyn Compress + Send + Sync>,
    b64u: Arc<dyn Base64Url + Send + Sync>,
    aead: Arc<dyn Aead + Send + Sync>,
    json: Arc<dyn CanonicalJson + Send + Sync>,
    kem: Arc<dyn Kem + Send + Sync>,
    sign: Arc<dyn Sign + Send + Sync>,
}

impl Suite {
    /// Build a v1 suite from library- or host-supplied adapters.
    #[must_use]
    pub fn new(
        hmac: Arc<dyn HmacSha256 + Send + Sync>,
        compress: Arc<dyn Compress + Send + Sync>,
        b64u: Arc<dyn Base64Url + Send + Sync>,
        aead: Arc<dyn Aead + Send + Sync>,
        json: Arc<dyn CanonicalJson + Send + Sync>,
        kem: Arc<dyn Kem + Send + Sync>,
        sign: Arc<dyn Sign + Send + Sync>,
    ) -> Self {
        Self {
            hmac,
            compress,
            b64u,
            aead,
            json,
            kem,
            sign,
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

    /// AES-256-GCM.
    #[must_use]
    pub(crate) fn aead(&self) -> &dyn Aead {
        &*self.aead
    }

    /// RFC 8785.
    #[must_use]
    pub(crate) fn canonical_json(&self) -> &dyn CanonicalJson {
        &*self.json
    }

    /// Intake and identity encryption keypair generator.
    #[must_use]
    pub(crate) fn kem(&self) -> &dyn Kem {
        &*self.kem
    }

    /// Identity signing keypair generator.
    #[must_use]
    pub(crate) fn sign(&self) -> &dyn Sign {
        &*self.sign
    }
}

impl core::fmt::Debug for Suite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(
            "Suite { hmac: .., compress: .., b64u: .., aead: .., json: .., kem: .., sign: .. }",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::Suite;
    use crate::protocol::Policy;
    use crate::protocol::v1::{
        Aead, AeadError, AeadKey, AeadNonce, Base64Url, Base64UrlError, CanonicalJson,
        CanonicalJsonError, Compress, CompressError, HmacSha256, HmacSha256Key, HmacSha256Mac,
        IdentitySignKeypair, IntakeKeypair, Json, KEM_SEED_LEN, Kem, KemError, KemSeed, SECRET_LEN,
        SIGN_SEED_LEN, Sign, SignError, SignSeed,
    };
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

    struct EmptyAead;

    impl Aead for EmptyAead {
        fn seal(
            &self,
            _key: &AeadKey,
            _nonce: &AeadNonce,
            _aad: &[u8],
            _plaintext: &[u8],
        ) -> Vec<u8> {
            Vec::new()
        }

        fn open(
            &self,
            _key: &AeadKey,
            _nonce: &AeadNonce,
            _aad: &[u8],
            _ciphertext: &[u8],
        ) -> Result<Vec<u8>, AeadError> {
            Ok(Vec::new())
        }
    }

    struct EmptyJson;

    impl CanonicalJson for EmptyJson {
        fn encode(&self, _value: &Json) -> Vec<u8> {
            Vec::new()
        }

        fn decode(&self, _bytes: &[u8]) -> Result<Json, CanonicalJsonError> {
            Ok(Json::Null)
        }
    }

    struct EmptyKem;

    impl Kem for EmptyKem {
        fn generate(&self, policy: Policy, _seed: &KemSeed) -> Result<IntakeKeypair, KemError> {
            Err(KemError::UnsupportedPolicy(policy))
        }
    }

    struct EmptySign;

    impl Sign for EmptySign {
        fn generate(
            &self,
            policy: Policy,
            _seed: &SignSeed,
        ) -> Result<IdentitySignKeypair, SignError> {
            Err(SignError::UnsupportedPolicy(policy))
        }
    }

    fn suite() -> Suite {
        Suite::new(
            Arc::new(ConstHmac(1)),
            Arc::new(EmptyCompress),
            Arc::new(EmptyB64),
            Arc::new(EmptyAead),
            Arc::new(EmptyJson),
            Arc::new(EmptyKem),
            Arc::new(EmptySign),
        )
    }

    #[test]
    fn debug_redacts_capabilities() {
        let suite = suite();
        assert_eq!(
            format!("{suite:?}"),
            "Suite { hmac: .., compress: .., b64u: .., aead: .., json: .., kem: .., sign: .. }"
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
        let nonce = AeadNonce::from_bytes(core::array::from_fn(|i| i as u8));
        let key = AeadKey::from_bytes([0; 32]);
        assert!(suite.aead().seal(&key, &nonce, b"", b"x").is_empty());
        assert!(
            suite
                .aead()
                .open(&key, &nonce, b"", b"x")
                .expect("open")
                .is_empty()
        );
        assert!(suite.canonical_json().encode(&Json::Null).is_empty());
        assert_eq!(
            suite.canonical_json().decode(b"").expect("json"),
            Json::Null
        );
        assert_eq!(
            suite
                .kem()
                .generate(Policy::Hybrid, &KemSeed::from_bytes([0; KEM_SEED_LEN]))
                .unwrap_err(),
            KemError::UnsupportedPolicy(Policy::Hybrid)
        );
        assert_eq!(
            suite
                .sign()
                .generate(Policy::Hybrid, &SignSeed::from_bytes([0; SIGN_SEED_LEN]))
                .unwrap_err(),
            SignError::UnsupportedPolicy(Policy::Hybrid)
        );
        let _ = suite.clone();
    }
}
