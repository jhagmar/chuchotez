//! v1 capability bag.

use super::{Aead, Argon2id, Base64Url, CanonicalJson, Compress, HmacSha256, Kem, Sha256, Sign};
use std::sync::Arc;

/// HMAC, compress, b64u, AEAD, canonical JSON, KEM, Sign, SHA-256, and Argon2id.
#[derive(Clone)]
pub struct Suite {
    hmac: Arc<dyn HmacSha256 + Send + Sync>,
    compress: Arc<dyn Compress + Send + Sync>,
    b64u: Arc<dyn Base64Url + Send + Sync>,
    aead: Arc<dyn Aead + Send + Sync>,
    json: Arc<dyn CanonicalJson + Send + Sync>,
    kem: Arc<dyn Kem + Send + Sync>,
    sign: Arc<dyn Sign + Send + Sync>,
    hash: Arc<dyn Sha256 + Send + Sync>,
    argon: Arc<dyn Argon2id + Send + Sync>,
}

impl Suite {
    /// Build a v1 suite from library- or host-supplied adapters.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        hmac: Arc<dyn HmacSha256 + Send + Sync>,
        compress: Arc<dyn Compress + Send + Sync>,
        b64u: Arc<dyn Base64Url + Send + Sync>,
        aead: Arc<dyn Aead + Send + Sync>,
        json: Arc<dyn CanonicalJson + Send + Sync>,
        kem: Arc<dyn Kem + Send + Sync>,
        sign: Arc<dyn Sign + Send + Sync>,
        hash: Arc<dyn Sha256 + Send + Sync>,
        argon: Arc<dyn Argon2id + Send + Sync>,
    ) -> Self {
        Self {
            hmac,
            compress,
            b64u,
            aead,
            json,
            kem,
            sign,
            hash,
            argon,
        }
    }

    #[must_use]
    pub(crate) fn hmac(&self) -> &dyn HmacSha256 {
        &*self.hmac
    }

    #[must_use]
    pub(crate) fn compress(&self) -> &dyn Compress {
        &*self.compress
    }

    #[must_use]
    pub(crate) fn b64u(&self) -> &dyn Base64Url {
        &*self.b64u
    }

    #[must_use]
    pub(crate) fn aead(&self) -> &dyn Aead {
        &*self.aead
    }

    #[must_use]
    pub(crate) fn canonical_json(&self) -> &dyn CanonicalJson {
        &*self.json
    }

    #[must_use]
    pub(crate) fn kem(&self) -> &dyn Kem {
        &*self.kem
    }

    #[must_use]
    pub(crate) fn sign(&self) -> &dyn Sign {
        &*self.sign
    }

    #[must_use]
    pub(crate) fn hash(&self) -> &dyn Sha256 {
        &*self.hash
    }

    #[must_use]
    pub(crate) fn argon(&self) -> &dyn Argon2id {
        &*self.argon
    }
}

impl core::fmt::Debug for Suite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Suite { .. }")
    }
}

#[cfg(test)]
mod tests {
    use super::Suite;
    use crate::protocol::Policy;
    use crate::protocol::Random32;
    use crate::protocol::v1::{
        Aead, AeadError, AeadKey, AeadNonce, Argon2Error, Argon2id, Base64Url, Base64UrlError,
        CanonicalJson, CanonicalJsonError, Compress, CompressError, HmacSha256, HmacSha256Key,
        HmacSha256Mac, Json, KEM_SEED_LEN, Kem, KemError, KemSeed, KeyPair, SECRET_LEN,
        SIGN_SEED_LEN, Sha256, Sign, SignError, SignSeed, SigningKeyPair,
    };
    use std::sync::Arc;

    struct ConstHmac;
    impl HmacSha256 for ConstHmac {
        fn mac(&self, _key: &HmacSha256Key, _data: &[u8]) -> HmacSha256Mac {
            HmacSha256Mac::from_bytes([1; SECRET_LEN])
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
        fn generate(&self, policy: Policy, _seed: &KemSeed) -> Result<KeyPair, KemError> {
            Err(KemError::UnsupportedPolicy(policy))
        }
        fn wrap(
            &self,
            policy: Policy,
            _pk: &[u8],
            _seed: &KemSeed,
        ) -> Result<(Vec<u8>, Vec<u8>), KemError> {
            Err(KemError::UnsupportedPolicy(policy))
        }
        fn unwrap(&self, policy: Policy, _sk: &[u8], _kem_ct: &[u8]) -> Result<Vec<u8>, KemError> {
            Err(KemError::UnsupportedPolicy(policy))
        }
    }
    struct EmptySign;
    impl Sign for EmptySign {
        fn generate(&self, policy: Policy, _seed: &SignSeed) -> Result<SigningKeyPair, SignError> {
            Err(SignError::UnsupportedPolicy(policy))
        }
        fn sign(
            &self,
            policy: Policy,
            _sk: &[u8],
            _message: &[u8],
            _seed: &Random32,
        ) -> Result<Vec<u8>, SignError> {
            Err(SignError::UnsupportedPolicy(policy))
        }
        fn verify(
            &self,
            policy: Policy,
            _pk: &[u8],
            _message: &[u8],
            _sig: &[u8],
        ) -> Result<(), SignError> {
            Err(SignError::UnsupportedPolicy(policy))
        }
    }
    struct EmptyHash;
    impl Sha256 for EmptyHash {
        fn hash(&self, _data: &[u8]) -> [u8; 32] {
            [0; 32]
        }
    }
    struct EmptyArgon;
    impl Argon2id for EmptyArgon {
        fn hash(
            &self,
            _passphrase: &[u8],
            _salt: &[u8; 16],
            _m: u32,
            _t: u32,
            _p: u32,
        ) -> Result<[u8; 32], Argon2Error> {
            Err(Argon2Error::Refused)
        }
    }

    #[test]
    fn debug_redacts_capabilities() {
        let suite = Suite::new(
            Arc::new(ConstHmac),
            Arc::new(EmptyCompress),
            Arc::new(EmptyB64),
            Arc::new(EmptyAead),
            Arc::new(EmptyJson),
            Arc::new(EmptyKem),
            Arc::new(EmptySign),
            Arc::new(EmptyHash),
            Arc::new(EmptyArgon),
        );
        assert_eq!(format!("{suite:?}"), "Suite { .. }");
        assert_eq!(
            suite
                .hmac()
                .mac(&HmacSha256Key::from_bytes([0; SECRET_LEN]), b"")
                .as_bytes()[0],
            1
        );
        assert!(suite.compress().compress(b"x").is_empty());
        assert!(suite.b64u().encode(b"x").is_empty());
        assert!(suite.hash().hash(b"x").iter().all(|b| *b == 0));
        assert_eq!(
            suite
                .argon()
                .hash(b"passpass", &[0; 16], 8, 1, 1)
                .unwrap_err(),
            Argon2Error::Refused
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
        assert!(suite.compress().decompress(b"x", 8).expect("d").is_empty());
        assert!(suite.b64u().decode("x").expect("b").is_empty());
        let nonce = AeadNonce::from_bytes([0; 12]);
        let key = AeadKey::from_bytes([0; 32]);
        assert!(suite.aead().seal(&key, &nonce, b"", b"x").is_empty());
        assert!(
            suite
                .aead()
                .open(&key, &nonce, b"", b"x")
                .expect("o")
                .is_empty()
        );
        assert!(suite.canonical_json().encode(&Json::Null).is_empty());
        assert_eq!(suite.canonical_json().decode(b"").expect("j"), Json::Null);
        assert_eq!(
            suite
                .kem()
                .wrap(
                    Policy::Classic,
                    &[],
                    &KemSeed::from_bytes([0; KEM_SEED_LEN])
                )
                .unwrap_err(),
            KemError::UnsupportedPolicy(Policy::Classic)
        );
        assert_eq!(
            suite.kem().unwrap(Policy::Classic, &[], &[]).unwrap_err(),
            KemError::UnsupportedPolicy(Policy::Classic)
        );
        let r = Random32::from_bytes([0; 32]);
        assert_eq!(
            suite
                .sign()
                .sign(Policy::Classic, &[], b"", &r)
                .unwrap_err(),
            SignError::UnsupportedPolicy(Policy::Classic)
        );
        assert_eq!(
            suite
                .sign()
                .verify(Policy::Classic, &[], b"", &[])
                .unwrap_err(),
            SignError::UnsupportedPolicy(Policy::Classic)
        );
        let _ = suite.clone();
    }
}
