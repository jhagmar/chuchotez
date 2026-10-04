//! KEM port: keygen, wrap, and unwrap.

use crate::protocol::bytes32;
use crate::protocol::{Policy, RANDOM32_LEN, Random32};

/// Length of [`KemSeed`].
pub const KEM_SEED_LEN: usize = 64;

/// Classic X25519 encapsulation-key length.
pub const CLASSIC_KEM_PK_LEN: usize = 32;

/// ML-KEM-768 encapsulation-key length.
pub const MLKEM768_KEM_PK_LEN: usize = 1184;

/// X-Wing encapsulation-key length.
pub const XWING_KEM_PK_LEN: usize = 1216;

/// Classic X25519 secret-key length.
pub const CLASSIC_KEM_SK_LEN: usize = 32;

/// ML-KEM-768 secret-key length.
pub const MLKEM768_KEM_SK_LEN: usize = 2400;

/// X-Wing secret-key length.
pub const XWING_KEM_SK_LEN: usize = 32;

/// Classic wrap ciphertext length.
pub const CLASSIC_KEM_CT_LEN: usize = 32;

/// ML-KEM-768 wrap ciphertext length.
pub const MLKEM768_KEM_CT_LEN: usize = 1088;

/// X-Wing wrap ciphertext length.
pub const XWING_KEM_CT_LEN: usize = 1120;

/// Shared secret length from [`Kem::wrap`].
pub const KEM_SHARED_LEN: usize = 32;

/// [`KEM_SEED_LEN`] bytes as an array.
pub type KemSeedBytes = [u8; KEM_SEED_LEN];

/// Encapsulation-key length for `policy`.
#[must_use]
pub const fn kem_pk_len(policy: Policy) -> usize {
    match policy {
        Policy::Classic => CLASSIC_KEM_PK_LEN,
        Policy::PostQuantum => MLKEM768_KEM_PK_LEN,
        Policy::Hybrid => XWING_KEM_PK_LEN,
    }
}

/// Secret-key length for `policy`.
#[must_use]
pub const fn kem_sk_len(policy: Policy) -> usize {
    match policy {
        Policy::Classic => CLASSIC_KEM_SK_LEN,
        Policy::PostQuantum => MLKEM768_KEM_SK_LEN,
        Policy::Hybrid => XWING_KEM_SK_LEN,
    }
}

/// Wrap ciphertext length for `policy`.
#[must_use]
pub const fn kem_ct_len(policy: Policy) -> usize {
    match policy {
        Policy::Classic => CLASSIC_KEM_CT_LEN,
        Policy::PostQuantum => MLKEM768_KEM_CT_LEN,
        Policy::Hybrid => XWING_KEM_CT_LEN,
    }
}

/// Derandomized KEM seed: two [`Random32`] draws.
#[derive(Clone, Eq)]
pub struct KemSeed(KemSeedBytes);

impl KemSeed {
    /// Wrap [`KEM_SEED_LEN`] cryptographically random bytes.
    #[must_use]
    pub const fn from_bytes(bytes: KemSeedBytes) -> Self {
        Self(bytes)
    }

    /// Concatenate two [`Random32`] draws.
    #[must_use]
    pub fn from_pair(first: Random32, second: Random32) -> Self {
        let mut bytes = [0u8; KEM_SEED_LEN];
        bytes[..RANDOM32_LEN].copy_from_slice(first.as_bytes());
        bytes[RANDOM32_LEN..].copy_from_slice(second.as_bytes());
        Self(bytes)
    }

    /// Raw bytes for a derandomized generator.
    #[must_use]
    pub const fn as_bytes(&self) -> &KemSeedBytes {
        &self.0
    }
}

impl PartialEq for KemSeed {
    fn eq(&self, other: &Self) -> bool {
        bytes32::ct_eq(&self.0, &other.0)
    }
}

impl core::fmt::Debug for KemSeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KemSeed(..)")
    }
}

/// Encapsulation public key for one [`Policy`].
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct EncryptionPublicKey(Vec<u8>);

impl EncryptionPublicKey {
    /// Bytes whose length already matches `policy`.
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Accept `bytes` when the length is `kem_pk_len(policy)`.
    pub fn parse(policy: Policy, bytes: impl Into<Vec<u8>>) -> Option<Self> {
        let bytes = bytes.into();
        (bytes.len() == kem_pk_len(policy)).then_some(Self(bytes))
    }

    /// Raw encapsulation key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for EncryptionPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl core::ops::Deref for EncryptionPublicKey {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for EncryptionPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EncryptionPublicKey(..)")
    }
}

/// A `wrap` key pair.
#[derive(Clone)]
pub struct KeyPair {
    public: Vec<u8>,
    secret: Vec<u8>,
}

impl KeyPair {
    /// Wrap public and secret key bytes from a KEM adapter.
    #[must_use]
    pub fn from_parts(public: Vec<u8>, secret: Vec<u8>) -> Self {
        Self { public, secret }
    }

    /// Encapsulation-key bytes.
    #[must_use]
    pub fn public_bytes(&self) -> &[u8] {
        &self.public
    }

    /// Decapsulation-key bytes.
    #[must_use]
    pub fn secret_bytes(&self) -> &[u8] {
        &self.secret
    }
}

impl PartialEq for KeyPair {
    fn eq(&self, other: &Self) -> bool {
        self.public == other.public && self.secret == other.secret
    }
}

impl Eq for KeyPair {}

impl core::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KeyPair(..)")
    }
}

/// Failure from [`Kem`] methods.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KemError {
    /// This suite has no generator for `policy`.
    UnsupportedPolicy(Policy),
    /// The primitive rejected the seed, key, or ciphertext.
    KeyGen,
    /// Wrap or unwrap failed.
    Wrap,
}

impl core::fmt::Display for KemError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedPolicy(policy) => {
                write!(f, "unsupported kem policy {policy:?}")
            }
            Self::KeyGen => f.write_str("kem key generation failed"),
            Self::Wrap => f.write_str("kem wrap failed"),
        }
    }
}

impl std::error::Error for KemError {}

/// Generate, wrap, and unwrap for a [`Policy`]. Adapters supply the primitive.
pub trait Kem {
    /// Expand a keypair for `policy` from `seed`.
    fn generate(&self, policy: Policy, seed: &KemSeed) -> Result<KeyPair, KemError>;

    /// Wrap a one-time shared secret to `pk`.
    fn wrap(
        &self,
        policy: Policy,
        pk: &[u8],
        seed: &KemSeed,
    ) -> Result<(Vec<u8>, Vec<u8>), KemError>;

    /// Recover the shared secret from `kem_ct` using `sk`.
    fn unwrap(&self, policy: Policy, sk: &[u8], kem_ct: &[u8]) -> Result<Vec<u8>, KemError>;
}

#[cfg(test)]
mod tests {
    use super::{
        EncryptionPublicKey, KEM_SEED_LEN, KemError, KemSeed, KemSeedBytes, KeyPair, kem_ct_len,
        kem_pk_len, kem_sk_len,
    };
    use crate::protocol::{Policy, RANDOM32_LEN, Random32};

    #[test]
    fn kem_seed_from_pair_eq_and_debug() {
        let first = Random32::from_bytes([0xab; RANDOM32_LEN]);
        let second = Random32::from_bytes([0xcd; RANDOM32_LEN]);
        let seed = KemSeed::from_pair(first, second);
        let mut expected = [0u8; KEM_SEED_LEN];
        expected[..RANDOM32_LEN].fill(0xab);
        expected[RANDOM32_LEN..].fill(0xcd);
        let _: &KemSeedBytes = seed.as_bytes();
        assert_eq!(seed.as_bytes(), &expected);
        assert_eq!(seed, KemSeed::from_bytes(expected));
        assert_ne!(seed, KemSeed::from_bytes([0; KEM_SEED_LEN]));
        assert_eq!(seed.clone().as_bytes(), &expected);
        assert_eq!(format!("{seed:?}"), "KemSeed(..)");
        assert!(!format!("{seed:?}").contains("ab"));
        let keys = KeyPair::from_parts(vec![1, 2], vec![3, 4]);
        assert_eq!(keys.public_bytes(), &[1, 2]);
        let parsed = EncryptionPublicKey::parse(Policy::Classic, vec![0; 32]).expect("pk");
        assert_eq!(parsed.as_ref(), &[0; 32]);
        assert!(EncryptionPublicKey::parse(Policy::Classic, vec![0; 3]).is_none());
        assert_eq!(
            format!("{:?}", EncryptionPublicKey::from_bytes(vec![1])),
            "EncryptionPublicKey(..)"
        );
        assert_eq!(keys.secret_bytes(), &[3, 4]);
        assert_eq!(format!("{keys:?}"), "KeyPair(..)");
        assert_eq!(keys, keys.clone());
        assert_eq!(
            format!("{}", KemError::UnsupportedPolicy(Policy::Hybrid)),
            "unsupported kem policy Hybrid"
        );
        assert_eq!(format!("{}", KemError::KeyGen), "kem key generation failed");
        assert_eq!(format!("{}", KemError::Wrap), "kem wrap failed");
        let _ = &KemError::KeyGen as &dyn std::error::Error;
        assert_ne!(KemError::KeyGen, KemError::Wrap);
        assert_eq!(kem_pk_len(Policy::Classic), 32);
        assert_eq!(kem_pk_len(Policy::PostQuantum), 1184);
        assert_eq!(kem_pk_len(Policy::Hybrid), 1216);
        assert_eq!(kem_sk_len(Policy::Classic), 32);
        assert_eq!(kem_sk_len(Policy::PostQuantum), 2400);
        assert_eq!(kem_sk_len(Policy::Hybrid), 32);
        assert_eq!(kem_ct_len(Policy::Classic), 32);
        assert_eq!(kem_ct_len(Policy::PostQuantum), 1088);
        assert_eq!(kem_ct_len(Policy::Hybrid), 1120);
    }
}
