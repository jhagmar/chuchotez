//! Identity signing keypair and the Sign port.

use crate::protocol::bytes32;
use crate::protocol::{Policy, RANDOM32_LEN, Random32};

/// Length of [`SignSeed`].
pub const SIGN_SEED_LEN: usize = 64;

/// Classic Ed25519 verification-key length.
pub const CLASSIC_SIGN_PK_LEN: usize = 32;

/// ML-DSA-65 verification-key length.
pub const MLDSA65_SIGN_PK_LEN: usize = 1952;

/// Hybrid verification-key length (Ed25519 then ML-DSA-65).
pub const HYBRID_SIGN_PK_LEN: usize = CLASSIC_SIGN_PK_LEN + MLDSA65_SIGN_PK_LEN;

/// Classic Ed25519 signing-key length.
pub const CLASSIC_SIGN_SK_LEN: usize = 32;

/// ML-DSA-65 signing-key length.
pub const MLDSA65_SIGN_SK_LEN: usize = 4032;

/// Hybrid signing-key length.
pub const HYBRID_SIGN_SK_LEN: usize = CLASSIC_SIGN_SK_LEN + MLDSA65_SIGN_SK_LEN;

/// Classic Ed25519 signature length.
pub const CLASSIC_SIGN_SIG_LEN: usize = 64;

/// ML-DSA-65 signature length.
pub const MLDSA65_SIGN_SIG_LEN: usize = 3309;

/// Hybrid signature length.
pub const HYBRID_SIGN_SIG_LEN: usize = CLASSIC_SIGN_SIG_LEN + MLDSA65_SIGN_SIG_LEN;

/// [`SIGN_SEED_LEN`] bytes as an array.
pub type SignSeedBytes = [u8; SIGN_SEED_LEN];

/// Verification-key length for `policy`.
#[must_use]
pub const fn sign_pk_len(policy: Policy) -> usize {
    match policy {
        Policy::Classic => CLASSIC_SIGN_PK_LEN,
        Policy::PostQuantum => MLDSA65_SIGN_PK_LEN,
        Policy::Hybrid => HYBRID_SIGN_PK_LEN,
    }
}

/// Signing-key length for `policy`.
#[must_use]
pub const fn sign_sk_len(policy: Policy) -> usize {
    match policy {
        Policy::Classic => CLASSIC_SIGN_SK_LEN,
        Policy::PostQuantum => MLDSA65_SIGN_SK_LEN,
        Policy::Hybrid => HYBRID_SIGN_SK_LEN,
    }
}

/// Signature length for `policy`.
#[must_use]
pub const fn sign_sig_len(policy: Policy) -> usize {
    match policy {
        Policy::Classic => CLASSIC_SIGN_SIG_LEN,
        Policy::PostQuantum => MLDSA65_SIGN_SIG_LEN,
        Policy::Hybrid => HYBRID_SIGN_SIG_LEN,
    }
}

/// Derandomized signing key-generation seed.
///
/// [`super::Engine::create_identity`] concatenates two [`Random32`] draws.
/// Classic Ed25519 and PostQuantum ML-DSA-65 consume the first [`RANDOM32_LEN`]
/// bytes; Hybrid consumes [`SIGN_SEED_LEN`].
#[derive(Clone, Eq)]
pub struct SignSeed(SignSeedBytes);

impl SignSeed {
    /// Wrap [`SIGN_SEED_LEN`] cryptographically random bytes.
    #[must_use]
    pub const fn from_bytes(bytes: SignSeedBytes) -> Self {
        Self(bytes)
    }

    /// Concatenate two [`Random32`] draws.
    #[must_use]
    pub fn from_pair(first: Random32, second: Random32) -> Self {
        let mut bytes = [0u8; SIGN_SEED_LEN];
        bytes[..RANDOM32_LEN].copy_from_slice(first.as_bytes());
        bytes[RANDOM32_LEN..].copy_from_slice(second.as_bytes());
        Self(bytes)
    }

    /// Raw bytes for a derandomized generator.
    #[must_use]
    pub const fn as_bytes(&self) -> &SignSeedBytes {
        &self.0
    }
}

impl PartialEq for SignSeed {
    fn eq(&self, other: &Self) -> bool {
        bytes32::ct_eq(&self.0, &other.0)
    }
}

impl core::fmt::Debug for SignSeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SignSeed(..)")
    }
}

/// A `sign` key pair.
#[derive(Clone)]
pub struct SigningKeyPair {
    public: Vec<u8>,
    secret: Vec<u8>,
}

impl SigningKeyPair {
    /// Wrap public and secret key bytes from a Sign adapter.
    #[must_use]
    pub fn from_parts(public: Vec<u8>, secret: Vec<u8>) -> Self {
        Self { public, secret }
    }

    /// Verification-key bytes.
    #[must_use]
    pub fn public_bytes(&self) -> &[u8] {
        &self.public
    }

    /// Signing-key bytes.
    #[must_use]
    pub fn secret_bytes(&self) -> &[u8] {
        &self.secret
    }
}

impl PartialEq for SigningKeyPair {
    fn eq(&self, other: &Self) -> bool {
        self.public == other.public && self.secret == other.secret
    }
}

impl Eq for SigningKeyPair {}

impl core::fmt::Debug for SigningKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SigningKeyPair(..)")
    }
}

impl Drop for SigningKeyPair {
    fn drop(&mut self) {
        self.secret.fill(0);
    }
}

/// Failure from [`Sign::generate`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignError {
    /// This suite has no generator for `policy`.
    UnsupportedPolicy(Policy),
    /// The primitive rejected the seed or failed to expand a keypair.
    KeyGen,
    /// Sign or verify failed.
    Sign,
}

impl core::fmt::Display for SignError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedPolicy(policy) => {
                write!(f, "unsupported sign policy {policy:?}")
            }
            Self::KeyGen => f.write_str("sign key generation failed"),
            Self::Sign => f.write_str("sign failed"),
        }
    }
}

impl std::error::Error for SignError {}

/// Verification key for one [`Policy`].
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct SigningPublicKey(Vec<u8>);

impl SigningPublicKey {
    /// Bytes whose length already matches `policy`.
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Accept `bytes` when the length is `sign_pk_len(policy)`.
    pub fn parse(policy: Policy, bytes: impl Into<Vec<u8>>) -> Option<Self> {
        let bytes = bytes.into();
        (bytes.len() == sign_pk_len(policy)).then_some(Self(bytes))
    }

    /// Raw verification key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for SigningPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl core::ops::Deref for SigningPublicKey {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for SigningPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SigningPublicKey(..)")
    }
}

/// Generate, sign, and verify for a [`Policy`]. Adapters supply the primitive.
pub trait Sign {
    /// Expand a signing keypair for `policy` from `seed`.
    fn generate(&self, policy: Policy, seed: &SignSeed) -> Result<SigningKeyPair, SignError>;

    /// Sign `message` with `sk`. Classic ignores `seed`; PostQuantum and Hybrid consume it.
    fn sign(
        &self,
        policy: Policy,
        sk: &[u8],
        message: &[u8],
        seed: &Random32,
    ) -> Result<Vec<u8>, SignError>;

    /// Accept when `sig` matches `pk` and `message`.
    fn verify(
        &self,
        policy: Policy,
        pk: &[u8],
        message: &[u8],
        sig: &[u8],
    ) -> Result<(), SignError>;
}

#[cfg(test)]
mod tests {
    use super::{
        SIGN_SEED_LEN, SignError, SignSeed, SignSeedBytes, SigningKeyPair, SigningPublicKey,
        sign_pk_len, sign_sig_len, sign_sk_len,
    };
    use crate::protocol::{Policy, RANDOM32_LEN, Random32};

    #[test]
    fn sign_seed_from_pair_eq_and_debug() {
        let first = Random32::from_bytes([0x11; RANDOM32_LEN]);
        let second = Random32::from_bytes([0x22; RANDOM32_LEN]);
        let seed = SignSeed::from_pair(first, second);
        let mut expected = [0u8; SIGN_SEED_LEN];
        expected[..RANDOM32_LEN].fill(0x11);
        expected[RANDOM32_LEN..].fill(0x22);
        let _: &SignSeedBytes = seed.as_bytes();
        assert_eq!(seed.as_bytes(), &expected);
        assert_eq!(seed, SignSeed::from_bytes(expected));
        assert_ne!(seed, SignSeed::from_bytes([0; SIGN_SEED_LEN]));
        assert_eq!(seed.clone().as_bytes(), &expected);
        assert_eq!(format!("{seed:?}"), "SignSeed(..)");
        assert!(!format!("{seed:?}").contains("11"));
        assert_eq!(sign_pk_len(Policy::Classic), 32);
        assert_eq!(sign_pk_len(Policy::PostQuantum), 1952);
        assert_eq!(sign_pk_len(Policy::Hybrid), 1984);
        assert_eq!(sign_sk_len(Policy::Classic), 32);
        assert_eq!(sign_sk_len(Policy::PostQuantum), 4032);
        assert_eq!(sign_sk_len(Policy::Hybrid), 4064);
        assert_eq!(sign_sig_len(Policy::Classic), 64);
        assert_eq!(sign_sig_len(Policy::PostQuantum), 3309);
        assert_eq!(sign_sig_len(Policy::Hybrid), 3373);
        let keys = SigningKeyPair::from_parts(vec![1, 2], vec![3, 4]);
        assert_eq!(keys.public_bytes(), &[1, 2]);
        let parsed = SigningPublicKey::parse(Policy::Classic, vec![0; 32]).expect("pk");
        assert_eq!(parsed.as_ref(), &[0; 32]);
        assert!(SigningPublicKey::parse(Policy::Classic, vec![0; 3]).is_none());
        assert_eq!(
            format!("{:?}", SigningPublicKey::from_bytes(vec![1])),
            "SigningPublicKey(..)"
        );
        assert_eq!(keys.secret_bytes(), &[3, 4]);
        assert_eq!(format!("{keys:?}"), "SigningKeyPair(..)");
        assert!(!format!("{keys:?}").contains('3'));
        assert_eq!(keys, keys.clone());
        assert_eq!(
            format!("{}", SignError::KeyGen),
            "sign key generation failed"
        );
        assert_eq!(format!("{}", SignError::Sign), "sign failed");
        assert_eq!(
            format!("{}", SignError::UnsupportedPolicy(Policy::Classic)),
            "unsupported sign policy Classic"
        );
        let _ = &SignError::KeyGen as &dyn std::error::Error;
        assert_ne!(
            SignError::KeyGen,
            SignError::UnsupportedPolicy(Policy::Hybrid)
        );
    }
}
