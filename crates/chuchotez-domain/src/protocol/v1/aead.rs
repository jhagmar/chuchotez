//! AES-256-GCM port.

use crate::protocol::bytes32;

/// AES-256-GCM key length.
pub const AEAD_KEY_LEN: usize = 32;

/// AES-256-GCM nonce length.
pub const AEAD_NONCE_LEN: usize = 12;

/// AES-256-GCM key bytes.
pub type AeadKeyBytes = [u8; AEAD_KEY_LEN];

/// AES-256-GCM nonce bytes.
pub type AeadNonceBytes = [u8; AEAD_NONCE_LEN];

/// AES-256-GCM key.
#[derive(Clone, Eq)]
pub struct AeadKey(AeadKeyBytes);

impl AeadKey {
    /// Wrap bytes that already have the AEAD-key role.
    #[must_use]
    pub const fn from_bytes(bytes: AeadKeyBytes) -> Self {
        Self(bytes)
    }

    /// Key bytes for an AEAD adapter.
    #[must_use]
    pub const fn as_bytes(&self) -> &AeadKeyBytes {
        &self.0
    }
}

impl PartialEq for AeadKey {
    fn eq(&self, other: &Self) -> bool {
        bytes32::ct_eq(&self.0, &other.0)
    }
}

impl core::fmt::Debug for AeadKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AeadKey(..)")
    }
}

/// AES-256-GCM nonce.
#[derive(Clone, Eq)]
pub struct AeadNonce(AeadNonceBytes);

impl AeadNonce {
    /// Wrap bytes that already have the AEAD-nonce role.
    #[must_use]
    pub const fn from_bytes(bytes: AeadNonceBytes) -> Self {
        Self(bytes)
    }

    /// Nonce bytes for an AEAD adapter.
    #[must_use]
    pub const fn as_bytes(&self) -> &AeadNonceBytes {
        &self.0
    }
}

impl PartialEq for AeadNonce {
    fn eq(&self, other: &Self) -> bool {
        bytes32::ct_eq(&self.0, &other.0)
    }
}

impl core::fmt::Debug for AeadNonce {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AeadNonce(..)")
    }
}

/// Failure from [`Aead::open`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AeadError {
    /// Authentication failed, or the ciphertext was too short.
    Open,
}

impl core::fmt::Display for AeadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("aead open failed")
    }
}

impl std::error::Error for AeadError {}

/// AES-256-GCM seal / open. Adapters supply the primitive; tests inject a fake.
pub trait Aead {
    /// Seal `plaintext` under `key` with `nonce` and `aad`.
    fn seal(&self, key: &AeadKey, nonce: &AeadNonce, aad: &[u8], plaintext: &[u8]) -> Vec<u8>;

    /// Open `ciphertext` under `key` with `nonce` and `aad`.
    fn open(
        &self,
        key: &AeadKey,
        nonce: &AeadNonce,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, AeadError>;
}

#[cfg(test)]
mod tests {
    use super::{AEAD_KEY_LEN, AEAD_NONCE_LEN, AeadError, AeadKey, AeadNonce};

    #[test]
    fn aead_error_display() {
        assert_eq!(format!("{}", AeadError::Open), "aead open failed");
        assert_eq!(AeadError::Open, AeadError::Open);
        let _ = &AeadError::Open as &dyn std::error::Error;
    }

    #[test]
    fn aead_key_and_nonce_eq_debug() {
        let key = AeadKey::from_bytes([0xab; AEAD_KEY_LEN]);
        assert_eq!(key, AeadKey::from_bytes([0xab; AEAD_KEY_LEN]));
        assert_ne!(key, AeadKey::from_bytes([0xcd; AEAD_KEY_LEN]));
        assert_eq!(key.as_bytes(), &[0xab; AEAD_KEY_LEN]);
        assert_eq!(format!("{key:?}"), "AeadKey(..)");
        assert!(!format!("{key:?}").contains("ab"));
        assert_eq!(key.clone(), key);
        let nonce = AeadNonce::from_bytes(core::array::from_fn(|i| i as u8));
        assert_eq!(nonce.as_bytes()[0], 0);
        assert_eq!(nonce, nonce.clone());
        assert_ne!(nonce, AeadNonce::from_bytes([0; AEAD_NONCE_LEN]));
        assert_eq!(format!("{nonce:?}"), "AeadNonce(..)");
    }
}
