//! Host CSPRNG port: branded 32-byte draws.

use super::bytes32;

/// Length of [`Random32`] CSPRNG output.
pub const RANDOM32_LEN: usize = 32;

/// [`RANDOM32_LEN`] bytes as an array.
pub type Random32Bytes = [u8; RANDOM32_LEN];

/// [`RANDOM32_LEN`] cryptographically random bytes from [`Rng`].
///
/// Branded so a hash digest or a key cannot be passed where fresh entropy is
/// required. [`super::v1::Engine::try_new_invite`] assigns those bytes the
/// Ticket-secret role.
#[derive(Clone, Eq)]
pub struct Random32(Random32Bytes);

impl Random32 {
    /// Wrap output that is already [`RANDOM32_LEN`] cryptographically random bytes.
    #[must_use]
    pub const fn from_bytes(bytes: Random32Bytes) -> Self {
        Self(bytes)
    }

    /// Raw bytes for a constructor that consumes entropy.
    #[must_use]
    pub const fn as_bytes(&self) -> &Random32Bytes {
        &self.0
    }

    /// Consume the wrapper and return the array.
    #[must_use]
    pub const fn into_bytes(self) -> Random32Bytes {
        self.0
    }
}

impl PartialEq for Random32 {
    fn eq(&self, other: &Self) -> bool {
        bytes32::ct_eq(&self.0, &other.0)
    }
}

impl core::fmt::Debug for Random32 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Random32(..)")
    }
}

/// Cryptographic randomness. The host supplies a CSPRNG on every call that
/// needs entropy. Tests inject a seed.
pub trait Rng {
    /// [`RANDOM32_LEN`] cryptographically random bytes.
    fn random32(&self) -> Random32;
}

#[cfg(test)]
mod tests {
    use super::Random32;
    use crate::protocol::v1::fixtures;

    #[test]
    fn random32_eq_and_debug() {
        let a = Random32::from_bytes(fixtures::fill(0xab));
        let b = Random32::from_bytes(fixtures::fill(0xab));
        let c = Random32::from_bytes(fixtures::fill(0xcd));
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.as_bytes(), &fixtures::fill(0xab));
        assert_eq!(a.clone().into_bytes(), fixtures::fill(0xab));
        assert_eq!(format!("{a:?}"), "Random32(..)");
        assert!(!format!("{a:?}").contains("ab"));
    }
}
