//! Intake keypair, calling-card receiver, and the KEM port.

use super::{MAILBOX_MAX_COUNT, Mailbox, WIRE_MAX_COUNT, Wire};
use crate::protocol::bytes32;
use crate::protocol::{Policy, RANDOM32_LEN, Random32};

/// Length of [`KemSeed`].
pub const KEM_SEED_LEN: usize = 64;

/// Classic X25519 encapsulation-key length.
pub const CLASSIC_INTAKE_PK_LEN: usize = 32;

/// ML-KEM-768 encapsulation-key length.
pub const MLKEM768_INTAKE_PK_LEN: usize = 1184;

/// X-Wing encapsulation-key length.
pub const XWING_INTAKE_PK_LEN: usize = 1216;

/// [`KEM_SEED_LEN`] bytes as an array.
pub type KemSeedBytes = [u8; KEM_SEED_LEN];

/// Encapsulation-key length for `policy`.
#[must_use]
pub const fn intake_pk_len(policy: Policy) -> usize {
    match policy {
        Policy::Classic => CLASSIC_INTAKE_PK_LEN,
        Policy::PostQuantum => MLKEM768_INTAKE_PK_LEN,
        Policy::Hybrid => XWING_INTAKE_PK_LEN,
    }
}

/// Derandomized Intake key-generation seed.
///
/// [`super::Engine::create_invite`] concatenates two [`Random32`] draws.
/// [`Kem::generate`] is a function of [`Policy`] and this seed. Classic X25519
/// and Hybrid X-Wing consume the first [`RANDOM32_LEN`] bytes; PostQuantum
/// ML-KEM-768 consumes [`KEM_SEED_LEN`].
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

/// Public and secret KEM bytes for an [`Intake`].
#[derive(Clone)]
pub struct IntakeKeypair {
    public: Vec<u8>,
    secret: Vec<u8>,
}

/// Public and secret KEM bytes for an [`super::Identity`].
#[derive(Clone)]
pub struct IdentityKemKeypair {
    public: Vec<u8>,
    secret: Vec<u8>,
}

impl IdentityKemKeypair {
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

impl PartialEq for IdentityKemKeypair {
    fn eq(&self, other: &Self) -> bool {
        self.public == other.public && self.secret == other.secret
    }
}

impl Eq for IdentityKemKeypair {}

impl core::fmt::Debug for IdentityKemKeypair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("IdentityKemKeypair(..)")
    }
}

impl IntakeKeypair {
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

impl core::fmt::Debug for IntakeKeypair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("IntakeKeypair(..)")
    }
}

/// Why assembling an [`Intake`] failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntakeError {
    /// Mailbox list is empty.
    EmptyMailboxes,
    /// Mailbox count exceeds [`MAILBOX_MAX_COUNT`].
    TooManyMailboxes,
    /// Wire count exceeds [`WIRE_MAX_COUNT`].
    TooManyWires,
}

impl core::fmt::Display for IntakeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyMailboxes => f.write_str("intake needs at least one Mailbox"),
            Self::TooManyMailboxes => f.write_str("intake has too many Mailboxes"),
            Self::TooManyWires => f.write_str("intake has too many Wires"),
        }
    }
}

impl std::error::Error for IntakeError {}

/// Calling-card receiver: KEM keypair, Mailboxes, and Wires.
#[derive(Clone)]
pub struct Intake {
    keys: IntakeKeypair,
    mailboxes: Vec<Mailbox>,
    wires: Vec<Wire>,
}

impl Intake {
    pub(crate) fn from_parts(
        keys: IntakeKeypair,
        mailboxes: Vec<Mailbox>,
        wires: Vec<Wire>,
    ) -> Result<Self, IntakeError> {
        if mailboxes.is_empty() {
            return Err(IntakeError::EmptyMailboxes);
        }
        if mailboxes.len() > MAILBOX_MAX_COUNT {
            return Err(IntakeError::TooManyMailboxes);
        }
        if wires.len() > WIRE_MAX_COUNT {
            return Err(IntakeError::TooManyWires);
        }
        Ok(Self {
            keys,
            mailboxes,
            wires,
        })
    }

    /// Encapsulation-key bytes.
    #[must_use]
    pub fn public_bytes(&self) -> &[u8] {
        self.keys.public_bytes()
    }

    /// Decapsulation-key bytes.
    #[must_use]
    pub fn secret_bytes(&self) -> &[u8] {
        self.keys.secret_bytes()
    }

    /// Mailboxes the invitee uses for the calling card.
    #[must_use]
    pub fn mailboxes(&self) -> &[Mailbox] {
        &self.mailboxes
    }

    /// Wires the invitee may open.
    #[must_use]
    pub fn wires(&self) -> &[Wire] {
        &self.wires
    }
}

impl PartialEq for Intake {
    fn eq(&self, other: &Self) -> bool {
        self.keys.public == other.keys.public
            && self.keys.secret == other.keys.secret
            && self.mailboxes == other.mailboxes
            && self.wires == other.wires
    }
}

impl Eq for Intake {}

impl core::fmt::Debug for Intake {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Intake(..)")
    }
}

/// Failure from [`Kem::generate`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KemError {
    /// This suite has no generator for `policy`.
    UnsupportedPolicy(Policy),
    /// The primitive rejected the seed or failed to expand a keypair.
    KeyGen,
}

impl core::fmt::Display for KemError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedPolicy(policy) => {
                write!(f, "unsupported kem policy {policy:?}")
            }
            Self::KeyGen => f.write_str("kem key generation failed"),
        }
    }
}

impl std::error::Error for KemError {}

/// Generate an [`IntakeKeypair`] for a [`Policy`]. Adapters supply the primitive.
pub trait Kem {
    /// Expand an Intake keypair for `policy` from `seed`.
    fn generate(&self, policy: Policy, seed: &KemSeed) -> Result<IntakeKeypair, KemError>;
}

#[cfg(test)]
mod tests {
    use super::{
        Intake, IntakeError, IntakeKeypair, KEM_SEED_LEN, KemError, KemSeed, KemSeedBytes,
        intake_pk_len,
    };
    use crate::protocol::v1::fixtures;
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
    }

    #[test]
    fn intake_and_kem_error() {
        let keys = IntakeKeypair::from_parts(vec![1, 2], vec![3, 4]);
        assert_eq!(keys.public_bytes(), &[1, 2]);
        assert_eq!(keys.secret_bytes(), &[3, 4]);
        assert_eq!(format!("{keys:?}"), "IntakeKeypair(..)");
        assert!(!format!("{keys:?}").contains('3'));
        let intake = Intake::from_parts(
            keys,
            vec![fixtures::sample_mailbox()],
            vec![fixtures::sample_wire()],
        )
        .expect("intake");
        assert_eq!(intake.public_bytes(), &[1, 2]);
        assert_eq!(intake.secret_bytes(), &[3, 4]);
        assert_eq!(intake.mailboxes().len(), 1);
        assert_eq!(intake.wires().len(), 1);
        assert_eq!(format!("{intake:?}"), "Intake(..)");
        assert_eq!(intake, intake);
        assert_eq!(
            Intake::from_parts(
                IntakeKeypair::from_parts(vec![1], vec![2]),
                Vec::new(),
                Vec::new(),
            )
            .unwrap_err(),
            IntakeError::EmptyMailboxes
        );
        let many_m = vec![fixtures::sample_mailbox(); crate::protocol::v1::MAILBOX_MAX_COUNT + 1];
        assert_eq!(
            Intake::from_parts(
                IntakeKeypair::from_parts(vec![1], vec![2]),
                many_m,
                Vec::new(),
            )
            .unwrap_err(),
            IntakeError::TooManyMailboxes
        );
        let many_w = vec![fixtures::sample_wire(); crate::protocol::v1::WIRE_MAX_COUNT + 1];
        assert_eq!(
            Intake::from_parts(
                IntakeKeypair::from_parts(vec![1], vec![2]),
                vec![fixtures::sample_mailbox()],
                many_w,
            )
            .unwrap_err(),
            IntakeError::TooManyWires
        );
        assert_ne!(IntakeError::EmptyMailboxes, IntakeError::TooManyWires);
        assert_eq!(
            format!("{}", IntakeError::EmptyMailboxes),
            "intake needs at least one Mailbox"
        );
        assert_eq!(
            format!("{}", IntakeError::TooManyMailboxes),
            "intake has too many Mailboxes"
        );
        assert_eq!(
            format!("{}", IntakeError::TooManyWires),
            "intake has too many Wires"
        );
        let _ = &IntakeError::EmptyMailboxes as &dyn std::error::Error;
        assert_eq!(
            format!("{}", KemError::UnsupportedPolicy(Policy::Hybrid)),
            "unsupported kem policy Hybrid"
        );
        assert_eq!(
            KemError::UnsupportedPolicy(Policy::Classic),
            KemError::UnsupportedPolicy(Policy::Classic)
        );
        assert_ne!(
            KemError::UnsupportedPolicy(Policy::Classic),
            KemError::UnsupportedPolicy(Policy::Hybrid)
        );
        let _ = &KemError::UnsupportedPolicy(Policy::PostQuantum) as &dyn std::error::Error;
        assert_eq!(format!("{}", KemError::KeyGen), "kem key generation failed");
        assert_eq!(KemError::KeyGen, KemError::KeyGen);
        assert_ne!(
            KemError::KeyGen,
            KemError::UnsupportedPolicy(Policy::Classic)
        );
        let _ = &KemError::KeyGen as &dyn std::error::Error;
        assert_eq!(intake_pk_len(Policy::Classic), 32);
        assert_eq!(intake_pk_len(Policy::PostQuantum), 1184);
        assert_eq!(intake_pk_len(Policy::Hybrid), 1216);
        let id_keys = super::IdentityKemKeypair::from_parts(vec![9], vec![8]);
        assert_eq!(id_keys.public_bytes(), &[9]);
        assert_eq!(id_keys.secret_bytes(), &[8]);
        assert_eq!(format!("{id_keys:?}"), "IdentityKemKeypair(..)");
        assert_eq!(id_keys, id_keys.clone());
    }
}
