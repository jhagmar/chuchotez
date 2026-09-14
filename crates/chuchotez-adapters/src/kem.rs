//! Intake generator over `libcrux-kem`.

use chuchotez_domain::Policy;
use chuchotez_domain::v1::{IntakeKeypair, Kem, KemError, KemSeed};
use libcrux_kem::{Algorithm, key_gen_derand};

/// libcrux Intake KEM: X25519, ML-KEM-768, and X-Wing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LibcruxKem;

/// X25519 and X-Wing `key_gen_derand` seed length.
const SEED_32: usize = 32;

fn pair_from_seed(alg: Algorithm, seed: &[u8]) -> Result<IntakeKeypair, KemError> {
    let (sk, pk) = key_gen_derand(alg, seed).map_err(|_| KemError::KeyGen)?;
    Ok(IntakeKeypair::from_parts(pk.encode(), sk.encode()))
}

impl Kem for LibcruxKem {
    fn generate(&self, policy: Policy, seed: &KemSeed) -> Result<IntakeKeypair, KemError> {
        let bytes = seed.as_bytes();
        match policy {
            Policy::Classic => pair_from_seed(Algorithm::X25519, &bytes[..SEED_32]),
            Policy::PostQuantum => pair_from_seed(Algorithm::MlKem768, bytes),
            Policy::Hybrid => pair_from_seed(Algorithm::XWingKemDraft06, &bytes[..SEED_32]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{LibcruxKem, pair_from_seed};
    use chuchotez_domain::Policy;
    use chuchotez_domain::v1::{KEM_SEED_LEN, Kem, KemError, KemSeed};
    use libcrux_kem::Algorithm;

    #[test]
    fn generates_every_policy() {
        let port = LibcruxKem;
        let seed = KemSeed::from_bytes([3; KEM_SEED_LEN]);
        let classic = port.generate(Policy::Classic, &seed).expect("classic");
        assert_eq!(classic.public_bytes().len(), 32);
        assert_eq!(classic.secret_bytes().len(), 32);
        let pq = port.generate(Policy::PostQuantum, &seed).expect("pq");
        assert_eq!(pq.public_bytes().len(), 1184);
        assert_eq!(pq.secret_bytes().len(), 2400);
        let hybrid = port.generate(Policy::Hybrid, &seed).expect("hybrid");
        assert_eq!(hybrid.public_bytes().len(), 1216);
        assert_eq!(hybrid.secret_bytes().len(), 32);
        assert_eq!(port, LibcruxKem);
        assert_eq!(format!("{port:?}"), "LibcruxKem");
        assert_eq!(
            pair_from_seed(Algorithm::X25519, &[]).unwrap_err(),
            KemError::KeyGen
        );
        assert_eq!(
            pair_from_seed(Algorithm::MlKem768, &[0; 8]).unwrap_err(),
            KemError::KeyGen
        );
        assert_eq!(
            pair_from_seed(Algorithm::XWingKemDraft06, &[]).unwrap_err(),
            KemError::KeyGen
        );
    }
}
