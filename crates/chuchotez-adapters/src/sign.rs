//! Identity signing adapter over `libcrux-ed25519` and `libcrux-ml-dsa`.

use chuchotez_domain::Policy;
use chuchotez_domain::v1::{IdentitySignKeypair, Sign, SignError, SignSeed};
use libcrux_ml_dsa::ml_dsa_65;

/// libcrux identity signatures: Ed25519, ML-DSA-65, and both concatenated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LibcruxSign;

const SEED_32: usize = 32;

fn classic_from_seed(seed32: &[u8; SEED_32]) -> IdentitySignKeypair {
    let mut public = [0u8; SEED_32];
    libcrux_ed25519::secret_to_public(&mut public, seed32);
    IdentitySignKeypair::from_parts(public.to_vec(), seed32.to_vec())
}

fn pq_from_seed(seed32: [u8; SEED_32]) -> IdentitySignKeypair {
    let pair = ml_dsa_65::generate_key_pair(seed32);
    IdentitySignKeypair::from_parts(
        pair.verification_key.as_ref().to_vec(),
        pair.signing_key.as_ref().to_vec(),
    )
}

impl Sign for LibcruxSign {
    fn generate(&self, policy: Policy, seed: &SignSeed) -> Result<IdentitySignKeypair, SignError> {
        let bytes = seed.as_bytes();
        let mut first = [0u8; SEED_32];
        first.copy_from_slice(&bytes[..SEED_32]);
        match policy {
            Policy::Classic => Ok(classic_from_seed(&first)),
            Policy::PostQuantum => Ok(pq_from_seed(first)),
            Policy::Hybrid => {
                let mut second = [0u8; SEED_32];
                second.copy_from_slice(&bytes[SEED_32..]);
                let classic = classic_from_seed(&first);
                let pq = pq_from_seed(second);
                let mut public = classic.public_bytes().to_vec();
                public.extend_from_slice(pq.public_bytes());
                let mut secret = classic.secret_bytes().to_vec();
                secret.extend_from_slice(pq.secret_bytes());
                Ok(IdentitySignKeypair::from_parts(public, secret))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::LibcruxSign;
    use chuchotez_domain::Policy;
    use chuchotez_domain::v1::{SIGN_SEED_LEN, Sign, SignSeed, sign_pk_len};

    #[test]
    fn generates_every_policy() {
        let port = LibcruxSign;
        let seed = SignSeed::from_bytes([5; SIGN_SEED_LEN]);
        let classic = port.generate(Policy::Classic, &seed).expect("classic");
        assert_eq!(classic.public_bytes().len(), sign_pk_len(Policy::Classic));
        assert_eq!(classic.secret_bytes().len(), 32);
        let pq = port.generate(Policy::PostQuantum, &seed).expect("pq");
        assert_eq!(pq.public_bytes().len(), sign_pk_len(Policy::PostQuantum));
        let hybrid = port.generate(Policy::Hybrid, &seed).expect("hybrid");
        assert_eq!(hybrid.public_bytes().len(), sign_pk_len(Policy::Hybrid));
        assert_eq!(
            hybrid.secret_bytes().len(),
            classic.secret_bytes().len() + pq.secret_bytes().len()
        );
        assert_eq!(port, LibcruxSign);
        assert_eq!(format!("{port:?}"), "LibcruxSign");
    }
}
