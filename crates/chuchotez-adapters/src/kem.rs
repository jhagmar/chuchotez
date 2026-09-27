//! KEM generator and wrap over `libcrux-kem`.

use chuchotez_domain::Policy;
use chuchotez_domain::v1::{Kem, KemError, KemSeed, KeyPair};
use libcrux_kem::{Algorithm, Ct, PrivateKey, PublicKey, key_gen_derand};

/// libcrux KEM: X25519, ML-KEM-768, and X-Wing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LibcruxKem;

const SEED_32: usize = 32;

fn alg(policy: Policy) -> Algorithm {
    match policy {
        Policy::Classic => Algorithm::X25519,
        Policy::PostQuantum => Algorithm::MlKem768,
        Policy::Hybrid => Algorithm::XWingKemDraft06,
    }
}

fn wrap_seed(policy: Policy, seed: &KemSeed) -> &[u8] {
    let bytes = seed.as_bytes();
    match policy {
        Policy::Classic => &bytes[..SEED_32],
        Policy::PostQuantum => &bytes[..SEED_32],
        Policy::Hybrid => bytes.as_slice(),
    }
}

impl Kem for LibcruxKem {
    fn generate(&self, policy: Policy, seed: &KemSeed) -> Result<KeyPair, KemError> {
        let bytes = seed.as_bytes();
        let slice = match policy {
            Policy::Classic | Policy::Hybrid => &bytes[..SEED_32],
            Policy::PostQuantum => bytes.as_slice(),
        };
        let (sk, pk) = key_gen_derand(alg(policy), slice).map_err(|_| KemError::KeyGen)?;
        Ok(KeyPair::from_parts(pk.encode(), sk.encode()))
    }

    fn wrap(
        &self,
        policy: Policy,
        pk: &[u8],
        seed: &KemSeed,
    ) -> Result<(Vec<u8>, Vec<u8>), KemError> {
        let public = PublicKey::decode(alg(policy), pk).map_err(|_| KemError::Wrap)?;
        let (ss, ct) = public
            .encapsulate_derand(wrap_seed(policy, seed))
            .map_err(|_| KemError::Wrap)?;
        Ok((ss.encode(), ct.encode()))
    }

    fn unwrap(&self, policy: Policy, sk: &[u8], kem_ct: &[u8]) -> Result<Vec<u8>, KemError> {
        let secret = PrivateKey::decode(alg(policy), sk).map_err(|_| KemError::Wrap)?;
        let ct = Ct::decode(alg(policy), kem_ct).map_err(|_| KemError::Wrap)?;
        Ok(ct
            .decapsulate(&secret)
            .map_err(|_| KemError::Wrap)?
            .encode())
    }
}

#[cfg(test)]
mod tests {
    use super::LibcruxKem;
    use chuchotez_domain::Policy;
    use chuchotez_domain::v1::{KEM_SEED_LEN, Kem, KemSeed, kem_ct_len, kem_pk_len};

    #[test]
    fn wrap_roundtrip_every_policy() {
        let port = LibcruxKem;
        let seed = KemSeed::from_bytes([3; KEM_SEED_LEN]);
        let wrap_seed = KemSeed::from_bytes([9; KEM_SEED_LEN]);
        for policy in [Policy::Classic, Policy::PostQuantum, Policy::Hybrid] {
            let keys = port.generate(policy, &seed).expect("gen");
            assert_eq!(keys.public_bytes().len(), kem_pk_len(policy));
            let (ss, ct) = port
                .wrap(policy, keys.public_bytes(), &wrap_seed)
                .expect("wrap");
            assert_eq!(ct.len(), kem_ct_len(policy));
            let opened = port
                .unwrap(policy, keys.secret_bytes(), &ct)
                .expect("unwrap");
            assert_eq!(opened, ss);
        }
        assert_eq!(port, LibcruxKem);
        assert_eq!(format!("{port:?}"), "LibcruxKem");
        assert!(port.wrap(Policy::Classic, &[], &seed).is_err());
    }
}
