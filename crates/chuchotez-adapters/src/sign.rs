//! Identity signatures over `libcrux-ed25519` and `libcrux-ml-dsa`.

use chuchotez_domain::Policy;
use chuchotez_domain::Random32;
use chuchotez_domain::v1::{Sign, SignError, SignSeed, SigningKeyPair};
use libcrux_ml_dsa::ml_dsa_65;
use libcrux_ml_dsa::{MLDSASignature, MLDSASigningKey, MLDSAVerificationKey};

/// libcrux identity signatures: Ed25519, ML-DSA-65, and both concatenated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LibcruxSign;

const SEED_32: usize = 32;
const CLASSIC_SIG: usize = 64;
const PQ_SIG: usize = 3309;
const PQ_SK: usize = 4032;
const PQ_PK: usize = 1952;

fn classic_from_seed(seed32: &[u8; SEED_32]) -> SigningKeyPair {
    let mut public = [0u8; SEED_32];
    libcrux_ed25519::secret_to_public(&mut public, seed32);
    SigningKeyPair::from_parts(public.to_vec(), seed32.to_vec())
}

fn pq_from_seed(seed32: [u8; SEED_32]) -> SigningKeyPair {
    let pair = ml_dsa_65::generate_key_pair(seed32);
    SigningKeyPair::from_parts(
        pair.verification_key.as_ref().to_vec(),
        pair.signing_key.as_ref().to_vec(),
    )
}

impl Sign for LibcruxSign {
    fn generate(&self, policy: Policy, seed: &SignSeed) -> Result<SigningKeyPair, SignError> {
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
                Ok(SigningKeyPair::from_parts(public, secret))
            }
        }
    }

    fn sign(
        &self,
        policy: Policy,
        sk: &[u8],
        message: &[u8],
        seed: &Random32,
    ) -> Result<Vec<u8>, SignError> {
        match policy {
            Policy::Classic => {
                let sk: &[u8; 32] = sk.try_into().map_err(|_| SignError::Sign)?;
                Ok(libcrux_ed25519::sign(message, sk)
                    .map_err(|_| SignError::Sign)?
                    .to_vec())
            }
            Policy::PostQuantum => {
                let arr: [u8; PQ_SK] = sk.try_into().map_err(|_| SignError::Sign)?;
                let key = MLDSASigningKey::new(arr);
                let sig = ml_dsa_65::sign(&key, message, b"", *seed.as_bytes())
                    .map_err(|_| SignError::Sign)?;
                Ok(sig.as_ref().to_vec())
            }
            Policy::Hybrid => {
                if sk.len() != 32 + PQ_SK {
                    return Err(SignError::Sign);
                }
                let mut classic = self.sign(Policy::Classic, &sk[..32], message, seed)?;
                let pq = self.sign(Policy::PostQuantum, &sk[32..], message, seed)?;
                classic.extend_from_slice(&pq);
                Ok(classic)
            }
        }
    }

    fn verify(
        &self,
        policy: Policy,
        pk: &[u8],
        message: &[u8],
        sig: &[u8],
    ) -> Result<(), SignError> {
        match policy {
            Policy::Classic => {
                let pk: &[u8; 32] = pk.try_into().map_err(|_| SignError::Sign)?;
                let sig: &[u8; CLASSIC_SIG] = sig.try_into().map_err(|_| SignError::Sign)?;
                libcrux_ed25519::verify(message, pk, sig).map_err(|_| SignError::Sign)
            }
            Policy::PostQuantum => {
                let pk_arr: [u8; PQ_PK] = pk.try_into().map_err(|_| SignError::Sign)?;
                let sig_arr: [u8; PQ_SIG] = sig.try_into().map_err(|_| SignError::Sign)?;
                ml_dsa_65::verify(
                    &MLDSAVerificationKey::new(pk_arr),
                    message,
                    b"",
                    &MLDSASignature::new(sig_arr),
                )
                .map_err(|_| SignError::Sign)
            }
            Policy::Hybrid => {
                if pk.len() != 32 + PQ_PK || sig.len() != CLASSIC_SIG + PQ_SIG {
                    return Err(SignError::Sign);
                }
                self.verify(Policy::Classic, &pk[..32], message, &sig[..CLASSIC_SIG])?;
                self.verify(Policy::PostQuantum, &pk[32..], message, &sig[CLASSIC_SIG..])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::LibcruxSign;
    use chuchotez_domain::Policy;
    use chuchotez_domain::Random32;
    use chuchotez_domain::v1::{SIGN_SEED_LEN, Sign, SignSeed, sign_pk_len};

    #[test]
    fn sign_verify_every_policy() {
        let port = LibcruxSign;
        let seed = SignSeed::from_bytes([5; SIGN_SEED_LEN]);
        let rng = Random32::from_bytes([7; 32]);
        for policy in [Policy::Classic, Policy::PostQuantum, Policy::Hybrid] {
            let keys = port.generate(policy, &seed).expect("gen");
            assert_eq!(keys.public_bytes().len(), sign_pk_len(policy));
            let sig = port
                .sign(policy, keys.secret_bytes(), b"msg", &rng)
                .expect("sign");
            port.verify(policy, keys.public_bytes(), b"msg", &sig)
                .expect("ok");
            assert!(
                port.verify(policy, keys.public_bytes(), b"no", &sig)
                    .is_err()
            );
        }
        assert_eq!(
            port.sign(Policy::Hybrid, &[], b"m", &rng).unwrap_err(),
            chuchotez_domain::v1::SignError::Sign
        );
        assert!(port.verify(Policy::Hybrid, &[], b"m", &[]).is_err());
        assert_eq!(port, LibcruxSign);
        assert_eq!(format!("{port:?}"), "LibcruxSign");
    }
}
