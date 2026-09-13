//! AES-256-GCM over `libcrux-aes`.

use chuchotez_domain::v1::{Aead, AeadError, AeadKey, AeadNonce};
use libcrux_aes::{AesGcm256Key, AesGcm256Nonce, AesGcm256Tag, TAG_LEN};

/// AES-256-GCM.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AesGcm;

impl Aead for AesGcm {
    fn seal(&self, key: &AeadKey, nonce: &AeadNonce, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let key: AesGcm256Key = (*key.as_bytes()).into();
        let nonce: AesGcm256Nonce = (*nonce.as_bytes()).into();
        let mut tag: AesGcm256Tag = [0; TAG_LEN].into();
        let mut ct = vec![0; plaintext.len()];
        key.encrypt(&mut ct, &mut tag, &nonce, aad, plaintext)
            .expect("aes-256-gcm seal honors the port");
        ct.extend_from_slice(tag.as_ref());
        ct
    }

    fn open(
        &self,
        key: &AeadKey,
        nonce: &AeadNonce,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        if ciphertext.len() < TAG_LEN {
            return Err(AeadError::Open);
        }
        let (ct, tag_bytes) = ciphertext.split_at(ciphertext.len() - TAG_LEN);
        let tag_arr: [u8; TAG_LEN] = tag_bytes.try_into().map_err(|_| AeadError::Open)?;
        let key: AesGcm256Key = (*key.as_bytes()).into();
        let nonce: AesGcm256Nonce = (*nonce.as_bytes()).into();
        let tag: AesGcm256Tag = tag_arr.into();
        let mut pt = vec![0; ct.len()];
        key.decrypt(&mut pt, &nonce, aad, ct, &tag)
            .map_err(|_| AeadError::Open)?;
        Ok(pt)
    }
}

#[cfg(test)]
mod tests {
    use super::AesGcm;
    use chuchotez_domain::v1::{Aead, AeadError, AeadKey, AeadNonce};

    #[test]
    fn aes_gcm_roundtrip_and_aad() {
        let port = AesGcm;
        let key = AeadKey::from_bytes([7u8; 32]);
        let nonce = AeadNonce::from_bytes(core::array::from_fn(|i| 9u8.wrapping_add(i as u8)));
        let pt = b"notice-body";
        let aad = [0xC1, 0x01];
        let ct = port.seal(&key, &nonce, &aad, pt);
        assert_eq!(port.open(&key, &nonce, &aad, &ct).expect("open"), pt);
        assert_eq!(
            port.open(&key, &nonce, &[0xC1, 0x02], &ct).unwrap_err(),
            AeadError::Open
        );
        assert_eq!(port, AesGcm);
        assert_eq!(format!("{port:?}"), "AesGcm");
        assert_eq!(
            port.open(&key, &nonce, &aad, &[0u8; 8]).unwrap_err(),
            AeadError::Open
        );
    }
}
