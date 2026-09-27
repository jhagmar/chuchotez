//! Argon2id over the `argon2` crate.

use argon2::{Algorithm, Argon2, Params, Version};
use chuchotez_domain::v1::{Argon2Error, Argon2id};

/// RFC 9106 Argon2id.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RustcryptoArgon2id;

impl Argon2id for RustcryptoArgon2id {
    fn hash(
        &self,
        passphrase: &[u8],
        salt: &[u8; 16],
        m: u32,
        t: u32,
        p: u32,
    ) -> Result<[u8; 32], Argon2Error> {
        let params = Params::new(m, t, p, Some(32)).map_err(|_| Argon2Error::Refused)?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; 32];
        argon
            .hash_password_into(passphrase, salt, &mut out)
            .map_err(|_| Argon2Error::Refused)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::RustcryptoArgon2id;
    use chuchotez_domain::v1::{Argon2Error, Argon2id};

    fn fixture_salt() -> [u8; 16] {
        core::array::from_fn(|i| i as u8)
    }

    #[test]
    fn argon2id_roundtrip_params() {
        let port = RustcryptoArgon2id;
        let salt = fixture_salt();
        let a = port.hash(b"passpass", &salt, 8, 1, 1).expect("ok");
        let b = port.hash(b"passpass", &salt, 8, 1, 1).expect("ok2");
        assert_eq!(a, b);
        assert_eq!(
            port.hash(b"passpass", &salt, 0, 1, 1).unwrap_err(),
            Argon2Error::Refused
        );
        assert_eq!(port, RustcryptoArgon2id);
        assert_eq!(format!("{port:?}"), "RustcryptoArgon2id");
    }
}
