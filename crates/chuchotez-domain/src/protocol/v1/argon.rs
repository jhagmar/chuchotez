//! Argon2id passphrase stretching port.

/// Failure from [`Argon2id::hash`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Argon2Error {
    /// Parameters or passphrase were refused by the primitive.
    Refused,
}

impl core::fmt::Display for Argon2Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("argon2id refused")
    }
}

impl std::error::Error for Argon2Error {}

/// RFC 9106 Argon2id. Adapters supply the primitive.
pub trait Argon2id {
    /// Stretch `passphrase` with `salt` and parameters `m`, `t`, `p` to 32 bytes.
    fn hash(
        &self,
        passphrase: &[u8],
        salt: &[u8; 16],
        m: u32,
        t: u32,
        p: u32,
    ) -> Result<[u8; 32], Argon2Error>;
}

#[cfg(test)]
mod tests {
    use super::{Argon2Error, Argon2id};

    struct FailingArgon;

    impl Argon2id for FailingArgon {
        fn hash(
            &self,
            _passphrase: &[u8],
            _salt: &[u8; 16],
            _m: u32,
            _t: u32,
            _p: u32,
        ) -> Result<[u8; 32], Argon2Error> {
            Err(Argon2Error::Refused)
        }
    }

    #[test]
    fn argon_error() {
        assert_eq!(
            FailingArgon
                .hash(b"passpass", &[0; 16], 8, 1, 1)
                .unwrap_err(),
            Argon2Error::Refused
        );
        assert_eq!(format!("{}", Argon2Error::Refused), "argon2id refused");
        let _ = &Argon2Error::Refused as &dyn std::error::Error;
    }
}
