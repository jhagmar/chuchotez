//! HMAC-SHA-256 port and one-block HKDF-Expand (RFC 5869 `T(1)`).

use super::super::bytes32;

/// SHA-256 digest length, and therefore HMAC-SHA-256 output length.
pub const DIGEST_LEN: usize = 32;

/// HMAC-SHA-256 / SHA-256 output as an array. Distinct roles wrap this in a newtype.
pub type DigestBytes = [u8; DIGEST_LEN];

/// HKDF-Expand `L` when the derived secret is one SHA-256 block.
pub(crate) const EXPAND_LEN: usize = DIGEST_LEN;

/// RFC 5869 `T(1)` counter appended to `info` for the first Expand block.
pub(crate) const EXPAND_T1_COUNTER: u8 = 0x01;

const _: () = assert!(EXPAND_LEN == DIGEST_LEN);

/// HMAC-SHA-256 key.
#[derive(Clone, Eq)]
pub struct HmacSha256Key(DigestBytes);

impl HmacSha256Key {
    /// Wrap bytes that already have the HMAC-SHA-256 key role.
    #[must_use]
    pub const fn from_bytes(bytes: DigestBytes) -> Self {
        Self(bytes)
    }

    /// Key bytes for an HMAC adapter.
    #[must_use]
    pub const fn as_bytes(&self) -> &DigestBytes {
        &self.0
    }

    /// Consume the wrapper and return the array.
    #[must_use]
    pub const fn into_bytes(self) -> DigestBytes {
        self.0
    }
}

impl PartialEq for HmacSha256Key {
    fn eq(&self, other: &Self) -> bool {
        bytes32::ct_eq(&self.0, &other.0)
    }
}

impl core::fmt::Debug for HmacSha256Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HmacSha256Key(..)")
    }
}

/// HMAC-SHA-256 output (one SHA-256 block).
#[derive(Clone, Eq)]
pub struct HmacSha256Mac(DigestBytes);

impl HmacSha256Mac {
    /// Wrap bytes that already have the HMAC-SHA-256 output role.
    #[must_use]
    pub const fn from_bytes(bytes: DigestBytes) -> Self {
        Self(bytes)
    }

    /// MAC bytes for an adapter or a protocol constructor.
    #[must_use]
    pub const fn as_bytes(&self) -> &DigestBytes {
        &self.0
    }

    /// Consume the wrapper and return the array.
    #[must_use]
    pub const fn into_bytes(self) -> DigestBytes {
        self.0
    }
}

impl PartialEq for HmacSha256Mac {
    fn eq(&self, other: &Self) -> bool {
        bytes32::ct_eq(&self.0, &other.0)
    }
}

impl core::fmt::Debug for HmacSha256Mac {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HmacSha256Mac(..)")
    }
}

/// HMAC-SHA-256. Adapters supply the primitive; tests inject a fake.
pub trait HmacSha256 {
    /// `HMAC-SHA-256(key, data)`.
    fn mac(&self, key: &HmacSha256Key, data: &[u8]) -> HmacSha256Mac;
}

/// HKDF-Expand with `L = `[`EXPAND_LEN`].
pub(super) fn expand<H: HmacSha256 + ?Sized>(
    hmac: &H,
    key: &HmacSha256Key,
    info: &[u8],
) -> HmacSha256Mac {
    let mut data = Vec::with_capacity(info.len() + core::mem::size_of_val(&EXPAND_T1_COUNTER));
    data.extend_from_slice(info);
    data.push(EXPAND_T1_COUNTER);
    hmac.mac(key, &data)
}

#[cfg(test)]
mod tests {
    use super::{
        DIGEST_LEN, EXPAND_LEN, EXPAND_T1_COUNTER, HmacSha256, HmacSha256Key, HmacSha256Mac, expand,
    };
    use std::cell::RefCell;

    fn fill(byte: u8) -> [u8; DIGEST_LEN] {
        [byte; DIGEST_LEN]
    }

    struct RecordingHmac {
        data: RefCell<Vec<u8>>,
        out: HmacSha256Mac,
    }

    impl HmacSha256 for RecordingHmac {
        fn mac(&self, _key: &HmacSha256Key, data: &[u8]) -> HmacSha256Mac {
            self.data.replace(data.to_vec());
            self.out.clone()
        }
    }

    #[test]
    fn expand_appends_hkdf_counter() {
        let hmac = RecordingHmac {
            data: RefCell::new(Vec::new()),
            out: HmacSha256Mac::from_bytes(fill(0x42)),
        };
        let info = b"chuchotez/1/invite-tag";
        let key = HmacSha256Key::from_bytes(fill(0x11));
        let out = expand(&hmac, &key, info);
        assert_eq!(out, HmacSha256Mac::from_bytes(fill(0x42)));
        assert_eq!(out.as_bytes(), &fill(0x42));
        assert_eq!(out.as_bytes().len(), EXPAND_LEN);
        let recorded = hmac.data.borrow();
        assert_eq!(&recorded[..info.len()], info.as_slice());
        assert_eq!(*recorded.last().expect("counter byte"), EXPAND_T1_COUNTER);
        assert_eq!(
            recorded.len(),
            info.len() + core::mem::size_of_val(&EXPAND_T1_COUNTER)
        );
    }

    #[test]
    fn key_and_mac_eq_debug_and_bytes() {
        let key_a = HmacSha256Key::from_bytes(fill(0xab));
        let key_b = HmacSha256Key::from_bytes(fill(0xab));
        let key_c = HmacSha256Key::from_bytes(fill(0xcd));
        assert_eq!(key_a, key_b);
        assert_ne!(key_a, key_c);
        assert_eq!(key_a.as_bytes(), &fill(0xab));
        assert_eq!(key_a.clone().into_bytes(), fill(0xab));
        assert_eq!(format!("{key_a:?}"), "HmacSha256Key(..)");
        assert!(!format!("{key_a:?}").contains("ab"));

        let mac_a = HmacSha256Mac::from_bytes(fill(0x11));
        let mac_b = HmacSha256Mac::from_bytes(fill(0x11));
        let mac_c = HmacSha256Mac::from_bytes(fill(0x22));
        assert_eq!(mac_a, mac_b);
        assert_ne!(mac_a, mac_c);
        assert_eq!(mac_a.as_bytes(), &fill(0x11));
        assert_eq!(mac_a.clone().into_bytes(), fill(0x11));
        assert_eq!(format!("{mac_a:?}"), "HmacSha256Mac(..)");
        assert!(!format!("{mac_a:?}").contains("11"));
    }
}
