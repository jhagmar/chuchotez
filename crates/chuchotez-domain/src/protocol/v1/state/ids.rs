//! Branded 32-byte identifiers for the [`super::EngineState`] tree.

use crate::protocol::v1::SECRET_LEN;
use crate::protocol::{RANDOM32_LEN, Random32};

const fn assert_id_len() {
    const _: () = assert!(SECRET_LEN == RANDOM32_LEN);
}

/// Host-facing account slot. Assigned at create from [`Random32`].
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UserId([u8; SECRET_LEN]);

/// Local identity handle. Assigned at create from [`Random32`].
///
/// A later slice replaces this assignment with the tagged digest of signature
/// public keys.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IdentityId([u8; SECRET_LEN]);

/// Conversation handle. Assigned at create from [`Random32`].
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConversationId([u8; SECRET_LEN]);

macro_rules! impl_id {
    ($name:ident, $label:literal) => {
        impl $name {
            /// Wrap [`SECRET_LEN`] identifier bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; SECRET_LEN]) -> Self {
                assert_id_len();
                Self(bytes)
            }

            /// Identifier bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; SECRET_LEN] {
                &self.0
            }

            pub(crate) fn from_random32(value: Random32) -> Self {
                Self::from_bytes(value.into_bytes())
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str($label)?;
                f.write_str("(")?;
                for byte in &self.0 {
                    write!(f, "{byte:02x}")?;
                }
                f.write_str(")")
            }
        }
    };
}

impl_id!(UserId, "UserId");
impl_id!(IdentityId, "IdentityId");
impl_id!(ConversationId, "ConversationId");

#[cfg(test)]
mod tests {
    use super::{ConversationId, IdentityId, UserId};
    use crate::protocol::v1::SECRET_LEN;

    #[test]
    fn ids_ord_eq_debug() {
        let a = UserId::from_bytes([1; SECRET_LEN]);
        let b = UserId::from_bytes([2; SECRET_LEN]);
        assert_eq!(a, UserId::from_bytes([1; SECRET_LEN]));
        assert_ne!(a, b);
        assert!(a < b);
        assert_eq!(a.as_bytes()[0], 1);
        let debug = format!("{a:?}");
        assert!(debug.starts_with("UserId("));
        assert!(debug.contains("01"));
        let id = IdentityId::from_bytes([3; SECRET_LEN]);
        assert!(format!("{id:?}").starts_with("IdentityId("));
        let cid = ConversationId::from_bytes([4; SECRET_LEN]);
        assert!(format!("{cid:?}").starts_with("ConversationId("));
        assert_eq!(cid, cid);
    }
}
