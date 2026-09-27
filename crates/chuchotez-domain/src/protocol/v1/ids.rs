//! Branded 32-byte identifiers, secrets, and tags.

use crate::protocol::bytes32;

macro_rules! bytes32_type {
    ($name:ident, $debug:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Eq)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Wrap 32 bytes that already have this role.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Raw bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            /// Consume the wrapper.
            #[must_use]
            pub const fn into_bytes(self) -> [u8; 32] {
                self.0
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                bytes32::ct_eq(&self.0, &other.0)
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str($debug)
            }
        }
    };
}

bytes32_type!(UserId, "UserId(..)", "Identifies a user.");
bytes32_type!(
    IdentityId,
    "IdentityId(..)",
    "Identifies an identity under a user."
);
bytes32_type!(
    ConversationId,
    "ConversationId(..)",
    "Identifies a conversation."
);
bytes32_type!(
    DeviceId,
    "DeviceId(..)",
    "Identifies a linked device in a Synchronization."
);
bytes32_type!(Secret, "Secret(..)", "32-byte secret.");
bytes32_type!(Tag, "Tag(..)", "32-byte locator.");
bytes32_type!(
    TagKey,
    "TagKey(..)",
    "32-byte key from which tags are derived with expand."
);

impl From<crate::protocol::Random32> for UserId {
    fn from(value: crate::protocol::Random32) -> Self {
        Self::from_bytes(value.into_bytes())
    }
}

impl From<crate::protocol::Random32> for IdentityId {
    fn from(value: crate::protocol::Random32) -> Self {
        Self::from_bytes(value.into_bytes())
    }
}

impl From<crate::protocol::Random32> for ConversationId {
    fn from(value: crate::protocol::Random32) -> Self {
        Self::from_bytes(value.into_bytes())
    }
}

impl From<crate::protocol::Random32> for DeviceId {
    fn from(value: crate::protocol::Random32) -> Self {
        Self::from_bytes(value.into_bytes())
    }
}

impl From<crate::protocol::Random32> for Secret {
    fn from(value: crate::protocol::Random32) -> Self {
        Self::from_bytes(value.into_bytes())
    }
}

impl From<crate::protocol::Random32> for Tag {
    fn from(value: crate::protocol::Random32) -> Self {
        Self::from_bytes(value.into_bytes())
    }
}

impl From<crate::protocol::Random32> for TagKey {
    fn from(value: crate::protocol::Random32) -> Self {
        Self::from_bytes(value.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::{ConversationId, DeviceId, IdentityId, Secret, Tag, TagKey, UserId};
    use crate::protocol::Random32;

    #[test]
    fn ids_eq_debug() {
        let r = Random32::from_bytes([7; 32]);
        let u = UserId::from(r.clone());
        assert_eq!(u.as_bytes()[0], 7);
        assert_eq!(format!("{u:?}"), "UserId(..)");
        assert_eq!(u, UserId::from_bytes(u.into_bytes()));
        assert_eq!(
            format!("{:?}", IdentityId::from(r.clone())),
            "IdentityId(..)"
        );
        assert_eq!(
            format!("{:?}", ConversationId::from(r.clone())),
            "ConversationId(..)"
        );
        assert_eq!(format!("{:?}", DeviceId::from(r.clone())), "DeviceId(..)");
        assert_eq!(format!("{:?}", Secret::from(r.clone())), "Secret(..)");
        assert_eq!(format!("{:?}", Tag::from(r.clone())), "Tag(..)");
        assert_eq!(format!("{:?}", TagKey::from(r)), "TagKey(..)");
        assert_ne!(UserId::from_bytes([1; 32]), UserId::from_bytes([2; 32]));
    }
}
