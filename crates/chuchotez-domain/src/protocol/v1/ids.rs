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

        impl PartialOrd for $name {
            fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        impl Ord for $name {
            fn cmp(&self, other: &Self) -> core::cmp::Ordering {
                self.0.cmp(&other.0)
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

macro_rules! u64_type {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub struct $name(u64);

        impl $name {
            /// Wrap a value that already has this role.
            #[must_use]
            pub const fn from_u64(n: u64) -> Self {
                Self(n)
            }

            /// Raw integer.
            #[must_use]
            pub const fn as_u64(self) -> u64 {
                self.0
            }

            /// Saturating add of a raw count.
            #[must_use]
            pub const fn saturating_add(self, n: u64) -> Self {
                Self(self.0.saturating_add(n))
            }

            /// Saturating subtract of a raw count.
            #[must_use]
            pub const fn saturating_sub(self, n: u64) -> Self {
                Self(self.0.saturating_sub(n))
            }
        }
    };
}

u64_type!(UnixSeconds, "Unix time in seconds.");
u64_type!(TimeBin, "Hour index of Unix time.");
u64_type!(PersistSeq, "Persist-record sequence number.");
u64_type!(PacketSeq, "Packet sequence on a sending chain.");
u64_type!(PacketEpoch, "Sending-chain epoch.");
u64_type!(FragIndex, "Fragment index within a packet transaction.");

/// Actor bytes on a conversation: empty on handshake, signing public key or
/// device id on Established sorts.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct ActorId(Vec<u8>);

impl ActorId {
    /// Wrap actor bytes that already have this role.
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Handshake sending-chain actor (empty `actor_id`).
    #[must_use]
    pub const fn handshake() -> Self {
        Self(Vec::new())
    }

    /// Raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for ActorId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ActorId(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ActorId, ConversationId, DeviceId, FragIndex, IdentityId, PacketEpoch, PacketSeq,
        PersistSeq, Secret, Tag, TagKey, TimeBin, UnixSeconds, UserId,
    };
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
        assert!(UserId::from_bytes([1; 32]) < UserId::from_bytes([2; 32]));
        assert_eq!(UnixSeconds::from_u64(3).as_u64(), 3);
        assert_eq!(UnixSeconds::from_u64(3).saturating_add(1).as_u64(), 4);
        assert_eq!(UnixSeconds::from_u64(0).saturating_sub(1).as_u64(), 0);
        assert_eq!(TimeBin::from_u64(4).saturating_add(1).as_u64(), 5);
        assert_eq!(TimeBin::from_u64(0).saturating_sub(1).as_u64(), 0);
        assert_eq!(PersistSeq::from_u64(1).saturating_add(1).as_u64(), 2);
        assert_eq!(PersistSeq::from_u64(1).saturating_sub(1).as_u64(), 0);
        assert_eq!(PacketSeq::from_u64(2).saturating_add(1).as_u64(), 3);
        assert_eq!(PacketSeq::from_u64(2).saturating_sub(1).as_u64(), 1);
        assert_eq!(PacketEpoch::from_u64(0).as_u64(), 0);
        assert_eq!(PacketEpoch::from_u64(1).saturating_add(1).as_u64(), 2);
        assert_eq!(PacketEpoch::from_u64(1).saturating_sub(1).as_u64(), 0);
        assert_eq!(FragIndex::from_u64(7).as_u64(), 7);
        assert_eq!(FragIndex::from_u64(7).saturating_add(1).as_u64(), 8);
        assert_eq!(FragIndex::from_u64(7).saturating_sub(1).as_u64(), 6);
        let actor = ActorId::from_bytes([1, 2]);
        assert_eq!(actor.as_bytes(), &[1, 2]);
        assert_eq!(format!("{actor:?}"), "ActorId(..)");
        assert_eq!(ActorId::handshake().as_bytes().len(), 0);
        assert!(ActorId::handshake() < actor);
    }
}
