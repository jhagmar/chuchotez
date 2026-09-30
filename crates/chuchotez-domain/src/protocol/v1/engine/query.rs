//! Conversation query ADTs, poll locators, and mutation results.

use super::super::{
    Address, ConversationId, IdentityId, Kind, PersistSeq, Policy, Tag, UnixSeconds, UserId,
};
use super::super::{DurableChannel, EphemeralChannel};
use super::state::EngineState;

/// Conversation ids, user ids, identity ids.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConversationRef {
    /// User.
    pub user_id: UserId,
    /// Identity.
    pub identity_id: IdentityId,
    /// Conversation.
    pub conversation_id: ConversationId,
}

/// Successful mutation.
#[derive(Clone, Debug)]
pub struct MutateOk {
    /// Folded state.
    pub state: EngineState,
    pub(super) persist: Vec<Vec<u8>>,
    pub(super) pings: Vec<PingTarget>,
}

impl MutateOk {
    /// Persist records for the host log.
    #[must_use]
    pub fn persist(&self) -> &[Vec<u8>] {
        &self.persist
    }

    /// Wake POST targets.
    #[must_use]
    pub fn pings(&self) -> &[PingTarget] {
        &self.pings
    }
}

/// Web Push target from a peer Wake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PingTarget {
    /// Endpoint.
    pub endpoint: String,
    /// P-256 dh.
    pub p256dh: [u8; 65],
    /// Auth.
    pub auth: [u8; 16],
    /// Optional VAPID pk.
    pub vapid_pk: Option<Vec<u8>>,
}

/// Vault header bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WrapDekOk {
    /// Packed header.
    pub header: Vec<u8>,
}

/// Mapper work for the ticked now.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Poll {
    /// Durable list locators.
    pub list: Vec<DurableLocator>,
    /// Durable listen locators.
    pub listen_durable: Vec<DurableLocator>,
    /// Ephemeral listen locators.
    pub listen_ephemeral: Vec<EphemeralLocator>,
    /// Durable writes.
    pub write_durable: Vec<DurableWrite>,
    /// Ephemeral writes.
    pub write_ephemeral: Vec<EphemeralWrite>,
    /// Blob puts.
    pub blob_put: Vec<BlobPut>,
    /// Blob gets.
    pub blob_get: Vec<BlobGet>,
    /// Identities missing a display name.
    pub blocked: Vec<BlockedIdentity>,
}

/// Durable list/listen locator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableLocator {
    /// Channel.
    pub channel: DurableChannel,
    /// Tag.
    pub tag: Tag,
}

/// Ephemeral listen locator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EphemeralLocator {
    /// Channel.
    pub channel: EphemeralChannel,
    /// Tag.
    pub tag: Tag,
}

/// Durable write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableWrite {
    /// Channel.
    pub channel: DurableChannel,
    /// Tag.
    pub tag: Tag,
    /// 512-byte packet.
    pub body: Vec<u8>,
}

/// Ephemeral write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EphemeralWrite {
    /// Channel.
    pub channel: EphemeralChannel,
    /// Tag.
    pub tag: Tag,
    /// 512-byte packet.
    pub body: Vec<u8>,
}

/// Blob put.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobPut {
    /// Kind.
    pub kind: Kind,
    /// Address.
    pub address: Address,
    /// Tag.
    pub tag: Tag,
    /// Body.
    pub body: Vec<u8>,
}

/// Blob get.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobGet {
    /// Kind.
    pub kind: Kind,
    /// Address.
    pub address: Address,
    /// Tag.
    pub tag: Tag,
}

/// Why `poll.blocked` names an identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockedMissing {
    /// `DisplayName` is required before intro mint.
    DisplayName,
}

/// Identity missing a required display name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockedIdentity {
    /// User.
    pub user_id: UserId,
    /// Identity.
    pub identity_id: IdentityId,
    /// Required field that is absent.
    pub missing: BlockedMissing,
}

/// Query row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationListRow {
    /// Conversation.
    pub conversation_id: ConversationId,
    /// Query ADT for that row.
    pub conversation: Conversation,
}

/// Folded snapshot plus persist seq.
#[derive(Clone, Debug)]
pub struct FoldOk {
    /// Mutated state.
    pub state: EngineState,
    pub(super) persist: Vec<Vec<u8>>,
    pub(super) pings: Vec<PingTarget>,
    /// Sealed snapshot bytes.
    pub snapshot: Vec<u8>,
    /// Persist seq included in the snapshot.
    pub seq: PersistSeq,
}

impl FoldOk {
    /// Persist records for the host log.
    #[must_use]
    pub fn persist(&self) -> &[Vec<u8>] {
        &self.persist
    }

    /// Wake POST targets.
    #[must_use]
    pub fn pings(&self) -> &[PingTarget] {
        &self.pings
    }
}

/// Attachment for `send_media`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaDraft {
    /// Plaintext bytes.
    pub media_bytes: Vec<u8>,
    /// MIME type.
    pub mime: String,
    /// Filename.
    pub filename: String,
}

/// Inviter handshake query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandshakeInviter {
    /// Ticket minted; invite-tag writes still outstanding.
    InviteCreated {
        /// Expiry Unix seconds.
        expires: UnixSeconds,
    },
    /// Invite-tag packet set acked.
    NoticePinned {
        /// Expiry Unix seconds.
        expires: UnixSeconds,
    },
    /// Invitee intro ingested; inviter intro minted.
    IntroductionMinted {
        /// Expiry Unix seconds.
        expires: UnixSeconds,
    },
    /// Intro packet set acked; waiting on confirm.
    Confirming {
        /// Expiry Unix seconds.
        expires: UnixSeconds,
        /// `text(fingerprint)`.
        confirmation_digest: String,
    },
}

/// Invitee handshake query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandshakeInvitee {
    /// Ticket accepted; notice not yet ingested.
    TicketReceived,
    /// Valid notice ingested.
    InviteReceived {
        /// Notice Policy.
        policy: Policy,
        /// Expiry Unix seconds.
        expires: UnixSeconds,
    },
    /// Invitee intro minted.
    IntroductionMinted {
        /// Notice Policy.
        policy: Policy,
        /// Expiry Unix seconds.
        expires: UnixSeconds,
    },
    /// Invitee intro packet set acked.
    IntroductionSent {
        /// Notice Policy.
        policy: Policy,
        /// Expiry Unix seconds.
        expires: UnixSeconds,
    },
    /// Inviter intro ingested; waiting on confirm.
    Confirming {
        /// Notice Policy.
        policy: Policy,
        /// Expiry Unix seconds.
        expires: UnixSeconds,
        /// `text(fingerprint)`.
        confirmation_digest: String,
    },
}

/// Failed conversation query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailedReason {
    /// Notice Policy disagrees with the identity or Sync Policy.
    PolicyNotAccepted {
        /// Notice Policy.
        policy: Policy,
    },
    /// Ticked now is past `expires` pre-confirm.
    InviteExpired {
        /// Expiry Unix seconds.
        expires: UnixSeconds,
    },
    /// Notice `open`, decompress, or parse refused.
    NoticeUnlockFailed,
    /// A second well-formed Notice disagrees with the stored one.
    NoticeConflict,
    /// Intro unlock refused.
    IntroUnlockFailed,
    /// Intro signature verify refused.
    IntroVerifyFailed,
    /// A second valid intro from that role arrived.
    DuplicateIntro,
    /// `rejectEstablished`.
    ConfirmationRejected,
    /// Same `tx_id` with a disagreeing payload.
    Equivocation,
    /// `rejectGroup`.
    OfferRejected,
    /// Roster omitted local `signing_pk`.
    Kicked,
    /// `TxGroupLeave` for self after local delete.
    Left,
}

/// Handshake query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Handshake {
    /// Inviter.
    Inviter(HandshakeInviter),
    /// Invitee.
    Invitee(HandshakeInvitee),
    /// Failed handshake.
    Failed(FailedReason),
}

/// Established or failed DM query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectMessageQuery {
    /// Child DM after both confirms.
    Established,
    /// Failed DM.
    Failed(FailedReason),
}

/// Group query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupQuery {
    /// Incoming group offer on a DM.
    GroupOffer,
    /// Owner or accepted member roster.
    GroupEstablished,
    /// Failed group.
    GroupFailed(FailedReason),
}

/// Synchronization query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SynchronizationQuery {
    /// Sync handshake.
    Handshake(Handshake),
    /// Linked devices.
    SyncEstablished,
    /// Failed Synchronization.
    Failed(FailedReason),
}

/// Query conversation ADT.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Conversation {
    /// DM handshake.
    HandshakeDm(Handshake),
    /// Sync handshake.
    HandshakeSync(Handshake),
    /// Established or failed DM.
    DirectMessage(DirectMessageQuery),
    /// Group.
    Group(GroupQuery),
    /// Synchronization.
    Synchronization(SynchronizationQuery),
}
