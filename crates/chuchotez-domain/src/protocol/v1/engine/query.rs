//! Conversation query ADTs, poll locators, and mutation results.

use super::super::payload::Hlc;
use super::super::{
    Address, ConversationId, DisplayName, IdentityId, Kind, PersistSeq, Policy, Tag, UnixSeconds,
    UserId,
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
#[derive(Clone, Eq, PartialEq)]
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

impl core::fmt::Debug for PingTarget {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PingTarget")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
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
    /// Blob mapper kind.
    pub kind: Kind,
    /// Blob mapper address.
    pub address: Address,
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
}

/// Terminal group row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupEnd {
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

/// Chat row in query `messages`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChatItem {
    /// Text.
    Text(super::super::payload::TxText),
    /// Edit.
    Edit(super::super::payload::TxEdit),
    /// Remove.
    Remove {
        /// Target tx id.
        target: Tag,
    },
    /// Reaction.
    Reaction(super::super::payload::TxReaction),
    /// Read up to.
    Read {
        /// Target tx id.
        up_to: Tag,
    },
    /// Delivered up to.
    Delivered {
        /// Target tx id.
        up_to: Tag,
    },
    /// Media pointer.
    Media(super::super::payload::TxMedia),
}

/// One durable row in query `messages`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryItem {
    /// Transaction id.
    pub tx_id: Tag,
    /// Sender signing key, or device id.
    pub sender: super::super::Actor,
    /// Presentation timestamp.
    pub hlc: Hlc,
    /// Chat record.
    pub item: ChatItem,
    /// Disappear time, or never.
    pub expire_at: Option<UnixSeconds>,
}

/// Composing signal on an established DM.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypingView {
    /// Whether the peer is composing.
    pub composing: bool,
    /// Time the signal is measured from.
    pub last_active: UnixSeconds,
}

/// Liveness signal on an established DM.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PresenceView {
    /// Time of the latest presence packet.
    pub last_active: UnixSeconds,
}

/// Established DM query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DmEstablished {
    /// Peer display name.
    pub name: DisplayName,
    /// Peer profile picture.
    pub profile_pic: Option<super::super::ProfilePic>,
    /// Peer encryption public key.
    pub encryption_pk: super::super::EncryptionPublicKey,
    /// Peer signing public key.
    pub signing_pk: super::super::SigningPublicKey,
    /// Persistent channels.
    pub persistents: Vec<super::super::DurableChannel>,
    /// Ephemeral channels.
    pub ephemerals: Vec<super::super::EphemeralChannel>,
    /// `text(fingerprint)`.
    pub confirmation_digest: String,
    /// Latest presence time.
    pub last_active: Option<UnixSeconds>,
    /// Peer composing signal.
    pub typing: Option<TypingView>,
    /// Peer liveness signal.
    pub presence: Option<PresenceView>,
    /// Latest read marker.
    pub read_up_to: Option<Tag>,
    /// Latest delivered marker.
    pub delivered_up_to: Option<Tag>,
    /// This member's prefs. Wake key material is omitted.
    pub local_prefs: QueryLocalPrefs,
    /// Peer prefs. Wake key material is omitted.
    pub peer_prefs: QueryPeerPrefs,
    /// Most recent durable chat items.
    pub messages: Vec<HistoryItem>,
}

/// Peer prefs shown by query. `p256dh` and `auth` stay off this view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryPeerPrefs {
    /// Read receipts.
    pub read_receipts: bool,
    /// Online visible.
    pub online_visible: bool,
    /// Send typing.
    pub send_typing: bool,
    /// Disappear after seconds, or never.
    pub disappear_after: Option<u64>,
    /// Wake endpoint, or unpublished.
    pub wake_endpoint: Option<String>,
    /// VAPID public key, or unpublished.
    pub vapid_pk: Option<Vec<u8>>,
}

/// Local prefs shown by query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryLocalPrefs {
    /// Read receipts.
    pub read_receipts: bool,
    /// Online visible.
    pub online_visible: bool,
    /// Send typing.
    pub send_typing: bool,
    /// Disappear after seconds, or never.
    pub disappear_after: Option<u64>,
    /// Wake endpoint, or unpublished.
    pub wake_endpoint: Option<String>,
    /// VAPID public key, or unpublished.
    pub vapid_pk: Option<Vec<u8>>,
    /// Notification privacy. Local only.
    pub notification_privacy: super::super::NotificationPrivacy,
}

/// RFC 8291 target. `body` is empty plaintext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PingPost {
    /// `https:` endpoint.
    pub endpoint: String,
    /// Empty plaintext body.
    pub body: Vec<u8>,
}

/// Empty-body POST targets for `https:` ping rows.
#[must_use]
pub fn ping_posts(pings: &[PingTarget]) -> Vec<PingPost> {
    pings
        .iter()
        .filter(|ping| ping.endpoint.starts_with("https:"))
        .map(|ping| PingPost {
            endpoint: ping.endpoint.clone(),
            body: Vec::new(),
        })
        .collect()
}

/// Group query.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GroupQuery {
    /// Incoming group offer on a DM.
    GroupOffer(GroupOfferView),
    /// Owner or accepted member roster.
    GroupEstablished(GroupEstablishedView),
    /// Failed group.
    GroupFailed(GroupEnd),
}

/// Incoming group offer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupOfferView {
    /// Group name.
    pub name: DisplayName,
    /// Group photo.
    pub photo: Option<super::super::ProfilePic>,
    /// Owner signing public key.
    pub owner_signing_pk: super::super::SigningPublicKey,
    /// DM the offer arrived on.
    pub from_conversation_id: ConversationId,
}

/// Accepted member shown in the group query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupMemberView {
    /// Signing public key.
    pub signing_pk: super::super::SigningPublicKey,
    /// Encryption public key.
    pub encryption_pk: super::super::EncryptionPublicKey,
    /// Display name carried with the member.
    pub name: DisplayName,
    /// Photo carried with the member.
    pub photo: Option<super::super::ProfilePic>,
    /// Composing signal for this member.
    pub typing: Option<TypingView>,
    /// Liveness signal for this member.
    pub presence: Option<PresenceView>,
}

/// Invite that is not yet accepted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupPendingView {
    /// Invitee signing public key.
    pub signing_pk: super::super::SigningPublicKey,
    /// DM the invite was posted on.
    pub from_conversation_id: ConversationId,
    /// Name on the invite.
    pub name: DisplayName,
    /// Photo on the invite.
    pub photo: Option<super::super::ProfilePic>,
}

/// Established group query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupEstablishedView {
    /// Group name.
    pub name: DisplayName,
    /// Group photo.
    pub photo: Option<super::super::ProfilePic>,
    /// Owner signing public key.
    pub owner_signing_pk: super::super::SigningPublicKey,
    /// Accepted members.
    pub members: Vec<GroupMemberView>,
    /// Outstanding invites.
    pub pending: Vec<GroupPendingView>,
    /// Persistent channels.
    pub persistents: Vec<super::super::DurableChannel>,
    /// Ephemeral channels.
    pub ephemerals: Vec<super::super::EphemeralChannel>,
    /// Latest presence time.
    pub last_active: Option<UnixSeconds>,
    /// This member's prefs. Wake key material is omitted.
    pub local_prefs: QueryLocalPrefs,
    /// Chat history.
    pub messages: Vec<HistoryItem>,
}

/// One linked device in the sync query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncMemberView {
    /// Device id.
    pub device_id: super::super::DeviceId,
    /// Signing public key.
    pub signing_pk: super::super::SigningPublicKey,
    /// Encryption public key.
    pub encryption_pk: super::super::EncryptionPublicKey,
    /// Device name.
    pub name: DisplayName,
    /// Latest presence time.
    pub last_active: Option<UnixSeconds>,
}

/// Established sync query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncEstablishedView {
    /// This device's name.
    pub device_name: DisplayName,
    /// Linked devices.
    pub members: Vec<SyncMemberView>,
    /// Persistent channels.
    pub persistents: Vec<super::super::DurableChannel>,
    /// Ephemeral channels.
    pub ephemerals: Vec<super::super::EphemeralChannel>,
    /// Latest presence time.
    pub last_active: Option<UnixSeconds>,
}

/// Query conversation ADT.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Conversation {
    /// DM handshake.
    HandshakeDm(Handshake),
    /// Sync handshake.
    HandshakeSync(Handshake),
    /// Established DM.
    DirectMessage(DmEstablished),
    /// Group.
    Group(GroupQuery),
    /// Established Synchronization.
    Synchronization(SyncEstablishedView),
}
