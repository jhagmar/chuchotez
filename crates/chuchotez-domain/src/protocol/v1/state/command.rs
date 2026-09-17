//! Deterministic log records. Artifacts are already drawn.

use super::{CallingCard, ConversationId, DisplayName, Failed, IdentityId, UserId};
use crate::protocol::v1::{IdentityKemKeypair, IdentitySignKeypair, Invite, Notice, Ticket};

/// One recorded mutation of [`super::EngineState`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    /// Insert a user.
    CreateUser {
        /// Drawn [`UserId`].
        user_id: UserId,
    },
    /// Insert an identity under a user.
    CreateIdentity {
        /// Existing user.
        user_id: UserId,
        /// Drawn [`IdentityId`].
        identity_id: IdentityId,
        /// Policy-matched encryption keypair.
        encryption: IdentityKemKeypair,
        /// Policy-matched signing keypair.
        signing: IdentitySignKeypair,
    },
    /// Remove a user and nested identities and conversations.
    DeleteUser {
        /// User to remove.
        user_id: UserId,
    },
    /// Remove an identity and nested conversations.
    DeleteIdentity {
        /// Parent user.
        user_id: UserId,
        /// Identity to remove.
        identity_id: IdentityId,
    },
    /// Remove a conversation.
    DeleteConversation {
        /// Parent user.
        user_id: UserId,
        /// Parent identity.
        identity_id: IdentityId,
        /// Conversation to remove.
        conversation_id: ConversationId,
    },
    /// Set a preferred display name.
    SetDisplayName {
        /// Parent user.
        user_id: UserId,
        /// Identity.
        identity_id: IdentityId,
        /// Nonempty name.
        name: DisplayName,
    },
    /// Clear the preferred display name.
    UnsetDisplayName {
        /// Parent user.
        user_id: UserId,
        /// Identity.
        identity_id: IdentityId,
    },
    /// Insert [`super::Inviter::InviteCreated`].
    CreateInvite {
        /// Parent user.
        user_id: UserId,
        /// Parent identity.
        identity_id: IdentityId,
        /// Drawn conversation id.
        conversation_id: ConversationId,
        /// Minted Ticket plus Intake.
        invite: Invite,
    },
    /// [`super::Inviter::InviteCreated`] to [`super::Inviter::NoticePinned`].
    MarkNoticesPinned {
        /// Parent user.
        user_id: UserId,
        /// Parent identity.
        identity_id: IdentityId,
        /// Conversation.
        conversation_id: ConversationId,
    },
    /// Insert [`super::Invitee::TicketReceived`].
    ReceiveTicket {
        /// Parent user.
        user_id: UserId,
        /// Parent identity.
        identity_id: IdentityId,
        /// Drawn conversation id.
        conversation_id: ConversationId,
        /// Parsed Ticket.
        ticket: Ticket,
    },
    /// [`super::Invitee::TicketReceived`] to [`super::Invitee::InviteReceived`].
    ReceiveNotice {
        /// Parent user.
        user_id: UserId,
        /// Parent identity.
        identity_id: IdentityId,
        /// Conversation.
        conversation_id: ConversationId,
        /// Opened Notice.
        notice: Notice,
    },
    /// [`super::Invitee::TicketReceived`] to [`super::Failed`].
    FailConversation {
        /// Parent user.
        user_id: UserId,
        /// Parent identity.
        identity_id: IdentityId,
        /// Conversation.
        conversation_id: ConversationId,
        /// Failure payload.
        failed: Failed,
    },
    /// [`super::Invitee::InviteReceived`] to [`super::Invitee::CallingCardCreated`].
    CreateCallingCard {
        /// Parent user.
        user_id: UserId,
        /// Parent identity.
        identity_id: IdentityId,
        /// Conversation.
        conversation_id: ConversationId,
        /// Minted card.
        card: CallingCard,
    },
}
