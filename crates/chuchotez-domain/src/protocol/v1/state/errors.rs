//! Fail-closed errors for apply, persist, and named Engine methods.

use super::{ConversationId, ConversationPhase, DisplayNameError, IdentityId, UserId};
use crate::protocol::v1::{
    AeadError, CallingCardError, CanonicalJsonError, CompressError, EnvelopeError, IntakeError,
    InviteError, KemError, NoticeError, SignError,
};

/// Why [`crate::protocol::v1::Engine::apply`] failed. State is unchanged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApplyError {
    /// No such user.
    UnknownUser(UserId),
    /// No such identity.
    UnknownIdentity {
        /// Parent user.
        user_id: UserId,
        /// Missing identity.
        identity_id: IdentityId,
    },
    /// No such conversation.
    UnknownConversation {
        /// Parent user.
        user_id: UserId,
        /// Parent identity.
        identity_id: IdentityId,
        /// Missing conversation.
        conversation_id: ConversationId,
    },
    /// [`super::Command::CreateUser`] id already present.
    DuplicateUser(UserId),
    /// [`super::Command::CreateIdentity`] id already present.
    DuplicateIdentity {
        /// Parent user.
        user_id: UserId,
        /// Conflicting identity.
        identity_id: IdentityId,
    },
    /// Conversation id already present.
    DuplicateConversation {
        /// Parent user.
        user_id: UserId,
        /// Parent identity.
        identity_id: IdentityId,
        /// Conflicting conversation.
        conversation_id: ConversationId,
    },
    /// Command is illegal in this phase.
    UnexpectedPhase {
        /// Parent user.
        user_id: UserId,
        /// Parent identity.
        identity_id: IdentityId,
        /// Conversation.
        conversation_id: ConversationId,
        /// Phase that was found.
        found: ConversationPhase,
    },
    /// [`super::EngineState::command_seq`] is [`u64::MAX`].
    SeqOverflow,
}

impl core::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownUser(id) => write!(f, "unknown user {id:?}"),
            Self::UnknownIdentity {
                user_id,
                identity_id,
            } => {
                write!(f, "unknown identity {identity_id:?} under {user_id:?}")
            }
            Self::UnknownConversation {
                user_id,
                identity_id,
                conversation_id,
            } => write!(
                f,
                "unknown conversation {conversation_id:?} under {user_id:?} {identity_id:?}"
            ),
            Self::DuplicateUser(id) => write!(f, "duplicate user {id:?}"),
            Self::DuplicateIdentity {
                user_id,
                identity_id,
            } => write!(f, "duplicate identity {identity_id:?} under {user_id:?}"),
            Self::DuplicateConversation {
                user_id,
                identity_id,
                conversation_id,
            } => write!(
                f,
                "duplicate conversation {conversation_id:?} under {user_id:?} {identity_id:?}"
            ),
            Self::UnexpectedPhase {
                user_id,
                identity_id,
                conversation_id,
                found,
            } => write!(
                f,
                "unexpected phase {found:?} for {conversation_id:?} under {user_id:?} {identity_id:?}"
            ),
            Self::SeqOverflow => f.write_str("command sequence overflow"),
        }
    }
}

impl std::error::Error for ApplyError {}

/// Why sealed-command encode or decode failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PersistError {
    /// Blob shorter than nonce length, or empty after open.
    TooShort,
    /// Blob longer than [`super::COMMAND_MAX_PERSIST_LEN`].
    TooLong,
    /// AEAD open failed.
    Aead(AeadError),
    /// Inflate failed or exceeded cap.
    Compress(CompressError),
    /// RFC 8785 failed.
    Json(CanonicalJsonError),
    /// `v` was missing or not `"1"`.
    InvalidVersion,
    /// `op` was missing or unknown.
    UnknownOp,
    /// A required member was missing.
    MissingField,
    /// An unknown member was present.
    UnknownField,
    /// JSON root or a member had the wrong type.
    Type,
    /// An id was not 32 decoded bytes.
    InvalidId,
    /// Ticket compact blob failed.
    Ticket(EnvelopeError),
    /// Nested Notice JSON failed.
    Notice(NoticeError),
    /// Nested Intake failed.
    Intake(IntakeError),
    /// Nested display name failed.
    DisplayName(DisplayNameError),
    /// Nested CallingCard failed.
    CallingCard(CallingCardError),
    /// [`u64::MAX`] sequence cannot be sealed.
    SeqOverflow,
}

impl core::fmt::Display for PersistError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort => f.write_str("persisted command is too short"),
            Self::TooLong => f.write_str("persisted command is too long"),
            Self::Aead(err) => write!(f, "persisted command: {err}"),
            Self::Compress(err) => write!(f, "persisted command: {err}"),
            Self::Json(err) => write!(f, "persisted command: {err}"),
            Self::InvalidVersion => f.write_str("persisted command version is invalid"),
            Self::UnknownOp => f.write_str("persisted command op is unknown"),
            Self::MissingField => f.write_str("persisted command json is missing a member"),
            Self::UnknownField => f.write_str("persisted command json has an unknown member"),
            Self::Type => f.write_str("persisted command json has the wrong type"),
            Self::InvalidId => f.write_str("persisted command id is invalid"),
            Self::Ticket(err) => write!(f, "persisted command ticket: {err}"),
            Self::Notice(err) => write!(f, "persisted command notice: {err}"),
            Self::Intake(err) => write!(f, "persisted command intake: {err}"),
            Self::DisplayName(err) => write!(f, "persisted command display name: {err}"),
            Self::CallingCard(err) => write!(f, "persisted command calling card: {err}"),
            Self::SeqOverflow => f.write_str("command sequence overflow"),
        }
    }
}

impl std::error::Error for PersistError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Aead(err) => Some(err),
            Self::Compress(err) => Some(err),
            Self::Json(err) => Some(err),
            Self::Ticket(err) => Some(err),
            Self::Notice(err) => Some(err),
            Self::Intake(err) => Some(err),
            Self::DisplayName(err) => Some(err),
            Self::CallingCard(err) => Some(err),
            Self::TooShort
            | Self::TooLong
            | Self::InvalidVersion
            | Self::UnknownOp
            | Self::MissingField
            | Self::UnknownField
            | Self::Type
            | Self::InvalidId
            | Self::SeqOverflow => None,
        }
    }
}

/// Why [`crate::protocol::v1::Engine::create_user`] failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CreateUserError {
    /// Drawn id already present.
    DuplicateUser(UserId),
    /// Sequence cannot increment.
    SeqOverflow,
    /// Sealing the Command failed.
    Persist(PersistError),
}

/// Why [`crate::protocol::v1::Engine::create_identity`] failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CreateIdentityError {
    /// No such user.
    UnknownUser(UserId),
    /// Drawn id already present.
    DuplicateIdentity {
        /// Parent user.
        user_id: UserId,
        /// Conflicting identity.
        identity_id: IdentityId,
    },
    /// Encryption key generation failed.
    Kem(KemError),
    /// Signing key generation failed.
    Sign(SignError),
    /// Sequence cannot increment.
    SeqOverflow,
    /// Sealing the Command failed.
    Persist(PersistError),
}

/// Why [`crate::protocol::v1::Engine::create_calling_card`] failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CreateCallingCardError {
    /// No such user.
    UnknownUser(UserId),
    /// No such identity.
    UnknownIdentity {
        /// Parent user.
        user_id: UserId,
        /// Missing identity.
        identity_id: IdentityId,
    },
    /// No such conversation.
    UnknownConversation {
        /// Parent user.
        user_id: UserId,
        /// Parent identity.
        identity_id: IdentityId,
        /// Missing conversation.
        conversation_id: ConversationId,
    },
    /// Conversation is not [`super::Invitee::InviteReceived`].
    UnexpectedPhase {
        /// Parent user.
        user_id: UserId,
        /// Parent identity.
        identity_id: IdentityId,
        /// Conversation.
        conversation_id: ConversationId,
        /// Phase that was found.
        found: ConversationPhase,
    },
    /// Identity has no display name.
    UnsetDisplayName,
    /// Mailbox or wire list failed the card gates.
    CallingCard(CallingCardError),
    /// Sequence cannot increment.
    SeqOverflow,
    /// Sealing the Command failed.
    Persist(PersistError),
}

/// Why an Engine query getter failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QueryError {
    /// No such user.
    UnknownUser(UserId),
    /// No such identity.
    UnknownIdentity {
        /// Parent user.
        user_id: UserId,
        /// Missing identity.
        identity_id: IdentityId,
    },
    /// No such conversation.
    UnknownConversation {
        /// Parent user.
        user_id: UserId,
        /// Parent identity.
        identity_id: IdentityId,
        /// Missing conversation.
        conversation_id: ConversationId,
    },
    /// Conversation phase does not expose this artifact.
    UnexpectedPhase {
        /// Parent user.
        user_id: UserId,
        /// Parent identity.
        identity_id: IdentityId,
        /// Conversation.
        conversation_id: ConversationId,
        /// Phase that was found.
        found: ConversationPhase,
    },
}

/// Why [`crate::protocol::v1::Engine::delete_user`] failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeleteUserError {
    /// No such user.
    UnknownUser(UserId),
    /// Sequence cannot increment.
    SeqOverflow,
    /// Sealing the Command failed.
    Persist(PersistError),
}

/// Why [`crate::protocol::v1::Engine::delete_identity`] failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeleteIdentityError {
    /// No such user.
    UnknownUser(UserId),
    /// No such identity.
    UnknownIdentity {
        /// Parent user.
        user_id: UserId,
        /// Missing identity.
        identity_id: IdentityId,
    },
    /// Sequence cannot increment.
    SeqOverflow,
    /// Sealing the Command failed.
    Persist(PersistError),
}

/// Why [`crate::protocol::v1::Engine::delete_conversation`] failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeleteConversationError {
    /// No such user.
    UnknownUser(UserId),
    /// No such identity.
    UnknownIdentity {
        /// Parent user.
        user_id: UserId,
        /// Missing identity.
        identity_id: IdentityId,
    },
    /// No such conversation.
    UnknownConversation {
        /// Parent user.
        user_id: UserId,
        /// Parent identity.
        identity_id: IdentityId,
        /// Missing conversation.
        conversation_id: ConversationId,
    },
    /// Sequence cannot increment.
    SeqOverflow,
    /// Sealing the Command failed.
    Persist(PersistError),
}

/// Why [`crate::protocol::v1::Engine::set_display_name`] failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SetDisplayNameError {
    /// No such user.
    UnknownUser(UserId),
    /// No such identity.
    UnknownIdentity {
        /// Parent user.
        user_id: UserId,
        /// Missing identity.
        identity_id: IdentityId,
    },
    /// Sequence cannot increment.
    SeqOverflow,
    /// Sealing the Command failed.
    Persist(PersistError),
}

/// Why [`crate::protocol::v1::Engine::unset_display_name`] failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UnsetDisplayNameError {
    /// No such user.
    UnknownUser(UserId),
    /// No such identity.
    UnknownIdentity {
        /// Parent user.
        user_id: UserId,
        /// Missing identity.
        identity_id: IdentityId,
    },
    /// Sequence cannot increment.
    SeqOverflow,
    /// Sealing the Command failed.
    Persist(PersistError),
}

/// Why [`crate::protocol::v1::Engine::create_invite`] failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CreateInviteError {
    /// No such user.
    UnknownUser(UserId),
    /// No such identity.
    UnknownIdentity {
        /// Parent user.
        user_id: UserId,
        /// Missing identity.
        identity_id: IdentityId,
    },
    /// Drawn conversation id already present.
    DuplicateConversation {
        /// Parent user.
        user_id: UserId,
        /// Parent identity.
        identity_id: IdentityId,
        /// Conflicting conversation.
        conversation_id: ConversationId,
    },
    /// Minting Ticket plus Intake failed.
    Invite(InviteError),
    /// Sequence cannot increment.
    SeqOverflow,
    /// Sealing the Command failed.
    Persist(PersistError),
}

/// Why [`crate::protocol::v1::Engine::mark_notices_pinned`] failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MarkNoticesPinnedError {
    /// No such user.
    UnknownUser(UserId),
    /// No such identity.
    UnknownIdentity {
        /// Parent user.
        user_id: UserId,
        /// Missing identity.
        identity_id: IdentityId,
    },
    /// No such conversation.
    UnknownConversation {
        /// Parent user.
        user_id: UserId,
        /// Parent identity.
        identity_id: IdentityId,
        /// Missing conversation.
        conversation_id: ConversationId,
    },
    /// Conversation is not [`super::Inviter::InviteCreated`].
    UnexpectedPhase {
        /// Parent user.
        user_id: UserId,
        /// Parent identity.
        identity_id: IdentityId,
        /// Conversation.
        conversation_id: ConversationId,
        /// Phase that was found.
        found: ConversationPhase,
    },
    /// Sequence cannot increment.
    SeqOverflow,
    /// Sealing the Command failed.
    Persist(PersistError),
}

/// Why [`crate::protocol::v1::Engine::receive_ticket`] failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceiveTicketError {
    /// No such user.
    UnknownUser(UserId),
    /// No such identity.
    UnknownIdentity {
        /// Parent user.
        user_id: UserId,
        /// Missing identity.
        identity_id: IdentityId,
    },
    /// Drawn conversation id already present.
    DuplicateConversation {
        /// Parent user.
        user_id: UserId,
        /// Parent identity.
        identity_id: IdentityId,
        /// Conflicting conversation.
        conversation_id: ConversationId,
    },
    /// Compact Ticket blob failed.
    Ticket(EnvelopeError),
    /// Sequence cannot increment.
    SeqOverflow,
    /// Sealing the Command failed.
    Persist(PersistError),
}

/// Why [`crate::protocol::v1::Engine::receive_notice`] failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceiveNoticeError {
    /// No such user.
    UnknownUser(UserId),
    /// No such identity.
    UnknownIdentity {
        /// Parent user.
        user_id: UserId,
        /// Missing identity.
        identity_id: IdentityId,
    },
    /// No such conversation.
    UnknownConversation {
        /// Parent user.
        user_id: UserId,
        /// Parent identity.
        identity_id: IdentityId,
        /// Missing conversation.
        conversation_id: ConversationId,
    },
    /// Conversation is not [`super::Invitee::TicketReceived`].
    UnexpectedPhase {
        /// Parent user.
        user_id: UserId,
        /// Parent identity.
        identity_id: IdentityId,
        /// Conversation.
        conversation_id: ConversationId,
        /// Phase that was found.
        found: ConversationPhase,
    },
    /// Notice blob failed to parse.
    Notice(NoticeError),
    /// Sequence cannot increment.
    SeqOverflow,
    /// Sealing the Command failed.
    Persist(PersistError),
}

fn write_unknown_user(f: &mut core::fmt::Formatter<'_>, id: &UserId) -> core::fmt::Result {
    write!(f, "unknown user {id:?}")
}

fn write_unknown_identity(
    f: &mut core::fmt::Formatter<'_>,
    user_id: &UserId,
    identity_id: &IdentityId,
) -> core::fmt::Result {
    write!(f, "unknown identity {identity_id:?} under {user_id:?}")
}

fn write_unknown_conversation(
    f: &mut core::fmt::Formatter<'_>,
    user_id: &UserId,
    identity_id: &IdentityId,
    conversation_id: &ConversationId,
) -> core::fmt::Result {
    write!(
        f,
        "unknown conversation {conversation_id:?} under {user_id:?} {identity_id:?}"
    )
}

fn write_dup_conversation(
    f: &mut core::fmt::Formatter<'_>,
    user_id: &UserId,
    identity_id: &IdentityId,
    conversation_id: &ConversationId,
) -> core::fmt::Result {
    write!(
        f,
        "duplicate conversation {conversation_id:?} under {user_id:?} {identity_id:?}"
    )
}

fn write_phase(
    f: &mut core::fmt::Formatter<'_>,
    user_id: &UserId,
    identity_id: &IdentityId,
    conversation_id: &ConversationId,
    found: &ConversationPhase,
) -> core::fmt::Result {
    write!(
        f,
        "unexpected phase {found:?} for {conversation_id:?} under {user_id:?} {identity_id:?}"
    )
}

impl core::fmt::Display for CreateUserError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DuplicateUser(id) => write!(f, "duplicate user {id:?}"),
            Self::SeqOverflow => f.write_str("command sequence overflow"),
            Self::Persist(err) => write!(f, "persist: {err}"),
        }
    }
}

impl core::fmt::Display for CreateIdentityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownUser(id) => write_unknown_user(f, id),
            Self::DuplicateIdentity {
                user_id,
                identity_id,
            } => write!(f, "duplicate identity {identity_id:?} under {user_id:?}"),
            Self::Kem(err) => write!(f, "identity kem: {err}"),
            Self::Sign(err) => write!(f, "identity sign: {err}"),
            Self::SeqOverflow => f.write_str("command sequence overflow"),
            Self::Persist(err) => write!(f, "persist: {err}"),
        }
    }
}

impl core::fmt::Display for CreateCallingCardError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownUser(id) => write_unknown_user(f, id),
            Self::UnknownIdentity {
                user_id,
                identity_id,
            } => write_unknown_identity(f, user_id, identity_id),
            Self::UnknownConversation {
                user_id,
                identity_id,
                conversation_id,
            } => write_unknown_conversation(f, user_id, identity_id, conversation_id),
            Self::UnexpectedPhase {
                user_id,
                identity_id,
                conversation_id,
                found,
            } => write_phase(f, user_id, identity_id, conversation_id, found),
            Self::UnsetDisplayName => f.write_str("identity display name is unset"),
            Self::CallingCard(err) => write!(f, "calling card: {err}"),
            Self::SeqOverflow => f.write_str("command sequence overflow"),
            Self::Persist(err) => write!(f, "persist: {err}"),
        }
    }
}

impl core::fmt::Display for QueryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownUser(id) => write_unknown_user(f, id),
            Self::UnknownIdentity {
                user_id,
                identity_id,
            } => write_unknown_identity(f, user_id, identity_id),
            Self::UnknownConversation {
                user_id,
                identity_id,
                conversation_id,
            } => write_unknown_conversation(f, user_id, identity_id, conversation_id),
            Self::UnexpectedPhase {
                user_id,
                identity_id,
                conversation_id,
                found,
            } => write_phase(f, user_id, identity_id, conversation_id, found),
        }
    }
}

impl core::fmt::Display for DeleteUserError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownUser(id) => write_unknown_user(f, id),
            Self::SeqOverflow => f.write_str("command sequence overflow"),
            Self::Persist(err) => write!(f, "persist: {err}"),
        }
    }
}

impl core::fmt::Display for DeleteIdentityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownUser(id) => write_unknown_user(f, id),
            Self::UnknownIdentity {
                user_id,
                identity_id,
            } => write_unknown_identity(f, user_id, identity_id),
            Self::SeqOverflow => f.write_str("command sequence overflow"),
            Self::Persist(err) => write!(f, "persist: {err}"),
        }
    }
}

impl core::fmt::Display for DeleteConversationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownUser(id) => write_unknown_user(f, id),
            Self::UnknownIdentity {
                user_id,
                identity_id,
            } => write_unknown_identity(f, user_id, identity_id),
            Self::UnknownConversation {
                user_id,
                identity_id,
                conversation_id,
            } => write_unknown_conversation(f, user_id, identity_id, conversation_id),
            Self::SeqOverflow => f.write_str("command sequence overflow"),
            Self::Persist(err) => write!(f, "persist: {err}"),
        }
    }
}

impl core::fmt::Display for SetDisplayNameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownUser(id) => write_unknown_user(f, id),
            Self::UnknownIdentity {
                user_id,
                identity_id,
            } => write_unknown_identity(f, user_id, identity_id),
            Self::SeqOverflow => f.write_str("command sequence overflow"),
            Self::Persist(err) => write!(f, "persist: {err}"),
        }
    }
}

impl core::fmt::Display for UnsetDisplayNameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownUser(id) => write_unknown_user(f, id),
            Self::UnknownIdentity {
                user_id,
                identity_id,
            } => write_unknown_identity(f, user_id, identity_id),
            Self::SeqOverflow => f.write_str("command sequence overflow"),
            Self::Persist(err) => write!(f, "persist: {err}"),
        }
    }
}

impl core::fmt::Display for CreateInviteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownUser(id) => write_unknown_user(f, id),
            Self::UnknownIdentity {
                user_id,
                identity_id,
            } => write_unknown_identity(f, user_id, identity_id),
            Self::DuplicateConversation {
                user_id,
                identity_id,
                conversation_id,
            } => write_dup_conversation(f, user_id, identity_id, conversation_id),
            Self::Invite(err) => write!(f, "invite: {err}"),
            Self::SeqOverflow => f.write_str("command sequence overflow"),
            Self::Persist(err) => write!(f, "persist: {err}"),
        }
    }
}

impl core::fmt::Display for MarkNoticesPinnedError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownUser(id) => write_unknown_user(f, id),
            Self::UnknownIdentity {
                user_id,
                identity_id,
            } => write_unknown_identity(f, user_id, identity_id),
            Self::UnknownConversation {
                user_id,
                identity_id,
                conversation_id,
            } => write_unknown_conversation(f, user_id, identity_id, conversation_id),
            Self::UnexpectedPhase {
                user_id,
                identity_id,
                conversation_id,
                found,
            } => write_phase(f, user_id, identity_id, conversation_id, found),
            Self::SeqOverflow => f.write_str("command sequence overflow"),
            Self::Persist(err) => write!(f, "persist: {err}"),
        }
    }
}

impl core::fmt::Display for ReceiveTicketError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownUser(id) => write_unknown_user(f, id),
            Self::UnknownIdentity {
                user_id,
                identity_id,
            } => write_unknown_identity(f, user_id, identity_id),
            Self::DuplicateConversation {
                user_id,
                identity_id,
                conversation_id,
            } => write_dup_conversation(f, user_id, identity_id, conversation_id),
            Self::Ticket(err) => write!(f, "ticket: {err}"),
            Self::SeqOverflow => f.write_str("command sequence overflow"),
            Self::Persist(err) => write!(f, "persist: {err}"),
        }
    }
}

impl core::fmt::Display for ReceiveNoticeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownUser(id) => write_unknown_user(f, id),
            Self::UnknownIdentity {
                user_id,
                identity_id,
            } => write_unknown_identity(f, user_id, identity_id),
            Self::UnknownConversation {
                user_id,
                identity_id,
                conversation_id,
            } => write_unknown_conversation(f, user_id, identity_id, conversation_id),
            Self::UnexpectedPhase {
                user_id,
                identity_id,
                conversation_id,
                found,
            } => write_phase(f, user_id, identity_id, conversation_id, found),
            Self::Notice(err) => write!(f, "notice: {err}"),
            Self::SeqOverflow => f.write_str("command sequence overflow"),
            Self::Persist(err) => write!(f, "persist: {err}"),
        }
    }
}

macro_rules! impl_std_error {
    ($($ty:ty),+) => {
        $(impl std::error::Error for $ty {})+
    };
}

impl_std_error!(
    CreateUserError,
    CreateIdentityError,
    CreateCallingCardError,
    QueryError,
    DeleteUserError,
    DeleteIdentityError,
    DeleteConversationError,
    SetDisplayNameError,
    UnsetDisplayNameError,
    CreateInviteError,
    MarkNoticesPinnedError,
    ReceiveTicketError,
    ReceiveNoticeError
);
