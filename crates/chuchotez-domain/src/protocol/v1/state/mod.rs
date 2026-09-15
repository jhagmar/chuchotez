//! Host-owned conversation state, Commands, and named Engine methods.

mod apply;
mod command;
mod display_name;
mod errors;
mod ids;
mod ops;
mod persist;
mod tree;

#[cfg(test)]
mod flow;

pub use command::Command;
pub use display_name::{DisplayName, DisplayNameError};
pub use errors::{
    ApplyError, CreateIdentityError, CreateInviteError, CreateUserError, DeleteConversationError,
    DeleteIdentityError, DeleteUserError, MarkNoticesPinnedError, PersistError, ReceiveNoticeError,
    ReceiveTicketError, SetDisplayNameError, UnsetDisplayNameError,
};
pub use ids::{ConversationId, IdentityId, UserId};
pub use ops::{
    CreateIdentityOk, CreateInviteOk, CreateUserOk, PersistOk, ReceiveNoticeOk, ReceiveTicketOk,
};
pub use persist::PersistedCommand;
pub use tree::{
    Conversation, ConversationPhase, DirectMessage, EngineState, Established, Failed, Group,
    Identity, Invitee, Inviter, Synchronization, User,
};

/// UTF-8 byte cap for [`DisplayName`].
pub const DISPLAY_NAME_MAX_LEN: usize = 64;

/// Command JSON schema string (`"1"`).
pub const COMMAND_SCHEMA_VERSION: &str = "1";

/// Persist envelope version byte in AEAD AAD.
pub const COMMAND_PERSIST_VERSION: u8 = 1;

/// Cap on uncompressed Command JSON bytes.
pub const COMMAND_MAX_UNCOMPRESSED: usize = 16384;

/// Cap on the Command Deflate body.
pub const COMMAND_MAX_COMPRESSED: usize = COMMAND_MAX_UNCOMPRESSED.saturating_add(16);

/// Cap on `nonce || ciphertext` for a sealed Command.
pub const COMMAND_MAX_PERSIST_LEN: usize = 12 + COMMAND_MAX_COMPRESSED + 256;
