//! Host-owned handle bound to a v1 [`Suite`] and [`Defaults`].

mod fold_tree;
mod handshake;
mod helpers;
mod identity;
mod invite;
mod party;
mod persist;
mod poll;
mod query;
mod ratchet;
mod session;
mod state;
mod vault;

#[cfg(test)]
mod tests;

pub use query::{
    BlobGet, BlobPut, BlockedIdentity, BlockedMissing, Conversation, ConversationListRow,
    ConversationRef, DirectMessageQuery, DurableLocator, DurableWrite, EphemeralLocator,
    EphemeralWrite, FailedReason, FoldOk, GroupQuery, Handshake, HandshakeInvitee,
    HandshakeInviter, MediaDraft, MutateOk, PingTarget, Poll, SynchronizationQuery, WrapDekOk,
};
pub use state::EngineState;

use super::{AeadKey, Defaults, DisplayName, Suite};

/// Persist format version in the nonce high four bytes.
pub(super) const PERSIST_VERSION: u32 = 1;

/// Folded snapshot format version.
pub(super) const FOLD_VERSION: u32 = 1;

pub(super) const SPAWN_SECRET_INFO: &[u8] = b"chuchotez/1/spawn-secret";
pub(super) const SPAWN_CONVERSATION_ID_INFO: &[u8] = b"chuchotez/1/spawn-conversation-id";
pub(super) const HANDSHAKE_DM_ESTABLISHED_INFO: &[u8] = b"chuchotez/1/handshake-dm-established";
pub(super) const HANDSHAKE_SYNC_ESTABLISHED_INFO: &[u8] = b"chuchotez/1/handshake-sync-established";

/// Host-owned handle bound to a suite and Defaults.
#[derive(Clone)]
pub struct Engine {
    pub(super) suite: Suite,
    pub(super) defaults: Defaults,
    pub(super) dek: Option<AeadKey>,
}

impl core::fmt::Debug for Engine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Engine")
            .field("locked", &self.dek.is_none())
            .finish()
    }
}

impl Engine {
    /// Bind this engine to `suite` and `defaults`.
    #[must_use]
    pub fn new(suite: Suite, defaults: Defaults) -> Self {
        Self {
            suite,
            defaults,
            dek: None,
        }
    }

    /// Constructor Defaults.
    #[must_use]
    pub fn defaults(&self) -> &Defaults {
        &self.defaults
    }

    /// Brand a display name.
    pub fn try_new_display_name(name: &str) -> Result<DisplayName, super::DisplayNameError> {
        DisplayName::try_from(name)
    }
}
