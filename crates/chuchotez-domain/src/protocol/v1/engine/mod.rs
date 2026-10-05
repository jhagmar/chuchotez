//! Host-owned handle bound to a v1 [`Suite`] and [`Defaults`].

mod chains;
mod chat;
mod fold_tree;
mod group;
mod handshake;
mod heal;
mod helpers;
mod identity;
mod invite;
mod live;
mod party;
mod persist;
mod poll;
mod query;
mod ratchet;
mod row_log;
mod session;
mod state;
mod vault;

#[cfg(test)]
mod tests;

pub use query::{
    BlobGet, BlobPut, BlockedIdentity, BlockedMissing, ChatItem, Conversation, ConversationListRow,
    ConversationRef, DmEstablished, DurableLocator, DurableWrite, EphemeralLocator, EphemeralWrite,
    FailedReason, FoldOk, GroupEnd, GroupEstablishedView, GroupOfferView, GroupQuery, Handshake,
    HandshakeInvitee, HandshakeInviter, HistoryItem, MediaDraft, MutateOk, PingPost, PingTarget,
    Poll, PresenceView, QueryLocalPrefs, QueryPeerPrefs, SyncEstablishedView, SyncMemberView,
    TypingView, WrapDekOk,
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

    /// RFC 8291 empty-body POSTs for `https:` ping rows.
    #[must_use]
    pub fn ping_posts(pings: &[PingTarget]) -> Vec<PingPost> {
        query::ping_posts(pings)
    }
}
