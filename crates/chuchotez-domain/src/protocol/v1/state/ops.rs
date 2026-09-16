//! Named Engine methods that drive [`super::EngineState`].

use super::{
    ApplyError, Command, Conversation, ConversationId, CreateIdentityError, CreateInviteError,
    CreateUserError, DeleteConversationError, DeleteIdentityError, DeleteUserError, DirectMessage,
    DisplayName, EngineState, Failed, IdentityId, Invitee, MarkNoticesPinnedError, PersistError,
    PersistedCommand, ReceiveNoticeError, ReceiveTicketError, SetDisplayNameError,
    UnsetDisplayNameError, UserId,
};
use crate::protocol::v1::{AeadKey, Billboard, BillboardTag, Mailbox, Wire, notice};
use crate::protocol::{Policy, Rng};

/// Success from [`crate::protocol::v1::Engine::create_user`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateUserOk {
    /// Drawn id.
    pub user_id: UserId,
    /// Sealed Command.
    pub persist: PersistedCommand,
}

/// Success from [`crate::protocol::v1::Engine::create_identity`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateIdentityOk {
    /// Drawn id.
    pub identity_id: IdentityId,
    /// Sealed Command.
    pub persist: PersistedCommand,
}

/// Success from a delete or display-name Command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistOk {
    /// Sealed Command.
    pub persist: PersistedCommand,
}

/// Success from [`crate::protocol::v1::Engine::create_invite`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateInviteOk {
    /// Drawn conversation id.
    pub conversation_id: ConversationId,
    /// Sealed Command.
    pub persist: PersistedCommand,
    /// Compact Ticket blob for the host to present after pin.
    pub ticket_blob: String,
    /// Sealed Notice blob for the host to pin.
    pub notice_blob: String,
    /// Billboard Tag derived from the Ticket.
    pub billboard_tag: BillboardTag,
}

/// Success from [`crate::protocol::v1::Engine::receive_ticket`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiveTicketOk {
    /// Drawn conversation id.
    pub conversation_id: ConversationId,
    /// Sealed Command.
    pub persist: PersistedCommand,
}

/// Success from [`crate::protocol::v1::Engine::receive_notice`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceiveNoticeOk {
    /// Policy was in the allowlist.
    Accepted {
        /// Sealed Command.
        persist: PersistedCommand,
    },
    /// Policy was outside the allowlist. Conversation is [`super::Failed`].
    Refused {
        /// Sealed Command.
        persist: PersistedCommand,
        /// Policy published in the Notice.
        found: Policy,
    },
}

impl ReceiveNoticeOk {
    /// Sealed Command for this outcome.
    #[must_use]
    pub fn persist(&self) -> &PersistedCommand {
        match self {
            Self::Accepted { persist } => persist,
            Self::Refused { persist, .. } => persist,
        }
    }
}

impl crate::protocol::v1::Engine {
    /// Insert a user. Draws [`UserId`] from `rng`.
    pub fn create_user(
        &self,
        state: EngineState,
        rng: &dyn Rng,
        dek: &AeadKey,
    ) -> (EngineState, Result<CreateUserOk, CreateUserError>) {
        let user_id = UserId::from_random32(rng.random32());
        if state.user(&user_id).is_some() {
            return (state, Err(CreateUserError::DuplicateUser(user_id)));
        }
        let cmd = Command::CreateUser { user_id };
        match self.commit(state, dek, &cmd) {
            (state, Ok(persist)) => (state, Ok(CreateUserOk { user_id, persist })),
            (state, Err(err)) => (state, Err(map_create_user(err))),
        }
    }

    /// Insert an identity under `user_id`. Draws [`IdentityId`] from `rng`.
    pub fn create_identity(
        &self,
        state: EngineState,
        rng: &dyn Rng,
        dek: &AeadKey,
        user_id: UserId,
    ) -> (EngineState, Result<CreateIdentityOk, CreateIdentityError>) {
        let identity_id = IdentityId::from_random32(rng.random32());
        match state.user(&user_id) {
            None => return (state, Err(CreateIdentityError::UnknownUser(user_id))),
            Some(user) if user.identity(&identity_id).is_some() => {
                return (
                    state,
                    Err(CreateIdentityError::DuplicateIdentity {
                        user_id,
                        identity_id,
                    }),
                );
            }
            Some(_) => {}
        }
        let cmd = Command::CreateIdentity {
            user_id,
            identity_id,
        };
        match self.commit(state, dek, &cmd) {
            (state, Ok(persist)) => (
                state,
                Ok(CreateIdentityOk {
                    identity_id,
                    persist,
                }),
            ),
            (state, Err(err)) => (state, Err(map_create_identity(err))),
        }
    }

    /// Remove a user and nested identities and conversations.
    pub fn delete_user(
        &self,
        state: EngineState,
        dek: &AeadKey,
        user_id: UserId,
    ) -> (EngineState, Result<PersistOk, DeleteUserError>) {
        self.commit_persist(state, dek, Command::DeleteUser { user_id })
            .map_err_state(map_delete_user)
    }

    /// Remove an identity and nested conversations.
    pub fn delete_identity(
        &self,
        state: EngineState,
        dek: &AeadKey,
        user_id: UserId,
        identity_id: IdentityId,
    ) -> (EngineState, Result<PersistOk, DeleteIdentityError>) {
        self.commit_persist(
            state,
            dek,
            Command::DeleteIdentity {
                user_id,
                identity_id,
            },
        )
        .map_err_state(map_delete_identity)
    }

    /// Remove a conversation.
    pub fn delete_conversation(
        &self,
        state: EngineState,
        dek: &AeadKey,
        user_id: UserId,
        identity_id: IdentityId,
        conversation_id: ConversationId,
    ) -> (EngineState, Result<PersistOk, DeleteConversationError>) {
        self.commit_persist(
            state,
            dek,
            Command::DeleteConversation {
                user_id,
                identity_id,
                conversation_id,
            },
        )
        .map_err_state(map_delete_conversation)
    }

    /// Set the preferred display name.
    pub fn set_display_name(
        &self,
        state: EngineState,
        dek: &AeadKey,
        user_id: UserId,
        identity_id: IdentityId,
        name: DisplayName,
    ) -> (EngineState, Result<PersistOk, SetDisplayNameError>) {
        self.commit_persist(
            state,
            dek,
            Command::SetDisplayName {
                user_id,
                identity_id,
                name,
            },
        )
        .map_err_state(map_set_display_name)
    }

    /// Clear the preferred display name.
    pub fn unset_display_name(
        &self,
        state: EngineState,
        dek: &AeadKey,
        user_id: UserId,
        identity_id: IdentityId,
    ) -> (EngineState, Result<PersistOk, UnsetDisplayNameError>) {
        self.commit_persist(
            state,
            dek,
            Command::UnsetDisplayName {
                user_id,
                identity_id,
            },
        )
        .map_err_state(map_unset_display_name)
    }

    /// Mint an Invite into [`super::Inviter::InviteCreated`].
    #[allow(clippy::too_many_arguments)]
    pub fn create_invite(
        &self,
        state: EngineState,
        rng: &dyn Rng,
        dek: &AeadKey,
        user_id: UserId,
        identity_id: IdentityId,
        billboards: &[Billboard],
        mailboxes: &[Mailbox],
        wires: &[Wire],
    ) -> (EngineState, Result<CreateInviteOk, CreateInviteError>) {
        let conversation_id = ConversationId::from_random32(rng.random32());
        match state.user(&user_id) {
            None => return (state, Err(CreateInviteError::UnknownUser(user_id))),
            Some(user) => match user.identity(&identity_id) {
                None => {
                    return (
                        state,
                        Err(CreateInviteError::UnknownIdentity {
                            user_id,
                            identity_id,
                        }),
                    );
                }
                Some(identity) if identity.conversation(&conversation_id).is_some() => {
                    return (
                        state,
                        Err(CreateInviteError::DuplicateConversation {
                            user_id,
                            identity_id,
                            conversation_id,
                        }),
                    );
                }
                Some(_) => {}
            },
        }
        let invite = match self.try_new_invite(rng, billboards, mailboxes, wires) {
            Ok(invite) => invite,
            Err(err) => return (state, Err(CreateInviteError::Invite(err))),
        };
        let ticket_blob = invite.ticket().serialize(self);
        let notice_blob = self.serialize_notice(invite.ticket(), invite.intake());
        let billboard_tag = invite.ticket().billboard_tag(self);
        let cmd = Command::CreateInvite {
            user_id,
            identity_id,
            conversation_id,
            invite,
        };
        match self.commit(state, dek, &cmd) {
            (state, Ok(persist)) => (
                state,
                Ok(CreateInviteOk {
                    conversation_id,
                    persist,
                    ticket_blob,
                    notice_blob,
                    billboard_tag,
                }),
            ),
            (state, Err(err)) => (state, Err(map_create_invite(err))),
        }
    }

    /// Record that the Notice is pinned on every Billboard in the Invite.
    pub fn mark_notices_pinned(
        &self,
        state: EngineState,
        dek: &AeadKey,
        user_id: UserId,
        identity_id: IdentityId,
        conversation_id: ConversationId,
    ) -> (EngineState, Result<PersistOk, MarkNoticesPinnedError>) {
        self.commit_persist(
            state,
            dek,
            Command::MarkNoticesPinned {
                user_id,
                identity_id,
                conversation_id,
            },
        )
        .map_err_state(map_mark_pinned)
    }

    /// Parse a compact Ticket blob and insert [`super::Invitee::TicketReceived`].
    pub fn receive_ticket(
        &self,
        state: EngineState,
        rng: &dyn Rng,
        dek: &AeadKey,
        user_id: UserId,
        identity_id: IdentityId,
        ticket_blob: &str,
    ) -> (EngineState, Result<ReceiveTicketOk, ReceiveTicketError>) {
        let ticket = match self.try_parse_ticket(ticket_blob) {
            Ok(ticket) => ticket,
            Err(err) => return (state, Err(ReceiveTicketError::Ticket(err))),
        };
        let conversation_id = ConversationId::from_random32(rng.random32());
        match state.user(&user_id) {
            None => return (state, Err(ReceiveTicketError::UnknownUser(user_id))),
            Some(user) => match user.identity(&identity_id) {
                None => {
                    return (
                        state,
                        Err(ReceiveTicketError::UnknownIdentity {
                            user_id,
                            identity_id,
                        }),
                    );
                }
                Some(identity) if identity.conversation(&conversation_id).is_some() => {
                    return (
                        state,
                        Err(ReceiveTicketError::DuplicateConversation {
                            user_id,
                            identity_id,
                            conversation_id,
                        }),
                    );
                }
                Some(_) => {}
            },
        }
        let cmd = Command::ReceiveTicket {
            user_id,
            identity_id,
            conversation_id,
            ticket,
        };
        match self.commit(state, dek, &cmd) {
            (state, Ok(persist)) => (
                state,
                Ok(ReceiveTicketOk {
                    conversation_id,
                    persist,
                }),
            ),
            (state, Err(err)) => (state, Err(map_receive_ticket(err))),
        }
    }

    /// Open a Notice blob. Allowlist decides [`ReceiveNoticeOk::Accepted`] vs refuse.
    #[allow(clippy::too_many_arguments)]
    pub fn receive_notice(
        &self,
        state: EngineState,
        dek: &AeadKey,
        user_id: UserId,
        identity_id: IdentityId,
        conversation_id: ConversationId,
        notice_blob: &str,
        accepted: &[Policy],
    ) -> (EngineState, Result<ReceiveNoticeOk, ReceiveNoticeError>) {
        let ticket = match lookup_conversation(&state, user_id, identity_id, conversation_id) {
            Lookup::Ok(Conversation::DirectMessage(DirectMessage::Invitee(
                Invitee::TicketReceived { ticket },
            ))) => ticket.clone(),
            Lookup::UnknownUser => {
                return (state, Err(ReceiveNoticeError::UnknownUser(user_id)));
            }
            Lookup::UnknownIdentity => {
                return (
                    state,
                    Err(ReceiveNoticeError::UnknownIdentity {
                        user_id,
                        identity_id,
                    }),
                );
            }
            Lookup::UnknownConversation => {
                return (
                    state,
                    Err(ReceiveNoticeError::UnknownConversation {
                        user_id,
                        identity_id,
                        conversation_id,
                    }),
                );
            }
            Lookup::Ok(found) => {
                let found = found.phase();
                return (
                    state,
                    Err(ReceiveNoticeError::UnexpectedPhase {
                        user_id,
                        identity_id,
                        conversation_id,
                        found,
                    }),
                );
            }
        };
        let notice = match notice::try_parse_notice_any_policy(self, &ticket, notice_blob) {
            Ok(notice) => notice,
            Err(err) => return (state, Err(ReceiveNoticeError::Notice(err))),
        };
        let found = notice.policy();
        let cmd = if accepted.contains(&found) {
            Command::ReceiveNotice {
                user_id,
                identity_id,
                conversation_id,
                notice,
            }
        } else {
            Command::FailConversation {
                user_id,
                identity_id,
                conversation_id,
                failed: Failed::PolicyNotAccepted { ticket, notice },
            }
        };
        let accepted_ok = accepted.contains(&found);
        match self.commit(state, dek, &cmd) {
            (state, Ok(persist)) => {
                let ok = if accepted_ok {
                    ReceiveNoticeOk::Accepted { persist }
                } else {
                    ReceiveNoticeOk::Refused { persist, found }
                };
                (state, Ok(ok))
            }
            (state, Err(err)) => (state, Err(map_receive_notice(err))),
        }
    }

    fn commit(
        &self,
        state: EngineState,
        dek: &AeadKey,
        cmd: &Command,
    ) -> (EngineState, Result<PersistedCommand, CommitError>) {
        if state.command_seq() == u64::MAX {
            return (state, Err(CommitError::SeqOverflow));
        }
        let seq = state.command_seq();
        let persist = match self.seal_command(dek, seq, cmd) {
            Ok(persist) => persist,
            Err(err) => return (state, Err(CommitError::Persist(err))),
        };
        let (state, result) = self.apply(state, cmd);
        match result {
            Ok(()) => (state, Ok(persist)),
            Err(err) => (state, Err(CommitError::Apply(err))),
        }
    }

    fn commit_persist(
        &self,
        state: EngineState,
        dek: &AeadKey,
        cmd: Command,
    ) -> (EngineState, Result<PersistOk, CommitError>) {
        match self.commit(state, dek, &cmd) {
            (state, Ok(persist)) => (state, Ok(PersistOk { persist })),
            (state, Err(err)) => (state, Err(err)),
        }
    }
}

trait MapErrState<T, E> {
    fn map_err_state<F, E2>(self, map: F) -> (EngineState, Result<T, E2>)
    where
        F: FnOnce(E) -> E2;
}

impl<T, E> MapErrState<T, E> for (EngineState, Result<T, E>) {
    fn map_err_state<F, E2>(self, map: F) -> (EngineState, Result<T, E2>)
    where
        F: FnOnce(E) -> E2,
    {
        let (state, result) = self;
        (state, result.map_err(map))
    }
}

enum CommitError {
    SeqOverflow,
    Persist(PersistError),
    Apply(ApplyError),
}

enum Lookup<'a> {
    Ok(&'a Conversation),
    UnknownUser,
    UnknownIdentity,
    UnknownConversation,
}

fn lookup_conversation(
    state: &EngineState,
    user_id: UserId,
    identity_id: IdentityId,
    conversation_id: ConversationId,
) -> Lookup<'_> {
    match state.user(&user_id) {
        None => Lookup::UnknownUser,
        Some(user) => match user.identity(&identity_id) {
            None => Lookup::UnknownIdentity,
            Some(identity) => match identity.conversation(&conversation_id) {
                None => Lookup::UnknownConversation,
                Some(conversation) => Lookup::Ok(conversation),
            },
        },
    }
}

fn map_create_user(err: CommitError) -> CreateUserError {
    match err {
        CommitError::SeqOverflow => CreateUserError::SeqOverflow,
        CommitError::Persist(err) => CreateUserError::Persist(err),
        CommitError::Apply(ApplyError::DuplicateUser(id)) => CreateUserError::DuplicateUser(id),
        CommitError::Apply(_) => CreateUserError::SeqOverflow,
    }
}

fn map_create_identity(err: CommitError) -> CreateIdentityError {
    match err {
        CommitError::SeqOverflow => CreateIdentityError::SeqOverflow,
        CommitError::Persist(err) => CreateIdentityError::Persist(err),
        CommitError::Apply(ApplyError::UnknownUser(id)) => CreateIdentityError::UnknownUser(id),
        CommitError::Apply(ApplyError::DuplicateIdentity {
            user_id,
            identity_id,
        }) => CreateIdentityError::DuplicateIdentity {
            user_id,
            identity_id,
        },
        CommitError::Apply(_) => CreateIdentityError::SeqOverflow,
    }
}

fn map_delete_user(err: CommitError) -> DeleteUserError {
    match err {
        CommitError::SeqOverflow => DeleteUserError::SeqOverflow,
        CommitError::Persist(err) => DeleteUserError::Persist(err),
        CommitError::Apply(ApplyError::UnknownUser(id)) => DeleteUserError::UnknownUser(id),
        CommitError::Apply(_) => DeleteUserError::SeqOverflow,
    }
}

fn map_delete_identity(err: CommitError) -> DeleteIdentityError {
    match err {
        CommitError::SeqOverflow => DeleteIdentityError::SeqOverflow,
        CommitError::Persist(err) => DeleteIdentityError::Persist(err),
        CommitError::Apply(ApplyError::UnknownUser(id)) => DeleteIdentityError::UnknownUser(id),
        CommitError::Apply(ApplyError::UnknownIdentity {
            user_id,
            identity_id,
        }) => DeleteIdentityError::UnknownIdentity {
            user_id,
            identity_id,
        },
        CommitError::Apply(_) => DeleteIdentityError::SeqOverflow,
    }
}

fn map_delete_conversation(err: CommitError) -> DeleteConversationError {
    match err {
        CommitError::SeqOverflow => DeleteConversationError::SeqOverflow,
        CommitError::Persist(err) => DeleteConversationError::Persist(err),
        CommitError::Apply(ApplyError::UnknownUser(id)) => DeleteConversationError::UnknownUser(id),
        CommitError::Apply(ApplyError::UnknownIdentity {
            user_id,
            identity_id,
        }) => DeleteConversationError::UnknownIdentity {
            user_id,
            identity_id,
        },
        CommitError::Apply(ApplyError::UnknownConversation {
            user_id,
            identity_id,
            conversation_id,
        }) => DeleteConversationError::UnknownConversation {
            user_id,
            identity_id,
            conversation_id,
        },
        CommitError::Apply(_) => DeleteConversationError::SeqOverflow,
    }
}

fn map_set_display_name(err: CommitError) -> SetDisplayNameError {
    match err {
        CommitError::SeqOverflow => SetDisplayNameError::SeqOverflow,
        CommitError::Persist(err) => SetDisplayNameError::Persist(err),
        CommitError::Apply(ApplyError::UnknownUser(id)) => SetDisplayNameError::UnknownUser(id),
        CommitError::Apply(ApplyError::UnknownIdentity {
            user_id,
            identity_id,
        }) => SetDisplayNameError::UnknownIdentity {
            user_id,
            identity_id,
        },
        CommitError::Apply(_) => SetDisplayNameError::SeqOverflow,
    }
}

fn map_unset_display_name(err: CommitError) -> UnsetDisplayNameError {
    match err {
        CommitError::SeqOverflow => UnsetDisplayNameError::SeqOverflow,
        CommitError::Persist(err) => UnsetDisplayNameError::Persist(err),
        CommitError::Apply(ApplyError::UnknownUser(id)) => UnsetDisplayNameError::UnknownUser(id),
        CommitError::Apply(ApplyError::UnknownIdentity {
            user_id,
            identity_id,
        }) => UnsetDisplayNameError::UnknownIdentity {
            user_id,
            identity_id,
        },
        CommitError::Apply(_) => UnsetDisplayNameError::SeqOverflow,
    }
}

fn map_create_invite(err: CommitError) -> CreateInviteError {
    match err {
        CommitError::SeqOverflow => CreateInviteError::SeqOverflow,
        CommitError::Persist(err) => CreateInviteError::Persist(err),
        CommitError::Apply(ApplyError::UnknownUser(id)) => CreateInviteError::UnknownUser(id),
        CommitError::Apply(ApplyError::UnknownIdentity {
            user_id,
            identity_id,
        }) => CreateInviteError::UnknownIdentity {
            user_id,
            identity_id,
        },
        CommitError::Apply(ApplyError::DuplicateConversation {
            user_id,
            identity_id,
            conversation_id,
        }) => CreateInviteError::DuplicateConversation {
            user_id,
            identity_id,
            conversation_id,
        },
        CommitError::Apply(_) => CreateInviteError::SeqOverflow,
    }
}

fn map_mark_pinned(err: CommitError) -> MarkNoticesPinnedError {
    match err {
        CommitError::SeqOverflow => MarkNoticesPinnedError::SeqOverflow,
        CommitError::Persist(err) => MarkNoticesPinnedError::Persist(err),
        CommitError::Apply(ApplyError::UnknownUser(id)) => MarkNoticesPinnedError::UnknownUser(id),
        CommitError::Apply(ApplyError::UnknownIdentity {
            user_id,
            identity_id,
        }) => MarkNoticesPinnedError::UnknownIdentity {
            user_id,
            identity_id,
        },
        CommitError::Apply(ApplyError::UnknownConversation {
            user_id,
            identity_id,
            conversation_id,
        }) => MarkNoticesPinnedError::UnknownConversation {
            user_id,
            identity_id,
            conversation_id,
        },
        CommitError::Apply(ApplyError::UnexpectedPhase {
            user_id,
            identity_id,
            conversation_id,
            found,
        }) => MarkNoticesPinnedError::UnexpectedPhase {
            user_id,
            identity_id,
            conversation_id,
            found,
        },
        CommitError::Apply(_) => MarkNoticesPinnedError::SeqOverflow,
    }
}

fn map_receive_ticket(err: CommitError) -> ReceiveTicketError {
    match err {
        CommitError::SeqOverflow => ReceiveTicketError::SeqOverflow,
        CommitError::Persist(err) => ReceiveTicketError::Persist(err),
        CommitError::Apply(ApplyError::UnknownUser(id)) => ReceiveTicketError::UnknownUser(id),
        CommitError::Apply(ApplyError::UnknownIdentity {
            user_id,
            identity_id,
        }) => ReceiveTicketError::UnknownIdentity {
            user_id,
            identity_id,
        },
        CommitError::Apply(ApplyError::DuplicateConversation {
            user_id,
            identity_id,
            conversation_id,
        }) => ReceiveTicketError::DuplicateConversation {
            user_id,
            identity_id,
            conversation_id,
        },
        CommitError::Apply(_) => ReceiveTicketError::SeqOverflow,
    }
}

fn map_receive_notice(err: CommitError) -> ReceiveNoticeError {
    match err {
        CommitError::SeqOverflow => ReceiveNoticeError::SeqOverflow,
        CommitError::Persist(err) => ReceiveNoticeError::Persist(err),
        CommitError::Apply(ApplyError::UnknownUser(id)) => ReceiveNoticeError::UnknownUser(id),
        CommitError::Apply(ApplyError::UnknownIdentity {
            user_id,
            identity_id,
        }) => ReceiveNoticeError::UnknownIdentity {
            user_id,
            identity_id,
        },
        CommitError::Apply(ApplyError::UnknownConversation {
            user_id,
            identity_id,
            conversation_id,
        }) => ReceiveNoticeError::UnknownConversation {
            user_id,
            identity_id,
            conversation_id,
        },
        CommitError::Apply(ApplyError::UnexpectedPhase {
            user_id,
            identity_id,
            conversation_id,
            found,
        }) => ReceiveNoticeError::UnexpectedPhase {
            user_id,
            identity_id,
            conversation_id,
            found,
        },
        CommitError::Apply(_) => ReceiveNoticeError::SeqOverflow,
    }
}

#[cfg(test)]
mod map_tests {
    use super::*;
    use crate::protocol::v1::ConversationPhase;

    fn ids() -> (UserId, IdentityId, ConversationId) {
        (
            UserId::from_bytes([1; 32]),
            IdentityId::from_bytes([2; 32]),
            ConversationId::from_bytes([3; 32]),
        )
    }

    fn every_apply() -> [ApplyError; 8] {
        let (u, i, c) = ids();
        [
            ApplyError::UnknownUser(u),
            ApplyError::UnknownIdentity {
                user_id: u,
                identity_id: i,
            },
            ApplyError::UnknownConversation {
                user_id: u,
                identity_id: i,
                conversation_id: c,
            },
            ApplyError::DuplicateUser(u),
            ApplyError::DuplicateIdentity {
                user_id: u,
                identity_id: i,
            },
            ApplyError::DuplicateConversation {
                user_id: u,
                identity_id: i,
                conversation_id: c,
            },
            ApplyError::UnexpectedPhase {
                user_id: u,
                identity_id: i,
                conversation_id: c,
                found: ConversationPhase::Group,
            },
            ApplyError::SeqOverflow,
        ]
    }

    #[test]
    fn mappers_cover_commit_errors() {
        let persist = PersistError::TooShort;
        for apply in every_apply() {
            let _ = format!(
                "{}{}{}{}{}{}{}{}{}{}{}",
                map_create_user(CommitError::Apply(apply.clone())),
                map_create_identity(CommitError::Apply(apply.clone())),
                map_delete_user(CommitError::Apply(apply.clone())),
                map_delete_identity(CommitError::Apply(apply.clone())),
                map_delete_conversation(CommitError::Apply(apply.clone())),
                map_set_display_name(CommitError::Apply(apply.clone())),
                map_unset_display_name(CommitError::Apply(apply.clone())),
                map_create_invite(CommitError::Apply(apply.clone())),
                map_mark_pinned(CommitError::Apply(apply.clone())),
                map_receive_ticket(CommitError::Apply(apply.clone())),
                map_receive_notice(CommitError::Apply(apply.clone())),
            );
        }
        let _ = (
            map_create_user(CommitError::SeqOverflow),
            map_create_user(CommitError::Persist(persist.clone())),
            map_create_identity(CommitError::SeqOverflow),
            map_create_identity(CommitError::Persist(persist.clone())),
            map_delete_user(CommitError::SeqOverflow),
            map_delete_user(CommitError::Persist(persist.clone())),
            map_delete_identity(CommitError::SeqOverflow),
            map_delete_identity(CommitError::Persist(persist.clone())),
            map_delete_conversation(CommitError::SeqOverflow),
            map_delete_conversation(CommitError::Persist(persist.clone())),
            map_set_display_name(CommitError::SeqOverflow),
            map_set_display_name(CommitError::Persist(persist.clone())),
            map_unset_display_name(CommitError::SeqOverflow),
            map_unset_display_name(CommitError::Persist(persist.clone())),
            map_create_invite(CommitError::SeqOverflow),
            map_create_invite(CommitError::Persist(persist.clone())),
            map_mark_pinned(CommitError::SeqOverflow),
            map_mark_pinned(CommitError::Persist(persist.clone())),
            map_receive_ticket(CommitError::SeqOverflow),
            map_receive_ticket(CommitError::Persist(persist.clone())),
            map_receive_notice(CommitError::SeqOverflow),
            map_receive_notice(CommitError::Persist(persist)),
        );
        let (u, i, c) = ids();
        assert!(!format!("{}", ApplyError::UnknownUser(u)).is_empty());
        assert!(
            !format!(
                "{}",
                ApplyError::UnknownIdentity {
                    user_id: u,
                    identity_id: i
                }
            )
            .is_empty()
        );
        assert!(
            !format!(
                "{}",
                ApplyError::UnknownConversation {
                    user_id: u,
                    identity_id: i,
                    conversation_id: c
                }
            )
            .is_empty()
        );
        assert!(!format!("{}", ApplyError::DuplicateUser(u)).is_empty());
        assert!(
            !format!(
                "{}",
                ApplyError::DuplicateIdentity {
                    user_id: u,
                    identity_id: i
                }
            )
            .is_empty()
        );
        assert!(
            !format!(
                "{}",
                ApplyError::DuplicateConversation {
                    user_id: u,
                    identity_id: i,
                    conversation_id: c
                }
            )
            .is_empty()
        );
        assert!(
            !format!(
                "{}",
                ApplyError::UnexpectedPhase {
                    user_id: u,
                    identity_id: i,
                    conversation_id: c,
                    found: ConversationPhase::Failed
                }
            )
            .is_empty()
        );
    }
}
