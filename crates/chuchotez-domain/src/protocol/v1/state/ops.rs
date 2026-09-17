//! Named Engine methods that drive [`super::EngineState`].

use super::{
    ApplyError, CallingCard, Command, Conversation, ConversationId, CreateCallingCardError,
    CreateIdentityError, CreateInviteError, CreateUserError, DeleteConversationError,
    DeleteIdentityError, DeleteUserError, DirectMessage, DisplayName, EngineState, Failed,
    IdentityId, Invitee, Inviter, MarkNoticesPinnedError, PersistError, PersistedCommand,
    QueryError, ReceiveNoticeError, ReceiveTicketError, SetDisplayNameError, UnsetDisplayNameError,
    UserId,
};
use crate::protocol::v1::{
    AeadKey, Billboard, BillboardTag, IdentityKemKeypair, Invite, KemSeed, Mailbox, SignSeed, Wire,
    notice,
};
use crate::protocol::{Policy, Rng};

/// Success from a named method that drives [`EngineState`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistOk {
    /// Sealed Command.
    pub persist: PersistedCommand,
}

impl crate::protocol::v1::Engine {
    /// Insert a user. Draws [`UserId`] from `rng` and returns it.
    pub fn create_user(
        &self,
        state: EngineState,
        rng: &dyn Rng,
        dek: &AeadKey,
    ) -> (EngineState, UserId, Result<PersistOk, CreateUserError>) {
        let user_id = UserId::from_random32(rng.random32());
        if state.user(&user_id).is_some() {
            return (state, user_id, Err(CreateUserError::DuplicateUser(user_id)));
        }
        with_id(
            user_id,
            self.commit_persist(state, dek, Command::CreateUser { user_id })
                .map_err_state(map_create_user),
        )
    }

    /// Insert an identity under `user_id`. Draws [`IdentityId`] and keypair seeds from `rng` and returns the id.
    pub fn create_identity(
        &self,
        state: EngineState,
        rng: &dyn Rng,
        dek: &AeadKey,
        user_id: UserId,
    ) -> (
        EngineState,
        IdentityId,
        Result<PersistOk, CreateIdentityError>,
    ) {
        let identity_id = IdentityId::from_random32(rng.random32());
        match state.user(&user_id) {
            None => {
                return (
                    state,
                    identity_id,
                    Err(CreateIdentityError::UnknownUser(user_id)),
                );
            }
            Some(user) if user.identity(&identity_id).is_some() => {
                return (
                    state,
                    identity_id,
                    Err(CreateIdentityError::DuplicateIdentity {
                        user_id,
                        identity_id,
                    }),
                );
            }
            Some(_) => {}
        }
        let kem_seed = KemSeed::from_pair(rng.random32(), rng.random32());
        let intake = match self.kem().generate(self.policy(), &kem_seed) {
            Ok(keys) => keys,
            Err(err) => return (state, identity_id, Err(CreateIdentityError::Kem(err))),
        };
        let encryption = IdentityKemKeypair::from_parts(
            intake.public_bytes().to_vec(),
            intake.secret_bytes().to_vec(),
        );
        let sign_seed = SignSeed::from_pair(rng.random32(), rng.random32());
        let signing = match self.sign().generate(self.policy(), &sign_seed) {
            Ok(keys) => keys,
            Err(err) => return (state, identity_id, Err(CreateIdentityError::Sign(err))),
        };
        with_id(
            identity_id,
            self.commit_persist(
                state,
                dek,
                Command::CreateIdentity {
                    user_id,
                    identity_id,
                    encryption,
                    signing,
                },
            )
            .map_err_state(map_create_identity),
        )
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

    /// Mint an Invite into [`super::Inviter::InviteCreated`]. Returns the drawn
    /// [`ConversationId`].
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
    ) -> (
        EngineState,
        ConversationId,
        Result<PersistOk, CreateInviteError>,
    ) {
        let conversation_id = ConversationId::from_random32(rng.random32());
        match state.user(&user_id) {
            None => {
                return (
                    state,
                    conversation_id,
                    Err(CreateInviteError::UnknownUser(user_id)),
                );
            }
            Some(user) => match user.identity(&identity_id) {
                None => {
                    return (
                        state,
                        conversation_id,
                        Err(CreateInviteError::UnknownIdentity {
                            user_id,
                            identity_id,
                        }),
                    );
                }
                Some(identity) if identity.conversation(&conversation_id).is_some() => {
                    return (
                        state,
                        conversation_id,
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
            Err(err) => return (state, conversation_id, Err(CreateInviteError::Invite(err))),
        };
        with_id(
            conversation_id,
            self.commit_persist(
                state,
                dek,
                Command::CreateInvite {
                    user_id,
                    identity_id,
                    conversation_id,
                    invite,
                },
            )
            .map_err_state(map_create_invite),
        )
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
    /// Returns the drawn [`ConversationId`].
    pub fn receive_ticket(
        &self,
        state: EngineState,
        rng: &dyn Rng,
        dek: &AeadKey,
        user_id: UserId,
        identity_id: IdentityId,
        ticket_blob: &str,
    ) -> (
        EngineState,
        ConversationId,
        Result<PersistOk, ReceiveTicketError>,
    ) {
        let conversation_id = ConversationId::from_random32(rng.random32());
        let ticket = match self.try_parse_ticket(ticket_blob) {
            Ok(ticket) => ticket,
            Err(err) => {
                return (state, conversation_id, Err(ReceiveTicketError::Ticket(err)));
            }
        };
        match state.user(&user_id) {
            None => {
                return (
                    state,
                    conversation_id,
                    Err(ReceiveTicketError::UnknownUser(user_id)),
                );
            }
            Some(user) => match user.identity(&identity_id) {
                None => {
                    return (
                        state,
                        conversation_id,
                        Err(ReceiveTicketError::UnknownIdentity {
                            user_id,
                            identity_id,
                        }),
                    );
                }
                Some(identity) if identity.conversation(&conversation_id).is_some() => {
                    return (
                        state,
                        conversation_id,
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
        with_id(
            conversation_id,
            self.commit_persist(
                state,
                dek,
                Command::ReceiveTicket {
                    user_id,
                    identity_id,
                    conversation_id,
                    ticket,
                },
            )
            .map_err_state(map_receive_ticket),
        )
    }

    /// Open a Notice blob. Allowlist decides InviteReceived vs [`super::Failed`].
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
    ) -> (EngineState, Result<PersistOk, ReceiveNoticeError>) {
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
        match self.commit(state, dek, &cmd) {
            (state, Ok(persist)) => (state, Ok(PersistOk { persist })),
            (state, Err(err)) => (state, Err(map_receive_notice(err))),
        }
    }

    /// Mint a CallingCard from [`super::Invitee::InviteReceived`].
    #[allow(clippy::too_many_arguments)]
    pub fn create_calling_card(
        &self,
        state: EngineState,
        rng: &dyn Rng,
        dek: &AeadKey,
        user_id: UserId,
        identity_id: IdentityId,
        conversation_id: ConversationId,
        mailboxes: &[Mailbox],
        wires: &[Wire],
    ) -> (EngineState, Result<PersistOk, CreateCallingCardError>) {
        let identity = match state.user(&user_id) {
            None => return (state, Err(CreateCallingCardError::UnknownUser(user_id))),
            Some(user) => match user.identity(&identity_id) {
                None => {
                    return (
                        state,
                        Err(CreateCallingCardError::UnknownIdentity {
                            user_id,
                            identity_id,
                        }),
                    );
                }
                Some(identity) => identity,
            },
        };
        match identity.conversation(&conversation_id) {
            None => {
                return (
                    state,
                    Err(CreateCallingCardError::UnknownConversation {
                        user_id,
                        identity_id,
                        conversation_id,
                    }),
                );
            }
            Some(Conversation::DirectMessage(DirectMessage::Invitee(
                Invitee::InviteReceived { .. },
            ))) => {}
            Some(found) => {
                let found = found.phase();
                return (
                    state,
                    Err(CreateCallingCardError::UnexpectedPhase {
                        user_id,
                        identity_id,
                        conversation_id,
                        found,
                    }),
                );
            }
        }
        let display_name = match identity.display_name() {
            Some(name) => name.clone(),
            None => return (state, Err(CreateCallingCardError::UnsetDisplayName)),
        };
        let card = match self.try_new_calling_card(
            rng,
            display_name,
            identity.encryption().public_bytes().to_vec(),
            identity.signing().public_bytes().to_vec(),
            mailboxes.to_vec(),
            wires.to_vec(),
        ) {
            Ok(card) => card,
            Err(err) => return (state, Err(CreateCallingCardError::CallingCard(err))),
        };
        self.commit_persist(
            state,
            dek,
            Command::CreateCallingCard {
                user_id,
                identity_id,
                conversation_id,
                card,
            },
        )
        .map_err_state(map_create_calling_card)
    }

    /// Compact Ticket string for an Inviter conversation.
    pub fn ticket_blob(
        &self,
        state: &EngineState,
        user_id: UserId,
        identity_id: IdentityId,
        conversation_id: ConversationId,
    ) -> Result<String, QueryError> {
        Ok(lookup_invite(state, user_id, identity_id, conversation_id)?
            .ticket()
            .serialize(self))
    }

    /// Sealed Notice string for an Inviter conversation.
    pub fn notice_blob(
        &self,
        state: &EngineState,
        user_id: UserId,
        identity_id: IdentityId,
        conversation_id: ConversationId,
    ) -> Result<String, QueryError> {
        let invite = lookup_invite(state, user_id, identity_id, conversation_id)?;
        Ok(self.serialize_notice(invite.ticket(), invite.intake()))
    }

    /// Billboard tags, one per Billboard on the Ticket.
    pub fn billboard_tags(
        &self,
        state: &EngineState,
        user_id: UserId,
        identity_id: IdentityId,
        conversation_id: ConversationId,
    ) -> Result<Vec<BillboardTag>, QueryError> {
        let invite = lookup_invite(state, user_id, identity_id, conversation_id)?;
        let tag = invite.ticket().billboard_tag(self);
        Ok(invite
            .ticket()
            .billboards()
            .iter()
            .map(|_| tag.clone())
            .collect())
    }

    /// CallingCard for [`super::Invitee::CallingCardCreated`].
    pub fn calling_card<'a>(
        &self,
        state: &'a EngineState,
        user_id: UserId,
        identity_id: IdentityId,
        conversation_id: ConversationId,
    ) -> Result<&'a CallingCard, QueryError> {
        let _ = self;
        match lookup_conversation(state, user_id, identity_id, conversation_id) {
            Lookup::Ok(Conversation::DirectMessage(DirectMessage::Invitee(
                Invitee::CallingCardCreated { card, .. },
            ))) => Ok(card),
            Lookup::UnknownUser => Err(QueryError::UnknownUser(user_id)),
            Lookup::UnknownIdentity => Err(QueryError::UnknownIdentity {
                user_id,
                identity_id,
            }),
            Lookup::UnknownConversation => Err(QueryError::UnknownConversation {
                user_id,
                identity_id,
                conversation_id,
            }),
            Lookup::Ok(found) => Err(QueryError::UnexpectedPhase {
                user_id,
                identity_id,
                conversation_id,
                found: found.phase(),
            }),
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

fn with_id<Id, T, E>(
    id: Id,
    outcome: (EngineState, Result<T, E>),
) -> (EngineState, Id, Result<T, E>) {
    (outcome.0, id, outcome.1)
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

fn lookup_invite(
    state: &EngineState,
    user_id: UserId,
    identity_id: IdentityId,
    conversation_id: ConversationId,
) -> Result<&Invite, QueryError> {
    match lookup_conversation(state, user_id, identity_id, conversation_id) {
        Lookup::Ok(Conversation::DirectMessage(DirectMessage::Inviter(
            Inviter::InviteCreated { invite } | Inviter::NoticePinned { invite },
        ))) => Ok(invite),
        Lookup::UnknownUser => Err(QueryError::UnknownUser(user_id)),
        Lookup::UnknownIdentity => Err(QueryError::UnknownIdentity {
            user_id,
            identity_id,
        }),
        Lookup::UnknownConversation => Err(QueryError::UnknownConversation {
            user_id,
            identity_id,
            conversation_id,
        }),
        Lookup::Ok(found) => Err(QueryError::UnexpectedPhase {
            user_id,
            identity_id,
            conversation_id,
            found: found.phase(),
        }),
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

fn map_create_calling_card(err: CommitError) -> CreateCallingCardError {
    match err {
        CommitError::SeqOverflow => CreateCallingCardError::SeqOverflow,
        CommitError::Persist(err) => CreateCallingCardError::Persist(err),
        CommitError::Apply(ApplyError::UnknownUser(id)) => CreateCallingCardError::UnknownUser(id),
        CommitError::Apply(ApplyError::UnknownIdentity {
            user_id,
            identity_id,
        }) => CreateCallingCardError::UnknownIdentity {
            user_id,
            identity_id,
        },
        CommitError::Apply(ApplyError::UnknownConversation {
            user_id,
            identity_id,
            conversation_id,
        }) => CreateCallingCardError::UnknownConversation {
            user_id,
            identity_id,
            conversation_id,
        },
        CommitError::Apply(ApplyError::UnexpectedPhase {
            user_id,
            identity_id,
            conversation_id,
            found,
        }) => CreateCallingCardError::UnexpectedPhase {
            user_id,
            identity_id,
            conversation_id,
            found,
        },
        CommitError::Apply(_) => CreateCallingCardError::SeqOverflow,
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
                "{}{}{}{}{}{}{}{}{}{}{}{}",
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
                map_create_calling_card(CommitError::Apply(apply.clone())),
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
            map_receive_notice(CommitError::Persist(persist.clone())),
            map_create_calling_card(CommitError::SeqOverflow),
            map_create_calling_card(CommitError::Persist(persist)),
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
