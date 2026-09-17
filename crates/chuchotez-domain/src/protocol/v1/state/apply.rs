//! Deterministic [`super::Command`] application.

use super::{
    ApplyError, Command, Conversation, ConversationId, DirectMessage, EngineState, Identity,
    IdentityId, Invitee, Inviter, User, UserId,
};

impl crate::protocol::v1::Engine {
    /// Fold `command` into `state`. No entropy. On `Err`, returned state is unchanged.
    pub fn apply(
        &self,
        mut state: EngineState,
        command: &Command,
    ) -> (EngineState, Result<(), ApplyError>) {
        if state.command_seq() == u64::MAX {
            return (state, Err(ApplyError::SeqOverflow));
        }
        match apply_inner(&mut state, command) {
            Ok(()) => {
                state.set_command_seq(state.command_seq() + 1);
                (state, Ok(()))
            }
            Err(err) => (state, Err(err)),
        }
    }
}

fn apply_inner(state: &mut EngineState, command: &Command) -> Result<(), ApplyError> {
    match command {
        Command::CreateUser { user_id } => {
            if state.users().contains_key(user_id) {
                return Err(ApplyError::DuplicateUser(*user_id));
            }
            state.users_mut().insert(*user_id, User::new());
            Ok(())
        }
        Command::CreateIdentity {
            user_id,
            identity_id,
            encryption,
            signing,
        } => {
            let user = user_mut(state, user_id)?;
            if user.identities().contains_key(identity_id) {
                return Err(ApplyError::DuplicateIdentity {
                    user_id: *user_id,
                    identity_id: *identity_id,
                });
            }
            user.identities_mut().insert(
                *identity_id,
                Identity::new(encryption.clone(), signing.clone()),
            );
            Ok(())
        }
        Command::DeleteUser { user_id } => {
            if state.users_mut().remove(user_id).is_none() {
                return Err(ApplyError::UnknownUser(*user_id));
            }
            Ok(())
        }
        Command::DeleteIdentity {
            user_id,
            identity_id,
        } => {
            let user = user_mut(state, user_id)?;
            if user.identities_mut().remove(identity_id).is_none() {
                return Err(ApplyError::UnknownIdentity {
                    user_id: *user_id,
                    identity_id: *identity_id,
                });
            }
            Ok(())
        }
        Command::DeleteConversation {
            user_id,
            identity_id,
            conversation_id,
        } => {
            let identity = identity_mut(state, user_id, identity_id)?;
            if identity
                .conversations_mut()
                .remove(conversation_id)
                .is_none()
            {
                return Err(ApplyError::UnknownConversation {
                    user_id: *user_id,
                    identity_id: *identity_id,
                    conversation_id: *conversation_id,
                });
            }
            Ok(())
        }
        Command::SetDisplayName {
            user_id,
            identity_id,
            name,
        } => {
            let identity = identity_mut(state, user_id, identity_id)?;
            identity.set_display_name(Some(name.clone()));
            Ok(())
        }
        Command::UnsetDisplayName {
            user_id,
            identity_id,
        } => {
            let identity = identity_mut(state, user_id, identity_id)?;
            identity.set_display_name(None);
            Ok(())
        }
        Command::CreateInvite {
            user_id,
            identity_id,
            conversation_id,
            invite,
        } => {
            let identity = identity_mut(state, user_id, identity_id)?;
            if identity.conversations().contains_key(conversation_id) {
                return Err(ApplyError::DuplicateConversation {
                    user_id: *user_id,
                    identity_id: *identity_id,
                    conversation_id: *conversation_id,
                });
            }
            identity.conversations_mut().insert(
                *conversation_id,
                Conversation::DirectMessage(DirectMessage::Inviter(Inviter::InviteCreated {
                    invite: invite.clone(),
                })),
            );
            Ok(())
        }
        Command::MarkNoticesPinned {
            user_id,
            identity_id,
            conversation_id,
        } => {
            let identity = identity_mut(state, user_id, identity_id)?;
            let conversation = conversation_mut(identity, user_id, identity_id, conversation_id)?;
            let Conversation::DirectMessage(DirectMessage::Inviter(Inviter::InviteCreated {
                invite,
            })) = conversation
            else {
                return Err(ApplyError::UnexpectedPhase {
                    user_id: *user_id,
                    identity_id: *identity_id,
                    conversation_id: *conversation_id,
                    found: conversation.phase(),
                });
            };
            *conversation =
                Conversation::DirectMessage(DirectMessage::Inviter(Inviter::NoticePinned {
                    invite: invite.clone(),
                }));
            Ok(())
        }
        Command::ReceiveTicket {
            user_id,
            identity_id,
            conversation_id,
            ticket,
        } => {
            let identity = identity_mut(state, user_id, identity_id)?;
            if identity.conversations().contains_key(conversation_id) {
                return Err(ApplyError::DuplicateConversation {
                    user_id: *user_id,
                    identity_id: *identity_id,
                    conversation_id: *conversation_id,
                });
            }
            identity.conversations_mut().insert(
                *conversation_id,
                Conversation::DirectMessage(DirectMessage::Invitee(Invitee::TicketReceived {
                    ticket: ticket.clone(),
                })),
            );
            Ok(())
        }
        Command::ReceiveNotice {
            user_id,
            identity_id,
            conversation_id,
            notice,
        } => {
            let identity = identity_mut(state, user_id, identity_id)?;
            let conversation = conversation_mut(identity, user_id, identity_id, conversation_id)?;
            let Conversation::DirectMessage(DirectMessage::Invitee(Invitee::TicketReceived {
                ticket,
            })) = conversation
            else {
                return Err(ApplyError::UnexpectedPhase {
                    user_id: *user_id,
                    identity_id: *identity_id,
                    conversation_id: *conversation_id,
                    found: conversation.phase(),
                });
            };
            *conversation =
                Conversation::DirectMessage(DirectMessage::Invitee(Invitee::InviteReceived {
                    ticket: ticket.clone(),
                    notice: notice.clone(),
                }));
            Ok(())
        }
        Command::FailConversation {
            user_id,
            identity_id,
            conversation_id,
            failed,
        } => {
            let identity = identity_mut(state, user_id, identity_id)?;
            let conversation = conversation_mut(identity, user_id, identity_id, conversation_id)?;
            let Conversation::DirectMessage(DirectMessage::Invitee(Invitee::TicketReceived {
                ..
            })) = conversation
            else {
                return Err(ApplyError::UnexpectedPhase {
                    user_id: *user_id,
                    identity_id: *identity_id,
                    conversation_id: *conversation_id,
                    found: conversation.phase(),
                });
            };
            *conversation = Conversation::DirectMessage(DirectMessage::Failed(failed.clone()));
            Ok(())
        }
        Command::CreateCallingCard {
            user_id,
            identity_id,
            conversation_id,
            card,
        } => {
            let identity = identity_mut(state, user_id, identity_id)?;
            let conversation = conversation_mut(identity, user_id, identity_id, conversation_id)?;
            let Conversation::DirectMessage(DirectMessage::Invitee(Invitee::InviteReceived {
                ticket,
                notice,
            })) = conversation
            else {
                return Err(ApplyError::UnexpectedPhase {
                    user_id: *user_id,
                    identity_id: *identity_id,
                    conversation_id: *conversation_id,
                    found: conversation.phase(),
                });
            };
            *conversation =
                Conversation::DirectMessage(DirectMessage::Invitee(Invitee::CallingCardCreated {
                    ticket: ticket.clone(),
                    notice: notice.clone(),
                    card: card.clone(),
                }));
            Ok(())
        }
    }
}

fn user_mut<'a>(state: &'a mut EngineState, user_id: &UserId) -> Result<&'a mut User, ApplyError> {
    state
        .users_mut()
        .get_mut(user_id)
        .ok_or(ApplyError::UnknownUser(*user_id))
}

fn identity_mut<'a>(
    state: &'a mut EngineState,
    user_id: &UserId,
    identity_id: &IdentityId,
) -> Result<&'a mut Identity, ApplyError> {
    let user = user_mut(state, user_id)?;
    user.identities_mut()
        .get_mut(identity_id)
        .ok_or(ApplyError::UnknownIdentity {
            user_id: *user_id,
            identity_id: *identity_id,
        })
}

fn conversation_mut<'a>(
    identity: &'a mut Identity,
    user_id: &UserId,
    identity_id: &IdentityId,
    conversation_id: &ConversationId,
) -> Result<&'a mut Conversation, ApplyError> {
    identity
        .conversations_mut()
        .get_mut(conversation_id)
        .ok_or(ApplyError::UnknownConversation {
            user_id: *user_id,
            identity_id: *identity_id,
            conversation_id: *conversation_id,
        })
}
