//! Host-owned conversation tree: users, identities, conversations.

use super::CallingCard;
use super::{ConversationId, DisplayName, IdentityId, UserId};
use crate::protocol::v1::{IdentityKemKeypair, IdentitySignKeypair, Invite, Notice, Ticket};
use std::collections::BTreeMap;

/// Host-owned handle tree. Mutations go through [`crate::protocol::v1::Engine`] methods.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EngineState {
    users: BTreeMap<UserId, User>,
    command_seq: u64,
}

impl EngineState {
    /// Empty tree, `command_seq` 0.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Users keyed by [`UserId`].
    #[must_use]
    pub const fn users(&self) -> &BTreeMap<UserId, User> {
        &self.users
    }

    /// Next persist-command sequence (AEAD nonce / AAD).
    #[must_use]
    pub const fn command_seq(&self) -> u64 {
        self.command_seq
    }

    /// Look up a user.
    #[must_use]
    pub fn user(&self, id: &UserId) -> Option<&User> {
        self.users.get(id)
    }

    pub(crate) fn users_mut(&mut self) -> &mut BTreeMap<UserId, User> {
        &mut self.users
    }

    pub(crate) fn set_command_seq(&mut self, seq: u64) {
        self.command_seq = seq;
    }

    #[cfg(test)]
    pub(crate) fn with_command_seq(mut self, seq: u64) -> Self {
        self.command_seq = seq;
        self
    }
}

/// Account slot: a map of identities.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct User {
    identities: BTreeMap<IdentityId, Identity>,
}

impl User {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Identities keyed by [`IdentityId`].
    #[must_use]
    pub const fn identities(&self) -> &BTreeMap<IdentityId, Identity> {
        &self.identities
    }

    /// Look up an identity.
    #[must_use]
    pub fn identity(&self, id: &IdentityId) -> Option<&Identity> {
        self.identities.get(id)
    }

    pub(crate) fn identities_mut(&mut self) -> &mut BTreeMap<IdentityId, Identity> {
        &mut self.identities
    }
}

/// Local persona with Policy-matched encryption and signing keypairs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identity {
    display_name: Option<DisplayName>,
    encryption: IdentityKemKeypair,
    signing: IdentitySignKeypair,
    conversations: BTreeMap<ConversationId, Conversation>,
}

impl Identity {
    pub(crate) fn new(encryption: IdentityKemKeypair, signing: IdentitySignKeypair) -> Self {
        Self {
            display_name: None,
            encryption,
            signing,
            conversations: BTreeMap::new(),
        }
    }

    /// Preferred display name. `None` at create.
    #[must_use]
    pub const fn display_name(&self) -> Option<&DisplayName> {
        self.display_name.as_ref()
    }

    /// Identity encryption keypair.
    #[must_use]
    pub const fn encryption(&self) -> &IdentityKemKeypair {
        &self.encryption
    }

    /// Identity signing keypair.
    #[must_use]
    pub const fn signing(&self) -> &IdentitySignKeypair {
        &self.signing
    }

    /// Conversations keyed by [`ConversationId`].
    #[must_use]
    pub const fn conversations(&self) -> &BTreeMap<ConversationId, Conversation> {
        &self.conversations
    }

    /// Look up a conversation.
    #[must_use]
    pub fn conversation(&self, id: &ConversationId) -> Option<&Conversation> {
        self.conversations.get(id)
    }

    pub(crate) fn set_display_name(&mut self, name: Option<DisplayName>) {
        self.display_name = name;
    }

    pub(crate) fn conversations_mut(&mut self) -> &mut BTreeMap<ConversationId, Conversation> {
        &mut self.conversations
    }
}

/// Conversation ADT. Group and Synchronization are placeholders this slice.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum Conversation {
    /// Direct-message handshake and session.
    DirectMessage(DirectMessage),
    /// Group conversation. Uninhabited this slice.
    Group(Group),
    /// Sync among one user's identities. Uninhabited this slice.
    Synchronization(Synchronization),
}

/// Direct-message conversation phases.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirectMessage {
    /// This identity minted the Invite.
    Inviter(Inviter),
    /// This identity received a Ticket (and maybe a Notice).
    Invitee(Invitee),
    /// Handshake complete. Uninhabited this slice.
    Established(Established),
    /// Terminal failure.
    Failed(Failed),
}

/// Inviter-side DM phases.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Inviter {
    /// Invite minted. Notice is not yet pinned on every Billboard.
    InviteCreated {
        /// Ticket plus Intake.
        invite: Invite,
    },
    /// Notice pinned on every Billboard in the Invite. Ticket may be presented.
    NoticePinned {
        /// Ticket plus Intake.
        invite: Invite,
    },
}

/// Invitee-side DM phases.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Invitee {
    /// Compact Ticket parsed.
    TicketReceived {
        /// QR capability.
        ticket: Ticket,
    },
    /// Notice opened. Public Intake artifacts are present.
    InviteReceived {
        /// QR capability.
        ticket: Ticket,
        /// Billboard plaintext.
        notice: Notice,
    },
    /// Local CallingCard minted. Wrap and send are a later slice.
    CallingCardCreated {
        /// QR capability.
        ticket: Ticket,
        /// Billboard plaintext.
        notice: Notice,
        /// Minted card.
        card: CallingCard,
    },
}

/// Handshake complete. No fields this slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Established;

/// Group conversation. No fields this slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Group;

/// Sync conversation. No fields this slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Synchronization;

/// Terminal DM failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Failed {
    /// Notice Policy was outside the host allowlist.
    PolicyNotAccepted {
        /// Compact Ticket used to open the Notice.
        ticket: Ticket,
        /// Opened Notice. [`Notice::policy`] is the found Policy.
        notice: Notice,
    },
}

/// Leaf name of a [`Conversation`] for unexpected-phase errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversationPhase {
    /// [`Inviter::InviteCreated`].
    InviterInviteCreated,
    /// [`Inviter::NoticePinned`].
    InviterNoticePinned,
    /// [`Invitee::TicketReceived`].
    InviteeTicketReceived,
    /// [`Invitee::InviteReceived`].
    InviteeInviteReceived,
    /// [`Invitee::CallingCardCreated`].
    InviteeCallingCardCreated,
    /// [`DirectMessage::Established`].
    Established,
    /// [`DirectMessage::Failed`].
    Failed,
    /// [`Conversation::Group`].
    Group,
    /// [`Conversation::Synchronization`].
    Synchronization,
}

impl Conversation {
    /// Phase tag for errors.
    #[must_use]
    pub const fn phase(&self) -> ConversationPhase {
        match self {
            Self::DirectMessage(DirectMessage::Inviter(Inviter::InviteCreated { .. })) => {
                ConversationPhase::InviterInviteCreated
            }
            Self::DirectMessage(DirectMessage::Inviter(Inviter::NoticePinned { .. })) => {
                ConversationPhase::InviterNoticePinned
            }
            Self::DirectMessage(DirectMessage::Invitee(Invitee::TicketReceived { .. })) => {
                ConversationPhase::InviteeTicketReceived
            }
            Self::DirectMessage(DirectMessage::Invitee(Invitee::InviteReceived { .. })) => {
                ConversationPhase::InviteeInviteReceived
            }
            Self::DirectMessage(DirectMessage::Invitee(Invitee::CallingCardCreated { .. })) => {
                ConversationPhase::InviteeCallingCardCreated
            }
            Self::DirectMessage(DirectMessage::Established(_)) => ConversationPhase::Established,
            Self::DirectMessage(DirectMessage::Failed(_)) => ConversationPhase::Failed,
            Self::Group(_) => ConversationPhase::Group,
            Self::Synchronization(_) => ConversationPhase::Synchronization,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Conversation, ConversationPhase, DirectMessage, EngineState, Established, Failed, Group,
        Identity, Invitee, Inviter, Synchronization, User,
    };
    use crate::protocol::v1::fixtures;

    #[test]
    fn empty_state_and_placeholders() {
        let state = EngineState::new();
        assert!(state.users().is_empty());
        assert_eq!(state.command_seq(), 0);
        assert_eq!(state, EngineState::default());
        assert!(
            state
                .user(&crate::protocol::v1::UserId::from_bytes([0; 32]))
                .is_none()
        );
        let user = User::new();
        assert!(user.identities().is_empty());
        let identity = Identity::new(
            crate::protocol::v1::IdentityKemKeypair::from_parts(vec![1], vec![2]),
            crate::protocol::v1::IdentitySignKeypair::from_parts(vec![3], vec![4]),
        );
        assert!(identity.display_name().is_none());
        assert_eq!(identity.encryption().public_bytes(), &[1]);
        assert_eq!(identity.signing().public_bytes(), &[3]);
        assert!(identity.display_name().is_none());
        assert!(identity.conversations().is_empty());
        let g = Conversation::Group(Group);
        assert_eq!(g.phase(), ConversationPhase::Group);
        let s = Conversation::Synchronization(Synchronization);
        assert_eq!(s.phase(), ConversationPhase::Synchronization);
        let e = Conversation::DirectMessage(DirectMessage::Established(Established));
        assert_eq!(e.phase(), ConversationPhase::Established);
        let _ = (
            g.clone(),
            s.clone(),
            e.clone(),
            user.clone(),
            identity.clone(),
        );
        let _ = format!("{g:?}{s:?}{e:?}");
        let _ = EngineState::new().with_command_seq(3);
        let _ = fixtures::sample_billboard();
        let _ = Failed::PolicyNotAccepted {
            ticket: fixtures::sample_ticket(1),
            notice: crate::protocol::v1::Notice::from_intake(crate::protocol::Policy::Hybrid, &{
                let engine = fixtures::test_engine();
                engine
                    .try_new_invite(
                        &fixtures::SeedRng(fixtures::fill(0x11)),
                        &[fixtures::sample_billboard()],
                        &[fixtures::sample_mailbox()],
                        &[],
                    )
                    .expect("invite")
                    .intake()
                    .clone()
            }),
        };
        let dm = Conversation::DirectMessage(DirectMessage::Inviter(Inviter::InviteCreated {
            invite: fixtures::test_engine()
                .try_new_invite(
                    &fixtures::SeedRng(fixtures::fill(0x11)),
                    &[fixtures::sample_billboard()],
                    &[fixtures::sample_mailbox()],
                    &[],
                )
                .expect("invite"),
        }));
        assert_eq!(dm.phase(), ConversationPhase::InviterInviteCreated);
        let pinned = Conversation::DirectMessage(DirectMessage::Inviter(Inviter::NoticePinned {
            invite: fixtures::test_engine()
                .try_new_invite(
                    &fixtures::SeedRng(fixtures::fill(0x11)),
                    &[fixtures::sample_billboard()],
                    &[fixtures::sample_mailbox()],
                    &[],
                )
                .expect("invite"),
        }));
        assert_eq!(pinned.phase(), ConversationPhase::InviterNoticePinned);
        let tr = Conversation::DirectMessage(DirectMessage::Invitee(Invitee::TicketReceived {
            ticket: fixtures::sample_ticket(2),
        }));
        assert_eq!(tr.phase(), ConversationPhase::InviteeTicketReceived);
        let notice = crate::protocol::v1::Notice::from_intake(crate::protocol::Policy::Hybrid, &{
            let engine = fixtures::test_engine();
            engine
                .try_new_invite(
                    &fixtures::SeedRng(fixtures::fill(0x11)),
                    &[fixtures::sample_billboard()],
                    &[fixtures::sample_mailbox()],
                    &[],
                )
                .expect("invite")
                .intake()
                .clone()
        });
        let ir = Conversation::DirectMessage(DirectMessage::Invitee(Invitee::InviteReceived {
            ticket: fixtures::sample_ticket(2),
            notice: notice.clone(),
        }));
        assert_eq!(ir.phase(), ConversationPhase::InviteeInviteReceived);
        let card = crate::protocol::v1::CallingCard::from_parts(
            crate::protocol::v1::DisplayName::try_from("Ada").expect("name"),
            vec![1],
            vec![2],
            crate::protocol::v1::MailboxTagKey::from_bytes([7; 32]),
            vec![fixtures::sample_mailbox()],
            Vec::new(),
        )
        .expect("card");
        let cc = Conversation::DirectMessage(DirectMessage::Invitee(Invitee::CallingCardCreated {
            ticket: fixtures::sample_ticket(2),
            notice,
            card,
        }));
        assert_eq!(cc.phase(), ConversationPhase::InviteeCallingCardCreated);
        let failed =
            Conversation::DirectMessage(DirectMessage::Failed(Failed::PolicyNotAccepted {
                ticket: fixtures::sample_ticket(1),
                notice: crate::protocol::v1::Notice::from_intake(
                    crate::protocol::Policy::Hybrid,
                    &{
                        let engine = fixtures::test_engine();
                        engine
                            .try_new_invite(
                                &fixtures::SeedRng(fixtures::fill(0x11)),
                                &[fixtures::sample_billboard()],
                                &[fixtures::sample_mailbox()],
                                &[],
                            )
                            .expect("invite")
                            .intake()
                            .clone()
                    },
                ),
            }));
        assert_eq!(failed.phase(), ConversationPhase::Failed);
    }
}
