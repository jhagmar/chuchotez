//! Handshake phases. Each variant holds the secrets that exist in that phase.

use super::super::kem::KeyPair;
use super::super::payload::Ticket;
use super::super::{Policy, Secret, TimeBin};
use super::query::FailedReason;

/// Failure stored on a handshake. Group reasons are not members.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HandshakeFailure {
    PolicyNotAccepted { policy: Policy },
    InviteExpired { expires: super::super::UnixSeconds },
    NoticeUnlockFailed,
    NoticeConflict,
    IntroUnlockFailed,
    IntroVerifyFailed,
    DuplicateIntro,
    ConfirmationRejected,
    Equivocation,
}

impl From<HandshakeFailure> for FailedReason {
    fn from(value: HandshakeFailure) -> Self {
        match value {
            HandshakeFailure::PolicyNotAccepted { policy } => {
                FailedReason::PolicyNotAccepted { policy }
            }
            HandshakeFailure::InviteExpired { expires } => FailedReason::InviteExpired { expires },
            HandshakeFailure::NoticeUnlockFailed => FailedReason::NoticeUnlockFailed,
            HandshakeFailure::NoticeConflict => FailedReason::NoticeConflict,
            HandshakeFailure::IntroUnlockFailed => FailedReason::IntroUnlockFailed,
            HandshakeFailure::IntroVerifyFailed => FailedReason::IntroVerifyFailed,
            HandshakeFailure::DuplicateIntro => FailedReason::DuplicateIntro,
            HandshakeFailure::ConfirmationRejected => FailedReason::ConfirmationRejected,
            HandshakeFailure::Equivocation => FailedReason::Equivocation,
        }
    }
}

/// Inviter handshake phases.
#[derive(Clone, Debug)]
pub(super) enum InviterPhase {
    InviteCreated {
        ticket: Ticket,
        intake: KeyPair,
        list_from: TimeBin,
    },
    NoticePinned {
        ticket: Ticket,
        intake: KeyPair,
        list_from: TimeBin,
    },
    IntroductionMinted {
        ticket: Ticket,
        intake: KeyPair,
        shared_inviter: Secret,
        shared_invitee: Secret,
        list_from: TimeBin,
    },
    Confirming {
        ticket: Ticket,
        intake: KeyPair,
        shared_inviter: Secret,
        shared_invitee: Secret,
        list_from: TimeBin,
    },
    Failed {
        ticket: Ticket,
        list_from: TimeBin,
        reason: HandshakeFailure,
    },
}

impl InviterPhase {
    pub(super) fn ticket(&self) -> &Ticket {
        match self {
            Self::InviteCreated { ticket, .. }
            | Self::NoticePinned { ticket, .. }
            | Self::IntroductionMinted { ticket, .. }
            | Self::Confirming { ticket, .. }
            | Self::Failed { ticket, .. } => ticket,
        }
    }

    pub(super) fn list_from(&self) -> TimeBin {
        match self {
            Self::InviteCreated { list_from, .. }
            | Self::NoticePinned { list_from, .. }
            | Self::IntroductionMinted { list_from, .. }
            | Self::Confirming { list_from, .. }
            | Self::Failed { list_from, .. } => *list_from,
        }
    }

    pub(super) fn intake(&self) -> Option<&KeyPair> {
        match self {
            Self::InviteCreated { intake, .. }
            | Self::NoticePinned { intake, .. }
            | Self::IntroductionMinted { intake, .. }
            | Self::Confirming { intake, .. } => Some(intake),
            Self::Failed { .. } => None,
        }
    }

    pub(super) fn shared_inviter(&self) -> Option<&Secret> {
        match self {
            Self::IntroductionMinted { shared_inviter, .. }
            | Self::Confirming { shared_inviter, .. } => Some(shared_inviter),
            _ => None,
        }
    }

    pub(super) fn shared_invitee(&self) -> Option<&Secret> {
        match self {
            Self::IntroductionMinted { shared_invitee, .. }
            | Self::Confirming { shared_invitee, .. } => Some(shared_invitee),
            _ => None,
        }
    }

    pub(super) fn failure(&self) -> Option<HandshakeFailure> {
        match self {
            Self::Failed { reason, .. } => Some(*reason),
            _ => None,
        }
    }

    /// `InviteCreated` becomes `NoticePinned` once invite-tag writes are acked.
    pub(super) fn ack_notice(&mut self) {
        if let Self::InviteCreated {
            ticket,
            intake,
            list_from,
        } = self
        {
            *self = Self::NoticePinned {
                ticket: ticket.clone(),
                intake: intake.clone(),
                list_from: *list_from,
            };
        }
    }

    /// `IntroductionMinted` becomes `Confirming` once intro writes are acked.
    pub(super) fn ack_intro(&mut self) {
        if let Self::IntroductionMinted {
            ticket,
            intake,
            shared_inviter,
            shared_invitee,
            list_from,
        } = self
        {
            *self = Self::Confirming {
                ticket: ticket.clone(),
                intake: intake.clone(),
                shared_inviter: *shared_inviter,
                shared_invitee: *shared_invitee,
                list_from: *list_from,
            };
        }
    }

    /// `NoticePinned` becomes `IntroductionMinted` with both shared secrets.
    pub(super) fn mint_intro(&mut self, shared_inviter: Secret, shared_invitee: Secret) -> bool {
        if let Self::NoticePinned {
            ticket,
            intake,
            list_from,
        } = self
        {
            *self = Self::IntroductionMinted {
                ticket: ticket.clone(),
                intake: intake.clone(),
                shared_inviter,
                shared_invitee,
                list_from: *list_from,
            };
            true
        } else {
            false
        }
    }

    pub(super) fn fail(&mut self, reason: HandshakeFailure) {
        if matches!(self, Self::Failed { .. }) {
            return;
        }
        let ticket = self.ticket().clone();
        let list_from = self.list_from();
        *self = Self::Failed {
            ticket,
            list_from,
            reason,
        };
    }
}

/// Invitee handshake phases.
#[derive(Clone, Debug)]
pub(super) enum InviteePhase {
    TicketReceived {
        ticket: Ticket,
        list_from: TimeBin,
    },
    InviteReceived {
        ticket: Ticket,
        list_from: TimeBin,
        policy: Policy,
    },
    IntroductionMinted {
        ticket: Ticket,
        list_from: TimeBin,
        policy: Policy,
        intake: KeyPair,
        shared_inviter: Secret,
    },
    IntroductionSent {
        ticket: Ticket,
        list_from: TimeBin,
        policy: Policy,
        intake: KeyPair,
        shared_inviter: Secret,
    },
    Confirming {
        ticket: Ticket,
        list_from: TimeBin,
        policy: Policy,
        intake: KeyPair,
        shared_inviter: Secret,
        shared_invitee: Secret,
    },
    Failed {
        ticket: Ticket,
        list_from: TimeBin,
        reason: HandshakeFailure,
    },
}

impl InviteePhase {
    pub(super) fn ticket(&self) -> &Ticket {
        match self {
            Self::TicketReceived { ticket, .. }
            | Self::InviteReceived { ticket, .. }
            | Self::IntroductionMinted { ticket, .. }
            | Self::IntroductionSent { ticket, .. }
            | Self::Confirming { ticket, .. }
            | Self::Failed { ticket, .. } => ticket,
        }
    }

    pub(super) fn list_from(&self) -> TimeBin {
        match self {
            Self::TicketReceived { list_from, .. }
            | Self::InviteReceived { list_from, .. }
            | Self::IntroductionMinted { list_from, .. }
            | Self::IntroductionSent { list_from, .. }
            | Self::Confirming { list_from, .. }
            | Self::Failed { list_from, .. } => *list_from,
        }
    }

    pub(super) fn policy(&self) -> Option<Policy> {
        match self {
            Self::InviteReceived { policy, .. }
            | Self::IntroductionMinted { policy, .. }
            | Self::IntroductionSent { policy, .. }
            | Self::Confirming { policy, .. } => Some(*policy),
            _ => None,
        }
    }

    pub(super) fn intake(&self) -> Option<&KeyPair> {
        match self {
            Self::IntroductionMinted { intake, .. }
            | Self::IntroductionSent { intake, .. }
            | Self::Confirming { intake, .. } => Some(intake),
            _ => None,
        }
    }

    pub(super) fn shared_inviter(&self) -> Option<&Secret> {
        match self {
            Self::IntroductionMinted { shared_inviter, .. }
            | Self::IntroductionSent { shared_inviter, .. }
            | Self::Confirming { shared_inviter, .. } => Some(shared_inviter),
            _ => None,
        }
    }

    pub(super) fn shared_invitee(&self) -> Option<&Secret> {
        match self {
            Self::Confirming { shared_invitee, .. } => Some(shared_invitee),
            _ => None,
        }
    }

    pub(super) fn failure(&self) -> Option<HandshakeFailure> {
        match self {
            Self::Failed { reason, .. } => Some(*reason),
            _ => None,
        }
    }

    pub(super) fn receive_notice(&mut self, policy: Policy) -> bool {
        if let Self::TicketReceived { ticket, list_from } = self {
            *self = Self::InviteReceived {
                ticket: ticket.clone(),
                list_from: *list_from,
                policy,
            };
            true
        } else {
            false
        }
    }

    pub(super) fn ack_intro(&mut self) {
        if let Self::IntroductionMinted {
            ticket,
            list_from,
            policy,
            intake,
            shared_inviter,
        } = self
        {
            *self = Self::IntroductionSent {
                ticket: ticket.clone(),
                list_from: *list_from,
                policy: *policy,
                intake: intake.clone(),
                shared_inviter: *shared_inviter,
            };
        }
    }

    pub(super) fn mint_intro(&mut self, intake: KeyPair, shared_inviter: Secret) -> bool {
        if let Self::InviteReceived {
            ticket,
            list_from,
            policy,
        } = self
        {
            *self = Self::IntroductionMinted {
                ticket: ticket.clone(),
                list_from: *list_from,
                policy: *policy,
                intake,
                shared_inviter,
            };
            true
        } else {
            false
        }
    }

    /// Inviter intro accepted from `IntroductionMinted` or `IntroductionSent`.
    pub(super) fn confirm_peer(&mut self, shared_invitee: Secret) -> bool {
        match self {
            Self::IntroductionMinted {
                ticket,
                list_from,
                policy,
                intake,
                shared_inviter,
            }
            | Self::IntroductionSent {
                ticket,
                list_from,
                policy,
                intake,
                shared_inviter,
            } => {
                *self = Self::Confirming {
                    ticket: ticket.clone(),
                    list_from: *list_from,
                    policy: *policy,
                    intake: intake.clone(),
                    shared_inviter: *shared_inviter,
                    shared_invitee,
                };
                true
            }
            _ => false,
        }
    }

    pub(super) fn fail(&mut self, reason: HandshakeFailure) {
        if matches!(self, Self::Failed { .. }) {
            return;
        }
        let ticket = self.ticket().clone();
        let list_from = self.list_from();
        *self = Self::Failed {
            ticket,
            list_from,
            reason,
        };
    }
}

macro_rules! party_impl {
    ($name:ident) => {
        impl $name {
            pub(super) fn inviter(phase: InviterPhase) -> Self {
                Self::Inviter(phase)
            }

            pub(super) fn invitee(phase: InviteePhase) -> Self {
                Self::Invitee(phase)
            }

            pub(super) fn ticket(&self) -> &Ticket {
                match self {
                    Self::Inviter(p) => p.ticket(),
                    Self::Invitee(p) => p.ticket(),
                }
            }

            pub(super) fn list_from(&self) -> TimeBin {
                match self {
                    Self::Inviter(p) => p.list_from(),
                    Self::Invitee(p) => p.list_from(),
                }
            }

            pub(super) fn intake(&self) -> Option<&KeyPair> {
                match self {
                    Self::Inviter(p) => p.intake(),
                    Self::Invitee(p) => p.intake(),
                }
            }

            pub(super) fn shared_inviter(&self) -> Option<&Secret> {
                match self {
                    Self::Inviter(p) => p.shared_inviter(),
                    Self::Invitee(p) => p.shared_inviter(),
                }
            }

            pub(super) fn shared_invitee(&self) -> Option<&Secret> {
                match self {
                    Self::Inviter(p) => p.shared_invitee(),
                    Self::Invitee(p) => p.shared_invitee(),
                }
            }

            pub(super) fn failure(&self) -> Option<HandshakeFailure> {
                match self {
                    Self::Inviter(p) => p.failure(),
                    Self::Invitee(p) => p.failure(),
                }
            }

            pub(super) fn is_inviter(&self) -> bool {
                matches!(self, Self::Inviter(_))
            }

            pub(super) fn ack_posted(&mut self) {
                match self {
                    Self::Inviter(p) => {
                        p.ack_notice();
                        p.ack_intro();
                    }
                    Self::Invitee(p) => p.ack_intro(),
                }
            }

            pub(super) fn fail(&mut self, reason: HandshakeFailure) {
                match self {
                    Self::Inviter(p) => p.fail(reason),
                    Self::Invitee(p) => p.fail(reason),
                }
            }

            pub(super) fn inviter_mut(&mut self) -> Option<&mut InviterPhase> {
                match self {
                    Self::Inviter(p) => Some(p),
                    Self::Invitee(_) => None,
                }
            }

            pub(super) fn invitee_mut(&mut self) -> Option<&mut InviteePhase> {
                match self {
                    Self::Invitee(p) => Some(p),
                    Self::Inviter(_) => None,
                }
            }
        }
    };
}

/// DM handshake party.
#[derive(Clone, Debug)]
pub(super) enum DmParty {
    Inviter(InviterPhase),
    Invitee(InviteePhase),
}

party_impl!(DmParty);

/// Sync handshake party.
#[derive(Clone, Debug)]
pub(super) enum SyncParty {
    Inviter(InviterPhase),
    Invitee(InviteePhase),
}

party_impl!(SyncParty);

/// Which handshake phase is stored, without its secrets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PhaseKind {
    InviteCreated,
    NoticePinned,
    InviterIntroMinted,
    Confirming,
    TicketReceived,
    InviteReceived,
    InviteeIntroMinted,
    IntroductionSent,
    Failed(HandshakeFailure),
}
pub(super) enum PartyRef<'a> {
    Dm(&'a DmParty),
    Sync(&'a SyncParty),
}

impl PartyRef<'_> {
    pub(super) fn ticket(&self) -> &Ticket {
        match self {
            Self::Dm(p) => p.ticket(),
            Self::Sync(p) => p.ticket(),
        }
    }

    pub(super) fn list_from(&self) -> TimeBin {
        match self {
            Self::Dm(p) => p.list_from(),
            Self::Sync(p) => p.list_from(),
        }
    }

    pub(super) fn intake(&self) -> Option<&KeyPair> {
        match self {
            Self::Dm(p) => p.intake(),
            Self::Sync(p) => p.intake(),
        }
    }

    pub(super) fn shared_inviter(&self) -> Option<&Secret> {
        match self {
            Self::Dm(p) => p.shared_inviter(),
            Self::Sync(p) => p.shared_inviter(),
        }
    }

    pub(super) fn shared_invitee(&self) -> Option<&Secret> {
        match self {
            Self::Dm(p) => p.shared_invitee(),
            Self::Sync(p) => p.shared_invitee(),
        }
    }

    pub(super) fn failure(&self) -> Option<HandshakeFailure> {
        match self {
            Self::Dm(p) => p.failure(),
            Self::Sync(p) => p.failure(),
        }
    }

    pub(super) fn is_inviter(&self) -> bool {
        match self {
            Self::Dm(p) => p.is_inviter(),
            Self::Sync(p) => p.is_inviter(),
        }
    }

    pub(super) fn invitee_policy(&self) -> Option<Policy> {
        match self {
            Self::Dm(DmParty::Invitee(p)) | Self::Sync(SyncParty::Invitee(p)) => p.policy(),
            _ => None,
        }
    }

    pub(super) fn kind(&self) -> PhaseKind {
        match self {
            Self::Dm(DmParty::Inviter(p)) | Self::Sync(SyncParty::Inviter(p)) => match p {
                InviterPhase::InviteCreated { .. } => PhaseKind::InviteCreated,
                InviterPhase::NoticePinned { .. } => PhaseKind::NoticePinned,
                InviterPhase::IntroductionMinted { .. } => PhaseKind::InviterIntroMinted,
                InviterPhase::Confirming { .. } => PhaseKind::Confirming,
                InviterPhase::Failed { reason, .. } => PhaseKind::Failed(*reason),
            },
            Self::Dm(DmParty::Invitee(p)) | Self::Sync(SyncParty::Invitee(p)) => match p {
                InviteePhase::TicketReceived { .. } => PhaseKind::TicketReceived,
                InviteePhase::InviteReceived { .. } => PhaseKind::InviteReceived,
                InviteePhase::IntroductionMinted { .. } => PhaseKind::InviteeIntroMinted,
                InviteePhase::IntroductionSent { .. } => PhaseKind::IntroductionSent,
                InviteePhase::Confirming { .. } => PhaseKind::Confirming,
                InviteePhase::Failed { reason, .. } => PhaseKind::Failed(*reason),
            },
        }
    }
}

/// Mutable DM or Sync party.
pub(super) enum PartyMut<'a> {
    Dm(&'a mut DmParty),
    Sync(&'a mut SyncParty),
}

impl PartyMut<'_> {
    pub(super) fn ack_posted(&mut self) {
        match self {
            Self::Dm(p) => p.ack_posted(),
            Self::Sync(p) => p.ack_posted(),
        }
    }

    pub(super) fn fail(&mut self, reason: HandshakeFailure) {
        match self {
            Self::Dm(p) => p.fail(reason),
            Self::Sync(p) => p.fail(reason),
        }
    }

    pub(super) fn inviter_mut(&mut self) -> Option<&mut InviterPhase> {
        match self {
            Self::Dm(p) => p.inviter_mut(),
            Self::Sync(p) => p.inviter_mut(),
        }
    }

    pub(super) fn invitee_mut(&mut self) -> Option<&mut InviteePhase> {
        match self {
            Self::Dm(p) => p.invitee_mut(),
            Self::Sync(p) => p.invitee_mut(),
        }
    }
}

/// Conversation stored on an identity.
#[derive(Clone, Debug)]
pub(super) enum IdentityConversation {
    DmHandshake(DmParty),
    DirectMessage {
        secret: Secret,
        parent: super::super::ConversationId,
    },
    Group(GroupPhase),
}

/// Group row on an identity.
#[derive(Clone, Debug)]
pub(super) enum GroupPhase {
    /// Owner or accepted member.
    Live(GroupLive),
    /// Invitee has the wrapped secret and has not accepted.
    Offer(GroupOffer),
    /// Terminal group failure.
    Failed(FailedReason),
}

/// Established group membership.
#[derive(Clone, Debug)]
pub(super) struct GroupLive {
    pub(super) secret: Secret,
    pub(super) name: super::super::DisplayName,
    pub(super) photo: Option<super::super::ProfilePic>,
    pub(super) owner_signing_pk: Vec<u8>,
    pub(super) persistents: Vec<super::super::DurableChannel>,
    pub(super) ephemerals: Vec<super::super::EphemeralChannel>,
    pub(super) members: Vec<super::super::payload::GroupMember>,
    pub(super) pending: Vec<GroupPending>,
    pub(super) epoch: u64,
}

/// Incoming group offer.
#[derive(Clone, Debug)]
pub(super) struct GroupOffer {
    pub(super) secret: Secret,
    pub(super) name: super::super::DisplayName,
    pub(super) photo: Option<super::super::ProfilePic>,
    pub(super) owner_signing_pk: Vec<u8>,
    pub(super) from_conversation_id: super::super::ConversationId,
}

/// Invite not yet accepted.
#[derive(Clone, Debug)]
pub(super) struct GroupPending {
    pub(super) signing_pk: Vec<u8>,
    pub(super) encryption_pk: Vec<u8>,
    pub(super) from_conversation_id: super::super::ConversationId,
    pub(super) name: super::super::DisplayName,
    pub(super) photo: Option<super::super::ProfilePic>,
}

/// Conversation stored on this device.
#[derive(Clone, Debug)]
pub(super) enum DeviceConversation {
    SyncHandshake(SyncParty),
    Synchronization {
        secret: Secret,
        parent: super::super::ConversationId,
        peer: Option<super::super::DeviceId>,
    },
}
