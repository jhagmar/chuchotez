//! Invite: Ticket and Intake.

use super::{Intake, IntakeError, KemError, Ticket, TicketError};

/// Why [`super::Engine::try_new_invite`] failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InviteError {
    /// Ticket Billboard list failed.
    Ticket(TicketError),
    /// Intake Mailbox or Wire list failed.
    Intake(IntakeError),
    /// Intake key generation failed.
    Kem(KemError),
}

impl core::fmt::Display for InviteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Ticket(err) => write!(f, "invite: {err}"),
            Self::Intake(err) => write!(f, "invite: {err}"),
            Self::Kem(err) => write!(f, "invite: {err}"),
        }
    }
}

impl std::error::Error for InviteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Ticket(err) => Some(err),
            Self::Intake(err) => Some(err),
            Self::Kem(err) => Some(err),
        }
    }
}

impl From<TicketError> for InviteError {
    fn from(err: TicketError) -> Self {
        Self::Ticket(err)
    }
}

impl From<IntakeError> for InviteError {
    fn from(err: IntakeError) -> Self {
        Self::Intake(err)
    }
}

impl From<KemError> for InviteError {
    fn from(err: KemError) -> Self {
        Self::Kem(err)
    }
}

/// Minted DM invite: Ticket and Intake.
pub struct Invite {
    ticket: Ticket,
    intake: Intake,
}

impl Invite {
    pub(crate) fn from_parts(ticket: Ticket, intake: Intake) -> Self {
        Self { ticket, intake }
    }

    /// QR capability.
    #[must_use]
    pub const fn ticket(&self) -> &Ticket {
        &self.ticket
    }

    /// Calling-card receiver.
    #[must_use]
    pub const fn intake(&self) -> &Intake {
        &self.intake
    }
}

impl PartialEq for Invite {
    fn eq(&self, other: &Self) -> bool {
        self.ticket == other.ticket && self.intake == other.intake
    }
}

impl Eq for Invite {}

impl core::fmt::Debug for Invite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Invite(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::InviteError;
    use crate::protocol::Policy;
    use crate::protocol::v1::{
        IntakeError, KemError, MAILBOX_MAX_COUNT, TicketError, WIRE_MAX_COUNT,
    };

    #[test]
    fn invite_error_display() {
        assert_eq!(
            format!("{}", InviteError::Intake(IntakeError::EmptyMailboxes)),
            format!("invite: {}", IntakeError::EmptyMailboxes)
        );
        assert_eq!(
            format!("{}", InviteError::Ticket(TicketError::EmptyBillboards)),
            format!("invite: {}", TicketError::EmptyBillboards)
        );
        assert_eq!(
            format!(
                "{}",
                InviteError::Kem(KemError::UnsupportedPolicy(Policy::Hybrid))
            ),
            format!("invite: {}", KemError::UnsupportedPolicy(Policy::Hybrid))
        );
        assert!(
            std::error::Error::source(&InviteError::Ticket(TicketError::EmptyBillboards)).is_some()
        );
        assert!(
            std::error::Error::source(&InviteError::Intake(IntakeError::EmptyMailboxes)).is_some()
        );
        assert!(
            std::error::Error::source(&InviteError::Kem(KemError::UnsupportedPolicy(
                Policy::Classic
            )))
            .is_some()
        );
        assert_eq!(
            InviteError::from(TicketError::TooManyBillboards),
            InviteError::Ticket(TicketError::TooManyBillboards)
        );
        assert_eq!(
            InviteError::from(IntakeError::TooManyWires),
            InviteError::Intake(IntakeError::TooManyWires)
        );
        assert_eq!(
            InviteError::from(KemError::UnsupportedPolicy(Policy::PostQuantum)),
            InviteError::Kem(KemError::UnsupportedPolicy(Policy::PostQuantum))
        );
        let _ = MAILBOX_MAX_COUNT;
        let _ = WIRE_MAX_COUNT;
    }

    #[test]
    fn try_new_invite_uses_entropy() {
        use crate::protocol::v1::fixtures;
        let rng = fixtures::SeedRng(fixtures::fill(0x11));
        let engine = fixtures::test_engine();
        let invite = engine
            .try_new_invite(
                &rng,
                &[fixtures::sample_billboard()],
                &[fixtures::sample_mailbox()],
                &[fixtures::sample_wire()],
            )
            .expect("invite");
        let expected = crate::protocol::v1::Ticket::from_parts(
            fixtures::fill(0x11),
            vec![fixtures::sample_billboard()],
        )
        .expect("expected");
        assert_eq!(invite.ticket(), &expected);
        assert_eq!(invite.ticket().billboards().len(), 1);
        assert_eq!(invite.intake().mailboxes().len(), 1);
        assert_eq!(invite.intake().wires().len(), 1);
        let _ = engine.serialize_notice(invite.ticket(), invite.intake());
        assert_eq!(invite.intake().public_bytes()[0], 0x11);
        assert_eq!(format!("{:?}", invite), "Invite(..)");
        assert_eq!(
            engine
                .try_new_invite(&rng, &[], &[fixtures::sample_mailbox()], &[])
                .unwrap_err(),
            InviteError::Ticket(TicketError::EmptyBillboards)
        );
    }

    #[test]
    fn every_policy_mints_invite() {
        use crate::protocol::v1::fixtures;
        use crate::protocol::v1::intake_pk_len;
        for policy in [Policy::Classic, Policy::PostQuantum, Policy::Hybrid] {
            let engine = fixtures::engine_with_policy(policy);
            assert_eq!(engine.policy(), policy);
            let board = engine.new_billboard(
                engine.try_new_billboard_kind("nostr").expect("kind"),
                engine
                    .try_new_billboard_address("wss://relay.example")
                    .expect("addr"),
            );
            let mailbox = engine.new_mailbox(
                engine.try_new_mailbox_kind("nostr").expect("kind"),
                engine
                    .try_new_mailbox_address("wss://mailbox.example")
                    .expect("addr"),
            );
            let invite = engine
                .try_new_invite(
                    &fixtures::SeedRng(fixtures::fill(0x11)),
                    &[board],
                    &[mailbox],
                    &[],
                )
                .expect("invite");
            let ticket_blob = invite.ticket().serialize(&engine);
            let parsed = engine.try_parse_ticket(&ticket_blob).expect("parse");
            assert_eq!(&parsed, invite.ticket());
            let notice_blob = engine.serialize_notice(invite.ticket(), invite.intake());
            let notice = engine
                .try_parse_notice(invite.ticket(), &notice_blob)
                .expect("notice");
            assert_eq!(notice.policy(), policy);
            assert_eq!(notice.intake_pk().len(), intake_pk_len(policy));
            assert_eq!(notice.mailboxes().len(), 1);
        }
    }

    #[test]
    fn notice_rejects_foreign_ticket_and_policy() {
        use crate::protocol::v1::{
            MAILBOX_MAX_COUNT, NOTICE_MAX_B64U_LEN, WIRE_MAX_COUNT, fixtures,
        };
        let engine = fixtures::test_engine();
        let invite = engine
            .try_new_invite(
                &fixtures::SeedRng(fixtures::fill(0x11)),
                &[fixtures::sample_billboard()],
                &[fixtures::sample_mailbox()],
                &[],
            )
            .expect("invite");
        let blob = engine.serialize_notice(invite.ticket(), invite.intake());
        let again = engine.serialize_notice(invite.ticket(), invite.intake());
        assert_eq!(blob, again);
        let other = engine
            .try_new_invite(
                &fixtures::SeedRng(fixtures::fill(0x22)),
                &[fixtures::sample_billboard()],
                &[fixtures::sample_mailbox()],
                &[],
            )
            .expect("other");
        assert!(engine.try_parse_notice(other.ticket(), &blob).is_err());
        let classic = fixtures::engine_with_policy(Policy::Classic);
        assert_eq!(
            classic
                .try_parse_notice(invite.ticket(), &blob)
                .unwrap_err(),
            crate::protocol::v1::NoticeError::PolicyMismatch
        );
        assert_eq!(
            engine
                .try_new_invite(
                    &fixtures::SeedRng(fixtures::fill(0x11)),
                    &[fixtures::sample_billboard()],
                    &[],
                    &[]
                )
                .unwrap_err(),
            InviteError::Intake(IntakeError::EmptyMailboxes)
        );
        let many_mail = vec![fixtures::sample_mailbox(); MAILBOX_MAX_COUNT + 1];
        assert_eq!(
            engine
                .try_new_invite(
                    &fixtures::SeedRng(fixtures::fill(0x11)),
                    &[fixtures::sample_billboard()],
                    &many_mail,
                    &[]
                )
                .unwrap_err(),
            InviteError::Intake(IntakeError::TooManyMailboxes)
        );
        let many_wire = vec![fixtures::sample_wire(); WIRE_MAX_COUNT + 1];
        assert_eq!(
            engine
                .try_new_invite(
                    &fixtures::SeedRng(fixtures::fill(0x11)),
                    &[fixtures::sample_billboard()],
                    &[fixtures::sample_mailbox()],
                    &many_wire
                )
                .unwrap_err(),
            InviteError::Intake(IntakeError::TooManyWires)
        );
        assert_ne!(invite, other);
        assert_eq!(invite, invite);
        assert!(format!("{:?}", invite.intake()).starts_with("Intake"));
        let long = "aa".repeat(NOTICE_MAX_B64U_LEN);
        assert_eq!(
            engine.try_parse_notice(invite.ticket(), &long).unwrap_err(),
            crate::protocol::v1::NoticeError::TooLong
        );
        assert_eq!(
            engine.try_parse_notice(invite.ticket(), "").unwrap_err(),
            crate::protocol::v1::NoticeError::Empty
        );
        assert!(matches!(
            engine.try_parse_notice(invite.ticket(), "0g"),
            Err(crate::protocol::v1::NoticeError::Base64(_))
        ));
    }
}
