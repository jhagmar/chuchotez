//! Local CallingCard minted at [`super::Invitee::CallingCardCreated`].

use super::DisplayName;
use crate::protocol::v1::{MAILBOX_MAX_COUNT, Mailbox, MailboxTagKey, WIRE_MAX_COUNT, Wire};

/// Why assembling a [`CallingCard`] failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallingCardError {
    /// Mailbox list is empty.
    EmptyMailboxes,
    /// Mailbox count exceeds [`MAILBOX_MAX_COUNT`].
    TooManyMailboxes,
    /// Wire count exceeds [`WIRE_MAX_COUNT`].
    TooManyWires,
}

impl core::fmt::Display for CallingCardError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyMailboxes => f.write_str("calling card needs at least one Mailbox"),
            Self::TooManyMailboxes => f.write_str("calling card has too many Mailboxes"),
            Self::TooManyWires => f.write_str("calling card has too many Wires"),
        }
    }
}

impl std::error::Error for CallingCardError {}

/// Invitee card: display name, identity public keys, mailbox tag, channels.
#[derive(Clone, Eq, PartialEq)]
pub struct CallingCard {
    display_name: DisplayName,
    encryption_pk: Vec<u8>,
    signing_pk: Vec<u8>,
    mailbox_tag_key: MailboxTagKey,
    mailboxes: Vec<Mailbox>,
    wires: Vec<Wire>,
}

impl CallingCard {
    pub(crate) fn from_parts(
        display_name: DisplayName,
        encryption_pk: Vec<u8>,
        signing_pk: Vec<u8>,
        mailbox_tag_key: MailboxTagKey,
        mailboxes: Vec<Mailbox>,
        wires: Vec<Wire>,
    ) -> Result<Self, CallingCardError> {
        if mailboxes.is_empty() {
            return Err(CallingCardError::EmptyMailboxes);
        }
        if mailboxes.len() > MAILBOX_MAX_COUNT {
            return Err(CallingCardError::TooManyMailboxes);
        }
        if wires.len() > WIRE_MAX_COUNT {
            return Err(CallingCardError::TooManyWires);
        }
        Ok(Self {
            display_name,
            encryption_pk,
            signing_pk,
            mailbox_tag_key,
            mailboxes,
            wires,
        })
    }

    /// Snapshot of the identity display name at mint.
    #[must_use]
    pub const fn display_name(&self) -> &DisplayName {
        &self.display_name
    }

    /// Identity encryption public key.
    #[must_use]
    pub fn encryption_pk(&self) -> &[u8] {
        &self.encryption_pk
    }

    /// Identity signing public key.
    #[must_use]
    pub fn signing_pk(&self) -> &[u8] {
        &self.signing_pk
    }

    /// Mailbox Tag Key unique to this card.
    #[must_use]
    pub const fn mailbox_tag_key(&self) -> &MailboxTagKey {
        &self.mailbox_tag_key
    }

    /// Mailboxes this card can be used against.
    #[must_use]
    pub fn mailboxes(&self) -> &[Mailbox] {
        &self.mailboxes
    }

    /// Wires this card can be used against.
    #[must_use]
    pub fn wires(&self) -> &[Wire] {
        &self.wires
    }
}

impl core::fmt::Debug for CallingCard {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CallingCard(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::{CallingCard, CallingCardError};
    use crate::protocol::v1::{
        DisplayName, MAILBOX_MAX_COUNT, MailboxTagKey, SECRET_LEN, WIRE_MAX_COUNT, fixtures,
    };

    #[test]
    fn calling_card_parts_and_errors() {
        let name = DisplayName::try_from("Ada").expect("name");
        let tag = MailboxTagKey::from_bytes([7; SECRET_LEN]);
        let card = CallingCard::from_parts(
            name.clone(),
            vec![1],
            vec![2],
            tag.clone(),
            vec![fixtures::sample_mailbox()],
            vec![fixtures::sample_wire()],
        )
        .expect("card");
        assert_eq!(card.display_name(), &name);
        assert_eq!(card.encryption_pk(), &[1]);
        assert_eq!(card.signing_pk(), &[2]);
        assert_eq!(card.mailbox_tag_key(), &tag);
        assert_eq!(card.mailboxes().len(), 1);
        assert_eq!(card.wires().len(), 1);
        assert_eq!(format!("{card:?}"), "CallingCard(..)");
        assert_eq!(card, card.clone());
        assert_eq!(
            CallingCard::from_parts(
                name.clone(),
                vec![],
                vec![],
                tag.clone(),
                Vec::new(),
                Vec::new()
            )
            .unwrap_err(),
            CallingCardError::EmptyMailboxes
        );
        let many_m = vec![fixtures::sample_mailbox(); MAILBOX_MAX_COUNT + 1];
        assert_eq!(
            CallingCard::from_parts(
                name.clone(),
                vec![],
                vec![],
                tag.clone(),
                many_m,
                Vec::new()
            )
            .unwrap_err(),
            CallingCardError::TooManyMailboxes
        );
        let many_w = vec![fixtures::sample_wire(); WIRE_MAX_COUNT + 1];
        assert_eq!(
            CallingCard::from_parts(
                name,
                vec![],
                vec![],
                tag,
                vec![fixtures::sample_mailbox()],
                many_w,
            )
            .unwrap_err(),
            CallingCardError::TooManyWires
        );
        assert_eq!(
            format!("{}", CallingCardError::EmptyMailboxes),
            "calling card needs at least one Mailbox"
        );
        assert_eq!(
            format!("{}", CallingCardError::TooManyMailboxes),
            "calling card has too many Mailboxes"
        );
        assert_eq!(
            format!("{}", CallingCardError::TooManyWires),
            "calling card has too many Wires"
        );
        let _ = &CallingCardError::EmptyMailboxes as &dyn std::error::Error;
    }
}
