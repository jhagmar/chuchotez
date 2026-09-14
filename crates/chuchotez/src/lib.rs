//! Chuchotez is a communications backend the app author does not operate.
//!
//! Construct a [`v1::Engine`] with [`v1::std_engine`] or
//! [`v1::Engine::new`] plus [`v1::std_suite`]. Supply [`Rng`] on every call
//! that needs entropy. A [`v1::Invite`] is Ticket and Intake.
//!
//! ```
//! use chuchotez::v1;
//! use chuchotez::{RANDOM32_LEN, Random32, Rng};
//!
//! struct HostRng;
//!
//! impl Rng for HostRng {
//!     fn random32(&self) -> Random32 {
//!         Random32::from_bytes([1; RANDOM32_LEN])
//!     }
//! }
//!
//! let suite = v1::std_suite();
//! let engine = v1::Engine::new(suite, v1::Policy::Classic);
//! assert_eq!(engine.policy(), v1::Policy::Classic);
//! let _ = v1::std_engine(v1::Policy::Classic);
//!
//! let board = engine.new_billboard(
//!     engine.try_new_billboard_kind("nostr").expect("kind"),
//!     engine
//!         .try_new_billboard_address("wss://relay.example")
//!         .expect("addr"),
//! );
//! let mailbox = engine.new_mailbox(
//!     engine.try_new_mailbox_kind("nostr").expect("kind"),
//!     engine
//!         .try_new_mailbox_address("wss://mailbox.example")
//!         .expect("addr"),
//! );
//! let wire = engine.new_wire(
//!     engine.try_new_wire_kind("webrtc").expect("kind"),
//!     engine
//!         .try_new_wire_address("stun:stun.example")
//!         .expect("addr"),
//! );
//! assert_eq!(board.kind().as_str(), "nostr");
//! assert_eq!(board.address().as_str(), "wss://relay.example");
//! assert_eq!(mailbox.kind().as_str(), "nostr");
//! assert_eq!(mailbox.address().as_str(), "wss://mailbox.example");
//! assert_eq!(wire.kind().as_str(), "webrtc");
//! assert_eq!(wire.address().as_str(), "stun:stun.example");
//!
//! let invite = engine
//!     .try_new_invite(&HostRng, &[board], &[mailbox], &[wire])
//!     .expect("invite");
//! let ticket = invite.ticket();
//! let intake = invite.intake();
//!
//! let tag = ticket.billboard_tag(&engine);
//! let tag_key = ticket.mailbox_tag_key(&engine);
//! let _ = (tag.as_bytes(), tag_key.as_bytes());
//! assert_eq!(ticket.billboards()[0].kind().as_str(), "nostr");
//! assert_eq!(ticket.billboards()[0].address().as_str(), "wss://relay.example");
//! let ticket_blob = ticket.serialize(&engine);
//! let parsed_ticket = engine.try_parse_ticket(&ticket_blob).expect("ticket");
//! assert_eq!(parsed_ticket, *ticket);
//!
//! let notice_blob = engine.serialize_notice(ticket, intake);
//! let notice = engine
//!     .try_parse_notice(ticket, &notice_blob)
//!     .expect("notice");
//! assert_eq!(notice.policy(), v1::Policy::Classic);
//! let _ = notice.intake_pk();
//! assert_eq!(notice.mailboxes()[0].kind().as_str(), "nostr");
//! assert_eq!(
//!     notice.mailboxes()[0].address().as_str(),
//!     "wss://mailbox.example"
//! );
//! assert_eq!(notice.wires()[0].kind().as_str(), "webrtc");
//! assert_eq!(notice.wires()[0].address().as_str(), "stun:stun.example");
//!
//! let _ = (intake.public_bytes(), intake.secret_bytes());
//! ```

pub use chuchotez_adapters::{AesGcm, Base64Ct, Deflate, LibcruxHmac, LibcruxKem, Rfc8785};
pub use chuchotez_domain::{Policy, RANDOM32_LEN, Random32, Random32Bytes, Rng, VERSION, protocol};

/// First on-wire layout: engine, Invite, and portable adapters.
pub mod v1 {
    pub use chuchotez_adapters::v1::{std_engine, std_suite};
    pub use chuchotez_domain::v1::*;
}

#[cfg(test)]
mod tests {
    use super::v1;
    use super::{Policy, RANDOM32_LEN, Random32, Rng};

    struct SeedRng([u8; RANDOM32_LEN]);

    impl Rng for SeedRng {
        fn random32(&self) -> Random32 {
            Random32::from_bytes(self.0)
        }
    }

    fn fill(byte: u8) -> [u8; RANDOM32_LEN] {
        [byte; RANDOM32_LEN]
    }

    fn mint(engine: &v1::Engine, byte: u8) -> v1::Invite {
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
        engine
            .try_new_invite(
                &SeedRng(fill(byte)),
                std::slice::from_ref(&board),
                std::slice::from_ref(&mailbox),
                &[],
            )
            .expect("invite")
    }

    #[test]
    fn host_keeps_engine_and_supplies_rng() {
        let engine: v1::Engine = v1::std_engine(v1::Policy::Classic);
        let invite = mint(&engine, 0x11);
        assert_eq!(invite.ticket().billboards().len(), 1);
        let tag = invite.ticket().billboard_tag(&engine);
        let again = invite.ticket().billboard_tag(&engine);
        assert_eq!(tag, again);
        let key = invite.ticket().mailbox_tag_key(&engine);
        assert_ne!(tag.as_bytes(), key.as_bytes());
        assert_eq!(format!("{:?}", invite.ticket()), "Ticket(..)");
        let other = mint(&engine, 0x22);
        assert_ne!(invite, other);
        assert_eq!(invite, mint(&engine, 0x11));
        let other_engine = v1::std_engine(Policy::Classic);
        let blob = invite.ticket().serialize(&engine);
        let parsed = other_engine.try_parse_ticket(&blob).expect("parse");
        assert_eq!(parsed, *invite.ticket());
        assert_eq!(
            parsed.billboard_tag(&other_engine),
            invite.ticket().billboard_tag(&engine)
        );
        assert!(!blob.contains('='));
        let notice_blob = engine.serialize_notice(invite.ticket(), invite.intake());
        let notice = engine
            .try_parse_notice(invite.ticket(), &notice_blob)
            .expect("notice");
        assert_eq!(notice.policy(), v1::Policy::Classic);
        assert_eq!(notice.mailboxes().len(), 1);
        assert!(matches!(
            engine.try_parse_ticket("!!!!").unwrap_err(),
            v1::EnvelopeError::Base64(_)
        ));
        let _ = v1::std_suite();
        assert_eq!(
            v1::std_engine(Policy::PostQuantum).policy(),
            Policy::PostQuantum
        );
        let hybrid = v1::std_engine(Policy::Hybrid);
        let hybrid_invite = mint(&hybrid, 0x11);
        let hybrid_notice = hybrid.serialize_notice(hybrid_invite.ticket(), hybrid_invite.intake());
        let parsed = hybrid
            .try_parse_notice(hybrid_invite.ticket(), &hybrid_notice)
            .expect("hybrid notice");
        assert_eq!(parsed.policy(), Policy::Hybrid);
        assert_eq!(parsed.intake_pk().len(), 1216);
    }
}
