//! Chuchotez is a communications backend the app author does not operate.
//!
//! Construct a [`v1::Engine`] with [`v1::std_engine`] or
//! [`v1::Engine::new`] plus [`v1::std_suite`]. Keep [`v1::EngineState`] and a
//! DEK. Supply [`Rng`] on every call that needs entropy.
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
//! let board = v1::Billboard::new(
//!     v1::BillboardKind::try_from("nostr").expect("kind"),
//!     v1::BillboardAddress::try_from("wss://relay.example").expect("addr"),
//! );
//! let mailbox = v1::Mailbox::new(
//!     v1::MailboxKind::try_from("nostr").expect("kind"),
//!     v1::MailboxAddress::try_from("wss://mailbox.example").expect("addr"),
//! );
//! let wire = v1::Wire::new(
//!     v1::WireKind::try_from("webrtc").expect("kind"),
//!     v1::WireAddress::try_from("stun:stun.example").expect("addr"),
//! );
//! assert_eq!(board.kind().as_str(), "nostr");
//! assert_eq!(board.address().as_str(), "wss://relay.example");
//!
//! let dek = v1::AeadKey::from_bytes([2; RANDOM32_LEN]);
//! let (state, user_id, _) = engine.create_user(v1::EngineState::new(), &HostRng, &dek);
//! let (state, identity_id, _) = engine.create_identity(state, &HostRng, &dek, user_id);
//! let (state, conversation_id, _) = engine.create_invite(
//!     state,
//!     &HostRng,
//!     &dek,
//!     user_id,
//!     identity_id,
//!     std::slice::from_ref(&board),
//!     std::slice::from_ref(&mailbox),
//!     std::slice::from_ref(&wire),
//! );
//! let ticket_blob = engine
//!     .ticket_blob(&state, user_id, identity_id, conversation_id)
//!     .expect("ticket");
//! let notice_blob = engine
//!     .notice_blob(&state, user_id, identity_id, conversation_id)
//!     .expect("notice");
//! let tags = engine
//!     .billboard_tags(&state, user_id, identity_id, conversation_id)
//!     .expect("tags");
//! let (state, _) = engine.mark_notices_pinned(state, &dek, user_id, identity_id, conversation_id);
//! let (invitee, iu, _) = engine.create_user(v1::EngineState::new(), &HostRng, &dek);
//! let (invitee, ii, _) = engine.create_identity(invitee, &HostRng, &dek, iu);
//! let (invitee, icid, _) = engine.receive_ticket(invitee, &HostRng, &dek, iu, ii, &ticket_blob);
//! let (invitee, _) =
//!     engine.receive_notice(invitee, &dek, iu, ii, icid, &notice_blob, &[v1::Policy::Classic]);
//! let name = engine.try_new_display_name("Ada").expect("name");
//! let (invitee, _) = engine.set_display_name(invitee, &dek, iu, ii, name);
//! let (invitee, _) = engine.create_calling_card(
//!     invitee,
//!     &HostRng,
//!     &dek,
//!     iu,
//!     ii,
//!     icid,
//!     std::slice::from_ref(&mailbox),
//!     std::slice::from_ref(&wire),
//! );
//! let _ = engine.calling_card(&invitee, iu, ii, icid).expect("card");
//! let _ = (state, tags[0].as_bytes(), ticket_blob, notice_blob);
//! ```

pub use chuchotez_adapters::{
    AesGcm, Base64Ct, Deflate, LibcruxHmac, LibcruxKem, LibcruxSign, Rfc8785,
};
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
    use std::cell::Cell;

    struct CounterRng(Cell<u64>);

    impl CounterRng {
        fn new() -> Self {
            Self(Cell::new(0))
        }
    }

    impl Rng for CounterRng {
        fn random32(&self) -> Random32 {
            let i = self.0.get();
            self.0.set(i + 1);
            let mut bytes = [0u8; RANDOM32_LEN];
            bytes[RANDOM32_LEN - 8..].copy_from_slice(&i.to_be_bytes());
            Random32::from_bytes(bytes)
        }
    }

    fn dek() -> v1::AeadKey {
        v1::AeadKey::from_bytes([0x42; RANDOM32_LEN])
    }

    fn channels(engine: &v1::Engine) -> (v1::Billboard, v1::Mailbox, v1::Wire) {
        let _ = engine;
        (
            v1::Billboard::new(
                v1::BillboardKind::try_from("nostr").expect("kind"),
                v1::BillboardAddress::try_from("wss://relay.example").expect("addr"),
            ),
            v1::Mailbox::new(
                v1::MailboxKind::try_from("nostr").expect("kind"),
                v1::MailboxAddress::try_from("wss://mailbox.example").expect("addr"),
            ),
            v1::Wire::new(
                v1::WireKind::try_from("webrtc").expect("kind"),
                v1::WireAddress::try_from("stun:stun.example").expect("addr"),
            ),
        )
    }

    #[test]
    fn host_keeps_engine_and_engine_state() {
        let engine: v1::Engine = v1::std_engine(v1::Policy::Classic);
        let rng = CounterRng::new();
        let dek = dek();
        let (board, mailbox, wire) = channels(&engine);
        let (state, user_id, user_ok) = engine.create_user(v1::EngineState::new(), &rng, &dek);
        user_ok.expect("user");
        let (state, identity_id, id_ok) = engine.create_identity(state, &rng, &dek, user_id);
        id_ok.expect("identity");
        let (state, conversation_id, invite_ok) = engine.create_invite(
            state,
            &rng,
            &dek,
            user_id,
            identity_id,
            std::slice::from_ref(&board),
            std::slice::from_ref(&mailbox),
            std::slice::from_ref(&wire),
        );
        let invite_ok = invite_ok.expect("invite");
        assert_eq!(format!("{:?}", invite_ok.persist), "PersistedCommand(..)");
        let ticket_blob = engine
            .ticket_blob(&state, user_id, identity_id, conversation_id)
            .expect("ticket");
        let notice_blob = engine
            .notice_blob(&state, user_id, identity_id, conversation_id)
            .expect("notice");
        let tags = engine
            .billboard_tags(&state, user_id, identity_id, conversation_id)
            .expect("tags");
        let (state, pin) =
            engine.mark_notices_pinned(state, &dek, user_id, identity_id, conversation_id);
        pin.expect("pin");
        assert_eq!(
            state
                .user(&user_id)
                .expect("u")
                .identity(&identity_id)
                .expect("i")
                .conversation(&conversation_id)
                .expect("c")
                .phase(),
            v1::ConversationPhase::InviterNoticePinned
        );
        assert_ne!(tags[0].as_bytes(), &[0u8; RANDOM32_LEN]);
        assert!(!ticket_blob.contains('='));

        let rng = CounterRng::new();
        let (invitee, iu, ok) = engine.create_user(v1::EngineState::new(), &rng, &dek);
        ok.expect("iu");
        let (invitee, ii, ok) = engine.create_identity(invitee, &rng, &dek, iu);
        ok.expect("ii");
        let (invitee, cid, ok) = engine.receive_ticket(invitee, &rng, &dek, iu, ii, &ticket_blob);
        ok.expect("t");
        let (invitee, ok) =
            engine.receive_notice(invitee, &dek, iu, ii, cid, &notice_blob, &[Policy::Classic]);
        let persist = ok.expect("n").persist.clone();
        let cmd = engine
            .try_open_command(&dek, persist.as_bytes())
            .expect("open");
        let (folded, result) = engine.apply(v1::EngineState::new(), &cmd);
        assert!(result.is_err());
        let _ = folded;
        assert_eq!(
            invitee
                .user(&iu)
                .expect("u")
                .identity(&ii)
                .expect("i")
                .conversation(&cid)
                .expect("c")
                .phase(),
            v1::ConversationPhase::InviteeInviteReceived
        );
        let name = v1::DisplayName::try_from("Ada").expect("name");
        let (invitee, set_ok) = engine.set_display_name(invitee, &dek, iu, ii, name);
        set_ok.expect("set");
        let (invitee, card_ok) = engine.create_calling_card(
            invitee,
            &rng,
            &dek,
            iu,
            ii,
            cid,
            std::slice::from_ref(&mailbox),
            std::slice::from_ref(&wire),
        );
        card_ok.expect("card");
        let card = engine.calling_card(&invitee, iu, ii, cid).expect("get");
        assert_eq!(card.display_name().as_str(), "Ada");
        let (invitee, unset_ok) = engine.unset_display_name(invitee, &dek, iu, ii);
        unset_ok.expect("unset");
        let (invitee, del_c) = engine.delete_conversation(invitee, &dek, iu, ii, cid);
        del_c.expect("del c");
        let (invitee, del_i) = engine.delete_identity(invitee, &dek, iu, ii);
        del_i.expect("del i");
        let (invitee, del_u) = engine.delete_user(invitee, &dek, iu);
        del_u.expect("del u");
        assert!(invitee.user(&iu).is_none());

        let _ = v1::std_suite();
        assert_eq!(
            v1::std_engine(Policy::PostQuantum).policy(),
            Policy::PostQuantum
        );
        let hybrid = v1::std_engine(Policy::Hybrid);
        let rng = CounterRng::new();
        let (board, mailbox, _) = channels(&hybrid);
        let (state, uid, ok) = hybrid.create_user(v1::EngineState::new(), &rng, &dek);
        ok.expect("hu");
        let (state, iid, ok) = hybrid.create_identity(state, &rng, &dek, uid);
        ok.expect("hi");
        let (state, cid, ok) = hybrid.create_invite(
            state,
            &rng,
            &dek,
            uid,
            iid,
            std::slice::from_ref(&board),
            std::slice::from_ref(&mailbox),
            &[],
        );
        ok.expect("hinv");
        let notice_blob = hybrid.notice_blob(&state, uid, iid, cid).expect("hn");
        assert!(notice_blob.len() > 8);
    }
}
