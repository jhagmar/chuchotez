//! Chuchotez is a communications backend the app author does not operate.
//!
//! Construct a [`v1::Engine`] with [`v1::std_engine`] or
//! [`v1::Engine::new`] plus [`v1::std_suite`]. Keep [`v1::EngineState`] and
//! unlock a DEK. Supply [`Rng`] on every call that needs entropy.
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
//! let persistents = vec![v1::DurableChannel::new(
//!     v1::Kind::try_from("nostr").expect("kind"),
//!     v1::Address::try_from("wss://relay.example").expect("addr"),
//! )];
//! let defaults = v1::Defaults::try_new(
//!     persistents,
//!     Vec::new(),
//!     true,
//!     true,
//!     true,
//!     None,
//!     false,
//!     v1::NotificationPrivacy::Name,
//! )
//! .expect("defaults");
//! let mut engine = v1::std_engine(defaults);
//! let rng = HostRng;
//! let _ = engine
//!     .wrap_dek(&rng, &v1::UnlockSecret::Passphrase("passpass".into()))
//!     .expect("wrap");
//! let ticked = engine
//!     .tick(v1::EngineState::new(), 1_700_000_000)
//!     .expect("tick");
//! let (created, user_id) = engine.create_user(ticked.state, &rng).expect("user");
//! let (created, identity_id) = engine
//!     .create_identity(created.state, &rng, user_id, v1::Policy::Classic)
//!     .expect("identity");
//! let (invited, conversation_id) = engine
//!     .create_invite(created.state, &rng, user_id, identity_id, 1_700_003_600, None)
//!     .expect("invite");
//! let ids = v1::ConversationRef {
//!     user_id,
//!     identity_id,
//!     conversation_id,
//! };
//! let ticket = engine
//!     .ticket_host_string(&invited.state, &ids)
//!     .expect("ticket");
//! assert!(!ticket.is_empty());
//! ```

pub use chuchotez_adapters::{
    AesGcm, Base64Ct, Deflate, LibcruxHmac, LibcruxKem, LibcruxSha256, LibcruxSign, Rfc8785,
    RustcryptoArgon2id,
};
pub use chuchotez_domain::{Policy, RANDOM32_LEN, Random32, Random32Bytes, Rng, VERSION, protocol};

/// First on-wire layout: engine and portable adapters.
pub mod v1 {
    pub use chuchotez_adapters::v1::{std_engine, std_suite};
    pub use chuchotez_domain::v1::*;
}

#[cfg(test)]
mod tests {
    use super::v1;
    use super::{RANDOM32_LEN, Random32, Rng};
    use std::cell::Cell;

    struct HostRng;

    impl Rng for HostRng {
        fn random32(&self) -> Random32 {
            Random32::from_bytes([3; RANDOM32_LEN])
        }
    }

    struct CounterRng(Cell<u64>);

    impl Rng for CounterRng {
        fn random32(&self) -> Random32 {
            let i = self.0.get();
            self.0.set(i + 1);
            let mut bytes = [0u8; RANDOM32_LEN];
            bytes[RANDOM32_LEN - 8..].copy_from_slice(&i.to_be_bytes());
            Random32::from_bytes(bytes)
        }
    }

    fn sample_defaults() -> v1::Defaults {
        let persistents = vec![v1::DurableChannel::new(
            v1::Kind::try_from("nostr").expect("kind"),
            v1::Address::try_from("wss://relay.example").expect("addr"),
        )];
        v1::Defaults::try_new(
            persistents,
            Vec::new(),
            true,
            true,
            true,
            None,
            false,
            v1::NotificationPrivacy::Name,
        )
        .expect("defaults")
    }

    #[test]
    fn host_keeps_engine_and_engine_state() {
        let mut engine = v1::std_engine(sample_defaults());
        let rng = HostRng;
        engine
            .wrap_dek(&rng, &v1::UnlockSecret::Passphrase("passpass".into()))
            .expect("wrap");
        let ticked = engine
            .tick(v1::EngineState::new(), 1_700_000_000)
            .expect("tick");
        let (created, user_id) = engine.create_user(ticked.state, &rng).expect("user");
        let (created, identity_id) = engine
            .create_identity(created.state, &rng, user_id, v1::Policy::Classic)
            .expect("identity");
        let users = engine.list_users(&created.state).expect("users");
        assert_eq!(users[0], user_id);
        let ids = engine
            .list_identities(&created.state, user_id)
            .expect("ids");
        assert_eq!(ids[0], identity_id);
        engine.lock();
        assert!(format!("{engine:?}").contains("locked"));
    }

    #[test]
    fn std_engine_ingests_invite_notice() {
        let mut engine = v1::std_engine(sample_defaults());
        let rng = CounterRng(Cell::new(0));
        engine
            .wrap_dek(&rng, &v1::UnlockSecret::Passphrase("passpass".into()))
            .expect("wrap");
        let ticked = engine
            .tick(v1::EngineState::new(), 1_700_000_000)
            .expect("tick");
        let (created, user_id) = engine.create_user(ticked.state, &rng).expect("user");
        let (created, identity_id) = engine
            .create_identity(created.state, &rng, user_id, v1::Policy::Classic)
            .expect("identity");
        let (invited, conversation_id) = engine
            .create_invite(
                created.state,
                &rng,
                user_id,
                identity_id,
                1_800_000_000,
                None,
            )
            .expect("invite");
        let ids = v1::ConversationRef {
            user_id,
            identity_id,
            conversation_id,
        };
        let ticket = engine
            .ticket_host_string(&invited.state, &ids)
            .expect("ticket");
        let poll = engine.poll(&invited.state).expect("poll");
        let write = &poll.write_durable[0];
        let bodies: Vec<Vec<u8>> = poll.write_durable.iter().map(|w| w.body.clone()).collect();
        let invitee = engine
            .tick(v1::EngineState::new(), 1_700_000_000)
            .expect("itick");
        let (received, _) = engine
            .receive_ticket(invitee.state, &rng, user_id, identity_id, &ticket)
            .expect("recv");
        let ingested = engine
            .ingest_list(
                received.state,
                &rng,
                write.channel.clone(),
                write.tag,
                &bodies,
            )
            .expect("ingest");
        let rows = engine
            .list_conversations(&ingested.state, user_id, identity_id)
            .expect("rows");
        assert!(matches!(
            rows[0].conversation,
            v1::Conversation::HandshakeDm(v1::Handshake::Invitee(
                v1::HandshakeInvitee::InviteReceived {
                    policy: v1::Policy::Classic,
                    ..
                }
            ))
        ));
    }
}
