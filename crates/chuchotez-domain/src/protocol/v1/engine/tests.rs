use super::{ConversationRef, Engine, EngineState, FOLD_VERSION};
use crate::protocol::v1::fixtures::{CounterRng, test_engine};
use crate::protocol::v1::payload::{DurableBody, Hlc, TxPayload};
use crate::protocol::v1::{
    AEAD_NONCE_LEN, ActorId, AeadNonce, ConversationId, EngineError, IdentityId, Json, Policy,
    Secret, UnixSeconds, UnlockSecret, UserId,
};

#[test]
fn tick_user_identity_invite() {
    let mut engine = test_engine();
    let rng = CounterRng::new();
    assert_eq!(
        engine.tick(EngineState::new(), 10).unwrap_err(),
        EngineError::Locked
    );
    engine
        .wrap_dek(&rng, &UnlockSecret::Passphrase("passpass".into()))
        .expect("wrap");
    engine
        .wrap_dek(&rng, &UnlockSecret::Prf([8; 32]))
        .expect("prf");
    let ticked = engine
        .tick(EngineState::new(), 1_700_000_000)
        .expect("tick");
    assert_eq!(
        engine.tick(ticked.state.clone(), 1).unwrap_err(),
        EngineError::ClockWentBackwards
    );
    let poll = engine.poll(&ticked.state).expect("poll");
    assert!(poll.write_durable.is_empty());
    let defaults = engine.get_defaults(&ticked.state).expect("def");
    let set = engine
        .set_defaults(ticked.state.clone(), defaults)
        .expect("set");
    let set = engine
        .set_defaults(
            set.state,
            engine.get_defaults(&EngineState::new()).expect("gd2"),
        )
        .expect("set2");
    let (created, uid) = engine.create_user(set.state, &rng).expect("user");
    assert_eq!(engine.list_users(&created.state).expect("u")[0], uid);
    assert_eq!(
        engine
            .create_identity(
                created.state.clone(),
                &rng,
                crate::protocol::v1::UserId::from_bytes([0; 32]),
                Policy::Classic
            )
            .unwrap_err(),
        EngineError::UnknownIds
    );
    let (created, iid) = engine
        .create_identity(created.state, &rng, uid, Policy::Classic)
        .expect("id");
    assert_eq!(
        engine.list_identities(&created.state, uid).expect("i")[0],
        iid
    );
    engine
        .set_display_name(created.state.clone(), &rng, uid, iid, "")
        .unwrap_err();
    let named = engine
        .set_display_name(created.state.clone(), &rng, uid, iid, "Ada")
        .expect("name");
    let unnamed = engine
        .unset_display_name(named.state, uid, iid)
        .expect("unset");
    assert_eq!(
        engine
            .create_invite(unnamed.state.clone(), &rng, uid, iid, 1, None)
            .unwrap_err(),
        EngineError::ExpiresNotAfterNow
    );
    let (invited, cid) = engine
        .create_invite(unnamed.state, &rng, uid, iid, 1_800_000_000, None)
        .expect("inv");
    assert!(invited.state.tx_count() > 0);
    let ids = ConversationRef {
        user_id: uid,
        identity_id: iid,
        conversation_id: cid,
    };
    let ticket = engine.ticket_host_string(&invited.state, &ids).expect("t");
    assert!(!ticket.is_empty());
    let rows = engine
        .list_conversations(&invited.state, uid, iid)
        .expect("rows");
    assert!(matches!(
        rows[0].conversation,
        super::Conversation::HandshakeDm(super::Handshake::Inviter(
            super::HandshakeInviter::InviteCreated { .. }
        ))
    ));
    let poll = engine.poll(&invited.state).expect("p2");
    let w = &poll.write_durable[0];
    assert_eq!(w.body.len(), crate::protocol::v1::PACKET_LEN);
    let mut acked = engine
        .write_ack(invited.state.clone(), w.channel.clone(), w.tag, &w.body)
        .expect("ack");
    for write in poll.write_durable.iter().skip(1) {
        acked = engine
            .write_ack(acked.state, write.channel.clone(), write.tag, &write.body)
            .expect("ackn");
    }
    assert!(
        engine
            .poll(&acked.state)
            .expect("p3")
            .write_durable
            .is_empty()
    );
    assert_eq!(
        engine
            .write_ack(acked.state.clone(), w.channel.clone(), w.tag, &w.body)
            .unwrap_err(),
        EngineError::UnknownWrite
    );
    let rec = invited.persist()[0].clone();
    let folded = engine.apply(acked.state.clone(), &rec).expect("apply");
    let snap = engine.fold(folded.clone()).expect("foldok");
    let _ = snap.persist();
    let _ = snap.pings();
    let restored = engine.apply_folded(&snap.snapshot).expect("fold");
    assert!(invited.state.send_chain_seq(&cid).unwrap() >= 1);
    assert_eq!(
        invited.state.send_chain_seq(&cid),
        restored.send_chain_seq(&cid)
    );
    assert!(engine.apply(folded.clone(), &[]).is_err());
    let conv = engine
        .get_conversation(&acked.state, uid, iid, cid)
        .expect("q");
    assert!(matches!(
        conv,
        super::Conversation::HandshakeDm(super::Handshake::Inviter(
            super::HandshakeInviter::NoticePinned { .. }
        ))
    ));
    assert_eq!(
        engine
            .confirm_established(acked.state.clone(), &rng, ids)
            .unwrap_err(),
        EngineError::WrongPhase
    );
    assert_eq!(
        engine
            .reject_established(acked.state.clone(), &rng, ids)
            .unwrap_err(),
        EngineError::WrongPhase
    );
    assert_eq!(
        engine
            .send_text(acked.state.clone(), &rng, ids, "hi", None)
            .unwrap_err(),
        EngineError::WrongPhase
    );
    assert_eq!(
        engine
            .send_text(acked.state.clone(), &rng, ids, "", None)
            .unwrap_err(),
        EngineError::MalformedPayload
    );
    assert_eq!(
        engine
            .edit_message(
                acked.state.clone(),
                &rng,
                ids,
                crate::protocol::v1::Tag::from_bytes([1; 32]),
                "x",
            )
            .unwrap_err(),
        EngineError::WrongPhase
    );
    assert_eq!(
        engine
            .remove_message(
                acked.state.clone(),
                &rng,
                ids,
                crate::protocol::v1::Tag::from_bytes([1; 32]),
            )
            .unwrap_err(),
        EngineError::WrongPhase
    );
    assert_eq!(
        engine
            .send_reaction(
                acked.state.clone(),
                &rng,
                ids,
                crate::protocol::v1::Tag::from_bytes([1; 32]),
                "👍",
                true,
            )
            .unwrap_err(),
        EngineError::WrongPhase
    );
    assert_eq!(
        engine
            .send_read(
                acked.state.clone(),
                &rng,
                ids,
                crate::protocol::v1::Tag::from_bytes([1; 32]),
            )
            .unwrap_err(),
        EngineError::WrongPhase
    );
    assert_eq!(
        engine
            .send_delivered(
                acked.state.clone(),
                &rng,
                ids,
                crate::protocol::v1::Tag::from_bytes([1; 32]),
            )
            .unwrap_err(),
        EngineError::WrongPhase
    );
    assert_eq!(
        engine
            .send_typing(acked.state.clone(), &rng, ids, true)
            .unwrap_err(),
        EngineError::WrongPhase
    );
    assert_eq!(
        engine
            .send_presence(acked.state.clone(), &rng, ids)
            .unwrap_err(),
        EngineError::WrongPhase
    );
    assert_eq!(
        engine
            .set_conversation_prefs(
                acked.state.clone(),
                &rng,
                ids,
                crate::protocol::v1::ConversationPrefs {
                    read_receipts: true,
                    online_visible: true,
                    send_typing: true,
                    disappear_after: None,
                    notification_privacy: crate::protocol::v1::NotificationPrivacy::Name,
                    wake: None,
                },
            )
            .unwrap_err(),
        EngineError::WrongPhase
    );
    engine
        .set_profile_pic(acked.state.clone(), &rng, uid, iid, None)
        .expect("pic");
    assert_eq!(
        engine
            .set_group_name(acked.state.clone(), &rng, ids, "G")
            .unwrap_err(),
        EngineError::WrongPhase
    );
    assert_eq!(
        engine
            .set_group_photo(acked.state.clone(), &rng, ids, None)
            .unwrap_err(),
        EngineError::WrongPhase
    );
    engine
        .accept_group(acked.state.clone(), &rng, ids)
        .expect("ag");
    engine
        .reject_group(acked.state.clone(), &rng, ids)
        .expect("rg");
    engine
        .kick_group_member(acked.state.clone(), &rng, ids, &[1])
        .expect("kg");
    engine
        .leave_group(acked.state.clone(), &rng, ids)
        .expect("lg");
    assert_eq!(
        engine
            .create_group(acked.state.clone(), &rng, uid, iid, &[], "G", None)
            .unwrap_err(),
        EngineError::MemberCap
    );
    assert_eq!(
        engine
            .create_group(acked.state.clone(), &rng, uid, iid, &[cid], "G", None)
            .unwrap_err(),
        EngineError::WrongPhase
    );
    assert_eq!(
        engine
            .add_group_member(acked.state.clone(), &rng, ids, cid)
            .unwrap_err(),
        EngineError::WrongPhase
    );
    let _ = engine.confirmation_digest(&acked.state, &ids).unwrap_err();
    engine
        .delete_conversation(acked.state.clone(), ids)
        .expect("dc");
    let (sync_ok, _sid) = engine
        .create_sync_invite(
            restored,
            &rng,
            Policy::Classic,
            1_900_000_000,
            "phone",
            None,
        )
        .expect("sync");
    engine
        .set_device_name(sync_ok.state.clone(), &rng, "phone")
        .expect("dn");
    engine
        .kick_device(
            sync_ok.state.clone(),
            &rng,
            crate::protocol::v1::DeviceId::from_bytes([9; 32]),
        )
        .expect("kd");
    let kicked = engine
        .kick_device(
            sync_ok.state.clone(),
            &rng,
            crate::protocol::v1::DeviceId::from_bytes([9; 32]),
        )
        .expect("kd2");
    let kick_fresh = engine.tick(EngineState::new(), 2_050_000_000).expect("tk");
    engine
        .apply(kick_fresh.state, &kicked.persist()[0])
        .expect("ak");
    engine.leave_sync(sync_ok.state, &rng).expect("ls");
    assert!(
        engine
            .ingest_list(
                invited.state.clone(),
                &rng,
                w.channel.clone(),
                w.tag,
                &[vec![1]]
            )
            .is_ok()
    );
    assert!(
        engine
            .ingest_list(invited.state.clone(), &rng, w.channel.clone(), w.tag, &[])
            .is_ok()
    );
    assert_eq!(
        engine
            .write_blob_ack(
                invited.state.clone(),
                crate::protocol::v1::Kind::try_from("blossom").expect("k"),
                crate::protocol::v1::Address::try_from("https://blob.example").expect("a"),
                crate::protocol::v1::Tag::from_bytes([1; 32]),
                &[]
            )
            .unwrap_err(),
        EngineError::UnknownWrite
    );
    assert_eq!(
        engine
            .wrap_dek(&rng, &UnlockSecret::Passphrase("short".into()))
            .unwrap_err(),
        EngineError::UnlockFailed
    );
    assert_eq!(
        engine.unlock(b"null", &UnlockSecret::Passphrase("passpass".into())),
        Err(EngineError::UnlockFailed)
    );
    let header = engine
        .wrap_dek(&rng, &UnlockSecret::Prf([8; 32]))
        .expect("prfh");
    engine.lock();
    engine
        .unlock(&header.header, &UnlockSecret::Prf([8; 32]))
        .expect("prfu");
    let pass_h = engine
        .wrap_dek(&rng, &UnlockSecret::Passphrase("passpass".into()))
        .expect("ph");
    engine.lock();
    assert_eq!(
        engine.unlock(&pass_h.header, &UnlockSecret::Prf([8; 32])),
        Err(EngineError::UnlockFailed)
    );
    engine
        .unlock(&pass_h.header, &UnlockSecret::Passphrase("passpass".into()))
        .expect("pu");
    let prf_h = engine
        .wrap_dek(&rng, &UnlockSecret::Prf([8; 32]))
        .expect("pr2");
    engine.lock();
    assert_eq!(
        engine.unlock(&prf_h.header, &UnlockSecret::Passphrase("passpass".into())),
        Err(EngineError::UnlockFailed)
    );
    engine
        .unlock(&prf_h.header, &UnlockSecret::Prf([8; 32]))
        .expect("pru2");
    let salt = engine.suite.b64u().encode(&[9u8; 16]);
    let nonce = engine.suite.b64u().encode(&[8u8; 12]);
    let pass_missing_ct = engine.suite.canonical_json().encode(&Json::Object(vec![
        ("salt".into(), Json::String(salt.clone())),
        ("passphrase_nonce".into(), Json::String(nonce.clone())),
        ("passphrase_wrapped_dek".into(), Json::Null),
    ]));
    engine.lock();
    assert_eq!(
        engine.unlock(
            &pass_missing_ct,
            &UnlockSecret::Passphrase("passpass".into())
        ),
        Err(EngineError::UnlockFailed)
    );
    let prf_missing_ct = engine.suite.canonical_json().encode(&Json::Object(vec![
        ("salt".into(), Json::String(salt)),
        ("prf_nonce".into(), Json::String(nonce)),
        ("prf_wrapped_dek".into(), Json::Null),
    ]));
    assert_eq!(
        engine.unlock(&prf_missing_ct, &UnlockSecret::Prf([8; 32])),
        Err(EngineError::UnlockFailed)
    );
    engine
        .unlock(&prf_h.header, &UnlockSecret::Prf([8; 32]))
        .expect("pru3");
    assert!(Engine::try_new_display_name("Ada").is_ok());
    let received = engine
        .receive_ticket(folded, &rng, uid, iid, &ticket)
        .expect("recv");
    assert_eq!(
        engine
            .receive_sync_ticket(received.0.state.clone(), &rng, &ticket)
            .unwrap_err(),
        EngineError::EmptyEngineRequired
    );
    engine
        .delete_identity(received.0.state.clone(), uid, iid)
        .expect("di");
    engine.delete_user(received.0.state, uid).expect("du");
    engine.lock();
    assert_eq!(
        engine.poll(&EngineState::new()).unwrap_err(),
        EngineError::NotTicked
    );
    let _ = invited.pings();
    let _ = format!(
        "{:?}",
        ConversationRef {
            user_id: crate::protocol::v1::UserId::from_bytes([1; 32]),
            identity_id: crate::protocol::v1::IdentityId::from_bytes([2; 32]),
            conversation_id: crate::protocol::v1::ConversationId::from_bytes([3; 32]),
        }
    );
    let _ = format!(
        "{:?}",
        super::MediaDraft {
            media_bytes: vec![1],
            mime: "a".into(),
            filename: "b".into(),
        }
    );
}

#[test]
fn library_edges() {
    let mut engine = test_engine();
    let rng = CounterRng::new();
    engine
        .wrap_dek(&rng, &UnlockSecret::Passphrase("passpass".into()))
        .expect("wrap");
    assert_eq!(
        engine.apply_folded(&[]).unwrap_err(),
        EngineError::MalformedPersist
    );
    let mut ticked = engine
        .tick(EngineState::new(), 1_700_000_000)
        .expect("tick");
    ticked.state.set_next_seq(u64::MAX);
    assert_eq!(
        engine.create_user(ticked.state.clone(), &rng).unwrap_err(),
        EngineError::MalformedPersist
    );
    ticked.state.set_next_seq(0);
    let (created, uid) = engine.create_user(ticked.state, &rng).expect("u");
    let (created, iid) = engine
        .create_identity(created.state, &rng, uid, Policy::Classic)
        .expect("i");
    let (invited, cid) = engine
        .create_invite(created.state, &rng, uid, iid, 1_800_000_000, None)
        .expect("inv");
    let ids = ConversationRef {
        user_id: uid,
        identity_id: iid,
        conversation_id: cid,
    };
    assert_eq!(
        engine
            .confirm_established(invited.state.clone(), &rng, ids)
            .unwrap_err(),
        EngineError::WrongPhase
    );
    assert_eq!(
        engine
            .reject_established(invited.state.clone(), &rng, ids)
            .unwrap_err(),
        EngineError::WrongPhase
    );
    let media = engine
        .send_media(
            invited.state.clone(),
            &rng,
            ids,
            &[super::MediaDraft {
                media_bytes: b"blob".to_vec(),
                mime: "image/png".into(),
                filename: "a.png".into(),
            }],
            None,
            Some("cap"),
        )
        .unwrap_err();
    assert_eq!(media, EngineError::WrongPhase);
    assert_eq!(
        engine
            .send_media(invited.state.clone(), &rng, ids, &[], None, None)
            .unwrap_err(),
        EngineError::MalformedPayload
    );
    assert_eq!(
        engine
            .send_media(
                invited.state.clone(),
                &rng,
                ids,
                &vec![
                    super::MediaDraft {
                        media_bytes: vec![1],
                        mime: "image/png".into(),
                        filename: "a.png".into(),
                    };
                    5
                ],
                None,
                None,
            )
            .unwrap_err(),
        EngineError::MalformedPayload
    );
    assert_eq!(
        engine
            .send_media(
                invited.state.clone(),
                &rng,
                ids,
                &[super::MediaDraft {
                    media_bytes: vec![1],
                    mime: "image/png".into(),
                    filename: "a\u{0301}.png".into(),
                }],
                None,
                Some(""),
            )
            .unwrap_err(),
        EngineError::MalformedPayload
    );
    assert_eq!(
        engine
            .ticket_host_string(&EngineState::new(), &ids)
            .unwrap_err(),
        EngineError::UnknownIds
    );
    assert_eq!(
        engine
            .receive_ticket(invited.state.clone(), &rng, uid, iid, "!!")
            .unwrap_err(),
        EngineError::MalformedTicket
    );
    assert_eq!(
        engine
            .get_conversation(
                &invited.state,
                uid,
                iid,
                crate::protocol::v1::ConversationId::from_bytes([9; 32])
            )
            .unwrap_err(),
        EngineError::UnknownIds
    );
    let (sync_ok, sid) = engine
        .create_sync_invite(
            invited.state.clone(),
            &rng,
            Policy::Classic,
            1_900_000_000,
            "phone",
            None,
        )
        .expect("sy");
    let _ = engine
        .create_sync_invite(
            sync_ok.state.clone(),
            &rng,
            Policy::Classic,
            1_900_000_001,
            "phone2",
            None,
        )
        .expect("sy2");
    assert_eq!(
        engine.poll(&sync_ok.state).expect("sp").write_durable[0]
            .body
            .len(),
        crate::protocol::v1::PACKET_LEN
    );
    assert!(sync_ok.state.send_chain_seq(&sid).unwrap() >= 1);
    assert!(matches!(
        engine
            .get_conversation(&sync_ok.state, uid, iid, sid)
            .expect("sq"),
        super::Conversation::HandshakeSync(super::Handshake::Inviter(
            super::HandshakeInviter::InviteCreated { .. }
        ))
    ));
    let sync_rows = engine
        .list_conversations(&sync_ok.state, uid, iid)
        .expect("srows");
    assert!(
        sync_rows
            .iter()
            .any(|row| matches!(row.conversation, super::Conversation::HandshakeSync(_)))
    );
    assert_eq!(
        engine
            .create_sync_invite(
                invited.state.clone(),
                &rng,
                Policy::Classic,
                1,
                "phone",
                None
            )
            .unwrap_err(),
        EngineError::ExpiresNotAfterNow
    );
    assert_eq!(
        engine
            .kick_device(
                sync_ok.state.clone(),
                &rng,
                sync_ok.state.device.keys.as_ref().unwrap().id.unwrap()
            )
            .unwrap_err(),
        EngineError::WrongPhase
    );
    assert_eq!(
        engine
            .set_group_photo(invited.state.clone(), &rng, ids, Some(&[1, 2, 3]))
            .unwrap_err(),
        EngineError::MalformedPayload
    );
    assert_eq!(
        engine
            .set_profile_pic(invited.state.clone(), &rng, uid, iid, Some(&[1]))
            .unwrap_err(),
        EngineError::MalformedPayload
    );
    engine
        .set_device_name(EngineState::new(), &rng, "")
        .unwrap_err();
    let rec = invited.persist()[0].clone();
    assert_eq!(
        engine.apply_folded(&rec).unwrap_err(),
        EngineError::MalformedPersist
    );
    let empty = engine.tick(EngineState::new(), 2_000_000_000).expect("t2");
    engine
        .receive_sync_ticket(empty.state, &rng, "aa")
        .unwrap_err();
    assert_eq!(
        engine
            .edit_message(
                invited.state.clone(),
                &rng,
                ids,
                crate::protocol::v1::Tag::from_bytes([1; 32]),
                "",
            )
            .unwrap_err(),
        EngineError::MalformedPayload
    );
    assert_eq!(
        engine
            .send_reaction(
                invited.state.clone(),
                &rng,
                ids,
                crate::protocol::v1::Tag::from_bytes([1; 32]),
                "",
                true,
            )
            .unwrap_err(),
        EngineError::MalformedPayload
    );
    assert_eq!(
        engine
            .send_media(
                invited.state.clone(),
                &rng,
                ids,
                &[super::MediaDraft {
                    media_bytes: b"blob".to_vec(),
                    mime: String::new(),
                    filename: "a.png".into(),
                }],
                None,
                None,
            )
            .unwrap_err(),
        EngineError::MalformedPayload
    );
    let named = engine
        .set_device_name(EngineState::new(), &rng, "phone")
        .expect("dev");
    assert!(named.state.device.name.is_some());
    assert_eq!(
        engine
            .unlock(b"[]", &UnlockSecret::Passphrase("passpass".into()))
            .unwrap_err(),
        EngineError::UnlockFailed
    );
    assert_eq!(
        engine
            .unlock(
                br#"{"salt":1}"#,
                &UnlockSecret::Passphrase("passpass".into())
            )
            .unwrap_err(),
        EngineError::UnlockFailed
    );
    assert_eq!(
        engine
            .confirm_established(invited.state.clone(), &rng, ids)
            .unwrap_err(),
        EngineError::WrongPhase
    );
    assert_eq!(
        engine
            .send_text(invited.state.clone(), &rng, ids, "hi", None)
            .unwrap_err(),
        EngineError::WrongPhase
    );
    assert_eq!(
        engine
            .send_text(invited.state.clone(), &rng, ids, "hi", None)
            .unwrap_err(),
        EngineError::WrongPhase
    );
    let missing = ConversationRef {
        user_id: uid,
        identity_id: iid,
        conversation_id: ConversationId::from_bytes([7; 32]),
    };
    assert_eq!(
        engine
            .send_text(invited.state.clone(), &rng, missing, "hi", None)
            .unwrap_err(),
        EngineError::WrongPhase
    );
    assert_eq!(
        engine
            .delete_conversation(invited.state.clone(), missing)
            .unwrap_err(),
        EngineError::UnknownIds
    );
    let ghost = ConversationRef {
        user_id: uid,
        identity_id: IdentityId::from_bytes([7; 32]),
        conversation_id: cid,
    };
    assert_eq!(
        engine
            .send_text(invited.state.clone(), &rng, ghost, "hi", None)
            .unwrap_err(),
        EngineError::UnknownIds
    );
    let mut maxed = invited.state.clone();
    maxed.set_next_seq(u64::MAX);
    assert_eq!(
        engine.fold(maxed.clone()).unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .create_identity(maxed.clone(), &rng, uid, Policy::Classic)
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .set_display_name(maxed.clone(), &rng, uid, iid, "Ada")
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .unset_display_name(maxed.clone(), uid, iid)
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .set_profile_pic(maxed.clone(), &rng, uid, iid, None)
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine.set_device_name(maxed, &rng, "phone").unwrap_err(),
        EngineError::MalformedPersist
    );
    let secret = engine.engine_secret().expect("es");
    let init = TxPayload::EngineInit;
    let init_id = engine.tx_id(&secret, &init);
    let mut collided = engine
        .tick(EngineState::new(), 2_100_000_000)
        .expect("t3")
        .state;
    collided.txs.insert(
        init_id,
        DurableBody {
            conversation_id: engine.engine_conversation_id().expect("eid"),
            hlc: Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: TxPayload::EngineCreateUser {
                user_id: UserId::from_bytes([0; 32]),
            },
        },
    );
    assert_eq!(
        engine
            .set_defaults(
                collided,
                engine.get_defaults(&EngineState::new()).expect("gd")
            )
            .unwrap_err(),
        EngineError::Equivocation
    );
    let fresh = engine.tick(EngineState::new(), 2_200_000_000).expect("t4");
    let rec0 = invited.persist()[0].clone();
    let applied = engine.apply(fresh.state, &rec0).expect("ap0");
    assert!(applied.tx_count() > 0);
    let mut collide_apply = applied.clone();
    let body = collide_apply.txs.values().next().expect("b").clone();
    let tx_id = *collide_apply.txs.keys().next().expect("k");
    collide_apply.txs.insert(
        tx_id,
        DurableBody {
            conversation_id: body.conversation_id,
            hlc: body.hlc,
            payload: TxPayload::EngineDeleteUser {
                user_id: UserId::from_bytes([0; 32]),
            },
        },
    );
    assert_eq!(
        engine.apply(collide_apply, &rec0).unwrap_err(),
        EngineError::Equivocation
    );
    let sync_fold = engine.fold(sync_ok.state.clone()).expect("sfold");
    let restored_sync = engine.apply_folded(&sync_fold.snapshot).expect("as");
    assert!(restored_sync.has_sync_handshake());
    fn seal_fold(engine: &Engine, json: Json, seq: u64) -> Vec<u8> {
        let dek = engine.dek.as_ref().expect("dek");
        let canonical = engine.suite.canonical_json().encode(&json);
        let packed = engine.suite.compress().compress(&canonical);
        let mut nonce_bytes = [0u8; AEAD_NONCE_LEN];
        nonce_bytes[..4].copy_from_slice(&FOLD_VERSION.to_be_bytes());
        nonce_bytes[4..].copy_from_slice(&seq.to_be_bytes());
        let ct = engine
            .suite
            .aead()
            .seal(dek, &AeadNonce::from_bytes(nonce_bytes), b"", &packed);
        let mut snapshot = Vec::with_capacity(AEAD_NONCE_LEN + ct.len());
        snapshot.extend_from_slice(&nonce_bytes);
        snapshot.extend_from_slice(&ct);
        snapshot
    }
    assert_eq!(
        engine
            .apply_folded(&seal_fold(&engine, Json::Array(Vec::new()), 0))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![("next_seq".into(), Json::String("1".into()))]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    ("ticked".into(), Json::Bool(true)),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    let with_null_tick = engine
        .apply_folded(&seal_fold(
            &engine,
            Json::Object(vec![
                ("next_seq".into(), Json::Number(1)),
                ("ticked".into(), Json::Null),
            ]),
            0,
        ))
        .expect("nulltick");
    assert!(with_null_tick.ticked.is_none());
    let omitted_tick = engine
        .apply_folded(&seal_fold(
            &engine,
            Json::Object(vec![("next_seq".into(), Json::Number(2))]),
            0,
        ))
        .expect("omit");
    assert!(omitted_tick.ticked.is_none());
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    ("txs".into(), Json::Array(vec![Json::Number(1)])),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "txs".into(),
                        Json::Array(vec![Json::Object(vec![("tx_id".into(), Json::Number(1))])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    ("tickets".into(), Json::Array(vec![Json::Number(1)])),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "tickets".into(),
                        Json::Array(vec![Json::Object(vec![(
                            "conversation_id".into(),
                            Json::Number(1)
                        )])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    ("chains".into(), Json::Number(1)),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    ("chains".into(), Json::Array(vec![Json::Null])),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    ("recv_chains".into(), Json::Number(1)),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    ("skipped_mks".into(), Json::Number(1)),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    ("skipped_mks".into(), Json::Array(vec![Json::Null])),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "skipped_mks".into(),
                        Json::Array(vec![Json::Object(vec![(
                            "conversation_id".into(),
                            Json::Number(1)
                        ),])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    ("frags".into(), Json::Number(1)),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    ("frags".into(), Json::Array(vec![Json::Null])),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    ("bins".into(), Json::Number(1)),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    ("bins".into(), Json::Array(vec![Json::Null])),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "bins".into(),
                        Json::Array(vec![Json::Object(vec![("channel".into(), Json::Null)])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "skipped_mks".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("conversation_id".into(), Json::String("00".repeat(32))),
                            ("actor_id".into(), Json::String("00".repeat(32))),
                            ("mks".into(), Json::Number(1)),
                        ])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "skipped_mks".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("conversation_id".into(), Json::String("00".repeat(32))),
                            ("actor_id".into(), Json::String("00".repeat(32))),
                            ("mks".into(), Json::Array(vec![Json::Null])),
                        ])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "frags".into(),
                        Json::Array(vec![Json::Object(vec![("tx_id".into(), Json::Number(1))])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "frags".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("tx_id".into(), Json::String("00".repeat(32))),
                            ("conversation_id".into(), Json::String("00".repeat(32))),
                            ("last_i".into(), Json::Bool(true)),
                            ("parts".into(), Json::Array(Vec::new())),
                        ])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "frags".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("tx_id".into(), Json::String("00".repeat(32))),
                            ("conversation_id".into(), Json::String("00".repeat(32))),
                            ("last_i".into(), Json::Null),
                            ("parts".into(), Json::Number(1)),
                        ])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "frags".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("tx_id".into(), Json::String("00".repeat(32))),
                            ("conversation_id".into(), Json::String("00".repeat(32))),
                            ("last_i".into(), Json::Null),
                            ("parts".into(), Json::Array(vec![Json::Null])),
                        ])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "bins".into(),
                        Json::Array(vec![Json::Object(vec![
                            (
                                "channel".into(),
                                Json::Object(vec![
                                    ("kind".into(), Json::Number(1)),
                                    ("address".into(), Json::String("x".into())),
                                ])
                            ),
                            ("tag_key".into(), Json::String("00".repeat(32))),
                            ("watermark".into(), Json::Null),
                            ("completed".into(), Json::Array(Vec::new())),
                        ])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "bins".into(),
                        Json::Array(vec![Json::Object(vec![
                            (
                                "channel".into(),
                                Json::Object(vec![
                                    ("kind".into(), Json::String("nostr".into())),
                                    ("address".into(), Json::Number(1)),
                                ])
                            ),
                            ("tag_key".into(), Json::String("00".repeat(32))),
                            ("watermark".into(), Json::Null),
                            ("completed".into(), Json::Array(Vec::new())),
                        ])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    let hex32 = "00".repeat(32);
    let z32 = super::super::codec::bstr(engine.suite.b64u(), &[0u8; 32]);
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "skipped_mks".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("conversation_id".into(), z32.clone()),
                            ("actor_id".into(), z32.clone()),
                            (
                                "mks".into(),
                                Json::Array(vec![Json::Object(vec![
                                    ("mk".into(), Json::String(hex32.clone())),
                                    ("expires_at".into(), Json::Bool(true)),
                                ])])
                            ),
                        ])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "skipped_mks".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("conversation_id".into(), z32.clone()),
                            ("actor_id".into(), Json::Number(1)),
                            ("mks".into(), Json::Array(Vec::new())),
                        ])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "skipped_mks".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("conversation_id".into(), z32.clone()),
                            ("actor_id".into(), z32.clone()),
                            (
                                "mks".into(),
                                Json::Array(vec![Json::Object(vec![(
                                    "expires_at".into(),
                                    Json::Number(1)
                                )])])
                            ),
                        ])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "skipped_mks".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("conversation_id".into(), z32.clone()),
                            ("actor_id".into(), z32.clone()),
                            (
                                "mks".into(),
                                Json::Array(vec![Json::Object(vec![
                                    ("mk".into(), Json::String("00".into())),
                                    ("expires_at".into(), Json::Number(1)),
                                    ("tx_id".into(), Json::Number(1)),
                                ])])
                            ),
                        ])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "skipped_mks".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("conversation_id".into(), z32.clone()),
                            ("actor_id".into(), z32.clone()),
                            (
                                "mks".into(),
                                Json::Array(vec![Json::Object(vec![
                                    ("mk".into(), z32.clone()),
                                    ("expires_at".into(), Json::Number(1)),
                                    ("tx_id".into(), Json::Number(1)),
                                ])])
                            ),
                        ])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "frags".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("tx_id".into(), Json::String(hex32.clone())),
                            ("conversation_id".into(), Json::String("00".into())),
                        ])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "frags".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("tx_id".into(), Json::String(hex32.clone())),
                            ("conversation_id".into(), Json::String(hex32.clone())),
                            ("last_i".into(), Json::Null),
                            (
                                "parts".into(),
                                Json::Array(vec![Json::Object(vec![(
                                    "i".into(),
                                    Json::Bool(true)
                                )])])
                            ),
                        ])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "frags".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("tx_id".into(), Json::String(hex32.clone())),
                            ("conversation_id".into(), Json::String(hex32.clone())),
                            ("last_i".into(), Json::Null),
                            (
                                "parts".into(),
                                Json::Array(vec![Json::Object(vec![
                                    ("i".into(), Json::Number(0)),
                                    ("frag".into(), Json::Number(1)),
                                ])])
                            ),
                        ])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    let ch = Json::Object(vec![
        ("kind".into(), Json::String("nostr".into())),
        ("address".into(), Json::String("wss://relay.example".into())),
    ]);
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "bins".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("channel".into(), ch.clone()),
                            ("watermark".into(), Json::Null),
                            ("completed".into(), Json::Array(Vec::new())),
                        ])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "bins".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("channel".into(), ch.clone()),
                            ("tag_key".into(), Json::String("00".into())),
                            ("watermark".into(), Json::Null),
                            ("completed".into(), Json::Array(Vec::new())),
                        ])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "bins".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("channel".into(), ch.clone()),
                            ("tag_key".into(), Json::String(hex32.clone())),
                            ("watermark".into(), Json::Bool(true)),
                            ("completed".into(), Json::Array(Vec::new())),
                        ])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "bins".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("channel".into(), ch.clone()),
                            ("tag_key".into(), Json::String(hex32.clone())),
                            ("watermark".into(), Json::Null),
                            ("completed".into(), Json::Number(1)),
                        ])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    engine
        .apply_folded(&seal_fold(
            &engine,
            Json::Object(vec![
                ("next_seq".into(), Json::Number(1)),
                (
                    "bins".into(),
                    Json::Array(vec![Json::Object(vec![
                        ("channel".into(), ch.clone()),
                        ("tag_key".into(), z32.clone()),
                        ("watermark".into(), Json::Null),
                        ("completed".into(), Json::Array(vec![Json::Number(3)])),
                    ])]),
                ),
            ]),
            0,
        ))
        .expect("okbin");
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "bins".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("channel".into(), ch),
                            ("tag_key".into(), Json::String(hex32.clone())),
                            ("watermark".into(), Json::Number(3)),
                            ("completed".into(), Json::Array(vec![Json::Bool(true)])),
                        ])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    ("failed".into(), Json::Bool(true)),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    ("owners".into(), Json::Bool(true)),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    ("inviters".into(), Json::Bool(true)),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    ("intake".into(), Json::Bool(true)),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    ("shared_inviter".into(), Json::Bool(true)),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    ("established".into(), Json::Bool(true)),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    ("shared_invitee".into(), Json::Bool(true)),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "established".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("conversation_id".into(), Json::String(hex32.clone())),
                            ("handshake_id".into(), Json::String(hex32.clone())),
                            ("secret".into(), Json::String(hex32.clone())),
                        ])]),
                    ),
                ]),
                0,
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "established".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("conversation_id".into(), Json::String(hex32.clone())),
                            ("secret".into(), Json::String(hex32.clone())),
                        ])]),
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "established".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("conversation_id".into(), Json::String(hex32.clone())),
                            ("handshake_id".into(), Json::String(hex32.clone())),
                            ("secret".into(), Json::String(hex32.clone())),
                            ("sync".into(), Json::String("x".into())),
                        ])]),
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    ("established".into(), Json::Array(vec![Json::Bool(true)])),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    ("shared_inviter".into(), Json::Array(vec![Json::Bool(true)])),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    ("intake".into(), Json::Array(vec![Json::Bool(true)])),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    ("failed".into(), Json::Array(vec![Json::Bool(true)])),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    ("owners".into(), Json::Array(vec![Json::Bool(true)])),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "failed".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("conversation_id".into(), Json::String(hex32.clone())),
                            ("reason".into(), Json::String("nope".into())),
                        ])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "failed".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("conversation_id".into(), Json::String(hex32.clone())),
                            ("reason".into(), Json::String("PolicyNotAccepted".into())),
                            ("policy".into(), Json::String("nope".into())),
                        ])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    ("device_enc".into(), Json::Bool(true)),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "failed".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("conversation_id".into(), Json::String(hex32.clone())),
                            ("reason".into(), Json::Number(1)),
                        ])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "failed".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("conversation_id".into(), Json::String(hex32.clone())),
                            ("reason".into(), Json::String("InviteExpired".into())),
                        ])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "failed".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("conversation_id".into(), Json::String(hex32.clone())),
                            ("reason".into(), Json::String("PolicyNotAccepted".into())),
                        ])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    engine.lock();
    assert_eq!(
        engine
            .set_device_name(invited.state.clone(), &rng, "phone")
            .unwrap_err(),
        EngineError::Locked
    );
}

#[test]
fn query_adt_debug() {
    use super::{
        BlockedIdentity, BlockedMissing, Conversation, DirectMessageQuery, FailedReason,
        GroupQuery, Handshake, HandshakeInvitee, HandshakeInviter, SynchronizationQuery,
    };
    let expires = UnixSeconds::from_u64(1);
    let digest = String::new();
    let policy = Policy::Classic;
    for inviter in [
        HandshakeInviter::InviteCreated { expires },
        HandshakeInviter::NoticePinned { expires },
        HandshakeInviter::IntroductionMinted { expires },
        HandshakeInviter::Confirming {
            expires,
            confirmation_digest: digest.clone(),
        },
    ] {
        let _ = format!("{inviter:?}");
    }
    for invitee in [
        HandshakeInvitee::TicketReceived,
        HandshakeInvitee::InviteReceived { policy, expires },
        HandshakeInvitee::IntroductionMinted { policy, expires },
        HandshakeInvitee::IntroductionSent { policy, expires },
        HandshakeInvitee::Confirming {
            policy,
            expires,
            confirmation_digest: digest,
        },
    ] {
        let _ = format!("{invitee:?}");
    }
    for reason in [
        FailedReason::PolicyNotAccepted {
            policy: Policy::Hybrid,
        },
        FailedReason::InviteExpired { expires },
        FailedReason::NoticeUnlockFailed,
        FailedReason::NoticeConflict,
        FailedReason::IntroUnlockFailed,
        FailedReason::IntroVerifyFailed,
        FailedReason::DuplicateIntro,
        FailedReason::ConfirmationRejected,
        FailedReason::Equivocation,
        FailedReason::OfferRejected,
        FailedReason::Kicked,
        FailedReason::Left,
    ] {
        let _ = format!("{reason:?}");
    }
    let _ = format!(
        "{:?}",
        Handshake::Inviter(HandshakeInviter::InviteCreated { expires })
    );
    let _ = format!("{:?}", Handshake::Invitee(HandshakeInvitee::TicketReceived));
    let _ = format!("{:?}", Handshake::Failed(FailedReason::Left));
    let _ = format!(
        "{:?}",
        DirectMessageQuery::Established(super::DmEstablished::default())
    );
    let _ = format!("{:?}", DirectMessageQuery::Failed(FailedReason::Left));
    let _ = format!("{:?}", GroupQuery::GroupOffer);
    let _ = format!("{:?}", GroupQuery::GroupEstablished);
    let _ = format!("{:?}", GroupQuery::GroupFailed(FailedReason::Kicked));
    let hs = Handshake::Invitee(HandshakeInvitee::TicketReceived);
    let _ = format!("{:?}", SynchronizationQuery::Handshake(hs));
    let _ = format!("{:?}", SynchronizationQuery::SyncEstablished);
    let _ = format!("{:?}", SynchronizationQuery::Failed(FailedReason::Left));
    let _ = format!(
        "{:?}",
        Conversation::HandshakeDm(Handshake::Inviter(HandshakeInviter::InviteCreated {
            expires
        }))
    );
    let _ = format!(
        "{:?}",
        Conversation::HandshakeSync(Handshake::Inviter(HandshakeInviter::InviteCreated {
            expires
        }))
    );
    let _ = format!(
        "{:?}",
        Conversation::DirectMessage(DirectMessageQuery::Established(
            super::DmEstablished::default()
        ))
    );
    let _ = format!("{:?}", Conversation::Group(GroupQuery::GroupOffer));
    let _ = format!(
        "{:?}",
        Conversation::Synchronization(SynchronizationQuery::SyncEstablished)
    );
    let _ = format!(
        "{:?}",
        BlockedIdentity {
            user_id: crate::protocol::v1::UserId::from_bytes([1; 32]),
            identity_id: crate::protocol::v1::IdentityId::from_bytes([2; 32]),
            missing: BlockedMissing::DisplayName,
        }
    );
}

#[test]
fn invite_packets_open_from_ticket_secret() {
    use super::super::chain::{join, open_skip_ahead};
    use super::super::codec::ticket_from_json;
    use super::super::payload::{ConversationSort, PACKET_LEN, TICKET_MAX_UNCOMPRESSED};
    let mut engine = test_engine();
    let rng = CounterRng::new();
    engine
        .wrap_dek(&rng, &UnlockSecret::Passphrase("passpass".into()))
        .expect("wrap");
    let ticked = engine
        .tick(EngineState::new(), 1_700_000_000)
        .expect("tick");
    let (created, uid) = engine.create_user(ticked.state, &rng).expect("user");
    let (created, iid) = engine
        .create_identity(created.state, &rng, uid, Policy::Classic)
        .expect("id");
    let (invited, cid) = engine
        .create_invite(created.state, &rng, uid, iid, 1_800_000_000, None)
        .expect("inv");
    let ids = ConversationRef {
        user_id: uid,
        identity_id: iid,
        conversation_id: cid,
    };
    let ticket_s = engine.ticket_host_string(&invited.state, &ids).expect("t");
    let packed = engine.suite.b64u().decode(&ticket_s).expect("dec");
    let canonical = engine
        .suite
        .compress()
        .decompress(&packed, TICKET_MAX_UNCOMPRESSED)
        .expect("z");
    let json = engine.suite.canonical_json().decode(&canonical).expect("j");
    let ticket = ticket_from_json(engine.suite.b64u(), &json).expect("ticket");
    let chain = join(
        engine.suite.hmac(),
        ticket.secret.as_bytes(),
        ConversationSort::HandshakeDm,
        &[],
    )
    .expect("join");
    let poll = engine.poll(&invited.state).expect("p");
    assert_eq!(poll.write_durable[0].body.len(), PACKET_LEN);
    let opened = open_skip_ahead(
        &engine.suite,
        &chain,
        &[],
        1_700_000_000,
        &poll.write_durable[0].body,
    )
    .expect("open");
    assert!(!opened.from_cache);
    let tx_id = *invited
        .state
        .txs
        .iter()
        .find(|(_, b)| b.conversation_id == cid)
        .expect("tx")
        .0;
    let mut state = invited.state.clone();
    let seq0 = state.send_chain_seq(&cid).expect("seq");
    engine
        .post_handshake_packets(&mut state, &rng, cid, &ticket.secret, tx_id)
        .expect("again");
    assert!(state.send_chain_seq(&cid).expect("seq2") > seq0);
    let snap = engine.fold(invited.state.clone()).expect("fsnap");
    let restored = engine.apply_folded(&snap.snapshot).expect("rsnap");
    assert_eq!(
        restored.send_chain_seq(&cid),
        invited.state.send_chain_seq(&cid)
    );
    let mut with_recv = invited.state.clone();
    if let Some(chain) = with_recv
        .chains(cid)
        .and_then(|c| c.send.values().next().cloned())
    {
        with_recv.put_recv_chain(cid, ActorId::handshake(), chain);
    }
    let recv_snap = engine.fold(with_recv).expect("frsnap");
    assert!(
        engine
            .apply_folded(&recv_snap.snapshot)
            .expect("rrsnap")
            .recv_chain_seq(&cid)
            .is_some()
    );
    let mut sk = invited.state.clone();
    sk.put_skipped(
        cid,
        ActorId::handshake(),
        super::super::chain::CachedMk {
            mk: [1; 32],
            expires_at: UnixSeconds::from_u64(u64::MAX),
            tx_id: Some(crate::protocol::v1::Tag::from_bytes([2; 32])),
        },
    );
    engine.fold(sk).expect("fskip");
    let mut acked = invited.state.clone();
    acked.put_last_ack(
        cid,
        ActorId::handshake(),
        [crate::protocol::v1::Tag::from_bytes([3; 32])]
            .into_iter()
            .collect(),
    );
    engine.fold(acked).expect("fack");
    let ch = ticket.persistents[0].clone();
    let tag_key = super::helpers::handshake_tag_key(engine.suite.hmac(), ticket.secret.as_bytes());
    let key = super::helpers::progress_key(&ch, &tag_key);
    let mut bins = invited.state.clone();
    bins.bin_progress.insert(
        key,
        super::state::BinProgress {
            channel: ch,
            tag_key,
            watermark: Some(crate::protocol::v1::TimeBin::from_u64(2)),
            completed: [crate::protocol::v1::TimeBin::from_u64(3)]
                .into_iter()
                .collect(),
        },
    );
    engine.fold(bins).expect("fbins");
    assert_eq!(
        engine
            .post_handshake_packets(&mut EngineState::new(), &rng, cid, &ticket.secret, tx_id,)
            .unwrap_err(),
        EngineError::NotTicked
    );
    let mut unknown = invited.state.clone();
    assert_eq!(
        engine
            .post_handshake_packets(
                &mut unknown,
                &rng,
                crate::protocol::v1::ConversationId::from_bytes([0; 32]),
                &ticket.secret,
                tx_id,
            )
            .unwrap_err(),
        EngineError::UnknownIds
    );
    let mut missing_tx = invited.state.clone();
    assert_eq!(
        engine
            .post_handshake_packets(
                &mut missing_tx,
                &rng,
                cid,
                &ticket.secret,
                crate::protocol::v1::Tag::from_bytes([0; 32]),
            )
            .unwrap_err(),
        EngineError::UnknownIds
    );
    super::helpers::annotate_cached_mk(
        &mut EngineState::new(),
        cid,
        &ActorId::handshake(),
        &[0; 32],
        crate::protocol::v1::Tag::from_bytes([0; 32]),
    );
    let ghost_hit = super::state::HandshakeHit {
        cid: ConversationId::from_bytes([0xab; 32]),
        secret: ticket.secret,
        sort: ConversationSort::HandshakeDm,
        bin: crate::protocol::v1::TimeBin::from_u64(0),
        tag_key: crate::protocol::v1::TagKey::from_bytes([0; 32]),
    };
    let mut ghost = invited.state.clone();
    engine
        .open_and_merge(
            &mut ghost,
            &rng,
            &ghost_hit,
            UnixSeconds::from_u64(1_700_000_000),
            &poll.write_durable[0].body,
            true,
        )
        .expect("ghosthit");
    let mut huge = invited.state.clone();
    huge.txs.insert(
        tx_id,
        DurableBody {
            conversation_id: cid,
            hlc: Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: TxPayload::Text(crate::protocol::v1::TxText {
                body: (0..400_000)
                    .map(|i| char::from(((i * 31) % 95 + 32) as u8))
                    .collect(),
                reply_to: None,
                expire_at: None,
            }),
        },
    );
    assert_eq!(
        engine
            .post_handshake_packets(&mut huge, &rng, cid, &ticket.secret, tx_id)
            .unwrap_err(),
        EngineError::BodyTooLarge
    );
    let dropped = engine.delete_conversation(state, ids).expect("dc");
    assert!(dropped.state.send_chain_seq(&cid).is_none());
}

#[test]
fn ingest_list_merges_notice_and_completes_bin() {
    use super::super::chain::{join, mk, seal_packet, step};
    use super::super::codec::ticket_from_json;
    use super::super::payload::{
        ConversationSort, PacketPlain, PacketTxFragLast, PacketTxFragMore, PacketXorAck,
        TICKET_MAX_UNCOMPRESSED,
    };
    use super::{Conversation, FailedReason, Handshake, HandshakeInvitee, HandshakeInviter};
    use crate::protocol::v1::Tag;
    let mut engine = test_engine();
    let rng = CounterRng::new();
    engine
        .wrap_dek(&rng, &UnlockSecret::Passphrase("passpass".into()))
        .expect("wrap");
    let ticked = engine
        .tick(EngineState::new(), 1_700_000_000)
        .expect("tick");
    let (created, uid) = engine.create_user(ticked.state, &rng).expect("user");
    let (created, iid) = engine
        .create_identity(created.state, &rng, uid, Policy::Classic)
        .expect("id");
    let (invited, cid) = engine
        .create_invite(created.state, &rng, uid, iid, 1_800_000_000, None)
        .expect("inv");
    let ids = ConversationRef {
        user_id: uid,
        identity_id: iid,
        conversation_id: cid,
    };
    let ticket_s = engine.ticket_host_string(&invited.state, &ids).expect("t");
    let poll = engine.poll(&invited.state).expect("p");
    assert_eq!(poll.listen_durable.len(), 3);
    assert!(poll.listen_ephemeral.is_empty());
    assert!(poll.list.len() >= 3);
    for i in 1..poll.list.len() {
        let a = &poll.list[i - 1];
        let b = &poll.list[i];
        assert!(
            a.channel.kind().as_str() < b.channel.kind().as_str()
                || a.channel.kind().as_str() == b.channel.kind().as_str()
                    && (a.channel.address().as_str() < b.channel.address().as_str()
                        || a.channel.address().as_str() == b.channel.address().as_str()
                            && a.tag.as_bytes() <= b.tag.as_bytes())
        );
    }
    let w = &poll.write_durable[0];
    let bodies: Vec<Vec<u8>> = poll.write_durable.iter().map(|x| x.body.clone()).collect();
    let invitee_tick = engine
        .tick(EngineState::new(), 1_700_000_000)
        .expect("itick");
    let (received, placeholder) = engine
        .receive_ticket(invitee_tick.state, &rng, uid, iid, &ticket_s)
        .expect("recv");
    assert!(matches!(
        engine
            .get_conversation(&received.state, uid, iid, placeholder)
            .expect("q0"),
        Conversation::HandshakeDm(Handshake::Invitee(HandshakeInvitee::TicketReceived))
    ));
    let empty = engine
        .ingest_list(received.state.clone(), &rng, w.channel.clone(), w.tag, &[])
        .expect("empty");
    assert!(matches!(
        engine
            .get_conversation(&empty.state, uid, iid, placeholder)
            .expect("q1"),
        Conversation::HandshakeDm(Handshake::Invitee(HandshakeInvitee::TicketReceived))
    ));
    assert_eq!(
        engine
            .ingest_packet(
                empty.state.clone(),
                &rng,
                w.channel.clone(),
                crate::protocol::v1::Tag::from_bytes([0; 32]),
                &bodies[0]
            )
            .unwrap_err(),
        EngineError::UnknownTag
    );
    let ingested = engine
        .ingest_list(empty.state, &rng, w.channel.clone(), w.tag, &bodies)
        .expect("ing");
    assert!(!ingested.persist().is_empty());
    let rows = engine
        .list_conversations(&ingested.state, uid, iid)
        .expect("rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].conversation_id, cid);
    assert!(matches!(
        rows[0].conversation,
        Conversation::HandshakeDm(Handshake::Invitee(HandshakeInvitee::InviteReceived {
            policy: Policy::Classic,
            ..
        }))
    ));
    assert!(ingested.state.recv_chain_seq(&cid).is_some());
    let again = engine
        .ingest_list(
            ingested.state.clone(),
            &rng,
            w.channel.clone(),
            w.tag,
            &bodies,
        )
        .expect("dup");
    assert!(again.persist().is_empty());
    let snap = engine.fold(ingested.state.clone()).expect("fold");
    let restored = engine.apply_folded(&snap.snapshot).expect("af");
    assert_eq!(
        restored.recv_chain_seq(&cid),
        ingested.state.recv_chain_seq(&cid)
    );
    assert!(matches!(
        engine
            .get_conversation(&restored, uid, iid, cid)
            .expect("qr"),
        Conversation::HandshakeDm(Handshake::Invitee(HandshakeInvitee::InviteReceived { .. }))
    ));
    let mut outside = ingested.state.clone();
    let extra = Tag::from_bytes([0x11; 32]);
    outside.txs.insert(
        extra,
        DurableBody {
            conversation_id: cid,
            hlc: Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: TxPayload::Confirm,
        },
    );
    outside.persist_log.insert(outside.next_seq, extra);
    outside.next_seq = outside.next_seq.saturating_add(1);
    assert_eq!(engine.fold(outside).unwrap_err(), EngineError::WrongPhase);
    let xor_match = PacketPlain::XorAck(PacketXorAck {
        actor_id: vec![9],
        packet_seq: ingested.state.recv_chain_seq(&cid).expect("rseq"),
        set_xor: super::super::chain::set_xor_for(&ingested.state.txs, cid),
    });
    let packed_t = engine.suite.b64u().decode(&ticket_s).expect("dect");
    let canonical_t = engine
        .suite
        .compress()
        .decompress(&packed_t, TICKET_MAX_UNCOMPRESSED)
        .expect("zt");
    let json_t = engine
        .suite
        .canonical_json()
        .decode(&canonical_t)
        .expect("jt");
    let ticket_m = ticket_from_json(engine.suite.b64u(), &json_t).expect("ticketm");
    let mut ack_chain = join(
        engine.suite.hmac(),
        ticket_m.secret.as_bytes(),
        ConversationSort::HandshakeDm,
        &[],
    )
    .expect("joinm");
    for _ in 0..ingested.state.recv_chain_seq(&cid).expect("rseq2") {
        ack_chain = step(engine.suite.hmac(), &ack_chain);
    }
    let b_match = seal_packet(
        &engine.suite,
        &rng,
        &mk(engine.suite.hmac(), &ack_chain),
        &xor_match,
    )
    .expect("smatch");
    let matched = engine
        .ingest_packet(
            ingested.state.clone(),
            &rng,
            w.channel.clone(),
            w.tag,
            &b_match,
        )
        .expect("xmatch");
    assert!(matched.state.has_last_acks());
    engine.fold(matched.state.clone()).expect("2ack");
    let eph = crate::protocol::v1::EphemeralChannel::new(
        crate::protocol::v1::Kind::try_from("webrtc").expect("ek"),
        crate::protocol::v1::Address::try_from("https://eph.example").expect("ea"),
    );
    assert_eq!(
        engine
            .ingest_ephemeral_packet(matched.state.clone(), &rng, eph, w.tag, &b_match)
            .unwrap_err(),
        EngineError::UnknownTag
    );
    let mut collide = ingested.state.clone();
    let notice_id = *collide
        .txs
        .iter()
        .find(|(_, b)| matches!(b.payload, TxPayload::Notice(_)))
        .expect("nid")
        .0;
    collide.txs.insert(
        notice_id,
        DurableBody {
            conversation_id: cid,
            hlc: Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: TxPayload::Confirm,
        },
    );
    assert_eq!(
        engine
            .ingest_list(collide, &rng, w.channel.clone(), w.tag, &bodies)
            .unwrap_err(),
        EngineError::Equivocation
    );
    let mut listed = ingested.state.clone();
    let locators = engine.poll(&listed).expect("pl").list;
    for loc in locators {
        listed = engine
            .ingest_list(listed, &rng, loc.channel, loc.tag, &[])
            .expect("catch")
            .state;
    }
    assert_eq!(engine.poll(&listed).expect("pl2").list.len(), 3);
    listed = engine
        .ingest_list(listed, &rng, w.channel.clone(), w.tag, &[])
        .expect("againw")
        .state;
    let far = engine.tick(listed, 1_700_000_000 + 80 * 3600).expect("far");
    let fp = engine.poll(&far.state).expect("fpoll");
    assert!(fp.list.len() > 3);
    engine
        .ingest_list(
            far.state,
            &rng,
            fp.list[0].channel.clone(),
            fp.list[0].tag,
            &[],
        )
        .expect("prune");
    let packed = engine.suite.b64u().decode(&ticket_s).expect("dec");
    let canonical = engine
        .suite
        .compress()
        .decompress(&packed, TICKET_MAX_UNCOMPRESSED)
        .expect("z");
    let json = engine.suite.canonical_json().decode(&canonical).expect("j");
    let ticket = ticket_from_json(engine.suite.b64u(), &json).expect("ticket");
    let chain = join(
        engine.suite.hmac(),
        ticket.secret.as_bytes(),
        ConversationSort::HandshakeDm,
        &[],
    )
    .expect("join");
    let tx_id = notice_id;
    let more = PacketPlain::TxFragMore(PacketTxFragMore {
        actor_id: Vec::new(),
        packet_seq: 0,
        tx_id,
        frag_i: 0,
        frag: vec![1],
    });
    let last = PacketPlain::TxFragLast(PacketTxFragLast {
        actor_id: Vec::new(),
        packet_seq: 1,
        tx_id,
        frag_i: 1,
        frag: vec![2],
        set_xor: Tag::from_bytes([0; 32]),
    });
    let b_more =
        seal_packet(&engine.suite, &rng, &mk(engine.suite.hmac(), &chain), &more).expect("sm");
    let chain1 = step(engine.suite.hmac(), &chain);
    let b_last = seal_packet(
        &engine.suite,
        &rng,
        &mk(engine.suite.hmac(), &chain1),
        &last,
    )
    .expect("sl");
    let invitee2 = engine
        .tick(EngineState::new(), 1_700_000_000)
        .expect("t2")
        .state;
    let (recv2, ph2) = engine
        .receive_ticket(invitee2, &rng, uid, iid, &ticket_s)
        .expect("r2");
    let partial = engine
        .ingest_packet(recv2.state, &rng, w.channel.clone(), w.tag, &b_more)
        .expect("more");
    assert!(matches!(
        engine
            .get_conversation(&partial.state, uid, iid, ph2)
            .expect("qp"),
        Conversation::HandshakeDm(Handshake::Invitee(HandshakeInvitee::TicketReceived))
    ));
    let fold_partial = engine.fold(partial.state.clone()).expect("fp");
    let restored_partial = engine.apply_folded(&fold_partial.snapshot).expect("afp");
    let skip_first = engine
        .ingest_packet(restored_partial, &rng, w.channel.clone(), w.tag, &b_last)
        .expect("last");
    assert!(matches!(
        engine
            .get_conversation(&skip_first.state, uid, iid, ph2)
            .expect("ql"),
        Conversation::HandshakeDm(Handshake::Failed(FailedReason::NoticeUnlockFailed))
    ));
    engine
        .apply_folded(&engine.fold(skip_first.state.clone()).expect("skf").snapshot)
        .expect("skaf");
    let xor = PacketPlain::XorAck(PacketXorAck {
        actor_id: Vec::new(),
        packet_seq: 0,
        set_xor: Tag::from_bytes([1; 32]),
    });
    let b_xor =
        seal_packet(&engine.suite, &rng, &mk(engine.suite.hmac(), &chain), &xor).expect("sx");
    let invitee3 = engine
        .receive_ticket(
            engine
                .tick(EngineState::new(), 1_700_000_000)
                .expect("t3")
                .state,
            &rng,
            uid,
            iid,
            &ticket_s,
        )
        .expect("r3");
    let skipped = engine
        .ingest_packet(invitee3.0.state, &rng, w.channel.clone(), w.tag, &b_xor)
        .expect("xor");
    assert!(matches!(
        engine
            .get_conversation(&skipped.state, uid, iid, invitee3.1)
            .expect("qx"),
        Conversation::HandshakeDm(Handshake::Invitee(HandshakeInvitee::TicketReceived))
    ));
    let bad_last = PacketPlain::TxFragLast(PacketTxFragLast {
        actor_id: Vec::new(),
        packet_seq: 0,
        tx_id: Tag::from_bytes([9; 32]),
        frag_i: 0,
        frag: b"not-json".to_vec(),
        set_xor: Tag::from_bytes([0; 32]),
    });
    let b_bad = seal_packet(
        &engine.suite,
        &rng,
        &mk(engine.suite.hmac(), &chain),
        &bad_last,
    )
    .expect("sb");
    let bad = engine
        .ingest_packet(skipped.state, &rng, w.channel.clone(), w.tag, &b_bad)
        .expect("bad");
    assert!(matches!(
        engine
            .get_conversation(&bad.state, uid, iid, invitee3.1)
            .expect("qbad"),
        Conversation::HandshakeDm(Handshake::Failed(FailedReason::NoticeUnlockFailed))
    ));
    let (sync_ok, sid) = engine
        .create_sync_invite(
            invited.state.clone(),
            &rng,
            Policy::Classic,
            1_900_000_000,
            "phone",
            None,
        )
        .expect("sync");
    let sync_ids = ConversationRef {
        user_id: uid,
        identity_id: iid,
        conversation_id: sid,
    };
    let sync_ticket = engine
        .ticket_host_string(&sync_ok.state, &sync_ids)
        .expect("st");
    let sync_poll = engine.poll(&sync_ok.state).expect("sp");
    let dm_tags: Vec<_> = poll.write_durable.iter().map(|w| w.tag).collect();
    let sync_writes: Vec<_> = sync_poll
        .write_durable
        .iter()
        .filter(|w| !dm_tags.iter().any(|t| t == &w.tag))
        .cloned()
        .collect();
    let mut acked = sync_ok.state.clone();
    for write in &sync_poll.write_durable {
        acked = engine
            .write_ack(acked, write.channel.clone(), write.tag, &write.body)
            .expect("sack")
            .state;
    }
    assert!(matches!(
        engine.get_conversation(&acked, uid, iid, sid).expect("sq"),
        Conversation::HandshakeSync(Handshake::Inviter(HandshakeInviter::NoticePinned { .. }))
    ));
    let sync_invitee = engine
        .tick(EngineState::new(), 1_700_000_000)
        .expect("stt")
        .state;
    let (sync_recv, _) = engine
        .receive_sync_ticket(sync_invitee, &rng, &sync_ticket)
        .expect("srt");
    let sw = &sync_writes[0];
    let sync_bodies: Vec<Vec<u8>> = sync_writes.iter().map(|x| x.body.clone()).collect();
    let sync_ing = engine
        .ingest_list(
            sync_recv.state,
            &rng,
            sw.channel.clone(),
            sw.tag,
            &sync_bodies,
        )
        .expect("si");
    let sync_rows = engine
        .list_conversations(
            &sync_ing.state,
            UserId::from_bytes([0; 32]),
            IdentityId::from_bytes([0; 32]),
        )
        .expect("srows");
    assert!(matches!(
        sync_rows[0].conversation,
        Conversation::HandshakeSync(Handshake::Invitee(HandshakeInvitee::InviteReceived {
            policy: Policy::Classic,
            ..
        }))
    ));
    let mut leave_state = sync_ing.state.clone();
    leave_state.put_skipped(
        sid,
        ActorId::handshake(),
        super::super::chain::CachedMk {
            mk: [2; 32],
            expires_at: UnixSeconds::from_u64(u64::MAX),
            tx_id: None,
        },
    );
    engine.leave_sync(leave_state, &rng).expect("lsing");
    let disagree = PacketPlain::TxFragMore(PacketTxFragMore {
        actor_id: Vec::new(),
        packet_seq: 0,
        tx_id,
        frag_i: 0,
        frag: b"aaaa".to_vec(),
    });
    let b_dis = seal_packet(
        &engine.suite,
        &rng,
        &mk(engine.suite.hmac(), &chain),
        &disagree,
    )
    .expect("sd");
    let (recv_dis, _) = engine
        .receive_ticket(
            engine
                .tick(EngineState::new(), 1_700_000_000)
                .expect("td")
                .state,
            &rng,
            uid,
            iid,
            &ticket_s,
        )
        .expect("rd");
    let first_dis = engine
        .ingest_packet(recv_dis.state, &rng, w.channel.clone(), w.tag, &b_more)
        .expect("d1");
    let disagree2 = PacketPlain::TxFragMore(PacketTxFragMore {
        actor_id: Vec::new(),
        packet_seq: 0,
        tx_id,
        frag_i: 0,
        frag: b"bbbb".to_vec(),
    });
    let b_dis2 = seal_packet(
        &engine.suite,
        &rng,
        &mk(engine.suite.hmac(), &chain),
        &disagree2,
    )
    .expect("sd2");
    assert_eq!(
        engine
            .ingest_packet(first_dis.state, &rng, w.channel.clone(), w.tag, &b_dis2)
            .unwrap_err(),
        EngineError::Equivocation
    );
    let _ = b_dis;
    assert_eq!(
        engine
            .ingest_list(
                ingested.state.clone(),
                &rng,
                w.channel.clone(),
                crate::protocol::v1::Tag::from_bytes([2; 32]),
                &[]
            )
            .unwrap_err(),
        EngineError::UnknownTag
    );
    let other = crate::protocol::v1::DurableChannel::new(
        crate::protocol::v1::Kind::try_from("blossom").expect("k"),
        crate::protocol::v1::Address::try_from("https://blob.example").expect("a"),
    );
    assert_eq!(
        engine
            .ingest_list(ingested.state.clone(), &rng, other, w.tag, &[])
            .unwrap_err(),
        EngineError::UnknownTag
    );
    let last_hi = PacketPlain::TxFragLast(PacketTxFragLast {
        actor_id: Vec::new(),
        packet_seq: 0,
        tx_id,
        frag_i: 2,
        frag: vec![1],
        set_xor: Tag::from_bytes([0; 32]),
    });
    let last_hi2 = PacketPlain::TxFragLast(PacketTxFragLast {
        actor_id: Vec::new(),
        packet_seq: 0,
        tx_id,
        frag_i: 3,
        frag: vec![1],
        set_xor: Tag::from_bytes([0; 32]),
    });
    let b_hi = seal_packet(
        &engine.suite,
        &rng,
        &mk(engine.suite.hmac(), &chain),
        &last_hi,
    )
    .expect("shi");
    let b_hi2 = seal_packet(
        &engine.suite,
        &rng,
        &mk(engine.suite.hmac(), &chain),
        &last_hi2,
    )
    .expect("shi2");
    let (recv_hi, _) = engine
        .receive_ticket(
            engine
                .tick(EngineState::new(), 1_700_000_000)
                .expect("thi")
                .state,
            &rng,
            uid,
            iid,
            &ticket_s,
        )
        .expect("rhi");
    let partial_hi = engine
        .ingest_packet(recv_hi.state, &rng, w.channel.clone(), w.tag, &b_hi)
        .expect("hi");
    let _ = engine.fold(partial_hi.state.clone()).expect("fhi");
    engine
        .apply_folded(
            &engine
                .fold(partial_hi.state.clone())
                .expect("fhi2")
                .snapshot,
        )
        .expect("afhi");
    assert_eq!(
        engine
            .ingest_packet(partial_hi.state, &rng, w.channel.clone(), w.tag, &b_hi2)
            .unwrap_err(),
        EngineError::Equivocation
    );
    let too_big = PacketPlain::TxFragLast(PacketTxFragLast {
        actor_id: Vec::new(),
        packet_seq: 0,
        tx_id: Tag::from_bytes([7; 32]),
        frag_i: super::super::chain::MAX_FRAGS,
        frag: vec![1],
        set_xor: Tag::from_bytes([0; 32]),
    });
    let b_big = seal_packet(
        &engine.suite,
        &rng,
        &mk(engine.suite.hmac(), &chain),
        &too_big,
    )
    .expect("sbig");
    let (recv_big, _) = engine
        .receive_ticket(
            engine
                .tick(EngineState::new(), 1_700_000_000)
                .expect("tbig")
                .state,
            &rng,
            uid,
            iid,
            &ticket_s,
        )
        .expect("rbig");
    engine
        .ingest_packet(recv_big.state, &rng, w.channel.clone(), w.tag, &b_big)
        .expect("big");
    let b_null = seal_packet(
        &engine.suite,
        &rng,
        &mk(engine.suite.hmac(), &chain),
        &PacketPlain::TxFragLast(PacketTxFragLast {
            actor_id: Vec::new(),
            packet_seq: 0,
            tx_id: Tag::from_bytes([6; 32]),
            frag_i: 0,
            frag: b"null".to_vec(),
            set_xor: Tag::from_bytes([0; 32]),
        }),
    )
    .expect("snull");
    let (recv_null, _) = engine
        .receive_ticket(
            engine
                .tick(EngineState::new(), 1_700_000_000)
                .expect("tnull")
                .state,
            &rng,
            uid,
            iid,
            &ticket_s,
        )
        .expect("rnull");
    engine
        .ingest_packet(recv_null.state, &rng, w.channel.clone(), w.tag, &b_null)
        .expect("inull");
    let (recv_cache, phc) = engine
        .receive_ticket(
            engine
                .tick(EngineState::new(), 1_700_000_000)
                .expect("tc")
                .state,
            &rng,
            uid,
            iid,
            &ticket_s,
        )
        .expect("rc");
    let cached_first = engine
        .ingest_packet(recv_cache.state, &rng, w.channel.clone(), w.tag, &b_last)
        .expect("clast");
    let cached_second = engine
        .ingest_packet(cached_first.state, &rng, w.channel.clone(), w.tag, &b_more)
        .expect("cmore");
    assert!(matches!(
        engine
            .get_conversation(&cached_second.state, uid, iid, phc)
            .expect("qc"),
        Conversation::HandshakeDm(Handshake::Failed(FailedReason::NoticeUnlockFailed))
    ));
    engine
        .apply_folded(
            &engine
                .fold(cached_second.state.clone())
                .expect("cf")
                .snapshot,
        )
        .expect("caf");
    engine
        .tick(cached_second.state, 1_700_000_000 + 172_801)
        .expect("texp");
    let mut named = ingested.state.clone();
    named.txs.insert(
        Tag::from_bytes([0; 32]),
        DurableBody {
            conversation_id: cid,
            hlc: Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: TxPayload::EngineCreateUser { user_id: uid },
        },
    );
    assert!(matches!(
        engine.get_conversation(&named, uid, iid, cid).expect("qn"),
        Conversation::HandshakeDm(Handshake::Invitee(HandshakeInvitee::InviteReceived { .. }))
    ));
    let mut eph_state = ingested.state.clone();
    eph_state.eph_writes.push(super::EphemeralWrite {
        channel: crate::protocol::v1::EphemeralChannel::new(
            crate::protocol::v1::Kind::try_from("webrtc").expect("wk"),
            crate::protocol::v1::Address::try_from("https://eph.example").expect("wa"),
        ),
        tag: Tag::from_bytes([4; 32]),
        body: vec![0; crate::protocol::v1::PACKET_LEN],
    });
    eph_state.eph_writes.push(super::EphemeralWrite {
        channel: crate::protocol::v1::EphemeralChannel::new(
            crate::protocol::v1::Kind::try_from("webrtc").expect("wk2"),
            crate::protocol::v1::Address::try_from("wss://eph.example").expect("wa2"),
        ),
        tag: Tag::from_bytes([5; 32]),
        body: vec![0; crate::protocol::v1::PACKET_LEN],
    });
    eph_state.eph_writes.push(super::EphemeralWrite {
        channel: crate::protocol::v1::EphemeralChannel::new(
            crate::protocol::v1::Kind::try_from("webrtc").expect("wk3"),
            crate::protocol::v1::Address::try_from("https://eph.example").expect("wa3"),
        ),
        tag: Tag::from_bytes([6; 32]),
        body: vec![0; crate::protocol::v1::PACKET_LEN],
    });
    let _ = engine.poll(&eph_state).expect("peph");
    let mut drain = ingested.state.clone();
    for progress in drain.bin_progress.values_mut() {
        progress.watermark = Some(crate::protocol::v1::TimeBin::from_u64(472_220));
        progress
            .completed
            .insert(crate::protocol::v1::TimeBin::from_u64(472_221));
    }
    let drained = engine
        .ingest_list(drain, &rng, w.channel.clone(), w.tag, &[])
        .expect("drain");
    engine
        .apply_folded(&engine.fold(drained.state).expect("fdrain").snapshot)
        .expect("afdrain");
    assert_eq!(
        engine
            .reject_established(sync_ok.state.clone(), &rng, sync_ids)
            .unwrap_err(),
        EngineError::WrongPhase
    );
    let dummy_more = PacketPlain::TxFragMore(PacketTxFragMore {
        actor_id: Vec::new(),
        packet_seq: 1,
        tx_id: Tag::from_bytes([8; 32]),
        frag_i: 0,
        frag: vec![1],
    });
    let chain1 = step(engine.suite.hmac(), &chain);
    let b_dummy = seal_packet(
        &engine.suite,
        &rng,
        &mk(engine.suite.hmac(), &chain1),
        &dummy_more,
    )
    .expect("sdummy");
    let (recv_rk, ph_rk) = engine
        .receive_ticket(
            engine
                .tick(EngineState::new(), 1_700_000_000)
                .expect("trk")
                .state,
            &rng,
            uid,
            iid,
            &ticket_s,
        )
        .expect("rrk");
    let with_frag = engine
        .ingest_packet(recv_rk.state, &rng, w.channel.clone(), w.tag, &b_dummy)
        .expect("idummy");
    assert!(!with_frag.state.frags.is_empty());
    let mut with_frag_state = with_frag.state;
    with_frag_state.frags.insert(
        Tag::from_bytes([9; 32]),
        super::state::FragSet {
            conversation_id: ConversationId::from_bytes([1; 32]),
            parts: std::collections::BTreeMap::new(),
            last_i: None,
        },
    );
    let _ = super::helpers::sort32(&[0; 32], &[1; 32]);
    let _ = super::helpers::sort32(&[1; 32], &[0; 32]);
    let _ = super::helpers::take_shared32(vec![1]);
    with_frag_state.put_skipped(
        ph_rk,
        ActorId::handshake(),
        super::super::chain::CachedMk {
            mk: [3; 32],
            expires_at: UnixSeconds::from_u64(u64::MAX),
            tx_id: None,
        },
    );
    with_frag_state.put_skipped(
        ph_rk,
        ActorId::from_bytes([7; 8]),
        super::super::chain::CachedMk {
            mk: [6; 32],
            expires_at: UnixSeconds::from_u64(u64::MAX),
            tx_id: None,
        },
    );
    let rekeyed = engine
        .ingest_list(with_frag_state, &rng, w.channel.clone(), w.tag, &bodies)
        .expect("rekeyfrag");
    let mut drop_state = invited.state.clone();
    drop_state.copy_chains_from(&rekeyed.state, cid);
    drop_state.frags = rekeyed.state.frags.clone();
    engine.delete_conversation(drop_state, ids).expect("deling");
    let eph_a = crate::protocol::v1::EphemeralChannel::new(
        crate::protocol::v1::Kind::try_from("webrtc").expect("ska"),
        crate::protocol::v1::Address::try_from("https://eph.example").expect("saa"),
    );
    let eph_b = crate::protocol::v1::EphemeralChannel::new(
        crate::protocol::v1::Kind::try_from("webrtc").expect("skb"),
        crate::protocol::v1::Address::try_from("wss://eph.example").expect("sab"),
    );
    let mut eph = vec![
        super::EphemeralWrite {
            channel: eph_a.clone(),
            tag: Tag::from_bytes([1; 32]),
            body: vec![0; crate::protocol::v1::PACKET_LEN],
        },
        super::EphemeralWrite {
            channel: eph_a,
            tag: Tag::from_bytes([2; 32]),
            body: vec![0; crate::protocol::v1::PACKET_LEN],
        },
        super::EphemeralWrite {
            channel: eph_b,
            tag: Tag::from_bytes([1; 32]),
            body: vec![0; crate::protocol::v1::PACKET_LEN],
        },
    ];
    super::helpers::sort_ephemeral_writes(&mut eph);
    engine.lock();
    assert_eq!(
        engine
            .ingest_list(ingested.state.clone(), &rng, w.channel.clone(), w.tag, &[])
            .unwrap_err(),
        EngineError::Locked
    );
}

fn ack_all(engine: &Engine, mut state: EngineState) -> EngineState {
    loop {
        let poll = engine.poll(&state).expect("p");
        if poll.write_durable.is_empty() {
            return state;
        }
        for w in poll.write_durable {
            state = engine
                .write_ack(state, w.channel, w.tag, &w.body)
                .expect("ack")
                .state;
        }
    }
}

#[test]
fn handshake_intros_confirming_and_failures() {
    use super::super::chain::{fragment_body, join, mk, packed_tx, seal_packet, step};
    use super::super::codec::ticket_from_json;
    use super::super::payload::{
        ConversationSort, PacketPlain, PacketTxFragLast, Ticket, TxInviteeIntro, TxNotice,
    };
    use super::party::InviteePhase;
    use super::{
        Conversation, ConversationRef, DirectMessageQuery, FailedReason, Handshake,
        HandshakeInvitee, HandshakeInviter,
    };
    use crate::protocol::v1::{DisplayName, OnWirePrefs, Tag, TagKey};
    let mut engine = test_engine();
    let rng = CounterRng::new();
    engine
        .wrap_dek(&rng, &UnlockSecret::Passphrase("passpass".into()))
        .expect("wrap");
    let ticked = engine
        .tick(EngineState::new(), 1_700_000_000)
        .expect("tick");
    let (created, uid) = engine.create_user(ticked.state, &rng).expect("user");
    let (created, iid) = engine
        .create_identity(created.state, &rng, uid, Policy::Classic)
        .expect("id");
    let named = engine
        .set_display_name(created.state, &rng, uid, iid, "Ada")
        .expect("name");
    let (invited, cid) = engine
        .create_invite(named.state, &rng, uid, iid, 1_800_000_000, None)
        .expect("inv");
    let ids = ConversationRef {
        user_id: uid,
        identity_id: iid,
        conversation_id: cid,
    };
    let ticket_s = engine.ticket_host_string(&invited.state, &ids).expect("t");
    let notice_writes: Vec<_> = engine
        .poll(&invited.state)
        .expect("p")
        .write_durable
        .into_iter()
        .map(|w| (w.channel, w.tag, w.body))
        .collect();
    let mut pending_inviter = invited.state.clone();
    let inviter = ack_all(&engine, invited.state);
    assert!(matches!(
        engine.get_conversation(&inviter, uid, iid, cid).expect("q"),
        Conversation::HandshakeDm(Handshake::Inviter(HandshakeInviter::NoticePinned { .. }))
    ));
    let ie_tick = engine.tick(EngineState::new(), 1_700_000_000).expect("it");
    let (ie_user, ie_uid) = engine.create_user(ie_tick.state, &rng).expect("iu");
    let (ie_id, ie_iid) = engine
        .create_identity(ie_user.state, &rng, ie_uid, Policy::Classic)
        .expect("ii");
    let ie_named = engine
        .set_display_name(ie_id.state, &rng, ie_uid, ie_iid, "Bob")
        .expect("in");
    let (received, ie_cid) = engine
        .receive_ticket(ie_named.state, &rng, ie_uid, ie_iid, &ticket_s)
        .expect("recv");
    let mut ticket_recv = received.state.clone();
    let (ch, tag, _) = notice_writes[0].clone();
    let bodies: Vec<Vec<u8>> = notice_writes.iter().map(|w| w.2.clone()).collect();
    let minted = engine
        .ingest_list(received.state, &rng, ch.clone(), tag, &bodies)
        .expect("ing");
    assert!(matches!(
        engine
            .get_conversation(&minted.state, ie_uid, ie_iid, cid)
            .expect("ir"),
        Conversation::HandshakeDm(Handshake::Invitee(
            HandshakeInvitee::IntroductionMinted { .. }
        ))
    ));
    let intro_writes: Vec<_> = engine
        .poll(&minted.state)
        .expect("ip")
        .write_durable
        .into_iter()
        .map(|w| (w.channel, w.tag, w.body))
        .collect();
    let sent = ack_all(&engine, minted.state);
    let sent_gate = sent.clone();
    assert!(matches!(
        engine
            .get_conversation(&sent, ie_uid, ie_iid, cid)
            .expect("is"),
        Conversation::HandshakeDm(Handshake::Invitee(
            HandshakeInvitee::IntroductionSent { .. }
        ))
    ));
    let intro_bodies: Vec<Vec<u8>> = intro_writes.iter().map(|w| w.2.clone()).collect();
    let pinned = inviter.clone();
    let inv_minted = engine
        .ingest_list(
            inviter,
            &rng,
            intro_writes[0].0.clone(),
            intro_writes[0].1,
            &intro_bodies,
        )
        .expect("iing");
    assert!(matches!(
        engine
            .get_conversation(&inv_minted.state, uid, iid, cid)
            .expect("im"),
        Conversation::HandshakeDm(Handshake::Inviter(
            HandshakeInviter::IntroductionMinted { .. }
        ))
    ));
    let inv_intro_writes: Vec<_> = engine
        .poll(&inv_minted.state)
        .expect("iip")
        .write_durable
        .into_iter()
        .map(|w| (w.channel, w.tag, w.body))
        .collect();
    let intro_payload = inv_minted
        .state
        .txs
        .values()
        .find(|body| matches!(body.payload, TxPayload::InviterIntro(_)))
        .expect("minted intro")
        .payload
        .clone();
    let inv_conf = ack_all(&engine, inv_minted.state);
    assert!(matches!(
        engine
            .get_conversation(&inv_conf, uid, iid, cid)
            .expect("ic"),
        Conversation::HandshakeDm(Handshake::Inviter(HandshakeInviter::Confirming {
            confirmation_digest: ref d,
            ..
        })) if !d.is_empty()
    ));
    let inv_digest = engine.confirmation_digest(&inv_conf, &ids).expect("invcd");
    let mut swapped = inv_conf.clone();
    for tx in swapped.txs.values_mut() {
        match &mut tx.payload {
            TxPayload::InviterIntro(i) => i.signing_pk = vec![0xff; i.signing_pk.len()],
            TxPayload::InviteeIntro(i) => i.signing_pk = vec![0x00; i.signing_pk.len()],
            _ => {}
        }
    }
    let _ = engine.confirmation_digest(&swapped, &ids).expect("swap");
    let ie_conf = engine
        .ingest_list(
            sent,
            &rng,
            inv_intro_writes[0].0.clone(),
            inv_intro_writes[0].1,
            &inv_intro_writes
                .iter()
                .map(|w| w.2.clone())
                .collect::<Vec<_>>(),
        )
        .expect("ieing");
    assert!(matches!(
        engine
            .get_conversation(&ie_conf.state, ie_uid, ie_iid, cid)
            .expect("iec"),
        Conversation::HandshakeDm(Handshake::Invitee(HandshakeInvitee::Confirming {
            confirmation_digest: ref d,
            ..
        })) if d == &inv_digest
    ));
    let ie_ids = ConversationRef {
        user_id: ie_uid,
        identity_id: ie_iid,
        conversation_id: cid,
    };
    let confirmed_ie = engine
        .confirm_established(ie_conf.state.clone(), &rng, ie_ids)
        .expect("ieconf");
    let rows_ie = engine
        .list_conversations(&confirmed_ie.state, ie_uid, ie_iid)
        .expect("ielist");
    assert_eq!(rows_ie.len(), 2);
    let child_ie = rows_ie
        .iter()
        .find_map(|r| match r.conversation {
            Conversation::DirectMessage(DirectMessageQuery::Established(_)) => {
                Some(r.conversation_id)
            }
            _ => None,
        })
        .expect("iechild");
    assert!(matches!(
        engine
            .get_conversation(&confirmed_ie.state, ie_uid, ie_iid, cid)
            .expect("ieh"),
        Conversation::HandshakeDm(Handshake::Invitee(HandshakeInvitee::Confirming { .. }))
    ));
    assert_eq!(
        engine
            .confirm_established(confirmed_ie.state.clone(), &rng, ie_ids)
            .unwrap_err(),
        EngineError::WrongPhase
    );
    let mut child_ids = ie_ids;
    child_ids.conversation_id = child_ie;
    engine
        .delete_conversation(confirmed_ie.state.clone(), child_ids)
        .expect("delchild");
    let rejected = engine
        .reject_established(ie_conf.state.clone(), &rng, ie_ids)
        .expect("rej");
    assert!(matches!(
        engine
            .get_conversation(&rejected.state, ie_uid, ie_iid, cid)
            .expect("rejq"),
        Conversation::HandshakeDm(Handshake::Failed(FailedReason::ConfirmationRejected))
    ));
    let confirmed = engine
        .confirm_established(inv_conf.clone(), &rng, ids)
        .expect("conf");
    assert!(matches!(
        engine
            .get_conversation(&confirmed.state, uid, iid, cid)
            .expect("est"),
        Conversation::HandshakeDm(Handshake::Inviter(HandshakeInviter::Confirming { .. }))
    ));
    let rows = engine
        .list_conversations(&confirmed.state, uid, iid)
        .expect("list");
    assert_eq!(rows.len(), 2);
    let child = rows
        .iter()
        .find_map(|r| match r.conversation {
            Conversation::DirectMessage(DirectMessageQuery::Established(_)) => {
                Some(r.conversation_id)
            }
            _ => None,
        })
        .expect("child");
    assert_eq!(child, child_ie);
    assert!(matches!(
        engine
            .get_conversation(&confirmed.state, uid, iid, child)
            .expect("chq"),
        Conversation::DirectMessage(DirectMessageQuery::Established(_))
    ));
    assert!(confirmed.state.party(child).is_none());
    let mut spawned = confirmed.state.clone();
    engine.spawn_child(&mut spawned, cid).expect("idemp");
    engine
        .delete_conversation(
            spawned,
            ConversationRef {
                user_id: uid,
                identity_id: iid,
                conversation_id: cid,
            },
        )
        .expect("delhs");
    assert_eq!(
        engine
            .confirm_established(confirmed.state.clone(), &rng, ids)
            .unwrap_err(),
        EngineError::WrongPhase
    );
    let mut fold_c = confirmed.state.clone();
    fold_c.cover_last_acks();
    let snap_c = engine.fold(fold_c).expect("cfold");
    let restored_c = engine.apply_folded(&snap_c.snapshot).expect("caf");
    assert!(matches!(
        engine
            .get_conversation(&restored_c, uid, iid, child)
            .expect("chf"),
        Conversation::DirectMessage(DirectMessageQuery::Established(_))
    ));
    let mut no_map = confirmed.state.clone();
    no_map.cover_last_acks();
    let _ = engine.fold(no_map).expect("nfold");
    let persist = confirmed.persist()[0].clone();
    let applied = engine.apply(inv_conf.clone(), &persist).expect("applyc");
    assert!(applied.established_secret(child).is_some());
    let _ = engine.apply(applied, &persist).expect("applyc2");
    let mut missing = inv_conf.clone();
    missing.txs.retain(|_, body| {
        !matches!(
            body.payload,
            TxPayload::InviterIntro(_) | TxPayload::InviteeIntro(_)
        )
    });
    assert_eq!(
        engine.confirm_established(missing, &rng, ids).unwrap_err(),
        EngineError::MalformedPayload
    );
    let expired = engine.tick(inv_conf.clone(), 1_900_000_000).expect("exp");
    assert!(matches!(
        engine
            .get_conversation(&expired.state, uid, iid, cid)
            .expect("exq"),
        Conversation::HandshakeDm(Handshake::Failed(FailedReason::InviteExpired { .. }))
    ));
    assert_eq!(
        engine
            .confirm_established(expired.state.clone(), &rng, ids)
            .unwrap_err(),
        EngineError::WrongPhase
    );
    let epoll = engine.poll(&expired.state).expect("ep");
    assert_eq!(
        engine
            .ingest_packet(
                expired.state,
                &rng,
                epoll.list[0].channel.clone(),
                epoll.list[0].tag,
                &bodies[0]
            )
            .unwrap_err(),
        EngineError::WrongPhase
    );

    let delayed = engine.tick(EngineState::new(), 1_700_000_000).expect("dt");
    let (du, duid) = engine.create_user(delayed.state, &rng).expect("du");
    let (di, diid) = engine
        .create_identity(du.state, &rng, duid, Policy::Classic)
        .expect("di");
    let (drecv, _dcid) = engine
        .receive_ticket(di.state, &rng, duid, diid, &ticket_s)
        .expect("drecv");
    let blocked = engine.poll(&drecv.state).expect("blk");
    assert!(blocked.blocked.iter().any(|b| b.identity_id == diid));
    let got_notice = engine
        .ingest_list(drecv.state, &rng, ch.clone(), tag, &bodies)
        .expect("dn");
    assert!(matches!(
        engine
            .get_conversation(&got_notice.state, duid, diid, cid)
            .expect("dnr"),
        Conversation::HandshakeDm(Handshake::Invitee(HandshakeInvitee::InviteReceived { .. }))
    ));
    let invitee_notice = got_notice.state.clone();
    let named_ie = engine
        .set_display_name(got_notice.state, &rng, duid, diid, "Cyd")
        .expect("setn");
    assert!(matches!(
        engine
            .get_conversation(&named_ie.state, duid, diid, cid)
            .expect("dnm"),
        Conversation::HandshakeDm(Handshake::Invitee(
            HandshakeInvitee::IntroductionMinted { .. }
        ))
    ));

    let mismatch_tick = engine.tick(EngineState::new(), 1_700_000_000).expect("mt");
    let (mu, muid) = engine.create_user(mismatch_tick.state, &rng).expect("mu");
    let (mi, miid) = engine
        .create_identity(mu.state, &rng, muid, Policy::Hybrid)
        .expect("mi");
    let mn = engine
        .set_display_name(mi.state, &rng, muid, miid, "Eve")
        .expect("mn");
    let (mrecv, mcid) = engine
        .receive_ticket(mn.state, &rng, muid, miid, &ticket_s)
        .expect("mrecv");
    let mut policy_mint = mrecv.state.clone();
    let mfail = engine
        .ingest_list(mrecv.state, &rng, ch.clone(), tag, &bodies)
        .expect("ming");
    assert!(matches!(
        engine
            .get_conversation(&mfail.state, muid, miid, cid)
            .expect("mfq"),
        Conversation::HandshakeDm(Handshake::Failed(FailedReason::PolicyNotAccepted { .. }))
    ));

    for reason in [
        super::party::HandshakeFailure::PolicyNotAccepted {
            policy: Policy::Hybrid,
        },
        super::party::HandshakeFailure::InviteExpired {
            expires: UnixSeconds::from_u64(3),
        },
        super::party::HandshakeFailure::NoticeUnlockFailed,
        super::party::HandshakeFailure::NoticeConflict,
        super::party::HandshakeFailure::IntroUnlockFailed,
        super::party::HandshakeFailure::IntroVerifyFailed,
        super::party::HandshakeFailure::DuplicateIntro,
        super::party::HandshakeFailure::ConfirmationRejected,
        super::party::HandshakeFailure::Equivocation,
    ] {
        let mut folded_fail = pinned.clone();
        folded_fail.fail(cid, reason);
        folded_fail.cover_last_acks();
        let snap = engine.fold(folded_fail.clone()).expect("ff");
        let restored = engine.apply_folded(&snap.snapshot).expect("afr");
        assert_eq!(restored.failed(cid), Some(reason.into()));
    }

    let packed = engine.suite.b64u().decode(&ticket_s).expect("dec");
    let canonical = engine
        .suite
        .compress()
        .decompress(&packed, super::super::payload::TICKET_MAX_UNCOMPRESSED)
        .expect("z");
    let json = engine.suite.canonical_json().decode(&canonical).expect("j");
    let ticket = ticket_from_json(engine.suite.b64u(), &json).expect("tk");
    let other_notice = TxPayload::Notice(TxNotice {
        policy: Policy::Classic,
        intake_pk: vec![0; 32],
        persistents: ticket.persistents.clone(),
        ephemerals: Vec::new(),
        expires: UnixSeconds::from_u64(1_800_000_001),
    });
    let stored_notice = TxPayload::Notice(TxNotice {
        policy: Policy::Classic,
        intake_pk: vec![0; 32],
        persistents: ticket.persistents.clone(),
        ephemerals: Vec::new(),
        expires: UnixSeconds::from_u64(1_800_000_000),
    });
    policy_mint.txs.insert(
        Tag::from_bytes([0x22; 32]),
        DurableBody {
            conversation_id: mcid,
            hlc: Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: stored_notice.clone(),
        },
    );
    engine
        .handshake_ingest_gate(&mut policy_mint, mcid, &stored_notice)
        .expect("pm");
    assert_eq!(
        policy_mint.failed(mcid),
        Some(FailedReason::PolicyNotAccepted {
            policy: Policy::Classic
        })
    );
    let mut clash_state = named_ie.state.clone();
    let gated = engine
        .handshake_ingest_gate(&mut clash_state, cid, &other_notice)
        .expect("gate");
    assert!(gated.is_some());
    assert_eq!(clash_state.failed(cid), Some(FailedReason::NoticeConflict));
    let bad_intro = TxPayload::InviteeIntro(TxInviteeIntro {
        name: DisplayName::try_from("X").expect("dn"),
        profile_pic: None,
        send_tag_key: TagKey::from_bytes([1; 32]),
        eph_send_tag_key: TagKey::from_bytes([2; 32]),
        encryption_pk: vec![1],
        signing_pk: vec![2],
        intake_pk: vec![3],
        seed_ct: vec![4],
        prefs: OnWirePrefs {
            read_receipts: true,
            online_visible: true,
            send_typing: true,
            disappear_after: None,
            wake: None,
        },
    });
    let mut verify_state = pinned.clone();
    let gated = engine
        .handshake_ingest_gate(&mut verify_state, cid, &bad_intro)
        .expect("g2");
    assert!(gated.is_some());
    assert_eq!(
        verify_state.failed(cid),
        Some(FailedReason::IntroVerifyFailed)
    );
    let mut unwrap_ct = vec![0u8; 32];
    unwrap_ct[0] = 0xee;
    unwrap_ct[1] = 0xfd;
    let unwrap_fail = TxPayload::InviteeIntro(TxInviteeIntro {
        name: DisplayName::try_from("X").expect("dnu"),
        profile_pic: None,
        send_tag_key: TagKey::from_bytes([1; 32]),
        eph_send_tag_key: TagKey::from_bytes([2; 32]),
        encryption_pk: vec![1; 32],
        signing_pk: vec![1; 32],
        intake_pk: vec![1; 32],
        seed_ct: unwrap_ct.clone(),
        prefs: OnWirePrefs {
            read_receipts: true,
            online_visible: true,
            send_typing: true,
            disappear_after: None,
            wake: None,
        },
    });
    let mut unwrap_state = pinned.clone();
    let gated = engine
        .handshake_ingest_gate(&mut unwrap_state, cid, &unwrap_fail)
        .expect("gu");
    assert!(gated.is_some());
    assert_eq!(
        unwrap_state.failed(cid),
        Some(FailedReason::IntroVerifyFailed)
    );
    unwrap_ct[1] = 0xfe;
    let short_shared = TxPayload::InviteeIntro(TxInviteeIntro {
        name: DisplayName::try_from("X").expect("dns"),
        profile_pic: None,
        send_tag_key: TagKey::from_bytes([1; 32]),
        eph_send_tag_key: TagKey::from_bytes([2; 32]),
        encryption_pk: vec![1; 32],
        signing_pk: vec![1; 32],
        intake_pk: vec![1; 32],
        seed_ct: unwrap_ct.clone(),
        prefs: OnWirePrefs {
            read_receipts: true,
            online_visible: true,
            send_typing: true,
            disappear_after: None,
            wake: None,
        },
    });
    let mut short_state = pinned.clone();
    let gated = engine
        .handshake_ingest_gate(&mut short_state, cid, &short_shared)
        .expect("gs");
    assert!(gated.is_some());
    assert_eq!(
        short_state.failed(cid),
        Some(FailedReason::IntroVerifyFailed)
    );
    unwrap_ct[1] = 0xfd;
    let inviter_unwrap = TxPayload::InviterIntro(super::super::payload::TxInviterIntro {
        name: DisplayName::try_from("Y").expect("dnv"),
        profile_pic: None,
        send_tag_key: TagKey::from_bytes([3; 32]),
        eph_send_tag_key: TagKey::from_bytes([4; 32]),
        encryption_pk: vec![1; 32],
        signing_pk: vec![1; 32],
        seed_ct: unwrap_ct,
        prefs: OnWirePrefs {
            read_receipts: true,
            online_visible: true,
            send_typing: true,
            disappear_after: None,
            wake: None,
        },
    });
    let mut ie_unwrap = sent_gate.clone();
    let gated = engine
        .handshake_ingest_gate(&mut ie_unwrap, cid, &inviter_unwrap)
        .expect("giv");
    assert!(gated.is_some());
    assert_eq!(ie_unwrap.failed(cid), Some(FailedReason::IntroVerifyFailed));
    let ok_invitee = TxPayload::InviteeIntro(TxInviteeIntro {
        name: DisplayName::try_from("X").expect("dnx"),
        profile_pic: None,
        send_tag_key: TagKey::from_bytes([1; 32]),
        eph_send_tag_key: TagKey::from_bytes([2; 32]),
        encryption_pk: vec![1; 32],
        signing_pk: vec![1; 32],
        intake_pk: vec![1; 32],
        seed_ct: vec![1; 32],
        prefs: OnWirePrefs {
            read_receipts: true,
            online_visible: true,
            send_typing: true,
            disappear_after: None,
            wake: None,
        },
    });
    let mut no_sk_inv = pinned.clone();
    let gated = engine
        .handshake_ingest_gate(&mut no_sk_inv, cid, &ok_invitee)
        .expect("nski");
    assert!(gated.is_none());
    let ok_inviter = TxPayload::InviterIntro(super::super::payload::TxInviterIntro {
        name: DisplayName::try_from("Y").expect("dny"),
        profile_pic: None,
        send_tag_key: TagKey::from_bytes([3; 32]),
        eph_send_tag_key: TagKey::from_bytes([4; 32]),
        encryption_pk: vec![1; 32],
        signing_pk: vec![1; 32],
        seed_ct: vec![1; 32],
        prefs: OnWirePrefs {
            read_receipts: true,
            online_visible: true,
            send_typing: true,
            disappear_after: None,
            wake: None,
        },
    });
    let mut failed_inv = pinned.clone();
    failed_inv.fail(cid, super::party::HandshakeFailure::NoticeConflict);
    let gated = engine
        .handshake_ingest_gate(&mut failed_inv, cid, &ok_invitee)
        .expect("nosk");
    assert!(gated.is_none());
    let mut bare_ie = invitee_notice.clone();
    let gated = engine
        .handshake_ingest_gate(&mut bare_ie, cid, &ok_inviter)
        .expect("bare");
    assert!(gated.is_some());
    assert_eq!(bare_ie.failed(cid), Some(FailedReason::IntroVerifyFailed));
    let mut confirming = sent_gate.clone();
    {
        let mut party = confirming.party_mut(cid).expect("sent");
        assert!(
            party
                .invitee_mut()
                .expect("phase")
                .confirm_peer(Secret::from_bytes([7; 32]))
        );
    }
    let gated = engine
        .handshake_ingest_gate(&mut confirming, cid, &intro_payload)
        .expect("late");
    assert!(gated.is_some());
    assert_eq!(
        confirming.failed(cid),
        Some(FailedReason::IntroVerifyFailed)
    );
    let mut no_sk_ie = sent_gate;
    let gated = engine
        .handshake_ingest_gate(&mut no_sk_ie, cid, &ok_inviter)
        .expect("nskie");
    assert!(gated.is_none());
    let mut role_ie = invitee_notice;
    let gated = engine
        .handshake_ingest_gate(&mut role_ie, cid, &ok_invitee)
        .expect("roleie");
    assert!(gated.is_none());
    let mut role_inv = pinned.clone();
    let gated = engine
        .handshake_ingest_gate(&mut role_inv, cid, &ok_inviter)
        .expect("roleinv");
    assert!(gated.is_none());
    let mut dup_state = named_ie.state.clone();
    let gated = engine
        .handshake_ingest_gate(&mut dup_state, cid, &bad_intro)
        .expect("g3");
    assert!(gated.is_some());
    assert_eq!(dup_state.failed(cid), Some(FailedReason::DuplicateIntro));
    let no_notice = TxPayload::InviterIntro(super::super::payload::TxInviterIntro {
        name: DisplayName::try_from("Y").expect("dn2"),
        profile_pic: None,
        send_tag_key: TagKey::from_bytes([3; 32]),
        eph_send_tag_key: TagKey::from_bytes([4; 32]),
        encryption_pk: vec![1; 32],
        signing_pk: vec![1; 32],
        seed_ct: vec![1; 32],
        prefs: OnWirePrefs {
            read_receipts: true,
            online_visible: true,
            send_typing: true,
            disappear_after: None,
            wake: None,
        },
    });
    let mut empty_ticket = engine
        .tick(EngineState::new(), 1_700_000_000)
        .expect("et")
        .state;
    empty_ticket.put_dm_invitee(
        UserId::from_bytes([0; 32]),
        IdentityId::from_bytes([0; 32]),
        cid,
        InviteePhase::TicketReceived {
            ticket: ticket.clone(),
            list_from: crate::protocol::v1::TimeBin::from_u64(0),
        },
    );
    let gated = engine
        .handshake_ingest_gate(&mut empty_ticket, cid, &no_notice)
        .expect("g4");
    assert!(gated.is_some());
    assert_eq!(
        empty_ticket.failed(cid),
        Some(FailedReason::IntroVerifyFailed)
    );
    let mut unlock_inviter = pinned.clone();
    super::helpers::store_unlock_failed(&mut unlock_inviter, cid);
    assert_eq!(
        unlock_inviter.failed(cid),
        Some(FailedReason::IntroUnlockFailed)
    );
    super::helpers::store_unlock_failed(&mut unlock_inviter, cid);
    let mut unlock_invitee = EngineState::new();
    unlock_invitee.put_dm_invitee(
        UserId::from_bytes([0; 32]),
        IdentityId::from_bytes([0; 32]),
        cid,
        InviteePhase::TicketReceived {
            ticket: ticket.clone(),
            list_from: crate::protocol::v1::TimeBin::from_u64(0),
        },
    );
    super::helpers::store_unlock_failed(&mut unlock_invitee, cid);
    assert_eq!(
        unlock_invitee.failed(cid),
        Some(FailedReason::NoticeUnlockFailed)
    );
    let mut both_intros = ie_conf.state.clone();
    let gated = engine
        .handshake_ingest_gate(&mut both_intros, cid, &no_notice)
        .expect("g5");
    assert!(gated.is_some());
    assert_eq!(both_intros.failed(cid), Some(FailedReason::DuplicateIntro));
    let (sync_ok, sid) = engine
        .create_sync_invite(
            confirmed.state,
            &rng,
            Policy::Classic,
            1_900_000_000,
            "phone",
            None,
        )
        .expect("sync");
    let mut sync_fold_state = sync_ok.state.clone();
    sync_fold_state.cover_last_acks();
    let snap = engine.fold(sync_fold_state).expect("sfold");
    let restored = engine.apply_folded(&snap.snapshot).expect("saf");
    assert!(restored.device.keys.is_some());
    assert!(restored.is_inviter(sid));
    let st = engine
        .tick(EngineState::new(), 1_700_000_000)
        .expect("st")
        .state;
    let (srecv, _) = engine
        .receive_sync_ticket(st, &rng, &ticket_s)
        .expect("srecv");
    let spoll = engine.poll(&srecv.state).expect("sp");
    assert!(
        spoll
            .blocked
            .iter()
            .any(|b| b.user_id.as_bytes() == &[0; 32])
    );
    let ie_no_notice = TxPayload::InviteeIntro(TxInviteeIntro {
        name: DisplayName::try_from("N").expect("dnn"),
        profile_pic: None,
        send_tag_key: TagKey::from_bytes([8; 32]),
        eph_send_tag_key: TagKey::from_bytes([9; 32]),
        encryption_pk: vec![1; 32],
        signing_pk: vec![1; 32],
        intake_pk: vec![1; 32],
        seed_ct: vec![1; 32],
        prefs: OnWirePrefs {
            read_receipts: true,
            online_visible: true,
            send_typing: true,
            disappear_after: None,
            wake: None,
        },
    });
    let mut empty_ie = engine
        .tick(EngineState::new(), 1_700_000_000)
        .expect("et2")
        .state;
    empty_ie.put_dm_invitee(
        UserId::from_bytes([0; 32]),
        IdentityId::from_bytes([0; 32]),
        cid,
        InviteePhase::TicketReceived {
            ticket: ticket.clone(),
            list_from: crate::protocol::v1::TimeBin::from_u64(0),
        },
    );
    let gated = engine
        .handshake_ingest_gate(&mut empty_ie, cid, &ie_no_notice)
        .expect("g6");
    assert!(gated.is_some());
    assert_eq!(empty_ie.failed(cid), Some(FailedReason::IntroVerifyFailed));
    let bad_inviter_keys = TxPayload::InviterIntro(super::super::payload::TxInviterIntro {
        name: DisplayName::try_from("K").expect("dnk"),
        profile_pic: None,
        send_tag_key: TagKey::from_bytes([10; 32]),
        eph_send_tag_key: TagKey::from_bytes([11; 32]),
        encryption_pk: vec![1],
        signing_pk: vec![1],
        seed_ct: vec![1],
        prefs: OnWirePrefs {
            read_receipts: true,
            online_visible: true,
            send_typing: true,
            disappear_after: None,
            wake: None,
        },
    });
    let mut verify_inv = pinned.clone();
    let gated = engine
        .handshake_ingest_gate(&mut verify_inv, cid, &bad_inviter_keys)
        .expect("g7");
    assert!(gated.is_some());
    assert_eq!(
        verify_inv.failed(cid),
        Some(FailedReason::IntroVerifyFailed)
    );
    let mut wrap_fail = pinned.clone();
    wrap_fail.txs.insert(
        Tag::from_bytes([0x11; 32]),
        DurableBody {
            conversation_id: cid,
            hlc: Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: TxPayload::InviteeIntro(TxInviteeIntro {
                name: DisplayName::try_from("W").expect("dnw"),
                profile_pic: None,
                send_tag_key: TagKey::from_bytes([12; 32]),
                eph_send_tag_key: TagKey::from_bytes([13; 32]),
                encryption_pk: vec![1; 32],
                signing_pk: vec![1; 32],
                intake_pk: Vec::new(),
                seed_ct: vec![1; 32],
                prefs: OnWirePrefs {
                    read_receipts: true,
                    online_visible: true,
                    send_typing: true,
                    disappear_after: None,
                    wake: None,
                },
            }),
        },
    );
    let extra = engine
        .try_mint_inviter_intro(&mut wrap_fail, &rng, cid)
        .expect("wrapf");
    assert!(extra.is_empty());
    assert_eq!(wrap_fail.failed(cid), Some(FailedReason::IntroVerifyFailed));
    let mut already = pinned.clone();
    already.txs.insert(
        Tag::from_bytes([0x21; 32]),
        DurableBody {
            conversation_id: cid,
            hlc: Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: ok_inviter.clone(),
        },
    );
    assert!(
        engine
            .try_mint_inviter_intro(&mut already, &rng, cid)
            .expect("dupmint")
            .is_empty()
    );
    assert!(already.failed(cid).is_none());
    let intake_pk = pinned
        .party(cid)
        .expect("pinned")
        .intake()
        .expect("intake")
        .public_bytes()
        .to_vec();
    let mut unwrap_mint = pinned.clone();
    unwrap_mint.txs.insert(
        Tag::from_bytes([0x22; 32]),
        DurableBody {
            conversation_id: cid,
            hlc: Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: TxPayload::InviteeIntro(TxInviteeIntro {
                name: DisplayName::try_from("U").expect("dnu"),
                profile_pic: None,
                send_tag_key: TagKey::from_bytes([16; 32]),
                eph_send_tag_key: TagKey::from_bytes([17; 32]),
                encryption_pk: vec![1; 32],
                signing_pk: vec![1; 32],
                intake_pk,
                seed_ct: vec![0xee, 0xfd],
                prefs: OnWirePrefs {
                    read_receipts: true,
                    online_visible: true,
                    send_typing: true,
                    disappear_after: None,
                    wake: None,
                },
            }),
        },
    );
    assert!(
        engine
            .try_mint_inviter_intro(&mut unwrap_mint, &rng, cid)
            .expect("unwrapmint")
            .is_empty()
    );
    assert_eq!(
        unwrap_mint.failed(cid),
        Some(FailedReason::IntroVerifyFailed)
    );
    assert_eq!(
        unwrap_mint.failed(cid),
        Some(FailedReason::IntroVerifyFailed)
    );
    let mut no_ticket = pinned.clone();
    let _ = no_ticket.drop_conversation(cid);
    assert_eq!(
        engine.conv_secret(&no_ticket, &cid).unwrap_err(),
        EngineError::UnknownIds
    );
    no_ticket.txs.insert(
        Tag::from_bytes([0x33; 32]),
        DurableBody {
            conversation_id: cid,
            hlc: Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: TxPayload::InviteeIntro(TxInviteeIntro {
                name: DisplayName::try_from("T").expect("dnt"),
                profile_pic: None,
                send_tag_key: TagKey::from_bytes([14; 32]),
                eph_send_tag_key: TagKey::from_bytes([15; 32]),
                encryption_pk: vec![1; 32],
                signing_pk: vec![1; 32],
                intake_pk: vec![1; 32],
                seed_ct: vec![1; 32],
                prefs: OnWirePrefs {
                    read_receipts: true,
                    online_visible: true,
                    send_typing: true,
                    disappear_after: None,
                    wake: None,
                },
            }),
        },
    );
    assert!(
        engine
            .try_mint_inviter_intro(&mut no_ticket, &rng, cid)
            .expect("nt")
            .is_empty()
    );
    pending_inviter.txs.insert(
        Tag::from_bytes([0x34; 32]),
        DurableBody {
            conversation_id: cid,
            hlc: Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: TxPayload::InviteeIntro(TxInviteeIntro {
                name: DisplayName::try_from("P").expect("dnp"),
                profile_pic: None,
                send_tag_key: TagKey::from_bytes([16; 32]),
                eph_send_tag_key: TagKey::from_bytes([17; 32]),
                encryption_pk: vec![1; 32],
                signing_pk: vec![1; 32],
                intake_pk: vec![1; 32],
                seed_ct: vec![1; 32],
                prefs: OnWirePrefs {
                    read_receipts: true,
                    online_visible: true,
                    send_typing: true,
                    disappear_after: None,
                    wake: None,
                },
            }),
        },
    );
    engine
        .try_mint_inviter_intro(&mut pending_inviter, &rng, cid)
        .expect("pw");
    engine
        .try_mint_inviter_intro(&mut pinned.clone(), &rng, cid)
        .expect("noie");
    engine
        .try_mint_invitee_intro(&mut ticket_recv, &rng, ie_cid)
        .expect("nonotice");
    let mpoll = engine.poll(&mfail.state).expect("mp");
    let again = engine
        .ingest_packet(
            mfail.state,
            &rng,
            mpoll.list[0].channel.clone(),
            mpoll.list[0].tag,
            &bodies[0],
        )
        .expect("other-fail");
    assert!(again.persist().is_empty());
    let cid_j = super::super::codec::bstr(engine.suite.b64u(), cid.as_bytes());
    assert_eq!(
        super::helpers::parse_failed(
            engine.suite.b64u(),
            &Json::Object(vec![
                ("conversation_id".into(), cid_j.clone()),
                ("reason".into(), Json::String("PolicyNotAccepted".into())),
                ("policy".into(), Json::Number(1)),
            ]),
        )
        .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        super::helpers::parse_failed(
            engine.suite.b64u(),
            &Json::Object(vec![
                ("conversation_id".into(), cid_j),
                ("reason".into(), Json::String("InviteExpired".into())),
                ("expires".into(), Json::String("x".into())),
            ]),
        )
        .unwrap_err(),
        EngineError::MalformedPersist
    );
    let mut rk = EngineState::new();
    rk.put_dm_inviter(
        UserId::from_bytes([0; 32]),
        IdentityId::from_bytes([0; 32]),
        ConversationId::from_bytes([1; 32]),
        super::party::InviterPhase::Failed {
            ticket: Ticket {
                secret: Secret::from_bytes([0; 32]),
                persistents: Vec::new(),
                expires: UnixSeconds::from_u64(0),
            },
            list_from: crate::protocol::v1::TimeBin::from_u64(0),
            reason: super::party::HandshakeFailure::NoticeUnlockFailed,
        },
    );
    rk.put_skipped(
        ConversationId::from_bytes([1; 32]),
        ActorId::handshake(),
        super::super::chain::CachedMk {
            mk: [2; 32],
            expires_at: UnixSeconds::from_u64(9),
            tx_id: None,
        },
    );
    rk.frags.insert(
        Tag::from_bytes([4; 32]),
        super::state::FragSet {
            conversation_id: ConversationId::from_bytes([9; 32]),
            parts: Default::default(),
            last_i: None,
        },
    );
    let dummy = super::super::chain::SendChain {
        root: [0; 32],
        c: [0; 32],
        epoch: crate::protocol::v1::PacketEpoch::from_u64(0),
        packet_seq: crate::protocol::v1::PacketSeq::from_u64(0),
    };
    rk.put_send_chain(
        ConversationId::from_bytes([1; 32]),
        ActorId::handshake(),
        dummy.clone(),
    );
    rk.put_recv_chain(
        ConversationId::from_bytes([1; 32]),
        ActorId::handshake(),
        dummy,
    );
    rk.put_last_ack(
        ConversationId::from_bytes([1; 32]),
        ActorId::from_bytes(vec![1]),
        std::collections::BTreeSet::new(),
    );
    super::helpers::rekey_conversation(
        &mut rk,
        ConversationId::from_bytes([1; 32]),
        ConversationId::from_bytes([2; 32]),
    );
    assert_eq!(
        rk.failed(ConversationId::from_bytes([2; 32])),
        Some(FailedReason::NoticeUnlockFailed)
    );
    assert!(rk.is_inviter(ConversationId::from_bytes([2; 32])));
    let parent = ConversationId::from_bytes([8; 32]);
    let child_rk = ConversationId::from_bytes([9; 32]);
    rk.put_dm_inviter(
        UserId::from_bytes([0; 32]),
        IdentityId::from_bytes([0; 32]),
        parent,
        super::party::InviterPhase::InviteCreated {
            ticket: ticket.clone(),
            intake: crate::protocol::v1::KeyPair::from_parts(vec![1; 32], vec![2; 32]),
            list_from: crate::protocol::v1::TimeBin::from_u64(0),
        },
    );
    rk.put_dm(
        UserId::from_bytes([0; 32]),
        IdentityId::from_bytes([0; 32]),
        child_rk,
        super::state::IdentityNode::direct(Secret::from_bytes([7; 32]), parent),
    );
    super::helpers::rekey_conversation(&mut rk, child_rk, ConversationId::from_bytes([10; 32]));
    super::helpers::rekey_conversation(&mut rk, parent, ConversationId::from_bytes([11; 32]));
    engine
        .handshake_ingest_gate(&mut pinned.clone(), cid, &TxPayload::Confirm)
        .expect("g8");
    engine
        .try_mint_inviter_intro(&mut inv_conf.clone(), &rng, cid)
        .expect("hasintro");
    let secret = ticket.secret;
    let mut chain = named_ie
        .state
        .chains(cid)
        .and_then(|c| c.recv.get(&ActorId::handshake()).cloned())
        .expect("rc");
    let clash_body = DurableBody {
        conversation_id: cid,
        hlc: Hlc {
            wall_ms: 0,
            counter: 0,
        },
        payload: other_notice,
    };
    let packed_clash = packed_tx(&engine.suite, &clash_body);
    let pkts = fragment_body(
        &engine.suite,
        &packed_clash,
        Tag::from_bytes([0x44; 32]),
        Tag::from_bytes([0; 32]),
        chain.packet_seq.as_u64(),
        &[],
    )
    .expect("fr");
    let mut clash_ing = named_ie.state.clone();
    for pkt in pkts {
        let sealed =
            seal_packet(&engine.suite, &rng, &mk(engine.suite.hmac(), &chain), &pkt).expect("sl");
        clash_ing = engine
            .ingest_packet(clash_ing, &rng, ch.clone(), tag, &sealed)
            .expect("cling")
            .state;
        chain = step(engine.suite.hmac(), &chain);
    }
    assert_eq!(clash_ing.failed(cid), Some(FailedReason::NoticeConflict));
    let codec_chain = join(
        engine.suite.hmac(),
        secret.as_bytes(),
        ConversationSort::HandshakeDm,
        &[],
    )
    .expect("jnc");
    let b_codec = seal_packet(
        &engine.suite,
        &rng,
        &mk(engine.suite.hmac(), &codec_chain),
        &PacketPlain::TxFragLast(PacketTxFragLast {
            actor_id: Vec::new(),
            packet_seq: 0,
            tx_id: Tag::from_bytes([0x55; 32]),
            frag_i: 0,
            frag: vec![0xfe, 0xfd, 1],
            set_xor: Tag::from_bytes([0; 32]),
        }),
    )
    .expect("scodec");
    let (recv_codec, _) = engine
        .receive_ticket(
            engine
                .tick(EngineState::new(), 1_700_000_000)
                .expect("tco")
                .state,
            &rng,
            uid,
            iid,
            &ticket_s,
        )
        .expect("rco");
    engine
        .ingest_packet(recv_codec.state, &rng, ch, tag, &b_codec)
        .expect("ico");
    engine.lock();
}

#[test]
fn handshake_sync_intros() {
    use super::{
        Conversation, ConversationRef, FailedReason, Handshake, HandshakeInvitee, HandshakeInviter,
        SynchronizationQuery,
    };
    let mut engine = test_engine();
    let rng = CounterRng::new();
    engine
        .wrap_dek(&rng, &UnlockSecret::Passphrase("passpass".into()))
        .expect("wrap");
    let ticked = engine
        .tick(EngineState::new(), 1_700_000_000)
        .expect("tick");
    let (invited, sid) = engine
        .create_sync_invite(
            ticked.state,
            &rng,
            Policy::Classic,
            1_800_000_000,
            "phone",
            None,
        )
        .expect("sinv");
    let zeros = UserId::from_bytes([0; 32]);
    let zid = IdentityId::from_bytes([0; 32]);
    let ids = ConversationRef {
        user_id: zeros,
        identity_id: zid,
        conversation_id: sid,
    };
    let ticket_s = engine.ticket_host_string(&invited.state, &ids).expect("t");
    let notice_writes: Vec<_> = engine
        .poll(&invited.state)
        .expect("p")
        .write_durable
        .into_iter()
        .map(|w| (w.channel, w.tag, w.body))
        .collect();
    let inviter = ack_all(&engine, invited.state);
    let ie_tick = engine
        .tick(EngineState::new(), 1_700_000_000)
        .expect("it")
        .state;
    let (received, _) = engine
        .receive_sync_ticket(ie_tick, &rng, &ticket_s)
        .expect("recv");
    let named_ie = engine
        .set_device_name(received.state, &rng, "tablet")
        .expect("dn");
    let bodies: Vec<Vec<u8>> = notice_writes.iter().map(|w| w.2.clone()).collect();
    let minted = engine
        .ingest_list(
            named_ie.state,
            &rng,
            notice_writes[0].0.clone(),
            notice_writes[0].1,
            &bodies,
        )
        .expect("ing");
    assert!(matches!(
        engine
            .get_conversation(&minted.state, zeros, zid, sid)
            .expect("ir"),
        Conversation::HandshakeSync(Handshake::Invitee(
            HandshakeInvitee::IntroductionMinted { .. }
        ))
    ));
    let intro_writes: Vec<_> = engine
        .poll(&minted.state)
        .expect("ip")
        .write_durable
        .into_iter()
        .map(|w| (w.channel, w.tag, w.body))
        .collect();
    let sent = ack_all(&engine, minted.state);
    assert!(matches!(
        engine.get_conversation(&sent, zeros, zid, sid).expect("is"),
        Conversation::HandshakeSync(Handshake::Invitee(
            HandshakeInvitee::IntroductionSent { .. }
        ))
    ));
    let intro_bodies: Vec<Vec<u8>> = intro_writes.iter().map(|w| w.2.clone()).collect();
    let inv_minted = engine
        .ingest_list(
            inviter,
            &rng,
            intro_writes[0].0.clone(),
            intro_writes[0].1,
            &intro_bodies,
        )
        .expect("iing");
    assert!(matches!(
        engine
            .get_conversation(&inv_minted.state, zeros, zid, sid)
            .expect("im"),
        Conversation::HandshakeSync(Handshake::Inviter(
            HandshakeInviter::IntroductionMinted { .. }
        ))
    ));
    let inv_intro_writes: Vec<_> = engine
        .poll(&inv_minted.state)
        .expect("iip")
        .write_durable
        .into_iter()
        .map(|w| (w.channel, w.tag, w.body))
        .collect();
    let inv_conf = ack_all(&engine, inv_minted.state);
    assert!(matches!(
        engine
            .get_conversation(&inv_conf, zeros, zid, sid)
            .expect("ic"),
        Conversation::HandshakeSync(Handshake::Inviter(HandshakeInviter::Confirming {
            confirmation_digest: ref d,
            ..
        })) if !d.is_empty()
    ));
    let ie_conf = engine
        .ingest_list(
            sent,
            &rng,
            inv_intro_writes[0].0.clone(),
            inv_intro_writes[0].1,
            &inv_intro_writes
                .iter()
                .map(|w| w.2.clone())
                .collect::<Vec<_>>(),
        )
        .expect("ieing");
    assert!(matches!(
        engine
            .get_conversation(&ie_conf.state, zeros, zid, sid)
            .expect("iec"),
        Conversation::HandshakeSync(Handshake::Invitee(HandshakeInvitee::Confirming {
            confirmation_digest: ref d,
            ..
        })) if !d.is_empty()
    ));
    let mut missing_sync = ie_conf.state.clone();
    missing_sync.txs.retain(|_, body| {
        !matches!(
            body.payload,
            TxPayload::InviterIntro(_) | TxPayload::InviteeIntro(_)
        )
    });
    assert_eq!(
        engine
            .confirm_established(missing_sync, &rng, ids)
            .unwrap_err(),
        EngineError::MalformedPayload
    );
    let rejected = engine
        .reject_established(inv_conf.clone(), &rng, ids)
        .expect("rej");
    assert!(matches!(
        engine
            .get_conversation(&rejected.state, zeros, zid, sid)
            .expect("rejq"),
        Conversation::HandshakeSync(Handshake::Failed(FailedReason::ConfirmationRejected))
    ));
    let confirmed = engine
        .confirm_established(ie_conf.state, &rng, ids)
        .expect("conf");
    assert!(matches!(
        engine
            .get_conversation(&confirmed.state, zeros, zid, sid)
            .expect("est"),
        Conversation::HandshakeSync(Handshake::Invitee(HandshakeInvitee::Confirming { .. }))
    ));
    let rows = engine
        .list_conversations(&confirmed.state, zeros, zid)
        .expect("slist");
    assert_eq!(rows.len(), 2);
    let child = rows
        .iter()
        .find_map(|r| match r.conversation {
            Conversation::Synchronization(SynchronizationQuery::SyncEstablished) => {
                Some(r.conversation_id)
            }
            _ => None,
        })
        .expect("schild");
    assert!(matches!(
        engine
            .get_conversation(&confirmed.state, zeros, zid, child)
            .expect("schq"),
        Conversation::Synchronization(SynchronizationQuery::SyncEstablished)
    ));
    let mut fold_s = confirmed.state.clone();
    fold_s.cover_last_acks();
    let snap_s = engine.fold(fold_s).expect("sfoldc");
    let restored_s = engine.apply_folded(&snap_s.snapshot).expect("safc");
    assert!(restored_s.is_sync_established(child));
    let mut child_ids = ids;
    child_ids.conversation_id = child;
    engine
        .delete_conversation(confirmed.state.clone(), child_ids)
        .expect("delschild");
    engine
        .leave_sync(confirmed.state.clone(), &rng)
        .expect("lsync");
    let expired = engine.tick(inv_conf, 1_900_000_000).expect("exp");
    assert!(matches!(
        engine
            .get_conversation(&expired.state, zeros, zid, sid)
            .expect("exq"),
        Conversation::HandshakeSync(Handshake::Failed(FailedReason::InviteExpired { .. }))
    ));
    let _ = format!("{engine:?}");
    let _ = confirmed.persist();
    let _ = confirmed.pings();
    let _ = confirmed.state.tx_count();
    let _ = engine.defaults();
    let mut fold_e = expired.state.clone();
    fold_e.cover_last_acks();
    let snap = engine.fold(fold_e).expect("foldp");
    let _ = snap.persist();
    let _ = snap.pings();
    engine.lock();
}

#[test]
fn watermark_expire_live_ack_and_fold_fields() {
    use super::super::chain::{join, mk, seal_packet};
    use super::super::payload::{
        ConversationSort, PacketPlain, PacketTyping, PacketXorAck, TxMedia, TxText,
    };
    use crate::protocol::v1::fixtures::{sample_durable, test_suite};
    use crate::protocol::v1::{
        Address, Defaults, EphemeralChannel, Kind, NotificationPrivacy, Tag,
    };
    let eph = EphemeralChannel::new(
        Kind::try_from("webrtc").expect("ek"),
        Address::try_from("https://eph.example").expect("ea"),
    );
    let defaults = Defaults::try_new(
        vec![sample_durable()],
        vec![eph.clone()],
        true,
        true,
        true,
        None,
        false,
        NotificationPrivacy::Name,
    )
    .expect("def");
    let mut engine = Engine::new(test_suite(), defaults);
    let rng = CounterRng::new();
    engine
        .wrap_dek(&rng, &UnlockSecret::Passphrase("passpass".into()))
        .expect("wrap");
    let ticked = engine
        .tick(EngineState::new(), 1_700_000_000)
        .expect("tick");
    let (created, uid) = engine.create_user(ticked.state, &rng).expect("user");
    let eid = engine.engine_conversation_id().expect("eid");
    let mut exp = created.state.clone();
    let expired_tx = Tag::from_bytes([0x22; 32]);
    exp.txs.insert(
        expired_tx,
        DurableBody {
            conversation_id: eid,
            hlc: Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: TxPayload::Text(TxText {
                body: "x".into(),
                reply_to: None,
                expire_at: Some(UnixSeconds::from_u64(1)),
            }),
        },
    );
    exp.persist_log.insert(exp.next_seq, expired_tx);
    exp.next_seq = exp.next_seq.saturating_add(1);
    let snap_e = engine.fold(exp).expect("fexp");
    let restored_e = engine.apply_folded(&snap_e.snapshot).expect("aexp");
    assert!(!restored_e.txs.contains_key(&expired_tx));
    let (created, iid) = engine
        .create_identity(created.state, &rng, uid, Policy::Classic)
        .expect("id");
    let (invited, cid) = engine
        .create_invite(created.state, &rng, uid, iid, 1_800_000_000, None)
        .expect("inv");
    let ids = ConversationRef {
        user_id: uid,
        identity_id: iid,
        conversation_id: cid,
    };
    let ticket_s = engine.ticket_host_string(&invited.state, &ids).expect("t");
    let poll = engine.poll(&invited.state).expect("p");
    let w = &poll.write_durable[0];
    let bodies: Vec<Vec<u8>> = poll.write_durable.iter().map(|x| x.body.clone()).collect();
    let ie = engine
        .tick(EngineState::new(), 1_700_000_000)
        .expect("ie")
        .state;
    let (ie_u, ie_uid) = engine.create_user(ie, &rng).expect("ieu");
    let (ie_i, ie_iid) = engine
        .create_identity(ie_u.state, &rng, ie_uid, Policy::Classic)
        .expect("iei");
    let (recv, _) = engine
        .receive_ticket(ie_i.state, &rng, ie_uid, ie_iid, &ticket_s)
        .expect("recv");
    let ingested = engine
        .ingest_list(recv.state, &rng, w.channel.clone(), w.tag, &bodies)
        .expect("ing");
    let before = ingested.state.last_acks_snapshot();
    let xor = PacketPlain::XorAck(PacketXorAck {
        actor_id: Vec::new(),
        packet_seq: 0,
        set_xor: Tag::from_bytes([1; 32]),
    });
    let packed = engine.suite.b64u().decode(&ticket_s).expect("dec");
    let canonical = engine
        .suite
        .compress()
        .decompress(
            &packed,
            crate::protocol::v1::payload::TICKET_MAX_UNCOMPRESSED,
        )
        .expect("z");
    let json = engine.suite.canonical_json().decode(&canonical).expect("j");
    let ticket = super::super::codec::ticket_from_json(engine.suite.b64u(), &json).expect("ticket");
    let chain = join(
        engine.suite.hmac(),
        ticket.secret.as_bytes(),
        ConversationSort::HandshakeDm,
        &[],
    )
    .expect("join");
    let b_xor =
        seal_packet(&engine.suite, &rng, &mk(engine.suite.hmac(), &chain), &xor).expect("sx");
    let live = engine
        .ingest_ephemeral_packet(ingested.state.clone(), &rng, eph, w.tag, &b_xor)
        .expect("live");
    assert_eq!(live.state.last_acks_snapshot(), before);
    let typing = PacketPlain::Typing(PacketTyping {
        actor_id: Vec::new(),
        packet_seq: 0,
        conversation_id: cid,
        composing: true,
    });
    let b_ty = seal_packet(
        &engine.suite,
        &rng,
        &mk(engine.suite.hmac(), &chain),
        &typing,
    )
    .expect("sty");
    engine
        .ingest_packet(
            ingested.state.clone(),
            &rng,
            w.channel.clone(),
            w.tag,
            &b_ty,
        )
        .expect("ty");
    let mut ghost = ingested.state.clone();
    ghost.txs.insert(
        Tag::from_bytes([0x33; 32]),
        DurableBody {
            conversation_id: cid,
            hlc: Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: TxPayload::Confirm,
        },
    );
    engine.fold(ghost).expect("ghost");
    let mut empty_actors = ingested.state.clone();
    empty_actors.put_last_ack(cid, ActorId::handshake(), Default::default());
    engine.fold(empty_actors).expect("emptyack");
    let mut orphan = ingested.state.clone();
    orphan.persist_log.insert(
        crate::protocol::v1::PersistSeq::from_u64(999),
        Tag::from_bytes([0x44; 32]),
    );
    engine.fold(orphan).expect("orph");
    let mut media = ingested.state.clone();
    media.txs.insert(
        Tag::from_bytes([0x55; 32]),
        DurableBody {
            conversation_id: eid,
            hlc: Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: TxPayload::Media(TxMedia {
                mime: "image/png".into(),
                filename: "a.png".into(),
                hash: Tag::from_bytes([3; 32]),
                kind: Kind::try_from("nostr").expect("mk"),
                address: Address::try_from("https://blob.example").expect("ma"),
                tag: Tag::from_bytes([4; 32]),
                caption: None,
                reply_to: None,
                expire_at: Some(UnixSeconds::from_u64(1)),
            }),
        },
    );
    engine.fold(media).expect("fmedia");
    fn seal_fold(engine: &Engine, json: Json, seq: u64) -> Vec<u8> {
        let dek = engine.dek.as_ref().expect("dek");
        let canonical = engine.suite.canonical_json().encode(&json);
        let packed = engine.suite.compress().compress(&canonical);
        let mut nonce_bytes = [0u8; AEAD_NONCE_LEN];
        nonce_bytes[..4].copy_from_slice(&FOLD_VERSION.to_be_bytes());
        nonce_bytes[4..].copy_from_slice(&seq.to_be_bytes());
        let ct = engine
            .suite
            .aead()
            .seal(dek, &AeadNonce::from_bytes(nonce_bytes), b"", &packed);
        let mut snapshot = Vec::with_capacity(AEAD_NONCE_LEN + ct.len());
        snapshot.extend_from_slice(&nonce_bytes);
        snapshot.extend_from_slice(&ct);
        snapshot
    }
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(0)),
                    ("last_acks".into(), Json::Number(1)),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(0)),
                    ("persist_log".into(), Json::Number(1)),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(0)),
                    ("last_acks".into(), Json::Array(vec![Json::Number(1)])),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(0)),
                    ("persist_log".into(), Json::Array(vec![Json::Number(1)])),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    let z = super::super::codec::bstr(engine.suite.b64u(), &[0u8; 32]);
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(0)),
                    (
                        "last_acks".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("actor_id".into(), z.clone()),
                            ("tx_ids".into(), Json::Array(Vec::new())),
                        ])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(0)),
                    (
                        "last_acks".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("conversation_id".into(), z.clone()),
                            ("tx_ids".into(), Json::Array(Vec::new())),
                        ])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(0)),
                    (
                        "last_acks".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("conversation_id".into(), z.clone()),
                            ("actor_id".into(), z.clone()),
                            ("tx_ids".into(), Json::Number(1)),
                        ])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(0)),
                    (
                        "persist_log".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("seq".into(), Json::String("1".into())),
                            ("tx_id".into(), z.clone()),
                        ])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(0)),
                    (
                        "persist_log".into(),
                        Json::Array(vec![Json::Object(vec![("seq".into(), Json::Number(1))])])
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    let ticket_j = super::super::codec::ticket_to_json(engine.suite.b64u(), &ticket);
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(0)),
                    (
                        "tickets".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("conversation_id".into(), z.clone()),
                            ("ticket".into(), ticket_j.clone()),
                            ("list_from".into(), Json::Bool(true)),
                        ])]),
                    ),
                ]),
                0
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    engine
        .apply_folded(&seal_fold(
            &engine,
            Json::Object(vec![
                ("next_seq".into(), Json::Number(0)),
                (
                    "users".into(),
                    Json::Array(vec![Json::Object(vec![
                        ("user_id".into(), z.clone()),
                        (
                            "identities".into(),
                            Json::Array(vec![Json::Object(vec![
                                ("identity_id".into(), z.clone()),
                                ("name".into(), Json::Null),
                                ("pic".into(), Json::Null),
                                (
                                    "conversations".into(),
                                    Json::Array(vec![Json::Object(vec![
                                        ("conversation_id".into(), z.clone()),
                                        (
                                            "handshake".into(),
                                            Json::Object(vec![
                                                ("role".into(), Json::String("invitee".into())),
                                                (
                                                    "phase".into(),
                                                    Json::String("ticket-received".into()),
                                                ),
                                                ("ticket".into(), ticket_j),
                                                ("list_from".into(), Json::Number(1)),
                                            ]),
                                        ),
                                        (
                                            "chains".into(),
                                            Json::Array(vec![Json::Object(vec![
                                                ("conversation_id".into(), z.clone()),
                                                ("actor_id".into(), z.clone()),
                                                ("root".into(), z.clone()),
                                                ("c".into(), z.clone()),
                                                ("epoch".into(), Json::Number(0)),
                                                ("packet_seq".into(), Json::Number(0)),
                                            ])]),
                                        ),
                                        (
                                            "recv_chains".into(),
                                            Json::Array(vec![Json::Object(vec![
                                                ("conversation_id".into(), z.clone()),
                                                ("actor_id".into(), z.clone()),
                                                ("root".into(), z.clone()),
                                                ("c".into(), z.clone()),
                                                ("epoch".into(), Json::Number(0)),
                                                ("packet_seq".into(), Json::Number(0)),
                                            ])]),
                                        ),
                                        (
                                            "skipped_mks".into(),
                                            Json::Array(vec![Json::Object(vec![
                                                ("actor_id".into(), z.clone()),
                                                (
                                                    "mks".into(),
                                                    Json::Array(vec![Json::Object(vec![
                                                        ("mk".into(), z.clone()),
                                                        ("expires_at".into(), Json::Number(9)),
                                                        ("tx_id".into(), z.clone()),
                                                    ])]),
                                                ),
                                            ])]),
                                        ),
                                        (
                                            "last_acks".into(),
                                            Json::Array(vec![Json::Object(vec![
                                                ("actor_id".into(), z.clone()),
                                                ("tx_ids".into(), Json::Array(vec![z.clone()])),
                                            ])]),
                                        ),
                                    ])]),
                                ),
                            ])]),
                        ),
                    ])]),
                ),
                (
                    "device".into(),
                    Json::Object(vec![
                        ("name".into(), Json::Null),
                        ("keys".into(), Json::Null),
                        ("conversations".into(), Json::Array(Vec::new())),
                    ]),
                ),
                (
                    "persist_log".into(),
                    Json::Array(vec![Json::Object(vec![
                        ("seq".into(), Json::Number(0)),
                        ("tx_id".into(), z),
                    ])]),
                ),
            ]),
            0,
        ))
        .expect("okparse");
}

#[test]
fn fold_tree_phases_and_parse_errors() {
    use super::party::{HandshakeFailure, InviteePhase, InviterPhase};
    use super::{Engine, FOLD_VERSION};
    use crate::protocol::v1::fixtures::{CounterRng, test_engine};
    use crate::protocol::v1::{
        AeadNonce, ConversationId, EngineError, IdentityId, Json, KeyPair, Policy, Secret, Tag,
        TimeBin, UnixSeconds, UnlockSecret, UserId,
    };
    let mut engine = test_engine();
    let rng = CounterRng::new();
    engine
        .wrap_dek(&rng, &UnlockSecret::Passphrase("passpass".into()))
        .expect("wrap");
    let ticked = engine
        .tick(EngineState::new(), 1_700_000_000)
        .expect("tick")
        .state;
    let (user_state, uid) = engine.create_user(ticked, &rng).expect("user");
    let (id_state, iid) = engine
        .create_identity(user_state.state, &rng, uid, Policy::Classic)
        .expect("id");
    let named = engine
        .set_display_name(id_state.state, &rng, uid, iid, "Ada")
        .expect("name");
    let mut webp = vec![0u8; 12];
    webp[0..4].copy_from_slice(b"RIFF");
    webp[8..12].copy_from_slice(b"WEBP");
    let pictured = engine
        .set_profile_pic(named.state, &rng, uid, iid, Some(&webp))
        .expect("pic");
    let snap = engine.fold(pictured.state.clone()).expect("foldpic");
    engine.apply_folded(&snap.snapshot).expect("picback");
    let uid0 = UserId::from_bytes([9; 32]);
    let iid0 = IdentityId::from_bytes([8; 32]);
    let cid = ConversationId::from_bytes([7; 32]);
    let ticket = crate::protocol::v1::payload::Ticket {
        secret: Secret::from_bytes([4; 32]),
        persistents: vec![crate::protocol::v1::DurableChannel::new(
            crate::protocol::v1::Kind::try_from("nostr").expect("k"),
            crate::protocol::v1::Address::try_from("wss://relay.example").expect("a"),
        )],
        expires: UnixSeconds::from_u64(9),
    };
    let intake = KeyPair::from_parts(vec![1; 32], vec![2; 32]);
    let list_from = TimeBin::from_u64(3);
    let shared_a = Secret::from_bytes([5; 32]);
    let shared_b = Secret::from_bytes([6; 32]);
    let inviter_phases = [
        InviterPhase::InviteCreated {
            ticket: ticket.clone(),
            intake: intake.clone(),
            list_from,
        },
        InviterPhase::NoticePinned {
            ticket: ticket.clone(),
            intake: intake.clone(),
            list_from,
        },
        InviterPhase::IntroductionMinted {
            ticket: ticket.clone(),
            intake: intake.clone(),
            shared_inviter: shared_a,
            shared_invitee: shared_b,
            list_from,
        },
        InviterPhase::Confirming {
            ticket: ticket.clone(),
            intake: intake.clone(),
            shared_inviter: shared_a,
            shared_invitee: shared_b,
            list_from,
        },
        InviterPhase::Failed {
            ticket: ticket.clone(),
            list_from,
            reason: HandshakeFailure::NoticeConflict,
        },
    ];
    for phase in inviter_phases {
        let mut state = EngineState::new();
        state.put_dm_inviter(uid0, iid0, cid, phase);
        let _ = state.intake_secret(cid);
        let folded = engine.fold(state).expect("finv");
        let back = engine.apply_folded(&folded.snapshot).expect("ainv");
        if let Some(p) = back.party(cid) {
            let _ = p.shared_inviter();
            let _ = p.shared_invitee();
            let _ = p.intake();
        }
        assert!(back.ticket(cid).is_some());
        let _ = engine.get_conversation(&back, uid0, iid0, cid);
    }
    let invitee_phases = [
        InviteePhase::TicketReceived {
            ticket: ticket.clone(),
            list_from,
        },
        InviteePhase::InviteReceived {
            ticket: ticket.clone(),
            list_from,
            policy: Policy::Classic,
        },
        InviteePhase::IntroductionMinted {
            ticket: ticket.clone(),
            list_from,
            policy: Policy::Hybrid,
            intake: intake.clone(),
            shared_inviter: shared_a,
        },
        InviteePhase::IntroductionSent {
            ticket: ticket.clone(),
            list_from,
            policy: Policy::PostQuantum,
            intake: intake.clone(),
            shared_inviter: shared_a,
        },
        InviteePhase::Confirming {
            ticket: ticket.clone(),
            list_from,
            policy: Policy::Classic,
            intake: intake.clone(),
            shared_inviter: shared_a,
            shared_invitee: shared_b,
        },
        InviteePhase::Failed {
            ticket: ticket.clone(),
            list_from,
            reason: HandshakeFailure::InviteExpired {
                expires: UnixSeconds::from_u64(4),
            },
        },
    ];
    for phase in invitee_phases {
        let mut state = EngineState::new();
        state.put_dm_invitee(uid0, iid0, cid, phase);
        let _ = state.intake_secret(cid);
        let folded = engine.fold(state).expect("fie");
        let back = engine.apply_folded(&folded.snapshot).expect("aie");
        if let Some(p) = back.party(cid) {
            let _ = p.shared_inviter();
            let _ = p.shared_invitee();
            let _ = p.intake();
        }
        assert!(back.ticket(cid).is_some());
        let _ = engine.get_conversation(&back, uid0, iid0, cid);
    }
    let mut mismatch = pictured.state.clone();
    mismatch.put_dm_invitee(
        uid,
        iid,
        cid,
        InviteePhase::InviteReceived {
            ticket: ticket.clone(),
            list_from,
            policy: Policy::Hybrid,
        },
    );
    mismatch.txs.insert(
        Tag::from_bytes([0x71; 32]),
        crate::protocol::v1::payload::DurableBody {
            conversation_id: cid,
            hlc: crate::protocol::v1::payload::Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: crate::protocol::v1::payload::TxPayload::Notice(
                crate::protocol::v1::payload::TxNotice {
                    policy: Policy::Hybrid,
                    intake_pk: vec![0; 32],
                    persistents: ticket.persistents.clone(),
                    ephemerals: Vec::new(),
                    expires: UnixSeconds::from_u64(9),
                },
            ),
        },
    );
    let mut duplicate = mismatch.clone();
    duplicate.txs.insert(
        Tag::from_bytes([0x72; 32]),
        crate::protocol::v1::payload::DurableBody {
            conversation_id: cid,
            hlc: crate::protocol::v1::payload::Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: crate::protocol::v1::payload::TxPayload::InviteeIntro(
                crate::protocol::v1::payload::TxInviteeIntro {
                    name: crate::protocol::v1::DisplayName::try_from("A").expect("a"),
                    profile_pic: None,
                    send_tag_key: crate::protocol::v1::TagKey::from_bytes([1; 32]),
                    eph_send_tag_key: crate::protocol::v1::TagKey::from_bytes([2; 32]),
                    encryption_pk: vec![1; 32],
                    signing_pk: vec![1; 32],
                    intake_pk: vec![1; 32],
                    seed_ct: vec![1; 32],
                    prefs: crate::protocol::v1::OnWirePrefs {
                        read_receipts: true,
                        online_visible: true,
                        send_typing: true,
                        disappear_after: None,
                        wake: None,
                    },
                },
            ),
        },
    );
    assert!(
        engine
            .try_mint_invitee_intro(&mut duplicate, &rng, cid)
            .expect("dup")
            .is_empty()
    );
    engine
        .try_mint_invitee_intro(&mut mismatch, &rng, cid)
        .expect("mm");
    let mut wrap_fail = pictured.state.clone();
    wrap_fail.put_dm_inviter(
        uid,
        iid,
        cid,
        InviterPhase::NoticePinned {
            ticket: ticket.clone(),
            intake: intake.clone(),
            list_from,
        },
    );
    wrap_fail.txs.insert(
        Tag::from_bytes([0x73; 32]),
        crate::protocol::v1::payload::DurableBody {
            conversation_id: cid,
            hlc: crate::protocol::v1::payload::Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: crate::protocol::v1::payload::TxPayload::Notice(
                crate::protocol::v1::payload::TxNotice {
                    policy: Policy::Classic,
                    intake_pk: vec![0; 32],
                    persistents: ticket.persistents.clone(),
                    ephemerals: Vec::new(),
                    expires: UnixSeconds::from_u64(9),
                },
            ),
        },
    );
    wrap_fail.txs.insert(
        Tag::from_bytes([0x74; 32]),
        crate::protocol::v1::payload::DurableBody {
            conversation_id: cid,
            hlc: crate::protocol::v1::payload::Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: crate::protocol::v1::payload::TxPayload::InviteeIntro(
                crate::protocol::v1::payload::TxInviteeIntro {
                    name: crate::protocol::v1::DisplayName::try_from("B").expect("b"),
                    profile_pic: None,
                    send_tag_key: crate::protocol::v1::TagKey::from_bytes([3; 32]),
                    eph_send_tag_key: crate::protocol::v1::TagKey::from_bytes([4; 32]),
                    encryption_pk: vec![1; 8],
                    signing_pk: vec![1; 8],
                    intake_pk: vec![1; 8],
                    seed_ct: vec![1; 8],
                    prefs: crate::protocol::v1::OnWirePrefs {
                        read_receipts: true,
                        online_visible: true,
                        send_typing: true,
                        disappear_after: None,
                        wake: None,
                    },
                },
            ),
        },
    );
    assert!(
        engine
            .try_mint_inviter_intro(&mut wrap_fail, &rng, cid)
            .expect("wf")
            .is_empty()
    );
    let mut sync_state = EngineState::new();
    sync_state.put_sync_inviter(
        cid,
        InviterPhase::NoticePinned {
            ticket: ticket.clone(),
            intake: intake.clone(),
            list_from,
        },
    );
    sync_state.put_sync(
        ConversationId::from_bytes([3; 32]),
        super::state::DeviceNode::sync(Secret::from_bytes([1; 32]), cid),
    );
    sync_state.device.name = Some(crate::protocol::v1::DisplayName::try_from("phone").expect("dn"));
    sync_state.device.keys = Some(super::state::DeviceKeys {
        id: None,
        enc: intake.clone(),
        sign: crate::protocol::v1::SigningKeyPair::from_parts(vec![3; 32], vec![4; 32]),
    });
    let folded = engine.fold(sync_state).expect("fsync");
    let back = engine.apply_folded(&folded.snapshot).expect("async");
    assert!(back.is_sync(cid));
    assert!(back.device.keys.as_ref().unwrap().id.is_none());
    let (sync_ok, _) = engine
        .create_sync_invite(
            pictured.state,
            &rng,
            Policy::Classic,
            1_900_000_000,
            "phone",
            None,
        )
        .expect("s1");
    engine
        .create_sync_invite(
            sync_ok.state,
            &rng,
            Policy::Classic,
            1_900_000_000,
            "phone",
            None,
        )
        .expect("s2");
    fn seal(engine: &Engine, json: Json, ver: u32) -> Vec<u8> {
        use crate::protocol::v1::AEAD_NONCE_LEN;
        let dek = engine.dek.as_ref().expect("dek");
        let canonical = engine.suite.canonical_json().encode(&json);
        let packed = engine.suite.compress().compress(&canonical);
        let mut nonce_bytes = [0u8; AEAD_NONCE_LEN];
        nonce_bytes[..4].copy_from_slice(&ver.to_be_bytes());
        let ct = engine
            .suite
            .aead()
            .seal(dek, &AeadNonce::from_bytes(nonce_bytes), b"", &packed);
        let mut snapshot = Vec::with_capacity(AEAD_NONCE_LEN + ct.len());
        snapshot.extend_from_slice(&nonce_bytes);
        snapshot.extend_from_slice(&ct);
        snapshot
    }
    assert_eq!(
        engine
            .apply_folded(&seal(
                &engine,
                Json::Object(vec![("next_seq".into(), Json::Number(1))]),
                2
            ))
            .unwrap_err(),
        EngineError::MalformedPersist
    );
    let bad = [
        Json::Object(vec![
            ("next_seq".into(), Json::Number(1)),
            ("users".into(), Json::Number(1)),
        ]),
        Json::Object(vec![
            ("next_seq".into(), Json::Number(1)),
            ("users".into(), Json::Array(vec![Json::Number(1)])),
        ]),
        Json::Object(vec![
            ("next_seq".into(), Json::Number(1)),
            ("device".into(), Json::Array(Vec::new())),
        ]),
        Json::Object(vec![
            ("next_seq".into(), Json::Number(1)),
            (
                "device".into(),
                Json::Object(vec![
                    ("name".into(), Json::Number(1)),
                    ("keys".into(), Json::Null),
                    ("conversations".into(), Json::Array(Vec::new())),
                ]),
            ),
        ]),
    ];
    for json in bad {
        assert_eq!(
            engine
                .apply_folded(&seal(&engine, json, FOLD_VERSION))
                .unwrap_err(),
            EngineError::MalformedPersist
        );
    }
    let z = super::super::codec::bstr(engine.suite.b64u(), &[0u8; 32]);
    for reason in [
        "NoticeUnlockFailed",
        "NoticeConflict",
        "IntroUnlockFailed",
        "IntroVerifyFailed",
        "DuplicateIntro",
        "ConfirmationRejected",
        "Equivocation",
        "OfferRejected",
        "Kicked",
        "Left",
        "nope",
    ] {
        let value = Json::Object(vec![
            ("conversation_id".into(), z.clone()),
            ("reason".into(), Json::String(reason.into())),
        ]);
        let _ = super::helpers::parse_failed(engine.suite.b64u(), &value);
    }
    let _ = super::helpers::parse_failed(
        engine.suite.b64u(),
        &Json::Object(vec![
            ("conversation_id".into(), z.clone()),
            ("reason".into(), Json::String("PolicyNotAccepted".into())),
            ("policy".into(), Json::String("Classic".into())),
        ]),
    );
    let _ = super::helpers::parse_failed(
        engine.suite.b64u(),
        &Json::Object(vec![
            ("conversation_id".into(), z),
            ("reason".into(), Json::String("InviteExpired".into())),
            ("expires".into(), Json::Number(3)),
        ]),
    );
    let _ = Tag::from_bytes([0; 32]);
    let mut edges = EngineState::new();
    edges.put_dm_inviter(
        uid0,
        iid0,
        cid,
        InviterPhase::InviteCreated {
            ticket: ticket.clone(),
            intake: intake.clone(),
            list_from,
        },
    );
    {
        let mut party = edges.party_mut(cid).expect("inviter row");
        let inviter = party.inviter_mut().expect("inviter");
        assert!(!inviter.mint_intro(shared_a, shared_b));
        inviter.fail(HandshakeFailure::NoticeConflict);
        inviter.fail(HandshakeFailure::DuplicateIntro);
    }
    edges.put_dm_invitee(
        uid0,
        iid0,
        ConversationId::from_bytes([15; 32]),
        InviteePhase::IntroductionMinted {
            ticket: ticket.clone(),
            list_from,
            policy: Policy::Classic,
            intake: intake.clone(),
            shared_inviter: shared_a,
        },
    );
    {
        let mut party = edges
            .party_mut(ConversationId::from_bytes([15; 32]))
            .expect("minted");
        let invitee = party.invitee_mut().expect("invitee");
        assert!(invitee.confirm_peer(shared_b));
    }
    edges.put_dm_invitee(
        uid0,
        iid0,
        ConversationId::from_bytes([2; 32]),
        InviteePhase::TicketReceived {
            ticket: ticket.clone(),
            list_from,
        },
    );
    {
        let mut party = edges
            .party_mut(ConversationId::from_bytes([2; 32]))
            .expect("ticket");
        let invitee = party.invitee_mut().expect("invitee");
        assert!(!invitee.mint_intro(intake.clone(), shared_a));
        assert!(!invitee.confirm_peer(shared_b));
        assert!(invitee.receive_notice(Policy::Classic));
        assert!(!invitee.receive_notice(Policy::Classic));
        invitee.fail(HandshakeFailure::NoticeUnlockFailed);
        invitee.fail(HandshakeFailure::NoticeUnlockFailed);
    }
    {
        let mut party = edges
            .party_mut(ConversationId::from_bytes([2; 32]))
            .expect("failed invitee");
        assert!(party.inviter_mut().is_none());
    }
    let parent = ConversationId::from_bytes([11; 32]);
    let child = ConversationId::from_bytes([12; 32]);
    edges.put_sync(
        parent,
        super::state::DeviceNode::handshake(super::party::SyncParty::inviter(
            InviterPhase::NoticePinned {
                ticket: ticket.clone(),
                intake: intake.clone(),
                list_from,
            },
        )),
    );
    edges.put_sync(
        child,
        super::state::DeviceNode::sync(Secret::from_bytes([1; 32]), parent),
    );
    super::helpers::rekey_conversation(&mut edges, parent, ConversationId::from_bytes([13; 32]));
    edges.put_last_ack(
        child,
        crate::protocol::v1::ActorId::handshake(),
        Default::default(),
    );
    assert!(edges.has_last_acks());
    let _ = edges.last_acks_snapshot();
    let _ = edges.scope_of(child);
    assert!(edges.is_sync_established(child));
    let b64 = engine.suite.b64u();
    let mut parsed = EngineState::new();
    let z2 = super::super::codec::bstr(engine.suite.b64u(), &[0u8; 32]);
    assert!(super::fold_tree::install_users(b64, &mut parsed, &Json::Number(1)).is_err());
    assert!(
        super::fold_tree::install_users(
            b64,
            &mut parsed,
            &Json::Array(vec![Json::Object(vec![
                ("user_id".into(), z2.clone()),
                ("identities".into(), Json::Array(vec![Json::Number(1)])),
            ])])
        )
        .is_err()
    );
    assert!(super::helpers::parse_fold_keypair(b64, &Json::Number(1)).is_err());
    assert!(super::helpers::parse_fold_keypair(b64, &Json::Object(vec![])).is_err());
    assert!(super::fold_tree::install_device(b64, &mut parsed, &Json::Number(1)).is_err());
    {
        let mut party = edges.party_mut(cid).expect("failed inviter");
        assert!(party.invitee_mut().is_none());
    }
    let party = edges.party(cid).expect("p");
    let _ = party.shared_inviter();
    let _ = party.shared_invitee();
    let _ = party.intake();
    assert!(
        edges
            .scope_of(ConversationId::from_bytes([1; 32]))
            .is_none()
    );
    assert!(!edges.is_sync_established(cid));
    assert!(
        edges
            .child_of(ConversationId::from_bytes([13; 32]))
            .is_some()
    );
    edges.put_dm(
        uid0,
        iid0,
        ConversationId::from_bytes([14; 32]),
        super::state::IdentityNode::direct(Secret::from_bytes([1; 32]), cid),
    );
    assert!(
        edges
            .party_mut(ConversationId::from_bytes([14; 32]))
            .is_none()
    );
    assert!(edges.party_mut(child).is_none());
    let tj = super::super::codec::ticket_to_json(b64, &ticket);
    let bad_hs = [
        Json::Number(1),
        Json::Object(vec![("role".into(), Json::String("nope".into()))]),
        Json::Object(vec![
            ("role".into(), Json::String("inviter".into())),
            ("phase".into(), Json::String("nope".into())),
            ("ticket".into(), tj.clone()),
            ("list_from".into(), Json::Number(1)),
        ]),
        Json::Object(vec![
            ("role".into(), Json::String("invitee".into())),
            ("phase".into(), Json::String("invite-received".into())),
            ("ticket".into(), tj.clone()),
            ("list_from".into(), Json::Number(1)),
        ]),
        Json::Object(vec![
            ("role".into(), Json::String("inviter".into())),
            ("phase".into(), Json::String("invite-created".into())),
            ("ticket".into(), tj.clone()),
            ("list_from".into(), Json::Number(1)),
            ("chains".into(), Json::Number(1)),
        ]),
    ];
    for hs in bad_hs {
        let users = Json::Array(vec![Json::Object(vec![
            ("user_id".into(), z2.clone()),
            (
                "identities".into(),
                Json::Array(vec![Json::Object(vec![
                    ("identity_id".into(), z2.clone()),
                    ("name".into(), Json::Null),
                    ("pic".into(), Json::Null),
                    (
                        "conversations".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("conversation_id".into(), z2.clone()),
                            ("handshake".into(), hs),
                        ])]),
                    ),
                ])]),
            ),
        ])]);
        assert!(super::fold_tree::install_users(b64, &mut parsed, &users).is_err());
    }
    let _ = super::helpers::parse_failed(engine.suite.b64u(), &Json::Number(1));
    let _ = super::helpers::parse_failed(
        engine.suite.b64u(),
        &Json::Object(vec![
            ("conversation_id".into(), z2.clone()),
            ("reason".into(), Json::Number(1)),
        ]),
    );
    assert!(
        super::fold_tree::install_users(
            b64,
            &mut parsed,
            &Json::Array(vec![Json::Object(vec![
                ("user_id".into(), z2.clone()),
                (
                    "identities".into(),
                    Json::Array(vec![Json::Object(vec![
                        ("identity_id".into(), z2.clone()),
                        ("name".into(), Json::Null),
                        ("pic".into(), Json::Null),
                        ("conversations".into(), Json::Array(vec![Json::Number(1)])),
                    ])])
                ),
            ])])
        )
        .is_err()
    );
    assert!(super::fold_tree::install_device(b64, &mut parsed, &Json::Number(1)).is_err());
    assert!(
        super::fold_tree::install_users(
            b64,
            &mut parsed,
            &Json::Array(vec![Json::Object(vec![
                ("user_id".into(), z2.clone()),
                ("identities".into(), Json::Number(1)),
            ])])
        )
        .is_err()
    );
    assert!(
        super::fold_tree::install_device(
            b64,
            &mut parsed,
            &Json::Object(vec![
                ("name".into(), Json::Null),
                ("keys".into(), Json::Number(1)),
                ("conversations".into(), Json::Number(1)),
            ])
        )
        .is_err()
    );
    let id_shell = |conversations: Json| {
        Json::Array(vec![Json::Object(vec![
            ("user_id".into(), z2.clone()),
            (
                "identities".into(),
                Json::Array(vec![Json::Object(vec![
                    ("identity_id".into(), z2.clone()),
                    ("name".into(), Json::Null),
                    ("pic".into(), Json::Null),
                    ("conversations".into(), conversations),
                ])]),
            ),
        ])])
    };
    assert!(
        super::fold_tree::install_users(b64, &mut parsed, &Json::Array(vec![Json::Number(1)]))
            .is_err()
    );
    assert!(super::fold_tree::install_users(b64, &mut parsed, &id_shell(Json::Number(1))).is_err());
    assert!(
        super::fold_tree::install_users(
            b64,
            &mut parsed,
            &Json::Array(vec![Json::Object(vec![
                ("user_id".into(), z2.clone()),
                (
                    "identities".into(),
                    Json::Array(vec![Json::Object(vec![
                        ("identity_id".into(), z2.clone()),
                        ("name".into(), Json::Bool(true)),
                        ("pic".into(), Json::Null),
                        ("conversations".into(), Json::Array(Vec::new())),
                    ])]),
                ),
            ])])
        )
        .is_err()
    );
    assert!(
        super::fold_tree::install_device(
            b64,
            &mut parsed,
            &Json::Object(vec![
                ("name".into(), Json::Null),
                ("keys".into(), Json::Null),
                ("conversations".into(), Json::Number(1)),
            ])
        )
        .is_err()
    );
    let hs = Json::Object(vec![
        ("role".into(), Json::String("invitee".into())),
        ("phase".into(), Json::String("ticket-received".into())),
        ("ticket".into(), tj.clone()),
        ("list_from".into(), Json::Number(1)),
    ]);
    let conv = |extra: Vec<(&str, Json)>| {
        let mut members = vec![
            ("conversation_id".into(), z2.clone()),
            ("handshake".into(), hs.clone()),
        ];
        for (k, v) in extra {
            members.push((k.into(), v));
        }
        Json::Object(members)
    };
    for extra in [
        vec![("chains", Json::Number(1))],
        vec![("recv_chains", Json::Number(1))],
        vec![("skipped_mks", Json::Number(1))],
        vec![("last_acks", Json::Number(1))],
        vec![(
            "skipped_mks",
            Json::Array(vec![Json::Object(vec![
                ("actor_id".into(), z2.clone()),
                ("mks".into(), Json::Number(1)),
            ])]),
        )],
        vec![(
            "last_acks",
            Json::Array(vec![Json::Object(vec![
                ("actor_id".into(), z2.clone()),
                ("tx_ids".into(), Json::Number(1)),
            ])]),
        )],
    ] {
        assert!(
            super::fold_tree::install_users(
                b64,
                &mut parsed,
                &id_shell(Json::Array(vec![conv(extra)]))
            )
            .is_err()
        );
    }
    assert!(
        super::fold_tree::install_users(
            b64,
            &mut parsed,
            &id_shell(Json::Array(vec![Json::Object(vec![
                ("conversation_id".into(), z2.clone()),
                ("direct_message".into(), Json::Number(1)),
            ])]))
        )
        .is_err()
    );
    assert!(
        super::fold_tree::install_users(
            b64,
            &mut parsed,
            &id_shell(Json::Array(vec![Json::Object(vec![(
                "conversation_id".into(),
                z2.clone()
            )])]))
        )
        .is_err()
    );
    assert!(
        super::fold_tree::install_device(
            b64,
            &mut parsed,
            &Json::Object(vec![
                ("name".into(), Json::Null),
                ("keys".into(), Json::Null),
                (
                    "conversations".into(),
                    Json::Array(vec![Json::Object(vec![(
                        "conversation_id".into(),
                        z2.clone()
                    )])]),
                ),
            ])
        )
        .is_err()
    );
    assert!(
        super::fold_tree::install_users(
            b64,
            &mut parsed,
            &id_shell(Json::Array(vec![Json::Object(vec![
                ("conversation_id".into(), z2.clone()),
                (
                    "handshake".into(),
                    Json::Object(vec![
                        ("role".into(), Json::Number(1)),
                        ("phase".into(), Json::String("ticket-received".into())),
                        ("ticket".into(), tj.clone()),
                        ("list_from".into(), Json::Number(1)),
                    ]),
                ),
            ])]))
        )
        .is_err()
    );
    assert!(
        super::fold_tree::install_users(
            b64,
            &mut parsed,
            &id_shell(Json::Array(vec![Json::Object(vec![
                ("conversation_id".into(), z2.clone()),
                (
                    "handshake".into(),
                    Json::Object(vec![
                        ("role".into(), Json::String("invitee".into())),
                        ("phase".into(), Json::String("ticket-received".into())),
                        ("ticket".into(), tj.clone()),
                        ("list_from".into(), Json::Bool(true)),
                        ("policy".into(), Json::Number(1)),
                        (
                            "failure".into(),
                            Json::Object(vec![("reason".into(), Json::Number(1))]),
                        ),
                    ]),
                ),
            ])]))
        )
        .is_err()
    );
    let mut install_hs = |handshake: Json| {
        super::fold_tree::install_users(
            b64,
            &mut parsed,
            &id_shell(Json::Array(vec![Json::Object(vec![
                ("conversation_id".into(), z2.clone()),
                ("handshake".into(), handshake),
            ])])),
        )
    };
    let base = |phase: &str, role: &str| {
        Json::Object(vec![
            ("role".into(), Json::String(role.into())),
            ("phase".into(), Json::String(phase.into())),
            ("ticket".into(), tj.clone()),
            ("list_from".into(), Json::Number(1)),
        ])
    };
    assert!(
        install_hs(Json::Object(vec![
            ("role".into(), Json::String("invitee".into())),
            ("phase".into(), Json::Number(1)),
            ("ticket".into(), tj.clone()),
            ("list_from".into(), Json::Number(1)),
        ]))
        .is_err()
    );
    let mut policy_bad = base("ticket-received", "invitee");
    if let Json::Object(m) = &mut policy_bad {
        m.push(("policy".into(), Json::Number(1)));
    }
    assert!(install_hs(policy_bad).is_err());
    assert!(install_hs(base("nope", "invitee")).is_err());
    assert!(install_hs(base("ticket-received", "neither")).is_err());
    for failure in [
        Json::Number(1),
        Json::Object(vec![("reason".into(), Json::Number(1))]),
        Json::Object(vec![
            ("reason".into(), Json::String("PolicyNotAccepted".into())),
            ("policy".into(), Json::Number(1)),
        ]),
        Json::Object(vec![
            ("reason".into(), Json::String("InviteExpired".into())),
            ("expires".into(), Json::Bool(true)),
        ]),
        Json::Object(vec![("reason".into(), Json::String("Nope".into()))]),
    ] {
        let mut hs = base("failed", "invitee");
        if let Json::Object(m) = &mut hs {
            m.push(("failure".into(), failure));
        }
        assert!(install_hs(hs).is_err());
    }
    for extra in [
        vec![("skipped_mks", Json::Array(vec![Json::Number(1)]))],
        vec![(
            "skipped_mks",
            Json::Array(vec![Json::Object(vec![
                ("actor_id".into(), z2.clone()),
                ("mks".into(), Json::Array(vec![Json::Number(1)])),
            ])]),
        )],
        vec![(
            "skipped_mks",
            Json::Array(vec![Json::Object(vec![
                ("actor_id".into(), z2.clone()),
                (
                    "mks".into(),
                    Json::Array(vec![Json::Object(vec![
                        ("mk".into(), z2.clone()),
                        ("expires_at".into(), Json::Bool(true)),
                    ])]),
                ),
            ])]),
        )],
        vec![("last_acks", Json::Array(vec![Json::Number(1)]))],
    ] {
        assert!(
            super::fold_tree::install_users(
                b64,
                &mut parsed,
                &id_shell(Json::Array(vec![conv(extra)]))
            )
            .is_err()
        );
    }
    assert!(
        super::fold_tree::install_device(
            b64,
            &mut parsed,
            &Json::Object(vec![
                ("name".into(), Json::Null),
                (
                    "keys".into(),
                    Json::Object(vec![(
                        "id".into(),
                        super::super::codec::bstr(b64, &[1, 2, 3]),
                    )]),
                ),
                ("conversations".into(), Json::Array(Vec::new())),
            ])
        )
        .is_err()
    );
    assert!(
        super::fold_tree::install_device(
            b64,
            &mut parsed,
            &Json::Object(vec![
                ("name".into(), Json::Null),
                ("keys".into(), Json::Null),
                ("conversations".into(), Json::Array(vec![Json::Number(1)])),
            ])
        )
        .is_err()
    );
    assert!(
        super::fold_tree::install_device(
            b64,
            &mut parsed,
            &Json::Object(vec![
                ("name".into(), Json::Null),
                ("keys".into(), Json::Null),
                (
                    "conversations".into(),
                    Json::Array(vec![Json::Object(vec![
                        ("conversation_id".into(), z2.clone()),
                        ("synchronization".into(), Json::Number(1)),
                    ])]),
                ),
            ])
        )
        .is_err()
    );
}

#[test]
fn advertise_wrap_ack_and_mix() {
    use super::super::chain::{mix, mk, seal_packet};
    use super::super::payload::{ConversationSort, PacketPlain, PacketXorAck};
    use super::state::{IdentityNode, KnownShared, UnusedSk};
    use crate::protocol::v1::fixtures::suite_with_kem;
    use crate::protocol::v1::kem::Kem;
    use crate::protocol::v1::{ActorId, KemError, PacketEpoch, PacketSeq, Tag};
    use std::collections::BTreeSet;
    use std::sync::Arc;

    struct BoomKem;
    impl Kem for BoomKem {
        fn generate(
            &self,
            _policy: Policy,
            _seed: &crate::protocol::v1::KemSeed,
        ) -> Result<crate::protocol::v1::KeyPair, KemError> {
            Err(KemError::KeyGen)
        }
        fn wrap(
            &self,
            _policy: Policy,
            _pk: &[u8],
            _seed: &crate::protocol::v1::KemSeed,
        ) -> Result<(Vec<u8>, Vec<u8>), KemError> {
            Err(KemError::Wrap)
        }
        fn unwrap(&self, _policy: Policy, _sk: &[u8], _ct: &[u8]) -> Result<Vec<u8>, KemError> {
            Err(KemError::Wrap)
        }
    }
    struct ShortWrap;
    impl Kem for ShortWrap {
        fn generate(
            &self,
            policy: Policy,
            seed: &crate::protocol::v1::KemSeed,
        ) -> Result<crate::protocol::v1::KeyPair, KemError> {
            crate::protocol::v1::fixtures::EchoKem.generate(policy, seed)
        }
        fn wrap(
            &self,
            _policy: Policy,
            _pk: &[u8],
            _seed: &crate::protocol::v1::KemSeed,
        ) -> Result<(Vec<u8>, Vec<u8>), KemError> {
            Ok((vec![1], vec![1; 32]))
        }
        fn unwrap(&self, policy: Policy, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>, KemError> {
            crate::protocol::v1::fixtures::EchoKem.unwrap(policy, sk, ct)
        }
    }

    let _ = BoomKem.unwrap(Policy::Classic, &[], &[]);
    let _ = ShortWrap.wrap(
        Policy::Classic,
        &[],
        &crate::protocol::v1::KemSeed::from_bytes([1; 64]),
    );
    let _ = ShortWrap.unwrap(Policy::Classic, &[], &[1; 32]);

    let mut engine = test_engine();
    let rng = CounterRng::new();
    engine
        .wrap_dek(&rng, &UnlockSecret::Passphrase("passpass".into()))
        .expect("wrap");
    let ticked = engine
        .tick(EngineState::new(), 1_700_000_000)
        .expect("tick");
    let (created, uid) = engine.create_user(ticked.state, &rng).expect("user");
    let (created, iid) = engine
        .create_identity(created.state, &rng, uid, Policy::Classic)
        .expect("id");
    let (invited, cid) = engine
        .create_invite(created.state, &rng, uid, iid, 1_800_000_000, None)
        .expect("inv");
    let notice_tx = *invited
        .state
        .txs
        .iter()
        .find(|(_, body)| matches!(body.payload, TxPayload::Notice(_)))
        .expect("notice")
        .0;
    let secret = invited.state.ticket(cid).expect("ticket").secret;
    let poll = engine.poll(&invited.state).expect("poll");
    let channel = poll.write_durable[0].channel.clone();
    let tag = poll.write_durable[0].tag;

    let mut owed = invited.state.clone();
    owed.chains_mut(cid).expect("chains").ratchet.since = 50;
    engine
        .post_handshake_packets(&mut owed, &rng, cid, &secret, notice_tx)
        .expect("adv");
    assert!(
        owed.txs
            .values()
            .any(|body| matches!(body.payload, TxPayload::Advertise { .. }))
    );
    assert_eq!(owed.chains(cid).expect("c").ratchet.unused.len(), 1);
    assert!(owed.chains(cid).expect("c").ratchet.since < 50);

    let mut full = owed.clone();
    {
        let chains = full.chains_mut(cid).expect("chains");
        chains.ratchet.unused.clear();
        for i in 0..8u8 {
            let id = Tag::from_bytes([i; 32]);
            chains.ratchet.minted.insert(id);
            chains.ratchet.unused.push(UnusedSk {
                tx_id: id,
                pk: vec![i],
                sk: vec![i],
            });
        }
        chains.ratchet.since = 50;
    }
    engine
        .post_handshake_packets(&mut full, &rng, cid, &secret, notice_tx)
        .expect("drop");
    let unused = &full.chains(cid).expect("c").ratchet.unused;
    assert_eq!(unused.len(), 8);
    assert!(unused.iter().all(|sk| sk.tx_id != Tag::from_bytes([0; 32])));

    let mut acks = invited.state.clone();
    let peer_pk = vec![7u8; 32];
    let ad_tx = Tag::from_bytes([0x51; 32]);
    acks.txs.insert(
        ad_tx,
        DurableBody {
            conversation_id: cid,
            hlc: Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: TxPayload::Advertise {
                encaps_pk: peer_pk.clone(),
            },
        },
    );
    acks.chains_mut(cid).expect("c").ratchet.since = 50;
    engine
        .post_handshake_packets(&mut acks, &rng, cid, &secret, notice_tx)
        .expect("ackad");
    let pk_hash = Tag::from_bytes(engine.suite.hash().hash(&peer_pk));
    assert!(acks.txs.values().any(|body| matches!(
        &body.payload,
        TxPayload::Ack { ratchet_ack } if *ratchet_ack == pk_hash
    )));
    acks.chains_mut(cid).expect("c").ratchet.since = 50;
    engine
        .post_handshake_packets(&mut acks, &rng, cid, &secret, notice_tx)
        .expect("wrap");
    assert!(
        acks.chains(cid)
            .expect("c")
            .ratchet
            .known
            .iter()
            .any(|row| row.from_us && row.encaps_pk == peer_pk)
    );

    let mut peer_wrap = invited.state.clone();
    let sk_tx = Tag::from_bytes([0x41; 32]);
    {
        let chains = peer_wrap.chains_mut(cid).expect("c");
        chains.ratchet.minted.insert(sk_tx);
        chains.ratchet.unused.push(UnusedSk {
            tx_id: sk_tx,
            pk: vec![9; 32],
            sk: vec![9; 32],
        });
        chains.ratchet.known.push(KnownShared {
            wrap_tx: Tag::from_bytes([0x39; 32]),
            shared: Secret::from_bytes([1; 32]),
            ct_hash: Tag::from_bytes([0x38; 32]),
            from_us: true,
            encaps_pk: vec![1; 32],
        });
        chains.ratchet.since = 50;
    }
    let ct = vec![3u8; 32];
    peer_wrap.txs.insert(
        Tag::from_bytes([0x50; 32]),
        DurableBody {
            conversation_id: cid,
            hlc: Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: TxPayload::Wrap { kem_ct: ct },
        },
    );
    peer_wrap.txs.insert(
        Tag::from_bytes([0x43; 32]),
        DurableBody {
            conversation_id: cid,
            hlc: Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: TxPayload::Wrap { kem_ct: vec![1] },
        },
    );
    let mut reject = vec![0u8; 32];
    reject[0] = 0xee;
    reject[1] = 0xfd;
    peer_wrap.txs.insert(
        Tag::from_bytes([0x30; 32]),
        DurableBody {
            conversation_id: cid,
            hlc: Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: TxPayload::Wrap { kem_ct: reject },
        },
    );
    let mut short_ss = vec![0u8; 32];
    short_ss[0] = 0xee;
    short_ss[1] = 0xfe;
    peer_wrap.txs.insert(
        Tag::from_bytes([0x31; 32]),
        DurableBody {
            conversation_id: cid,
            hlc: Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: TxPayload::Wrap { kem_ct: short_ss },
        },
    );
    engine
        .post_handshake_packets(&mut peer_wrap, &rng, cid, &secret, notice_tx)
        .expect("ackwrap");
    assert!(
        peer_wrap
            .chains(cid)
            .expect("c")
            .ratchet
            .known
            .iter()
            .any(|row| !row.from_us)
    );
    assert!(
        peer_wrap
            .txs
            .values()
            .any(|body| matches!(body.payload, TxPayload::Ack { .. }))
    );
    let mut skipped_ack = invited.state.clone();
    let wrap_a = Tag::from_bytes([0x21; 32]);
    let wrap_b = Tag::from_bytes([0x22; 32]);
    let ack_a = Tag::from_bytes([0x23; 32]);
    let hash_a = Tag::from_bytes([0x24; 32]);
    let hash_b = Tag::from_bytes([0x25; 32]);
    {
        let chains = skipped_ack.chains_mut(cid).expect("c");
        chains.ratchet.known.push(KnownShared {
            wrap_tx: wrap_a,
            shared: Secret::from_bytes([2; 32]),
            ct_hash: hash_a,
            from_us: false,
            encaps_pk: Vec::new(),
        });
        chains.ratchet.known.push(KnownShared {
            wrap_tx: wrap_b,
            shared: Secret::from_bytes([3; 32]),
            ct_hash: hash_b,
            from_us: false,
            encaps_pk: Vec::new(),
        });
        chains.ratchet.since = 50;
        chains.last_acks.insert(
            ActorId::handshake(),
            BTreeSet::from([wrap_a, wrap_b, ack_a]),
        );
    }
    for (id, payload) in [
        (
            wrap_a,
            TxPayload::Wrap {
                kem_ct: vec![2; 32],
            },
        ),
        (
            wrap_b,
            TxPayload::Wrap {
                kem_ct: vec![3; 32],
            },
        ),
        (
            ack_a,
            TxPayload::Ack {
                ratchet_ack: hash_a,
            },
        ),
        (
            Tag::from_bytes([0x26; 32]),
            TxPayload::Ack {
                ratchet_ack: hash_b,
            },
        ),
    ] {
        skipped_ack.txs.insert(
            id,
            DurableBody {
                conversation_id: cid,
                hlc: Hlc {
                    wall_ms: 0,
                    counter: 0,
                },
                payload,
            },
        );
    }
    engine
        .post_handshake_packets(&mut skipped_ack, &rng, cid, &secret, notice_tx)
        .expect("skipack");

    let mut quiet = invited.state.clone();
    quiet.txs.get_mut(&notice_tx).expect("n").payload = TxPayload::Confirm;
    quiet.chains_mut(cid).expect("c").ratchet.since = 50;
    engine
        .post_handshake_packets(&mut quiet, &rng, cid, &secret, notice_tx)
        .expect("identity-policy");
    assert!(
        quiet
            .txs
            .values()
            .any(|body| matches!(body.payload, TxPayload::Advertise { .. }))
    );
    let child = ConversationId::from_bytes([8; 32]);
    quiet.put_dm(
        uid,
        iid,
        child,
        IdentityNode::direct(Secret::from_bytes([1; 32]), cid),
    );
    let sync_child = ConversationId::from_bytes([3; 32]);
    quiet.put_sync(
        sync_child,
        super::state::DeviceNode::sync(Secret::from_bytes([2; 32]), cid),
    );
    assert_eq!(quiet.established_parent(sync_child), Some(cid));
    let _ = format!("{:?}", quiet.chains(cid).expect("c").ratchet);
    assert_eq!(
        super::ratchet::conversation_policy(&quiet, ConversationId::from_bytes([9; 32])),
        None
    );
    assert_eq!(
        super::ratchet::conversation_policy(&quiet, child),
        Some(Policy::Classic)
    );
    let sync_cid = ConversationId::from_bytes([4; 32]);
    let ticket = quiet.ticket(cid).expect("t").clone();
    quiet.put_sync_invitee(
        sync_cid,
        super::party::InviteePhase::TicketReceived {
            ticket: ticket.clone(),
            list_from: crate::protocol::v1::TimeBin::from_u64(1),
        },
    );
    assert!(super::ratchet::conversation_policy(&quiet, sync_cid).is_none());
    let sync_tx = Tag::from_bytes([0x11; 32]);
    quiet.txs.insert(
        sync_tx,
        DurableBody {
            conversation_id: sync_cid,
            hlc: Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: TxPayload::Confirm,
        },
    );
    quiet.chains_mut(sync_cid).expect("sc").ratchet.since = 50;
    let sync_len = quiet.txs.len();
    engine
        .post_handshake_packets(&mut quiet, &rng, sync_cid, &ticket.secret, sync_tx)
        .expect("sync-none");
    assert_eq!(quiet.txs.len(), sync_len);
    let notice = invited
        .state
        .txs
        .get(&notice_tx)
        .expect("orig")
        .payload
        .clone();
    quiet.txs.get_mut(&notice_tx).expect("n").payload = notice;
    assert_eq!(
        super::ratchet::conversation_policy(&quiet, child),
        Some(Policy::Classic)
    );

    let mut hidden = invited.state.clone();
    hidden.txs.insert(
        Tag::from_bytes([0x52; 32]),
        DurableBody {
            conversation_id: cid,
            hlc: Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: TxPayload::Advertise {
                encaps_pk: vec![4; 32],
            },
        },
    );
    hidden
        .chains_mut(cid)
        .expect("c")
        .last_acks
        .insert(ActorId::handshake(), BTreeSet::from([notice_tx]));
    hidden.chains_mut(cid).expect("c").ratchet.since = 50;
    let ads_before = hidden
        .txs
        .values()
        .filter(|body| matches!(body.payload, TxPayload::Advertise { .. }))
        .count();
    engine
        .post_handshake_packets(&mut hidden, &rng, cid, &secret, notice_tx)
        .expect("hidden");
    let ads_after = hidden
        .txs
        .values()
        .filter(|body| matches!(body.payload, TxPayload::Advertise { .. }))
        .count();
    assert!(ads_after > ads_before);
    assert!(hidden.chains(cid).expect("c").ratchet.known.is_empty());

    let mut mix_state = invited.state.clone();
    {
        let chains = mix_state.chains_mut(cid).expect("c");
        let mut chain = chains
            .send
            .get(&ActorId::handshake())
            .expect("send")
            .clone();
        chain.packet_seq = PacketSeq::from_u64(8);
        chains.send.insert(ActorId::handshake(), chain);
        for i in 0..8u8 {
            chains.ratchet.known.push(KnownShared {
                wrap_tx: Tag::from_bytes([0x60 + i; 32]),
                shared: Secret::from_bytes([i; 32]),
                ct_hash: Tag::from_bytes([0x70 + i; 32]),
                from_us: true,
                encaps_pk: Vec::new(),
            });
        }
    }
    for i in 0..8u8 {
        let wrap_tx = Tag::from_bytes([0x60 + i; 32]);
        let ct_hash = Tag::from_bytes([0x70 + i; 32]);
        mix_state.txs.insert(
            wrap_tx,
            DurableBody {
                conversation_id: cid,
                hlc: Hlc {
                    wall_ms: 0,
                    counter: 0,
                },
                payload: TxPayload::Wrap {
                    kem_ct: vec![i; 32],
                },
            },
        );
        mix_state.txs.insert(
            Tag::from_bytes([0x80 + i; 32]),
            DurableBody {
                conversation_id: cid,
                hlc: Hlc {
                    wall_ms: 0,
                    counter: 0,
                },
                payload: TxPayload::Ack {
                    ratchet_ack: ct_hash,
                },
            },
        );
    }
    engine
        .post_handshake_packets(&mut mix_state, &rng, cid, &secret, notice_tx)
        .expect("mix");
    let mixed_chain = mix_state
        .chains(cid)
        .expect("c")
        .send
        .get(&ActorId::handshake())
        .expect("send")
        .clone();
    assert_eq!(mixed_chain.epoch, PacketEpoch::from_u64(1));

    let mut few = invited.state.clone();
    {
        let chains = few.chains_mut(cid).expect("c");
        let mut chain = chains
            .send
            .get(&ActorId::handshake())
            .expect("send")
            .clone();
        chain.packet_seq = PacketSeq::from_u64(8);
        chains.send.insert(ActorId::handshake(), chain);
        chains.ratchet.known.push(KnownShared {
            wrap_tx: Tag::from_bytes([0x91; 32]),
            shared: Secret::from_bytes([9; 32]),
            ct_hash: Tag::from_bytes([0x92; 32]),
            from_us: true,
            encaps_pk: Vec::new(),
        });
    }
    few.txs.insert(
        Tag::from_bytes([0x91; 32]),
        DurableBody {
            conversation_id: cid,
            hlc: Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: TxPayload::Wrap {
                kem_ct: vec![9; 32],
            },
        },
    );
    few.txs.insert(
        Tag::from_bytes([0x93; 32]),
        DurableBody {
            conversation_id: cid,
            hlc: Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: TxPayload::Ack {
                ratchet_ack: Tag::from_bytes([0x92; 32]),
            },
        },
    );
    engine
        .post_handshake_packets(&mut few, &rng, cid, &secret, notice_tx)
        .expect("nomix");
    assert_eq!(
        few.chains(cid)
            .expect("c")
            .send
            .get(&ActorId::handshake())
            .expect("send")
            .epoch,
        PacketEpoch::from_u64(0)
    );

    let mut recv_state = invited.state.clone();
    let start = {
        let chains = recv_state.chains_mut(cid).expect("c");
        let mut chain = chains
            .send
            .get(&ActorId::handshake())
            .expect("send")
            .clone();
        chain.packet_seq = PacketSeq::from_u64(8);
        chains.recv.insert(ActorId::handshake(), chain.clone());
        for i in 0..8u8 {
            let wrap_tx = Tag::from_bytes([0x60 + i; 32]);
            let ct_hash = Tag::from_bytes([0x70 + i; 32]);
            chains.ratchet.known.push(KnownShared {
                wrap_tx,
                shared: Secret::from_bytes([i; 32]),
                ct_hash,
                from_us: false,
                encaps_pk: Vec::new(),
            });
        }
        chain
    };
    for i in 0..8u8 {
        let wrap_tx = Tag::from_bytes([0x60 + i; 32]);
        let ct_hash = Tag::from_bytes([0x70 + i; 32]);
        recv_state.txs.insert(
            wrap_tx,
            DurableBody {
                conversation_id: cid,
                hlc: Hlc {
                    wall_ms: 0,
                    counter: 0,
                },
                payload: TxPayload::Wrap {
                    kem_ct: vec![i; 32],
                },
            },
        );
        recv_state.txs.insert(
            Tag::from_bytes([0xa0 + i; 32]),
            DurableBody {
                conversation_id: cid,
                hlc: Hlc {
                    wall_ms: 0,
                    counter: 0,
                },
                payload: TxPayload::Ack {
                    ratchet_ack: ct_hash,
                },
            },
        );
    }
    let mixed = mix(
        engine.suite.hmac(),
        &start,
        ConversationSort::HandshakeDm,
        &[0; 32],
    )
    .expect("mx");
    let body = seal_packet(
        &engine.suite,
        &rng,
        &mk(engine.suite.hmac(), &mixed),
        &PacketPlain::XorAck(PacketXorAck {
            actor_id: Vec::new(),
            packet_seq: 0,
            set_xor: Tag::from_bytes([3; 32]),
        }),
    )
    .expect("seal");
    let opened = engine
        .ingest_packet(recv_state, &rng, channel, tag, &body)
        .expect("recv-mix");
    assert_eq!(
        opened
            .state
            .chains(cid)
            .expect("c")
            .recv
            .get(&ActorId::handshake())
            .expect("recv")
            .epoch,
        PacketEpoch::from_u64(1)
    );

    let mut folded = invited.state.clone();
    {
        let chains = folded.chains_mut(cid).expect("c");
        chains.ratchet.since = 4;
        let id = Tag::from_bytes([1; 32]);
        chains.ratchet.minted.insert(id);
        chains.ratchet.unused.push(UnusedSk {
            tx_id: id,
            pk: vec![1],
            sk: vec![2],
        });
        chains.ratchet.known.push(KnownShared {
            wrap_tx: Tag::from_bytes([2; 32]),
            shared: Secret::from_bytes([3; 32]),
            ct_hash: Tag::from_bytes([4; 32]),
            from_us: true,
            encaps_pk: vec![5],
        });
        chains.skipped_mks.insert(
            ActorId::handshake(),
            vec![super::super::chain::CachedMk {
                mk: [6; 32],
                expires_at: UnixSeconds::from_u64(9),
                tx_id: None,
            }],
        );
    }
    folded.cover_last_acks();
    let snap = engine.fold(folded).expect("fold");
    let back = engine.apply_folded(&snap.snapshot).expect("apply");
    assert_eq!(back.chains(cid).expect("c").ratchet.since, 4);
    assert_eq!(back.chains(cid).expect("c").ratchet.unused.len(), 1);
    assert_eq!(back.chains(cid).expect("c").ratchet.known.len(), 1);
    let bare = super::super::chain::join(
        engine.suite.hmac(),
        secret.as_bytes(),
        ConversationSort::HandshakeDm,
        &[],
    )
    .expect("bare");
    let mut late = bare.clone();
    late.packet_seq = PacketSeq::from_u64(8);
    assert!(
        engine
            .mixed_chain(
                &EngineState::new(),
                cid,
                ConversationSort::HandshakeDm,
                &late,
                true
            )
            .is_none()
    );

    let mut boom = Engine::new(suite_with_kem(Arc::new(BoomKem)), engine.defaults().clone());
    boom.wrap_dek(&rng, &UnlockSecret::Passphrase("passpass".into()))
        .expect("bwrap");
    let mut boom_state = invited.state.clone();
    let peer = vec![6u8; 32];
    let peer_hash = Tag::from_bytes(engine.suite.hash().hash(&peer));
    boom_state.txs.insert(
        Tag::from_bytes([0x55; 32]),
        DurableBody {
            conversation_id: cid,
            hlc: Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: TxPayload::Advertise { encaps_pk: peer },
        },
    );
    boom_state.txs.insert(
        Tag::from_bytes([0x56; 32]),
        DurableBody {
            conversation_id: cid,
            hlc: Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: TxPayload::Ack {
                ratchet_ack: peer_hash,
            },
        },
    );
    boom_state.chains_mut(cid).expect("c").ratchet.since = 50;
    let boom_len = boom_state.txs.len();
    boom.post_handshake_packets(&mut boom_state, &rng, cid, &secret, notice_tx)
        .expect("boom");
    assert_eq!(boom_state.txs.len(), boom_len);

    let mut short = Engine::new(
        suite_with_kem(Arc::new(ShortWrap)),
        engine.defaults().clone(),
    );
    short
        .wrap_dek(&rng, &UnlockSecret::Passphrase("passpass".into()))
        .expect("swrap");
    let mut short_state = invited.state.clone();
    let old_pk = vec![8u8; 32];
    let new_pk = vec![9u8; 32];
    short_state
        .chains_mut(cid)
        .expect("c")
        .ratchet
        .known
        .push(KnownShared {
            wrap_tx: Tag::from_bytes([0x59; 32]),
            shared: Secret::from_bytes([8; 32]),
            ct_hash: Tag::from_bytes([0x5a; 32]),
            from_us: true,
            encaps_pk: old_pk.clone(),
        });
    short_state.txs.insert(
        Tag::from_bytes([0x57; 32]),
        DurableBody {
            conversation_id: cid,
            hlc: Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: TxPayload::Advertise { encaps_pk: old_pk },
        },
    );
    short_state.txs.insert(
        Tag::from_bytes([0x58; 32]),
        DurableBody {
            conversation_id: cid,
            hlc: Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: TxPayload::Ack {
                ratchet_ack: Tag::from_bytes(engine.suite.hash().hash(&[8u8; 32])),
            },
        },
    );
    short_state.txs.insert(
        Tag::from_bytes([0x5b; 32]),
        DurableBody {
            conversation_id: cid,
            hlc: Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: TxPayload::Advertise {
                encaps_pk: new_pk.clone(),
            },
        },
    );
    short_state.txs.insert(
        Tag::from_bytes([0x5c; 32]),
        DurableBody {
            conversation_id: cid,
            hlc: Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: TxPayload::Ack {
                ratchet_ack: Tag::from_bytes(engine.suite.hash().hash(&new_pk)),
            },
        },
    );
    short_state.chains_mut(cid).expect("c").ratchet.since = 50;
    let unused_before = short_state.chains(cid).expect("c").ratchet.unused.len();
    short
        .post_handshake_packets(&mut short_state, &rng, cid, &secret, notice_tx)
        .expect("short");
    assert!(short_state.chains(cid).expect("c").ratchet.unused.len() > unused_before);

    let b64 = engine.suite.b64u();
    let z = super::super::codec::bstr(b64, &[0u8; 32]);
    let mut parsed = EngineState::new();
    let dm = |ratchet: Json| {
        Json::Array(vec![Json::Object(vec![
            ("user_id".into(), z.clone()),
            (
                "identities".into(),
                Json::Array(vec![Json::Object(vec![
                    ("identity_id".into(), z.clone()),
                    ("name".into(), Json::Null),
                    ("pic".into(), Json::Null),
                    (
                        "conversations".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("conversation_id".into(), z.clone()),
                            (
                                "direct_message".into(),
                                Json::Object(vec![
                                    ("secret".into(), z.clone()),
                                    ("parent".into(), z.clone()),
                                ]),
                            ),
                            ("ratchet".into(), ratchet),
                        ])]),
                    ),
                ])]),
            ),
        ])])
    };
    for ratchet in [
        Json::Number(1),
        Json::Object(vec![("since".into(), Json::Bool(true))]),
        Json::Object(vec![
            ("since".into(), Json::Number(1)),
            ("minted".into(), Json::Number(1)),
        ]),
        Json::Object(vec![
            ("since".into(), Json::Number(1)),
            ("minted".into(), Json::Array(vec![Json::Number(1)])),
        ]),
        Json::Object(vec![
            ("since".into(), Json::Number(1)),
            ("minted".into(), Json::Array(Vec::new())),
            ("unused".into(), Json::Number(1)),
        ]),
        Json::Object(vec![
            ("since".into(), Json::Number(1)),
            ("minted".into(), Json::Array(Vec::new())),
            ("unused".into(), Json::Array(vec![Json::Number(1)])),
        ]),
        Json::Object(vec![
            ("since".into(), Json::Number(1)),
            ("minted".into(), Json::Array(Vec::new())),
            ("unused".into(), Json::Array(vec![Json::Object(vec![])])),
        ]),
        Json::Object(vec![
            ("since".into(), Json::Number(1)),
            ("minted".into(), Json::Array(Vec::new())),
            ("unused".into(), Json::Array(Vec::new())),
            ("known".into(), Json::Number(1)),
        ]),
        Json::Object(vec![
            ("since".into(), Json::Number(1)),
            ("minted".into(), Json::Array(Vec::new())),
            ("unused".into(), Json::Array(Vec::new())),
            ("known".into(), Json::Array(vec![Json::Number(1)])),
        ]),
        Json::Object(vec![
            ("since".into(), Json::Number(1)),
            ("minted".into(), Json::Array(Vec::new())),
            ("unused".into(), Json::Array(Vec::new())),
            (
                "known".into(),
                Json::Array(vec![Json::Object(vec![(
                    "from_us".into(),
                    Json::Number(1),
                )])]),
            ),
        ]),
    ] {
        assert!(super::fold_tree::install_users(b64, &mut parsed, &dm(ratchet)).is_err());
    }
    struct HugeCompress;
    impl crate::protocol::v1::Compress for HugeCompress {
        fn compress(&self, _data: &[u8]) -> Vec<u8> {
            vec![0; 10_000]
        }
        fn decompress(
            &self,
            data: &[u8],
            _limit: usize,
        ) -> Result<Vec<u8>, crate::protocol::v1::CompressError> {
            Ok(data.to_vec())
        }
    }
    let _ = crate::protocol::v1::Compress::decompress(&HugeCompress, &[1, 2], 8).expect("dec");
    let mut huge = Engine::new(
        crate::protocol::v1::Suite::new(
            Arc::new(crate::protocol::v1::fixtures::XorHmac),
            Arc::new(HugeCompress),
            Arc::new(crate::protocol::v1::fixtures::HexB64),
            Arc::new(crate::protocol::v1::fixtures::XorAead),
            Arc::new(crate::protocol::v1::fixtures::DetJson),
            Arc::new(crate::protocol::v1::fixtures::EchoKem),
            Arc::new(crate::protocol::v1::fixtures::EchoSign),
            Arc::new(crate::protocol::v1::fixtures::XorHash),
            Arc::new(crate::protocol::v1::fixtures::EchoArgon),
        ),
        engine.defaults().clone(),
    );
    huge.wrap_dek(&rng, &UnlockSecret::Passphrase("passpass".into()))
        .expect("hwrap");
    let mut huge_state = invited.state.clone();
    huge_state.chains_mut(cid).expect("c").ratchet.since = 50;
    assert_eq!(
        huge.post_handshake_packets(&mut huge_state, &rng, cid, &secret, notice_tx)
            .unwrap_err(),
        EngineError::BodyTooLarge
    );
}

#[test]
fn heal_searches_then_retransmits_and_falls_back() {
    use super::super::chain::{eph_mk, mk, open_skip_ahead, seal_packet};
    use super::super::payload::{ConversationSort, PacketPlain, PacketXorAck};
    use crate::protocol::v1::fixtures::sample_durable;
    use crate::protocol::v1::{
        ActorId, Address, Defaults, EphemeralChannel, Kind, NotificationPrivacy, Tag,
    };

    let mut engine = test_engine();
    let rng = CounterRng::new();
    engine
        .wrap_dek(&rng, &UnlockSecret::Passphrase("passpass".into()))
        .expect("wrap");
    let now = 1_700_000_000u64;
    let ticked = engine.tick(EngineState::new(), now).expect("tick");
    let (created, uid) = engine.create_user(ticked.state, &rng).expect("user");
    let (created, iid) = engine
        .create_identity(created.state, &rng, uid, Policy::Classic)
        .expect("id");
    let (invited, cid) = engine
        .create_invite(created.state, &rng, uid, iid, 1_800_000_000, None)
        .expect("inv");
    let ids = ConversationRef {
        user_id: uid,
        identity_id: iid,
        conversation_id: cid,
    };
    let ticket_s = engine
        .ticket_host_string(&invited.state, &ids)
        .expect("ticket");
    let poll = engine.poll(&invited.state).expect("poll");
    let channel = poll.write_durable[0].channel.clone();
    let tag = poll.write_durable[0].tag;
    let bodies: Vec<_> = poll.write_durable.iter().map(|w| w.body.clone()).collect();
    let ie = engine.tick(EngineState::new(), now).expect("ie").state;
    let (ie_u, ie_uid) = engine.create_user(ie, &rng).expect("ieu");
    let (ie_i, ie_iid) = engine
        .create_identity(ie_u.state, &rng, ie_uid, Policy::Classic)
        .expect("iei");
    let (recv, _) = engine
        .receive_ticket(ie_i.state, &rng, ie_uid, ie_iid, &ticket_s)
        .expect("recv");
    let mut bob = engine
        .ingest_list(recv.state, &rng, channel.clone(), tag, &bodies)
        .expect("ing")
        .state;
    let mut ada = invited.state.clone();
    let extra = Tag::from_bytes([0xab; 32]);
    ada.txs.insert(
        extra,
        DurableBody {
            conversation_id: cid,
            hlc: Hlc {
                wall_ms: 1,
                counter: 0,
            },
            payload: TxPayload::Confirm,
        },
    );
    let chain = ada
        .chains(cid)
        .expect("c")
        .send
        .get(&ActorId::handshake())
        .expect("send")
        .clone();
    let remote = super::super::chain::set_xor_for(&ada.txs, cid);
    let mismatch = seal_packet(
        &engine.suite,
        &rng,
        &mk(engine.suite.hmac(), &chain),
        &PacketPlain::XorAck(PacketXorAck {
            actor_id: Vec::new(),
            packet_seq: chain.packet_seq.as_u64(),
            set_xor: remote,
        }),
    )
    .expect("seal");
    let before = bob.writes.len();
    bob = engine
        .ingest_packet(bob, &rng, channel.clone(), tag, &mismatch)
        .expect("mismatch")
        .state;
    assert!(bob.writes.len() > before);
    assert!(bob.chains(cid).expect("c").heal.probes.len() == 1);
    let mut next_bob = before;
    let mut guard = 0;
    while !bob.txs.contains_key(&extra) && guard < 400 {
        guard += 1;
        let batch: Vec<_> = bob.writes[next_bob..]
            .iter()
            .map(|w| w.body.clone())
            .collect();
        next_bob = bob.writes.len();
        let mark = ada.writes.len();
        for body in &batch {
            ada = engine
                .ingest_packet(ada, &rng, channel.clone(), tag, body)
                .expect("to-ada")
                .state;
        }
        let reply: Vec<_> = ada.writes[mark..].iter().map(|w| w.body.clone()).collect();
        for body in &reply {
            bob = engine
                .ingest_packet(bob, &rng, channel.clone(), tag, body)
                .expect("to-bob")
                .state;
        }
    }
    assert!(bob.txs.contains_key(&extra), "rounds {guard}");
    assert!(bob.chains(cid).expect("c").heal.probes.is_empty());

    let eph = EphemeralChannel::new(
        Kind::try_from("webrtc").expect("k"),
        Address::try_from("https://eph.example").expect("a"),
    );
    let defaults = Defaults::try_new(
        vec![sample_durable()],
        vec![eph.clone()],
        true,
        true,
        true,
        None,
        false,
        NotificationPrivacy::Name,
    )
    .expect("def");
    let mut live_engine = Engine::new(engine.suite.clone(), defaults);
    live_engine
        .wrap_dek(&rng, &UnlockSecret::Passphrase("passpass".into()))
        .expect("lw");
    let ticked = live_engine.tick(EngineState::new(), now).expect("lt");
    let (created, uid) = live_engine.create_user(ticked.state, &rng).expect("lu");
    let (created, iid) = live_engine
        .create_identity(created.state, &rng, uid, Policy::Classic)
        .expect("li");
    let (invited, cid) = live_engine
        .create_invite(created.state, &rng, uid, iid, 1_800_000_000, None)
        .expect("linv");
    let ids = ConversationRef {
        user_id: uid,
        identity_id: iid,
        conversation_id: cid,
    };
    let ticket_s = live_engine
        .ticket_host_string(&invited.state, &ids)
        .expect("lticket");
    let poll = live_engine.poll(&invited.state).expect("lp");
    let channel = poll.write_durable[0].channel.clone();
    let tag = poll.write_durable[0].tag;
    let bodies: Vec<_> = poll.write_durable.iter().map(|w| w.body.clone()).collect();
    let ie = live_engine
        .tick(EngineState::new(), now)
        .expect("lie")
        .state;
    let (ie_u, ie_uid) = live_engine.create_user(ie, &rng).expect("lieu");
    let (ie_i, ie_iid) = live_engine
        .create_identity(ie_u.state, &rng, ie_uid, Policy::Classic)
        .expect("liei");
    let (recv, _) = live_engine
        .receive_ticket(ie_i.state, &rng, ie_uid, ie_iid, &ticket_s)
        .expect("lrecv");
    let mut bob = live_engine
        .ingest_list(recv.state, &rng, channel.clone(), tag, &bodies)
        .expect("ling")
        .state;
    let ada = invited.state;
    let chain = ada
        .chains(cid)
        .expect("lc")
        .send
        .get(&ActorId::handshake())
        .expect("lsend")
        .clone();
    let matched = super::super::chain::set_xor_for(&ada.txs, cid);
    let live_ack = seal_packet(
        &live_engine.suite,
        &rng,
        &eph_mk(live_engine.suite.hmac(), &chain),
        &PacketPlain::XorAck(PacketXorAck {
            actor_id: Vec::new(),
            packet_seq: chain.packet_seq.as_u64(),
            set_xor: matched,
        }),
    )
    .expect("lseal");
    bob = live_engine
        .ingest_ephemeral_packet(bob, &rng, eph.clone(), tag, &live_ack)
        .expect("live")
        .state;
    assert!(bob.chains(cid).expect("c").live_until.is_some());
    let mut ada = ada;
    ada.txs.insert(
        Tag::from_bytes([0xcd; 32]),
        DurableBody {
            conversation_id: cid,
            hlc: Hlc {
                wall_ms: 2,
                counter: 0,
            },
            payload: TxPayload::Reject,
        },
    );
    let mismatched = super::super::chain::set_xor_for(&ada.txs, cid);
    let probe = seal_packet(
        &live_engine.suite,
        &rng,
        &eph_mk(live_engine.suite.hmac(), &chain),
        &PacketPlain::XorAck(PacketXorAck {
            actor_id: Vec::new(),
            packet_seq: chain.packet_seq.as_u64(),
            set_xor: mismatched,
        }),
    )
    .expect("pseal");
    let durable_before = bob.writes.len();
    bob = live_engine
        .ingest_ephemeral_packet(bob, &rng, eph.clone(), tag, &probe)
        .expect("probe")
        .state;
    assert!(!bob.eph_writes.is_empty());
    assert_eq!(bob.writes.len(), durable_before);
    let early = live_engine.tick(bob.clone(), now + 2).expect("early").state;
    assert_eq!(early.writes.len(), durable_before);
    let later = live_engine.tick(early, now + 3).expect("later").state;
    assert!(later.writes.len() > durable_before);
    let origin = super::super::chain::join(
        live_engine.suite.hmac(),
        ada.ticket(cid).expect("t").secret.as_bytes(),
        ConversationSort::HandshakeDm,
        &[],
    )
    .expect("origin");
    let opened = open_skip_ahead(
        &live_engine.suite,
        &origin,
        &[],
        now,
        &later.writes[durable_before].body,
    );
    assert!(opened.is_ok());
    let stale = PacketPlain::HealWant(super::super::payload::PacketHealWant {
        actor_id: Vec::new(),
        packet_seq: 0,
        lo: Tag::from_bytes([0; 32]),
        hi: Tag::from_bytes([0xff; 32]),
        ids: vec![Tag::from_bytes([1; 32]); 33],
    });
    live_engine
        .on_heal_packet(&mut bob, &rng, cid, &stale)
        .expect("ignore");
    let typing = PacketPlain::Typing(super::super::payload::PacketTyping {
        actor_id: Vec::new(),
        packet_seq: 0,
        conversation_id: cid,
        composing: true,
    });
    let typed = seal_packet(
        &live_engine.suite,
        &rng,
        &eph_mk(live_engine.suite.hmac(), &chain),
        &typing,
    )
    .expect("type");
    bob = live_engine
        .ingest_ephemeral_packet(bob, &rng, eph.clone(), tag, &typed)
        .expect("typed")
        .state;
    let lone = Tag::from_bytes([0x11; 32]);
    let mut hi = *lone.as_bytes();
    hi[31] = hi[31].wrapping_add(1);
    let half = PacketPlain::HealHalfXor(super::super::payload::PacketHealHalfXor {
        actor_id: Vec::new(),
        packet_seq: 0,
        lo: lone,
        hi: Tag::from_bytes(hi),
        xor: lone,
    });
    live_engine
        .on_heal_packet(&mut bob, &rng, cid, &half)
        .expect("want-one");
    let empty = PacketPlain::HealHalfXor(super::super::payload::PacketHealHalfXor {
        actor_id: Vec::new(),
        packet_seq: 0,
        lo: Tag::from_bytes([0x22; 32]),
        hi: Tag::from_bytes([0x22; 32]),
        xor: Tag::from_bytes([1; 32]),
    });
    live_engine
        .on_heal_packet(&mut bob, &rng, cid, &empty)
        .expect("unsplittable");
    live_engine
        .on_heal_packet(&mut bob, &rng, cid, &typing)
        .expect("other");
    bob.chains_mut(cid).expect("c").heal.needs_reseal = true;
    bob.chains_mut(cid).expect("c").heal.on_ephemeral = true;
    bob.chains_mut(cid).expect("c").heal.ready.clear();
    live_engine.reseal_due(&mut bob, &rng).expect("reseal");
    let mut moving = bob.clone();
    moving.chains_mut(cid).expect("c").heal.on_ephemeral = true;
    moving.chains_mut(cid).expect("c").heal.sent_at = Some(
        crate::protocol::v1::UnixSeconds::from_u64(now.saturating_sub(3)),
    );
    moving
        .chains_mut(cid)
        .expect("c")
        .heal
        .probes
        .push(super::state::HealProbe::Half {
            lo: Tag::from_bytes([0; 32]),
            hi: Tag::from_bytes([0xff; 32]),
        });
    let notice = *ada
        .txs
        .iter()
        .find(|(_, body)| body.conversation_id == cid)
        .expect("tx")
        .0;
    live_engine
        .write_chain_packets(
            &mut moving,
            &rng,
            cid,
            ConversationSort::HandshakeDm,
            std::slice::from_ref(&channel),
            tag,
            notice,
            ActorId::handshake(),
            false,
        )
        .expect("move");
    live_engine.flush_heal(&mut EngineState::new());
    live_engine
        .reseal_heal(&mut EngineState::new(), &rng, cid)
        .expect("unticked");
    let have_many = PacketPlain::HealHave(super::super::payload::PacketHealHave {
        actor_id: Vec::new(),
        packet_seq: 0,
        lo: Tag::from_bytes([0; 32]),
        hi: Tag::from_bytes([0xff; 32]),
        ids: vec![Tag::from_bytes([1; 32]); 33],
    });
    live_engine
        .on_heal_packet(&mut bob, &rng, cid, &have_many)
        .expect("many");
    let known = *bob
        .txs
        .iter()
        .find(|(_, body)| body.conversation_id == cid)
        .expect("known")
        .0;
    let have_known = PacketPlain::HealHave(super::super::payload::PacketHealHave {
        actor_id: Vec::new(),
        packet_seq: 0,
        lo: Tag::from_bytes([0; 32]),
        hi: Tag::from_bytes([0xff; 32]),
        ids: vec![known],
    });
    live_engine
        .on_heal_packet(&mut bob, &rng, cid, &have_known)
        .expect("held");
    live_engine
        .observe_ephemeral(
            &mut bob,
            &rng,
            cid,
            crate::protocol::v1::UnixSeconds::from_u64(now),
            &half,
        )
        .expect("eph-heal");
    live_engine
        .note_set_xor(&mut bob, &rng, cid, Tag::from_bytes([7; 32]))
        .expect("again");
    let orphan = ConversationId::from_bytes([0x77; 32]);
    bob.put_dm(
        ie_uid,
        ie_iid,
        orphan,
        super::state::IdentityNode::direct(Secret::from_bytes([1; 32]), cid),
    );
    live_engine
        .note_set_xor(&mut bob, &rng, orphan, Tag::from_bytes([8; 32]))
        .expect("no-ticket");
    bob.chains_mut(orphan).expect("o").heal.probes.clear();
    bob.chains_mut(orphan).expect("o").heal.needs_reseal = true;
    bob.chains_mut(orphan).expect("o").heal.on_ephemeral = true;
    live_engine
        .reseal_due(&mut bob, &rng)
        .expect("empty-probes");
    let sync_cid = ConversationId::from_bytes([0x66; 32]);
    let ticket = bob.ticket(cid).expect("ticket").clone();
    bob.put_sync_invitee(
        sync_cid,
        super::party::InviteePhase::TicketReceived {
            ticket: ticket.clone(),
            list_from: crate::protocol::v1::TimeBin::from_u64(1),
        },
    );
    live_engine
        .note_set_xor(&mut bob, &rng, sync_cid, Tag::from_bytes([9; 32]))
        .expect("sync-sort");
    let mut bare = ticket.clone();
    bare.persistents.clear();
    let bare_cid = ConversationId::from_bytes([0x55; 32]);
    bob.put_sync_invitee(
        bare_cid,
        super::party::InviteePhase::TicketReceived {
            ticket: bare,
            list_from: crate::protocol::v1::TimeBin::from_u64(1),
        },
    );
    let held = Tag::from_bytes([0x44; 32]);
    bob.txs.insert(
        held,
        DurableBody {
            conversation_id: bare_cid,
            hlc: Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: TxPayload::Confirm,
        },
    );
    live_engine
        .on_heal_packet(
            &mut bob,
            &rng,
            bare_cid,
            &PacketPlain::HealWant(super::super::payload::PacketHealWant {
                actor_id: Vec::new(),
                packet_seq: 0,
                lo: Tag::from_bytes([0; 32]),
                hi: Tag::from_bytes([0xff; 32]),
                ids: vec![held],
            }),
        )
        .expect("empty-ch");
    let mut gap = bob.clone();
    gap.ticked = Some(crate::protocol::v1::UnixSeconds::from_u64(now + 9));
    {
        let chains = gap.chains_mut(cid).expect("g");
        chains.heal.on_ephemeral = true;
        chains.heal.fell_back = false;
        chains.heal.sent_at = Some(crate::protocol::v1::UnixSeconds::from_u64(1));
        chains.heal.ready = vec![vec![1, 2, 3]];
        chains.heal.sealed_from = None;
    }
    live_engine.flush_heal(&mut gap);
    {
        let chains = gap.chains_mut(cid).expect("g2");
        let origin = super::super::chain::join(
            live_engine.suite.hmac(),
            ticket.secret.as_bytes(),
            ConversationSort::HandshakeDm,
            &[],
        )
        .expect("j");
        chains.heal.on_ephemeral = true;
        chains.heal.fell_back = false;
        chains.heal.sent_at = Some(crate::protocol::v1::UnixSeconds::from_u64(1));
        chains.heal.ready = vec![vec![9]];
        chains.heal.sealed_from = Some(origin.clone());
        chains.heal.sealed_to = Some(origin.clone());
        chains.send.insert(ActorId::handshake(), origin);
    }
    live_engine.flush_heal(&mut gap);
    live_engine
        .reseal_heal(&mut bob, &rng, ConversationId::from_bytes([0x01; 32]))
        .expect("not-due");
    bob.chains_mut(cid).expect("c").heal.probes.clear();
    bob.chains_mut(cid).expect("c").heal.needs_reseal = true;
    bob.chains_mut(cid).expect("c").heal.on_ephemeral = true;
    live_engine.reseal_due(&mut bob, &rng).expect("no-probes");
    let sync_tx = Tag::from_bytes([0x42; 32]);
    bob.txs.insert(
        sync_tx,
        DurableBody {
            conversation_id: sync_cid,
            hlc: Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: TxPayload::Confirm,
        },
    );
    live_engine
        .on_heal_packet(
            &mut bob,
            &rng,
            sync_cid,
            &PacketPlain::HealWant(super::super::payload::PacketHealWant {
                actor_id: Vec::new(),
                packet_seq: 0,
                lo: Tag::from_bytes([0; 32]),
                hi: Tag::from_bytes([0xff; 32]),
                ids: vec![sync_tx],
            }),
        )
        .expect("sync-ret");
    let start = bob
        .chains(cid)
        .expect("c")
        .recv
        .get(&ActorId::handshake())
        .expect("recv")
        .clone();
    let text = DurableBody {
        conversation_id: cid,
        hlc: Hlc {
            wall_ms: 3,
            counter: 0,
        },
        payload: TxPayload::Text(super::super::payload::TxText {
            body: "z".repeat(6_000),
            reply_to: None,
            expire_at: None,
        }),
    };
    let tx = Tag::from_bytes([0xee; 32]);
    let xor = super::super::chain::set_xor_for(&bob.txs, cid);
    let packed = super::super::chain::packed_tx(&live_engine.suite, &text);
    let frags = super::super::chain::fragment_body(
        &live_engine.suite,
        &packed,
        tx,
        xor,
        start.packet_seq.as_u64(),
        &[],
    )
    .expect("frags");
    assert!(frags.len() > 1);
    let mut cursor = start;
    let mut sealed = Vec::new();
    for frag in &frags {
        let body = seal_packet(
            &live_engine.suite,
            &rng,
            &mk(live_engine.suite.hmac(), &cursor),
            frag,
        )
        .expect("sfrag");
        sealed.push((matches!(frag, PacketPlain::TxFragMore(_)), body));
        cursor = super::super::chain::step(live_engine.suite.hmac(), &cursor);
    }
    let last = sealed
        .iter()
        .find(|(more, _)| !more)
        .expect("last")
        .1
        .clone();
    bob = live_engine
        .ingest_packet(bob, &rng, channel.clone(), tag, &last)
        .expect("last-first")
        .state;
    for (more, body) in &sealed {
        if *more {
            bob = live_engine
                .ingest_packet(bob, &rng, channel.clone(), tag, body)
                .expect("more")
                .state;
        }
    }
    bob = live_engine
        .ingest_packet(bob, &rng, channel.clone(), tag, &last)
        .expect("last-again")
        .state;
    for (more, body) in &sealed {
        if *more {
            bob = live_engine
                .ingest_packet(bob, &rng, channel.clone(), tag, body)
                .expect("more-again")
                .state;
        }
    }
}

#[test]
fn live_path_waits_then_falls_back() {
    use super::super::chain::{eph_mk, join, mk, seal_packet};
    use super::super::payload::{ConversationSort, PacketPlain, PacketXorAck};
    use super::{Conversation, ConversationRef, DirectMessageQuery};
    use crate::protocol::v1::fixtures::sample_durable;
    use crate::protocol::v1::{
        Address, Defaults, EphemeralChannel, Kind, NotificationPrivacy, Tag,
    };
    let now = 1_700_000_000;
    let eph = EphemeralChannel::new(
        Kind::try_from("webrtc").expect("k"),
        Address::try_from("https://eph.example").expect("a"),
    );
    let defaults = Defaults::try_new(
        vec![sample_durable()],
        vec![eph.clone()],
        true,
        true,
        true,
        None,
        false,
        NotificationPrivacy::Name,
    )
    .expect("def");
    let mut engine = Engine::new(test_engine().suite.clone(), defaults);
    let rng = CounterRng::new();
    engine
        .wrap_dek(&rng, &UnlockSecret::Passphrase("passpass".into()))
        .expect("wrap");
    let ticked = engine.tick(EngineState::new(), now).expect("tick");
    let (created, uid) = engine.create_user(ticked.state, &rng).expect("user");
    let (created, iid) = engine
        .create_identity(created.state, &rng, uid, Policy::Classic)
        .expect("id");
    let named = engine
        .set_display_name(created.state, &rng, uid, iid, "Ada")
        .expect("name");
    let (invited, cid) = engine
        .create_invite(named.state, &rng, uid, iid, 1_800_000_000, None)
        .expect("inv");
    let ids = ConversationRef {
        user_id: uid,
        identity_id: iid,
        conversation_id: cid,
    };
    let ticket_s = engine.ticket_host_string(&invited.state, &ids).expect("t");
    let notice_writes: Vec<_> = engine
        .poll(&invited.state)
        .expect("p")
        .write_durable
        .into_iter()
        .map(|w| (w.channel, w.tag, w.body))
        .collect();
    let inviter = ack_all(&engine, invited.state);
    let ie_tick = engine.tick(EngineState::new(), now).expect("it");
    let (ie_user, ie_uid) = engine.create_user(ie_tick.state, &rng).expect("iu");
    let (ie_id, ie_iid) = engine
        .create_identity(ie_user.state, &rng, ie_uid, Policy::Classic)
        .expect("ii");
    let ie_named = engine
        .set_display_name(ie_id.state, &rng, ie_uid, ie_iid, "Bob")
        .expect("in");
    let (received, _) = engine
        .receive_ticket(ie_named.state, &rng, ie_uid, ie_iid, &ticket_s)
        .expect("recv");
    let bodies: Vec<Vec<u8>> = notice_writes.iter().map(|w| w.2.clone()).collect();
    let minted = engine
        .ingest_list(
            received.state,
            &rng,
            notice_writes[0].0.clone(),
            notice_writes[0].1,
            &bodies,
        )
        .expect("ing");
    let intro_writes: Vec<_> = engine
        .poll(&minted.state)
        .expect("ip")
        .write_durable
        .into_iter()
        .map(|w| (w.channel, w.tag, w.body))
        .collect();
    let sent = ack_all(&engine, minted.state);
    let intro_bodies: Vec<Vec<u8>> = intro_writes.iter().map(|w| w.2.clone()).collect();
    let inv_minted = engine
        .ingest_list(
            inviter,
            &rng,
            intro_writes[0].0.clone(),
            intro_writes[0].1,
            &intro_bodies,
        )
        .expect("iing");
    let inv_intro_writes: Vec<_> = engine
        .poll(&inv_minted.state)
        .expect("iip")
        .write_durable
        .into_iter()
        .map(|w| (w.channel, w.tag, w.body))
        .collect();
    let inv_conf = ack_all(&engine, inv_minted.state);
    let ie_conf = engine
        .ingest_list(
            sent,
            &rng,
            inv_intro_writes[0].0.clone(),
            inv_intro_writes[0].1,
            &inv_intro_writes
                .iter()
                .map(|w| w.2.clone())
                .collect::<Vec<_>>(),
        )
        .expect("ieing");
    let ie_ids = ConversationRef {
        user_id: ie_uid,
        identity_id: ie_iid,
        conversation_id: cid,
    };
    let confirmed_ie = engine
        .confirm_established(ie_conf.state, &rng, ie_ids)
        .expect("ieconf");
    let confirmed = engine
        .confirm_established(inv_conf, &rng, ids)
        .expect("conf");
    let child = engine
        .list_conversations(&confirmed.state, uid, iid)
        .expect("list")
        .into_iter()
        .find_map(|row| match row.conversation {
            Conversation::DirectMessage(DirectMessageQuery::Established(_)) => {
                Some(row.conversation_id)
            }
            _ => None,
        })
        .expect("child");
    let ie_child = engine
        .list_conversations(&confirmed_ie.state, ie_uid, ie_iid)
        .expect("ielist")
        .into_iter()
        .find_map(|row| match row.conversation {
            Conversation::DirectMessage(DirectMessageQuery::Established(_)) => {
                Some(row.conversation_id)
            }
            _ => None,
        })
        .expect("iechild");
    let mut ada = confirmed.state;
    let mut bob = confirmed_ie.state;
    let ada_ids = ConversationRef {
        user_id: uid,
        identity_id: iid,
        conversation_id: child,
    };
    let bob_ids = ConversationRef {
        user_id: ie_uid,
        identity_id: ie_iid,
        conversation_id: ie_child,
    };
    assert!(ada.eph_writes.is_empty());
    let durable_before = ada.writes.len();
    ada = engine
        .send_text(ada, &rng, ada_ids, "hi", None)
        .expect("s1")
        .state;
    assert!(ada.writes.len() == durable_before);
    let first_eph = ada.eph_writes.len();
    assert!(first_eph >= 2);
    assert_eq!(ada.chains(child).expect("c").live_pending.len(), 1);
    ada = engine
        .send_text(ada, &rng, ada_ids, "second", None)
        .expect("s2")
        .state;
    let text_eph = ada.eph_writes.len() - first_eph;
    assert!(text_eph < first_eph);
    assert_eq!(ada.chains(child).expect("c").live_pending.len(), 2);
    bob = engine
        .send_text(bob, &rng, bob_ids, "from-bob", None)
        .expect("sb")
        .state;
    assert!(!bob.eph_writes.is_empty());
    let bob_tag = bob.eph_writes[0].tag;
    let channel = ada.eph_writes[0].channel.clone();
    let first_tag = ada.eph_writes[0].tag;
    let first_body = ada.eph_writes[0].body.clone();
    for write in ada.eph_writes.clone() {
        bob = engine
            .ingest_ephemeral_packet(bob, &rng, write.channel, write.tag, &write.body)
            .expect("eph")
            .state;
    }
    for write in ada.eph_writes.clone() {
        bob = engine
            .ingest_ephemeral_packet(bob, &rng, write.channel, write.tag, &write.body)
            .expect("eph-again")
            .state;
    }
    assert!(
        bob.txs
            .values()
            .any(|tx| { matches!(&tx.payload, TxPayload::Text(text) if text.body == "hi") })
    );
    let bad = engine
        .ingest_ephemeral_packet(
            bob.clone(),
            &rng,
            channel.clone(),
            Tag::from_bytes([9; 32]),
            &first_body,
        )
        .unwrap_err();
    assert_eq!(bad, EngineError::UnknownTag);
    let bad_body = engine
        .ingest_ephemeral_packet(
            bob.clone(),
            &rng,
            channel.clone(),
            first_tag,
            &vec![0; first_body.len()],
        )
        .unwrap_err();
    assert_eq!(bad_body, EngineError::UnknownTag);
    let invitee_pk = ada
        .txs
        .values()
        .find_map(|tx| match &tx.payload {
            TxPayload::InviteeIntro(intro) if tx.conversation_id == cid => {
                Some(intro.signing_pk.clone())
            }
            _ => None,
        })
        .expect("pk");
    let secret = ada.established_secret(child).expect("sec");
    let peer = join(
        engine.suite.hmac(),
        secret.as_bytes(),
        ConversationSort::DirectMessage,
        &invitee_pk,
    )
    .expect("join");
    let set_xor = ada.chains(child).expect("c").live_pending[1].set_xor;
    let ack = seal_packet(
        &engine.suite,
        &rng,
        &eph_mk(engine.suite.hmac(), &peer),
        &PacketPlain::XorAck(PacketXorAck {
            actor_id: invitee_pk.clone(),
            packet_seq: peer.packet_seq.as_u64(),
            set_xor,
        }),
    )
    .expect("ack");
    ada = engine
        .ingest_ephemeral_packet(ada, &rng, channel.clone(), bob_tag, &ack)
        .expect("live-ack")
        .state;
    assert_eq!(ada.chains(child).expect("c").live_pending.len(), 1);
    assert!(ada.chains(child).expect("c").live_until.is_some());
    let mut stripped = ada.clone();
    stripped.txs.retain(|_, body| {
        !matches!(
            body.payload,
            TxPayload::InviterIntro(_) | TxPayload::InviteeIntro(_)
        )
    });
    let stripped_writes = stripped.writes.len();
    engine
        .post_live(
            &mut stripped,
            &rng,
            child,
            &secret,
            Tag::from_bytes([1; 32]),
            &TxPayload::Confirm,
        )
        .expect("no-route");
    assert_eq!(stripped.writes.len(), stripped_writes);
    let flushed_early = engine.tick(stripped, now + 3).expect("strip-tick");
    assert_eq!(flushed_early.state.writes.len(), stripped_writes);
    let held = ada.writes.len();
    ada = engine.tick(ada, now + 2).expect("soon").state;
    assert_eq!(ada.writes.len(), held);
    ada = engine.tick(ada, now + 3).expect("due").state;
    assert!(ada.writes.len() > held);
    assert!(ada.chains(child).expect("c").live_pending.is_empty());
    let durable_ch = ada.writes.last().expect("dw").channel.clone();
    let durable_tag = ada.writes.last().expect("dw").tag;
    let durable_body = ada.writes.last().expect("dw").body.clone();
    bob = engine
        .ingest_packet(bob, &rng, durable_ch.clone(), durable_tag, &durable_body)
        .expect("durable")
        .state;
    let xor = seal_packet(
        &engine.suite,
        &rng,
        &mk(engine.suite.hmac(), &peer),
        &PacketPlain::XorAck(PacketXorAck {
            actor_id: invitee_pk,
            packet_seq: 0,
            set_xor: super::super::chain::set_xor_for(&ada.txs, child),
        }),
    )
    .expect("dxor");
    ada = engine
        .ingest_packet(ada, &rng, durable_ch, durable_tag, &xor)
        .expect("durable-ack")
        .state;
    let live_before = ada.eph_writes.len();
    ada = engine
        .send_text(ada, &rng, ada_ids, "while-live", None)
        .expect("s3")
        .state;
    assert_eq!(ada.eph_writes.len(), live_before + text_eph);
    for tx in ada.txs.values_mut() {
        if let TxPayload::Notice(notice) = &mut tx.payload {
            notice.ephemerals.clear();
        }
    }
    let writes_before = ada.writes.len();
    let eph_before = ada.eph_writes.len();
    ada = engine
        .send_text(ada, &rng, ada_ids, "persistent", None)
        .expect("s4")
        .state;
    assert!(ada.writes.len() > writes_before);
    assert_eq!(ada.eph_writes.len(), eph_before);
    for write in ada.writes[writes_before..].iter().cloned() {
        bob = engine
            .ingest_packet(bob, &rng, write.channel, write.tag, &write.body)
            .expect("fresh-in")
            .state;
    }
    assert!(
        bob.txs.values().any(|tx| {
            matches!(&tx.payload, TxPayload::Text(text) if text.body == "persistent")
        })
    );
    let secret = ada.established_secret(child).expect("sec2");
    let payload = TxPayload::Advertise {
        encaps_pk: vec![7; 32],
    };
    let (tx_id, _, _) = engine
        .merge_tx(&mut ada, &secret, child, payload.clone())
        .expect("adv");
    for tx in ada.txs.values_mut() {
        if let TxPayload::Notice(notice) = &mut tx.payload {
            notice.ephemerals = vec![eph.clone()];
        }
    }
    let writes_before = ada.writes.len();
    let eph_before = ada.eph_writes.len();
    engine
        .post_live(&mut ada, &rng, child, &secret, tx_id, &payload)
        .expect("post-adv");
    assert!(ada.writes.len() > writes_before);
    assert!(ada.eph_writes.len() > eph_before);
    assert_eq!(
        engine
            .send_text(ada.clone(), &rng, ada_ids, "e\u{0301}", None)
            .unwrap_err(),
        EngineError::MalformedPayload
    );
    assert_eq!(
        engine
            .send_reaction(
                ada.clone(),
                &rng,
                ada_ids,
                crate::protocol::v1::Tag::from_bytes([1; 32]),
                &"x".repeat(33),
                true,
            )
            .unwrap_err(),
        EngineError::MalformedPayload
    );
    let secret = ada.established_secret(child).expect("sec3");
    let bare = TxPayload::Text(crate::protocol::v1::payload::TxText {
        body: "bare".into(),
        reply_to: None,
        expire_at: None,
    });
    engine
        .merge_tx(&mut ada, &secret, child, bare)
        .expect("bare");
    let early = ada.eph_writes.len();
    ada = engine
        .send_typing(ada, &rng, ada_ids, true)
        .expect("type-on")
        .state;
    let early_writes: Vec<_> = ada.eph_writes[early..].to_vec();
    for write in early_writes {
        ada = engine
            .ingest_ephemeral_packet(ada, &rng, write.channel, write.tag, &write.body)
            .expect("type-on-in")
            .state;
    }
    ada = engine
        .set_conversation_prefs(
            ada,
            &rng,
            ada_ids,
            crate::protocol::v1::ConversationPrefs {
                read_receipts: true,
                online_visible: false,
                send_typing: true,
                disappear_after: Some(1),
                notification_privacy: crate::protocol::v1::NotificationPrivacy::Name,
                wake: None,
            },
        )
        .expect("prefs")
        .state;
    ada = engine
        .set_conversation_prefs(
            ada,
            &rng,
            ada_ids,
            crate::protocol::v1::ConversationPrefs {
                read_receipts: true,
                online_visible: false,
                send_typing: true,
                disappear_after: Some(1),
                notification_privacy: crate::protocol::v1::NotificationPrivacy::Silent,
                wake: None,
            },
        )
        .expect("prefs2")
        .state;
    let stamped = engine
        .send_text(ada, &rng, ada_ids, "gone", None)
        .expect("gone");
    assert!(stamped.pings().is_empty());
    ada = stamped.state;
    let target = crate::protocol::v1::Tag::from_bytes([8; 32]);
    ada = engine
        .edit_message(ada, &rng, ada_ids, target, "edited")
        .expect("ed")
        .state;
    ada = engine
        .remove_message(ada, &rng, ada_ids, target)
        .expect("rm")
        .state;
    ada = engine
        .send_reaction(ada, &rng, ada_ids, target, "ok", true)
        .expect("rx")
        .state;
    ada = engine
        .send_read(ada, &rng, ada_ids, target)
        .expect("rd")
        .state;
    ada = engine
        .send_delivered(ada, &rng, ada_ids, target)
        .expect("dv")
        .state;
    ada = engine
        .set_group_name(ada, &rng, ada_ids, "Ada")
        .expect("name")
        .state;
    ada = engine
        .set_group_photo(ada, &rng, ada_ids, None)
        .expect("photo")
        .state;
    let mark = ada.eph_writes.len();
    ada = engine
        .send_typing(ada, &rng, ada_ids, false)
        .expect("type")
        .state;
    ada = engine
        .send_presence(ada, &rng, ada_ids)
        .expect("pres")
        .state;
    let signals: Vec<_> = ada.eph_writes[mark..].to_vec();
    for write in signals {
        ada = engine
            .ingest_ephemeral_packet(ada, &rng, write.channel, write.tag, &write.body)
            .expect("sig")
            .state;
    }
    let _ = engine
        .get_conversation(&ada, uid, iid, child)
        .expect("view");
    let view = engine.dm_view(&ada, child);
    assert!(view.messages.iter().any(|item| {
        matches!(&item.payload, TxPayload::Text(text) if text.body == "hi")
            && !item.sender.is_empty()
    }));
    assert!(view.messages.iter().any(|item| {
        matches!(&item.payload, TxPayload::Text(text) if text.body == "bare")
            && item.sender.is_empty()
    }));
    assert!(view.messages.iter().all(|item| !matches!(
        item.payload,
        TxPayload::Advertise { .. } | TxPayload::Name { .. }
    )));
    assert!(view.typing.is_some());
    assert!(view.presence.is_some());
    ada = engine.tick(ada, now + 4).expect("expire").state;
    let view = engine.dm_view(&ada, child);
    let mut saw_hi = false;
    for item in &view.messages {
        if let TxPayload::Text(text) = &item.payload {
            assert_ne!(text.body, "gone");
            if text.body == "hi" {
                saw_hi = true;
            }
        }
    }
    assert!(saw_hi);
    ada = engine.tick(ada, now + 12).expect("clear").state;
    let view = engine.dm_view(&ada, child);
    assert!(view.typing.is_none());
    assert!(view.presence.is_some());
    let wake = crate::protocol::v1::Wake::try_new(
        "https://push.example/x",
        &[3u8; 65],
        &[4u8; 16],
        Some(vec![9, 9, 9]),
    )
    .expect("wake");
    for tx in ada.txs.values_mut() {
        if let TxPayload::InviteeIntro(intro) = &mut tx.payload {
            intro.prefs.wake = Some(wake.clone());
        }
    }
    let pinged = engine
        .send_text(ada, &rng, ada_ids, "ping", None)
        .expect("ping");
    assert_eq!(pinged.pings().len(), 1);
    assert_eq!(pinged.pings()[0].endpoint, "https://push.example/x");
    for tx in bob.txs.values_mut() {
        if let TxPayload::InviterIntro(intro) = &mut tx.payload {
            intro.prefs.wake = Some(wake.clone());
        }
    }
    let bob_ping = engine
        .send_text(bob, &rng, bob_ids, "pong", None)
        .expect("pong");
    assert_eq!(bob_ping.pings().len(), 1);
    let sent = engine
        .send_media(
            pinged.state,
            &rng,
            ada_ids,
            &[super::MediaDraft {
                media_bytes: b"blob".to_vec(),
                mime: "image/png".into(),
                filename: "a.png".into(),
            }],
            None,
            Some("cap"),
        )
        .expect("media");
    let put = sent
        .state
        .blob_puts
        .iter()
        .find(|put| put.body != b"blob")
        .expect("put")
        .clone();
    assert_ne!(put.body, b"blob");
    let hash = sent
        .state
        .txs
        .values()
        .find_map(|tx| match &tx.payload {
            TxPayload::Media(media) if media.filename == "a.png" => Some(media.hash),
            _ => None,
        })
        .expect("hash");
    let plain = engine
        .open_media(&sent.state, child, hash, &put.body)
        .expect("open");
    assert_eq!(plain, b"blob");
    assert_eq!(
        engine
            .open_media(&sent.state, child, hash, &[0; 4])
            .unwrap_err(),
        EngineError::MalformedPayload
    );
    let mut corrupt = put.body.clone();
    *corrupt.last_mut().expect("tail") ^= 1;
    assert_eq!(
        engine
            .open_media(&sent.state, child, hash, &corrupt)
            .unwrap_err(),
        EngineError::MalformedPayload
    );
    let mut flipped = put.body.clone();
    flipped[12] ^= 1;
    assert_eq!(
        engine
            .open_media(&sent.state, child, hash, &flipped)
            .unwrap_err(),
        EngineError::MalformedPayload
    );
    let before = engine.poll(&sent.state).expect("poll");
    let put_tag = put.tag;
    assert!(before.blob_put.iter().any(|item| item.tag == put_tag));
    let acked = engine
        .write_blob_ack(
            sent.state,
            put.kind.clone(),
            put.address.clone(),
            put.tag,
            &put.body,
        )
        .expect("ack");
    let after = engine.poll(&acked.state).expect("poll2");
    assert!(after.blob_get.iter().any(|get| get.tag == put.tag));
}

#[test]
fn live_path_sync_uses_device_actor() {
    use super::{Conversation, ConversationRef, SynchronizationQuery};
    use crate::protocol::v1::fixtures::sample_durable;
    use crate::protocol::v1::{
        Address, Defaults, EphemeralChannel, IdentityId, Kind, NotificationPrivacy, UserId,
    };
    let now = 1_700_000_000;
    let eph = EphemeralChannel::new(
        Kind::try_from("webrtc").expect("k"),
        Address::try_from("https://eph.example").expect("a"),
    );
    let defaults = Defaults::try_new(
        vec![sample_durable()],
        vec![eph],
        true,
        true,
        true,
        None,
        false,
        NotificationPrivacy::Name,
    )
    .expect("def");
    let mut engine = Engine::new(test_engine().suite.clone(), defaults);
    let rng = CounterRng::new();
    engine
        .wrap_dek(&rng, &UnlockSecret::Passphrase("passpass".into()))
        .expect("wrap");
    let ticked = engine.tick(EngineState::new(), now).expect("tick");
    let (invited, sid) = engine
        .create_sync_invite(
            ticked.state,
            &rng,
            Policy::Classic,
            1_800_000_000,
            "phone",
            None,
        )
        .expect("sinv");
    let zeros = UserId::from_bytes([0; 32]);
    let zid = IdentityId::from_bytes([0; 32]);
    let ids = ConversationRef {
        user_id: zeros,
        identity_id: zid,
        conversation_id: sid,
    };
    let ticket_s = engine.ticket_host_string(&invited.state, &ids).expect("t");
    let notice_writes: Vec<_> = engine
        .poll(&invited.state)
        .expect("p")
        .write_durable
        .into_iter()
        .map(|w| (w.channel, w.tag, w.body))
        .collect();
    let inviter = ack_all(&engine, invited.state);
    let ie_tick = engine.tick(EngineState::new(), now).expect("it").state;
    let (received, _) = engine
        .receive_sync_ticket(ie_tick, &rng, &ticket_s)
        .expect("recv");
    let named_ie = engine
        .set_device_name(received.state, &rng, "tablet")
        .expect("dn");
    let bodies: Vec<Vec<u8>> = notice_writes.iter().map(|w| w.2.clone()).collect();
    let minted = engine
        .ingest_list(
            named_ie.state,
            &rng,
            notice_writes[0].0.clone(),
            notice_writes[0].1,
            &bodies,
        )
        .expect("ing");
    let intro_writes: Vec<_> = engine
        .poll(&minted.state)
        .expect("ip")
        .write_durable
        .into_iter()
        .map(|w| (w.channel, w.tag, w.body))
        .collect();
    let sent = ack_all(&engine, minted.state);
    let intro_bodies: Vec<Vec<u8>> = intro_writes.iter().map(|w| w.2.clone()).collect();
    let inv_minted = engine
        .ingest_list(
            inviter,
            &rng,
            intro_writes[0].0.clone(),
            intro_writes[0].1,
            &intro_bodies,
        )
        .expect("iing");
    let inv_intro_writes: Vec<_> = engine
        .poll(&inv_minted.state)
        .expect("iip")
        .write_durable
        .into_iter()
        .map(|w| (w.channel, w.tag, w.body))
        .collect();
    let inv_conf = ack_all(&engine, inv_minted.state);
    let ie_conf = engine
        .ingest_list(
            sent,
            &rng,
            inv_intro_writes[0].0.clone(),
            inv_intro_writes[0].1,
            &inv_intro_writes
                .iter()
                .map(|w| w.2.clone())
                .collect::<Vec<_>>(),
        )
        .expect("ieing");
    let confirmed = engine
        .confirm_established(inv_conf, &rng, ids)
        .expect("conf");
    let _ = engine
        .confirm_established(ie_conf.state, &rng, ids)
        .expect("ieconf");
    let child = engine
        .list_conversations(&confirmed.state, zeros, zid)
        .expect("list")
        .into_iter()
        .find_map(|row| match row.conversation {
            Conversation::Synchronization(SynchronizationQuery::SyncEstablished) => {
                Some(row.conversation_id)
            }
            _ => None,
        })
        .expect("child");
    let child_ids = ConversationRef {
        user_id: zeros,
        identity_id: zid,
        conversation_id: child,
    };
    let mut ada = confirmed.state;
    assert_eq!(
        engine
            .send_text(ada.clone(), &rng, child_ids, "sync-hi", None)
            .unwrap_err(),
        EngineError::WrongPhase
    );
    let secret = ada.established_secret(child).expect("sec");
    let payload = TxPayload::Text(crate::protocol::v1::payload::TxText {
        body: "sync-hi".into(),
        reply_to: None,
        expire_at: None,
    });
    let (tx_id, _, _) = engine
        .merge_tx(&mut ada, &secret, child, payload.clone())
        .expect("merge");
    let before = ada.writes.len();
    engine
        .post_live(&mut ada, &rng, child, &secret, tx_id, &payload)
        .expect("post");
    assert_eq!(ada.writes.len(), before);
    assert!(!ada.eph_writes.is_empty());
    assert_eq!(ada.chains(child).expect("c").live_pending.len(), 1);
    let write = ada.eph_writes[0].clone();
    ada = engine
        .ingest_ephemeral_packet(ada, &rng, write.channel, write.tag, &write.body)
        .expect("echo")
        .state;
    ada = engine.tick(ada, now + 3).expect("due").state;
    assert!(ada.writes.len() > before);
    assert!(ada.chains(child).expect("c").live_pending.is_empty());
    let eph_before = ada.eph_writes.len();
    ada = engine
        .send_presence(ada, &rng, child_ids)
        .expect("presence")
        .state;
    ada = engine
        .send_typing(ada, &rng, child_ids, true)
        .expect("typing")
        .state;
    assert!(ada.eph_writes.len() > eph_before);
}
