use super::{ConversationRef, Engine, EngineState, FOLD_VERSION};
use crate::protocol::v1::fixtures::{CounterRng, test_engine};
use crate::protocol::v1::payload::{DurableBody, Hlc, TxPayload};
use crate::protocol::v1::{
    AEAD_NONCE_LEN, AeadNonce, ConversationId, EngineError, IdentityId, Json, Policy, Secret,
    UnlockSecret, UserId,
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
    engine
        .send_text(acked.state.clone(), &rng, ids, "hi", None)
        .expect("txt");
    assert_eq!(
        engine
            .send_text(acked.state.clone(), &rng, ids, "", None)
            .unwrap_err(),
        EngineError::MalformedPayload
    );
    engine
        .edit_message(
            acked.state.clone(),
            &rng,
            ids,
            crate::protocol::v1::Tag::from_bytes([1; 32]),
            "x",
        )
        .expect("ed");
    engine
        .remove_message(
            acked.state.clone(),
            &rng,
            ids,
            crate::protocol::v1::Tag::from_bytes([1; 32]),
        )
        .expect("rm");
    engine
        .send_reaction(
            acked.state.clone(),
            &rng,
            ids,
            crate::protocol::v1::Tag::from_bytes([1; 32]),
            "👍",
            true,
        )
        .expect("rx");
    engine
        .send_read(
            acked.state.clone(),
            &rng,
            ids,
            crate::protocol::v1::Tag::from_bytes([1; 32]),
        )
        .expect("rd");
    engine
        .send_delivered(
            acked.state.clone(),
            &rng,
            ids,
            crate::protocol::v1::Tag::from_bytes([1; 32]),
        )
        .expect("dv");
    engine
        .send_typing(acked.state.clone(), &rng, ids, true)
        .expect("ty");
    engine
        .send_presence(acked.state.clone(), &rng, ids)
        .expect("pr");
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
        .expect("prefs");
    engine
        .set_profile_pic(acked.state.clone(), &rng, uid, iid, None)
        .expect("pic");
    engine
        .set_group_name(acked.state.clone(), &rng, ids, "G")
        .expect("gn");
    engine
        .set_group_photo(acked.state.clone(), &rng, ids, None)
        .expect("gp");
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
        .expect("media");
    let put = media.state.blob_puts[0].clone();
    engine
        .write_blob_ack(
            media.state.clone(),
            put.kind.clone(),
            put.address.clone(),
            put.tag,
            &put.body,
        )
        .expect("ba");
    assert_eq!(
        engine
            .send_media(invited.state.clone(), &rng, ids, &[], None, None)
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
                sync_ok.state.device.id.unwrap()
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
    let once = engine
        .send_text(invited.state.clone(), &rng, ids, "hi", None)
        .expect("txt1");
    engine
        .send_text(once.state, &rng, ids, "hi", None)
        .expect("txt2");
    let missing = ConversationRef {
        user_id: uid,
        identity_id: iid,
        conversation_id: ConversationId::from_bytes([7; 32]),
    };
    assert_eq!(
        engine
            .send_text(invited.state.clone(), &rng, missing, "hi", None)
            .unwrap_err(),
        EngineError::UnknownIds
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
                        Json::Array(vec![Json::Object(vec![("key".into(), Json::Number(1))])])
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
                            ("key".into(), Json::String("00".repeat(32))),
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
                            ("key".into(), Json::String("00".repeat(32))),
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
    assert_eq!(
        engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    (
                        "skipped_mks".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("key".into(), Json::String(hex32.clone())),
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
                            ("key".into(), Json::String(hex32.clone())),
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
                            ("key".into(), Json::String(hex32.clone())),
                            (
                                "mks".into(),
                                Json::Array(vec![Json::Object(vec![
                                    ("mk".into(), Json::String("00".into())),
                                    ("expires_at".into(), Json::Number(1)),
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
        .expect("estok");
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
    let expires = 1;
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
    let _ = format!("{:?}", DirectMessageQuery::Established);
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
        Conversation::DirectMessage(DirectMessageQuery::Established)
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
    leave_state.skipped_mks.insert(
        sid.as_bytes().to_vec(),
        vec![super::super::chain::CachedMk {
            mk: [2; 32],
            expires_at: u64::MAX,
        }],
    );
    leave_state.skipped_mks.insert(
        vec![9],
        vec![super::super::chain::CachedMk {
            mk: [8; 32],
            expires_at: u64::MAX,
        }],
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
        progress.watermark = Some(472_220);
        progress.completed.insert(472_221);
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
    with_frag_state.set_intake(
        ph_rk,
        crate::protocol::v1::KeyPair::from_parts(vec![1], vec![2]),
    );
    with_frag_state.set_shared_inviter(ph_rk, Secret::from_bytes([3; 32]));
    with_frag_state.set_shared_invitee(ph_rk, Secret::from_bytes([4; 32]));
    if let Some(hs) = with_frag_state.handshake_mut(ph_rk) {
        hs.set_child(ConversationId::from_bytes([5; 32]));
    }
    let _ = super::helpers::sort32(&[0; 32], &[1; 32]);
    let _ = super::helpers::sort32(&[1; 32], &[0; 32]);
    let _ = super::helpers::take_shared32(vec![1]);
    with_frag_state.skipped_mks.insert(
        ph_rk.as_bytes().to_vec(),
        vec![super::super::chain::CachedMk {
            mk: [3; 32],
            expires_at: u64::MAX,
        }],
    );
    let mut long_key = ph_rk.as_bytes().to_vec();
    long_key.extend_from_slice(&[7; 8]);
    with_frag_state.skipped_mks.insert(
        long_key,
        vec![super::super::chain::CachedMk {
            mk: [6; 32],
            expires_at: u64::MAX,
        }],
    );
    with_frag_state.skipped_mks.insert(
        [0xff; 32].to_vec(),
        vec![super::super::chain::CachedMk {
            mk: [4; 32],
            expires_at: u64::MAX,
        }],
    );
    with_frag_state.skipped_mks.insert(
        vec![1, 2],
        vec![super::super::chain::CachedMk {
            mk: [5; 32],
            expires_at: u64::MAX,
        }],
    );
    let rekeyed = engine
        .ingest_list(with_frag_state, &rng, w.channel.clone(), w.tag, &bodies)
        .expect("rekeyfrag");
    let mut drop_state = invited.state.clone();
    drop_state.recv_chains = rekeyed.state.recv_chains.clone();
    drop_state.skipped_mks = rekeyed.state.skipped_mks.clone();
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
    use super::state::{
        ConversationNode, ConversationScope, EstablishedSession, HandshakeRole, HandshakeSession,
    };
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
            Conversation::DirectMessage(DirectMessageQuery::Established) => Some(r.conversation_id),
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
            Conversation::DirectMessage(DirectMessageQuery::Established) => Some(r.conversation_id),
            _ => None,
        })
        .expect("child");
    assert_eq!(child, child_ie);
    assert!(matches!(
        engine
            .get_conversation(&confirmed.state, uid, iid, child)
            .expect("chq"),
        Conversation::DirectMessage(DirectMessageQuery::Established)
    ));
    assert!(confirmed.state.handshake(child).is_none());
    let mut spawned = confirmed.state.clone();
    spawned.fail(child, FailedReason::Left);
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
    let snap_c = engine.fold(confirmed.state.clone()).expect("cfold");
    let restored_c = engine.apply_folded(&snap_c.snapshot).expect("caf");
    assert!(matches!(
        engine
            .get_conversation(&restored_c, uid, iid, child)
            .expect("chf"),
        Conversation::DirectMessage(DirectMessageQuery::Established)
    ));
    let mut no_map = confirmed.state.clone();
    if let Some(hs) = no_map.handshake_mut(cid)
        && let Some(open) = hs.open_mut()
    {
        open.child = None;
    }
    let _ = engine.fold(no_map).expect("nfold");
    let persist = confirmed.persist()[0].clone();
    let applied = engine.apply(inv_conf.clone(), &persist).expect("applyc");
    assert!(applied.established(child).is_some());
    let _ = engine.apply(applied, &persist).expect("applyc2");
    let mut missing = inv_conf.clone();
    missing.clear_shared(cid);
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

    let mut folded_fail = named_ie.state.clone();
    for reason in [
        FailedReason::PolicyNotAccepted {
            policy: Policy::Hybrid,
        },
        FailedReason::InviteExpired { expires: 3 },
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
        folded_fail.fail(cid, reason);
        let snap = engine.fold(folded_fail.clone()).expect("ff");
        let restored = engine.apply_folded(&snap.snapshot).expect("afr");
        assert_eq!(restored.failed(cid), Some(reason));
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
        expires: 1_800_000_001,
    });
    policy_mint.txs.insert(
        Tag::from_bytes([0x22; 32]),
        DurableBody {
            conversation_id: mcid,
            hlc: Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: TxPayload::Notice(TxNotice {
                policy: Policy::Classic,
                intake_pk: vec![0; 32],
                persistents: ticket.persistents.clone(),
                ephemerals: Vec::new(),
                expires: 1_800_000_000,
            }),
        },
    );
    engine
        .try_mint_invitee_intro(&mut policy_mint, &rng, mcid)
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
    no_sk_inv.clear_intake(cid);
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
    let mut no_sk_ie = sent_gate;
    no_sk_ie.clear_intake(cid);
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
    empty_ticket.put_handshake(
        ConversationScope::Identity {
            user: UserId::from_bytes([0; 32]),
            identity: IdentityId::from_bytes([0; 32]),
        },
        cid,
        HandshakeSession::open(ticket.clone(), HandshakeRole::Invitee),
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
    unlock_invitee.put_handshake(
        ConversationScope::Identity {
            user: UserId::from_bytes([0; 32]),
            identity: IdentityId::from_bytes([0; 32]),
        },
        cid,
        HandshakeSession::open(ticket.clone(), HandshakeRole::Invitee),
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
    let snap = engine.fold(sync_ok.state.clone()).expect("sfold");
    let restored = engine.apply_folded(&snap.snapshot).expect("saf");
    assert!(restored.device.enc.is_some());
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
    empty_ie.put_handshake(
        ConversationScope::Identity {
            user: UserId::from_bytes([0; 32]),
            identity: IdentityId::from_bytes([0; 32]),
        },
        cid,
        HandshakeSession::open(ticket.clone(), HandshakeRole::Invitee),
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
    let mut no_ticket = pinned.clone();
    let _ = no_ticket.take_node(cid);
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
    rk.put_handshake(
        ConversationScope::Identity {
            user: UserId::from_bytes([0; 32]),
            identity: IdentityId::from_bytes([0; 32]),
        },
        ConversationId::from_bytes([1; 32]),
        HandshakeSession::failed(
            Ticket {
                secret: Secret::from_bytes([0; 32]),
                persistents: Vec::new(),
                expires: 0,
            },
            HandshakeRole::Inviter,
            FailedReason::NoticeUnlockFailed,
        ),
    );
    rk.skipped_mks.insert(
        [1; 32].to_vec(),
        vec![super::super::chain::CachedMk {
            mk: [2; 32],
            expires_at: 9,
        }],
    );
    rk.skipped_mks.insert(
        [9; 32].to_vec(),
        vec![super::super::chain::CachedMk {
            mk: [3; 32],
            expires_at: 9,
        }],
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
        epoch: 0,
        packet_seq: 0,
    };
    rk.send_chains.insert([1; 32].to_vec(), dummy.clone());
    rk.send_chains.insert([8; 32].to_vec(), dummy.clone());
    rk.recv_chains.insert([1; 32].to_vec(), dummy.clone());
    rk.recv_chains.insert([8; 32].to_vec(), dummy);
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
    rk.put_handshake(
        ConversationScope::Identity {
            user: UserId::from_bytes([0; 32]),
            identity: IdentityId::from_bytes([0; 32]),
        },
        parent,
        HandshakeSession::open(ticket.clone(), HandshakeRole::Inviter).with_child(Some(child_rk)),
    );
    rk.put_dm(
        UserId::from_bytes([0; 32]),
        IdentityId::from_bytes([0; 32]),
        child_rk,
        ConversationNode::Established(EstablishedSession {
            secret: Secret::from_bytes([7; 32]),
            parent,
        }),
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
    let key = super::super::chain::chain_key(&cid, &[]);
    let mut chain = named_ie.state.recv_chains.get(&key).cloned().expect("rc");
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
        chain.packet_seq,
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
    missing_sync.clear_shared(sid);
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
    let snap_s = engine.fold(confirmed.state.clone()).expect("sfoldc");
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
    let snap = engine.fold(expired.state.clone()).expect("foldp");
    let _ = snap.persist();
    let _ = snap.pings();
    engine.lock();
}
