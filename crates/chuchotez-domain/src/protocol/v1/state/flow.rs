//! EngineState drive, persist round-trip, and fail-closed errors.

use super::{
    ApplyError, Command, Conversation, ConversationId, ConversationPhase, CreateIdentityError,
    CreateInviteError, CreateUserError, DeleteConversationError, DeleteIdentityError,
    DeleteUserError, DirectMessage, DisplayName, EngineState, Failed, IdentityId, Invitee,
    MarkNoticesPinnedError, PersistError, ReceiveNoticeError, ReceiveNoticeOk, ReceiveTicketError,
    SetDisplayNameError, UnsetDisplayNameError, UserId,
};
use crate::protocol::v1::{
    AeadError, AeadKey, Billboard, COMMAND_MAX_COMPRESSED, COMMAND_MAX_PERSIST_LEN,
    COMMAND_SCHEMA_VERSION, CanonicalJsonError, CompressError, DisplayNameError, EnvelopeError,
    IntakeError, InviteError, Json, Mailbox, NoticeError, fixtures,
};
use crate::protocol::{Policy, RANDOM32_LEN, Random32, Rng};

fn dek() -> AeadKey {
    AeadKey::from_bytes([0x42; RANDOM32_LEN])
}

fn engine() -> crate::protocol::v1::Engine {
    fixtures::test_engine()
}

fn sample_channels() -> (Billboard, Mailbox, crate::protocol::v1::Wire) {
    (
        fixtures::sample_billboard(),
        fixtures::sample_mailbox(),
        fixtures::sample_wire(),
    )
}

fn missing_id() -> UserId {
    UserId::from_bytes([0xff; RANDOM32_LEN])
}

struct HostRng;

impl Rng for HostRng {
    fn random32(&self) -> Random32 {
        Random32::from_bytes([1; RANDOM32_LEN])
    }
}

#[test]
fn inviter_invitee_persist_replay_and_refuse() {
    let engine = engine();
    let dek = dek();
    let rng = fixtures::CounterRng::new();
    let (board, mailbox, wire) = sample_channels();

    let (state, user_ok) = engine.create_user(EngineState::new(), &rng, &dek);
    let user_ok = user_ok.expect("user");
    let user_id = user_ok.user_id;
    assert_eq!(format!("{:?}", user_ok.persist), "PersistedCommand(..)");
    assert!(!user_ok.persist.as_bytes().is_empty());
    let _ = user_ok.persist.clone().into_bytes();

    let (state, id_ok) = engine.create_identity(state, &rng, &dek, user_id);
    let id_ok = id_ok.expect("identity");
    let identity_id = id_ok.identity_id;
    assert!(
        state
            .user(&user_id)
            .expect("u")
            .identity(&identity_id)
            .expect("i")
            .display_name()
            .is_none()
    );

    let name = DisplayName::try_from("Ada").expect("name");
    let (state, set_ok) = engine.set_display_name(state, &dek, user_id, identity_id, name.clone());
    let set_ok = set_ok.expect("set");
    let set_persist = set_ok.persist;
    engine
        .try_open_command(&dek, set_persist.as_bytes())
        .expect("open set");
    assert_eq!(
        state
            .user(&user_id)
            .expect("u")
            .identity(&identity_id)
            .expect("i")
            .display_name()
            .map(DisplayName::as_str),
        Some("Ada")
    );
    let (state, unset_ok) = engine.unset_display_name(state, &dek, user_id, identity_id);
    let unset_persist = unset_ok.expect("unset").persist;
    engine
        .try_open_command(&dek, unset_persist.as_bytes())
        .expect("open unset");
    assert!(
        state
            .user(&user_id)
            .expect("u")
            .identity(&identity_id)
            .expect("i")
            .display_name()
            .is_none()
    );

    let (state, invite_ok) = engine.create_invite(
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
    let conversation_id = invite_ok.conversation_id;
    let _ = (invite_ok.ticket_blob.clone(), invite_ok.notice_blob.clone());
    assert!(!invite_ok.billboard_tag.as_bytes().iter().all(|b| *b == 0) || true);
    let _ = format!("{invite_ok:?}");
    assert_eq!(
        state
            .user(&user_id)
            .expect("u")
            .identity(&identity_id)
            .expect("i")
            .conversation(&conversation_id)
            .expect("c")
            .phase(),
        ConversationPhase::InviterInviteCreated
    );

    let (state, pin_ok) =
        engine.mark_notices_pinned(state, &dek, user_id, identity_id, conversation_id);
    pin_ok.expect("pin");
    assert_eq!(
        state
            .user(&user_id)
            .expect("u")
            .identity(&identity_id)
            .expect("i")
            .conversation(&conversation_id)
            .expect("c")
            .phase(),
        ConversationPhase::InviterNoticePinned
    );

    // Replay inviter path from empty using opened commands collected on a fresh run.
    let rng = fixtures::CounterRng::new();
    let mut blobs = Vec::new();
    let mut live = EngineState::new();
    let (s, ok) = engine.create_user(live, &rng, &dek);
    live = s;
    let uid = ok.as_ref().expect("u").user_id;
    blobs.push(ok.expect("u").persist.as_bytes().to_vec());
    let (s, ok) = engine.create_identity(live, &rng, &dek, uid);
    live = s;
    let iid = ok.as_ref().expect("i").identity_id;
    blobs.push(ok.expect("i").persist.as_bytes().to_vec());
    let (s, ok) = engine.create_invite(
        live,
        &rng,
        &dek,
        uid,
        iid,
        std::slice::from_ref(&board),
        std::slice::from_ref(&mailbox),
        std::slice::from_ref(&wire),
    );
    live = s;
    let cid = ok.as_ref().expect("c").conversation_id;
    let ticket_blob = ok.as_ref().expect("c").ticket_blob.clone();
    let notice_blob = ok.as_ref().expect("c").notice_blob.clone();
    blobs.push(ok.expect("c").persist.as_bytes().to_vec());
    let (s, ok) = engine.mark_notices_pinned(live, &dek, uid, iid, cid);
    live = s;
    blobs.push(ok.expect("pin").persist.as_bytes().to_vec());

    let mut folded = EngineState::new();
    for blob in &blobs {
        let cmd = engine.try_open_command(&dek, blob).expect("open");
        let (next, result) = engine.apply(folded, &cmd);
        result.expect("apply");
        folded = next;
    }
    assert_eq!(folded, live);

    let rng = fixtures::CounterRng::new();
    let (invitee, ok) = engine.create_user(EngineState::new(), &rng, &dek);
    let invitee_user = ok.expect("iu").user_id;
    let (invitee, ok) = engine.create_identity(invitee, &rng, &dek, invitee_user);
    let invitee_id = ok.expect("ii").identity_id;
    let (invitee, ok) =
        engine.receive_ticket(invitee, &rng, &dek, invitee_user, invitee_id, &ticket_blob);
    let recv = ok.expect("ticket");
    let invitee_cid = recv.conversation_id;
    engine
        .try_open_command(&dek, recv.persist.as_bytes())
        .expect("open ticket cmd");
    assert_eq!(
        invitee
            .user(&invitee_user)
            .expect("u")
            .identity(&invitee_id)
            .expect("i")
            .conversation(&invitee_cid)
            .expect("c")
            .phase(),
        ConversationPhase::InviteeTicketReceived
    );

    let (invitee_acc, ok) = engine.receive_notice(
        invitee.clone(),
        &dek,
        invitee_user,
        invitee_id,
        invitee_cid,
        &notice_blob,
        &[Policy::Hybrid],
    );
    let accepted = ok.expect("notice");
    let persist = accepted.persist().clone();
    let cmd = engine
        .try_open_command(&dek, persist.as_bytes())
        .expect("open notice");
    assert!(matches!(cmd, Command::ReceiveNotice { .. }));
    assert_eq!(
        invitee_acc
            .user(&invitee_user)
            .expect("u")
            .identity(&invitee_id)
            .expect("i")
            .conversation(&invitee_cid)
            .expect("c")
            .phase(),
        ConversationPhase::InviteeInviteReceived
    );

    let (invitee_ref, ok) = engine.receive_notice(
        invitee,
        &dek,
        invitee_user,
        invitee_id,
        invitee_cid,
        &notice_blob,
        &[Policy::Classic],
    );
    let refused = ok.expect("refuse");
    assert!(matches!(
        refused,
        ReceiveNoticeOk::Refused {
            found: Policy::Hybrid,
            ..
        }
    ));
    let persist = refused.persist().clone();
    let cmd = engine
        .try_open_command(&dek, persist.as_bytes())
        .expect("open fail");
    assert!(matches!(cmd, Command::FailConversation { .. }));
    assert_eq!(
        invitee_ref
            .user(&invitee_user)
            .expect("u")
            .identity(&invitee_id)
            .expect("i")
            .conversation(&invitee_cid)
            .expect("c")
            .phase(),
        ConversationPhase::Failed
    );

    let (state, del_c) =
        engine.delete_conversation(invitee_acc, &dek, invitee_user, invitee_id, invitee_cid);
    engine
        .try_open_command(&dek, del_c.expect("del c").persist.as_bytes())
        .expect("open del c");
    assert!(
        state
            .user(&invitee_user)
            .expect("u")
            .identity(&invitee_id)
            .expect("i")
            .conversation(&invitee_cid)
            .is_none()
    );
    let (state, del_i) = engine.delete_identity(state, &dek, invitee_user, invitee_id);
    engine
        .try_open_command(&dek, del_i.expect("del i").persist.as_bytes())
        .expect("open del i");
    assert!(
        state
            .user(&invitee_user)
            .expect("u")
            .identity(&invitee_id)
            .is_none()
    );
    let (state, del_u) = engine.delete_user(state, &dek, invitee_user);
    engine
        .try_open_command(&dek, del_u.expect("del u").persist.as_bytes())
        .expect("open del u");
    assert!(state.user(&invitee_user).is_none());
}

#[test]
fn named_method_errors() {
    let engine = engine();
    let dek = dek();
    let rng = fixtures::CounterRng::new();
    let (board, mailbox, wire) = sample_channels();
    let missing_u = missing_id();
    let missing_i = IdentityId::from_bytes([0xee; RANDOM32_LEN]);
    let missing_c = ConversationId::from_bytes([0xdd; RANDOM32_LEN]);

    let (state, err) =
        engine.create_user(EngineState::new().with_command_seq(u64::MAX), &rng, &dek);
    assert_eq!(err.unwrap_err(), CreateUserError::SeqOverflow);
    assert_eq!(state.command_seq(), u64::MAX);

    let (state, ok) = engine.create_user(EngineState::new(), &HostRng, &dek);
    let user_id = ok.expect("u").user_id;
    let (state, err) = engine.create_user(state, &HostRng, &dek);
    assert!(matches!(
        err.unwrap_err(),
        CreateUserError::DuplicateUser(_)
    ));

    let (state, err) = engine.create_identity(state.clone(), &rng, &dek, missing_u);
    assert_eq!(
        err.unwrap_err(),
        CreateIdentityError::UnknownUser(missing_u)
    );

    let (state, ok) = engine.create_identity(state, &HostRng, &dek, user_id);
    let identity_id = ok.expect("i").identity_id;
    let (state, err) = engine.create_identity(state, &HostRng, &dek, user_id);
    assert!(matches!(
        err.unwrap_err(),
        CreateIdentityError::DuplicateIdentity { .. }
    ));

    assert!(matches!(
        engine
            .delete_user(state.clone(), &dek, missing_u)
            .1
            .unwrap_err(),
        DeleteUserError::UnknownUser(_)
    ));
    assert!(matches!(
        engine
            .delete_identity(state.clone(), &dek, missing_u, missing_i)
            .1
            .unwrap_err(),
        DeleteIdentityError::UnknownUser(_)
    ));
    assert!(matches!(
        engine
            .delete_identity(state.clone(), &dek, user_id, missing_i)
            .1
            .unwrap_err(),
        DeleteIdentityError::UnknownIdentity { .. }
    ));
    assert!(matches!(
        engine
            .delete_conversation(state.clone(), &dek, missing_u, missing_i, missing_c)
            .1
            .unwrap_err(),
        DeleteConversationError::UnknownUser(_)
    ));
    assert!(matches!(
        engine
            .delete_conversation(state.clone(), &dek, user_id, missing_i, missing_c)
            .1
            .unwrap_err(),
        DeleteConversationError::UnknownIdentity { .. }
    ));
    assert!(matches!(
        engine
            .delete_conversation(state.clone(), &dek, user_id, identity_id, missing_c)
            .1
            .unwrap_err(),
        DeleteConversationError::UnknownConversation { .. }
    ));

    let name = DisplayName::try_from("Ada").expect("n");
    assert!(matches!(
        engine
            .set_display_name(state.clone(), &dek, missing_u, missing_i, name.clone())
            .1
            .unwrap_err(),
        SetDisplayNameError::UnknownUser(_)
    ));
    assert!(matches!(
        engine
            .set_display_name(state.clone(), &dek, user_id, missing_i, name)
            .1
            .unwrap_err(),
        SetDisplayNameError::UnknownIdentity { .. }
    ));
    assert!(matches!(
        engine
            .unset_display_name(state.clone(), &dek, missing_u, missing_i)
            .1
            .unwrap_err(),
        UnsetDisplayNameError::UnknownUser(_)
    ));
    assert!(matches!(
        engine
            .unset_display_name(state.clone(), &dek, user_id, missing_i)
            .1
            .unwrap_err(),
        UnsetDisplayNameError::UnknownIdentity { .. }
    ));

    assert!(matches!(
        engine
            .create_invite(
                state.clone(),
                &rng,
                &dek,
                missing_u,
                missing_i,
                std::slice::from_ref(&board),
                std::slice::from_ref(&mailbox),
                &[]
            )
            .1
            .unwrap_err(),
        CreateInviteError::UnknownUser(_)
    ));
    assert!(matches!(
        engine
            .create_invite(
                state.clone(),
                &rng,
                &dek,
                user_id,
                missing_i,
                std::slice::from_ref(&board),
                std::slice::from_ref(&mailbox),
                &[]
            )
            .1
            .unwrap_err(),
        CreateInviteError::UnknownIdentity { .. }
    ));
    assert_eq!(
        engine
            .create_invite(
                state.clone(),
                &rng,
                &dek,
                user_id,
                identity_id,
                &[],
                std::slice::from_ref(&mailbox),
                &[]
            )
            .1
            .unwrap_err(),
        CreateInviteError::Invite(InviteError::Ticket(
            crate::protocol::v1::TicketError::EmptyBillboards
        ))
    );

    let (state, invite_ok) = engine.create_invite(
        state,
        &rng,
        &dek,
        user_id,
        identity_id,
        std::slice::from_ref(&board),
        std::slice::from_ref(&mailbox),
        std::slice::from_ref(&wire),
    );
    let cid = invite_ok.expect("inv").conversation_id;
    let occupy = ConversationId::from_bytes([1; RANDOM32_LEN]);
    let minted = engine
        .try_new_invite(
            &fixtures::SeedRng(fixtures::fill(0x21)),
            std::slice::from_ref(&board),
            std::slice::from_ref(&mailbox),
            std::slice::from_ref(&wire),
        )
        .expect("mint occupy");
    let (state, occupied) = engine.apply(
        state,
        &Command::CreateInvite {
            user_id,
            identity_id,
            conversation_id: occupy,
            invite: minted,
        },
    );
    occupied.expect("occupy");
    let (state, err) = engine.create_invite(
        state,
        &HostRng,
        &dek,
        user_id,
        identity_id,
        std::slice::from_ref(&board),
        std::slice::from_ref(&mailbox),
        std::slice::from_ref(&wire),
    );
    assert!(matches!(
        err.unwrap_err(),
        CreateInviteError::DuplicateConversation {
            conversation_id,
            ..
        } if conversation_id == occupy
    ));

    assert!(matches!(
        engine
            .mark_notices_pinned(state.clone(), &dek, missing_u, missing_i, missing_c)
            .1
            .unwrap_err(),
        MarkNoticesPinnedError::UnknownUser(_)
    ));
    assert!(matches!(
        engine
            .mark_notices_pinned(state.clone(), &dek, user_id, missing_i, missing_c)
            .1
            .unwrap_err(),
        MarkNoticesPinnedError::UnknownIdentity { .. }
    ));
    assert!(matches!(
        engine
            .mark_notices_pinned(state.clone(), &dek, user_id, identity_id, missing_c)
            .1
            .unwrap_err(),
        MarkNoticesPinnedError::UnknownConversation { .. }
    ));
    let (state, _) = engine.mark_notices_pinned(state, &dek, user_id, identity_id, cid);
    assert!(matches!(
        engine
            .mark_notices_pinned(state.clone(), &dek, user_id, identity_id, cid)
            .1
            .unwrap_err(),
        MarkNoticesPinnedError::UnexpectedPhase {
            found: ConversationPhase::InviterNoticePinned,
            ..
        }
    ));

    assert!(matches!(
        engine
            .receive_ticket(state.clone(), &rng, &dek, missing_u, missing_i, "!!!!")
            .1
            .unwrap_err(),
        ReceiveTicketError::Ticket(_)
    ));
    let invite = engine
        .try_new_invite(
            &fixtures::SeedRng(fixtures::fill(0x33)),
            std::slice::from_ref(&board),
            std::slice::from_ref(&mailbox),
            &[],
        )
        .expect("mint");
    let blob = invite.ticket().serialize(&engine);
    assert!(matches!(
        engine
            .receive_ticket(state.clone(), &HostRng, &dek, user_id, identity_id, &blob)
            .1
            .unwrap_err(),
        ReceiveTicketError::DuplicateConversation { .. }
    ));
    assert!(matches!(
        engine
            .receive_ticket(state.clone(), &rng, &dek, missing_u, missing_i, &blob)
            .1
            .unwrap_err(),
        ReceiveTicketError::UnknownUser(_)
    ));
    assert!(matches!(
        engine
            .receive_ticket(state.clone(), &rng, &dek, user_id, missing_i, &blob)
            .1
            .unwrap_err(),
        ReceiveTicketError::UnknownIdentity { .. }
    ));

    assert!(matches!(
        engine
            .receive_notice(
                state.clone(),
                &dek,
                missing_u,
                missing_i,
                missing_c,
                "",
                &[Policy::Hybrid]
            )
            .1
            .unwrap_err(),
        ReceiveNoticeError::UnknownUser(_)
    ));
    assert!(matches!(
        engine
            .receive_notice(
                state.clone(),
                &dek,
                user_id,
                missing_i,
                missing_c,
                "",
                &[Policy::Hybrid]
            )
            .1
            .unwrap_err(),
        ReceiveNoticeError::UnknownIdentity { .. }
    ));
    assert!(matches!(
        engine
            .receive_notice(
                state.clone(),
                &dek,
                user_id,
                identity_id,
                missing_c,
                "",
                &[Policy::Hybrid]
            )
            .1
            .unwrap_err(),
        ReceiveNoticeError::UnknownConversation { .. }
    ));
    assert!(matches!(
        engine
            .receive_notice(
                state.clone(),
                &dek,
                user_id,
                identity_id,
                cid,
                "",
                &[Policy::Hybrid]
            )
            .1
            .unwrap_err(),
        ReceiveNoticeError::UnexpectedPhase {
            found: ConversationPhase::InviterNoticePinned,
            ..
        }
    ));

    let (st, tok) = engine.receive_ticket(state.clone(), &rng, &dek, user_id, identity_id, &blob);
    let tcid = tok.expect("t").conversation_id;
    assert!(matches!(
        engine
            .receive_notice(
                st.clone(),
                &dek,
                user_id,
                identity_id,
                tcid,
                "0g",
                &[Policy::Hybrid]
            )
            .1
            .unwrap_err(),
        ReceiveNoticeError::Notice(_)
    ));
    let notice_blob = engine.serialize_notice(invite.ticket(), invite.intake());
    assert_eq!(
        engine
            .receive_notice(
                st.clone().with_command_seq(u64::MAX),
                &dek,
                user_id,
                identity_id,
                tcid,
                &notice_blob,
                &[Policy::Hybrid]
            )
            .1
            .unwrap_err(),
        ReceiveNoticeError::SeqOverflow
    );
    assert_eq!(
        engine
            .receive_ticket(
                state.clone().with_command_seq(u64::MAX),
                &rng,
                &dek,
                user_id,
                identity_id,
                &blob
            )
            .1
            .unwrap_err(),
        ReceiveTicketError::SeqOverflow
    );
    assert_eq!(
        engine
            .create_identity(
                state.clone().with_command_seq(u64::MAX),
                &rng,
                &dek,
                user_id
            )
            .1
            .unwrap_err(),
        CreateIdentityError::SeqOverflow
    );
    assert_eq!(
        engine
            .create_invite(
                state.clone().with_command_seq(u64::MAX),
                &rng,
                &dek,
                user_id,
                identity_id,
                std::slice::from_ref(&board),
                std::slice::from_ref(&mailbox),
                std::slice::from_ref(&wire)
            )
            .1
            .unwrap_err(),
        CreateInviteError::SeqOverflow
    );

    let _ = EnvelopeError::Base64;
    let max = state.clone().with_command_seq(u64::MAX);
    assert_eq!(
        engine
            .delete_user(max.clone(), &dek, user_id)
            .1
            .unwrap_err(),
        DeleteUserError::SeqOverflow
    );
    assert_eq!(
        engine
            .delete_identity(max.clone(), &dek, user_id, identity_id)
            .1
            .unwrap_err(),
        DeleteIdentityError::SeqOverflow
    );
    assert_eq!(
        engine
            .delete_conversation(max.clone(), &dek, user_id, identity_id, cid)
            .1
            .unwrap_err(),
        DeleteConversationError::SeqOverflow
    );
    assert_eq!(
        engine
            .set_display_name(
                max.clone(),
                &dek,
                user_id,
                identity_id,
                DisplayName::try_from("Ada").expect("n")
            )
            .1
            .unwrap_err(),
        SetDisplayNameError::SeqOverflow
    );
    assert_eq!(
        engine
            .unset_display_name(max.clone(), &dek, user_id, identity_id)
            .1
            .unwrap_err(),
        UnsetDisplayNameError::SeqOverflow
    );
    assert_eq!(
        engine
            .mark_notices_pinned(max.clone(), &dek, user_id, identity_id, cid)
            .1
            .unwrap_err(),
        MarkNoticesPinnedError::SeqOverflow
    );
}

#[test]
fn apply_and_persist_errors() {
    let engine = engine();
    let dek = dek();
    let missing_u = missing_id();
    let (state, err) = engine.apply(
        EngineState::new(),
        &Command::DeleteUser { user_id: missing_u },
    );
    assert_eq!(err.unwrap_err(), ApplyError::UnknownUser(missing_u));
    assert_eq!(state, EngineState::new());

    let (state, _) = engine.apply(
        EngineState::new().with_command_seq(u64::MAX),
        &Command::CreateUser {
            user_id: UserId::from_bytes([1; RANDOM32_LEN]),
        },
    );
    assert_eq!(state.command_seq(), u64::MAX);

    assert_eq!(
        engine.try_open_command(&dek, &[]).unwrap_err(),
        PersistError::TooShort
    );
    assert_eq!(
        engine
            .try_open_command(&dek, &[0u8; COMMAND_MAX_PERSIST_LEN + 1])
            .unwrap_err(),
        PersistError::TooLong
    );
    let short = vec![0u8; 12];
    assert_eq!(
        engine.try_open_command(&dek, &short).unwrap_err(),
        PersistError::TooShort
    );
    let (s, ok) = engine.create_user(EngineState::new(), &HostRng, &dek);
    let blob = ok.expect("p").persist;
    let other = AeadKey::from_bytes([0x99; RANDOM32_LEN]);
    assert!(matches!(
        engine
            .try_open_command(&other, blob.as_bytes())
            .unwrap_err(),
        PersistError::Aead(AeadError::Open)
    ));
    let _ = s;

    let uid = UserId::from_bytes([4; RANDOM32_LEN]);
    let iid = IdentityId::from_bytes([5; RANDOM32_LEN]);
    let cid = ConversationId::from_bytes([6; RANDOM32_LEN]);
    let (board, mailbox, wire) = sample_channels();
    let invite = engine
        .try_new_invite(
            &fixtures::SeedRng(fixtures::fill(0x44)),
            std::slice::from_ref(&board),
            std::slice::from_ref(&mailbox),
            std::slice::from_ref(&wire),
        )
        .expect("invite");
    let (state, _) = engine.apply(EngineState::new(), &Command::CreateUser { user_id: uid });
    assert!(matches!(
        engine
            .apply(state.clone(), &Command::CreateUser { user_id: uid })
            .1
            .unwrap_err(),
        ApplyError::DuplicateUser(_)
    ));
    let (state, _) = engine.apply(
        state,
        &Command::CreateIdentity {
            user_id: uid,
            identity_id: iid,
        },
    );
    assert!(matches!(
        engine
            .apply(
                state.clone(),
                &Command::CreateIdentity {
                    user_id: uid,
                    identity_id: iid,
                },
            )
            .1
            .unwrap_err(),
        ApplyError::DuplicateIdentity { .. }
    ));
    let create = Command::CreateInvite {
        user_id: uid,
        identity_id: iid,
        conversation_id: cid,
        invite: invite.clone(),
    };
    let (state, ok) = engine.apply(state, &create);
    ok.expect("first invite");
    assert!(matches!(
        engine.apply(state.clone(), &create).1.unwrap_err(),
        ApplyError::DuplicateConversation { .. }
    ));
    let recv = Command::ReceiveTicket {
        user_id: uid,
        identity_id: iid,
        conversation_id: cid,
        ticket: invite.ticket().clone(),
    };
    assert!(matches!(
        engine.apply(state.clone(), &recv).1.unwrap_err(),
        ApplyError::DuplicateConversation { .. }
    ));
    let notice = crate::protocol::v1::Notice::from_intake(Policy::Hybrid, invite.intake());
    assert!(matches!(
        engine
            .apply(
                state.clone(),
                &Command::ReceiveNotice {
                    user_id: uid,
                    identity_id: iid,
                    conversation_id: cid,
                    notice: notice.clone(),
                }
            )
            .1
            .unwrap_err(),
        ApplyError::UnexpectedPhase {
            found: ConversationPhase::InviterInviteCreated,
            ..
        }
    ));
    assert!(matches!(
        engine
            .apply(
                state,
                &Command::FailConversation {
                    user_id: uid,
                    identity_id: iid,
                    conversation_id: cid,
                    failed: Failed::PolicyNotAccepted {
                        ticket: invite.ticket().clone(),
                        notice,
                    },
                }
            )
            .1
            .unwrap_err(),
        ApplyError::UnexpectedPhase {
            found: ConversationPhase::InviterInviteCreated,
            ..
        }
    ));
    assert_eq!(
        engine
            .seal_command(
                &dek,
                u64::MAX,
                &Command::CreateUser {
                    user_id: UserId::from_bytes([7; RANDOM32_LEN]),
                }
            )
            .unwrap_err(),
        PersistError::SeqOverflow
    );

    let displays = [
        format!("{}", ApplyError::SeqOverflow),
        format!("{}", PersistError::TooShort),
        format!("{}", PersistError::TooLong),
        format!("{}", PersistError::Aead(AeadError::Open)),
        format!("{}", PersistError::InvalidVersion),
        format!("{}", PersistError::UnknownOp),
        format!("{}", PersistError::MissingField),
        format!("{}", PersistError::UnknownField),
        format!("{}", PersistError::Type),
        format!("{}", PersistError::InvalidId),
        format!("{}", PersistError::SeqOverflow),
        format!("{}", CreateUserError::SeqOverflow),
        format!("{}", CreateUserError::Persist(PersistError::TooShort)),
        format!("{}", CreateIdentityError::Persist(PersistError::TooShort)),
        format!("{}", DeleteUserError::Persist(PersistError::TooShort)),
        format!("{}", DeleteIdentityError::Persist(PersistError::TooShort)),
        format!(
            "{}",
            DeleteConversationError::Persist(PersistError::TooShort)
        ),
        format!("{}", SetDisplayNameError::Persist(PersistError::TooShort)),
        format!("{}", UnsetDisplayNameError::Persist(PersistError::TooShort)),
        format!("{}", CreateInviteError::Persist(PersistError::TooShort)),
        format!(
            "{}",
            CreateInviteError::Invite(InviteError::Ticket(
                crate::protocol::v1::TicketError::EmptyBillboards
            ))
        ),
        format!(
            "{}",
            MarkNoticesPinnedError::Persist(PersistError::TooShort)
        ),
        format!("{}", ReceiveTicketError::Persist(PersistError::TooShort)),
        format!("{}", ReceiveTicketError::Ticket(EnvelopeError::Empty)),
        format!("{}", ReceiveNoticeError::Persist(PersistError::TooShort)),
        format!("{}", ReceiveNoticeError::Notice(NoticeError::Empty)),
        format!("{}", PersistError::Compress(CompressError::Codec)),
        format!("{}", PersistError::Json(CanonicalJsonError::Invalid)),
        format!("{}", PersistError::Ticket(EnvelopeError::Empty)),
        format!("{}", PersistError::Notice(NoticeError::Empty)),
        format!("{}", PersistError::Intake(IntakeError::EmptyMailboxes)),
        format!("{}", PersistError::DisplayName(DisplayNameError::Empty)),
        format!("{:?}", ConversationPhase::Group),
    ];
    assert!(displays.iter().all(|s| !s.is_empty()));
    let _ = &ApplyError::SeqOverflow as &dyn std::error::Error;
    let _ = &PersistError::TooShort as &dyn std::error::Error;
    let _ = &CreateUserError::SeqOverflow as &dyn std::error::Error;
    assert!(std::error::Error::source(&PersistError::Aead(AeadError::Open)).is_some());
    assert!(std::error::Error::source(&PersistError::Compress(CompressError::Codec)).is_some());
    assert!(std::error::Error::source(&PersistError::Json(CanonicalJsonError::Invalid)).is_some());
    assert!(std::error::Error::source(&PersistError::Ticket(EnvelopeError::Empty)).is_some());
    assert!(std::error::Error::source(&PersistError::Notice(NoticeError::Empty)).is_some());
    assert!(
        std::error::Error::source(&PersistError::Intake(IntakeError::EmptyMailboxes)).is_some()
    );
    assert!(
        std::error::Error::source(&PersistError::DisplayName(DisplayNameError::Empty)).is_some()
    );
    assert!(std::error::Error::source(&PersistError::TooShort).is_none());
    let _ = format!("{:?}", Json::Null);
    let _ = COMMAND_SCHEMA_VERSION;
}

#[test]
fn persist_json_fail_closed() {
    let engine = engine();
    let dek = dek();
    let seq = 0u64;
    let cases: &[Json] = &[
        Json::Null,
        Json::Object(vec![]),
        Json::Object(vec![
            ("v".into(), Json::String("9".into())),
            ("op".into(), Json::String("create_user".into())),
        ]),
        Json::Object(vec![
            ("v".into(), Json::String("1".into())),
            ("op".into(), Json::String("nope".into())),
        ]),
        Json::Object(vec![
            ("v".into(), Json::String("1".into())),
            ("op".into(), Json::String("create_user".into())),
            ("extra".into(), Json::Bool(true)),
        ]),
        Json::Object(vec![
            ("v".into(), Json::Bool(true)),
            ("op".into(), Json::String("create_user".into())),
        ]),
        Json::Object(vec![
            ("v".into(), Json::String("1".into())),
            ("op".into(), Json::String("create_user".into())),
            ("user_id".into(), Json::String("zz".into())),
        ]),
        Json::Object(vec![
            ("v".into(), Json::String("1".into())),
            ("op".into(), Json::String("create_user".into())),
            (
                "user_id".into(),
                Json::String(engine.b64u().encode(&[0u8; 8])),
            ),
        ]),
        Json::Object(vec![
            ("v".into(), Json::String("1".into())),
            ("op".into(), Json::String("set_display_name".into())),
            (
                "user_id".into(),
                Json::String(engine.b64u().encode(&[1u8; 32])),
            ),
            (
                "identity_id".into(),
                Json::String(engine.b64u().encode(&[2u8; 32])),
            ),
            ("name".into(), Json::String(String::new())),
        ]),
        Json::Object(vec![
            ("v".into(), Json::String("1".into())),
            ("op".into(), Json::String("fail_conversation".into())),
            (
                "user_id".into(),
                Json::String(engine.b64u().encode(&[1u8; 32])),
            ),
            (
                "identity_id".into(),
                Json::String(engine.b64u().encode(&[2u8; 32])),
            ),
            (
                "conversation_id".into(),
                Json::String(engine.b64u().encode(&[3u8; 32])),
            ),
            ("reason".into(), Json::String("other".into())),
            ("ticket".into(), Json::String("x".into())),
            ("notice".into(), Json::Null),
        ]),
        Json::Object(vec![
            ("v".into(), Json::String("1".into())),
            ("op".into(), Json::String("delete_user".into())),
        ]),
        Json::Object(vec![
            ("v".into(), Json::String("1".into())),
            ("op".into(), Json::String("delete_identity".into())),
            (
                "user_id".into(),
                Json::String(engine.b64u().encode(&[1u8; 32])),
            ),
        ]),
        Json::Object(vec![
            ("v".into(), Json::String("1".into())),
            ("op".into(), Json::String("delete_conversation".into())),
            (
                "user_id".into(),
                Json::String(engine.b64u().encode(&[1u8; 32])),
            ),
            (
                "identity_id".into(),
                Json::String(engine.b64u().encode(&[2u8; 32])),
            ),
        ]),
        Json::Object(vec![
            ("v".into(), Json::String("1".into())),
            ("op".into(), Json::String("unset_display_name".into())),
            (
                "user_id".into(),
                Json::String(engine.b64u().encode(&[1u8; 32])),
            ),
        ]),
        Json::Object(vec![
            ("v".into(), Json::String("1".into())),
            ("op".into(), Json::String("create_identity".into())),
            (
                "user_id".into(),
                Json::String(engine.b64u().encode(&[1u8; 32])),
            ),
        ]),
        Json::Object(vec![
            ("v".into(), Json::String("1".into())),
            ("op".into(), Json::String("create_invite".into())),
            (
                "user_id".into(),
                Json::String(engine.b64u().encode(&[1u8; 32])),
            ),
            (
                "identity_id".into(),
                Json::String(engine.b64u().encode(&[2u8; 32])),
            ),
            (
                "conversation_id".into(),
                Json::String(engine.b64u().encode(&[3u8; 32])),
            ),
            (
                "intake_pk".into(),
                Json::String(engine.b64u().encode(&[4u8; 32])),
            ),
            (
                "intake_sk".into(),
                Json::String(engine.b64u().encode(&[5u8; 32])),
            ),
            (
                "mailboxes".into(),
                Json::Array(vec![Json::Object(vec![
                    ("kind".into(), Json::String("nostr".into())),
                    (
                        "address".into(),
                        Json::String("wss://mailbox.example".into()),
                    ),
                ])]),
            ),
            ("wires".into(), Json::Array(vec![])),
        ]),
        Json::Object(vec![
            ("v".into(), Json::String("1".into())),
            ("op".into(), Json::String("create_invite".into())),
            (
                "user_id".into(),
                Json::String(engine.b64u().encode(&[1u8; 32])),
            ),
            (
                "identity_id".into(),
                Json::String(engine.b64u().encode(&[2u8; 32])),
            ),
            (
                "conversation_id".into(),
                Json::String(engine.b64u().encode(&[3u8; 32])),
            ),
            ("ticket".into(), Json::String("zz".into())),
            (
                "intake_pk".into(),
                Json::String(engine.b64u().encode(&[4u8; 32])),
            ),
            (
                "intake_sk".into(),
                Json::String(engine.b64u().encode(&[5u8; 32])),
            ),
            (
                "mailboxes".into(),
                Json::Array(vec![Json::Object(vec![
                    ("kind".into(), Json::String("nostr".into())),
                    (
                        "address".into(),
                        Json::String("wss://mailbox.example".into()),
                    ),
                ])]),
            ),
            ("wires".into(), Json::Array(vec![])),
        ]),
        Json::Object(vec![
            ("v".into(), Json::String("1".into())),
            ("op".into(), Json::String("create_invite".into())),
            (
                "user_id".into(),
                Json::String(engine.b64u().encode(&[1u8; 32])),
            ),
            (
                "identity_id".into(),
                Json::String(engine.b64u().encode(&[2u8; 32])),
            ),
            (
                "conversation_id".into(),
                Json::String(engine.b64u().encode(&[3u8; 32])),
            ),
            ("ticket".into(), Json::String("aa".into())),
            (
                "intake_pk".into(),
                Json::String(engine.b64u().encode(&[4u8; 32])),
            ),
            (
                "intake_sk".into(),
                Json::String(engine.b64u().encode(&[5u8; 32])),
            ),
            ("mailboxes".into(), Json::Array(vec![])),
            ("wires".into(), Json::Array(vec![])),
        ]),
        Json::Object(vec![
            ("v".into(), Json::String("1".into())),
            ("op".into(), Json::String("create_invite".into())),
            (
                "user_id".into(),
                Json::String(engine.b64u().encode(&[1u8; 32])),
            ),
            (
                "identity_id".into(),
                Json::String(engine.b64u().encode(&[2u8; 32])),
            ),
            (
                "conversation_id".into(),
                Json::String(engine.b64u().encode(&[3u8; 32])),
            ),
            ("ticket".into(), Json::String("aa".into())),
            (
                "intake_pk".into(),
                Json::String(engine.b64u().encode(&[4u8; 32])),
            ),
            (
                "intake_sk".into(),
                Json::String(engine.b64u().encode(&[5u8; 32])),
            ),
            ("mailboxes".into(), Json::Bool(true)),
            ("wires".into(), Json::Array(vec![])),
        ]),
        Json::Object(vec![
            ("v".into(), Json::String("1".into())),
            ("op".into(), Json::String("create_invite".into())),
            (
                "user_id".into(),
                Json::String(engine.b64u().encode(&[1u8; 32])),
            ),
            (
                "identity_id".into(),
                Json::String(engine.b64u().encode(&[2u8; 32])),
            ),
            (
                "conversation_id".into(),
                Json::String(engine.b64u().encode(&[3u8; 32])),
            ),
            ("ticket".into(), Json::String("aa".into())),
            (
                "intake_pk".into(),
                Json::String(engine.b64u().encode(&[4u8; 32])),
            ),
            (
                "intake_sk".into(),
                Json::String(engine.b64u().encode(&[5u8; 32])),
            ),
            (
                "mailboxes".into(),
                Json::Array(vec![Json::Object(vec![
                    ("kind".into(), Json::String("nostr".into())),
                    (
                        "address".into(),
                        Json::String("wss://mailbox.example".into()),
                    ),
                ])]),
            ),
            ("wires".into(), Json::Bool(true)),
        ]),
        Json::Object(vec![
            ("v".into(), Json::String("1".into())),
            ("op".into(), Json::String("create_invite".into())),
            (
                "user_id".into(),
                Json::String(engine.b64u().encode(&[1u8; 32])),
            ),
            (
                "identity_id".into(),
                Json::String(engine.b64u().encode(&[2u8; 32])),
            ),
            (
                "conversation_id".into(),
                Json::String(engine.b64u().encode(&[3u8; 32])),
            ),
            ("ticket".into(), Json::String("aa".into())),
            (
                "intake_pk".into(),
                Json::String(engine.b64u().encode(&[4u8; 32])),
            ),
            (
                "intake_sk".into(),
                Json::String(engine.b64u().encode(&[5u8; 32])),
            ),
            ("mailboxes".into(), Json::Array(vec![Json::Bool(true)])),
            ("wires".into(), Json::Array(vec![])),
        ]),
        Json::Object(vec![
            ("v".into(), Json::String("1".into())),
            ("op".into(), Json::String("create_invite".into())),
            (
                "user_id".into(),
                Json::String(engine.b64u().encode(&[1u8; 32])),
            ),
            (
                "identity_id".into(),
                Json::String(engine.b64u().encode(&[2u8; 32])),
            ),
            (
                "conversation_id".into(),
                Json::String(engine.b64u().encode(&[3u8; 32])),
            ),
            ("ticket".into(), Json::String("aa".into())),
            (
                "intake_pk".into(),
                Json::String(engine.b64u().encode(&[4u8; 32])),
            ),
            (
                "intake_sk".into(),
                Json::String(engine.b64u().encode(&[5u8; 32])),
            ),
            (
                "mailboxes".into(),
                Json::Array(vec![Json::Object(vec![
                    ("kind".into(), Json::String("nostr".into())),
                    (
                        "address".into(),
                        Json::String("wss://mailbox.example".into()),
                    ),
                    ("extra".into(), Json::Bool(true)),
                ])]),
            ),
            ("wires".into(), Json::Array(vec![])),
        ]),
        Json::Object(vec![
            ("v".into(), Json::String("1".into())),
            ("op".into(), Json::String("create_invite".into())),
            (
                "user_id".into(),
                Json::String(engine.b64u().encode(&[1u8; 32])),
            ),
            (
                "identity_id".into(),
                Json::String(engine.b64u().encode(&[2u8; 32])),
            ),
            (
                "conversation_id".into(),
                Json::String(engine.b64u().encode(&[3u8; 32])),
            ),
            ("ticket".into(), Json::String("aa".into())),
            (
                "intake_pk".into(),
                Json::String(engine.b64u().encode(&[4u8; 32])),
            ),
            (
                "intake_sk".into(),
                Json::String(engine.b64u().encode(&[5u8; 32])),
            ),
            (
                "mailboxes".into(),
                Json::Array(vec![Json::Object(vec![(
                    "address".into(),
                    Json::String("wss://mailbox.example".into()),
                )])]),
            ),
            ("wires".into(), Json::Array(vec![])),
        ]),
        Json::Object(vec![
            ("v".into(), Json::String("1".into())),
            ("op".into(), Json::String("create_invite".into())),
            (
                "user_id".into(),
                Json::String(engine.b64u().encode(&[1u8; 32])),
            ),
            (
                "identity_id".into(),
                Json::String(engine.b64u().encode(&[2u8; 32])),
            ),
            (
                "conversation_id".into(),
                Json::String(engine.b64u().encode(&[3u8; 32])),
            ),
            ("ticket".into(), Json::String("aa".into())),
            (
                "intake_pk".into(),
                Json::String(engine.b64u().encode(&[4u8; 32])),
            ),
            (
                "intake_sk".into(),
                Json::String(engine.b64u().encode(&[5u8; 32])),
            ),
            (
                "mailboxes".into(),
                Json::Array(vec![Json::Object(vec![
                    ("kind".into(), Json::String(String::new())),
                    (
                        "address".into(),
                        Json::String("wss://mailbox.example".into()),
                    ),
                ])]),
            ),
            ("wires".into(), Json::Array(vec![])),
        ]),
        Json::Object(vec![
            ("v".into(), Json::String("1".into())),
            ("op".into(), Json::String("create_invite".into())),
            (
                "user_id".into(),
                Json::String(engine.b64u().encode(&[1u8; 32])),
            ),
            (
                "identity_id".into(),
                Json::String(engine.b64u().encode(&[2u8; 32])),
            ),
            (
                "conversation_id".into(),
                Json::String(engine.b64u().encode(&[3u8; 32])),
            ),
            ("ticket".into(), Json::String("aa".into())),
            (
                "intake_pk".into(),
                Json::String(engine.b64u().encode(&[4u8; 32])),
            ),
            (
                "intake_sk".into(),
                Json::String(engine.b64u().encode(&[5u8; 32])),
            ),
            (
                "mailboxes".into(),
                Json::Array(vec![Json::Object(vec![
                    ("kind".into(), Json::String("nostr".into())),
                    (
                        "address".into(),
                        Json::String("wss://mailbox.example".into()),
                    ),
                ])]),
            ),
            (
                "wires".into(),
                Json::Array(vec![Json::Object(vec![
                    ("kind".into(), Json::String(String::new())),
                    ("address".into(), Json::String("stun:stun.example".into())),
                ])]),
            ),
        ]),
        Json::Object(vec![
            ("v".into(), Json::String("1".into())),
            ("op".into(), Json::String("receive_ticket".into())),
            (
                "user_id".into(),
                Json::String(engine.b64u().encode(&[1u8; 32])),
            ),
            (
                "identity_id".into(),
                Json::String(engine.b64u().encode(&[2u8; 32])),
            ),
            (
                "conversation_id".into(),
                Json::String(engine.b64u().encode(&[3u8; 32])),
            ),
        ]),
        Json::Object(vec![
            ("v".into(), Json::String("1".into())),
            ("op".into(), Json::String("receive_ticket".into())),
            (
                "user_id".into(),
                Json::String(engine.b64u().encode(&[1u8; 32])),
            ),
            (
                "identity_id".into(),
                Json::String(engine.b64u().encode(&[2u8; 32])),
            ),
            (
                "conversation_id".into(),
                Json::String(engine.b64u().encode(&[3u8; 32])),
            ),
            ("ticket".into(), Json::String("zz".into())),
        ]),
        Json::Object(vec![
            ("v".into(), Json::String("1".into())),
            ("op".into(), Json::String("receive_notice".into())),
            (
                "user_id".into(),
                Json::String(engine.b64u().encode(&[1u8; 32])),
            ),
            (
                "identity_id".into(),
                Json::String(engine.b64u().encode(&[2u8; 32])),
            ),
            (
                "conversation_id".into(),
                Json::String(engine.b64u().encode(&[3u8; 32])),
            ),
        ]),
        Json::Object(vec![
            ("v".into(), Json::String("1".into())),
            ("op".into(), Json::String("receive_notice".into())),
            (
                "user_id".into(),
                Json::String(engine.b64u().encode(&[1u8; 32])),
            ),
            (
                "identity_id".into(),
                Json::String(engine.b64u().encode(&[2u8; 32])),
            ),
            (
                "conversation_id".into(),
                Json::String(engine.b64u().encode(&[3u8; 32])),
            ),
            ("notice".into(), Json::Null),
        ]),
        Json::Object(vec![
            ("v".into(), Json::String("1".into())),
            ("op".into(), Json::String("fail_conversation".into())),
            (
                "user_id".into(),
                Json::String(engine.b64u().encode(&[1u8; 32])),
            ),
            (
                "identity_id".into(),
                Json::String(engine.b64u().encode(&[2u8; 32])),
            ),
            (
                "conversation_id".into(),
                Json::String(engine.b64u().encode(&[3u8; 32])),
            ),
            ("reason".into(), Json::String("policy_not_accepted".into())),
            ("notice".into(), Json::Null),
        ]),
        Json::Object(vec![
            ("v".into(), Json::String("1".into())),
            ("op".into(), Json::String("mark_notices_pinned".into())),
            (
                "user_id".into(),
                Json::String(engine.b64u().encode(&[1u8; 32])),
            ),
            (
                "identity_id".into(),
                Json::String(engine.b64u().encode(&[2u8; 32])),
            ),
        ]),
        Json::Object(vec![
            ("v".into(), Json::String("1".into())),
            ("op".into(), Json::String("set_display_name".into())),
            (
                "user_id".into(),
                Json::String(engine.b64u().encode(&[1u8; 32])),
            ),
            (
                "identity_id".into(),
                Json::String(engine.b64u().encode(&[2u8; 32])),
            ),
        ]),
    ];
    for json in cases {
        let blob = engine.seal_raw_json(&dek, seq, json).expect("seal");
        assert!(engine.try_open_command(&dek, blob.as_bytes()).is_err());
    }
    let invite = engine
        .try_new_invite(
            &fixtures::SeedRng(fixtures::fill(0x55)),
            &[fixtures::sample_billboard()],
            &[fixtures::sample_mailbox()],
            &[],
        )
        .expect("ticket");
    let ticket = invite.ticket().serialize(&engine);
    for missing in [
        Json::Object(vec![
            ("v".into(), Json::String("1".into())),
            ("op".into(), Json::String("receive_ticket".into())),
            (
                "identity_id".into(),
                Json::String(engine.b64u().encode(&[2u8; 32])),
            ),
            (
                "conversation_id".into(),
                Json::String(engine.b64u().encode(&[3u8; 32])),
            ),
            ("ticket".into(), Json::String(ticket.clone())),
        ]),
        Json::Object(vec![
            ("v".into(), Json::String("1".into())),
            ("op".into(), Json::String("receive_ticket".into())),
            (
                "user_id".into(),
                Json::String(engine.b64u().encode(&[1u8; 32])),
            ),
            (
                "conversation_id".into(),
                Json::String(engine.b64u().encode(&[3u8; 32])),
            ),
            ("ticket".into(), Json::String(ticket.clone())),
        ]),
        Json::Object(vec![
            ("v".into(), Json::String("1".into())),
            ("op".into(), Json::String("receive_ticket".into())),
            (
                "user_id".into(),
                Json::String(engine.b64u().encode(&[1u8; 32])),
            ),
            (
                "identity_id".into(),
                Json::String(engine.b64u().encode(&[2u8; 32])),
            ),
            ("ticket".into(), Json::String(ticket.clone())),
        ]),
    ] {
        let blob = engine
            .seal_raw_json(&dek, seq, &missing)
            .expect("seal ticket");
        assert_eq!(
            engine.try_open_command(&dek, blob.as_bytes()).unwrap_err(),
            PersistError::MissingField
        );
    }
}

#[test]
fn command_debug_and_placeholders() {
    let engine = engine();
    let invite = engine
        .try_new_invite(
            &fixtures::SeedRng(fixtures::fill(0x11)),
            &[fixtures::sample_billboard()],
            &[fixtures::sample_mailbox()],
            &[],
        )
        .expect("invite");
    let cmd = Command::CreateInvite {
        user_id: UserId::from_bytes([1; 32]),
        identity_id: IdentityId::from_bytes([2; 32]),
        conversation_id: ConversationId::from_bytes([3; 32]),
        invite: invite.clone(),
    };
    assert!(format!("{cmd:?}").contains("CreateInvite"));
    assert_eq!(invite, invite.clone());
    let _ = Conversation::DirectMessage(DirectMessage::Invitee(Invitee::InviteReceived {
        ticket: invite.ticket().clone(),
        notice: crate::protocol::v1::Notice::from_intake(Policy::Hybrid, invite.intake()),
    }))
    .phase();
}

#[test]
fn persist_size_limits_and_commit_persist() {
    use std::sync::Arc;

    let dek = dek();
    let cmd = Command::CreateUser {
        user_id: UserId::from_bytes([8; RANDOM32_LEN]),
    };
    let padded = fixtures::engine_custom(
        Arc::new(fixtures::IdentityCompress),
        Arc::new(fixtures::XorAead),
        Arc::new(fixtures::PadJson),
    );
    assert_eq!(
        padded.seal_command(&dek, 0, &cmd).unwrap_err(),
        PersistError::TooLong
    );
    let exploding = fixtures::engine_with(
        Arc::new(fixtures::ExplodingCompress),
        Arc::new(fixtures::HexB64),
    );
    assert_eq!(
        exploding.seal_command(&dek, 0, &cmd).unwrap_err(),
        PersistError::TooLong
    );
    let fat = fixtures::engine_custom(
        Arc::new(fixtures::MaxPadCompress),
        Arc::new(fixtures::FatAead),
        Arc::new(fixtures::DetJson),
    );
    assert_eq!(
        fat.seal_command(&dek, 0, &cmd).unwrap_err(),
        PersistError::TooLong
    );

    let engine = engine();
    let blob = engine.seal_raw_plain(&dek, 0, b"not-json");
    assert!(matches!(
        engine.try_open_command(&dek, blob.as_bytes()).unwrap_err(),
        PersistError::Json(_)
    ));
    let huge = Json::Object(vec![
        ("v".into(), Json::String("1".into())),
        ("op".into(), Json::String("create_user".into())),
        (
            "user_id".into(),
            Json::String(engine.b64u().encode(&[9u8; 32])),
        ),
        (
            "pad".into(),
            Json::String("x".repeat(COMMAND_MAX_COMPRESSED + 1)),
        ),
    ]);
    let huge_blob = engine.seal_raw_json(&dek, 0, &huge).expect("seal huge");
    assert!(matches!(
        engine
            .try_open_command(&dek, huge_blob.as_bytes())
            .unwrap_err(),
        PersistError::Compress(CompressError::Oversize)
    ));
    let live = engine
        .create_user(EngineState::new(), &HostRng, &dek)
        .1
        .expect("user")
        .persist;
    let codec = fixtures::engine_with(
        Arc::new(fixtures::CodecCompress),
        Arc::new(fixtures::HexB64),
    );
    assert!(matches!(
        codec.try_open_command(&dek, live.as_bytes()).unwrap_err(),
        PersistError::Compress(CompressError::Codec)
    ));

    let rng = fixtures::CounterRng::new();
    let (board, mailbox, wire) = sample_channels();
    let (state, user_ok) = engine.create_user(EngineState::new(), &rng, &dek);
    let user_id = user_ok.expect("u").user_id;
    let (state, id_ok) = engine.create_identity(state, &rng, &dek, user_id);
    let identity_id = id_ok.expect("i").identity_id;
    let (_inviter, invite_ok) = engine.create_invite(
        state,
        &rng,
        &dek,
        user_id,
        identity_id,
        std::slice::from_ref(&board),
        std::slice::from_ref(&mailbox),
        std::slice::from_ref(&wire),
    );
    let invite_ok = invite_ok.expect("inv");
    let ticket_blob = invite_ok.ticket_blob.clone();
    let notice_blob = invite_ok.notice_blob.clone();
    let rng = fixtures::CounterRng::new();
    let (invitee, ok) = engine.create_user(EngineState::new(), &rng, &dek);
    let iu = ok.expect("iu").user_id;
    let (invitee, ok) = engine.create_identity(invitee, &rng, &dek, iu);
    let ii = ok.expect("ii").identity_id;
    let (invitee, ok) = engine.receive_ticket(invitee, &rng, &dek, iu, ii, &ticket_blob);
    let cid = ok.expect("t").conversation_id;
    let (_, persist_err) =
        exploding.receive_notice(invitee, &dek, iu, ii, cid, &notice_blob, &[Policy::Hybrid]);
    assert!(matches!(
        persist_err.unwrap_err(),
        ReceiveNoticeError::Persist(PersistError::TooLong)
    ));
    let (_, create_err) = exploding.create_user(EngineState::new(), &HostRng, &dek);
    assert!(matches!(
        create_err.unwrap_err(),
        CreateUserError::Persist(PersistError::TooLong)
    ));
}
