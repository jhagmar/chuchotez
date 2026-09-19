//! EngineState drive, persist round-trip, and fail-closed errors.

use super::{
    ApplyError, Command, Conversation, ConversationId, ConversationPhase, CreateIdentityError,
    CreateInviteError, CreateUserError, DeleteConversationError, DeleteIdentityError,
    DeleteUserError, DirectMessage, DisplayName, EngineState, Failed, IdentityId, Invitee,
    MarkNoticesPinnedError, PersistError, ReceiveNoticeError, ReceiveTicketError,
    SetDisplayNameError, UnsetDisplayNameError, UserId,
};
use crate::protocol::v1::{
    AeadError, AeadKey, Billboard, COMMAND_MAX_COMPRESSED, COMMAND_MAX_PERSIST_LEN,
    COMMAND_SCHEMA_VERSION, CanonicalJsonError, CompressError, DisplayNameError, Engine,
    EnvelopeError, IntakeError, InviteError, Json, Mailbox, NoticeError, fixtures,
};
use crate::protocol::{Policy, RANDOM32_LEN, Random32, Rng};

fn dek() -> AeadKey {
    AeadKey::from_bytes([0x42; RANDOM32_LEN])
}

fn engine() -> Engine {
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

fn sample_keys() -> (
    crate::protocol::v1::IdentityKemKeypair,
    crate::protocol::v1::IdentitySignKeypair,
) {
    (
        crate::protocol::v1::IdentityKemKeypair::from_parts(vec![1], vec![2]),
        crate::protocol::v1::IdentitySignKeypair::from_parts(vec![3], vec![4]),
    )
}

fn conversation(
    state: &EngineState,
    user_id: UserId,
    identity_id: IdentityId,
    conversation_id: ConversationId,
) -> &Conversation {
    Engine::get_conversation(state, user_id, identity_id, conversation_id).expect("conversation")
}

fn inviter_invite(conv: &Conversation) -> &crate::protocol::v1::Invite {
    conv.as_inviter().expect("inviter").invite()
}

fn calling_card_of(conv: &Conversation) -> &super::CallingCard {
    conv.as_invitee().and_then(Invitee::card).expect("card")
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

    let (state, user_id, user_ok) = engine.create_user(EngineState::new(), &rng, &dek);
    let user_ok = user_ok.expect("user");
    assert_eq!(format!("{:?}", user_ok.persist), "PersistedCommand(..)");
    assert!(!user_ok.persist.as_bytes().is_empty());
    let _ = user_ok.persist.clone().into_bytes();

    let (state, identity_id, id_ok) = engine.create_identity(state, &rng, &dek, user_id);
    let id_ok = id_ok.expect("identity");
    let _ = format!("{id_ok:?}");
    assert!(
        state
            .user(&user_id)
            .expect("u")
            .identity(&identity_id)
            .expect("i")
            .display_name()
            .is_none()
    );
    assert_eq!(
        state
            .user(&user_id)
            .expect("u")
            .identity(&identity_id)
            .expect("i")
            .encryption()
            .public_bytes()
            .len(),
        crate::protocol::v1::intake_pk_len(Policy::Hybrid)
    );
    assert_eq!(
        state
            .user(&user_id)
            .expect("u")
            .identity(&identity_id)
            .expect("i")
            .signing()
            .public_bytes()
            .len(),
        crate::protocol::v1::sign_pk_len(Policy::Hybrid)
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
    let tags = {
        let invite = inviter_invite(conversation(&state, user_id, identity_id, conversation_id));
        let _ticket_blob = invite.ticket_blob(&engine);
        let _notice_blob = invite.notice_blob(&engine);
        invite.billboard_tags(&engine)
    };
    assert_eq!(tags.len(), 1);
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
    let (s, uid, ok) = engine.create_user(live, &rng, &dek);
    live = s;
    blobs.push(ok.expect("u").persist.as_bytes().to_vec());
    let (s, iid, ok) = engine.create_identity(live, &rng, &dek, uid);
    live = s;
    blobs.push(ok.expect("i").persist.as_bytes().to_vec());
    let (s, cid, ok) = engine.create_invite(
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
    let (ticket_blob, notice_blob) = {
        let invite = inviter_invite(conversation(&live, uid, iid, cid));
        (invite.ticket_blob(&engine), invite.notice_blob(&engine))
    };
    blobs.push(ok.expect("c").persist.as_bytes().to_vec());
    let (s, ok) = engine.mark_notices_pinned(live, &dek, uid, iid, cid);
    live = s;
    blobs.push(ok.expect("pin").persist.as_bytes().to_vec());

    let mut folded = EngineState::new();
    for blob in &blobs {
        let cmd = engine.try_open_command(&dek, blob).expect("open");
        let (next, result) = Engine::apply(folded, &cmd);
        result.expect("apply");
        folded = next;
    }
    assert_eq!(folded, live);
    assert_eq!(
        inviter_invite(conversation(&folded, uid, iid, cid)).ticket_blob(&engine),
        inviter_invite(conversation(&live, uid, iid, cid)).ticket_blob(&engine)
    );
    assert_eq!(
        inviter_invite(conversation(&folded, uid, iid, cid)).notice_blob(&engine),
        inviter_invite(conversation(&live, uid, iid, cid)).notice_blob(&engine)
    );
    assert_eq!(
        inviter_invite(conversation(&folded, uid, iid, cid)).billboard_tags(&engine),
        inviter_invite(conversation(&live, uid, iid, cid)).billboard_tags(&engine)
    );

    let rng = fixtures::CounterRng::new();
    let (invitee, invitee_user, ok) = engine.create_user(EngineState::new(), &rng, &dek);
    ok.expect("iu");
    let (invitee, invitee_id, ok) = engine.create_identity(invitee, &rng, &dek, invitee_user);
    ok.expect("ii");
    let (invitee, invitee_cid, ok) =
        engine.receive_ticket(invitee, &rng, &dek, invitee_user, invitee_id, &ticket_blob);
    let recv = ok.expect("ticket");
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
    let persist = accepted.persist.clone();
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
    let persist = refused.persist.clone();
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

    let (state, _, err) =
        engine.create_user(EngineState::new().with_command_seq(u64::MAX), &rng, &dek);
    assert_eq!(err.unwrap_err(), CreateUserError::SeqOverflow);
    assert_eq!(state.command_seq(), u64::MAX);

    let (state, user_id, ok) = engine.create_user(EngineState::new(), &HostRng, &dek);
    ok.expect("u");
    let (state, _, err) = engine.create_user(state, &HostRng, &dek);
    assert!(matches!(
        err.unwrap_err(),
        CreateUserError::DuplicateUser(_)
    ));

    let (state, _, err) = engine.create_identity(state.clone(), &rng, &dek, missing_u);
    assert_eq!(
        err.unwrap_err(),
        CreateIdentityError::UnknownUser(missing_u)
    );

    let (state, identity_id, ok) = engine.create_identity(state, &HostRng, &dek, user_id);
    ok.expect("i");
    let (state, _, err) = engine.create_identity(state, &HostRng, &dek, user_id);
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
            .2
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
            .2
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
            .2
            .unwrap_err(),
        CreateInviteError::Invite(InviteError::Ticket(
            crate::protocol::v1::TicketError::EmptyBillboards
        ))
    );

    let (state, cid, invite_ok) = engine.create_invite(
        state,
        &rng,
        &dek,
        user_id,
        identity_id,
        std::slice::from_ref(&board),
        std::slice::from_ref(&mailbox),
        std::slice::from_ref(&wire),
    );
    invite_ok.expect("inv");
    let occupy = ConversationId::from_bytes([1; RANDOM32_LEN]);
    let minted = engine
        .try_new_invite(
            &fixtures::SeedRng(fixtures::fill(0x21)),
            std::slice::from_ref(&board),
            std::slice::from_ref(&mailbox),
            std::slice::from_ref(&wire),
        )
        .expect("mint occupy");
    let (state, occupied) = Engine::apply(
        state,
        &Command::CreateInvite {
            user_id,
            identity_id,
            conversation_id: occupy,
            invite: minted,
        },
    );
    occupied.expect("occupy");
    let (state, _, err) = engine.create_invite(
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
            .2
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
            .2
            .unwrap_err(),
        ReceiveTicketError::DuplicateConversation { .. }
    ));
    assert!(matches!(
        engine
            .receive_ticket(state.clone(), &rng, &dek, missing_u, missing_i, &blob)
            .2
            .unwrap_err(),
        ReceiveTicketError::UnknownUser(_)
    ));
    assert!(matches!(
        engine
            .receive_ticket(state.clone(), &rng, &dek, user_id, missing_i, &blob)
            .2
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

    let (st, tcid, tok) =
        engine.receive_ticket(state.clone(), &rng, &dek, user_id, identity_id, &blob);
    tok.expect("t");
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
            .2
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
            .2
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
            .2
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
    let (state, err) = Engine::apply(
        EngineState::new(),
        &Command::DeleteUser { user_id: missing_u },
    );
    assert_eq!(err.unwrap_err(), ApplyError::UnknownUser(missing_u));
    assert_eq!(state, EngineState::new());

    let (state, _) = Engine::apply(
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
    let (s, _, ok) = engine.create_user(EngineState::new(), &HostRng, &dek);
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
    let (state, _) = Engine::apply(EngineState::new(), &Command::CreateUser { user_id: uid });
    assert!(matches!(
        Engine::apply(state.clone(), &Command::CreateUser { user_id: uid })
            .1
            .unwrap_err(),
        ApplyError::DuplicateUser(_)
    ));
    let (enc, sig) = sample_keys();
    let (state, _) = Engine::apply(
        state,
        &Command::CreateIdentity {
            user_id: uid,
            identity_id: iid,
            encryption: enc.clone(),
            signing: sig.clone(),
        },
    );
    assert!(matches!(
        Engine::apply(
            state.clone(),
            &Command::CreateIdentity {
                user_id: uid,
                identity_id: iid,
                encryption: enc,
                signing: sig,
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
    let (state, ok) = Engine::apply(state, &create);
    ok.expect("first invite");
    assert!(matches!(
        Engine::apply(state.clone(), &create).1.unwrap_err(),
        ApplyError::DuplicateConversation { .. }
    ));
    let recv = Command::ReceiveTicket {
        user_id: uid,
        identity_id: iid,
        conversation_id: cid,
        ticket: invite.ticket().clone(),
    };
    assert!(matches!(
        Engine::apply(state.clone(), &recv).1.unwrap_err(),
        ApplyError::DuplicateConversation { .. }
    ));
    let notice = crate::protocol::v1::Notice::from_intake(Policy::Hybrid, invite.intake());
    assert!(matches!(
        Engine::apply(
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
        Engine::apply(
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
        format!(
            "{}",
            PersistError::CallingCard(crate::protocol::v1::CallingCardError::EmptyMailboxes)
        ),
        format!(
            "{}",
            CreateIdentityError::Kem(crate::protocol::v1::KemError::KeyGen)
        ),
        format!(
            "{}",
            CreateIdentityError::Sign(crate::protocol::v1::SignError::KeyGen)
        ),
        format!("{}", super::CreateCallingCardError::UnsetDisplayName),
        format!(
            "{}",
            super::CreateCallingCardError::CallingCard(
                crate::protocol::v1::CallingCardError::EmptyMailboxes
            )
        ),
        format!(
            "{}",
            super::CreateCallingCardError::Persist(PersistError::TooShort)
        ),
        format!("{}", super::QueryError::UnknownUser(missing_id())),
        format!("{:?}", ConversationPhase::InviteeCallingCardCreated),
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
    assert!(
        std::error::Error::source(&PersistError::CallingCard(
            crate::protocol::v1::CallingCardError::EmptyMailboxes
        ))
        .is_some()
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
            (
                "identity_id".into(),
                Json::String(engine.b64u().encode(&[2u8; 32])),
            ),
        ]),
        Json::Object(vec![
            ("v".into(), Json::String("1".into())),
            ("op".into(), Json::String("create_calling_card".into())),
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
            ("name".into(), Json::String("Ada".into())),
            (
                "encryption_pk".into(),
                Json::String(engine.b64u().encode(&[4u8; 32])),
            ),
            (
                "signing_pk".into(),
                Json::String(engine.b64u().encode(&[5u8; 32])),
            ),
            (
                "mailbox_tag_key".into(),
                Json::String(engine.b64u().encode(&[6u8; 32])),
            ),
            ("mailboxes".into(), Json::Array(Vec::new())),
            ("wires".into(), Json::Array(Vec::new())),
        ]),
        Json::Object(vec![
            ("v".into(), Json::String("1".into())),
            ("op".into(), Json::String("create_calling_card".into())),
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
            ("name".into(), Json::String("Ada".into())),
            (
                "encryption_pk".into(),
                Json::String(engine.b64u().encode(&[4u8; 32])),
            ),
            (
                "signing_pk".into(),
                Json::String(engine.b64u().encode(&[5u8; 32])),
            ),
            (
                "mailbox_tag_key".into(),
                Json::String(engine.b64u().encode(&[6u8; 8])),
            ),
            ("mailboxes".into(), Json::Array(Vec::new())),
            ("wires".into(), Json::Array(Vec::new())),
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
        .2
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
    let (state, user_id, user_ok) = engine.create_user(EngineState::new(), &rng, &dek);
    user_ok.expect("u");
    let (state, identity_id, id_ok) = engine.create_identity(state, &rng, &dek, user_id);
    id_ok.expect("i");
    let (inviter, inviter_cid, invite_ok) = engine.create_invite(
        state,
        &rng,
        &dek,
        user_id,
        identity_id,
        std::slice::from_ref(&board),
        std::slice::from_ref(&mailbox),
        std::slice::from_ref(&wire),
    );
    invite_ok.expect("inv");
    let invite = inviter_invite(conversation(&inviter, user_id, identity_id, inviter_cid));
    let ticket_blob = invite.ticket_blob(&engine);
    let notice_blob = invite.notice_blob(&engine);
    let rng = fixtures::CounterRng::new();
    let (invitee, iu, ok) = engine.create_user(EngineState::new(), &rng, &dek);
    ok.expect("iu");
    let (invitee, ii, ok) = engine.create_identity(invitee, &rng, &dek, iu);
    ok.expect("ii");
    let (invitee, cid, ok) = engine.receive_ticket(invitee, &rng, &dek, iu, ii, &ticket_blob);
    ok.expect("t");
    let (_, persist_err) =
        exploding.receive_notice(invitee, &dek, iu, ii, cid, &notice_blob, &[Policy::Hybrid]);
    assert!(matches!(
        persist_err.unwrap_err(),
        ReceiveNoticeError::Persist(PersistError::TooLong)
    ));
    let (_, _, create_err) = exploding.create_user(EngineState::new(), &HostRng, &dek);
    assert!(matches!(
        create_err.unwrap_err(),
        CreateUserError::Persist(PersistError::TooLong)
    ));
}

#[test]
fn calling_card_mint_getters_and_errors() {
    use super::{CreateCallingCardError, QueryError};
    use crate::protocol::v1::{CallingCardError, MAILBOX_MAX_COUNT, WIRE_MAX_COUNT, sign_pk_len};
    use std::sync::Arc;

    let dek = dek();
    for policy in [Policy::Classic, Policy::PostQuantum, Policy::Hybrid] {
        let engine = fixtures::engine_with_policy(policy);
        let rng = fixtures::CounterRng::new();
        let (state, uid, ok) = engine.create_user(EngineState::new(), &rng, &dek);
        ok.expect("u");
        let (state, iid, ok) = engine.create_identity(state, &rng, &dek, uid);
        ok.expect("i");
        let identity = state.user(&uid).expect("u").identity(&iid).expect("i");
        assert_eq!(
            identity.encryption().public_bytes().len(),
            crate::protocol::v1::intake_pk_len(policy)
        );
        assert_eq!(identity.signing().public_bytes().len(), sign_pk_len(policy));
    }

    let fail_kem = fixtures::engine_with_kem_sign(
        Arc::new(fixtures::FailingKem),
        Arc::new(fixtures::EchoSign),
    );
    let rng = fixtures::CounterRng::new();
    let (state, uid, ok) = fail_kem.create_user(EngineState::new(), &rng, &dek);
    ok.expect("u");
    assert!(matches!(
        fail_kem
            .create_identity(state, &rng, &dek, uid)
            .2
            .unwrap_err(),
        CreateIdentityError::Kem(_)
    ));

    let fail_sign = fixtures::engine_with_kem_sign(
        Arc::new(fixtures::EchoKem),
        Arc::new(fixtures::FailingSign),
    );
    let rng = fixtures::CounterRng::new();
    let (state, uid, ok) = fail_sign.create_user(EngineState::new(), &rng, &dek);
    ok.expect("u");
    assert!(matches!(
        fail_sign
            .create_identity(state, &rng, &dek, uid)
            .2
            .unwrap_err(),
        CreateIdentityError::Sign(_)
    ));

    let engine = engine();
    let rng = fixtures::CounterRng::new();
    let (board, mailbox, wire) = sample_channels();
    let (state, uid, ok) = engine.create_user(EngineState::new(), &rng, &dek);
    ok.expect("u");
    let (state, iid, ok) = engine.create_identity(state, &rng, &dek, uid);
    ok.expect("i");
    let missing_u = missing_id();
    let missing_i = IdentityId::from_bytes([0xee; RANDOM32_LEN]);
    let missing_c = ConversationId::from_bytes([0xdd; RANDOM32_LEN]);

    assert!(matches!(
        engine
            .create_calling_card(
                state.clone(),
                &rng,
                &dek,
                missing_u,
                missing_i,
                missing_c,
                std::slice::from_ref(&mailbox),
                &[]
            )
            .1
            .unwrap_err(),
        CreateCallingCardError::UnknownUser(_)
    ));
    assert!(matches!(
        engine
            .create_calling_card(
                state.clone(),
                &rng,
                &dek,
                uid,
                missing_i,
                missing_c,
                std::slice::from_ref(&mailbox),
                &[]
            )
            .1
            .unwrap_err(),
        CreateCallingCardError::UnknownIdentity { .. }
    ));
    assert!(matches!(
        Engine::get_conversation(&state, missing_u, missing_i, missing_c).unwrap_err(),
        QueryError::UnknownUser(_)
    ));
    assert!(matches!(
        Engine::get_conversation(&state, uid, missing_i, missing_c).unwrap_err(),
        QueryError::UnknownIdentity { .. }
    ));
    assert!(matches!(
        Engine::get_conversation(&state, uid, iid, missing_c).unwrap_err(),
        QueryError::UnknownConversation { .. }
    ));
    assert!(matches!(
        engine
            .create_calling_card(
                state.clone(),
                &rng,
                &dek,
                uid,
                iid,
                missing_c,
                std::slice::from_ref(&mailbox),
                &[]
            )
            .1
            .unwrap_err(),
        CreateCallingCardError::UnknownConversation { .. }
    ));
    assert!(matches!(
        engine
            .create_calling_card(
                state.clone(),
                &rng,
                &dek,
                uid,
                iid,
                missing_c,
                std::slice::from_ref(&mailbox),
                &[]
            )
            .1
            .unwrap_err(),
        CreateCallingCardError::UnknownConversation { .. }
    ));

    let (inviter, inv_cid, ok) = engine.create_invite(
        state.clone(),
        &rng,
        &dek,
        uid,
        iid,
        std::slice::from_ref(&board),
        std::slice::from_ref(&mailbox),
        std::slice::from_ref(&wire),
    );
    ok.expect("inv");
    assert!(matches!(
        engine
            .create_calling_card(
                inviter.clone(),
                &rng,
                &dek,
                uid,
                iid,
                inv_cid,
                std::slice::from_ref(&mailbox),
                &[]
            )
            .1
            .unwrap_err(),
        CreateCallingCardError::UnexpectedPhase {
            found: ConversationPhase::InviterInviteCreated,
            ..
        }
    ));
    assert!(
        conversation(&inviter, uid, iid, inv_cid)
            .as_invitee()
            .and_then(Invitee::card)
            .is_none()
    );
    let invite = inviter_invite(conversation(&inviter, uid, iid, inv_cid));
    let ticket_blob = invite.ticket_blob(&engine);
    let notice_blob = invite.notice_blob(&engine);

    let rng = fixtures::CounterRng::new();
    let (invitee, iu, ok) = engine.create_user(EngineState::new(), &rng, &dek);
    ok.expect("iu");
    let (invitee, ii, ok) = engine.create_identity(invitee, &rng, &dek, iu);
    ok.expect("ii");
    assert_eq!(
        engine
            .create_calling_card(
                invitee.clone(),
                &rng,
                &dek,
                iu,
                ii,
                missing_c,
                std::slice::from_ref(&mailbox),
                &[]
            )
            .1
            .unwrap_err(),
        CreateCallingCardError::UnknownConversation {
            user_id: iu,
            identity_id: ii,
            conversation_id: missing_c,
        }
    );
    let (invitee, cid, ok) = engine.receive_ticket(invitee, &rng, &dek, iu, ii, &ticket_blob);
    ok.expect("ticket");
    assert!(conversation(&invitee, iu, ii, cid).as_inviter().is_none());
    let (invitee, ok) =
        engine.receive_notice(invitee, &dek, iu, ii, cid, &notice_blob, &[Policy::Hybrid]);
    ok.expect("notice");
    assert_eq!(
        engine
            .create_calling_card(
                invitee.clone(),
                &rng,
                &dek,
                iu,
                ii,
                cid,
                std::slice::from_ref(&mailbox),
                &[]
            )
            .1
            .unwrap_err(),
        CreateCallingCardError::UnsetDisplayName
    );
    let name = DisplayName::try_from("Ada").expect("name");
    let (invitee, ok) = engine.set_display_name(invitee, &dek, iu, ii, name.clone());
    ok.expect("set");
    assert_eq!(
        engine
            .create_calling_card(invitee.clone(), &rng, &dek, iu, ii, cid, &[], &[])
            .1
            .unwrap_err(),
        CreateCallingCardError::CallingCard(CallingCardError::EmptyMailboxes)
    );
    let many_m = vec![mailbox.clone(); MAILBOX_MAX_COUNT + 1];
    assert_eq!(
        engine
            .create_calling_card(invitee.clone(), &rng, &dek, iu, ii, cid, &many_m, &[])
            .1
            .unwrap_err(),
        CreateCallingCardError::CallingCard(CallingCardError::TooManyMailboxes)
    );
    let many_w = vec![wire.clone(); WIRE_MAX_COUNT + 1];
    assert_eq!(
        engine
            .create_calling_card(
                invitee.clone(),
                &rng,
                &dek,
                iu,
                ii,
                cid,
                std::slice::from_ref(&mailbox),
                &many_w
            )
            .1
            .unwrap_err(),
        CreateCallingCardError::CallingCard(CallingCardError::TooManyWires)
    );
    assert_eq!(
        engine
            .create_calling_card(
                invitee.clone().with_command_seq(u64::MAX),
                &rng,
                &dek,
                iu,
                ii,
                cid,
                std::slice::from_ref(&mailbox),
                &[]
            )
            .1
            .unwrap_err(),
        CreateCallingCardError::SeqOverflow
    );

    let (minted, ok) = engine.create_calling_card(
        invitee.clone(),
        &rng,
        &dek,
        iu,
        ii,
        cid,
        std::slice::from_ref(&mailbox),
        std::slice::from_ref(&wire),
    );
    let persist = ok.expect("card").persist;
    let cmd = engine
        .try_open_command(&dek, persist.as_bytes())
        .expect("open card");
    assert!(matches!(cmd, Command::CreateCallingCard { .. }));
    assert_eq!(
        minted
            .user(&iu)
            .expect("u")
            .identity(&ii)
            .expect("i")
            .conversation(&cid)
            .expect("c")
            .phase(),
        ConversationPhase::InviteeCallingCardCreated
    );
    let card = calling_card_of(conversation(&minted, iu, ii, cid));
    assert_eq!(card.display_name(), &name);
    assert_eq!(card.mailboxes().len(), 1);
    assert_eq!(card.wires().len(), 1);
    let enc_pk = minted
        .user(&iu)
        .expect("u")
        .identity(&ii)
        .expect("i")
        .encryption()
        .public_bytes();
    assert_eq!(card.encryption_pk(), enc_pk);

    let cmd = engine
        .try_open_command(&dek, persist.as_bytes())
        .expect("reopen");
    let (hydrated, result) = Engine::apply(invitee, &cmd);
    result.expect("apply card");
    assert_eq!(
        calling_card_of(conversation(&hydrated, iu, ii, cid)),
        calling_card_of(conversation(&minted, iu, ii, cid))
    );

    let (unset, ok) = engine.unset_display_name(minted.clone(), &dek, iu, ii);
    ok.expect("unset");
    assert!(
        unset
            .user(&iu)
            .expect("u")
            .identity(&ii)
            .expect("i")
            .display_name()
            .is_none()
    );
    let card_after = calling_card_of(conversation(&unset, iu, ii, cid));
    assert_eq!(card_after.display_name(), &name);

    let (enc, sig) = sample_keys();
    let (state, _) = Engine::apply(EngineState::new(), &Command::CreateUser { user_id: uid });
    let (state, _) = Engine::apply(
        state,
        &Command::CreateIdentity {
            user_id: uid,
            identity_id: iid,
            encryption: enc,
            signing: sig,
        },
    );
    let card = crate::protocol::v1::CallingCard::from_parts(
        name,
        vec![1],
        vec![2],
        crate::protocol::v1::MailboxTagKey::from_bytes([9; RANDOM32_LEN]),
        vec![mailbox],
        Vec::new(),
    )
    .expect("parts");
    assert!(matches!(
        Engine::apply(
            inviter,
            &Command::CreateCallingCard {
                user_id: uid,
                identity_id: iid,
                conversation_id: inv_cid,
                card: card.clone(),
            },
        )
        .1
        .unwrap_err(),
        ApplyError::UnexpectedPhase {
            found: ConversationPhase::InviterInviteCreated,
            ..
        }
    ));
    assert!(matches!(
        Engine::apply(
            state,
            &Command::CreateCallingCard {
                user_id: uid,
                identity_id: iid,
                conversation_id: missing_c,
                card,
            },
        )
        .1
        .unwrap_err(),
        ApplyError::UnknownConversation { .. }
    ));

    let _ = format!("{}", CreateCallingCardError::UnknownUser(missing_u));
    let _ = format!(
        "{}",
        CreateCallingCardError::UnknownIdentity {
            user_id: missing_u,
            identity_id: missing_i,
        }
    );
    let _ = format!(
        "{}",
        QueryError::UnknownIdentity {
            user_id: missing_u,
            identity_id: missing_i,
        }
    );
    let _ = format!(
        "{}",
        QueryError::UnknownConversation {
            user_id: missing_u,
            identity_id: missing_i,
            conversation_id: missing_c,
        }
    );
    let _ = &CreateCallingCardError::UnsetDisplayName as &dyn std::error::Error;
    let _ = &QueryError::UnknownUser(missing_u) as &dyn std::error::Error;
}
