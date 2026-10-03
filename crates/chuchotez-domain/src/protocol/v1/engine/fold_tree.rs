//! Fold snapshot of the user and device conversation trees.

use super::super::chain::{CachedMk, chain_from_json, chain_to_json};
use super::super::codec::{ticket_from_json, ticket_to_json};
use super::super::kem::KeyPair;
use super::super::payload::{Ticket, parse_policy, policy_str};
use super::super::sign::SigningKeyPair;
use super::super::{
    ActorId, Base64Url, ConversationId, DisplayName, EngineError, IdentityId, Json, ProfilePic,
    Secret, Tag, TimeBin, UserId,
};
use super::helpers::{decode_fold_bstr, decode_fold32, keypair_json, parse_fold_keypair};
use super::party::{
    DeviceConversation, DmParty, HandshakeFailure, IdentityConversation, InviteePhase,
    InviterPhase, SyncParty,
};
use super::state::{ConversationChains, Device, DeviceKeys, DeviceNode, EngineState, IdentityNode};
use std::collections::BTreeSet;

pub(super) fn users_json(b64u: &dyn Base64Url, state: &EngineState) -> Json {
    let mut users = Vec::new();
    for (uid, user) in &state.users {
        let mut identities = Vec::new();
        for (iid, ident) in &user.identities {
            let mut conversations = Vec::new();
            for (cid, node) in &ident.conversations {
                conversations.push(identity_conv_json(b64u, *cid, node));
            }
            identities.push(Json::Object(vec![
                ("identity_id".into(), bstr(b64u, iid.as_bytes())),
                (
                    "name".into(),
                    ident
                        .name
                        .as_ref()
                        .map(|n| Json::String(n.as_str().into()))
                        .unwrap_or(Json::Null),
                ),
                (
                    "pic".into(),
                    ident
                        .pic
                        .as_ref()
                        .map(|p| bstr(b64u, p.as_bytes()))
                        .unwrap_or(Json::Null),
                ),
                ("conversations".into(), Json::Array(conversations)),
            ]));
        }
        users.push(Json::Object(vec![
            ("user_id".into(), bstr(b64u, uid.as_bytes())),
            ("identities".into(), Json::Array(identities)),
        ]));
    }
    Json::Array(users)
}

pub(super) fn device_json(b64u: &dyn Base64Url, device: &Device) -> Json {
    let mut conversations = Vec::new();
    for (cid, node) in &device.conversations {
        conversations.push(device_conv_json(b64u, *cid, node));
    }
    let mut members = vec![
        (
            "name".into(),
            device
                .name
                .as_ref()
                .map(|n| Json::String(n.as_str().into()))
                .unwrap_or(Json::Null),
        ),
        (
            "keys".into(),
            device
                .keys
                .as_ref()
                .map(|k| keys_json(b64u, k))
                .unwrap_or(Json::Null),
        ),
        ("conversations".into(), Json::Array(conversations)),
    ];
    if let Some(ct) = &device.dek_ct {
        members.push(("dek_ct".into(), bstr(b64u, ct)));
    }
    Json::Object(members)
}

pub(super) fn install_users(
    b64u: &dyn Base64Url,
    state: &mut EngineState,
    value: &Json,
) -> Result<(), EngineError> {
    let Json::Array(users) = value else {
        return Err(EngineError::MalformedPersist);
    };
    for user in users {
        let Json::Object(m) = user else {
            return Err(EngineError::MalformedPersist);
        };
        let uid = UserId::from_bytes(decode_fold32(b64u, field(m, "user_id")?)?);
        let Json::Array(identities) = field(m, "identities")? else {
            return Err(EngineError::MalformedPersist);
        };
        for ident in identities {
            let Json::Object(im) = ident else {
                return Err(EngineError::MalformedPersist);
            };
            let iid = IdentityId::from_bytes(decode_fold32(b64u, field(im, "identity_id")?)?);
            let row = state.ensure_identity(uid, iid);
            row.name = match field(im, "name")? {
                Json::Null => None,
                Json::String(s) => Some(
                    DisplayName::try_from(s.as_str()).map_err(|_| EngineError::MalformedPersist)?,
                ),
                _ => return Err(EngineError::MalformedPersist),
            };
            row.pic = match field(im, "pic")? {
                Json::Null => None,
                other => Some(
                    ProfilePic::try_from(decode_fold_bstr(b64u, other)?.as_slice())
                        .map_err(|_| EngineError::MalformedPersist)?,
                ),
            };
            let Json::Array(conversations) = field(im, "conversations")? else {
                return Err(EngineError::MalformedPersist);
            };
            for conv in conversations {
                let (cid, node) = parse_identity_conv(b64u, conv)?;
                state.put_dm(uid, iid, cid, node);
            }
        }
    }
    Ok(())
}

pub(super) fn install_device(
    b64u: &dyn Base64Url,
    state: &mut EngineState,
    value: &Json,
) -> Result<(), EngineError> {
    let Json::Object(m) = value else {
        return Err(EngineError::MalformedPersist);
    };
    state.device.name = match field(m, "name")? {
        Json::Null => None,
        Json::String(s) => {
            Some(DisplayName::try_from(s.as_str()).map_err(|_| EngineError::MalformedPersist)?)
        }
        _ => return Err(EngineError::MalformedPersist),
    };
    state.device.keys = match field(m, "keys")? {
        Json::Null => None,
        other => Some(parse_keys(b64u, other)?),
    };
    state.device.dek_ct = match m.iter().find(|(key, _)| key == "dek_ct") {
        Some((_, Json::String(s))) => {
            Some(b64u.decode(s).map_err(|_| EngineError::MalformedPersist)?)
        }
        Some(_) => return Err(EngineError::MalformedPersist),
        None => None,
    };
    let Json::Array(conversations) = field(m, "conversations")? else {
        return Err(EngineError::MalformedPersist);
    };
    for conv in conversations {
        let (cid, node) = parse_device_conv(b64u, conv)?;
        state.put_sync(cid, node);
    }
    Ok(())
}

fn keys_json(b64u: &dyn Base64Url, keys: &DeviceKeys) -> Json {
    Json::Object(vec![
        (
            "id".into(),
            keys.id
                .map(|id| bstr(b64u, id.as_bytes()))
                .unwrap_or(Json::Null),
        ),
        (
            "enc".into(),
            keypair_json(b64u, keys.enc.public_bytes(), keys.enc.secret_bytes()),
        ),
        (
            "sign".into(),
            keypair_json(b64u, keys.sign.public_bytes(), keys.sign.secret_bytes()),
        ),
    ])
}

fn parse_keys(b64u: &dyn Base64Url, value: &Json) -> Result<DeviceKeys, EngineError> {
    let Json::Object(m) = value else {
        return Err(EngineError::MalformedPersist);
    };
    let id = match field(m, "id")? {
        Json::Null => None,
        other => Some(super::super::DeviceId::from_bytes(decode_fold32(
            b64u, other,
        )?)),
    };
    let (epk, esk) = parse_fold_keypair(b64u, field(m, "enc")?)?;
    let (spk, ssk) = parse_fold_keypair(b64u, field(m, "sign")?)?;
    Ok(DeviceKeys {
        id,
        enc: KeyPair::from_parts(epk, esk),
        sign: SigningKeyPair::from_parts(spk, ssk),
    })
}

fn identity_conv_json(b64u: &dyn Base64Url, cid: ConversationId, node: &IdentityNode) -> Json {
    let mut members = vec![
        ("conversation_id".into(), bstr(b64u, cid.as_bytes())),
        match &node.kind {
            IdentityConversation::DmHandshake(party) => {
                ("handshake".into(), party_json(b64u, party_of_dm(party)))
            }
            IdentityConversation::DirectMessage { secret, parent } => (
                "direct_message".into(),
                Json::Object(vec![
                    ("secret".into(), bstr(b64u, secret.as_bytes())),
                    ("parent".into(), bstr(b64u, parent.as_bytes())),
                ]),
            ),
            IdentityConversation::Group(phase) => {
                ("group".into(), super::group::group_json(b64u, phase))
            }
        },
    ];
    members.extend(chains_json(b64u, cid, &node.chains));
    Json::Object(members)
}

fn device_conv_json(b64u: &dyn Base64Url, cid: ConversationId, node: &DeviceNode) -> Json {
    let mut members = vec![
        ("conversation_id".into(), bstr(b64u, cid.as_bytes())),
        match &node.kind {
            DeviceConversation::SyncHandshake(party) => {
                ("handshake".into(), party_json(b64u, party_of_sync(party)))
            }
            DeviceConversation::Synchronization { secret, parent } => (
                "synchronization".into(),
                Json::Object(vec![
                    ("secret".into(), bstr(b64u, secret.as_bytes())),
                    ("parent".into(), bstr(b64u, parent.as_bytes())),
                ]),
            ),
        },
    ];
    members.extend(chains_json(b64u, cid, &node.chains));
    Json::Object(members)
}

enum PartyView<'a> {
    Inviter(&'a InviterPhase),
    Invitee(&'a InviteePhase),
}

fn party_of_dm(party: &DmParty) -> PartyView<'_> {
    match party {
        DmParty::Inviter(p) => PartyView::Inviter(p),
        DmParty::Invitee(p) => PartyView::Invitee(p),
    }
}

fn party_of_sync(party: &SyncParty) -> PartyView<'_> {
    match party {
        SyncParty::Inviter(p) => PartyView::Inviter(p),
        SyncParty::Invitee(p) => PartyView::Invitee(p),
    }
}

fn party_json(b64u: &dyn Base64Url, party: PartyView<'_>) -> Json {
    match party {
        PartyView::Inviter(p) => inviter_json(b64u, p),
        PartyView::Invitee(p) => invitee_json(b64u, p),
    }
}

fn inviter_json(b64u: &dyn Base64Url, phase: &InviterPhase) -> Json {
    let (name, ticket, intake, list_from, shared_inviter, shared_invitee, failure) = match phase {
        InviterPhase::InviteCreated {
            ticket,
            intake,
            list_from,
        } => (
            "invite-created",
            ticket,
            Some(intake),
            *list_from,
            None,
            None,
            None,
        ),
        InviterPhase::NoticePinned {
            ticket,
            intake,
            list_from,
        } => (
            "notice-pinned",
            ticket,
            Some(intake),
            *list_from,
            None,
            None,
            None,
        ),
        InviterPhase::IntroductionMinted {
            ticket,
            intake,
            shared_inviter,
            shared_invitee,
            list_from,
        } => (
            "introduction-minted",
            ticket,
            Some(intake),
            *list_from,
            Some(shared_inviter),
            Some(shared_invitee),
            None,
        ),
        InviterPhase::Confirming {
            ticket,
            intake,
            shared_inviter,
            shared_invitee,
            list_from,
        } => (
            "confirming",
            ticket,
            Some(intake),
            *list_from,
            Some(shared_inviter),
            Some(shared_invitee),
            None,
        ),
        InviterPhase::Failed {
            ticket,
            list_from,
            reason,
        } => (
            "failed",
            ticket,
            None,
            *list_from,
            None,
            None,
            Some(*reason),
        ),
    };
    phase_json(
        b64u,
        "inviter",
        name,
        ticket,
        intake,
        list_from,
        None,
        shared_inviter,
        shared_invitee,
        failure,
    )
}

fn invitee_json(b64u: &dyn Base64Url, phase: &InviteePhase) -> Json {
    let (name, ticket, intake, list_from, policy, shared_inviter, shared_invitee, failure) =
        match phase {
            InviteePhase::TicketReceived { ticket, list_from } => (
                "ticket-received",
                ticket,
                None,
                *list_from,
                None,
                None,
                None,
                None,
            ),
            InviteePhase::InviteReceived {
                ticket,
                list_from,
                policy,
            } => (
                "invite-received",
                ticket,
                None,
                *list_from,
                Some(*policy),
                None,
                None,
                None,
            ),
            InviteePhase::IntroductionMinted {
                ticket,
                list_from,
                policy,
                intake,
                shared_inviter,
            } => (
                "introduction-minted",
                ticket,
                Some(intake),
                *list_from,
                Some(*policy),
                Some(shared_inviter),
                None,
                None,
            ),
            InviteePhase::IntroductionSent {
                ticket,
                list_from,
                policy,
                intake,
                shared_inviter,
            } => (
                "introduction-sent",
                ticket,
                Some(intake),
                *list_from,
                Some(*policy),
                Some(shared_inviter),
                None,
                None,
            ),
            InviteePhase::Confirming {
                ticket,
                list_from,
                policy,
                intake,
                shared_inviter,
                shared_invitee,
            } => (
                "confirming",
                ticket,
                Some(intake),
                *list_from,
                Some(*policy),
                Some(shared_inviter),
                Some(shared_invitee),
                None,
            ),
            InviteePhase::Failed {
                ticket,
                list_from,
                reason,
            } => (
                "failed",
                ticket,
                None,
                *list_from,
                None,
                None,
                None,
                Some(*reason),
            ),
        };
    phase_json(
        b64u,
        "invitee",
        name,
        ticket,
        intake,
        list_from,
        policy,
        shared_inviter,
        shared_invitee,
        failure,
    )
}

#[allow(clippy::too_many_arguments)]
fn phase_json(
    b64u: &dyn Base64Url,
    role: &str,
    phase: &str,
    ticket: &Ticket,
    intake: Option<&KeyPair>,
    list_from: TimeBin,
    policy: Option<super::super::Policy>,
    shared_inviter: Option<&Secret>,
    shared_invitee: Option<&Secret>,
    failure: Option<HandshakeFailure>,
) -> Json {
    let mut members = vec![
        ("role".into(), Json::String(role.into())),
        ("phase".into(), Json::String(phase.into())),
        ("ticket".into(), ticket_to_json(b64u, ticket)),
        ("list_from".into(), Json::Number(list_from.as_u64())),
    ];
    if let Some(intake) = intake {
        members.push((
            "intake".into(),
            keypair_json(b64u, intake.public_bytes(), intake.secret_bytes()),
        ));
    }
    if let Some(policy) = policy {
        members.push(("policy".into(), Json::String(policy_str(policy).into())));
    }
    if let Some(secret) = shared_inviter {
        members.push(("shared_inviter".into(), bstr(b64u, secret.as_bytes())));
    }
    if let Some(secret) = shared_invitee {
        members.push(("shared_invitee".into(), bstr(b64u, secret.as_bytes())));
    }
    if let Some(reason) = failure {
        members.push(("failure".into(), failure_json(reason)));
    }
    Json::Object(members)
}

fn failure_json(reason: HandshakeFailure) -> Json {
    let name = match reason {
        HandshakeFailure::PolicyNotAccepted { .. } => "PolicyNotAccepted",
        HandshakeFailure::InviteExpired { .. } => "InviteExpired",
        HandshakeFailure::NoticeUnlockFailed => "NoticeUnlockFailed",
        HandshakeFailure::NoticeConflict => "NoticeConflict",
        HandshakeFailure::IntroUnlockFailed => "IntroUnlockFailed",
        HandshakeFailure::IntroVerifyFailed => "IntroVerifyFailed",
        HandshakeFailure::DuplicateIntro => "DuplicateIntro",
        HandshakeFailure::ConfirmationRejected => "ConfirmationRejected",
        HandshakeFailure::Equivocation => "Equivocation",
    };
    let mut members = vec![("reason".into(), Json::String(name.into()))];
    match reason {
        HandshakeFailure::PolicyNotAccepted { policy } => {
            members.push(("policy".into(), Json::String(policy_str(policy).into())));
        }
        HandshakeFailure::InviteExpired { expires } => {
            members.push(("expires".into(), Json::Number(expires.as_u64())));
        }
        _ => {}
    }
    Json::Object(members)
}

fn chains_json(
    b64u: &dyn Base64Url,
    cid: ConversationId,
    chains: &ConversationChains,
) -> Vec<(String, Json)> {
    let send: Vec<_> = chains
        .send
        .iter()
        .map(|(actor, chain)| chain_to_json(b64u, cid, actor, chain))
        .collect();
    let recv: Vec<_> = chains
        .recv
        .iter()
        .map(|(actor, chain)| chain_to_json(b64u, cid, actor, chain))
        .collect();
    let mut skipped = Vec::new();
    for (actor, entries) in &chains.skipped_mks {
        let mks: Vec<_> = entries
            .iter()
            .map(|e| {
                Json::Object(vec![
                    ("mk".into(), bstr(b64u, &e.mk)),
                    ("expires_at".into(), Json::Number(e.expires_at.as_u64())),
                    (
                        "tx_id".into(),
                        e.tx_id
                            .map(|id| bstr(b64u, id.as_bytes()))
                            .unwrap_or(Json::Null),
                    ),
                ])
            })
            .collect();
        skipped.push(Json::Object(vec![
            ("actor_id".into(), bstr(b64u, actor.as_bytes())),
            ("mks".into(), Json::Array(mks)),
        ]));
    }
    let mut last_acks = Vec::new();
    for (actor, ids) in &chains.last_acks {
        last_acks.push(Json::Object(vec![
            ("actor_id".into(), bstr(b64u, actor.as_bytes())),
            (
                "tx_ids".into(),
                Json::Array(ids.iter().map(|id| bstr(b64u, id.as_bytes())).collect()),
            ),
        ]));
    }
    vec![
        ("chains".into(), Json::Array(send)),
        ("recv_chains".into(), Json::Array(recv)),
        ("skipped_mks".into(), Json::Array(skipped)),
        ("last_acks".into(), Json::Array(last_acks)),
        ("ratchet".into(), ratchet_json(b64u, &chains.ratchet)),
    ]
}

fn ratchet_json(b64u: &dyn Base64Url, ratchet: &super::state::Ratchet) -> Json {
    let minted = ratchet
        .minted
        .iter()
        .map(|id| bstr(b64u, id.as_bytes()))
        .collect();
    let unused = ratchet
        .unused
        .iter()
        .map(|sk| {
            Json::Object(vec![
                ("tx_id".into(), bstr(b64u, sk.tx_id.as_bytes())),
                ("pk".into(), bstr(b64u, &sk.pk)),
                ("sk".into(), bstr(b64u, &sk.sk)),
            ])
        })
        .collect();
    let known = ratchet
        .known
        .iter()
        .map(|row| {
            Json::Object(vec![
                ("wrap_tx".into(), bstr(b64u, row.wrap_tx.as_bytes())),
                ("shared".into(), bstr(b64u, row.shared.as_bytes())),
                ("ct_hash".into(), bstr(b64u, row.ct_hash.as_bytes())),
                ("from_us".into(), Json::Bool(row.from_us)),
                ("encaps_pk".into(), bstr(b64u, &row.encaps_pk)),
            ])
        })
        .collect();
    Json::Object(vec![
        ("since".into(), Json::Number(ratchet.since)),
        ("minted".into(), Json::Array(minted)),
        ("unused".into(), Json::Array(unused)),
        ("known".into(), Json::Array(known)),
    ])
}

fn parse_identity_conv(
    b64u: &dyn Base64Url,
    value: &Json,
) -> Result<(ConversationId, IdentityNode), EngineError> {
    let Json::Object(m) = value else {
        return Err(EngineError::MalformedPersist);
    };
    let cid = ConversationId::from_bytes(decode_fold32(b64u, field(m, "conversation_id")?)?);
    let chains = parse_chains(b64u, m)?;
    let kind = if let Some(hs) = optional(m, "handshake") {
        IdentityConversation::DmHandshake(parse_dm_party(b64u, hs)?)
    } else if let Some(dm) = optional(m, "direct_message") {
        let Json::Object(d) = dm else {
            return Err(EngineError::MalformedPersist);
        };
        IdentityConversation::DirectMessage {
            secret: Secret::from_bytes(decode_fold32(b64u, field(d, "secret")?)?),
            parent: ConversationId::from_bytes(decode_fold32(b64u, field(d, "parent")?)?),
        }
    } else if let Some(group) = optional(m, "group") {
        IdentityConversation::Group(super::group::parse_group(b64u, group)?)
    } else {
        return Err(EngineError::MalformedPersist);
    };
    Ok((cid, IdentityNode { kind, chains }))
}

fn parse_device_conv(
    b64u: &dyn Base64Url,
    value: &Json,
) -> Result<(ConversationId, DeviceNode), EngineError> {
    let Json::Object(m) = value else {
        return Err(EngineError::MalformedPersist);
    };
    let cid = ConversationId::from_bytes(decode_fold32(b64u, field(m, "conversation_id")?)?);
    let chains = parse_chains(b64u, m)?;
    let kind = if let Some(hs) = optional(m, "handshake") {
        DeviceConversation::SyncHandshake(parse_sync_party(b64u, hs)?)
    } else if let Some(sync) = optional(m, "synchronization") {
        let Json::Object(d) = sync else {
            return Err(EngineError::MalformedPersist);
        };
        DeviceConversation::Synchronization {
            secret: Secret::from_bytes(decode_fold32(b64u, field(d, "secret")?)?),
            parent: ConversationId::from_bytes(decode_fold32(b64u, field(d, "parent")?)?),
        }
    } else {
        return Err(EngineError::MalformedPersist);
    };
    Ok((cid, DeviceNode { kind, chains }))
}

fn parse_dm_party(b64u: &dyn Base64Url, value: &Json) -> Result<DmParty, EngineError> {
    match parse_role_phase(b64u, value)? {
        ParsedParty::Inviter(p) => Ok(DmParty::Inviter(p)),
        ParsedParty::Invitee(p) => Ok(DmParty::Invitee(p)),
    }
}

fn parse_sync_party(b64u: &dyn Base64Url, value: &Json) -> Result<SyncParty, EngineError> {
    match parse_role_phase(b64u, value)? {
        ParsedParty::Inviter(p) => Ok(SyncParty::Inviter(p)),
        ParsedParty::Invitee(p) => Ok(SyncParty::Invitee(p)),
    }
}

enum ParsedParty {
    Inviter(InviterPhase),
    Invitee(InviteePhase),
}

fn parse_role_phase(b64u: &dyn Base64Url, value: &Json) -> Result<ParsedParty, EngineError> {
    let Json::Object(m) = value else {
        return Err(EngineError::MalformedPersist);
    };
    let Json::String(role) = field(m, "role")? else {
        return Err(EngineError::MalformedPersist);
    };
    let Json::String(phase) = field(m, "phase")? else {
        return Err(EngineError::MalformedPersist);
    };
    let ticket =
        ticket_from_json(b64u, field(m, "ticket")?).map_err(|_| EngineError::MalformedPersist)?;
    let Json::Number(list_from) = field(m, "list_from")? else {
        return Err(EngineError::MalformedPersist);
    };
    let list_from = TimeBin::from_u64(*list_from);
    let intake = match optional(m, "intake") {
        Some(v) => {
            let (pk, sk) = parse_fold_keypair(b64u, v)?;
            Some(KeyPair::from_parts(pk, sk))
        }
        None => None,
    };
    let policy = match optional(m, "policy") {
        Some(Json::String(s)) => Some(parse_policy(s).ok_or(EngineError::MalformedPersist)?),
        Some(_) => return Err(EngineError::MalformedPersist),
        None => None,
    };
    let shared_inviter = optional_secret(b64u, m, "shared_inviter")?;
    let shared_invitee = optional_secret(b64u, m, "shared_invitee")?;
    let failure = match optional(m, "failure") {
        Some(v) => Some(parse_failure(v)?),
        None => None,
    };
    if role == "inviter" {
        let phase = match phase.as_str() {
            "invite-created" => InviterPhase::InviteCreated {
                ticket,
                intake: intake.ok_or(EngineError::MalformedPersist)?,
                list_from,
            },
            "notice-pinned" => InviterPhase::NoticePinned {
                ticket,
                intake: intake.ok_or(EngineError::MalformedPersist)?,
                list_from,
            },
            "introduction-minted" => InviterPhase::IntroductionMinted {
                ticket,
                intake: intake.ok_or(EngineError::MalformedPersist)?,
                shared_inviter: shared_inviter.ok_or(EngineError::MalformedPersist)?,
                shared_invitee: shared_invitee.ok_or(EngineError::MalformedPersist)?,
                list_from,
            },
            "confirming" => InviterPhase::Confirming {
                ticket,
                intake: intake.ok_or(EngineError::MalformedPersist)?,
                shared_inviter: shared_inviter.ok_or(EngineError::MalformedPersist)?,
                shared_invitee: shared_invitee.ok_or(EngineError::MalformedPersist)?,
                list_from,
            },
            "failed" => InviterPhase::Failed {
                ticket,
                list_from,
                reason: failure.ok_or(EngineError::MalformedPersist)?,
            },
            _ => return Err(EngineError::MalformedPersist),
        };
        Ok(ParsedParty::Inviter(phase))
    } else if role == "invitee" {
        let phase = match phase.as_str() {
            "ticket-received" => InviteePhase::TicketReceived { ticket, list_from },
            "invite-received" => InviteePhase::InviteReceived {
                ticket,
                list_from,
                policy: policy.ok_or(EngineError::MalformedPersist)?,
            },
            "introduction-minted" => InviteePhase::IntroductionMinted {
                ticket,
                list_from,
                policy: policy.ok_or(EngineError::MalformedPersist)?,
                intake: intake.ok_or(EngineError::MalformedPersist)?,
                shared_inviter: shared_inviter.ok_or(EngineError::MalformedPersist)?,
            },
            "introduction-sent" => InviteePhase::IntroductionSent {
                ticket,
                list_from,
                policy: policy.ok_or(EngineError::MalformedPersist)?,
                intake: intake.ok_or(EngineError::MalformedPersist)?,
                shared_inviter: shared_inviter.ok_or(EngineError::MalformedPersist)?,
            },
            "confirming" => InviteePhase::Confirming {
                ticket,
                list_from,
                policy: policy.ok_or(EngineError::MalformedPersist)?,
                intake: intake.ok_or(EngineError::MalformedPersist)?,
                shared_inviter: shared_inviter.ok_or(EngineError::MalformedPersist)?,
                shared_invitee: shared_invitee.ok_or(EngineError::MalformedPersist)?,
            },
            "failed" => InviteePhase::Failed {
                ticket,
                list_from,
                reason: failure.ok_or(EngineError::MalformedPersist)?,
            },
            _ => return Err(EngineError::MalformedPersist),
        };
        Ok(ParsedParty::Invitee(phase))
    } else {
        Err(EngineError::MalformedPersist)
    }
}

fn parse_failure(value: &Json) -> Result<HandshakeFailure, EngineError> {
    let Json::Object(m) = value else {
        return Err(EngineError::MalformedPersist);
    };
    let Json::String(reason) = field(m, "reason")? else {
        return Err(EngineError::MalformedPersist);
    };
    Ok(match reason.as_str() {
        "PolicyNotAccepted" => {
            let Json::String(p) = field(m, "policy")? else {
                return Err(EngineError::MalformedPersist);
            };
            HandshakeFailure::PolicyNotAccepted {
                policy: parse_policy(p).ok_or(EngineError::MalformedPersist)?,
            }
        }
        "InviteExpired" => {
            let Json::Number(n) = field(m, "expires")? else {
                return Err(EngineError::MalformedPersist);
            };
            HandshakeFailure::InviteExpired {
                expires: super::super::UnixSeconds::from_u64(*n),
            }
        }
        "NoticeUnlockFailed" => HandshakeFailure::NoticeUnlockFailed,
        "NoticeConflict" => HandshakeFailure::NoticeConflict,
        "IntroUnlockFailed" => HandshakeFailure::IntroUnlockFailed,
        "IntroVerifyFailed" => HandshakeFailure::IntroVerifyFailed,
        "DuplicateIntro" => HandshakeFailure::DuplicateIntro,
        "ConfirmationRejected" => HandshakeFailure::ConfirmationRejected,
        "Equivocation" => HandshakeFailure::Equivocation,
        _ => return Err(EngineError::MalformedPersist),
    })
}

fn parse_chains(
    b64u: &dyn Base64Url,
    m: &[(String, Json)],
) -> Result<ConversationChains, EngineError> {
    let mut chains = ConversationChains::default();
    if let Some(Json::Array(items)) = optional(m, "chains") {
        for item in items {
            let (_, actor, chain) = chain_from_json(b64u, item)?;
            chains.send.insert(actor, chain);
        }
    } else if optional(m, "chains").is_some() {
        return Err(EngineError::MalformedPersist);
    }
    if let Some(Json::Array(items)) = optional(m, "recv_chains") {
        for item in items {
            let (_, actor, chain) = chain_from_json(b64u, item)?;
            chains.recv.insert(actor, chain);
        }
    } else if optional(m, "recv_chains").is_some() {
        return Err(EngineError::MalformedPersist);
    }
    if let Some(Json::Array(items)) = optional(m, "skipped_mks") {
        for item in items {
            let Json::Object(sm) = item else {
                return Err(EngineError::MalformedPersist);
            };
            let actor = ActorId::from_bytes(decode_fold_bstr(b64u, field(sm, "actor_id")?)?);
            let Json::Array(mks) = field(sm, "mks")? else {
                return Err(EngineError::MalformedPersist);
            };
            let mut entries = Vec::new();
            for mk in mks {
                let Json::Object(mm) = mk else {
                    return Err(EngineError::MalformedPersist);
                };
                let mk_v = decode_fold32(b64u, field(mm, "mk")?)?;
                let Json::Number(expires_at) = field(mm, "expires_at")? else {
                    return Err(EngineError::MalformedPersist);
                };
                let tx_id = match optional(mm, "tx_id") {
                    None | Some(Json::Null) => None,
                    Some(v) => Some(Tag::from_bytes(decode_fold32(b64u, v)?)),
                };
                entries.push(CachedMk {
                    mk: mk_v,
                    expires_at: super::super::UnixSeconds::from_u64(*expires_at),
                    tx_id,
                });
            }
            chains.skipped_mks.insert(actor, entries);
        }
    } else if optional(m, "skipped_mks").is_some() {
        return Err(EngineError::MalformedPersist);
    }
    if let Some(Json::Array(items)) = optional(m, "last_acks") {
        for item in items {
            let Json::Object(am) = item else {
                return Err(EngineError::MalformedPersist);
            };
            let actor = ActorId::from_bytes(decode_fold_bstr(b64u, field(am, "actor_id")?)?);
            let Json::Array(ids_v) = field(am, "tx_ids")? else {
                return Err(EngineError::MalformedPersist);
            };
            let mut ids = BTreeSet::new();
            for id in ids_v {
                ids.insert(Tag::from_bytes(decode_fold32(b64u, id)?));
            }
            chains.last_acks.insert(actor, ids);
        }
    } else if optional(m, "last_acks").is_some() {
        return Err(EngineError::MalformedPersist);
    }
    if let Some(value) = optional(m, "ratchet") {
        chains.ratchet = parse_ratchet(b64u, value)?;
    }
    Ok(chains)
}

fn parse_ratchet(b64u: &dyn Base64Url, value: &Json) -> Result<super::state::Ratchet, EngineError> {
    let Json::Object(m) = value else {
        return Err(EngineError::MalformedPersist);
    };
    let Json::Number(since) = field(m, "since")? else {
        return Err(EngineError::MalformedPersist);
    };
    let Json::Array(minted_v) = field(m, "minted")? else {
        return Err(EngineError::MalformedPersist);
    };
    let mut minted = BTreeSet::new();
    for id in minted_v {
        minted.insert(Tag::from_bytes(decode_fold32(b64u, id)?));
    }
    let Json::Array(unused_v) = field(m, "unused")? else {
        return Err(EngineError::MalformedPersist);
    };
    let mut unused = Vec::new();
    for item in unused_v {
        let Json::Object(row) = item else {
            return Err(EngineError::MalformedPersist);
        };
        unused.push(super::state::UnusedSk {
            tx_id: Tag::from_bytes(decode_fold32(b64u, field(row, "tx_id")?)?),
            pk: decode_fold_bstr(b64u, field(row, "pk")?)?,
            sk: decode_fold_bstr(b64u, field(row, "sk")?)?,
        });
    }
    let Json::Array(known_v) = field(m, "known")? else {
        return Err(EngineError::MalformedPersist);
    };
    let mut known = Vec::new();
    for item in known_v {
        let Json::Object(row) = item else {
            return Err(EngineError::MalformedPersist);
        };
        let Json::Bool(from_us) = field(row, "from_us")? else {
            return Err(EngineError::MalformedPersist);
        };
        known.push(super::state::KnownShared {
            wrap_tx: Tag::from_bytes(decode_fold32(b64u, field(row, "wrap_tx")?)?),
            shared: Secret::from_bytes(decode_fold32(b64u, field(row, "shared")?)?),
            ct_hash: Tag::from_bytes(decode_fold32(b64u, field(row, "ct_hash")?)?),
            from_us: *from_us,
            encaps_pk: decode_fold_bstr(b64u, field(row, "encaps_pk")?)?,
        });
    }
    Ok(super::state::Ratchet {
        since: *since,
        minted,
        unused,
        known,
    })
}

fn optional_secret(
    b64u: &dyn Base64Url,
    m: &[(String, Json)],
    key: &str,
) -> Result<Option<Secret>, EngineError> {
    match optional(m, key) {
        None | Some(Json::Null) => Ok(None),
        Some(v) => Ok(Some(Secret::from_bytes(decode_fold32(b64u, v)?))),
    }
}

fn field<'a>(m: &'a [(String, Json)], key: &str) -> Result<&'a Json, EngineError> {
    m.iter()
        .find(|(n, _)| n == key)
        .map(|(_, v)| v)
        .ok_or(EngineError::MalformedPersist)
}

fn optional<'a>(m: &'a [(String, Json)], key: &str) -> Option<&'a Json> {
    m.iter().find(|(n, _)| n == key).map(|(_, v)| v)
}

fn bstr(b64u: &dyn Base64Url, bytes: &[u8]) -> Json {
    super::super::codec::bstr(b64u, bytes)
}
