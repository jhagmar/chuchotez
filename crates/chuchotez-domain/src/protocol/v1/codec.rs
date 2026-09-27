//! JSON mapping `J` for Ticket, DurableBody, PacketPlain, and VaultHeader.

use super::channel::{Address, DurableChannel, EphemeralChannel, Kind};
use super::compress::Compress;
use super::defaults::{Defaults, DisplayName, NotificationPrivacy, OnWirePrefs, ProfilePic, Wake};
use super::error::EngineError;
use super::json::CanonicalJson;
use super::payload::{
    DurableBody, GroupMember, Hlc, PACKET_PAD_LEN, PacketHealHalfXor, PacketHealHave,
    PacketHealWant, PacketPlain, PacketPresence, PacketPresenceActive, PacketTxFragLast,
    PacketTxFragMore, PacketTyping, PacketTypingActive, PacketXorAck, Ticket, TxEdit,
    TxGroupInvite, TxGroupRoster, TxGroupWrap, TxInviteeIntro, TxInviterIntro, TxMedia, TxNotice,
    TxPayload, TxReaction, TxText, VaultHeader, parse_policy, policy_str,
};
use super::{
    Base64Url, ConversationId, DeviceId, IdentityId, Json, KeyPair, Secret, SigningKeyPair, Tag,
    TagKey, UserId,
};

pub(crate) fn bstr(b64u: &dyn Base64Url, bytes: &[u8]) -> Json {
    Json::String(b64u.encode(bytes))
}

pub(crate) fn durable_json(ch: &DurableChannel) -> Json {
    Json::Object(vec![
        ("kind".into(), Json::String(ch.kind().as_str().into())),
        ("address".into(), Json::String(ch.address().as_str().into())),
    ])
}

pub(crate) fn ephemeral_json(ch: &EphemeralChannel) -> Json {
    Json::Object(vec![
        ("kind".into(), Json::String(ch.kind().as_str().into())),
        ("address".into(), Json::String(ch.address().as_str().into())),
    ])
}

fn parse_obj(value: &Json) -> Result<&[(String, Json)], ()> {
    match value {
        Json::Object(m) => Ok(m),
        _ => Err(()),
    }
}

fn get<'a>(members: &'a [(String, Json)], key: &str) -> Result<&'a Json, ()> {
    members
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v)
        .ok_or(())
}

fn get_str<'a>(members: &'a [(String, Json)], key: &str) -> Result<&'a str, ()> {
    match get(members, key)? {
        Json::String(s) => Ok(s),
        _ => Err(()),
    }
}

fn get_u64(members: &[(String, Json)], key: &str) -> Result<u64, ()> {
    match get(members, key)? {
        Json::Number(n) => Ok(*n),
        _ => Err(()),
    }
}

fn get_bool(members: &[(String, Json)], key: &str) -> Result<bool, ()> {
    match get(members, key)? {
        Json::Bool(b) => Ok(*b),
        _ => Err(()),
    }
}

fn get_bstr(b64u: &dyn Base64Url, members: &[(String, Json)], key: &str) -> Result<Vec<u8>, ()> {
    b64u.decode(get_str(members, key)?).map_err(|_| ())
}

fn get_tag(b64u: &dyn Base64Url, members: &[(String, Json)], key: &str) -> Result<Tag, ()> {
    let bytes = get_bstr(b64u, members, key)?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| ())?;
    Ok(Tag::from_bytes(arr))
}

fn extra_ok(members: &[(String, Json)], keys: &[&str]) -> Result<(), ()> {
    for (k, _) in members {
        if !keys.contains(&k.as_str()) {
            return Err(());
        }
    }
    Ok(())
}

pub(crate) fn ticket_to_json(b64u: &dyn Base64Url, ticket: &Ticket) -> Json {
    Json::Object(vec![
        ("type".into(), Json::String("v1-handshake-ticket".into())),
        ("secret".into(), bstr(b64u, ticket.secret.as_bytes())),
        (
            "persistents".into(),
            Json::Array(ticket.persistents.iter().map(durable_json).collect()),
        ),
        ("expires".into(), Json::Number(ticket.expires)),
    ])
}

pub(crate) fn ticket_from_json(b64u: &dyn Base64Url, value: &Json) -> Result<Ticket, ()> {
    let m = parse_obj(value)?;
    extra_ok(m, &["type", "secret", "persistents", "expires"])?;
    if get_str(m, "type")? != "v1-handshake-ticket" {
        return Err(());
    }
    let secret_bytes = get_bstr(b64u, m, "secret")?;
    let secret = Secret::from_bytes(secret_bytes.try_into().map_err(|_| ())?);
    let persistents = parse_durable_list(get(m, "persistents")?)?;
    if persistents.is_empty() || persistents.len() > 4 {
        return Err(());
    }
    Ok(Ticket {
        secret,
        persistents,
        expires: get_u64(m, "expires")?,
    })
}

fn parse_durable_list(value: &Json) -> Result<Vec<DurableChannel>, ()> {
    let Json::Array(items) = value else {
        return Err(());
    };
    items.iter().map(parse_durable).collect()
}

fn parse_durable(value: &Json) -> Result<DurableChannel, ()> {
    let m = parse_obj(value)?;
    extra_ok(m, &["kind", "address"])?;
    let kind = Kind::try_from(get_str(m, "kind")?).map_err(|_| ())?;
    let address = Address::try_from(get_str(m, "address")?).map_err(|_| ())?;
    Ok(DurableChannel::new(kind, address))
}

fn parse_ephemeral_list(value: &Json) -> Result<Vec<EphemeralChannel>, ()> {
    let Json::Array(items) = value else {
        return Err(());
    };
    items.iter().map(parse_ephemeral).collect()
}

fn parse_ephemeral(value: &Json) -> Result<EphemeralChannel, ()> {
    let m = parse_obj(value)?;
    extra_ok(m, &["kind", "address"])?;
    let kind = Kind::try_from(get_str(m, "kind")?).map_err(|_| ())?;
    let address = Address::try_from(get_str(m, "address")?).map_err(|_| ())?;
    Ok(EphemeralChannel::new(kind, address))
}

pub(crate) fn hlc_json(hlc: &Hlc) -> Json {
    Json::Object(vec![
        ("wall_ms".into(), Json::Number(hlc.wall_ms)),
        ("counter".into(), Json::Number(hlc.counter)),
    ])
}

fn parse_hlc(value: &Json) -> Result<Hlc, ()> {
    let m = parse_obj(value)?;
    extra_ok(m, &["wall_ms", "counter"])?;
    Ok(Hlc {
        wall_ms: get_u64(m, "wall_ms")?,
        counter: get_u64(m, "counter")?,
    })
}

pub(crate) fn payload_type(payload: &TxPayload) -> &'static str {
    match payload {
        TxPayload::Notice(_) => "v1-handshake-notice",
        TxPayload::InviterIntro(_) => "v1-handshake-inviter-intro",
        TxPayload::InviteeIntro(_) => "v1-handshake-invitee-intro",
        TxPayload::Confirm => "v1-handshake-confirm",
        TxPayload::Reject => "v1-handshake-reject",
        TxPayload::Text(_) => "v1-text",
        TxPayload::Edit(_) => "v1-edit",
        TxPayload::Remove { .. } => "v1-remove",
        TxPayload::Reaction(_) => "v1-reaction",
        TxPayload::Read { .. } => "v1-read",
        TxPayload::Delivered { .. } => "v1-delivered",
        TxPayload::Media(_) => "v1-media",
        TxPayload::Advertise { .. } => "v1-advertise",
        TxPayload::Wrap { .. } => "v1-wrap",
        TxPayload::Ack { .. } => "v1-ack",
        TxPayload::Name { .. } => "v1-name",
        TxPayload::Photo { .. } => "v1-photo",
        TxPayload::Prefs(_) => "v1-prefs",
        TxPayload::GroupInvite(_) => "v1-group-invite",
        TxPayload::GroupAccept { .. } => "v1-group-accept",
        TxPayload::GroupReject { .. } => "v1-group-reject",
        TxPayload::GroupRoster(_) => "v1-group-roster",
        TxPayload::GroupWrap(_) => "v1-group-wrap",
        TxPayload::GroupLeave => "v1-group-leave",
        TxPayload::GroupKick { .. } => "v1-group-kick",
        TxPayload::EngineInit => "v1-engine-init",
        TxPayload::EngineSetDefaults { .. } => "v1-engine-set-defaults",
        TxPayload::EngineCreateUser { .. } => "v1-engine-create-user",
        TxPayload::EngineCreateIdentity { .. } => "v1-engine-create-identity",
        TxPayload::EngineDeleteUser { .. } => "v1-engine-delete-user",
        TxPayload::EngineDeleteIdentity { .. } => "v1-engine-delete-identity",
        TxPayload::EngineSetDisplayName { .. } => "v1-engine-set-display-name",
        TxPayload::EngineUnsetDisplayName { .. } => "v1-engine-unset-display-name",
        TxPayload::EngineSetProfilePic { .. } => "v1-engine-set-profile-pic",
        TxPayload::EngineSetDeviceName { .. } => "v1-engine-set-device-name",
        TxPayload::EngineKickDevice { .. } => "v1-engine-kick-device",
    }
}

fn opt_bstr(b64u: &dyn Base64Url, bytes: Option<&[u8]>) -> Json {
    match bytes {
        Some(b) => bstr(b64u, b),
        None => Json::Null,
    }
}

pub(crate) fn payload_to_json(b64u: &dyn Base64Url, payload: &TxPayload) -> Json {
    let mut members = vec![("type".into(), Json::String(payload_type(payload).into()))];
    match payload {
        TxPayload::Notice(n) => {
            members.push(("policy".into(), Json::String(policy_str(n.policy).into())));
            members.push(("intake_pk".into(), bstr(b64u, &n.intake_pk)));
            members.push((
                "persistents".into(),
                Json::Array(n.persistents.iter().map(durable_json).collect()),
            ));
            members.push((
                "ephemerals".into(),
                Json::Array(n.ephemerals.iter().map(ephemeral_json).collect()),
            ));
            members.push(("expires".into(), Json::Number(n.expires)));
        }
        TxPayload::Confirm | TxPayload::Reject | TxPayload::EngineInit | TxPayload::GroupLeave => {}
        TxPayload::EngineCreateUser { user_id } => {
            members.push(("user_id".into(), bstr(b64u, user_id.as_bytes())));
        }
        TxPayload::EngineDeleteUser { user_id } => {
            members.push(("user_id".into(), bstr(b64u, user_id.as_bytes())));
        }
        TxPayload::EngineCreateIdentity {
            user_id,
            identity_id,
            policy,
            encryption,
            signing,
        } => {
            members.push(("user_id".into(), bstr(b64u, user_id.as_bytes())));
            members.push(("identity_id".into(), bstr(b64u, identity_id.as_bytes())));
            members.push(("policy".into(), Json::String(policy_str(*policy).into())));
            members.push((
                "encryption".into(),
                Json::Object(vec![
                    ("pk".into(), bstr(b64u, encryption.public_bytes())),
                    ("sk".into(), bstr(b64u, encryption.secret_bytes())),
                ]),
            ));
            members.push((
                "signing".into(),
                Json::Object(vec![
                    ("pk".into(), bstr(b64u, signing.public_bytes())),
                    ("sk".into(), bstr(b64u, signing.secret_bytes())),
                ]),
            ));
        }
        TxPayload::EngineDeleteIdentity {
            user_id,
            identity_id,
        }
        | TxPayload::EngineUnsetDisplayName {
            user_id,
            identity_id,
        } => {
            members.push(("user_id".into(), bstr(b64u, user_id.as_bytes())));
            members.push(("identity_id".into(), bstr(b64u, identity_id.as_bytes())));
        }
        TxPayload::EngineSetDisplayName {
            user_id,
            identity_id,
            name,
        } => {
            members.push(("user_id".into(), bstr(b64u, user_id.as_bytes())));
            members.push(("identity_id".into(), bstr(b64u, identity_id.as_bytes())));
            members.push(("name".into(), Json::String(name.as_str().into())));
        }
        TxPayload::EngineSetProfilePic {
            user_id,
            identity_id,
            profile_pic,
        } => {
            members.push(("user_id".into(), bstr(b64u, user_id.as_bytes())));
            members.push(("identity_id".into(), bstr(b64u, identity_id.as_bytes())));
            members.push((
                "profile_pic".into(),
                opt_bstr(b64u, profile_pic.as_ref().map(ProfilePic::as_bytes)),
            ));
        }
        TxPayload::EngineSetDefaults { defaults } => {
            members.push(("defaults".into(), defaults_json(defaults)));
        }
        TxPayload::EngineSetDeviceName { name } => {
            members.push(("name".into(), Json::String(name.as_str().into())));
        }
        TxPayload::EngineKickDevice { device_id } => {
            members.push(("device_id".into(), bstr(b64u, device_id.as_bytes())));
        }
        TxPayload::Text(t) => {
            members.push(("body".into(), Json::String(t.body.clone())));
            members.push((
                "reply_to".into(),
                t.reply_to
                    .as_ref()
                    .map(|x| bstr(b64u, x.as_bytes()))
                    .unwrap_or(Json::Null),
            ));
            members.push((
                "expire_at".into(),
                t.expire_at.map(Json::Number).unwrap_or(Json::Null),
            ));
        }
        TxPayload::Edit(e) => {
            members.push(("target".into(), bstr(b64u, e.target.as_bytes())));
            members.push(("body".into(), Json::String(e.body.clone())));
        }
        TxPayload::Remove { target } => {
            members.push(("target".into(), bstr(b64u, target.as_bytes())));
        }
        TxPayload::Reaction(r) => {
            members.push(("target".into(), bstr(b64u, r.target.as_bytes())));
            members.push(("emoji".into(), Json::String(r.emoji.clone())));
            members.push(("add".into(), Json::Bool(r.add)));
        }
        TxPayload::Read { up_to } | TxPayload::Delivered { up_to } => {
            members.push(("up_to".into(), bstr(b64u, up_to.as_bytes())));
        }
        TxPayload::Name { name } => {
            members.push(("name".into(), Json::String(name.as_str().into())));
        }
        TxPayload::Photo { profile_pic } => {
            members.push((
                "profile_pic".into(),
                opt_bstr(b64u, profile_pic.as_ref().map(ProfilePic::as_bytes)),
            ));
        }
        TxPayload::Advertise { encaps_pk } => {
            members.push(("encaps_pk".into(), bstr(b64u, encaps_pk)));
        }
        TxPayload::Wrap { kem_ct } => {
            members.push(("kem_ct".into(), bstr(b64u, kem_ct)));
        }
        TxPayload::Ack { ratchet_ack } => {
            members.push(("ratchet_ack".into(), bstr(b64u, ratchet_ack.as_bytes())));
        }
        TxPayload::GroupAccept { group_id } | TxPayload::GroupReject { group_id } => {
            members.push(("group_id".into(), bstr(b64u, group_id.as_bytes())));
        }
        TxPayload::GroupKick { signing_pk } => {
            members.push(("signing_pk".into(), bstr(b64u, signing_pk)));
        }
        TxPayload::InviterIntro(i) => members.extend(intro_fields(b64u, i, false)),
        TxPayload::InviteeIntro(i) => members.extend(invitee_fields(b64u, i)),
        TxPayload::Media(m) => members.extend(media_fields(b64u, m)),
        TxPayload::Prefs(p) => members.extend(prefs_fields(b64u, p)),
        TxPayload::GroupInvite(g) => members.extend(group_invite_fields(b64u, g)),
        TxPayload::GroupRoster(r) => members.extend(roster_fields(b64u, r)),
        TxPayload::GroupWrap(w) => {
            members.push(("to".into(), bstr(b64u, &w.to)));
            members.push(("from".into(), bstr(b64u, &w.from)));
            members.push(("kem_ct".into(), bstr(b64u, &w.kem_ct)));
        }
    }
    Json::Object(members)
}

fn intro_fields(b64u: &dyn Base64Url, i: &TxInviterIntro, _invitee: bool) -> Vec<(String, Json)> {
    vec![
        ("name".into(), Json::String(i.name.as_str().into())),
        (
            "profile_pic".into(),
            opt_bstr(b64u, i.profile_pic.as_ref().map(ProfilePic::as_bytes)),
        ),
        ("send_tag_key".into(), bstr(b64u, i.send_tag_key.as_bytes())),
        (
            "eph_send_tag_key".into(),
            bstr(b64u, i.eph_send_tag_key.as_bytes()),
        ),
        ("encryption_pk".into(), bstr(b64u, &i.encryption_pk)),
        ("signing_pk".into(), bstr(b64u, &i.signing_pk)),
        ("seed_ct".into(), bstr(b64u, &i.seed_ct)),
        ("prefs".into(), prefs_object(b64u, &i.prefs)),
    ]
}

fn invitee_fields(b64u: &dyn Base64Url, i: &TxInviteeIntro) -> Vec<(String, Json)> {
    vec![
        ("name".into(), Json::String(i.name.as_str().into())),
        (
            "profile_pic".into(),
            opt_bstr(b64u, i.profile_pic.as_ref().map(ProfilePic::as_bytes)),
        ),
        ("send_tag_key".into(), bstr(b64u, i.send_tag_key.as_bytes())),
        (
            "eph_send_tag_key".into(),
            bstr(b64u, i.eph_send_tag_key.as_bytes()),
        ),
        ("encryption_pk".into(), bstr(b64u, &i.encryption_pk)),
        ("signing_pk".into(), bstr(b64u, &i.signing_pk)),
        ("intake_pk".into(), bstr(b64u, &i.intake_pk)),
        ("seed_ct".into(), bstr(b64u, &i.seed_ct)),
        ("prefs".into(), prefs_object(b64u, &i.prefs)),
    ]
}

fn prefs_object(b64u: &dyn Base64Url, p: &OnWirePrefs) -> Json {
    Json::Object(prefs_fields(b64u, p))
}

fn prefs_fields(b64u: &dyn Base64Url, p: &OnWirePrefs) -> Vec<(String, Json)> {
    vec![
        ("read_receipts".into(), Json::Bool(p.read_receipts)),
        ("online_visible".into(), Json::Bool(p.online_visible)),
        ("send_typing".into(), Json::Bool(p.send_typing)),
        (
            "disappear_after".into(),
            p.disappear_after.map(Json::Number).unwrap_or(Json::Null),
        ),
        (
            "wake".into(),
            p.wake
                .as_ref()
                .map(|w| wake_json(b64u, w))
                .unwrap_or(Json::Null),
        ),
    ]
}

fn wake_json(b64u: &dyn Base64Url, w: &Wake) -> Json {
    Json::Object(vec![
        ("endpoint".into(), Json::String(w.endpoint().into())),
        ("p256dh".into(), bstr(b64u, w.p256dh())),
        ("auth".into(), bstr(b64u, w.auth())),
        (
            "vapid_pk".into(),
            w.vapid_pk().map(|v| bstr(b64u, v)).unwrap_or(Json::Null),
        ),
    ])
}

fn defaults_json(d: &Defaults) -> Json {
    Json::Object(vec![
        (
            "persistents".into(),
            Json::Array(d.persistents().iter().map(durable_json).collect()),
        ),
        (
            "ephemerals".into(),
            Json::Array(d.ephemerals().iter().map(ephemeral_json).collect()),
        ),
        ("read_receipts".into(), Json::Bool(d.read_receipts())),
        ("online_visible".into(), Json::Bool(d.online_visible())),
        ("send_typing".into(), Json::Bool(d.send_typing())),
        (
            "disappear_after".into(),
            d.disappear_after().map(Json::Number).unwrap_or(Json::Null),
        ),
        ("publish_wake".into(), Json::Bool(d.publish_wake())),
        (
            "notification_privacy".into(),
            Json::String(d.notification_privacy().as_str().into()),
        ),
    ])
}

fn media_fields(b64u: &dyn Base64Url, m: &TxMedia) -> Vec<(String, Json)> {
    vec![
        ("mime".into(), Json::String(m.mime.clone())),
        ("filename".into(), Json::String(m.filename.clone())),
        ("hash".into(), bstr(b64u, m.hash.as_bytes())),
        ("kind".into(), Json::String(m.kind.as_str().into())),
        ("address".into(), Json::String(m.address.as_str().into())),
        ("tag".into(), bstr(b64u, m.tag.as_bytes())),
        (
            "caption".into(),
            m.caption
                .as_ref()
                .map(|c| Json::String(c.clone()))
                .unwrap_or(Json::Null),
        ),
        (
            "reply_to".into(),
            m.reply_to
                .as_ref()
                .map(|x| bstr(b64u, x.as_bytes()))
                .unwrap_or(Json::Null),
        ),
        (
            "expire_at".into(),
            m.expire_at.map(Json::Number).unwrap_or(Json::Null),
        ),
    ]
}

fn group_invite_fields(b64u: &dyn Base64Url, g: &TxGroupInvite) -> Vec<(String, Json)> {
    vec![
        ("group_id".into(), bstr(b64u, g.group_id.as_bytes())),
        ("owner_signing_pk".into(), bstr(b64u, &g.owner_signing_pk)),
        (
            "persistents".into(),
            Json::Array(g.persistents.iter().map(durable_json).collect()),
        ),
        (
            "ephemerals".into(),
            Json::Array(g.ephemerals.iter().map(ephemeral_json).collect()),
        ),
        ("name".into(), Json::String(g.name.as_str().into())),
        (
            "photo".into(),
            opt_bstr(b64u, g.photo.as_ref().map(ProfilePic::as_bytes)),
        ),
        (
            "invitee_signing_pk".into(),
            bstr(b64u, &g.invitee_signing_pk),
        ),
        ("group_secret_ct".into(), bstr(b64u, &g.group_secret_ct)),
    ]
}

fn roster_fields(b64u: &dyn Base64Url, r: &TxGroupRoster) -> Vec<(String, Json)> {
    vec![
        ("epoch".into(), Json::Number(r.epoch)),
        (
            "members".into(),
            Json::Array(
                r.members
                    .iter()
                    .map(|m| {
                        Json::Object(vec![
                            ("signing_pk".into(), bstr(b64u, &m.signing_pk)),
                            ("encryption_pk".into(), bstr(b64u, &m.encryption_pk)),
                            ("send_tag_key".into(), bstr(b64u, m.send_tag_key.as_bytes())),
                            (
                                "eph_send_tag_key".into(),
                                bstr(b64u, m.eph_send_tag_key.as_bytes()),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("sig".into(), bstr(b64u, &r.sig)),
    ]
}

pub(crate) fn durable_body_to_json(b64u: &dyn Base64Url, body: &DurableBody) -> Json {
    Json::Object(vec![
        ("type".into(), Json::String("v1-durable-body".into())),
        (
            "conversation_id".into(),
            bstr(b64u, body.conversation_id.as_bytes()),
        ),
        ("hlc".into(), hlc_json(&body.hlc)),
        ("payload".into(), payload_to_json(b64u, &body.payload)),
    ])
}

pub(crate) fn vault_header_to_json(b64u: &dyn Base64Url, header: &VaultHeader) -> Json {
    Json::Object(vec![
        ("type".into(), Json::String("v1-vault-header".into())),
        ("salt".into(), bstr(b64u, &header.salt)),
        ("m".into(), Json::Number(u64::from(header.m))),
        ("t".into(), Json::Number(u64::from(header.t))),
        ("p".into(), Json::Number(u64::from(header.p))),
        (
            "passphrase_nonce".into(),
            header
                .passphrase_nonce
                .map(|n| bstr(b64u, &n))
                .unwrap_or(Json::Null),
        ),
        (
            "passphrase_wrapped_dek".into(),
            header
                .passphrase_wrapped_dek
                .as_ref()
                .map(|b| bstr(b64u, b))
                .unwrap_or(Json::Null),
        ),
        (
            "prf_nonce".into(),
            header
                .prf_nonce
                .map(|n| bstr(b64u, &n))
                .unwrap_or(Json::Null),
        ),
        (
            "prf_wrapped_dek".into(),
            header
                .prf_wrapped_dek
                .as_ref()
                .map(|b| bstr(b64u, b))
                .unwrap_or(Json::Null),
        ),
    ])
}

#[inline(never)]
fn id32<T, F>(bytes: Vec<u8>, wrap: F) -> Result<T, ()>
where
    F: Fn([u8; 32]) -> T,
{
    Ok(wrap(bytes.try_into().map_err(|_| ())?))
}

fn parse_keypair(b64u: &dyn Base64Url, value: &Json) -> Result<KeyPair, ()> {
    let m = parse_obj(value)?;
    extra_ok(m, &["pk", "sk"])?;
    Ok(KeyPair::from_parts(
        get_bstr(b64u, m, "pk")?,
        get_bstr(b64u, m, "sk")?,
    ))
}

fn parse_sign_pair(b64u: &dyn Base64Url, value: &Json) -> Result<SigningKeyPair, ()> {
    let m = parse_obj(value)?;
    extra_ok(m, &["pk", "sk"])?;
    Ok(SigningKeyPair::from_parts(
        get_bstr(b64u, m, "pk")?,
        get_bstr(b64u, m, "sk")?,
    ))
}

fn parse_wake(b64u: &dyn Base64Url, value: &Json) -> Result<Wake, ()> {
    let m = parse_obj(value)?;
    extra_ok(m, &["endpoint", "p256dh", "auth", "vapid_pk"])?;
    let vapid = match get(m, "vapid_pk")? {
        Json::Null => None,
        Json::String(s) => Some(b64u.decode(s).map_err(|_| ())?),
        _ => return Err(()),
    };
    Wake::try_new(
        get_str(m, "endpoint")?,
        &get_bstr(b64u, m, "p256dh")?,
        &get_bstr(b64u, m, "auth")?,
        vapid,
    )
    .map_err(|_| ())
}

fn parse_prefs(b64u: &dyn Base64Url, value: &Json) -> Result<OnWirePrefs, ()> {
    let m = parse_obj(value)?;
    extra_ok(
        m,
        &[
            "read_receipts",
            "online_visible",
            "send_typing",
            "disappear_after",
            "wake",
        ],
    )?;
    let disappear = match get(m, "disappear_after")? {
        Json::Null => None,
        Json::Number(n) => Some(*n),
        _ => return Err(()),
    };
    let wake = match get(m, "wake")? {
        Json::Null => None,
        v => Some(parse_wake(b64u, v)?),
    };
    Ok(OnWirePrefs {
        read_receipts: get_bool(m, "read_receipts")?,
        online_visible: get_bool(m, "online_visible")?,
        send_typing: get_bool(m, "send_typing")?,
        disappear_after: disappear,
        wake,
    })
}

fn parse_defaults(value: &Json) -> Result<Defaults, ()> {
    let m = parse_obj(value)?;
    extra_ok(
        m,
        &[
            "persistents",
            "ephemerals",
            "read_receipts",
            "online_visible",
            "send_typing",
            "disappear_after",
            "publish_wake",
            "notification_privacy",
        ],
    )?;
    let disappear = match get(m, "disappear_after")? {
        Json::Null => None,
        Json::Number(n) => Some(*n),
        _ => return Err(()),
    };
    let privacy = NotificationPrivacy::parse(get_str(m, "notification_privacy")?).ok_or(())?;
    Defaults::try_new(
        parse_durable_list(get(m, "persistents")?)?,
        parse_ephemeral_list(get(m, "ephemerals")?)?,
        get_bool(m, "read_receipts")?,
        get_bool(m, "online_visible")?,
        get_bool(m, "send_typing")?,
        disappear,
        get_bool(m, "publish_wake")?,
        privacy,
    )
    .map_err(|_| ())
}

#[inline(never)]
fn parse_name(s: &str) -> Result<DisplayName, ()> {
    DisplayName::try_from(s).map_err(|_| ())
}

fn parse_pic(b64u: &dyn Base64Url, value: &Json) -> Result<Option<ProfilePic>, ()> {
    match value {
        Json::Null => Ok(None),
        Json::String(s) => {
            let bytes = b64u.decode(s).map_err(|_| ())?;
            Ok(Some(
                ProfilePic::try_from(bytes.as_slice()).map_err(|_| ())?,
            ))
        }
        _ => Err(()),
    }
}

fn parse_opt_tag(b64u: &dyn Base64Url, value: &Json) -> Result<Option<Tag>, ()> {
    match value {
        Json::Null => Ok(None),
        Json::String(s) => {
            let bytes = b64u.decode(s).map_err(|_| ())?;
            id32(bytes, Tag::from_bytes).map(Some)
        }
        _ => Err(()),
    }
}

fn parse_opt_u64(value: &Json) -> Result<Option<u64>, ()> {
    match value {
        Json::Null => Ok(None),
        Json::Number(n) => Ok(Some(*n)),
        _ => Err(()),
    }
}

fn parse_opt_str(value: &Json) -> Result<Option<String>, ()> {
    match value {
        Json::Null => Ok(None),
        Json::String(s) => Ok(Some(s.clone())),
        _ => Err(()),
    }
}

fn parse_intro(b64u: &dyn Base64Url, m: &[(String, Json)]) -> Result<TxInviterIntro, ()> {
    extra_ok(
        m,
        &[
            "type",
            "name",
            "profile_pic",
            "send_tag_key",
            "eph_send_tag_key",
            "encryption_pk",
            "signing_pk",
            "seed_ct",
            "prefs",
        ],
    )?;
    Ok(TxInviterIntro {
        name: parse_name(get_str(m, "name")?)?,
        profile_pic: parse_pic(b64u, get(m, "profile_pic")?)?,
        send_tag_key: id32(get_bstr(b64u, m, "send_tag_key")?, TagKey::from_bytes)?,
        eph_send_tag_key: id32(get_bstr(b64u, m, "eph_send_tag_key")?, TagKey::from_bytes)?,
        encryption_pk: get_bstr(b64u, m, "encryption_pk")?,
        signing_pk: get_bstr(b64u, m, "signing_pk")?,
        seed_ct: get_bstr(b64u, m, "seed_ct")?,
        prefs: parse_prefs(b64u, get(m, "prefs")?)?,
    })
}

fn parse_invitee(b64u: &dyn Base64Url, m: &[(String, Json)]) -> Result<TxInviteeIntro, ()> {
    extra_ok(
        m,
        &[
            "type",
            "name",
            "profile_pic",
            "send_tag_key",
            "eph_send_tag_key",
            "encryption_pk",
            "signing_pk",
            "intake_pk",
            "seed_ct",
            "prefs",
        ],
    )?;
    Ok(TxInviteeIntro {
        name: parse_name(get_str(m, "name")?)?,
        profile_pic: parse_pic(b64u, get(m, "profile_pic")?)?,
        send_tag_key: id32(get_bstr(b64u, m, "send_tag_key")?, TagKey::from_bytes)?,
        eph_send_tag_key: id32(get_bstr(b64u, m, "eph_send_tag_key")?, TagKey::from_bytes)?,
        encryption_pk: get_bstr(b64u, m, "encryption_pk")?,
        signing_pk: get_bstr(b64u, m, "signing_pk")?,
        intake_pk: get_bstr(b64u, m, "intake_pk")?,
        seed_ct: get_bstr(b64u, m, "seed_ct")?,
        prefs: parse_prefs(b64u, get(m, "prefs")?)?,
    })
}

fn parse_media(b64u: &dyn Base64Url, m: &[(String, Json)]) -> Result<TxMedia, ()> {
    extra_ok(
        m,
        &[
            "type",
            "mime",
            "filename",
            "hash",
            "kind",
            "address",
            "tag",
            "caption",
            "reply_to",
            "expire_at",
        ],
    )?;
    Ok(TxMedia {
        mime: get_str(m, "mime")?.into(),
        filename: get_str(m, "filename")?.into(),
        hash: id32(get_bstr(b64u, m, "hash")?, Tag::from_bytes)?,
        kind: Kind::try_from(get_str(m, "kind")?).map_err(|_| ())?,
        address: Address::try_from(get_str(m, "address")?).map_err(|_| ())?,
        tag: get_tag(b64u, m, "tag")?,
        caption: parse_opt_str(get(m, "caption")?)?,
        reply_to: parse_opt_tag(b64u, get(m, "reply_to")?)?,
        expire_at: parse_opt_u64(get(m, "expire_at")?)?,
    })
}

fn parse_group_invite(b64u: &dyn Base64Url, m: &[(String, Json)]) -> Result<TxGroupInvite, ()> {
    extra_ok(
        m,
        &[
            "type",
            "group_id",
            "owner_signing_pk",
            "persistents",
            "ephemerals",
            "name",
            "photo",
            "invitee_signing_pk",
            "group_secret_ct",
        ],
    )?;
    Ok(TxGroupInvite {
        group_id: id32(get_bstr(b64u, m, "group_id")?, ConversationId::from_bytes)?,
        owner_signing_pk: get_bstr(b64u, m, "owner_signing_pk")?,
        persistents: parse_durable_list(get(m, "persistents")?)?,
        ephemerals: parse_ephemeral_list(get(m, "ephemerals")?)?,
        name: parse_name(get_str(m, "name")?)?,
        photo: parse_pic(b64u, get(m, "photo")?)?,
        invitee_signing_pk: get_bstr(b64u, m, "invitee_signing_pk")?,
        group_secret_ct: get_bstr(b64u, m, "group_secret_ct")?,
    })
}

fn parse_roster(b64u: &dyn Base64Url, m: &[(String, Json)]) -> Result<TxGroupRoster, ()> {
    extra_ok(m, &["type", "epoch", "members", "sig"])?;
    let Json::Array(items) = get(m, "members")? else {
        return Err(());
    };
    let mut members = Vec::new();
    for item in items {
        let im = parse_obj(item)?;
        extra_ok(
            im,
            &[
                "signing_pk",
                "encryption_pk",
                "send_tag_key",
                "eph_send_tag_key",
            ],
        )?;
        members.push(GroupMember {
            signing_pk: get_bstr(b64u, im, "signing_pk")?,
            encryption_pk: get_bstr(b64u, im, "encryption_pk")?,
            send_tag_key: id32(get_bstr(b64u, im, "send_tag_key")?, TagKey::from_bytes)?,
            eph_send_tag_key: id32(get_bstr(b64u, im, "eph_send_tag_key")?, TagKey::from_bytes)?,
        });
    }
    Ok(TxGroupRoster {
        epoch: get_u64(m, "epoch")?,
        members,
        sig: get_bstr(b64u, m, "sig")?,
    })
}

pub(crate) fn payload_from_json(b64u: &dyn Base64Url, value: &Json) -> Result<TxPayload, ()> {
    let m = parse_obj(value)?;
    let ty = get_str(m, "type")?;
    match ty {
        "v1-handshake-notice" => {
            extra_ok(
                m,
                &[
                    "type",
                    "policy",
                    "intake_pk",
                    "persistents",
                    "ephemerals",
                    "expires",
                ],
            )?;
            Ok(TxPayload::Notice(TxNotice {
                policy: parse_policy(get_str(m, "policy")?).ok_or(())?,
                intake_pk: get_bstr(b64u, m, "intake_pk")?,
                persistents: parse_durable_list(get(m, "persistents")?)?,
                ephemerals: parse_ephemeral_list(get(m, "ephemerals")?)?,
                expires: get_u64(m, "expires")?,
            }))
        }
        "v1-handshake-inviter-intro" => Ok(TxPayload::InviterIntro(parse_intro(b64u, m)?)),
        "v1-handshake-invitee-intro" => Ok(TxPayload::InviteeIntro(parse_invitee(b64u, m)?)),
        "v1-handshake-confirm" => {
            extra_ok(m, &["type"])?;
            Ok(TxPayload::Confirm)
        }
        "v1-handshake-reject" => {
            extra_ok(m, &["type"])?;
            Ok(TxPayload::Reject)
        }
        "v1-text" => {
            extra_ok(m, &["type", "body", "reply_to", "expire_at"])?;
            Ok(TxPayload::Text(TxText {
                body: get_str(m, "body")?.into(),
                reply_to: parse_opt_tag(b64u, get(m, "reply_to")?)?,
                expire_at: parse_opt_u64(get(m, "expire_at")?)?,
            }))
        }
        "v1-edit" => {
            extra_ok(m, &["type", "target", "body"])?;
            Ok(TxPayload::Edit(TxEdit {
                target: get_tag(b64u, m, "target")?,
                body: get_str(m, "body")?.into(),
            }))
        }
        "v1-remove" => {
            extra_ok(m, &["type", "target"])?;
            Ok(TxPayload::Remove {
                target: get_tag(b64u, m, "target")?,
            })
        }
        "v1-reaction" => {
            extra_ok(m, &["type", "target", "emoji", "add"])?;
            Ok(TxPayload::Reaction(TxReaction {
                target: get_tag(b64u, m, "target")?,
                emoji: get_str(m, "emoji")?.into(),
                add: get_bool(m, "add")?,
            }))
        }
        "v1-read" => {
            extra_ok(m, &["type", "up_to"])?;
            Ok(TxPayload::Read {
                up_to: get_tag(b64u, m, "up_to")?,
            })
        }
        "v1-delivered" => {
            extra_ok(m, &["type", "up_to"])?;
            Ok(TxPayload::Delivered {
                up_to: get_tag(b64u, m, "up_to")?,
            })
        }
        "v1-media" => Ok(TxPayload::Media(parse_media(b64u, m)?)),
        "v1-advertise" => {
            extra_ok(m, &["type", "encaps_pk"])?;
            Ok(TxPayload::Advertise {
                encaps_pk: get_bstr(b64u, m, "encaps_pk")?,
            })
        }
        "v1-wrap" => {
            extra_ok(m, &["type", "kem_ct"])?;
            Ok(TxPayload::Wrap {
                kem_ct: get_bstr(b64u, m, "kem_ct")?,
            })
        }
        "v1-ack" => {
            extra_ok(m, &["type", "ratchet_ack"])?;
            Ok(TxPayload::Ack {
                ratchet_ack: get_tag(b64u, m, "ratchet_ack")?,
            })
        }
        "v1-name" => {
            extra_ok(m, &["type", "name"])?;
            Ok(TxPayload::Name {
                name: parse_name(get_str(m, "name")?)?,
            })
        }
        "v1-photo" => {
            extra_ok(m, &["type", "profile_pic"])?;
            Ok(TxPayload::Photo {
                profile_pic: parse_pic(b64u, get(m, "profile_pic")?)?,
            })
        }
        "v1-prefs" => Ok(TxPayload::Prefs(parse_prefs(
            b64u,
            &Json::Object(m.iter().filter(|(k, _)| k != "type").cloned().collect()),
        )?)),
        "v1-group-invite" => Ok(TxPayload::GroupInvite(parse_group_invite(b64u, m)?)),
        "v1-group-accept" => {
            extra_ok(m, &["type", "group_id"])?;
            Ok(TxPayload::GroupAccept {
                group_id: id32(get_bstr(b64u, m, "group_id")?, ConversationId::from_bytes)?,
            })
        }
        "v1-group-reject" => {
            extra_ok(m, &["type", "group_id"])?;
            Ok(TxPayload::GroupReject {
                group_id: id32(get_bstr(b64u, m, "group_id")?, ConversationId::from_bytes)?,
            })
        }
        "v1-group-roster" => Ok(TxPayload::GroupRoster(parse_roster(b64u, m)?)),
        "v1-group-wrap" => {
            extra_ok(m, &["type", "to", "from", "kem_ct"])?;
            Ok(TxPayload::GroupWrap(TxGroupWrap {
                to: get_bstr(b64u, m, "to")?,
                from: get_bstr(b64u, m, "from")?,
                kem_ct: get_bstr(b64u, m, "kem_ct")?,
            }))
        }
        "v1-group-leave" => {
            extra_ok(m, &["type"])?;
            Ok(TxPayload::GroupLeave)
        }
        "v1-group-kick" => {
            extra_ok(m, &["type", "signing_pk"])?;
            Ok(TxPayload::GroupKick {
                signing_pk: get_bstr(b64u, m, "signing_pk")?,
            })
        }
        "v1-engine-init" => {
            extra_ok(m, &["type"])?;
            Ok(TxPayload::EngineInit)
        }
        "v1-engine-set-defaults" => {
            extra_ok(m, &["type", "defaults"])?;
            Ok(TxPayload::EngineSetDefaults {
                defaults: parse_defaults(get(m, "defaults")?)?,
            })
        }
        "v1-engine-create-user" => {
            extra_ok(m, &["type", "user_id"])?;
            Ok(TxPayload::EngineCreateUser {
                user_id: id32(get_bstr(b64u, m, "user_id")?, UserId::from_bytes)?,
            })
        }
        "v1-engine-create-identity" => {
            extra_ok(
                m,
                &[
                    "type",
                    "user_id",
                    "identity_id",
                    "policy",
                    "encryption",
                    "signing",
                ],
            )?;
            Ok(TxPayload::EngineCreateIdentity {
                user_id: id32(get_bstr(b64u, m, "user_id")?, UserId::from_bytes)?,
                identity_id: id32(get_bstr(b64u, m, "identity_id")?, IdentityId::from_bytes)?,
                policy: parse_policy(get_str(m, "policy")?).ok_or(())?,
                encryption: parse_keypair(b64u, get(m, "encryption")?)?,
                signing: parse_sign_pair(b64u, get(m, "signing")?)?,
            })
        }
        "v1-engine-delete-user" => {
            extra_ok(m, &["type", "user_id"])?;
            Ok(TxPayload::EngineDeleteUser {
                user_id: id32(get_bstr(b64u, m, "user_id")?, UserId::from_bytes)?,
            })
        }
        "v1-engine-delete-identity" => {
            extra_ok(m, &["type", "user_id", "identity_id"])?;
            Ok(TxPayload::EngineDeleteIdentity {
                user_id: id32(get_bstr(b64u, m, "user_id")?, UserId::from_bytes)?,
                identity_id: id32(get_bstr(b64u, m, "identity_id")?, IdentityId::from_bytes)?,
            })
        }
        "v1-engine-set-display-name" => {
            extra_ok(m, &["type", "user_id", "identity_id", "name"])?;
            Ok(TxPayload::EngineSetDisplayName {
                user_id: id32(get_bstr(b64u, m, "user_id")?, UserId::from_bytes)?,
                identity_id: id32(get_bstr(b64u, m, "identity_id")?, IdentityId::from_bytes)?,
                name: parse_name(get_str(m, "name")?)?,
            })
        }
        "v1-engine-unset-display-name" => {
            extra_ok(m, &["type", "user_id", "identity_id"])?;
            Ok(TxPayload::EngineUnsetDisplayName {
                user_id: id32(get_bstr(b64u, m, "user_id")?, UserId::from_bytes)?,
                identity_id: id32(get_bstr(b64u, m, "identity_id")?, IdentityId::from_bytes)?,
            })
        }
        "v1-engine-set-profile-pic" => {
            extra_ok(m, &["type", "user_id", "identity_id", "profile_pic"])?;
            Ok(TxPayload::EngineSetProfilePic {
                user_id: id32(get_bstr(b64u, m, "user_id")?, UserId::from_bytes)?,
                identity_id: id32(get_bstr(b64u, m, "identity_id")?, IdentityId::from_bytes)?,
                profile_pic: parse_pic(b64u, get(m, "profile_pic")?)?,
            })
        }
        "v1-engine-set-device-name" => {
            extra_ok(m, &["type", "name"])?;
            Ok(TxPayload::EngineSetDeviceName {
                name: parse_name(get_str(m, "name")?)?,
            })
        }
        "v1-engine-kick-device" => {
            extra_ok(m, &["type", "device_id"])?;
            Ok(TxPayload::EngineKickDevice {
                device_id: id32(get_bstr(b64u, m, "device_id")?, DeviceId::from_bytes)?,
            })
        }
        _ => Err(()),
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn packet_type(packet: &PacketPlain) -> &'static str {
    match packet {
        PacketPlain::TxFragMore(_) => "v1-packet-tx-frag-more",
        PacketPlain::TxFragLast(_) => "v1-packet-tx-frag-last",
        PacketPlain::XorAck(_) => "v1-packet-xor-ack",
        PacketPlain::HealHalfXor(_) => "v1-packet-heal-half-xor",
        PacketPlain::HealWant(_) => "v1-packet-heal-want",
        PacketPlain::HealHave(_) => "v1-packet-heal-have",
        PacketPlain::Typing(_) => "v1-packet-typing",
        PacketPlain::TypingActive(_) => "v1-packet-typing-active",
        PacketPlain::Presence(_) => "v1-packet-presence",
        PacketPlain::PresenceActive(_) => "v1-packet-presence-active",
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn tags_json(b64u: &dyn Base64Url, ids: &[Tag]) -> Json {
    Json::Array(ids.iter().map(|t| bstr(b64u, t.as_bytes())).collect())
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn packet_to_json(b64u: &dyn Base64Url, packet: &PacketPlain) -> Json {
    let mut members = vec![
        ("type".into(), Json::String(packet_type(packet).into())),
        ("version".into(), Json::Number(1)),
    ];
    match packet {
        PacketPlain::TxFragMore(p) => {
            members.push(("actor_id".into(), bstr(b64u, &p.actor_id)));
            members.push(("packet_seq".into(), Json::Number(p.packet_seq)));
            members.push(("tx_id".into(), bstr(b64u, p.tx_id.as_bytes())));
            members.push(("frag_i".into(), Json::Number(p.frag_i)));
            members.push(("frag".into(), bstr(b64u, &p.frag)));
        }
        PacketPlain::TxFragLast(p) => {
            members.push(("actor_id".into(), bstr(b64u, &p.actor_id)));
            members.push(("packet_seq".into(), Json::Number(p.packet_seq)));
            members.push(("tx_id".into(), bstr(b64u, p.tx_id.as_bytes())));
            members.push(("frag_i".into(), Json::Number(p.frag_i)));
            members.push(("frag".into(), bstr(b64u, &p.frag)));
            members.push(("set_xor".into(), bstr(b64u, p.set_xor.as_bytes())));
        }
        PacketPlain::XorAck(p) => {
            members.push(("actor_id".into(), bstr(b64u, &p.actor_id)));
            members.push(("packet_seq".into(), Json::Number(p.packet_seq)));
            members.push(("set_xor".into(), bstr(b64u, p.set_xor.as_bytes())));
        }
        PacketPlain::HealHalfXor(p) => {
            members.push(("actor_id".into(), bstr(b64u, &p.actor_id)));
            members.push(("packet_seq".into(), Json::Number(p.packet_seq)));
            members.push(("lo".into(), bstr(b64u, p.lo.as_bytes())));
            members.push(("hi".into(), bstr(b64u, p.hi.as_bytes())));
            members.push(("xor".into(), bstr(b64u, p.xor.as_bytes())));
        }
        PacketPlain::HealWant(p) => {
            members.push(("actor_id".into(), bstr(b64u, &p.actor_id)));
            members.push(("packet_seq".into(), Json::Number(p.packet_seq)));
            members.push(("lo".into(), bstr(b64u, p.lo.as_bytes())));
            members.push(("hi".into(), bstr(b64u, p.hi.as_bytes())));
            members.push(("ids".into(), tags_json(b64u, &p.ids)));
        }
        PacketPlain::HealHave(p) => {
            members.push(("actor_id".into(), bstr(b64u, &p.actor_id)));
            members.push(("packet_seq".into(), Json::Number(p.packet_seq)));
            members.push(("lo".into(), bstr(b64u, p.lo.as_bytes())));
            members.push(("hi".into(), bstr(b64u, p.hi.as_bytes())));
            members.push(("ids".into(), tags_json(b64u, &p.ids)));
        }
        PacketPlain::Typing(p) => {
            members.push(("actor_id".into(), bstr(b64u, &p.actor_id)));
            members.push(("packet_seq".into(), Json::Number(p.packet_seq)));
            members.push((
                "conversation_id".into(),
                bstr(b64u, p.conversation_id.as_bytes()),
            ));
            members.push(("composing".into(), Json::Bool(p.composing)));
        }
        PacketPlain::TypingActive(p) => {
            members.push(("actor_id".into(), bstr(b64u, &p.actor_id)));
            members.push(("packet_seq".into(), Json::Number(p.packet_seq)));
            members.push((
                "conversation_id".into(),
                bstr(b64u, p.conversation_id.as_bytes()),
            ));
            members.push(("last_active".into(), Json::Number(p.last_active)));
            members.push(("composing".into(), Json::Bool(p.composing)));
        }
        PacketPlain::Presence(p) => {
            members.push(("actor_id".into(), bstr(b64u, &p.actor_id)));
            members.push(("packet_seq".into(), Json::Number(p.packet_seq)));
            members.push((
                "conversation_id".into(),
                bstr(b64u, p.conversation_id.as_bytes()),
            ));
        }
        PacketPlain::PresenceActive(p) => {
            members.push(("actor_id".into(), bstr(b64u, &p.actor_id)));
            members.push(("packet_seq".into(), Json::Number(p.packet_seq)));
            members.push((
                "conversation_id".into(),
                bstr(b64u, p.conversation_id.as_bytes()),
            ));
            members.push(("last_active".into(), Json::Number(p.last_active)));
        }
    }
    Json::Object(members)
}

#[cfg_attr(not(test), allow(dead_code))]
fn get_cid(b64u: &dyn Base64Url, m: &[(String, Json)]) -> Result<ConversationId, ()> {
    id32(
        get_bstr(b64u, m, "conversation_id")?,
        ConversationId::from_bytes,
    )
}

#[cfg_attr(not(test), allow(dead_code))]
fn require_v1(m: &[(String, Json)]) -> Result<(), ()> {
    (get_u64(m, "version")? == 1).then_some(()).ok_or(())
}

#[cfg_attr(not(test), allow(dead_code))]
fn get_frag_i(m: &[(String, Json)], max: u64) -> Result<u64, ()> {
    let n = get_u64(m, "frag_i")?;
    (n <= max).then_some(n).ok_or(())
}

#[cfg_attr(not(test), allow(dead_code))]
fn get_ids(b64u: &dyn Base64Url, m: &[(String, Json)]) -> Result<Vec<Tag>, ()> {
    let Json::Array(items) = get(m, "ids")? else {
        return Err(());
    };
    (items.len() <= 32).then_some(()).ok_or(())?;
    items
        .iter()
        .map(|item| match item {
            Json::String(s) => id32(b64u.decode(s).map_err(|_| ())?, Tag::from_bytes),
            _ => Err(()),
        })
        .collect()
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn packet_from_json(b64u: &dyn Base64Url, value: &Json) -> Result<PacketPlain, ()> {
    let m = parse_obj(value)?;
    require_v1(m)?;
    match get_str(m, "type")? {
        "v1-packet-tx-frag-more" => {
            extra_ok(
                m,
                &[
                    "type",
                    "version",
                    "actor_id",
                    "packet_seq",
                    "tx_id",
                    "frag_i",
                    "frag",
                ],
            )?;
            Ok(PacketPlain::TxFragMore(PacketTxFragMore {
                actor_id: get_bstr(b64u, m, "actor_id")?,
                packet_seq: get_u64(m, "packet_seq")?,
                tx_id: get_tag(b64u, m, "tx_id")?,
                frag_i: get_frag_i(m, 62)?,
                frag: get_bstr(b64u, m, "frag")?,
            }))
        }
        "v1-packet-tx-frag-last" => {
            extra_ok(
                m,
                &[
                    "type",
                    "version",
                    "actor_id",
                    "packet_seq",
                    "tx_id",
                    "frag_i",
                    "frag",
                    "set_xor",
                ],
            )?;
            Ok(PacketPlain::TxFragLast(PacketTxFragLast {
                actor_id: get_bstr(b64u, m, "actor_id")?,
                packet_seq: get_u64(m, "packet_seq")?,
                tx_id: get_tag(b64u, m, "tx_id")?,
                frag_i: get_frag_i(m, 63)?,
                frag: get_bstr(b64u, m, "frag")?,
                set_xor: get_tag(b64u, m, "set_xor")?,
            }))
        }
        "v1-packet-xor-ack" => {
            extra_ok(m, &["type", "version", "actor_id", "packet_seq", "set_xor"])?;
            Ok(PacketPlain::XorAck(PacketXorAck {
                actor_id: get_bstr(b64u, m, "actor_id")?,
                packet_seq: get_u64(m, "packet_seq")?,
                set_xor: get_tag(b64u, m, "set_xor")?,
            }))
        }
        "v1-packet-heal-half-xor" => {
            extra_ok(
                m,
                &[
                    "type",
                    "version",
                    "actor_id",
                    "packet_seq",
                    "lo",
                    "hi",
                    "xor",
                ],
            )?;
            Ok(PacketPlain::HealHalfXor(PacketHealHalfXor {
                actor_id: get_bstr(b64u, m, "actor_id")?,
                packet_seq: get_u64(m, "packet_seq")?,
                lo: get_tag(b64u, m, "lo")?,
                hi: get_tag(b64u, m, "hi")?,
                xor: get_tag(b64u, m, "xor")?,
            }))
        }
        "v1-packet-heal-want" => {
            extra_ok(
                m,
                &[
                    "type",
                    "version",
                    "actor_id",
                    "packet_seq",
                    "lo",
                    "hi",
                    "ids",
                ],
            )?;
            Ok(PacketPlain::HealWant(PacketHealWant {
                actor_id: get_bstr(b64u, m, "actor_id")?,
                packet_seq: get_u64(m, "packet_seq")?,
                lo: get_tag(b64u, m, "lo")?,
                hi: get_tag(b64u, m, "hi")?,
                ids: get_ids(b64u, m)?,
            }))
        }
        "v1-packet-heal-have" => {
            extra_ok(
                m,
                &[
                    "type",
                    "version",
                    "actor_id",
                    "packet_seq",
                    "lo",
                    "hi",
                    "ids",
                ],
            )?;
            Ok(PacketPlain::HealHave(PacketHealHave {
                actor_id: get_bstr(b64u, m, "actor_id")?,
                packet_seq: get_u64(m, "packet_seq")?,
                lo: get_tag(b64u, m, "lo")?,
                hi: get_tag(b64u, m, "hi")?,
                ids: get_ids(b64u, m)?,
            }))
        }
        "v1-packet-typing" => {
            extra_ok(
                m,
                &[
                    "type",
                    "version",
                    "actor_id",
                    "packet_seq",
                    "conversation_id",
                    "composing",
                ],
            )?;
            Ok(PacketPlain::Typing(PacketTyping {
                actor_id: get_bstr(b64u, m, "actor_id")?,
                packet_seq: get_u64(m, "packet_seq")?,
                conversation_id: get_cid(b64u, m)?,
                composing: get_bool(m, "composing")?,
            }))
        }
        "v1-packet-typing-active" => {
            extra_ok(
                m,
                &[
                    "type",
                    "version",
                    "actor_id",
                    "packet_seq",
                    "conversation_id",
                    "last_active",
                    "composing",
                ],
            )?;
            Ok(PacketPlain::TypingActive(PacketTypingActive {
                actor_id: get_bstr(b64u, m, "actor_id")?,
                packet_seq: get_u64(m, "packet_seq")?,
                conversation_id: get_cid(b64u, m)?,
                last_active: get_u64(m, "last_active")?,
                composing: get_bool(m, "composing")?,
            }))
        }
        "v1-packet-presence" => {
            extra_ok(
                m,
                &[
                    "type",
                    "version",
                    "actor_id",
                    "packet_seq",
                    "conversation_id",
                ],
            )?;
            Ok(PacketPlain::Presence(PacketPresence {
                actor_id: get_bstr(b64u, m, "actor_id")?,
                packet_seq: get_u64(m, "packet_seq")?,
                conversation_id: get_cid(b64u, m)?,
            }))
        }
        "v1-packet-presence-active" => {
            extra_ok(
                m,
                &[
                    "type",
                    "version",
                    "actor_id",
                    "packet_seq",
                    "conversation_id",
                    "last_active",
                ],
            )?;
            Ok(PacketPlain::PresenceActive(PacketPresenceActive {
                actor_id: get_bstr(b64u, m, "actor_id")?,
                packet_seq: get_u64(m, "packet_seq")?,
                conversation_id: get_cid(b64u, m)?,
                last_active: get_u64(m, "last_active")?,
            }))
        }
        _ => Err(()),
    }
}

pub(crate) fn packed_packet(
    json: &dyn CanonicalJson,
    b64u: &dyn Base64Url,
    compress: &dyn Compress,
    packet: &PacketPlain,
) -> Result<Vec<u8>, EngineError> {
    let packed = compress.compress(&json.encode(&packet_to_json(b64u, packet)));
    (packed.len() <= PACKET_PAD_LEN)
        .then_some(packed)
        .ok_or(EngineError::BodyTooLarge)
}

pub(crate) fn packed_durable_body(
    json: &dyn CanonicalJson,
    b64u: &dyn Base64Url,
    compress: &dyn Compress,
    body: &DurableBody,
) -> Vec<u8> {
    compress.compress(&json.encode(&durable_body_to_json(b64u, body)))
}

pub(crate) fn durable_body_from_json(
    b64u: &dyn Base64Url,
    value: &Json,
) -> Result<DurableBody, ()> {
    let m = parse_obj(value)?;
    extra_ok(m, &["type", "conversation_id", "hlc", "payload"])?;
    if get_str(m, "type")? != "v1-durable-body" {
        return Err(());
    }
    Ok(DurableBody {
        conversation_id: id32(
            get_bstr(b64u, m, "conversation_id")?,
            ConversationId::from_bytes,
        )?,
        hlc: parse_hlc(get(m, "hlc")?)?,
        payload: payload_from_json(b64u, get(m, "payload")?)?,
    })
}

#[cfg(test)]
mod tests {
    use super::super::defaults::{
        Defaults, DisplayName, NotificationPrivacy, OnWirePrefs, ProfilePic,
    };
    use super::super::payload::{
        DurableBody, GroupMember, Hlc, PACKET_PAD_LEN, PacketHealHalfXor, PacketHealHave,
        PacketHealWant, PacketPlain, PacketPresence, PacketPresenceActive, PacketTxFragLast,
        PacketTxFragMore, PacketTyping, PacketTypingActive, PacketXorAck, Ticket, TxEdit,
        TxGroupInvite, TxGroupRoster, TxGroupWrap, TxInviteeIntro, TxInviterIntro, TxMedia,
        TxNotice, TxPayload, TxReaction, TxText, VaultHeader, pad, unpad,
    };
    use super::super::{
        Address, Base64Url, Base64UrlError, ConversationId, DeviceId, DurableChannel, EngineError,
        EphemeralChannel, IdentityId, Json, KeyPair, Kind, Secret, SigningKeyPair, Tag, TagKey,
        UserId, Wake,
    };
    use super::{
        bstr, durable_body_from_json, durable_body_to_json, durable_json, extra_ok, get, get_bool,
        get_str, get_tag, get_u64, id32, packed_packet, packet_from_json, packet_to_json,
        packet_type, parse_durable_list, parse_ephemeral_list, parse_hlc, parse_obj, parse_opt_str,
        parse_opt_tag, parse_opt_u64, parse_pic, payload_from_json, payload_to_json, payload_type,
        ticket_from_json, ticket_to_json, vault_header_to_json,
    };
    use crate::protocol::Policy;
    use crate::protocol::v1::fixtures::{DetJson, IdentityCompress};
    struct Hex;
    impl Base64Url for Hex {
        fn encode(&self, src: &[u8]) -> String {
            src.iter().map(|b| format!("{b:02x}")).collect()
        }
        fn decode(&self, src: &str) -> Result<Vec<u8>, Base64UrlError> {
            if !src.len().is_multiple_of(2) {
                return Err(Base64UrlError::Invalid);
            }
            let mut out = Vec::new();
            let b = src.as_bytes();
            let mut i = 0;
            while i < b.len() {
                let hi = match b[i] {
                    b'0'..=b'9' => b[i] - b'0',
                    b'a'..=b'f' => b[i] - b'a' + 10,
                    _ => return Err(Base64UrlError::Invalid),
                };
                let lo = match b[i + 1] {
                    b'0'..=b'9' => b[i + 1] - b'0',
                    b'a'..=b'f' => b[i + 1] - b'a' + 10,
                    _ => return Err(Base64UrlError::Invalid),
                };
                out.push((hi << 4) | lo);
                i += 2;
            }
            Ok(out)
        }
    }

    #[test]
    fn ticket_roundtrip() {
        let ch = DurableChannel::new(
            Kind::try_from("nostr").expect("k"),
            Address::try_from("wss://relay.example").expect("a"),
        );
        let ticket = Ticket {
            secret: Secret::from_bytes([9; 32]),
            persistents: vec![ch.clone()],
            expires: 99,
        };
        let json = ticket_to_json(&Hex, &ticket);
        let back = ticket_from_json(&Hex, &json).expect("parse");
        assert_eq!(back.expires, 99);
        assert!(Hex.decode("a").is_err());
        assert!(Hex.decode("zz").is_err());
        assert!(Hex.decode("0g").is_err());
        assert_eq!(payload_type(&TxPayload::Confirm), "v1-handshake-confirm");
        assert!(id32(vec![1u8], TagKey::from_bytes).is_err());
        assert!(id32(vec![1u8], UserId::from_bytes).is_err());
        assert!(id32(vec![1u8], IdentityId::from_bytes).is_err());
        assert!(id32(vec![1u8], ConversationId::from_bytes).is_err());
        assert!(id32(vec![1u8], DeviceId::from_bytes).is_err());
        assert!(id32(vec![0u8; 32], Tag::from_bytes).is_ok());
        assert!(super::parse_name("Ada").is_ok());
        assert!(super::parse_name("").is_err());
        assert_eq!(payload_type(&TxPayload::EngineInit), "v1-engine-init");
        assert_eq!(payload_type(&TxPayload::GroupLeave), "v1-group-leave");
        assert_eq!(payload_type(&TxPayload::Reject), "v1-handshake-reject");
        assert!(ticket_from_json(&Hex, &Json::Null).is_err());
        assert!(
            ticket_from_json(&Hex, &Json::Object(vec![("type".into(), Json::Number(1))])).is_err()
        );
        let mut bad = ticket_to_json(&Hex, &ticket);
        fn shove_extra(j: &mut Json) {
            let Json::Object(m) = j else {
                return;
            };
            m.push(("extra".into(), Json::Null));
        }
        shove_extra(&mut bad);
        shove_extra(&mut Json::Null);
        assert!(ticket_from_json(&Hex, &bad).is_err());
        let wrong_ty = Json::Object(vec![
            ("type".into(), Json::String("nope".into())),
            ("secret".into(), Json::String("00".repeat(32))),
            ("persistents".into(), Json::Array(vec![durable_json(&ch)])),
            ("expires".into(), Json::Number(1)),
        ]);
        assert!(ticket_from_json(&Hex, &wrong_ty).is_err());
        let empty_p = Json::Object(vec![
            ("type".into(), Json::String("v1-handshake-ticket".into())),
            ("secret".into(), Json::String("00".repeat(32))),
            ("persistents".into(), Json::Array(Vec::new())),
            ("expires".into(), Json::Number(1)),
        ]);
        assert!(ticket_from_json(&Hex, &empty_p).is_err());
        assert!(parse_durable_list(&Json::Null).is_err());
        assert!(parse_ephemeral_list(&Json::Null).is_err());
        assert!(parse_obj(&Json::Null).is_err());
        assert!(get(&[], "x").is_err());
        assert!(get_str(&[("k".into(), Json::Number(1))], "k").is_err());
        assert!(get_u64(&[("k".into(), Json::Bool(true))], "k").is_err());
        assert!(get_bool(&[("k".into(), Json::String("x".into()))], "k").is_err());
        assert!(get_tag(&Hex, &[("k".into(), Json::String("aa".into()))], "k").is_err());
        assert!(parse_hlc(&Json::Null).is_err());
        assert!(extra_ok(&[("z".into(), Json::Null)], &["a"]).is_err());
        let header = VaultHeader {
            salt: [1; 16],
            m: 8,
            t: 1,
            p: 1,
            passphrase_nonce: None,
            passphrase_wrapped_dek: None,
            prf_nonce: None,
            prf_wrapped_dek: None,
        };
        let _ = vault_header_to_json(&Hex, &header);
        assert!(
            payload_from_json(
                &Hex,
                &Json::Object(vec![("type".into(), Json::String("unknown".into()))])
            )
            .is_err()
        );
        assert!(parse_opt_str(&Json::Null).unwrap().is_none());
        assert_eq!(
            parse_opt_str(&Json::String("x".into())).unwrap().as_deref(),
            Some("x")
        );
    }

    fn webp() -> ProfilePic {
        let mut b = vec![0u8; 16];
        b[0..4].copy_from_slice(b"RIFF");
        b[8..12].copy_from_slice(b"WEBP");
        ProfilePic::try_from(b.as_slice()).expect("webp")
    }

    fn name() -> DisplayName {
        DisplayName::try_from("Ada").expect("n")
    }

    fn ch() -> DurableChannel {
        DurableChannel::new(
            Kind::try_from("nostr").expect("k"),
            Address::try_from("wss://relay.example").expect("a"),
        )
    }

    fn eph() -> EphemeralChannel {
        EphemeralChannel::new(
            Kind::try_from("webrtc").expect("k"),
            Address::try_from("stun:stun.example").expect("a"),
        )
    }

    fn prefs() -> OnWirePrefs {
        OnWirePrefs {
            read_receipts: true,
            online_visible: true,
            send_typing: false,
            disappear_after: None,
            wake: None,
        }
    }

    fn roundtrip(payload: TxPayload) {
        let json = payload_to_json(&Hex, &payload);
        let back = payload_from_json(&Hex, &json).expect("round");
        assert_eq!(back, payload);
        let body = DurableBody {
            conversation_id: ConversationId::from_bytes([2; 32]),
            hlc: Hlc {
                wall_ms: 1,
                counter: 2,
            },
            payload,
        };
        let bj = durable_body_to_json(&Hex, &body);
        let bb = durable_body_from_json(&Hex, &bj).expect("body");
        assert_eq!(bb, body);
    }

    #[test]
    fn payload_roundtrips() {
        let tag = Tag::from_bytes([3; 32]);
        let tk = TagKey::from_bytes([4; 32]);
        roundtrip(TxPayload::Confirm);
        roundtrip(TxPayload::Reject);
        roundtrip(TxPayload::EngineInit);
        roundtrip(TxPayload::GroupLeave);
        roundtrip(TxPayload::Notice(TxNotice {
            policy: Policy::Hybrid,
            intake_pk: vec![1, 2, 3],
            persistents: vec![ch()],
            ephemerals: vec![eph()],
            expires: 9,
        }));
        roundtrip(TxPayload::InviterIntro(TxInviterIntro {
            name: name(),
            profile_pic: Some(webp()),
            send_tag_key: tk,
            eph_send_tag_key: tk,
            encryption_pk: vec![9],
            signing_pk: vec![8],
            seed_ct: vec![7],
            prefs: prefs(),
        }));
        roundtrip(TxPayload::InviteeIntro(TxInviteeIntro {
            name: name(),
            profile_pic: None,
            send_tag_key: tk,
            eph_send_tag_key: tk,
            encryption_pk: vec![9],
            signing_pk: vec![8],
            intake_pk: vec![6],
            seed_ct: vec![7],
            prefs: prefs(),
        }));
        roundtrip(TxPayload::Text(TxText {
            body: "hi".into(),
            reply_to: Some(tag),
            expire_at: Some(3),
        }));
        roundtrip(TxPayload::Text(TxText {
            body: "hi".into(),
            reply_to: None,
            expire_at: None,
        }));
        roundtrip(TxPayload::Edit(TxEdit {
            target: tag,
            body: "x".into(),
        }));
        roundtrip(TxPayload::Remove { target: tag });
        roundtrip(TxPayload::Reaction(TxReaction {
            target: tag,
            emoji: "👍".into(),
            add: true,
        }));
        roundtrip(TxPayload::Read { up_to: tag });
        roundtrip(TxPayload::Delivered { up_to: tag });
        roundtrip(TxPayload::Media(TxMedia {
            mime: "image/png".into(),
            filename: "a.png".into(),
            hash: tag,
            kind: Kind::try_from("blossom").expect("k"),
            address: Address::try_from("https://blob.example").expect("a"),
            tag,
            caption: Some("c".into()),
            reply_to: Some(tag),
            expire_at: Some(9),
        }));
        roundtrip(TxPayload::Advertise { encaps_pk: vec![1] });
        roundtrip(TxPayload::Wrap { kem_ct: vec![2] });
        roundtrip(TxPayload::Ack { ratchet_ack: tag });
        roundtrip(TxPayload::Name { name: name() });
        roundtrip(TxPayload::Photo {
            profile_pic: Some(webp()),
        });
        roundtrip(TxPayload::Photo { profile_pic: None });
        roundtrip(TxPayload::Prefs(prefs()));
        roundtrip(TxPayload::GroupInvite(TxGroupInvite {
            group_id: ConversationId::from_bytes([5; 32]),
            owner_signing_pk: vec![1],
            persistents: vec![ch()],
            ephemerals: Vec::new(),
            name: name(),
            photo: None,
            invitee_signing_pk: vec![2],
            group_secret_ct: vec![3],
        }));
        roundtrip(TxPayload::GroupAccept {
            group_id: ConversationId::from_bytes([5; 32]),
        });
        roundtrip(TxPayload::GroupReject {
            group_id: ConversationId::from_bytes([5; 32]),
        });
        roundtrip(TxPayload::GroupRoster(TxGroupRoster {
            epoch: 1,
            members: vec![GroupMember {
                signing_pk: vec![1],
                encryption_pk: vec![2],
                send_tag_key: tk,
                eph_send_tag_key: tk,
            }],
            sig: vec![9],
        }));
        roundtrip(TxPayload::GroupWrap(TxGroupWrap {
            to: vec![1],
            from: vec![2],
            kem_ct: vec![3],
        }));
        roundtrip(TxPayload::GroupKick {
            signing_pk: vec![1],
        });
        roundtrip(TxPayload::EngineCreateUser {
            user_id: UserId::from_bytes([1; 32]),
        });
        roundtrip(TxPayload::EngineDeleteUser {
            user_id: UserId::from_bytes([1; 32]),
        });
        roundtrip(TxPayload::EngineCreateIdentity {
            user_id: UserId::from_bytes([1; 32]),
            identity_id: IdentityId::from_bytes([2; 32]),
            policy: Policy::PostQuantum,
            encryption: KeyPair::from_parts(vec![1], vec![2]),
            signing: SigningKeyPair::from_parts(vec![3], vec![4]),
        });
        roundtrip(TxPayload::EngineDeleteIdentity {
            user_id: UserId::from_bytes([1; 32]),
            identity_id: IdentityId::from_bytes([2; 32]),
        });
        roundtrip(TxPayload::EngineUnsetDisplayName {
            user_id: UserId::from_bytes([1; 32]),
            identity_id: IdentityId::from_bytes([2; 32]),
        });
        roundtrip(TxPayload::EngineSetDisplayName {
            user_id: UserId::from_bytes([1; 32]),
            identity_id: IdentityId::from_bytes([2; 32]),
            name: name(),
        });
        roundtrip(TxPayload::EngineSetProfilePic {
            user_id: UserId::from_bytes([1; 32]),
            identity_id: IdentityId::from_bytes([2; 32]),
            profile_pic: None,
        });
        let defaults = Defaults::try_new(
            vec![ch()],
            vec![eph()],
            true,
            true,
            true,
            Some(8),
            false,
            NotificationPrivacy::Preview,
        )
        .expect("d");
        roundtrip(TxPayload::EngineSetDefaults { defaults });
        roundtrip(TxPayload::EngineSetDeviceName { name: name() });
        roundtrip(TxPayload::EngineKickDevice {
            device_id: DeviceId::from_bytes([9; 32]),
        });
        let wake = Wake::try_new(
            "https://push.example/x",
            &[3u8; 65],
            &[4u8; 16],
            Some(vec![1]),
        )
        .expect("w");
        let mut p = prefs();
        p.wake = Some(wake);
        p.disappear_after = Some(9);
        roundtrip(TxPayload::Prefs(p));
        assert!(Hex.decode("g0").is_err());
        assert!(Hex.decode("0g").is_err());
        assert!(Hex.decode("0").is_err());
        assert!(
            payload_from_json(
                &Hex,
                &Json::Object(vec![("type".into(), Json::String("v1-text".into()))])
            )
            .is_err()
        );
        assert!(
            durable_body_from_json(
                &Hex,
                &Json::Object(vec![
                    ("type".into(), Json::String("nope".into())),
                    ("conversation_id".into(), Json::String("00".repeat(32))),
                    (
                        "hlc".into(),
                        Json::Object(vec![
                            ("wall_ms".into(), Json::Number(1)),
                            ("counter".into(), Json::Number(0)),
                        ])
                    ),
                    (
                        "payload".into(),
                        Json::Object(vec![("type".into(), Json::String("v1-engine-init".into()))])
                    ),
                ])
            )
            .is_err()
        );
        assert!(id32::<Tag, _>(vec![1, 2], Tag::from_bytes).is_err());
        assert!(parse_pic(&Hex, &Json::Number(1)).is_err());
        assert!(parse_opt_tag(&Hex, &Json::Number(1)).is_err());
        assert!(parse_opt_u64(&Json::Bool(true)).is_err());
        assert!(parse_opt_str(&Json::Number(1)).is_err());
        assert!(payload_from_json(&Hex, &Json::Null).is_err());
        assert!(
            payload_from_json(
                &Hex,
                &Json::Object(vec![("type".into(), Json::String("nope".into()))])
            )
            .is_err()
        );
        assert!(durable_body_from_json(&Hex, &Json::Null).is_err());
        let header = VaultHeader {
            salt: [2; 16],
            m: 8,
            t: 1,
            p: 1,
            passphrase_nonce: Some([3; 12]),
            passphrase_wrapped_dek: Some(vec![1, 2]),
            prf_nonce: Some([4; 12]),
            prf_wrapped_dek: Some(vec![3, 4]),
        };
        let _ = vault_header_to_json(&Hex, &header);
        roundtrip(TxPayload::Media(TxMedia {
            mime: "image/png".into(),
            filename: "a.png".into(),
            hash: tag,
            kind: Kind::try_from("blossom").expect("k"),
            address: Address::try_from("https://blob.example").expect("a"),
            tag,
            caption: None,
            reply_to: None,
            expire_at: None,
        }));
        let null_vapid =
            Wake::try_new("https://push.example/x", &[3u8; 65], &[4u8; 16], None).expect("w0");
        let mut prefs_null = prefs();
        prefs_null.wake = Some(null_vapid);
        roundtrip(TxPayload::Prefs(prefs_null));
        fn extra(j: Json) -> Json {
            match j {
                Json::Object(mut m) => {
                    m.push(("nope".into(), Json::Bool(true)));
                    Json::Object(m)
                }
                other => other,
            }
        }
        fn map_obj(j: &mut Json, f: fn(&mut Vec<(String, Json)>)) {
            let Json::Object(m) = j else {
                return;
            };
            f(m);
        }
        #[allow(clippy::ptr_arg)]
        fn members_to_number(m: &mut Vec<(String, Json)>) {
            for (k, v) in m.iter_mut() {
                if k == "members" {
                    *v = Json::Number(1);
                }
            }
        }
        let _ = extra(Json::Null);
        map_obj(&mut Json::Null, members_to_number);
        for p in [
            TxPayload::Notice(TxNotice {
                policy: Policy::Classic,
                intake_pk: vec![1],
                persistents: vec![ch()],
                ephemerals: vec![eph()],
                expires: 1,
            }),
            TxPayload::InviterIntro(TxInviterIntro {
                name: name(),
                profile_pic: None,
                send_tag_key: tk,
                eph_send_tag_key: tk,
                encryption_pk: vec![1],
                signing_pk: vec![2],
                seed_ct: vec![3],
                prefs: prefs(),
            }),
            TxPayload::InviteeIntro(TxInviteeIntro {
                name: name(),
                profile_pic: None,
                send_tag_key: tk,
                eph_send_tag_key: tk,
                encryption_pk: vec![1],
                signing_pk: vec![2],
                intake_pk: vec![3],
                seed_ct: vec![4],
                prefs: prefs(),
            }),
            TxPayload::Media(TxMedia {
                mime: "image/png".into(),
                filename: "a.png".into(),
                hash: tag,
                kind: Kind::try_from("blossom").expect("k"),
                address: Address::try_from("https://blob.example").expect("a"),
                tag,
                caption: None,
                reply_to: None,
                expire_at: None,
            }),
            TxPayload::GroupInvite(TxGroupInvite {
                group_id: ConversationId::from_bytes([5; 32]),
                owner_signing_pk: vec![1],
                persistents: vec![ch()],
                ephemerals: Vec::new(),
                name: name(),
                photo: None,
                invitee_signing_pk: vec![2],
                group_secret_ct: vec![3],
            }),
            TxPayload::EngineCreateIdentity {
                user_id: UserId::from_bytes([1; 32]),
                identity_id: IdentityId::from_bytes([2; 32]),
                policy: Policy::Classic,
                encryption: KeyPair::from_parts(vec![1], vec![2]),
                signing: SigningKeyPair::from_parts(vec![3], vec![4]),
            },
            TxPayload::EngineSetDefaults {
                defaults: Defaults::try_new(
                    vec![ch()],
                    Vec::new(),
                    true,
                    true,
                    true,
                    None,
                    false,
                    NotificationPrivacy::Name,
                )
                .expect("d"),
            },
        ] {
            assert!(payload_from_json(&Hex, &extra(payload_to_json(&Hex, &p))).is_err());
        }
        let mut roster = payload_to_json(
            &Hex,
            &TxPayload::GroupRoster(TxGroupRoster {
                epoch: 1,
                members: vec![GroupMember {
                    signing_pk: vec![1],
                    encryption_pk: vec![2],
                    send_tag_key: tk,
                    eph_send_tag_key: tk,
                }],
                sig: vec![9],
            }),
        );
        map_obj(&mut roster, members_to_number);
        assert!(payload_from_json(&Hex, &roster).is_err());
        let mut member_extra = payload_to_json(
            &Hex,
            &TxPayload::GroupRoster(TxGroupRoster {
                epoch: 1,
                members: vec![GroupMember {
                    signing_pk: vec![1],
                    encryption_pk: vec![2],
                    send_tag_key: tk,
                    eph_send_tag_key: tk,
                }],
                sig: vec![9],
            }),
        );
        map_obj(&mut member_extra, |m| {
            for (k, v) in m.iter_mut() {
                if k == "members"
                    && let Json::Array(items) = v
                    && let Json::Object(im) = &mut items[0]
                {
                    im.push(("nope".into(), Json::Bool(true)));
                }
            }
        });
        assert!(payload_from_json(&Hex, &member_extra).is_err());
        let mut prefs_j = payload_to_json(&Hex, &TxPayload::Prefs(prefs()));
        map_obj(&mut prefs_j, |m| {
            for (k, v) in m.iter_mut() {
                if k == "disappear_after" {
                    *v = Json::Bool(true);
                }
            }
        });
        assert!(payload_from_json(&Hex, &prefs_j).is_err());
        assert!(
            payload_from_json(
                &Hex,
                &extra(payload_to_json(&Hex, &TxPayload::Prefs(prefs())))
            )
            .is_err()
        );
        let mut wake_bad_vapid = payload_to_json(
            &Hex,
            &TxPayload::Prefs({
                let mut p = prefs();
                p.wake = Some(
                    Wake::try_new("https://push.example/x", &[3u8; 65], &[4u8; 16], None)
                        .expect("w"),
                );
                p
            }),
        );
        map_obj(&mut wake_bad_vapid, |m| {
            for (k, v) in m.iter_mut() {
                if k == "wake"
                    && let Json::Object(w) = v
                {
                    for (wk, wv) in w.iter_mut() {
                        if wk == "vapid_pk" {
                            *wv = Json::Number(1);
                        }
                    }
                }
            }
        });
        assert!(payload_from_json(&Hex, &wake_bad_vapid).is_err());
        let mut wake_extra = payload_to_json(
            &Hex,
            &TxPayload::Prefs({
                let mut p = prefs();
                p.wake = Some(
                    Wake::try_new("https://push.example/x", &[3u8; 65], &[4u8; 16], None)
                        .expect("w"),
                );
                p
            }),
        );
        map_obj(&mut wake_extra, |m| {
            for (k, v) in m.iter_mut() {
                if k == "wake"
                    && let Json::Object(w) = v
                {
                    w.push(("nope".into(), Json::Bool(true)));
                }
            }
        });
        assert!(payload_from_json(&Hex, &wake_extra).is_err());
        let mut def_j = payload_to_json(
            &Hex,
            &TxPayload::EngineSetDefaults {
                defaults: Defaults::try_new(
                    vec![ch()],
                    Vec::new(),
                    true,
                    true,
                    true,
                    None,
                    false,
                    NotificationPrivacy::Name,
                )
                .expect("d"),
            },
        );
        map_obj(&mut def_j, |m| {
            for (k, v) in m.iter_mut() {
                if k == "defaults"
                    && let Json::Object(d) = v
                {
                    for (dk, dv) in d.iter_mut() {
                        if dk == "disappear_after" {
                            *dv = Json::Bool(true);
                        }
                    }
                }
            }
        });
        assert!(payload_from_json(&Hex, &def_j).is_err());
        let mut def_extra = payload_to_json(
            &Hex,
            &TxPayload::EngineSetDefaults {
                defaults: Defaults::try_new(
                    vec![ch()],
                    Vec::new(),
                    true,
                    true,
                    true,
                    None,
                    false,
                    NotificationPrivacy::Name,
                )
                .expect("d"),
            },
        );
        map_obj(&mut def_extra, |m| {
            for (k, v) in m.iter_mut() {
                if k == "defaults"
                    && let Json::Object(d) = v
                {
                    d.push(("nope".into(), Json::Bool(true)));
                }
            }
        });
        assert!(payload_from_json(&Hex, &def_extra).is_err());
        let mut body_j = durable_body_to_json(
            &Hex,
            &DurableBody {
                conversation_id: ConversationId::from_bytes([1; 32]),
                hlc: Hlc {
                    wall_ms: 1,
                    counter: 0,
                },
                payload: TxPayload::EngineInit,
            },
        );
        map_obj(&mut body_j, |m| {
            for (k, v) in m.iter_mut() {
                if k == "conversation_id" {
                    *v = Json::String("aa".into());
                }
            }
        });
        assert!(durable_body_from_json(&Hex, &body_j).is_err());
    }

    #[test]
    fn packet_roundtrips() {
        let actor = vec![7u8; 32];
        let tag = Tag::from_bytes([3; 32]);
        let inf = Tag::from_bytes([0xff; 32]);
        let cid = ConversationId::from_bytes([4; 32]);
        let packets = [
            PacketPlain::TxFragMore(PacketTxFragMore {
                actor_id: actor.clone(),
                packet_seq: 1,
                tx_id: tag,
                frag_i: 0,
                frag: vec![9, 8, 7],
            }),
            PacketPlain::TxFragMore(PacketTxFragMore {
                actor_id: actor.clone(),
                packet_seq: 2,
                tx_id: tag,
                frag_i: 62,
                frag: Vec::new(),
            }),
            PacketPlain::TxFragLast(PacketTxFragLast {
                actor_id: actor.clone(),
                packet_seq: 3,
                tx_id: tag,
                frag_i: 0,
                frag: vec![1],
                set_xor: tag,
            }),
            PacketPlain::TxFragLast(PacketTxFragLast {
                actor_id: actor.clone(),
                packet_seq: 4,
                tx_id: tag,
                frag_i: 63,
                frag: vec![2],
                set_xor: inf,
            }),
            PacketPlain::XorAck(PacketXorAck {
                actor_id: actor.clone(),
                packet_seq: 5,
                set_xor: tag,
            }),
            PacketPlain::HealHalfXor(PacketHealHalfXor {
                actor_id: actor.clone(),
                packet_seq: 6,
                lo: tag,
                hi: inf,
                xor: tag,
            }),
            PacketPlain::HealWant(PacketHealWant {
                actor_id: actor.clone(),
                packet_seq: 7,
                lo: tag,
                hi: inf,
                ids: Vec::new(),
            }),
            PacketPlain::HealWant(PacketHealWant {
                actor_id: actor.clone(),
                packet_seq: 8,
                lo: tag,
                hi: inf,
                ids: vec![tag; 32],
            }),
            PacketPlain::HealHave(PacketHealHave {
                actor_id: actor.clone(),
                packet_seq: 9,
                lo: tag,
                hi: inf,
                ids: vec![tag],
            }),
            PacketPlain::Typing(PacketTyping {
                actor_id: actor.clone(),
                packet_seq: 10,
                conversation_id: cid,
                composing: true,
            }),
            PacketPlain::TypingActive(PacketTypingActive {
                actor_id: actor.clone(),
                packet_seq: 11,
                conversation_id: cid,
                last_active: 99,
                composing: false,
            }),
            PacketPlain::Presence(PacketPresence {
                actor_id: actor.clone(),
                packet_seq: 12,
                conversation_id: cid,
            }),
            PacketPlain::PresenceActive(PacketPresenceActive {
                actor_id: actor.clone(),
                packet_seq: 13,
                conversation_id: cid,
                last_active: 100,
            }),
        ];
        fn extra(j: Json) -> Json {
            match j {
                Json::Object(mut m) => {
                    m.push(("nope".into(), Json::Bool(true)));
                    Json::Object(m)
                }
                other => other,
            }
        }
        for p in &packets {
            let j = packet_to_json(&Hex, p);
            assert_eq!(packet_from_json(&Hex, &j).expect("round"), *p);
            assert!(packet_from_json(&Hex, &extra(j)).is_err());
        }
        let _ = extra(Json::Null);
        assert_eq!(packet_type(&packets[0]), "v1-packet-tx-frag-more");
        assert!(format!("{:?}", packets[5]).contains("HealHalfXor"));
        fn on_obj(j: &mut Json, f: fn(&mut Vec<(String, Json)>)) {
            let Json::Object(m) = j else {
                return;
            };
            f(m);
        }
        #[allow(clippy::ptr_arg)]
        fn drop_cid(m: &mut Vec<(String, Json)>) {
            m.retain(|(k, _)| k != "conversation_id");
        }
        #[allow(clippy::ptr_arg)]
        fn set_type_nope(m: &mut Vec<(String, Json)>) {
            for (k, v) in m.iter_mut() {
                if k == "type" {
                    *v = Json::String("v1-nope".into());
                }
            }
        }
        #[allow(clippy::ptr_arg)]
        fn set_version_2(m: &mut Vec<(String, Json)>) {
            for (k, v) in m.iter_mut() {
                if k == "version" {
                    *v = Json::Number(2);
                }
            }
        }
        #[allow(clippy::ptr_arg)]
        fn set_frag_63(m: &mut Vec<(String, Json)>) {
            for (k, v) in m.iter_mut() {
                if k == "frag_i" {
                    *v = Json::Number(63);
                }
            }
        }
        #[allow(clippy::ptr_arg)]
        fn set_frag_64(m: &mut Vec<(String, Json)>) {
            for (k, v) in m.iter_mut() {
                if k == "frag_i" {
                    *v = Json::Number(64);
                }
            }
        }
        #[allow(clippy::ptr_arg)]
        fn push_id(m: &mut Vec<(String, Json)>) {
            for (k, v) in m.iter_mut() {
                if k == "ids"
                    && let Json::Array(a) = v
                {
                    a.push(bstr(&Hex, Tag::from_bytes([3; 32]).as_bytes()));
                }
            }
        }
        #[allow(clippy::ptr_arg)]
        fn ids_number(m: &mut Vec<(String, Json)>) {
            for (k, v) in m.iter_mut() {
                if k == "ids" {
                    *v = Json::Array(vec![Json::Number(1)]);
                }
            }
        }
        #[allow(clippy::ptr_arg)]
        fn ids_bool(m: &mut Vec<(String, Json)>) {
            for (k, v) in m.iter_mut() {
                if k == "ids" {
                    *v = Json::Bool(true);
                }
            }
        }
        #[allow(clippy::ptr_arg)]
        fn short_cid(m: &mut Vec<(String, Json)>) {
            for (k, v) in m.iter_mut() {
                if k == "conversation_id" {
                    *v = Json::String("aa".into());
                }
            }
        }
        on_obj(&mut Json::Null, drop_cid);
        let mut missing = packet_to_json(&Hex, &packets[11]);
        on_obj(&mut missing, drop_cid);
        assert!(packet_from_json(&Hex, &missing).is_err());
        let mut unknown = packet_to_json(&Hex, &packets[4]);
        on_obj(&mut unknown, set_type_nope);
        assert!(packet_from_json(&Hex, &unknown).is_err());
        let mut ver = packet_to_json(&Hex, &packets[4]);
        on_obj(&mut ver, set_version_2);
        assert!(packet_from_json(&Hex, &ver).is_err());
        let mut more_i = packet_to_json(&Hex, &packets[0]);
        on_obj(&mut more_i, set_frag_63);
        assert!(packet_from_json(&Hex, &more_i).is_err());
        let mut last_i = packet_to_json(&Hex, &packets[2]);
        on_obj(&mut last_i, set_frag_64);
        assert!(packet_from_json(&Hex, &last_i).is_err());
        let mut ids_long = packet_to_json(&Hex, &packets[7]);
        on_obj(&mut ids_long, push_id);
        assert!(packet_from_json(&Hex, &ids_long).is_err());
        let mut ids_num = packet_to_json(&Hex, &packets[8]);
        on_obj(&mut ids_num, ids_number);
        assert!(packet_from_json(&Hex, &ids_num).is_err());
        let mut ids_ty = packet_to_json(&Hex, &packets[8]);
        on_obj(&mut ids_ty, ids_bool);
        assert!(packet_from_json(&Hex, &ids_ty).is_err());
        let mut bad_cid = packet_to_json(&Hex, &packets[11]);
        on_obj(&mut bad_cid, short_cid);
        assert!(packet_from_json(&Hex, &bad_cid).is_err());
        let small = packed_packet(&DetJson, &Hex, &IdentityCompress, &packets[11]).expect("pack");
        assert!(small.len() <= PACKET_PAD_LEN);
        let padded = pad(&small, PACKET_PAD_LEN).expect("pad");
        assert_eq!(unpad(&padded), small.as_slice());
        let huge = PacketPlain::TxFragMore(PacketTxFragMore {
            actor_id: actor,
            packet_seq: 99,
            tx_id: tag,
            frag_i: 0,
            frag: vec![1; 600],
        });
        assert_eq!(
            packed_packet(&DetJson, &Hex, &IdentityCompress, &huge),
            Err(EngineError::BodyTooLarge)
        );
    }
}
