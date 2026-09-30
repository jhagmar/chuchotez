//! Shared engine helpers.

use super::super::hmac::{HmacSha256, HmacSha256Key, expand};
use super::super::kem::{KEM_SHARED_LEN, kem_ct_len, kem_pk_len};
use super::super::payload::{
    BIN_WINDOW, ConversationSort, PacketPlain, Ticket, TxInviteeIntro, TxInviterIntro, TxNotice,
    TxPayload, parse_policy, policy_str,
};
use super::super::sign::sign_pk_len;
use super::super::{
    Address, ConversationId, DisplayName, DurableChannel, EngineError, Json, Kind, Policy, Secret,
    Tag, TagKey,
};
use super::query::{DurableLocator, DurableWrite, EphemeralWrite, FailedReason};
use super::state::{BinKey, BinProgress, EngineState};
use std::cmp::Ordering;
use std::collections::BTreeMap;

pub(super) type CallingParts = (
    DisplayName,
    Option<super::super::ProfilePic>,
    Vec<u8>,
    Vec<u8>,
);

pub(super) fn notice_for(
    state: &EngineState,
    conversation_id: ConversationId,
) -> Option<&TxNotice> {
    state.txs.values().find_map(|t| match &t.payload {
        TxPayload::Notice(n) if t.conversation_id == conversation_id => Some(n),
        _ => None,
    })
}

pub(super) fn invitee_intro_for(
    state: &EngineState,
    conversation_id: ConversationId,
) -> Option<&TxInviteeIntro> {
    state.txs.values().find_map(|t| match &t.payload {
        TxPayload::InviteeIntro(i) if t.conversation_id == conversation_id => Some(i),
        _ => None,
    })
}

pub(super) fn inviter_intro_for(
    state: &EngineState,
    conversation_id: ConversationId,
) -> Option<&TxInviterIntro> {
    state.txs.values().find_map(|t| match &t.payload {
        TxPayload::InviterIntro(i) if t.conversation_id == conversation_id => Some(i),
        _ => None,
    })
}

pub(super) fn intro_keys_ok(
    policy: Policy,
    encryption_pk: &[u8],
    signing_pk: &[u8],
    intake_pk: Option<&[u8]>,
    seed_ct: &[u8],
) -> bool {
    encryption_pk.len() == kem_pk_len(policy)
        && signing_pk.len() == sign_pk_len(policy)
        && seed_ct.len() == kem_ct_len(policy)
        && intake_pk.is_none_or(|pk| pk.len() == kem_pk_len(policy))
}

pub(super) fn store_unlock_failed(state: &mut EngineState, cid: ConversationId) {
    if state.failed(cid).is_some() {
        return;
    }
    let conversation_id = cid;
    let reason = if notice_for(state, conversation_id).is_some() || state.is_inviter(cid) {
        FailedReason::IntroUnlockFailed
    } else {
        FailedReason::NoticeUnlockFailed
    };
    state.fail(cid, reason);
}

pub(super) fn handshake_rows(
    state: &EngineState,
) -> Vec<(ConversationId, Ticket, ConversationSort)> {
    state
        .handshake_entries()
        .into_iter()
        .map(|(id, hs, sort)| (id, hs.ticket.clone(), sort))
        .collect()
}

pub(super) fn window_start(w: u64) -> u64 {
    w.saturating_sub(BIN_WINDOW.saturating_sub(1))
}

pub(super) fn listen_bins(w: u64) -> [u64; 3] {
    [w.saturating_sub(1), w, w.saturating_add(1)]
}

pub(super) fn handshake_tag_key(hmac: &dyn HmacSha256, secret: &[u8; 32]) -> TagKey {
    TagKey::from_bytes(
        expand(
            hmac,
            &HmacSha256Key::from_bytes(*secret),
            b"chuchotez/1/handshake-invite",
        )
        .into_bytes(),
    )
}

pub(super) fn invite_tag(hmac: &dyn HmacSha256, secret: &[u8; 32], bin: u64) -> Tag {
    Tag::from_bytes(
        expand(
            hmac,
            &HmacSha256Key::from_bytes(*secret),
            &[
                b"chuchotez/1/handshake-invite".as_slice(),
                &bin.to_be_bytes(),
            ]
            .concat(),
        )
        .into_bytes(),
    )
}

pub(super) fn progress_key(channel: &DurableChannel, tag_key: &TagKey) -> BinKey {
    BinKey {
        kind: channel.kind().as_str().into(),
        address: channel.address().as_str().into(),
        tag_key: *tag_key,
    }
}

pub(super) fn bin_complete(progress: Option<&BinProgress>, bin: u64) -> bool {
    let Some(p) = progress else {
        return false;
    };
    p.watermark.is_some_and(|w| bin <= w) || p.completed.contains(&bin)
}

pub(super) fn prune_progress(progress: &mut BinProgress, start: u64) {
    if let Some(w) = progress.watermark
        && w < start
    {
        progress.watermark = None;
    }
    progress.completed.retain(|&b| b >= start);
    loop {
        let next = match progress.watermark {
            None => start,
            Some(w) => w.saturating_add(1),
        };
        if progress.completed.remove(&next) {
            progress.watermark = Some(next);
        } else {
            break;
        }
    }
}

pub(super) fn locator_ord(a: &DurableLocator, b: &DurableLocator) -> Ordering {
    a.channel
        .kind()
        .as_str()
        .cmp(b.channel.kind().as_str())
        .then_with(|| {
            a.channel
                .address()
                .as_str()
                .cmp(b.channel.address().as_str())
        })
        .then_with(|| a.tag.as_bytes().cmp(b.tag.as_bytes()))
}

pub(super) fn sort_durable_locators(locators: &mut [DurableLocator]) {
    locators.sort_by(locator_ord);
}

pub(super) fn sort_durable_writes(writes: &mut [DurableWrite]) {
    writes.sort_by(|a, b| {
        locator_ord(
            &DurableLocator {
                channel: a.channel.clone(),
                tag: a.tag,
            },
            &DurableLocator {
                channel: b.channel.clone(),
                tag: b.tag,
            },
        )
    });
}

pub(super) fn sort_ephemeral_writes(writes: &mut [EphemeralWrite]) {
    writes.sort_by(|a, b| {
        a.channel
            .kind()
            .as_str()
            .cmp(b.channel.kind().as_str())
            .then_with(|| {
                a.channel
                    .address()
                    .as_str()
                    .cmp(b.channel.address().as_str())
            })
            .then_with(|| a.tag.as_bytes().cmp(b.tag.as_bytes()))
    });
}

pub(super) struct FragPart {
    pub(super) tx_id: Tag,
    pub(super) frag_i: u64,
    pub(super) frag: Vec<u8>,
    pub(super) last_i: Option<u64>,
}

pub(super) fn frag_parts(packet: &PacketPlain) -> Option<FragPart> {
    match packet {
        PacketPlain::TxFragMore(p) => Some(FragPart {
            tx_id: p.tx_id,
            frag_i: p.frag_i,
            frag: p.frag.clone(),
            last_i: None,
        }),
        PacketPlain::TxFragLast(p) => Some(FragPart {
            tx_id: p.tx_id,
            frag_i: p.frag_i,
            frag: p.frag.clone(),
            last_i: Some(p.frag_i),
        }),
        _ => None,
    }
}

pub(super) fn rekey_conversation(
    state: &mut EngineState,
    from: ConversationId,
    to: ConversationId,
) {
    state.rekey_row(from, to);
    rekey_prefix(&mut state.send_chains, from, to);
    rekey_prefix(&mut state.recv_chains, from, to);
    rekey_prefix(&mut state.skipped_mks, from, to);
    for frag in state.frags.values_mut() {
        frag.conversation_id = rekey_cid(frag.conversation_id, from, to);
    }
}

#[rustfmt::skip]
pub(super) fn rekey_cid(cid: ConversationId, from: ConversationId, to: ConversationId) -> ConversationId {
    if cid == from { to } else { cid }
}

#[rustfmt::skip]
pub(super) fn rekey_prefix<V>(map: &mut BTreeMap<Vec<u8>, V>, from: ConversationId, to: ConversationId) {
    *map = std::mem::take(map).into_iter().map(|(k, v)| {
        if k.len() >= 32 && k[..32] == *from.as_bytes() { let mut nk = to.as_bytes().to_vec(); nk.extend_from_slice(&k[32..]); (nk, v) } else { (k, v) }
    }).collect();
}

pub(super) fn decode_fold_bstr(
    b64u: &dyn super::super::Base64Url,
    value: &Json,
) -> Result<Vec<u8>, EngineError> {
    let Json::String(s) = value else {
        return Err(EngineError::MalformedPersist);
    };
    b64u.decode(s).map_err(|_| EngineError::MalformedPersist)
}

pub(super) fn decode_fold32(
    b64u: &dyn super::super::Base64Url,
    value: &Json,
) -> Result<[u8; 32], EngineError> {
    decode_fold_bstr(b64u, value)?
        .try_into()
        .map_err(|_| EngineError::MalformedPersist)
}

pub(super) fn parse_fold_shared_map(
    b64u: &dyn super::super::Base64Url,
    value: Option<&Json>,
    out: &mut BTreeMap<ConversationId, Secret>,
) -> Result<(), EngineError> {
    match value {
        Some(Json::Array(items)) => {
            for item in items {
                let Json::Object(m) = item else {
                    return Err(EngineError::MalformedPersist);
                };
                let getm = |k: &str| m.iter().find(|(n, _)| n == k).map(|(_, v)| v);
                #[rustfmt::skip]
                let cid = decode_fold32(b64u, getm("conversation_id").ok_or(EngineError::MalformedPersist)?)?;
                #[rustfmt::skip]
                let shared = decode_fold32(b64u, getm("shared").ok_or(EngineError::MalformedPersist)?)?;
                out.insert(ConversationId::from_bytes(cid), Secret::from_bytes(shared));
            }
            Ok(())
        }
        None => Ok(()),
        Some(_) => Err(EngineError::MalformedPersist),
    }
}

pub(super) fn sort32(a: &[u8; 32], b: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    if a <= b {
        out.extend_from_slice(a);
        out.extend_from_slice(b);
    } else {
        out.extend_from_slice(b);
        out.extend_from_slice(a);
    }
    out
}

pub(super) fn take_shared32(shared: Vec<u8>) -> Secret {
    let mut out = [0u8; KEM_SHARED_LEN];
    let n = shared.len().min(KEM_SHARED_LEN);
    out[..n].copy_from_slice(&shared[..n]);
    Secret::from_bytes(out)
}

pub(super) fn keypair_json(b64u: &dyn super::super::Base64Url, pk: &[u8], sk: &[u8]) -> Json {
    Json::Object(vec![
        ("pk".into(), super::super::codec::bstr(b64u, pk)),
        ("sk".into(), super::super::codec::bstr(b64u, sk)),
    ])
}

pub(super) fn parse_fold_keypair(
    b64u: &dyn super::super::Base64Url,
    value: &Json,
) -> Result<(Vec<u8>, Vec<u8>), EngineError> {
    let Json::Object(m) = value else {
        return Err(EngineError::MalformedPersist);
    };
    let get = |k: &str| m.iter().find(|(n, _)| n == k).map(|(_, v)| v);
    let pk = decode_fold_bstr(b64u, get("pk").ok_or(EngineError::MalformedPersist)?)?;
    let sk = decode_fold_bstr(b64u, get("sk").ok_or(EngineError::MalformedPersist)?)?;
    Ok((pk, sk))
}

pub(super) fn failed_to_json(
    b64u: &dyn super::super::Base64Url,
    id: ConversationId,
    reason: FailedReason,
) -> Json {
    let mut members = vec![
        (
            "conversation_id".into(),
            super::super::codec::bstr(b64u, id.as_bytes()),
        ),
        (
            "reason".into(),
            Json::String(
                match reason {
                    FailedReason::PolicyNotAccepted { .. } => "PolicyNotAccepted",
                    FailedReason::InviteExpired { .. } => "InviteExpired",
                    FailedReason::NoticeUnlockFailed => "NoticeUnlockFailed",
                    FailedReason::NoticeConflict => "NoticeConflict",
                    FailedReason::IntroUnlockFailed => "IntroUnlockFailed",
                    FailedReason::IntroVerifyFailed => "IntroVerifyFailed",
                    FailedReason::DuplicateIntro => "DuplicateIntro",
                    FailedReason::ConfirmationRejected => "ConfirmationRejected",
                    FailedReason::Equivocation => "Equivocation",
                    FailedReason::OfferRejected => "OfferRejected",
                    FailedReason::Kicked => "Kicked",
                    FailedReason::Left => "Left",
                }
                .into(),
            ),
        ),
    ];
    match reason {
        FailedReason::PolicyNotAccepted { policy } => {
            members.push(("policy".into(), Json::String(policy_str(policy).into())));
        }
        FailedReason::InviteExpired { expires } => {
            members.push(("expires".into(), Json::Number(expires)));
        }
        _ => {}
    }
    Json::Object(members)
}

pub(super) fn parse_failed(
    b64u: &dyn super::super::Base64Url,
    value: &Json,
) -> Result<(ConversationId, FailedReason), EngineError> {
    let Json::Object(m) = value else {
        return Err(EngineError::MalformedPersist);
    };
    let get = |k: &str| m.iter().find(|(n, _)| n == k).map(|(_, v)| v);
    #[rustfmt::skip]
    let cid = decode_fold32(b64u, get("conversation_id").ok_or(EngineError::MalformedPersist)?)?;
    let Json::String(reason) = get("reason").ok_or(EngineError::MalformedPersist)? else {
        return Err(EngineError::MalformedPersist);
    };
    let parsed = match reason.as_str() {
        "PolicyNotAccepted" => {
            let Json::String(p) = get("policy").ok_or(EngineError::MalformedPersist)? else {
                return Err(EngineError::MalformedPersist);
            };
            FailedReason::PolicyNotAccepted {
                policy: parse_policy(p).ok_or(EngineError::MalformedPersist)?,
            }
        }
        "InviteExpired" => {
            let Json::Number(expires) = get("expires").ok_or(EngineError::MalformedPersist)? else {
                return Err(EngineError::MalformedPersist);
            };
            FailedReason::InviteExpired { expires: *expires }
        }
        "NoticeUnlockFailed" => FailedReason::NoticeUnlockFailed,
        "NoticeConflict" => FailedReason::NoticeConflict,
        "IntroUnlockFailed" => FailedReason::IntroUnlockFailed,
        "IntroVerifyFailed" => FailedReason::IntroVerifyFailed,
        "DuplicateIntro" => FailedReason::DuplicateIntro,
        "ConfirmationRejected" => FailedReason::ConfirmationRejected,
        "Equivocation" => FailedReason::Equivocation,
        "OfferRejected" => FailedReason::OfferRejected,
        "Kicked" => FailedReason::Kicked,
        "Left" => FailedReason::Left,
        _ => return Err(EngineError::MalformedPersist),
    };
    Ok((ConversationId::from_bytes(cid), parsed))
}

pub(super) fn parse_fold_channel(value: &Json) -> Result<DurableChannel, EngineError> {
    let Json::Object(m) = value else {
        return Err(EngineError::MalformedPersist);
    };
    let get = |k: &str| m.iter().find(|(n, _)| n == k).map(|(_, v)| v);
    let Json::String(kind) = get("kind").ok_or(EngineError::MalformedPersist)? else {
        return Err(EngineError::MalformedPersist);
    };
    let Json::String(address) = get("address").ok_or(EngineError::MalformedPersist)? else {
        return Err(EngineError::MalformedPersist);
    };
    let kind = Kind::try_from(kind.as_str()).map_err(|_| EngineError::MalformedPersist)?;
    let address = Address::try_from(address.as_str()).map_err(|_| EngineError::MalformedPersist)?;
    Ok(DurableChannel::new(kind, address))
}
