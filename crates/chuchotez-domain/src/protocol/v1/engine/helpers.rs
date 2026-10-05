//! Shared engine helpers.

use super::super::chain::set_xor_for;
use super::super::hmac::{HmacSha256, HmacSha256Key, expand};
use super::super::kem::{KEM_SHARED_LEN, kem_ct_len, kem_pk_len};
use super::super::payload::{
    ConversationSort, PacketPlain, Ticket, TxInviteeIntro, TxInviterIntro, TxNotice, TxPayload,
};
use super::super::sign::sign_pk_len;
use super::super::{
    Actor, Address, ConversationId, DisplayName, DurableChannel, EngineError, FragIndex, Json,
    Kind, Policy, Secret, Tag, TagKey, TimeBin, UnixSeconds,
};
use super::party::HandshakeFailure;
use super::query::*;
use super::state::{BinKey, BinProgress, EngineState};
use std::cmp::Ordering;
use std::collections::BTreeSet;

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
    if let Some(log) = dm_handshake_log(state, conversation_id) {
        return log.values().find_map(|row| match &row.payload {
            super::row_log::DmHandshakeTx::Notice(notice) => Some(notice),
            _ => None,
        });
    }
    sync_handshake_log(state, conversation_id).and_then(|log| {
        log.values().find_map(|row| match &row.payload {
            super::row_log::SyncHandshakeTx::Notice(notice) => Some(notice),
            _ => None,
        })
    })
}

pub(super) fn invitee_intro_for(
    state: &EngineState,
    conversation_id: ConversationId,
) -> Option<&TxInviteeIntro> {
    if let Some(log) = dm_handshake_log(state, conversation_id) {
        return log.values().find_map(|row| match &row.payload {
            super::row_log::DmHandshakeTx::InviteeIntro(intro) => Some(intro),
            _ => None,
        });
    }
    sync_handshake_log(state, conversation_id).and_then(|log| {
        log.values().find_map(|row| match &row.payload {
            super::row_log::SyncHandshakeTx::InviteeIntro(intro) => Some(&intro.intro),
            _ => None,
        })
    })
}

pub(super) fn invitee_intro_tx_id(
    state: &EngineState,
    conversation_id: ConversationId,
) -> Option<Tag> {
    state
        .body_pairs()
        .into_iter()
        .find_map(|(id, t)| match &t.payload {
            TxPayload::InviteeIntro(_) | TxPayload::SyncInviteeIntro(_)
                if t.conversation_id == conversation_id =>
            {
                Some(id)
            }
            _ => None,
        })
}

pub(super) fn sync_peer_device(
    state: &EngineState,
    handshake: ConversationId,
) -> Option<super::super::DeviceId> {
    let ours = state.device.keys.as_ref().map(|keys| keys.id);
    state.bodies().iter().find_map(|tx| {
        if tx.conversation_id != handshake {
            return None;
        }
        match &tx.payload {
            TxPayload::SyncInviterIntro(intro) if ours != Some(intro.device_id) => {
                Some(intro.device_id)
            }
            TxPayload::SyncInviteeIntro(intro) if ours != Some(intro.device_id) => {
                Some(intro.device_id)
            }
            _ => None,
        }
    })
}

pub(super) fn inviter_intro_for(
    state: &EngineState,
    conversation_id: ConversationId,
) -> Option<&TxInviterIntro> {
    if let Some(log) = dm_handshake_log(state, conversation_id) {
        return log.values().find_map(|row| match &row.payload {
            super::row_log::DmHandshakeTx::InviterIntro(intro) => Some(intro),
            _ => None,
        });
    }
    sync_handshake_log(state, conversation_id).and_then(|log| {
        log.values().find_map(|row| match &row.payload {
            super::row_log::SyncHandshakeTx::InviterIntro(intro) => Some(&intro.intro),
            _ => None,
        })
    })
}

fn dm_handshake_log(
    state: &EngineState,
    cid: ConversationId,
) -> Option<&super::row_log::TxLog<super::row_log::DmHandshakeTx>> {
    for user in state.users.values() {
        for ident in user.identities.values() {
            if let Some(super::party::IdentityConversation::DmHandshake { log, .. }) =
                ident.conversations.get(&cid).map(|node| &node.kind)
            {
                return Some(log);
            }
        }
    }
    None
}

fn sync_handshake_log(
    state: &EngineState,
    cid: ConversationId,
) -> Option<&super::row_log::TxLog<super::row_log::SyncHandshakeTx>> {
    match state.device.conversations.get(&cid).map(|node| &node.kind) {
        Some(super::party::DeviceConversation::SyncHandshake { log, .. }) => Some(log),
        _ => None,
    }
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
        HandshakeFailure::IntroUnlockFailed
    } else {
        HandshakeFailure::NoticeUnlockFailed
    };
    state.fail(cid, reason);
}

pub(super) fn handshake_rows(
    state: &EngineState,
) -> Vec<(ConversationId, Ticket, ConversationSort)> {
    state
        .handshake_entries()
        .into_iter()
        .map(|row| (row.cid, row.party.ticket().clone(), row.sort))
        .collect()
}

pub(super) fn catch_up_start(progress: Option<&BinProgress>, list_from: TimeBin) -> TimeBin {
    progress
        .and_then(|p| p.watermark)
        .map(|w| w.saturating_add(1))
        .unwrap_or(list_from)
}

pub(super) fn listen_bins(w: TimeBin) -> [TimeBin; 3] {
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

pub(super) fn invite_tag(hmac: &dyn HmacSha256, secret: &[u8; 32], bin: TimeBin) -> Tag {
    Tag::from_bytes(
        expand(
            hmac,
            &HmacSha256Key::from_bytes(*secret),
            &[
                b"chuchotez/1/handshake-invite".as_slice(),
                &bin.as_u64().to_be_bytes(),
            ]
            .concat(),
        )
        .into_bytes(),
    )
}

pub(super) fn progress_key(channel: &DurableChannel, tag_key: &TagKey) -> BinKey {
    BinKey {
        channel: channel.clone(),
        tag_key: *tag_key,
    }
}

pub(super) fn bin_complete(progress: Option<&BinProgress>, bin: TimeBin) -> bool {
    let Some(p) = progress else {
        return false;
    };
    p.watermark.is_some_and(|w| bin <= w) || p.completed.contains(&bin)
}

pub(super) fn advance_progress(progress: &mut BinProgress, list_from: TimeBin) {
    loop {
        let next = match progress.watermark {
            None => list_from,
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
    pub(super) frag_i: FragIndex,
    pub(super) frag: Vec<u8>,
    pub(super) last_i: Option<FragIndex>,
}

pub(super) fn frag_parts(packet: &PacketPlain) -> Option<FragPart> {
    match packet {
        PacketPlain::TxFragMore(p) => Some(FragPart {
            tx_id: p.tx_id,
            frag_i: FragIndex::from_u64(p.frag_i),
            frag: p.frag.clone(),
            last_i: None,
        }),
        PacketPlain::TxFragLast(p) => Some(FragPart {
            tx_id: p.tx_id,
            frag_i: FragIndex::from_u64(p.frag_i),
            frag: p.frag.clone(),
            last_i: Some(FragIndex::from_u64(p.frag_i)),
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
    for frag in state.frags.values_mut() {
        frag.conversation_id = rekey_cid(frag.conversation_id, from, to);
    }
}

#[rustfmt::skip]
pub(super) fn rekey_cid(cid: ConversationId, from: ConversationId, to: ConversationId) -> ConversationId {
    if cid == from { to } else { cid }
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

#[cfg(test)]
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
                policy: super::super::payload::parse_policy(p)
                    .ok_or(EngineError::MalformedPersist)?,
            }
        }
        "InviteExpired" => {
            let Json::Number(expires) = get("expires").ok_or(EngineError::MalformedPersist)? else {
                return Err(EngineError::MalformedPersist);
            };
            FailedReason::InviteExpired {
                expires: UnixSeconds::from_u64(*expires),
            }
        }
        "NoticeUnlockFailed" => FailedReason::NoticeUnlockFailed,
        "NoticeConflict" => FailedReason::NoticeConflict,
        "IntroUnlockFailed" => FailedReason::IntroUnlockFailed,
        "IntroVerifyFailed" => FailedReason::IntroVerifyFailed,
        "DuplicateIntro" => FailedReason::DuplicateIntro,
        "ConfirmationRejected" => FailedReason::ConfirmationRejected,
        "Equivocation" => FailedReason::Equivocation,
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

pub(super) fn actor_for(
    sort: super::super::payload::ConversationSort,
    bytes: &[u8],
) -> Option<super::super::Actor> {
    use super::super::Actor;
    use super::super::payload::ConversationSort;
    match sort {
        ConversationSort::HandshakeDm | ConversationSort::HandshakeSync => {
            bytes.is_empty().then_some(Actor::handshake())
        }
        ConversationSort::DirectMessage | ConversationSort::Group => {
            (!bytes.is_empty()).then(|| Actor::signing(bytes.to_vec()))
        }
        ConversationSort::Synchronization => {
            let id: [u8; 32] = bytes.try_into().ok()?;
            Some(Actor::device(super::super::DeviceId::from_bytes(id)))
        }
        ConversationSort::Engine => None,
    }
}

pub(super) fn conversation_tx_ids(
    state: &EngineState,
    conversation_id: ConversationId,
) -> BTreeSet<Tag> {
    state
        .body_pairs()
        .into_iter()
        .filter(|(_, body)| body.conversation_id == conversation_id)
        .map(|(id, _)| id)
        .collect()
}

pub(super) fn watermark_of(state: &EngineState, conversation_id: ConversationId) -> BTreeSet<Tag> {
    let Some(chains) = state.chains(conversation_id) else {
        return conversation_tx_ids(state, conversation_id);
    };
    let mut iter = chains.last_acks.values().filter(|set| !set.is_empty());
    let Some(first) = iter.next() else {
        return conversation_tx_ids(state, conversation_id);
    };
    iter.fold(first.clone(), |acc, set| {
        acc.intersection(set).copied().collect()
    })
}

pub(super) fn tx_watermarked(state: &EngineState, tx_id: Tag) -> bool {
    state
        .body(&tx_id)
        .is_some_and(|body| watermark_of(state, body.conversation_id).contains(&tx_id))
}

pub(super) fn payload_expire_at(payload: &TxPayload) -> Option<UnixSeconds> {
    match payload {
        TxPayload::Text(t) => t.expire_at,
        TxPayload::Media(m) => m.expire_at,
        _ => None,
    }
}

pub(super) fn persist_outside_watermark(state: &EngineState) -> bool {
    let now = state.ticked.unwrap_or_default();
    state.persist_log.values().any(|tx_id| {
        let Some(body) = state.body(tx_id) else {
            return false;
        };
        if payload_expire_at(&body.payload).is_some_and(|expires| expires <= now) {
            return false;
        }
        !tx_watermarked(state, *tx_id)
    })
}

pub(super) fn store_durable_last_ack(
    state: &mut EngineState,
    conversation_id: ConversationId,
    actor_id: &[u8],
    set_xor: Tag,
) {
    if set_xor_for(state.body_pairs(), conversation_id) != set_xor {
        return;
    }
    let Some(sort) = state.sort_of(conversation_id) else {
        return;
    };
    let Some(actor) = actor_for(sort, actor_id) else {
        return;
    };
    let ids = conversation_tx_ids(state, conversation_id);
    if let Some(chains) = state.chains_mut(conversation_id) {
        chains.last_acks.insert(actor, ids);
    }
}

pub(super) fn prune_cached_mks(state: &mut EngineState) {
    let drop: BTreeSet<Tag> = {
        let mut ids = Vec::new();
        state.for_each_chains(|_, chains| {
            ids.extend(
                chains
                    .skipped_mks
                    .values()
                    .flatten()
                    .filter_map(|e| e.tx_id),
            );
        });
        ids.into_iter()
            .filter(|id| tx_watermarked(state, *id))
            .collect()
    };
    state.each_chains_mut(|chains| {
        for entries in chains.skipped_mks.values_mut() {
            entries.retain(|e| e.tx_id.is_none_or(|id| !drop.contains(&id)));
        }
        chains.skipped_mks.retain(|_, e| !e.is_empty());
    });
}

pub(super) fn annotate_cached_mk(
    state: &mut EngineState,
    cid: ConversationId,
    actor: &Actor,
    mk: &[u8; 32],
    tx_id: Tag,
) {
    if let Some(chains) = state.chains_mut(cid)
        && let Some(entries) = chains.skipped_mks.get_mut(actor)
    {
        for e in entries {
            if &e.mk == mk {
                e.tx_id = Some(tx_id);
            }
        }
    }
}

pub(super) fn intro_watermarked(state: &EngineState, conversation_id: ConversationId) -> bool {
    let Some(tx_id) = invitee_intro_tx_id(state, conversation_id) else {
        return false;
    };
    state
        .chains(conversation_id)
        .is_some_and(|c| c.last_acks.values().any(|set| !set.is_empty()))
        && watermark_of(state, conversation_id).contains(&tx_id)
}
