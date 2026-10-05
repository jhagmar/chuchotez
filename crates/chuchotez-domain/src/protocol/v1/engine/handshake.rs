//! Handshake query, intro mint, ingest, fingerprint, and spawn.

use super::super::chain::{eph_mk, join, open_at, open_plain};
use super::super::codec::{durable_body_from_json, payload_to_json};
use super::super::hmac::{HmacSha256Key, expand};
use super::super::kem::KEM_SHARED_LEN;
use super::super::payload::{
    PACKET_MAX_UNCOMPRESSED, PacketPlain, TxInviteeIntro, TxInviterIntro, TxPayload, time_bin,
};
use super::super::{
    Actor, Address, ConversationId, DurableChannel, EngineError, EphemeralChannel, FragIndex,
    IdentityId, KemSeed, Kind, OnWirePrefs, Policy, Secret, SignSeed, Tag, TagKey, TimeBin,
    UnixSeconds, UserId,
};
use super::helpers::*;
use super::live::LiveChannel;
use super::party::{HandshakeFailure, PhaseKind};
use super::query::*;
use super::state::*;
use super::{
    Engine, EngineState, HANDSHAKE_DM_ESTABLISHED_INFO, HANDSHAKE_SYNC_ESTABLISHED_INFO,
    SPAWN_CONVERSATION_ID_INFO, SPAWN_SECRET_INFO,
};
use crate::protocol::Rng;
use std::collections::{BTreeMap, BTreeSet};

fn fingerprint_payloads(
    state: &EngineState,
    conversation_id: ConversationId,
    inviter: &TxInviterIntro,
    invitee: &TxInviteeIntro,
) -> Option<(TxPayload, TxPayload)> {
    let (inviter_payload, invitee_payload) = if state.is_sync(conversation_id) {
        let mut inviter_payload = None;
        let mut invitee_payload = None;
        for tx in state.bodies().iter() {
            if tx.conversation_id != conversation_id {
                continue;
            }
            match &tx.payload {
                TxPayload::SyncInviterIntro(_) => inviter_payload = Some(tx.payload.clone()),
                TxPayload::SyncInviteeIntro(_) => invitee_payload = Some(tx.payload.clone()),
                _ => continue,
            }
        }
        (inviter_payload?, invitee_payload?)
    } else {
        (
            TxPayload::InviterIntro(inviter.clone()),
            TxPayload::InviteeIntro(invitee.clone()),
        )
    };
    if inviter.signing_pk <= invitee.signing_pk {
        Some((inviter_payload, invitee_payload))
    } else {
        Some((invitee_payload, inviter_payload))
    }
}

pub(super) enum HitChannel<'a> {
    Durable(&'a DurableChannel),
    Ephemeral(&'a EphemeralChannel),
}

impl Engine {
    /// List conversations.
    pub fn list_conversations(
        &self,
        state: &EngineState,
        _user_id: UserId,
        _identity_id: IdentityId,
    ) -> Result<Vec<ConversationListRow>, EngineError> {
        Ok(state
            .conversation_ids_for(_user_id, _identity_id)
            .into_iter()
            .filter_map(|conversation_id| {
                self.conversation_at(state, conversation_id)
                    .map(|conversation| ConversationListRow {
                        conversation_id,
                        conversation,
                    })
            })
            .collect())
    }

    pub(super) fn conversation_at(
        &self,
        state: &EngineState,
        conversation_id: ConversationId,
    ) -> Option<Conversation> {
        if let Some(group) = self.group_view(state, conversation_id) {
            return Some(group);
        }
        if state.established_secret(conversation_id).is_some() {
            if state.is_sync(conversation_id) {
                return Some(Conversation::Synchronization(
                    self.sync_view(state, conversation_id),
                ));
            }
            return Some(Conversation::DirectMessage(
                self.dm_view(state, conversation_id),
            ));
        }
        let party = state.party(conversation_id)?;
        let sync = state.is_sync(conversation_id);
        let row = self.project_party(state, conversation_id, &party);
        Some(if sync {
            Conversation::HandshakeSync(row)
        } else {
            Conversation::HandshakeDm(row)
        })
    }

    pub(super) fn sync_view(
        &self,
        state: &EngineState,
        cid: ConversationId,
    ) -> super::SyncEstablishedView {
        let device_name = state
            .device
            .name
            .clone()
            .unwrap_or_else(|| super::super::DisplayName::try_from(".").expect("dot"));
        let parent = state.established_parent(cid);
        let notice = parent.and_then(|id| notice_for(state, id));
        let mut members = Vec::new();
        if let Some(keys) = &state.device.keys {
            members.push(super::SyncMemberView {
                device_id: keys.id,
                signing_pk: crate::protocol::v1::SigningPublicKey::from_bytes(
                    keys.sign.public_bytes().to_vec(),
                ),
                encryption_pk: crate::protocol::v1::EncryptionPublicKey::from_bytes(
                    keys.enc.public_bytes().to_vec(),
                ),
                name: device_name.clone(),
                last_active: None,
            });
        }
        let local_sign = state
            .device
            .keys
            .as_ref()
            .map(|keys| keys.sign.public_bytes().to_vec());
        let peer_device = state
            .device
            .conversations
            .get(&cid)
            .and_then(|node| match &node.kind {
                super::party::DeviceConversation::Synchronization { peer, .. } => Some(*peer),
                super::party::DeviceConversation::SyncHandshake { .. } => None,
            });
        if let (Some(parent), Some(peer_device)) = (parent, peer_device) {
            if let Some(intro) = inviter_intro_for(state, parent)
                && local_sign
                    .as_ref()
                    .is_none_or(|signing| signing.as_slice() != intro.signing_pk.as_bytes())
            {
                members.push(super::SyncMemberView {
                    device_id: peer_device,
                    signing_pk: intro.signing_pk.clone(),
                    encryption_pk: intro.encryption_pk.clone(),
                    name: intro.name.clone(),
                    last_active: state.established(cid).and_then(|chains| chains.presence_at),
                });
            } else if let Some(intro) = invitee_intro_for(state, parent) {
                members.push(super::SyncMemberView {
                    device_id: peer_device,
                    signing_pk: intro.signing_pk.clone(),
                    encryption_pk: intro.encryption_pk.clone(),
                    name: intro.name.clone(),
                    last_active: state.established(cid).and_then(|chains| chains.presence_at),
                });
            }
        }
        super::SyncEstablishedView {
            device_name,
            members,
            persistents: notice
                .map(|row| row.persistents.clone())
                .unwrap_or_default(),
            ephemerals: notice.map(|row| row.ephemerals.clone()).unwrap_or_default(),
            last_active: state.established(cid).and_then(|chains| chains.presence_at),
        }
    }

    pub(super) fn project_party(
        &self,
        state: &EngineState,
        conversation_id: ConversationId,
        party: &super::party::PartyRef<'_>,
    ) -> Handshake {
        use super::party::PhaseKind;
        let expires = party.ticket().expires;
        let digest = self
            .try_fingerprint(state, conversation_id)
            .map(|(d, _)| d)
            .unwrap_or_default();
        let policy = party
            .invitee_policy()
            .unwrap_or(super::super::Policy::Classic);
        match party.kind() {
            PhaseKind::InviteCreated => {
                Handshake::Inviter(HandshakeInviter::InviteCreated { expires })
            }
            PhaseKind::NoticePinned => {
                Handshake::Inviter(HandshakeInviter::NoticePinned { expires })
            }
            PhaseKind::InviterIntroMinted => {
                Handshake::Inviter(HandshakeInviter::IntroductionMinted { expires })
            }
            PhaseKind::Confirming if party.is_inviter() => {
                Handshake::Inviter(HandshakeInviter::Confirming {
                    expires,
                    confirmation_digest: digest,
                })
            }
            PhaseKind::Confirming => Handshake::Invitee(HandshakeInvitee::Confirming {
                policy,
                expires,
                confirmation_digest: digest,
            }),
            PhaseKind::TicketReceived => Handshake::Invitee(HandshakeInvitee::TicketReceived),
            PhaseKind::InviteReceived => {
                Handshake::Invitee(HandshakeInvitee::InviteReceived { policy, expires })
            }
            PhaseKind::InviteeIntroMinted => {
                Handshake::Invitee(HandshakeInvitee::IntroductionMinted { policy, expires })
            }
            PhaseKind::IntroductionSent => {
                Handshake::Invitee(HandshakeInvitee::IntroductionSent { policy, expires })
            }
            PhaseKind::Failed(reason) => Handshake::Failed(reason.into()),
        }
    }

    pub(super) fn conv_secret(
        &self,
        state: &EngineState,
        conversation_id: &ConversationId,
    ) -> Result<Secret, EngineError> {
        state
            .ticket(*conversation_id)
            .map(|t| t.secret)
            .or_else(|| state.established_secret(*conversation_id))
            .ok_or(EngineError::UnknownIds)
    }

    pub(super) fn try_fingerprint(
        &self,
        state: &EngineState,
        conversation_id: ConversationId,
    ) -> Option<(String, Secret)> {
        let ticket = state.ticket(conversation_id)?;
        let inviter = inviter_intro_for(state, conversation_id)?;
        let invitee = invitee_intro_for(state, conversation_id)?;
        let hs = state.party(conversation_id)?;
        let shared_inviter = hs.shared_inviter()?;
        let shared_invitee = hs.shared_invitee()?;
        let hmac = self.suite.hmac();
        let key = HmacSha256Key::from_bytes(*ticket.secret.as_bytes());
        let mut spawn_data = SPAWN_SECRET_INFO.to_vec();
        spawn_data.extend(sort32(shared_inviter.as_bytes(), shared_invitee.as_bytes()));
        let spawn_secret = Secret::from_bytes(hmac.mac(&key, &spawn_data).into_bytes());
        let label = if state.is_sync(conversation_id) {
            HANDSHAKE_SYNC_ESTABLISHED_INFO
        } else {
            HANDSHAKE_DM_ESTABLISHED_INFO
        };
        let fp_key = expand(hmac, &key, label);
        let (lo, hi) = fingerprint_payloads(state, conversation_id, inviter, invitee)?;
        let mut data = self
            .suite
            .canonical_json()
            .encode(&payload_to_json(self.suite.b64u(), &lo));
        data.extend(
            self.suite
                .canonical_json()
                .encode(&payload_to_json(self.suite.b64u(), &hi)),
        );
        data.extend_from_slice(spawn_secret.as_bytes());
        let fingerprint = hmac
            .mac(&HmacSha256Key::from_bytes(*fp_key.as_bytes()), &data)
            .into_bytes();
        Some((self.suite.b64u().encode(&fingerprint), spawn_secret))
    }

    pub(super) fn unwrap_shared(&self, policy: Policy, sk: &[u8], ct: &[u8]) -> Result<Secret, ()> {
        let shared = self.suite.kem().unwrap(policy, sk, ct).map_err(|_| ())?;
        if shared.len() != KEM_SHARED_LEN {
            return Err(());
        }
        let mut out = [0u8; KEM_SHARED_LEN];
        out.copy_from_slice(&shared);
        Ok(Secret::from_bytes(out))
    }

    pub(super) fn spawn_child(
        &self,
        state: &mut EngineState,
        handshake: ConversationId,
    ) -> Result<(), EngineError> {
        let cid = handshake;
        let Some((_, spawn_secret)) = self.try_fingerprint(state, handshake) else {
            return Err(EngineError::MalformedPayload);
        };
        let child = ConversationId::from_bytes(
            self.suite
                .hmac()
                .mac(
                    &HmacSha256Key::from_bytes(*spawn_secret.as_bytes()),
                    SPAWN_CONVERSATION_ID_INFO,
                )
                .into_bytes(),
        );
        let peer = if state.is_sync(handshake) {
            #[rustfmt::skip]
            let id = super::helpers::sync_peer_device(state, handshake).ok_or(EngineError::WrongPhase)?;
            super::state::SpawnPeer::Sync(id)
        } else {
            super::state::SpawnPeer::Direct
        };
        state.spawn_established(cid, child, spawn_secret, peer);
        Ok(())
    }

    /// Move handshake phases whose invite-tag writes are fully acked.
    pub(super) fn advance_ack_phases(&self, state: &mut EngineState) {
        let cids: Vec<_> = handshake_rows(state)
            .into_iter()
            .map(|(id, _, _)| id)
            .collect();
        for cid in cids {
            if !self.invite_writes_pending(state, cid) {
                state.ack_posted(cid);
            }
        }
    }

    fn invite_writes_pending(&self, state: &EngineState, cid: ConversationId) -> bool {
        let party = state.party(cid).expect("handshake row");
        let ticket = party.ticket().clone();
        let start = party.list_from();
        let end = state
            .ticked
            .map(super::super::payload::time_bin)
            .unwrap_or(start)
            .saturating_add(1);
        let mut tags = Vec::new();
        let mut bin = start;
        loop {
            tags.push(invite_tag(self.suite.hmac(), ticket.secret.as_bytes(), bin));
            if bin >= end {
                break;
            }
            bin = bin.saturating_add(1);
        }
        state.writes.iter().any(|w| {
            ticket.persistents.iter().any(|ch| ch == &w.channel)
                && tags.iter().any(|tag| tag == &w.tag)
        })
    }

    pub(super) fn require_ids(
        &self,
        state: &EngineState,
        ids: &ConversationRef,
    ) -> Result<(), EngineError> {
        self.identity_policy(state, &ids.user_id, &ids.identity_id)?;
        Ok(())
    }

    pub(super) fn mint_on(
        &self,
        state: EngineState,
        rng: &dyn Rng,
        ids: &ConversationRef,
        payload: TxPayload,
    ) -> Result<MutateOk, EngineError> {
        self.require_ids(&state, ids)?;
        let secret = self.conv_secret(&state, &ids.conversation_id)?;
        let mut ok = self.mutate_on(state, &secret, ids.conversation_id, vec![payload.clone()])?;
        #[rustfmt::skip]
        self.deliver_live(&mut ok.state, rng, ids.conversation_id, &secret, std::slice::from_ref(&payload))?;
        Ok(ok)
    }

    pub(super) fn require_confirming(
        &self,
        state: &EngineState,
        ids: &ConversationRef,
    ) -> Result<(), EngineError> {
        match self.conversation_at(state, ids.conversation_id) {
            Some(Conversation::HandshakeDm(Handshake::Inviter(HandshakeInviter::Confirming {
                ..
            })))
            | Some(Conversation::HandshakeDm(Handshake::Invitee(HandshakeInvitee::Confirming {
                ..
            })))
            | Some(Conversation::HandshakeSync(Handshake::Inviter(
                HandshakeInviter::Confirming { .. },
            )))
            | Some(Conversation::HandshakeSync(Handshake::Invitee(
                HandshakeInvitee::Confirming { .. },
            ))) => {
                let decided = state.bodies().iter().any(|t| {
                    matches!(t.payload, TxPayload::Confirm | TxPayload::Reject)
                        && t.conversation_id == ids.conversation_id
                });
                if decided {
                    Err(EngineError::WrongPhase)
                } else {
                    Ok(())
                }
            }
            _ => Err(EngineError::WrongPhase),
        }
    }

    pub(super) fn on_wire_prefs(&self) -> OnWirePrefs {
        OnWirePrefs {
            read_receipts: self.defaults.read_receipts(),
            online_visible: self.defaults.online_visible(),
            send_typing: self.defaults.send_typing(),
            disappear_after: self.defaults.disappear_after(),
            wake: None,
        }
    }

    pub(super) fn identity_keys(
        &self,
        state: &EngineState,
        user_id: &UserId,
        identity_id: &IdentityId,
    ) -> Option<(Policy, Vec<u8>, Vec<u8>)> {
        state.bodies().iter().find_map(|tx| match &tx.payload {
            TxPayload::EngineCreateIdentity {
                user_id: u,
                identity_id: i,
                policy,
                encryption,
                signing,
            } if u == user_id && i == identity_id => Some((
                *policy,
                encryption.public_bytes().to_vec(),
                signing.public_bytes().to_vec(),
            )),
            _ => None,
        })
    }

    pub(super) fn ensure_device_keys(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        policy: Policy,
    ) -> Result<(), EngineError> {
        if state.device.keys.is_none() {
            state.device.keys = Some(super::state::DeviceKeys {
                id: super::super::DeviceId::from(rng.random32()),
                enc: self
                    .suite
                    .kem()
                    .generate(policy, &KemSeed::from_pair(rng.random32(), rng.random32()))
                    .map_err(|_| EngineError::MalformedPayload)?,
                sign: self
                    .suite
                    .sign()
                    .generate(policy, &SignSeed::from_pair(rng.random32(), rng.random32()))
                    .map_err(|_| EngineError::MalformedPayload)?,
            });
        }
        Ok(())
    }

    pub(super) fn local_calling(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        conversation_id: ConversationId,
        policy: Policy,
    ) -> Result<Option<CallingParts>, EngineError> {
        let cid = conversation_id;
        if state.is_sync(cid) {
            #[rustfmt::skip]
            let Some(name) = state.device.name.clone() else { return Ok(None); };
            self.ensure_device_keys(state, rng, policy)?;
            let keys = state.device.keys.as_ref().expect("device keys");
            return Ok(Some((
                name,
                None,
                keys.enc.public_bytes().to_vec(),
                keys.sign.public_bytes().to_vec(),
            )));
        }
        #[rustfmt::skip]
        let Some((uid, iid)) = state.owner(cid) else { return Ok(None); };
        #[rustfmt::skip]
        let Some(name) = state.display_name(iid).cloned() else { return Ok(None); };
        #[rustfmt::skip]
        let Some((id_policy, enc, sign)) = self.identity_keys(state, &uid, &iid) else { return Ok(None); };
        if id_policy != policy {
            state.fail(cid, HandshakeFailure::PolicyNotAccepted { policy });
            return Ok(None);
        }
        let pic = state.profile_pic(iid);
        Ok(Some((name, pic, enc, sign)))
    }

    pub(super) fn mint_pending_intros(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
    ) -> Result<Vec<Vec<u8>>, EngineError> {
        let cids: Vec<ConversationId> = handshake_rows(state)
            .into_iter()
            .map(|(id, _, _)| id)
            .collect();
        let mut persist = Vec::new();
        for cid in cids {
            persist.extend(self.try_mint_invitee_intro(state, rng, cid)?);
            persist.extend(self.try_mint_inviter_intro(state, rng, cid)?);
        }
        Ok(persist)
    }

    pub(super) fn try_mint_invitee_intro(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        conversation_id: ConversationId,
    ) -> Result<Vec<Vec<u8>>, EngineError> {
        let cid = conversation_id;
        if state.party(conversation_id).map(|p| p.kind()) != Some(PhaseKind::InviteReceived) {
            return Ok(Vec::new());
        }
        if invitee_intro_for(state, conversation_id).is_some() {
            return Ok(Vec::new());
        }
        #[rustfmt::skip]
        let Some(notice) = notice_for(state, conversation_id).cloned() else { return Ok(Vec::new()); };
        #[rustfmt::skip]
        let Some((name, pic, enc, sign)) = self.local_calling(state, rng, conversation_id, notice.policy)? else { return Ok(Vec::new()); };
        let intake = self
            .suite
            .kem()
            .generate(
                notice.policy,
                &KemSeed::from_pair(rng.random32(), rng.random32()),
            )
            .map_err(|_| EngineError::MalformedPayload)?;
        let seed = KemSeed::from_pair(rng.random32(), rng.random32());
        #[rustfmt::skip]
        let (shared, seed_ct) = self.suite.kem().wrap(notice.policy, &notice.intake_pk, &seed).map_err(|_| EngineError::MalformedPayload)?;
        let shared_inviter = take_shared32(shared);
        let intro = TxInviteeIntro {
            name,
            profile_pic: pic,
            send_tag_key: TagKey::from(rng.random32()),
            eph_send_tag_key: TagKey::from(rng.random32()),
            encryption_pk: crate::protocol::v1::EncryptionPublicKey::from_bytes(enc),
            signing_pk: crate::protocol::v1::SigningPublicKey::from_bytes(sign),
            intake_pk: crate::protocol::v1::EncryptionPublicKey::from_bytes(
                intake.public_bytes().to_vec(),
            ),
            seed_ct,
            prefs: self.on_wire_prefs(),
        };
        let payload = if state.is_sync(conversation_id) {
            let device_id = state
                .device
                .keys
                .as_ref()
                .map(|keys| keys.id)
                .ok_or(EngineError::WrongPhase)?;
            TxPayload::SyncInviteeIntro(super::super::payload::SyncInviteeIntro {
                intro,
                device_id,
            })
        } else {
            TxPayload::InviteeIntro(intro)
        };
        if let Some(mut party) = state.party_mut(cid)
            && let Some(invitee) = party.invitee_mut()
        {
            let _ = invitee.mint_intro(intake, shared_inviter);
        }
        let secret = self.conv_secret(state, &conversation_id)?;
        let (tx_id, _, rec) = self.merge_tx(state, &secret, conversation_id, payload)?;
        self.post_handshake_packets(state, rng, conversation_id, &secret, tx_id)?;
        Ok(vec![rec])
    }

    pub(super) fn try_mint_inviter_intro(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        conversation_id: ConversationId,
    ) -> Result<Vec<Vec<u8>>, EngineError> {
        let cid = conversation_id;
        if state.party(conversation_id).map(|p| p.kind()) != Some(PhaseKind::NoticePinned) {
            return Ok(Vec::new());
        }
        if inviter_intro_for(state, conversation_id).is_some() {
            return Ok(Vec::new());
        }
        #[rustfmt::skip]
        let Some(invitee) = invitee_intro_for(state, conversation_id).cloned() else { return Ok(Vec::new()); };
        #[rustfmt::skip]
        let Some(notice) = notice_for(state, conversation_id).cloned() else { return Ok(Vec::new()); };
        #[rustfmt::skip]
        let Some((name, pic, enc, sign)) = self.local_calling(state, rng, conversation_id, notice.policy)? else { return Ok(Vec::new()); };
        let seed = KemSeed::from_pair(rng.random32(), rng.random32());
        let (shared, seed_ct) = match self.suite.kem().wrap(
            notice.policy,
            &invitee.intake_pk,
            &seed,
        ) {
            Ok(v) => v,
            #[rustfmt::skip]
            Err(_) => { state.fail(cid, HandshakeFailure::IntroVerifyFailed); return Ok(Vec::new()); }
        };
        let sk = state.intake_secret(cid).expect("inviter intake");
        let shared_inviter = match self.unwrap_shared(notice.policy, &sk, &invitee.seed_ct) {
            Ok(s) => s,
            Err(()) => {
                state.fail(cid, HandshakeFailure::IntroVerifyFailed);
                return Ok(Vec::new());
            }
        };
        let shared_invitee = take_shared32(shared);
        if let Some(mut party) = state.party_mut(cid)
            && let Some(inviter) = party.inviter_mut()
        {
            let _ = inviter.mint_intro(shared_inviter, shared_invitee);
        }
        let intro = TxInviterIntro {
            name,
            profile_pic: pic,
            send_tag_key: TagKey::from(rng.random32()),
            eph_send_tag_key: TagKey::from(rng.random32()),
            encryption_pk: crate::protocol::v1::EncryptionPublicKey::from_bytes(enc),
            signing_pk: crate::protocol::v1::SigningPublicKey::from_bytes(sign),
            seed_ct,
            prefs: self.on_wire_prefs(),
        };
        let payload = if state.is_sync(conversation_id) {
            let device_id = state
                .device
                .keys
                .as_ref()
                .map(|keys| keys.id)
                .ok_or(EngineError::WrongPhase)?;
            TxPayload::SyncInviterIntro(super::super::payload::SyncInviterIntro {
                intro,
                device_id,
            })
        } else {
            TxPayload::InviterIntro(intro)
        };
        let secret = self.conv_secret(state, &conversation_id)?;
        let (tx_id, _, rec) = self.merge_tx(state, &secret, conversation_id, payload)?;
        self.post_handshake_packets(state, rng, conversation_id, &secret, tx_id)?;
        Ok(vec![rec])
    }

    /// Ingest a complete durable `list` snapshot. Completes that TimeBin in
    /// `BinProgress`. A valid `TxNotice` is `InviteReceived`. A valid intro
    /// advances IntroductionMinted / Confirming. Unlock and policy failures
    /// store `FailedReason`.
    pub fn ingest_list(
        &mut self,
        state: EngineState,
        rng: &dyn Rng,
        channel: DurableChannel,
        tag: Tag,
        bodies: &[Vec<u8>],
    ) -> Result<MutateOk, EngineError> {
        let now = Self::require_tick(&state)?;
        let _ = self.require_dek()?;
        let hits = self.handshake_hits(&state, HitChannel::Durable(&channel), &tag, now);
        if hits.is_empty() {
            return Err(EngineError::UnknownTag);
        }
        let mut state = state;
        self.reseal_due(&mut state, rng)?;
        let mut persist = Vec::new();
        for body in bodies {
            persist.extend(self.ingest_known_body(&mut state, rng, &hits, body, true)?);
        }
        self.complete_list_bin(&mut state, &channel, &hits[0], now);
        Ok(MutateOk {
            state,
            persist,
            pings: Vec::new(),
        })
    }

    /// Ingest one 512-byte mapper body. Opens with skip-ahead `mk` and
    /// reassembles fragments. Durable `PacketTxFragLast` / `PacketXorAck`
    /// matching `set_xor` after merge stores that actor's last Persistent ack.
    pub fn ingest_packet(
        &mut self,
        mut state: EngineState,
        rng: &dyn Rng,
        channel: DurableChannel,
        tag: Tag,
        body: &[u8],
    ) -> Result<MutateOk, EngineError> {
        let now = Self::require_tick(&state)?;
        let hits = self.handshake_hits(&state, HitChannel::Durable(&channel), &tag, now);
        if hits.is_empty() {
            return self.finish_established(state, rng, LiveChannel::Durable(&channel), &tag, body);
        }
        self.reseal_due(&mut state, rng)?;
        let persist = self.ingest_known_body(&mut state, rng, &hits, body, true)?;
        Ok(MutateOk {
            state,
            persist,
            pings: Vec::new(),
        })
    }

    /// Ingest one 512-byte ephemeral body. Matching `PacketXorAck` is a live
    /// ack only.
    pub fn ingest_ephemeral_packet(
        &mut self,
        mut state: EngineState,
        rng: &dyn Rng,
        channel: EphemeralChannel,
        tag: Tag,
        body: &[u8],
    ) -> Result<MutateOk, EngineError> {
        let now = Self::require_tick(&state)?;
        let _ = self.require_dek()?;
        let hits = self.handshake_hits(&state, HitChannel::Ephemeral(&channel), &tag, now);
        if hits.is_empty() {
            return self.finish_established(state, rng, LiveChannel::Eph(&channel), &tag, body);
        }
        self.reseal_due(&mut state, rng)?;
        let persist = self.ingest_known_body(&mut state, rng, &hits, body, false)?;
        Ok(MutateOk {
            state,
            persist,
            pings: Vec::new(),
        })
    }

    /// Ack a blob put.
    pub fn write_blob_ack(
        &self,
        mut state: EngineState,
        kind: Kind,
        address: Address,
        tag: Tag,
        body: &[u8],
    ) -> Result<MutateOk, EngineError> {
        let before = state.blob_puts.len();
        state.blob_puts.retain(|w| {
            !(w.kind == kind && w.address == address && w.tag == tag && w.body.as_slice() == body)
        });
        if state.blob_puts.len() == before {
            return Err(EngineError::UnknownWrite);
        }
        Ok(MutateOk {
            state,
            persist: Vec::new(),
            pings: Vec::new(),
        })
    }

    /// Create a Sync invite. Posts sealed `PacketTxFragLast` (and `More`) of
    pub(super) fn handshake_hits(
        &self,
        state: &EngineState,
        channel: HitChannel<'_>,
        tag: &Tag,
        now: UnixSeconds,
    ) -> Vec<HandshakeHit> {
        let w = time_bin(now);
        let end = w.saturating_add(1);
        let mut hits = Vec::new();
        for row in state.handshake_entries() {
            let cid = row.cid;
            let ticket = row.party.ticket();
            let sort = row.sort;
            let matches_ch = match channel {
                HitChannel::Durable(d) => ticket.persistents.iter().any(|ch| ch == d),
                HitChannel::Ephemeral(e) => {
                    notice_for(state, cid).is_some_and(|n| n.ephemerals.iter().any(|ch| ch == e))
                }
            };
            if !matches_ch {
                continue;
            }
            let secret = ticket.secret;
            let tag_key = handshake_tag_key(self.suite.hmac(), secret.as_bytes());
            let progress = match channel {
                HitChannel::Durable(d) => state.bin_progress.get(&progress_key(d, &tag_key)),
                HitChannel::Ephemeral(_) => None,
            };
            let start = catch_up_start(progress, row.party.list_from());
            let mut bins: BTreeSet<TimeBin> = BTreeSet::new();
            for n in start.as_u64()..=end.as_u64() {
                bins.insert(TimeBin::from_u64(n));
            }
            for bin in listen_bins(w) {
                bins.insert(bin);
            }
            for bin in bins {
                if invite_tag(self.suite.hmac(), secret.as_bytes(), bin) == *tag {
                    hits.push(HandshakeHit {
                        cid,
                        secret,
                        sort,
                        bin,
                        tag_key,
                    });
                }
            }
        }
        hits
    }

    pub(super) fn ingest_known_body(
        &mut self,
        state: &mut EngineState,
        rng: &dyn Rng,
        hits: &[HandshakeHit],
        body: &[u8],
        persistent: bool,
    ) -> Result<Vec<Vec<u8>>, EngineError> {
        let now = Self::require_tick(state)?;
        for hit in hits {
            match self.open_and_merge(state, rng, hit, now, body, persistent) {
                Ok(persist) => return Ok(persist),
                Err(EngineError::UnknownTag) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(Vec::new())
    }

    pub(super) fn open_and_merge(
        &mut self,
        state: &mut EngineState,
        rng: &dyn Rng,
        hit: &HandshakeHit,
        now: UnixSeconds,
        body: &[u8],
        persistent: bool,
    ) -> Result<Vec<Vec<u8>>, EngineError> {
        if matches!(
            state.failed(hit.cid),
            Some(FailedReason::InviteExpired { .. })
        ) {
            return Err(EngineError::WrongPhase);
        }
        if state.failed(hit.cid).is_some() {
            return Err(EngineError::UnknownTag);
        }
        let actor = Actor::handshake();
        self.absorb_peer_wraps(state, hit.cid);
        let joined = join(self.suite.hmac(), hit.secret.as_bytes(), hit.sort, &[])?;
        let start = state
            .chains(hit.cid)
            .and_then(|c| c.recv.get(&actor).cloned())
            .unwrap_or_else(|| joined.clone());
        let mixed = self.mixed_chain(state, hit.cid, hit.sort, &start, false);
        let mut cached = state
            .chains(hit.cid)
            .and_then(|c| c.skipped_mks.get(&actor).cloned())
            .unwrap_or_default();
        cached.retain(|e| e.expires_at > now);
        if !persistent {
            let key = eph_mk(self.suite.hmac(), &start);
            if let Ok(packet) = open_plain(&self.suite, &key, body) {
                self.observe_ephemeral(state, rng, hit.cid, now, &packet)?;
                return Ok(Vec::new());
            }
        }
        let opened = match open_at(
            &self.suite,
            &start,
            mixed.as_ref(),
            &cached,
            now.as_u64(),
            body,
        ) {
            Ok(opened) => opened,
            Err(EngineError::UnknownTag)
                if start.epoch != joined.epoch
                    || start.packet_seq != joined.packet_seq
                    || start.root != joined.root =>
            {
                open_at(&self.suite, &joined, None, &cached, now.as_u64(), body)?
            }
            Err(e) => return Err(e),
        };
        cached.extend(opened.skipped.clone());
        cached.retain(|e| e.expires_at > now);
        if let Some(chains) = state.chains_mut(hit.cid) {
            if cached.is_empty() {
                chains.skipped_mks.remove(&actor);
            } else {
                chains.skipped_mks.insert(actor.clone(), cached);
            }
            if !opened.from_cache {
                let ahead = chains.recv.get(&actor).is_none_or(|cur| {
                    opened.chain.epoch > cur.epoch
                        || (opened.chain.epoch == cur.epoch
                            && opened.chain.packet_seq > cur.packet_seq)
                });
                if ahead {
                    chains.recv.insert(actor.clone(), opened.chain.clone());
                }
            } else {
                chains.recv.entry(actor.clone()).or_insert(start);
            }
        }
        let packet_tx = match &opened.packet {
            PacketPlain::TxFragMore(p) => Some(p.tx_id),
            PacketPlain::TxFragLast(p) => Some(p.tx_id),
            _ => None,
        };
        if opened.from_cache
            && let Some(tx_id) = packet_tx
        {
            annotate_cached_mk(state, hit.cid, &actor, &opened.mk, tx_id);
        }
        if let PacketPlain::XorAck(ack) = &opened.packet {
            let remote = ack.set_xor;
            if persistent {
                store_durable_last_ack(state, hit.cid, &ack.actor_id, remote);
            }
            self.note_set_xor(state, rng, hit.cid, remote)?;
            prune_cached_mks(state);
            return Ok(Vec::new());
        }
        if matches!(
            opened.packet,
            PacketPlain::HealHalfXor(_) | PacketPlain::HealWant(_) | PacketPlain::HealHave(_)
        ) {
            self.on_heal_packet(state, rng, hit.cid, &opened.packet)?;
            prune_cached_mks(state);
            return Ok(Vec::new());
        }
        let Some(part) = frag_parts(&opened.packet) else {
            prune_cached_mks(state);
            return Ok(Vec::new());
        };
        let set = state.frags.entry(part.tx_id).or_insert_with(|| FragSet {
            conversation_id: hit.cid,
            parts: BTreeMap::new(),
            last_i: None,
        });
        if let Some(existing) = set.parts.get(&part.frag_i)
            && existing != &part.frag
        {
            return Err(EngineError::Equivocation);
        }
        if let Some(prev_last) = set.last_i
            && let Some(new_last) = part.last_i
            && prev_last != new_last
        {
            return Err(EngineError::Equivocation);
        }
        set.parts.insert(part.frag_i, part.frag);
        if let Some(n) = part.last_i {
            set.last_i = Some(n);
        }
        let Some(last) = set.last_i else {
            return Ok(Vec::new());
        };
        for n in 0..=last.as_u64() {
            let i = FragIndex::from_u64(n);
            if !set.parts.contains_key(&i) {
                return Ok(Vec::new());
            }
        }
        let mut packed = Vec::new();
        for n in 0..=last.as_u64() {
            packed.extend_from_slice(&set.parts[&FragIndex::from_u64(n)]);
        }
        state.frags.remove(&part.tx_id);
        let canonical = match self
            .suite
            .compress()
            .decompress(&packed, PACKET_MAX_UNCOMPRESSED)
        {
            Ok(c) => c,
            #[rustfmt::skip]
            Err(_) => { store_unlock_failed(state, hit.cid); return Ok(Vec::new()); }
        };
        let json = match self.suite.canonical_json().decode(&canonical) {
            Ok(j) => j,
            #[rustfmt::skip]
            Err(_) => { store_unlock_failed(state, hit.cid); return Ok(Vec::new()); }
        };
        let durable = match durable_body_from_json(self.suite.b64u(), &json) {
            Ok(b) => b,
            #[rustfmt::skip]
            Err(()) => { store_unlock_failed(state, hit.cid); return Ok(Vec::new()); }
        };
        if durable.conversation_id != hit.cid {
            rekey_conversation(state, hit.cid, durable.conversation_id);
        }
        if let Some(existing) = state.body(&part.tx_id) {
            if existing.payload == durable.payload {
                #[allow(clippy::let_unit_value)]
                #[rustfmt::skip]
                let () = self.ack_completed_last(state, rng, persistent, &opened.packet, durable.conversation_id)?;
                prune_cached_mks(state);
                return Ok(Vec::new());
            }
            return Err(EngineError::Equivocation);
        }
        let cid = durable.conversation_id;
        if let Some(extra) = self.handshake_ingest_gate(state, cid, &durable.payload)? {
            return Ok(extra);
        }
        if let TxPayload::SyncDek { ct } = &durable.payload {
            self.hold_sync_dek(state, ct)?;
        }
        let seq = state.next_seq;
        let persist = self.persist_record(seq, &durable)?;
        state.persist_log.insert(seq, part.tx_id);
        state.next_seq = state.next_seq.saturating_add(1);
        state.insert_body(part.tx_id, durable)?;
        self.ack_completed_last(state, rng, persistent, &opened.packet, cid)?;
        prune_cached_mks(state);
        let conversation_id = cid;
        let mut out = vec![persist];
        out.extend(self.try_mint_invitee_intro(state, rng, conversation_id)?);
        out.extend(self.try_mint_inviter_intro(state, rng, conversation_id)?);
        Ok(out)
    }

    pub(super) fn handshake_ingest_gate(
        &self,
        state: &mut EngineState,
        cid: ConversationId,
        payload: &TxPayload,
    ) -> Result<Option<Vec<Vec<u8>>>, EngineError> {
        let conversation_id = cid;
        match payload {
            TxPayload::Notice(n) => {
                if let Some(existing) = notice_for(state, conversation_id)
                    && existing != n
                {
                    state.fail(cid, HandshakeFailure::NoticeConflict);
                    return Ok(Some(Vec::new()));
                }
                if let Some((uid, iid)) = state.owner(cid)
                    && let Ok(policy) = self.identity_policy(state, &uid, &iid)
                    && policy != n.policy
                {
                    state.fail(
                        cid,
                        HandshakeFailure::PolicyNotAccepted { policy: n.policy },
                    );
                } else if let Some(mut party) = state.party_mut(cid)
                    && let Some(invitee) = party.invitee_mut()
                {
                    let _ = invitee.receive_notice(n.policy);
                }
                Ok(None)
            }
            TxPayload::InviteeIntro(i) => self.gate_invitee_intro(state, cid, i),
            TxPayload::SyncInviteeIntro(s) => self.gate_invitee_intro(state, cid, &s.intro),
            TxPayload::InviterIntro(i) => self.gate_inviter_intro(state, cid, i),
            TxPayload::SyncInviterIntro(s) => self.gate_inviter_intro(state, cid, &s.intro),
            _ => Ok(None),
        }
    }

    fn gate_invitee_intro(
        &self,
        state: &mut EngineState,
        cid: ConversationId,
        i: &TxInviteeIntro,
    ) -> Result<Option<Vec<Vec<u8>>>, EngineError> {
        let conversation_id = cid;
        {
            if invitee_intro_for(state, conversation_id).is_some() {
                state.fail(cid, HandshakeFailure::DuplicateIntro);
                return Ok(Some(Vec::new()));
            }
            let Some(notice) = notice_for(state, conversation_id) else {
                state.fail(cid, HandshakeFailure::IntroVerifyFailed);
                return Ok(Some(Vec::new()));
            };
            if !intro_keys_ok(
                notice.policy,
                &i.encryption_pk,
                &i.signing_pk,
                Some(&i.intake_pk),
                &i.seed_ct,
            ) {
                state.fail(cid, HandshakeFailure::IntroVerifyFailed);
                return Ok(Some(Vec::new()));
            }
            let policy = notice.policy;
            if state.is_inviter(cid) {
                let sk = state.intake_secret(cid);
                if let Some(sk) = sk {
                    match self.unwrap_shared(policy, &sk, &i.seed_ct) {
                        Ok(_) => {}
                        Err(()) => {
                            state.fail(cid, HandshakeFailure::IntroVerifyFailed);
                            return Ok(Some(Vec::new()));
                        }
                    }
                }
            }
            Ok(None)
        }
    }

    fn gate_inviter_intro(
        &self,
        state: &mut EngineState,
        cid: ConversationId,
        i: &TxInviterIntro,
    ) -> Result<Option<Vec<Vec<u8>>>, EngineError> {
        let conversation_id = cid;
        {
            if inviter_intro_for(state, conversation_id).is_some() {
                state.fail(cid, HandshakeFailure::DuplicateIntro);
                return Ok(Some(Vec::new()));
            }
            #[rustfmt::skip]
                let Some(notice) = notice_for(state, conversation_id) else { state.fail(cid, HandshakeFailure::IntroVerifyFailed); return Ok(Some(Vec::new())); };
            if !intro_keys_ok(
                notice.policy,
                &i.encryption_pk,
                &i.signing_pk,
                None,
                &i.seed_ct,
            ) {
                state.fail(cid, HandshakeFailure::IntroVerifyFailed);
                return Ok(Some(Vec::new()));
            }
            let policy = notice.policy;
            if !state.is_inviter(cid) {
                let sk = state.intake_secret(cid);
                let Some(sk) = sk else {
                    state.fail(cid, HandshakeFailure::IntroVerifyFailed);
                    return Ok(Some(Vec::new()));
                };
                match self.unwrap_shared(policy, &sk, &i.seed_ct) {
                    Ok(s) => {
                        let accepted = state
                            .party_mut(cid)
                            .and_then(|mut party| {
                                party.invitee_mut().map(|inv| inv.confirm_peer(s))
                            })
                            .unwrap_or(false);
                        if !accepted {
                            state.fail(cid, HandshakeFailure::IntroVerifyFailed);
                            return Ok(Some(Vec::new()));
                        }
                    }
                    Err(()) => {
                        state.fail(cid, HandshakeFailure::IntroVerifyFailed);
                        return Ok(Some(Vec::new()));
                    }
                }
            }
            Ok(None)
        }
    }

    #[rustfmt::skip]
    fn ack_completed_last(&self, state: &mut EngineState, rng: &dyn Rng, persistent: bool, packet: &PacketPlain, cid: ConversationId) -> Result<(), EngineError> {
        if persistent && let PacketPlain::TxFragLast(last) = packet { store_durable_last_ack(state, cid, &last.actor_id, last.set_xor); self.note_set_xor(state, rng, cid, last.set_xor)?; }
        Ok(())
    }

    pub(super) fn complete_list_bin(
        &self,
        state: &mut EngineState,
        channel: &DurableChannel,
        hit: &HandshakeHit,
        _now: UnixSeconds,
    ) {
        let list_from = state.list_from(hit.cid).unwrap_or(hit.bin);
        let key = progress_key(channel, &hit.tag_key);
        let progress = state
            .bin_progress
            .entry(key)
            .or_insert_with(|| BinProgress {
                channel: channel.clone(),
                tag_key: hit.tag_key,
                watermark: None,
                completed: BTreeSet::new(),
            });
        if progress.watermark.is_some_and(|w| hit.bin <= w) {
            return;
        }
        progress.completed.insert(hit.bin);
        advance_progress(progress, list_from);
    }
}
