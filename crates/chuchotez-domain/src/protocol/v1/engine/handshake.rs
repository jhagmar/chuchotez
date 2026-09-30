//! Handshake query, intro mint, ingest, fingerprint, and spawn.

use super::super::chain::{chain_key, join, open_skip_ahead};
use super::super::codec::{durable_body_from_json, payload_to_json};
use super::super::hmac::{HmacSha256Key, expand};
use super::super::kem::KEM_SHARED_LEN;
use super::super::payload::{
    PACKET_MAX_UNCOMPRESSED, Ticket, TxInviteeIntro, TxInviterIntro, TxPayload, time_bin,
};
use super::super::{
    Address, ConversationId, DurableChannel, EngineError, IdentityId, KemSeed, Kind, OnWirePrefs,
    Policy, Secret, SignSeed, Tag, TagKey, UserId,
};
use super::helpers::*;
use super::query::*;
use super::state::*;
use super::{
    Engine, EngineState, HANDSHAKE_DM_ESTABLISHED_INFO, HANDSHAKE_SYNC_ESTABLISHED_INFO,
    SPAWN_CONVERSATION_ID_INFO, SPAWN_SECRET_INFO,
};
use crate::protocol::Rng;
use std::collections::{BTreeMap, BTreeSet};
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
        if state.established(conversation_id).is_some() {
            if state.is_sync(conversation_id) {
                return Some(Conversation::Synchronization(
                    SynchronizationQuery::SyncEstablished,
                ));
            }
            return Some(Conversation::DirectMessage(DirectMessageQuery::Established));
        }
        if let Some(hs) = state.handshake(conversation_id) {
            let ticket = &hs.ticket;
            if let Some(reason) = hs.failed_reason() {
                return Some(if state.is_sync(conversation_id) {
                    Conversation::HandshakeSync(Handshake::Failed(reason))
                } else {
                    Conversation::HandshakeDm(Handshake::Failed(reason))
                });
            }
            let has_reject = state.txs.values().any(|t| {
                matches!(t.payload, TxPayload::Reject) && t.conversation_id == conversation_id
            });
            if has_reject {
                let failed = Handshake::Failed(FailedReason::ConfirmationRejected);
                return Some(if state.is_sync(conversation_id) {
                    Conversation::HandshakeSync(failed)
                } else {
                    Conversation::HandshakeDm(failed)
                });
            }
            let row = self.handshake_at(state, conversation_id, ticket);
            return Some(if state.is_sync(conversation_id) {
                Conversation::HandshakeSync(row)
            } else {
                Conversation::HandshakeDm(row)
            });
        }
        None
    }

    pub(super) fn handshake_at(
        &self,
        state: &EngineState,
        conversation_id: ConversationId,
        ticket: &Ticket,
    ) -> Handshake {
        let pending = state
            .writes
            .iter()
            .any(|w| ticket.persistents.iter().any(|ch| ch == &w.channel));
        let notice = notice_for(state, conversation_id);
        let invitee_intro = invitee_intro_for(state, conversation_id).is_some();
        let inviter_intro = inviter_intro_for(state, conversation_id).is_some();
        let is_inviter = state.is_inviter(conversation_id);
        let digest = self
            .try_fingerprint(state, conversation_id)
            .map(|(d, _)| d)
            .unwrap_or_default();
        if is_inviter {
            let expires = ticket.expires;
            if inviter_intro {
                if pending {
                    return Handshake::Inviter(HandshakeInviter::IntroductionMinted { expires });
                }
                return Handshake::Inviter(HandshakeInviter::Confirming {
                    expires,
                    confirmation_digest: digest,
                });
            }
            if pending {
                return Handshake::Inviter(HandshakeInviter::InviteCreated { expires });
            }
            return Handshake::Inviter(HandshakeInviter::NoticePinned { expires });
        }
        match (notice, invitee_intro, inviter_intro) {
            (Some(n), _, true) => Handshake::Invitee(HandshakeInvitee::Confirming {
                policy: n.policy,
                expires: n.expires,
                confirmation_digest: digest,
            }),
            (Some(n), true, false) if pending => {
                Handshake::Invitee(HandshakeInvitee::IntroductionMinted {
                    policy: n.policy,
                    expires: n.expires,
                })
            }
            (Some(n), true, false) => Handshake::Invitee(HandshakeInvitee::IntroductionSent {
                policy: n.policy,
                expires: n.expires,
            }),
            (Some(n), false, false) => Handshake::Invitee(HandshakeInvitee::InviteReceived {
                policy: n.policy,
                expires: n.expires,
            }),
            _ => Handshake::Invitee(HandshakeInvitee::TicketReceived),
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
            .or_else(|| state.established(*conversation_id).map(|es| es.secret))
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
        let hs = state.handshake(conversation_id)?;
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
        let (lo, hi) = if inviter.signing_pk <= invitee.signing_pk {
            (
                TxPayload::InviterIntro(inviter.clone()),
                TxPayload::InviteeIntro(invitee.clone()),
            )
        } else {
            (
                TxPayload::InviteeIntro(invitee.clone()),
                TxPayload::InviterIntro(inviter.clone()),
            )
        };
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
        state.spawn_established(cid, child, spawn_secret);
        Ok(())
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
        ids: &ConversationRef,
        payload: TxPayload,
    ) -> Result<MutateOk, EngineError> {
        self.require_ids(&state, ids)?;
        let secret = self.conv_secret(&state, &ids.conversation_id)?;
        self.mutate_on(state, &secret, ids.conversation_id, vec![payload])
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
                let decided = state.txs.values().any(|t| {
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
        state.txs.values().find_map(|tx| match &tx.payload {
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
        if state.device.enc.is_none() {
            state.device.enc = Some(
                self.suite
                    .kem()
                    .generate(policy, &KemSeed::from_pair(rng.random32(), rng.random32()))
                    .map_err(|_| EngineError::MalformedPayload)?,
            );
        }
        if state.device.sign.is_none() {
            state.device.sign = Some(
                self.suite
                    .sign()
                    .generate(policy, &SignSeed::from_pair(rng.random32(), rng.random32()))
                    .map_err(|_| EngineError::MalformedPayload)?,
            );
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
            #[rustfmt::skip]
            let enc = state.device.enc.as_ref().ok_or(EngineError::MalformedPayload)?;
            #[rustfmt::skip]
            let sign = state.device.sign.as_ref().ok_or(EngineError::MalformedPayload)?;
            return Ok(Some((
                name,
                None,
                enc.public_bytes().to_vec(),
                sign.public_bytes().to_vec(),
            )));
        }
        #[rustfmt::skip]
        let Some((uid, iid)) = state.owner(cid) else { return Ok(None); };
        #[rustfmt::skip]
        let Some(name) = state.display_name(iid).cloned() else { return Ok(None); };
        #[rustfmt::skip]
        let Some((id_policy, enc, sign)) = self.identity_keys(state, &uid, &iid) else { return Ok(None); };
        if id_policy != policy {
            state.fail(cid, FailedReason::PolicyNotAccepted { policy });
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
        if state.failed(cid).is_some() || state.is_inviter(cid) {
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
        state.set_shared_inviter(cid, take_shared32(shared));
        let payload = TxPayload::InviteeIntro(TxInviteeIntro {
            name,
            profile_pic: pic,
            send_tag_key: TagKey::from(rng.random32()),
            eph_send_tag_key: TagKey::from(rng.random32()),
            encryption_pk: enc,
            signing_pk: sign,
            intake_pk: intake.public_bytes().to_vec(),
            seed_ct,
            prefs: self.on_wire_prefs(),
        });
        state.set_intake(cid, intake);
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
        if state.failed(cid).is_some() || !state.is_inviter(cid) {
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
        let (shared, seed_ct) =
            match self
                .suite
                .kem()
                .wrap(notice.policy, &invitee.intake_pk, &seed)
            {
                Ok(v) => v,
                #[rustfmt::skip]
            Err(_) => { state.fail(cid, FailedReason::IntroVerifyFailed); return Ok(Vec::new()); }
            };
        state.set_shared_invitee(cid, take_shared32(shared));
        let persistents = state
            .ticket(cid)
            .map(|t| t.persistents.clone())
            .unwrap_or_default();
        state
            .writes
            .retain(|w| !persistents.iter().any(|ch| ch == &w.channel));
        let payload = TxPayload::InviterIntro(TxInviterIntro {
            name,
            profile_pic: pic,
            send_tag_key: TagKey::from(rng.random32()),
            eph_send_tag_key: TagKey::from(rng.random32()),
            encryption_pk: enc,
            signing_pk: sign,
            seed_ct,
            prefs: self.on_wire_prefs(),
        });
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
        &self,
        state: EngineState,
        rng: &dyn Rng,
        channel: DurableChannel,
        tag: Tag,
        bodies: &[Vec<u8>],
    ) -> Result<MutateOk, EngineError> {
        let now = Self::require_tick(&state)?;
        let _ = self.require_dek()?;
        let hits = self.handshake_hits(&state, &channel, &tag, now);
        if hits.is_empty() {
            return Err(EngineError::UnknownTag);
        }
        let mut state = state;
        let mut persist = Vec::new();
        for body in bodies {
            persist.extend(self.ingest_known_body(&mut state, rng, &hits, body)?);
        }
        self.complete_list_bin(&mut state, &channel, &hits[0], now);
        Ok(MutateOk {
            state,
            persist,
            pings: Vec::new(),
        })
    }

    /// Ingest one 512-byte mapper body. Opens with skip-ahead `mk` and
    /// reassembles fragments.
    pub fn ingest_packet(
        &self,
        mut state: EngineState,
        rng: &dyn Rng,
        channel: DurableChannel,
        tag: Tag,
        body: &[u8],
    ) -> Result<MutateOk, EngineError> {
        let now = Self::require_tick(&state)?;
        let _ = self.require_dek()?;
        let hits = self.handshake_hits(&state, &channel, &tag, now);
        if hits.is_empty() {
            return Err(EngineError::UnknownTag);
        }
        let persist = self.ingest_known_body(&mut state, rng, &hits, body)?;
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
        channel: &DurableChannel,
        tag: &Tag,
        now: u64,
    ) -> Vec<HandshakeHit> {
        let w = time_bin(now);
        let start = window_start(w);
        let end = w.saturating_add(1);
        let mut hits = Vec::new();
        for (cid, ticket, sort) in handshake_rows(state) {
            if !ticket.persistents.iter().any(|ch| ch == channel) {
                continue;
            }
            let secret = ticket.secret;
            let tag_key = handshake_tag_key(self.suite.hmac(), secret.as_bytes());
            for bin in start..=end {
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
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        hits: &[HandshakeHit],
        body: &[u8],
    ) -> Result<Vec<Vec<u8>>, EngineError> {
        let now = Self::require_tick(state)?;
        for hit in hits {
            match self.open_and_merge(state, rng, hit, now, body) {
                Ok(persist) => return Ok(persist),
                Err(EngineError::UnknownTag) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(Vec::new())
    }

    pub(super) fn open_and_merge(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        hit: &HandshakeHit,
        now: u64,
        body: &[u8],
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
        let key = chain_key(&hit.cid, &[]);
        let start = join(self.suite.hmac(), hit.secret.as_bytes(), hit.sort, &[])?;
        let mut cached = state.skipped_mks.get(&key).cloned().unwrap_or_default();
        cached.retain(|e| e.expires_at > now);
        let opened = open_skip_ahead(&self.suite, &start, &cached, now, body)?;
        cached.extend(opened.skipped);
        cached.retain(|e| e.expires_at > now);
        if cached.is_empty() {
            state.skipped_mks.remove(&key);
        } else {
            state.skipped_mks.insert(key.clone(), cached);
        }
        if !opened.from_cache {
            state.recv_chains.insert(key, opened.chain);
        } else {
            state.recv_chains.entry(key).or_insert(start);
        }
        let Some(part) = frag_parts(&opened.packet) else {
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
        for i in 0..=last {
            if !set.parts.contains_key(&i) {
                return Ok(Vec::new());
            }
        }
        let mut packed = Vec::new();
        for i in 0..=last {
            packed.extend_from_slice(&set.parts[&i]);
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
        if let Some(existing) = state.txs.get(&part.tx_id) {
            if existing.payload == durable.payload {
                return Ok(Vec::new());
            }
            return Err(EngineError::Equivocation);
        }
        let cid = durable.conversation_id;
        if let Some(extra) = self.handshake_ingest_gate(state, cid, &durable.payload)? {
            return Ok(extra);
        }
        let persist = self.persist_record(state.next_seq, &durable)?;
        state.next_seq = state.next_seq.saturating_add(1);
        state.txs.insert(part.tx_id, durable);
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
                    state.fail(cid, FailedReason::NoticeConflict);
                    return Ok(Some(Vec::new()));
                }
                if let Some((uid, iid)) = state.owner(cid)
                    && let Ok(policy) = self.identity_policy(state, &uid, &iid)
                    && policy != n.policy
                {
                    state.fail(cid, FailedReason::PolicyNotAccepted { policy: n.policy });
                }
                Ok(None)
            }
            TxPayload::InviteeIntro(i) => {
                if invitee_intro_for(state, conversation_id).is_some() {
                    state.fail(cid, FailedReason::DuplicateIntro);
                    return Ok(Some(Vec::new()));
                }
                let Some(notice) = notice_for(state, conversation_id) else {
                    state.fail(cid, FailedReason::IntroVerifyFailed);
                    return Ok(Some(Vec::new()));
                };
                if !intro_keys_ok(
                    notice.policy,
                    &i.encryption_pk,
                    &i.signing_pk,
                    Some(&i.intake_pk),
                    &i.seed_ct,
                ) {
                    state.fail(cid, FailedReason::IntroVerifyFailed);
                    return Ok(Some(Vec::new()));
                }
                let policy = notice.policy;
                if state.is_inviter(cid) {
                    let sk = state
                        .handshake(cid)
                        .and_then(|h| h.intake())
                        .map(|k| k.secret_bytes().to_vec());
                    if let Some(sk) = sk {
                        match self.unwrap_shared(policy, &sk, &i.seed_ct) {
                            Ok(s) => {
                                state.set_shared_inviter(cid, s);
                            }
                            Err(()) => {
                                state.fail(cid, FailedReason::IntroVerifyFailed);
                                return Ok(Some(Vec::new()));
                            }
                        }
                    }
                }
                Ok(None)
            }
            TxPayload::InviterIntro(i) => {
                if inviter_intro_for(state, conversation_id).is_some() {
                    state.fail(cid, FailedReason::DuplicateIntro);
                    return Ok(Some(Vec::new()));
                }
                #[rustfmt::skip]
                let Some(notice) = notice_for(state, conversation_id) else { state.fail(cid, FailedReason::IntroVerifyFailed); return Ok(Some(Vec::new())); };
                if !intro_keys_ok(
                    notice.policy,
                    &i.encryption_pk,
                    &i.signing_pk,
                    None,
                    &i.seed_ct,
                ) {
                    state.fail(cid, FailedReason::IntroVerifyFailed);
                    return Ok(Some(Vec::new()));
                }
                let policy = notice.policy;
                if !state.is_inviter(cid) {
                    let sk = state
                        .handshake(cid)
                        .and_then(|h| h.intake())
                        .map(|k| k.secret_bytes().to_vec());
                    if let Some(sk) = sk {
                        match self.unwrap_shared(policy, &sk, &i.seed_ct) {
                            Ok(s) => {
                                state.set_shared_invitee(cid, s);
                            }
                            Err(()) => {
                                state.fail(cid, FailedReason::IntroVerifyFailed);
                                return Ok(Some(Vec::new()));
                            }
                        }
                    }
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    pub(super) fn complete_list_bin(
        &self,
        state: &mut EngineState,
        channel: &DurableChannel,
        hit: &HandshakeHit,
        now: u64,
    ) {
        let start = window_start(time_bin(now));
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
        prune_progress(progress, start);
        if progress.watermark.is_some_and(|w| hit.bin <= w) {
            return;
        }
        progress.completed.insert(hit.bin);
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
}
