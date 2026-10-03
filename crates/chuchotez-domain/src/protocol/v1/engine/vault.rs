//! Vault wrap, persist records, and mutation.

use super::super::chain::{join, mk, next_fragment, packed_tx, seal_packet, set_xor_for, step};
use super::super::codec::{durable_body_to_json, vault_header_to_json};
use super::super::hmac::{HmacSha256Key, expand};
use super::super::payload::{
    ConversationSort, DurableBody, Hlc, PERSIST_MAX_UNCOMPRESSED, TxPayload, UnlockSecret, VAULT_M,
    VAULT_P, VAULT_T, VaultHeader, time_bin,
};
use super::super::{
    AEAD_NONCE_LEN, ActorId, AeadKey, AeadNonce, ConversationId, EngineError, Json, PersistSeq,
    Secret, Tag, UnixSeconds,
};
use super::query::*;
use super::{Engine, EngineState, PERSIST_VERSION};
use crate::protocol::Rng;
impl Engine {
    /// Wrap the held DEK, minting one from `rng` when absent.
    pub fn wrap_dek(
        &mut self,
        rng: &dyn Rng,
        secret: &UnlockSecret,
    ) -> Result<WrapDekOk, EngineError> {
        if self.dek.is_none() {
            self.dek = Some(AeadKey::from_bytes(rng.random32().into_bytes()));
        }
        let dek = self.dek.as_ref().expect("dek");
        let salt: [u8; 16] = rng.random32().into_bytes()[..16].try_into().expect("16");
        let mut header = VaultHeader {
            salt,
            m: VAULT_M,
            t: VAULT_T,
            p: VAULT_P,
            passphrase_nonce: None,
            passphrase_wrapped_dek: None,
            prf_nonce: None,
            prf_wrapped_dek: None,
        };
        match secret {
            UnlockSecret::Passphrase(pass) => {
                if pass.len() < 8 || pass.len() > 1024 {
                    return Err(EngineError::UnlockFailed);
                }
                let kek = self
                    .suite
                    .argon()
                    .hash(pass.as_bytes(), &salt, VAULT_M, VAULT_T, VAULT_P)
                    .map_err(|_| EngineError::UnlockFailed)?;
                let nonce_bytes: [u8; 12] =
                    rng.random32().into_bytes()[..12].try_into().expect("12");
                let nonce = AeadNonce::from_bytes(nonce_bytes);
                let ct =
                    self.suite
                        .aead()
                        .seal(&AeadKey::from_bytes(kek), &nonce, b"", dek.as_bytes());
                header.passphrase_nonce = Some(nonce_bytes);
                header.passphrase_wrapped_dek = Some(ct);
            }
            UnlockSecret::Prf(prf) => {
                let nonce_bytes: [u8; 12] =
                    rng.random32().into_bytes()[..12].try_into().expect("12");
                let nonce = AeadNonce::from_bytes(nonce_bytes);
                let ct =
                    self.suite
                        .aead()
                        .seal(&AeadKey::from_bytes(*prf), &nonce, b"", dek.as_bytes());
                header.prf_nonce = Some(nonce_bytes);
                header.prf_wrapped_dek = Some(ct);
            }
        }
        let json = vault_header_to_json(self.suite.b64u(), &header);
        let packed = self
            .suite
            .compress()
            .compress(&self.suite.canonical_json().encode(&json));
        Ok(WrapDekOk { header: packed })
    }

    /// Derive the KEK and hold the DEK.
    pub fn unlock(&mut self, header: &[u8], secret: &UnlockSecret) -> Result<(), EngineError> {
        let raw = self
            .suite
            .compress()
            .decompress(header, super::super::payload::VAULT_MAX_UNCOMPRESSED)
            .map_err(|_| EngineError::UnlockFailed)?;
        let json = self
            .suite
            .canonical_json()
            .decode(&raw)
            .map_err(|_| EngineError::UnlockFailed)?;
        let Json::Object(members) = json else {
            return Err(EngineError::UnlockFailed);
        };
        let get = |k: &str| members.iter().find(|(n, _)| n == k).map(|(_, v)| v);
        let salt_s = match get("salt") {
            Some(Json::String(s)) => s,
            _ => return Err(EngineError::UnlockFailed),
        };
        let salt_v = self
            .suite
            .b64u()
            .decode(salt_s)
            .map_err(|_| EngineError::UnlockFailed)?;
        let salt: [u8; 16] = salt_v.try_into().map_err(|_| EngineError::UnlockFailed)?;
        match secret {
            UnlockSecret::Passphrase(pass) => {
                let kek = self
                    .suite
                    .argon()
                    .hash(pass.as_bytes(), &salt, VAULT_M, VAULT_T, VAULT_P)
                    .map_err(|_| EngineError::UnlockFailed)?;
                let nonce_s = match get("passphrase_nonce") {
                    Some(Json::String(s)) => s,
                    _ => return Err(EngineError::UnlockFailed),
                };
                let nonce_v = self
                    .suite
                    .b64u()
                    .decode(nonce_s)
                    .map_err(|_| EngineError::UnlockFailed)?;
                let nonce_arr: [u8; 12] =
                    nonce_v.try_into().map_err(|_| EngineError::UnlockFailed)?;
                let ct_s = match get("passphrase_wrapped_dek") {
                    Some(Json::String(s)) => s,
                    _ => return Err(EngineError::UnlockFailed),
                };
                let ct = self
                    .suite
                    .b64u()
                    .decode(ct_s)
                    .map_err(|_| EngineError::UnlockFailed)?;
                let dek = self
                    .suite
                    .aead()
                    .open(
                        &AeadKey::from_bytes(kek),
                        &AeadNonce::from_bytes(nonce_arr),
                        b"",
                        &ct,
                    )
                    .map_err(|_| EngineError::UnlockFailed)?;
                let dek_arr: [u8; 32] = dek.try_into().map_err(|_| EngineError::UnlockFailed)?;
                self.dek = Some(AeadKey::from_bytes(dek_arr));
            }
            UnlockSecret::Prf(prf) => {
                let nonce_s = match get("prf_nonce") {
                    Some(Json::String(s)) => s,
                    _ => return Err(EngineError::UnlockFailed),
                };
                let nonce_v = self
                    .suite
                    .b64u()
                    .decode(nonce_s)
                    .map_err(|_| EngineError::UnlockFailed)?;
                let nonce_arr: [u8; 12] =
                    nonce_v.try_into().map_err(|_| EngineError::UnlockFailed)?;
                let ct_s = match get("prf_wrapped_dek") {
                    Some(Json::String(s)) => s,
                    _ => return Err(EngineError::UnlockFailed),
                };
                let ct = self
                    .suite
                    .b64u()
                    .decode(ct_s)
                    .map_err(|_| EngineError::UnlockFailed)?;
                let dek = self
                    .suite
                    .aead()
                    .open(
                        &AeadKey::from_bytes(*prf),
                        &AeadNonce::from_bytes(nonce_arr),
                        b"",
                        &ct,
                    )
                    .map_err(|_| EngineError::UnlockFailed)?;
                let dek_arr: [u8; 32] = dek.try_into().map_err(|_| EngineError::UnlockFailed)?;
                self.dek = Some(AeadKey::from_bytes(dek_arr));
            }
        }
        Ok(())
    }

    /// Drop the held DEK.
    pub fn lock(&mut self) {
        self.dek = None;
    }

    pub(super) fn require_dek(&self) -> Result<&AeadKey, EngineError> {
        self.dek.as_ref().ok_or(EngineError::Locked)
    }

    pub(super) fn require_tick(state: &EngineState) -> Result<UnixSeconds, EngineError> {
        state.ticked.ok_or(EngineError::NotTicked)
    }

    pub(super) fn engine_secret(&self) -> Result<Secret, EngineError> {
        let dek = self.require_dek()?;
        Ok(Secret::from_bytes(
            expand(
                self.suite.hmac(),
                &HmacSha256Key::from_bytes(*dek.as_bytes()),
                b"chuchotez/1/engine",
            )
            .into_bytes(),
        ))
    }

    pub(super) fn engine_conversation_id(&self) -> Result<ConversationId, EngineError> {
        let secret = self.engine_secret()?;
        Ok(ConversationId::from_bytes(
            expand(
                self.suite.hmac(),
                &HmacSha256Key::from_bytes(*secret.as_bytes()),
                b"chuchotez/1/engine-id",
            )
            .into_bytes(),
        ))
    }

    pub(super) fn tx_id(&self, conv_secret: &Secret, payload: &TxPayload) -> Tag {
        let key = expand(
            self.suite.hmac(),
            &HmacSha256Key::from_bytes(*conv_secret.as_bytes()),
            b"chuchotez/1/tx-id",
        );
        let json = super::super::codec::payload_to_json(self.suite.b64u(), payload);
        let canonical = self.suite.canonical_json().encode(&json);
        Tag::from_bytes(
            self.suite
                .hmac()
                .mac(&HmacSha256Key::from_bytes(key.into_bytes()), &canonical)
                .into_bytes(),
        )
    }

    pub(super) fn persist_record(
        &self,
        seq: PersistSeq,
        body: &DurableBody,
    ) -> Result<Vec<u8>, EngineError> {
        let dek = self.require_dek()?;
        if seq.as_u64() == u64::MAX {
            return Err(EngineError::MalformedPersist);
        }
        let json = durable_body_to_json(self.suite.b64u(), body);
        let canonical = self.suite.canonical_json().encode(&json);
        (canonical.len() <= PERSIST_MAX_UNCOMPRESSED)
            .then_some(())
            .ok_or(EngineError::BodyTooLarge)?;
        let packed = self.suite.compress().compress(&canonical);
        let _ = self.suite.hash().hash(&packed);
        let mut nonce_bytes = [0u8; AEAD_NONCE_LEN];
        nonce_bytes[..4].copy_from_slice(&PERSIST_VERSION.to_be_bytes());
        nonce_bytes[4..].copy_from_slice(&seq.as_u64().to_be_bytes());
        let nonce = AeadNonce::from_bytes(nonce_bytes);
        let ct = self.suite.aead().seal(dek, &nonce, b"", &packed);
        let mut out = Vec::with_capacity(AEAD_NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub(super) fn post_handshake_packets(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        conversation_id: ConversationId,
        conv_secret: &Secret,
        tx_id: Tag,
    ) -> Result<(), EngineError> {
        let now = Self::require_tick(state)?;
        let cid = conversation_id;
        let (sort, persistents) = if let Some(t) = state.ticket(cid) {
            let sort = if state.is_sync(cid) {
                ConversationSort::HandshakeSync
            } else {
                ConversationSort::HandshakeDm
            };
            (sort, t.persistents.clone())
        } else {
            return Err(EngineError::UnknownIds);
        };
        let tag = Tag::from_bytes(
            expand(
                self.suite.hmac(),
                &HmacSha256Key::from_bytes(*conv_secret.as_bytes()),
                &[
                    b"chuchotez/1/handshake-invite".as_slice(),
                    &time_bin(now).as_u64().to_be_bytes(),
                ]
                .concat(),
            )
            .into_bytes(),
        );
        let actor = ActorId::handshake();
        self.absorb_peer_wraps(state, cid);
        if let Some(owed) = self.mint_if_owed(state, rng, cid, conv_secret)? {
            self.write_chain_packets(
                state,
                rng,
                cid,
                sort,
                &persistents,
                tag,
                owed,
                actor.clone(),
                false,
            )?;
        }
        self.write_chain_packets(state, rng, cid, sort, &persistents, tag, tx_id, actor, true)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn write_chain_packets(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        conversation_id: ConversationId,
        sort: super::super::payload::ConversationSort,
        persistents: &[super::super::DurableChannel],
        tag: Tag,
        tx_id: Tag,
        actor: ActorId,
        count_since: bool,
    ) -> Result<(), EngineError> {
        let secret = state
            .ticket(conversation_id)
            .map(|t| t.secret)
            .ok_or(EngineError::UnknownIds)?;
        let now = state.ticked;
        if let Some(chains) = state.chains_mut(conversation_id)
            && chains.heal.on_ephemeral
        {
            let due = now.is_some_and(|now| {
                chains
                    .heal
                    .sent_at
                    .is_some_and(|sent| now >= sent.saturating_add(3))
            });
            chains.heal.ready.clear();
            chains.heal.sealed_from = None;
            chains.heal.sealed_to = None;
            if due {
                chains.heal.needs_reseal = true;
            }
        }
        let body = state
            .txs
            .get(&tx_id)
            .ok_or(EngineError::UnknownIds)?
            .clone();
        let mut packed = packed_tx(&self.suite, &body);
        let set_xor = set_xor_for(&state.txs, conversation_id);
        let mut chain = match state
            .chains(conversation_id)
            .and_then(|c| c.send.get(&actor))
        {
            Some(c) => c.clone(),
            None => join(self.suite.hmac(), secret.as_bytes(), sort, &[])?,
        };
        let mut frag_i = 0u64;
        loop {
            if let Some(mixed) = self.mixed_chain(state, conversation_id, sort, &chain, true) {
                chain = mixed;
            }
            let (packet, n) = next_fragment(
                &self.suite,
                &packed,
                tx_id,
                set_xor,
                chain.packet_seq.as_u64(),
                frag_i,
                actor.as_bytes(),
            )?;
            let mk_bytes = mk(self.suite.hmac(), &chain);
            let sealed = seal_packet(&self.suite, rng, &mk_bytes, &packet)?;
            for ch in persistents {
                state.writes.push(DurableWrite {
                    channel: ch.clone(),
                    tag,
                    body: sealed.clone(),
                });
            }
            chain = step(self.suite.hmac(), &chain);
            if count_since {
                self.note_sent_packet(state, conversation_id);
            }
            let finished = matches!(packet, super::super::payload::PacketPlain::TxFragLast(_));
            packed = packed.get(n..).unwrap_or_default().to_vec();
            frag_i = frag_i.saturating_add(1);
            if finished {
                break;
            }
        }
        if let Some(chains) = state.chains_mut(conversation_id) {
            chains.send.insert(actor, chain);
        }
        Ok(())
    }

    pub(super) fn merge_tx(
        &self,
        state: &mut EngineState,
        conv_secret: &Secret,
        conversation_id: ConversationId,
        payload: TxPayload,
    ) -> Result<(Tag, DurableBody, Vec<u8>), EngineError> {
        let now = Self::require_tick(state)?;
        let tx_id = self.tx_id(conv_secret, &payload);
        let body = DurableBody {
            conversation_id,
            hlc: Hlc {
                wall_ms: now.as_u64().saturating_mul(1000),
                counter: 0,
            },
            payload,
        };
        if let Some(existing) = state.txs.get(&tx_id) {
            if existing.payload == body.payload {
                let persist = self.persist_record(state.next_seq, existing)?;
                return Ok((tx_id, existing.clone(), persist));
            }
            return Err(EngineError::Equivocation);
        }
        let persist = self.persist_record(state.next_seq, &body)?;
        let seq = state.next_seq;
        state.persist_log.insert(seq, tx_id);
        state.next_seq = state.next_seq.saturating_add(1);
        state.txs.insert(tx_id, body.clone());
        Ok((tx_id, body, persist))
    }

    pub(super) fn mutate(
        &self,
        state: EngineState,
        rng: Option<&dyn crate::protocol::Rng>,
        conv_secret: &Secret,
        payloads: Vec<TxPayload>,
    ) -> Result<MutateOk, EngineError> {
        let conversation_id = self.engine_conversation_id()?;
        let mut ok = self.mutate_on(state, conv_secret, conversation_id, payloads.clone())?;
        if let Some(rng) = rng {
            self.fan_engine_to_sync(&mut ok.state, rng, &payloads)?;
        }
        Ok(ok)
    }

    pub(super) fn mutate_on(
        &self,
        mut state: EngineState,
        conv_secret: &Secret,
        conversation_id: ConversationId,
        payloads: Vec<TxPayload>,
    ) -> Result<MutateOk, EngineError> {
        let mut persist = Vec::new();
        for payload in payloads {
            let (_, _, rec) = self.merge_tx(&mut state, conv_secret, conversation_id, payload)?;
            persist.push(rec);
        }
        Ok(MutateOk {
            state,
            persist,
            pings: Vec::new(),
        })
    }
}
