//! Vault wrap, persist records, and mutation.

use super::super::chain::{
    chain_key, fragment_body, join, mk, packed_tx, seal_packet, set_xor_for, step,
};
use super::super::codec::{durable_body_to_json, vault_header_to_json};
use super::super::hmac::{HmacSha256Key, expand};
use super::super::payload::{
    ConversationSort, DurableBody, Hlc, PERSIST_MAX_UNCOMPRESSED, TxPayload, UnlockSecret, VAULT_M,
    VAULT_P, VAULT_T, VaultHeader, time_bin,
};
use super::super::{
    AEAD_NONCE_LEN, AeadKey, AeadNonce, ConversationId, EngineError, Json, Secret, Tag,
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

    pub(super) fn require_tick(state: &EngineState) -> Result<u64, EngineError> {
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
        seq: u64,
        body: &DurableBody,
    ) -> Result<Vec<u8>, EngineError> {
        let dek = self.require_dek()?;
        if seq == u64::MAX {
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
        nonce_bytes[4..].copy_from_slice(&seq.to_be_bytes());
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
                    &time_bin(now).to_be_bytes(),
                ]
                .concat(),
            )
            .into_bytes(),
        );
        let body = state
            .txs
            .get(&tx_id)
            .ok_or(EngineError::UnknownIds)?
            .clone();
        let packed = packed_tx(&self.suite, &body);
        let set_xor = set_xor_for(&state.txs, conversation_id);
        let key = chain_key(&conversation_id, &[]);
        let mut chain = match state.send_chains.get(&key) {
            Some(c) => c.clone(),
            None => join(self.suite.hmac(), conv_secret.as_bytes(), sort, &[])?,
        };
        let packets = fragment_body(&self.suite, &packed, tx_id, set_xor, chain.packet_seq, &[])?;
        for packet in packets {
            let mk_bytes = mk(self.suite.hmac(), &chain);
            let sealed = seal_packet(&self.suite, rng, &mk_bytes, &packet)?;
            for ch in &persistents {
                state.writes.push(DurableWrite {
                    channel: ch.clone(),
                    tag,
                    body: sealed.clone(),
                });
            }
            chain = step(self.suite.hmac(), &chain);
        }
        state.send_chains.insert(key, chain);
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
                wall_ms: now.saturating_mul(1000),
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
        state.next_seq = state.next_seq.saturating_add(1);
        state.txs.insert(tx_id, body.clone());
        Ok((tx_id, body, persist))
    }

    pub(super) fn mutate(
        &self,
        state: EngineState,
        conv_secret: &Secret,
        payloads: Vec<TxPayload>,
    ) -> Result<MutateOk, EngineError> {
        let conversation_id = self.engine_conversation_id()?;
        self.mutate_on(state, conv_secret, conversation_id, payloads)
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
