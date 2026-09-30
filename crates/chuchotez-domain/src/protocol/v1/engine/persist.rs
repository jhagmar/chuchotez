//! Fold and apply persist records.

use super::super::codec::{durable_body_from_json, durable_body_to_json, durable_json};
use super::super::payload::{PACKET_NONCE_LEN, PERSIST_MAX_UNCOMPRESSED, TxPayload};
use super::super::{
    AEAD_NONCE_LEN, AeadNonce, ConversationId, EngineError, FragIndex, Json, PersistSeq, Secret,
    Tag, TagKey, TimeBin, UnixSeconds,
};
use super::helpers::*;
use super::query::*;
use super::state::*;
use super::{Engine, EngineState, FOLD_VERSION};
use std::collections::{BTreeMap, BTreeSet};
impl Engine {
    /// Fold a snapshot of watermark txs. `WrongPhase` when a persist seq's tx
    /// is outside the watermark.
    pub fn fold(&self, state: EngineState) -> Result<FoldOk, EngineError> {
        let dek = self.require_dek()?;
        let seq = state.next_seq;
        if seq.as_u64() == u64::MAX {
            return Err(EngineError::MalformedPersist);
        }
        if persist_outside_watermark(&state) {
            return Err(EngineError::WrongPhase);
        }
        let now = state.ticked.unwrap_or_default();
        let mut txs = Vec::new();
        let mut kept: BTreeSet<Tag> = BTreeSet::new();
        for (id, body) in &state.txs {
            if !tx_watermarked(&state, *id) {
                continue;
            }
            if payload_expire_at(&body.payload).is_some_and(|expires| expires <= now) {
                continue;
            }
            kept.insert(*id);
            txs.push(Json::Object(vec![
                (
                    "tx_id".into(),
                    super::super::codec::bstr(self.suite.b64u(), id.as_bytes()),
                ),
                ("body".into(), durable_body_to_json(self.suite.b64u(), body)),
            ]));
        }
        let mut frags = Vec::new();
        for (tx_id, set) in &state.frags {
            let mut parts = Vec::new();
            for (i, frag) in &set.parts {
                parts.push(Json::Object(vec![
                    ("i".into(), Json::Number(i.as_u64())),
                    (
                        "frag".into(),
                        super::super::codec::bstr(self.suite.b64u(), frag),
                    ),
                ]));
            }
            frags.push(Json::Object(vec![
                (
                    "tx_id".into(),
                    super::super::codec::bstr(self.suite.b64u(), tx_id.as_bytes()),
                ),
                (
                    "conversation_id".into(),
                    super::super::codec::bstr(self.suite.b64u(), set.conversation_id.as_bytes()),
                ),
                (
                    "last_i".into(),
                    set.last_i
                        .map(|i| Json::Number(i.as_u64()))
                        .unwrap_or(Json::Null),
                ),
                ("parts".into(), Json::Array(parts)),
            ]));
        }
        let mut bins = Vec::new();
        for progress in state.bin_progress.values() {
            bins.push(Json::Object(vec![
                ("channel".into(), durable_json(&progress.channel)),
                (
                    "tag_key".into(),
                    super::super::codec::bstr(self.suite.b64u(), progress.tag_key.as_bytes()),
                ),
                (
                    "watermark".into(),
                    progress
                        .watermark
                        .map(|w| Json::Number(w.as_u64()))
                        .unwrap_or(Json::Null),
                ),
                (
                    "completed".into(),
                    Json::Array(
                        progress
                            .completed
                            .iter()
                            .copied()
                            .map(|b| Json::Number(b.as_u64()))
                            .collect(),
                    ),
                ),
            ]));
        }

        let mut persist_log = Vec::new();
        for (pseq, tx_id) in &state.persist_log {
            if !kept.contains(tx_id) {
                continue;
            }
            persist_log.push(Json::Object(vec![
                ("seq".into(), Json::Number(pseq.as_u64())),
                (
                    "tx_id".into(),
                    super::super::codec::bstr(self.suite.b64u(), tx_id.as_bytes()),
                ),
            ]));
        }
        let users = super::fold_tree::users_json(self.suite.b64u(), &state);
        let device = super::fold_tree::device_json(self.suite.b64u(), &state.device);
        let json = Json::Object(vec![
            ("type".into(), Json::String("v1-engine-snapshot".into())),
            ("next_seq".into(), Json::Number(seq.as_u64())),
            (
                "ticked".into(),
                state
                    .ticked
                    .map(|t| Json::Number(t.as_u64()))
                    .unwrap_or(Json::Null),
            ),
            ("txs".into(), Json::Array(txs)),
            ("users".into(), users),
            ("device".into(), device),
            ("frags".into(), Json::Array(frags)),
            ("bins".into(), Json::Array(bins)),
            ("persist_log".into(), Json::Array(persist_log)),
        ]);
        let canonical = self.suite.canonical_json().encode(&json);
        (canonical.len() <= PERSIST_MAX_UNCOMPRESSED)
            .then_some(())
            .ok_or(EngineError::BodyTooLarge)?;
        let packed = self.suite.compress().compress(&canonical);
        let mut nonce_bytes = [0u8; AEAD_NONCE_LEN];
        nonce_bytes[..4].copy_from_slice(&FOLD_VERSION.to_be_bytes());
        nonce_bytes[4..].copy_from_slice(&seq.as_u64().to_be_bytes());
        let ct = self
            .suite
            .aead()
            .seal(dek, &AeadNonce::from_bytes(nonce_bytes), b"", &packed);
        let mut snapshot = Vec::with_capacity(AEAD_NONCE_LEN + ct.len());
        snapshot.extend_from_slice(&nonce_bytes);
        snapshot.extend_from_slice(&ct);
        Ok(FoldOk {
            state,
            persist: Vec::new(),
            pings: Vec::new(),
            snapshot,
            seq,
        })
    }

    /// Apply a persist record.
    pub fn apply(
        &self,
        mut state: EngineState,
        persist: &[u8],
    ) -> Result<EngineState, EngineError> {
        let dek = self.require_dek()?;
        if persist.len() < AEAD_NONCE_LEN {
            return Err(EngineError::MalformedPersist);
        }
        let nonce_bytes: [u8; AEAD_NONCE_LEN] = persist[..AEAD_NONCE_LEN]
            .try_into()
            .map_err(|_| EngineError::MalformedPersist)?;
        let ct = &persist[AEAD_NONCE_LEN..];
        let packed = self
            .suite
            .aead()
            .open(dek, &AeadNonce::from_bytes(nonce_bytes), b"", ct)
            .map_err(|_| EngineError::MalformedPersist)?;
        let canonical = self
            .suite
            .compress()
            .decompress(&packed, PERSIST_MAX_UNCOMPRESSED)
            .map_err(|_| EngineError::MalformedPersist)?;
        let json = self
            .suite
            .canonical_json()
            .decode(&canonical)
            .map_err(|_| EngineError::MalformedPersist)?;
        let body = durable_body_from_json(self.suite.b64u(), &json)
            .map_err(|_| EngineError::MalformedPersist)?;
        let secret = match &body.payload {
            TxPayload::EngineInit
            | TxPayload::EngineSetDefaults { .. }
            | TxPayload::EngineCreateUser { .. }
            | TxPayload::EngineCreateIdentity { .. }
            | TxPayload::EngineDeleteUser { .. }
            | TxPayload::EngineDeleteIdentity { .. }
            | TxPayload::EngineSetDisplayName { .. }
            | TxPayload::EngineUnsetDisplayName { .. }
            | TxPayload::EngineSetProfilePic { .. }
            | TxPayload::EngineSetDeviceName { .. }
            | TxPayload::EngineKickDevice { .. } => self.engine_secret()?,
            _ => self
                .conv_secret(&state, &body.conversation_id)
                .unwrap_or(Secret::from_bytes(*body.conversation_id.as_bytes())),
        };
        let tx_id = self.tx_id(&secret, &body.payload);
        if let Some(existing) = state.txs.get(&tx_id)
            && existing.payload != body.payload
        {
            return Err(EngineError::Equivocation);
        }
        let is_confirm = matches!(body.payload, TxPayload::Confirm);
        let conversation_id = body.conversation_id;
        state.txs.insert(tx_id, body);
        if is_confirm {
            let _ = self.spawn_child(&mut state, conversation_id);
        }
        let seq = PersistSeq::from_u64(u64::from_be_bytes(
            nonce_bytes[4..]
                .try_into()
                .map_err(|_| EngineError::MalformedPersist)?,
        ));
        if seq.saturating_add(1) > state.next_seq {
            state.next_seq = seq.saturating_add(1);
        }
        state.persist_log.insert(seq, tx_id);
        let _ = PACKET_NONCE_LEN;
        Ok(state)
    }

    /// Apply a folded snapshot.
    pub fn apply_folded(&self, snapshot: &[u8]) -> Result<EngineState, EngineError> {
        let dek = self.require_dek()?;
        if snapshot.len() < AEAD_NONCE_LEN {
            return Err(EngineError::MalformedPersist);
        }
        let nonce_bytes: [u8; AEAD_NONCE_LEN] = snapshot[..AEAD_NONCE_LEN]
            .try_into()
            .map_err(|_| EngineError::MalformedPersist)?;
        let ver = u32::from_be_bytes(
            nonce_bytes[..4]
                .try_into()
                .map_err(|_| EngineError::MalformedPersist)?,
        );
        if ver != FOLD_VERSION {
            return Err(EngineError::MalformedPersist);
        }
        let packed = self
            .suite
            .aead()
            .open(
                dek,
                &AeadNonce::from_bytes(nonce_bytes),
                b"",
                &snapshot[AEAD_NONCE_LEN..],
            )
            .map_err(|_| EngineError::MalformedPersist)?;
        let canonical = self
            .suite
            .compress()
            .decompress(&packed, PERSIST_MAX_UNCOMPRESSED)
            .map_err(|_| EngineError::MalformedPersist)?;
        let json = self
            .suite
            .canonical_json()
            .decode(&canonical)
            .map_err(|_| EngineError::MalformedPersist)?;
        let Json::Object(members) = json else {
            return Err(EngineError::MalformedPersist);
        };
        let get = |k: &str| members.iter().find(|(n, _)| n == k).map(|(_, v)| v);
        let Json::Number(next_seq) = get("next_seq").ok_or(EngineError::MalformedPersist)? else {
            return Err(EngineError::MalformedPersist);
        };
        let ticked = match get("ticked") {
            Some(Json::Null) | None => None,
            Some(Json::Number(n)) => Some(UnixSeconds::from_u64(*n)),
            _ => return Err(EngineError::MalformedPersist),
        };
        let mut state = EngineState::new();
        state.next_seq = PersistSeq::from_u64(*next_seq);
        state.ticked = ticked;
        if let Some(Json::Array(txs)) = get("txs") {
            for item in txs {
                let Json::Object(m) = item else {
                    return Err(EngineError::MalformedPersist);
                };
                let getm = |k: &str| m.iter().find(|(n, _)| n == k).map(|(_, v)| v);
                let Json::String(id_s) = getm("tx_id").ok_or(EngineError::MalformedPersist)? else {
                    return Err(EngineError::MalformedPersist);
                };
                let id_v = self
                    .suite
                    .b64u()
                    .decode(id_s)
                    .map_err(|_| EngineError::MalformedPersist)?;
                let tx_id =
                    Tag::from_bytes(id_v.try_into().map_err(|_| EngineError::MalformedPersist)?);
                let body = durable_body_from_json(
                    self.suite.b64u(),
                    getm("body").ok_or(EngineError::MalformedPersist)?,
                )
                .map_err(|_| EngineError::MalformedPersist)?;
                state.txs.insert(tx_id, body);
            }
        }
        if let Some(Json::Array(items)) = get("frags") {
            for item in items {
                let Json::Object(m) = item else {
                    return Err(EngineError::MalformedPersist);
                };
                let getm = |k: &str| m.iter().find(|(n, _)| n == k).map(|(_, v)| v);
                let tx_id = decode_fold32(
                    self.suite.b64u(),
                    getm("tx_id").ok_or(EngineError::MalformedPersist)?,
                )?;
                let conversation_id = decode_fold32(
                    self.suite.b64u(),
                    getm("conversation_id").ok_or(EngineError::MalformedPersist)?,
                )?;
                let last_i = match getm("last_i") {
                    Some(Json::Null) | None => None,
                    Some(Json::Number(n)) => Some(FragIndex::from_u64(*n)),
                    _ => return Err(EngineError::MalformedPersist),
                };
                let Json::Array(parts_v) = getm("parts").ok_or(EngineError::MalformedPersist)?
                else {
                    return Err(EngineError::MalformedPersist);
                };
                let mut parts = BTreeMap::new();
                for part in parts_v {
                    let Json::Object(pm) = part else {
                        return Err(EngineError::MalformedPersist);
                    };
                    let getp = |k: &str| pm.iter().find(|(n, _)| n == k).map(|(_, v)| v);
                    let Json::Number(i) = getp("i").ok_or(EngineError::MalformedPersist)? else {
                        return Err(EngineError::MalformedPersist);
                    };
                    let frag = decode_fold_bstr(
                        self.suite.b64u(),
                        getp("frag").ok_or(EngineError::MalformedPersist)?,
                    )?;
                    parts.insert(FragIndex::from_u64(*i), frag);
                }
                state.frags.insert(
                    Tag::from_bytes(tx_id),
                    FragSet {
                        conversation_id: ConversationId::from_bytes(conversation_id),
                        parts,
                        last_i,
                    },
                );
            }
        } else if get("frags").is_some() {
            return Err(EngineError::MalformedPersist);
        }
        if let Some(Json::Array(items)) = get("bins") {
            for item in items {
                let Json::Object(m) = item else {
                    return Err(EngineError::MalformedPersist);
                };
                let getm = |k: &str| m.iter().find(|(n, _)| n == k).map(|(_, v)| v);
                let channel =
                    parse_fold_channel(getm("channel").ok_or(EngineError::MalformedPersist)?)?;
                let tag_key = decode_fold32(
                    self.suite.b64u(),
                    getm("tag_key").ok_or(EngineError::MalformedPersist)?,
                )?;
                let watermark = match getm("watermark").ok_or(EngineError::MalformedPersist)? {
                    Json::Null => None,
                    Json::Number(n) => Some(TimeBin::from_u64(*n)),
                    _ => return Err(EngineError::MalformedPersist),
                };
                let Json::Array(completed_v) =
                    getm("completed").ok_or(EngineError::MalformedPersist)?
                else {
                    return Err(EngineError::MalformedPersist);
                };
                let mut completed = BTreeSet::new();
                for c in completed_v {
                    let Json::Number(n) = c else {
                        return Err(EngineError::MalformedPersist);
                    };
                    completed.insert(TimeBin::from_u64(*n));
                }
                let key = progress_key(&channel, &TagKey::from_bytes(tag_key));
                state.bin_progress.insert(
                    key,
                    BinProgress {
                        channel,
                        tag_key: TagKey::from_bytes(tag_key),
                        watermark,
                        completed,
                    },
                );
            }
        } else if get("bins").is_some() {
            return Err(EngineError::MalformedPersist);
        }
        if let Some(Json::Array(items)) = get("persist_log") {
            for item in items {
                let Json::Object(m) = item else {
                    return Err(EngineError::MalformedPersist);
                };
                let getm = |k: &str| m.iter().find(|(n, _)| n == k).map(|(_, v)| v);
                let Json::Number(pseq) = getm("seq").ok_or(EngineError::MalformedPersist)? else {
                    return Err(EngineError::MalformedPersist);
                };
                #[rustfmt::skip]
                let tx_id = Tag::from_bytes(decode_fold32(self.suite.b64u(), getm("tx_id").ok_or(EngineError::MalformedPersist)?)?);
                state.persist_log.insert(PersistSeq::from_u64(*pseq), tx_id);
            }
        } else if get("persist_log").is_some() {
            return Err(EngineError::MalformedPersist);
        }
        let banned = [
            "tickets",
            "chains",
            "recv_chains",
            "skipped_mks",
            "failed",
            "owners",
            "inviters",
            "intake",
            "shared_inviter",
            "shared_invitee",
            "established",
            "last_acks",
            "device_enc",
            "device_sign",
        ];
        if banned.iter().any(|k| get(k).is_some()) {
            return Err(EngineError::MalformedPersist);
        }
        if let Some(users) = get("users") {
            super::fold_tree::install_users(self.suite.b64u(), &mut state, users)?;
        }
        if let Some(device) = get("device") {
            super::fold_tree::install_device(self.suite.b64u(), &mut state, device)?;
        }
        Ok(state)
    }
}
