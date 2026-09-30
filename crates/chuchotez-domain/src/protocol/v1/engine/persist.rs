//! Fold and apply persist records.

use super::super::chain::{CachedMk, chain_from_json, chain_to_json};
use super::super::codec::{
    durable_body_from_json, durable_body_to_json, durable_json, ticket_from_json, ticket_to_json,
};
use super::super::kem::KeyPair;
use super::super::payload::{
    ConversationSort, PACKET_NONCE_LEN, PERSIST_MAX_UNCOMPRESSED, TxPayload,
};
use super::super::sign::SigningKeyPair;
use super::super::{
    AEAD_NONCE_LEN, AeadNonce, ConversationId, EngineError, IdentityId, Json, Secret, Tag, TagKey,
    UserId,
};
use super::helpers::*;
use super::query::*;
use super::state::*;
use super::{Engine, EngineState, FOLD_VERSION};
use std::collections::{BTreeMap, BTreeSet};
impl Engine {
    /// Fold a snapshot.
    pub fn fold(&self, state: EngineState) -> Result<FoldOk, EngineError> {
        let dek = self.require_dek()?;
        let seq = state.next_seq;
        if seq == u64::MAX {
            return Err(EngineError::MalformedPersist);
        }
        let mut txs = Vec::new();
        for (id, body) in &state.txs {
            txs.push(Json::Object(vec![
                (
                    "tx_id".into(),
                    super::super::codec::bstr(self.suite.b64u(), id.as_bytes()),
                ),
                ("body".into(), durable_body_to_json(self.suite.b64u(), body)),
            ]));
        }
        let mut tickets = Vec::new();
        for (id, hs, sort) in state.handshake_entries() {
            tickets.push(Json::Object(vec![
                (
                    "conversation_id".into(),
                    super::super::codec::bstr(self.suite.b64u(), id.as_bytes()),
                ),
                (
                    "ticket".into(),
                    ticket_to_json(self.suite.b64u(), &hs.ticket),
                ),
                (
                    "sync".into(),
                    Json::Bool(matches!(sort, ConversationSort::HandshakeSync)),
                ),
            ]));
        }
        let mut chains = Vec::new();
        for (key, chain) in &state.send_chains {
            chains.push(chain_to_json(self.suite.b64u(), key, chain));
        }
        let mut recv_chains = Vec::new();
        for (key, chain) in &state.recv_chains {
            recv_chains.push(chain_to_json(self.suite.b64u(), key, chain));
        }
        let mut skipped = Vec::new();
        for (key, entries) in &state.skipped_mks {
            let mut mks = Vec::new();
            for e in entries {
                mks.push(Json::Object(vec![
                    (
                        "mk".into(),
                        super::super::codec::bstr(self.suite.b64u(), &e.mk),
                    ),
                    ("expires_at".into(), Json::Number(e.expires_at)),
                ]));
            }
            skipped.push(Json::Object(vec![
                (
                    "key".into(),
                    super::super::codec::bstr(self.suite.b64u(), key),
                ),
                ("mks".into(), Json::Array(mks)),
            ]));
        }
        let mut frags = Vec::new();
        for (tx_id, set) in &state.frags {
            let mut parts = Vec::new();
            for (i, frag) in &set.parts {
                parts.push(Json::Object(vec![
                    ("i".into(), Json::Number(*i)),
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
                    set.last_i.map(Json::Number).unwrap_or(Json::Null),
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
                    progress.watermark.map(Json::Number).unwrap_or(Json::Null),
                ),
                (
                    "completed".into(),
                    Json::Array(
                        progress
                            .completed
                            .iter()
                            .copied()
                            .map(Json::Number)
                            .collect(),
                    ),
                ),
            ]));
        }
        let mut failed = Vec::new();
        let mut owners = Vec::new();
        let mut inviters = Vec::new();
        let mut intake = Vec::new();
        let mut shared_inviter = Vec::new();
        let mut shared_invitee = Vec::new();
        for (id, hs, _) in state.handshake_entries() {
            if let Some(reason) = hs.failed_reason() {
                failed.push(failed_to_json(self.suite.b64u(), id, reason));
            }
            if let Some((uid, iid)) = state.owner(id) {
                owners.push(Json::Object(vec![
                    (
                        "conversation_id".into(),
                        super::super::codec::bstr(self.suite.b64u(), id.as_bytes()),
                    ),
                    (
                        "user_id".into(),
                        super::super::codec::bstr(self.suite.b64u(), uid.as_bytes()),
                    ),
                    (
                        "identity_id".into(),
                        super::super::codec::bstr(self.suite.b64u(), iid.as_bytes()),
                    ),
                ]));
            }
            if hs.is_inviter() {
                inviters.push(super::super::codec::bstr(self.suite.b64u(), id.as_bytes()));
            }
            if let Some(kp) = hs.intake() {
                intake.push(Json::Object(vec![
                    (
                        "conversation_id".into(),
                        super::super::codec::bstr(self.suite.b64u(), id.as_bytes()),
                    ),
                    (
                        "pk".into(),
                        super::super::codec::bstr(self.suite.b64u(), kp.public_bytes()),
                    ),
                    (
                        "sk".into(),
                        super::super::codec::bstr(self.suite.b64u(), kp.secret_bytes()),
                    ),
                ]));
            }
            if let Some(shared) = hs.shared_inviter() {
                shared_inviter.push(Json::Object(vec![
                    (
                        "conversation_id".into(),
                        super::super::codec::bstr(self.suite.b64u(), id.as_bytes()),
                    ),
                    (
                        "shared".into(),
                        super::super::codec::bstr(self.suite.b64u(), shared.as_bytes()),
                    ),
                ]));
            }
            if let Some(shared) = hs.shared_invitee() {
                shared_invitee.push(Json::Object(vec![
                    (
                        "conversation_id".into(),
                        super::super::codec::bstr(self.suite.b64u(), id.as_bytes()),
                    ),
                    (
                        "shared".into(),
                        super::super::codec::bstr(self.suite.b64u(), shared.as_bytes()),
                    ),
                ]));
            }
        }
        let mut established = Vec::new();
        for (child, es, sync) in state.established_entries() {
            if let Some((uid, iid)) = state.owner(child) {
                owners.push(Json::Object(vec![
                    (
                        "conversation_id".into(),
                        super::super::codec::bstr(self.suite.b64u(), child.as_bytes()),
                    ),
                    (
                        "user_id".into(),
                        super::super::codec::bstr(self.suite.b64u(), uid.as_bytes()),
                    ),
                    (
                        "identity_id".into(),
                        super::super::codec::bstr(self.suite.b64u(), iid.as_bytes()),
                    ),
                ]));
            }
            established.push(Json::Object(vec![
                (
                    "conversation_id".into(),
                    super::super::codec::bstr(self.suite.b64u(), child.as_bytes()),
                ),
                (
                    "handshake_id".into(),
                    super::super::codec::bstr(self.suite.b64u(), es.parent.as_bytes()),
                ),
                (
                    "secret".into(),
                    super::super::codec::bstr(self.suite.b64u(), es.secret.as_bytes()),
                ),
                ("sync".into(), Json::Bool(sync)),
            ]));
        }
        let device_enc = state
            .device
            .enc
            .as_ref()
            .map(|k| keypair_json(self.suite.b64u(), k.public_bytes(), k.secret_bytes()))
            .unwrap_or(Json::Null);
        let device_sign = state
            .device
            .sign
            .as_ref()
            .map(|k| keypair_json(self.suite.b64u(), k.public_bytes(), k.secret_bytes()))
            .unwrap_or(Json::Null);
        let json = Json::Object(vec![
            ("type".into(), Json::String("v1-engine-snapshot".into())),
            ("next_seq".into(), Json::Number(seq)),
            (
                "ticked".into(),
                state.ticked.map(Json::Number).unwrap_or(Json::Null),
            ),
            ("txs".into(), Json::Array(txs)),
            ("tickets".into(), Json::Array(tickets)),
            ("chains".into(), Json::Array(chains)),
            ("recv_chains".into(), Json::Array(recv_chains)),
            ("skipped_mks".into(), Json::Array(skipped)),
            ("frags".into(), Json::Array(frags)),
            ("bins".into(), Json::Array(bins)),
            ("failed".into(), Json::Array(failed)),
            ("owners".into(), Json::Array(owners)),
            ("inviters".into(), Json::Array(inviters)),
            ("intake".into(), Json::Array(intake)),
            ("shared_inviter".into(), Json::Array(shared_inviter)),
            ("shared_invitee".into(), Json::Array(shared_invitee)),
            ("established".into(), Json::Array(established)),
            ("device_enc".into(), device_enc),
            ("device_sign".into(), device_sign),
        ]);
        let canonical = self.suite.canonical_json().encode(&json);
        (canonical.len() <= PERSIST_MAX_UNCOMPRESSED)
            .then_some(())
            .ok_or(EngineError::BodyTooLarge)?;
        let packed = self.suite.compress().compress(&canonical);
        let mut nonce_bytes = [0u8; AEAD_NONCE_LEN];
        nonce_bytes[..4].copy_from_slice(&FOLD_VERSION.to_be_bytes());
        nonce_bytes[4..].copy_from_slice(&seq.to_be_bytes());
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
        let seq = u64::from_be_bytes(
            nonce_bytes[4..]
                .try_into()
                .map_err(|_| EngineError::MalformedPersist)?,
        );
        if seq.saturating_add(1) > state.next_seq {
            state.next_seq = seq.saturating_add(1);
        }
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
            Some(Json::Number(n)) => Some(*n),
            _ => return Err(EngineError::MalformedPersist),
        };
        let mut state = EngineState::new();
        state.next_seq = *next_seq;
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
        let mut fold_tickets = Vec::new();
        if let Some(Json::Array(tickets)) = get("tickets") {
            for item in tickets {
                let Json::Object(m) = item else {
                    return Err(EngineError::MalformedPersist);
                };
                let getm = |k: &str| m.iter().find(|(n, _)| n == k).map(|(_, v)| v);
                let Json::String(id_s) =
                    getm("conversation_id").ok_or(EngineError::MalformedPersist)?
                else {
                    return Err(EngineError::MalformedPersist);
                };
                let id_v = self
                    .suite
                    .b64u()
                    .decode(id_s)
                    .map_err(|_| EngineError::MalformedPersist)?;
                let cid = ConversationId::from_bytes(
                    id_v.try_into().map_err(|_| EngineError::MalformedPersist)?,
                );
                let ticket = ticket_from_json(
                    self.suite.b64u(),
                    getm("ticket").ok_or(EngineError::MalformedPersist)?,
                )
                .map_err(|_| EngineError::MalformedPersist)?;
                let sync = matches!(getm("sync"), Some(Json::Bool(true)));
                fold_tickets.push((cid, ticket, sync));
            }
        }
        if let Some(Json::Array(chains)) = get("chains") {
            for item in chains {
                let (key, chain) = chain_from_json(self.suite.b64u(), item)?;
                state.send_chains.insert(key, chain);
            }
        } else if get("chains").is_some() {
            return Err(EngineError::MalformedPersist);
        }
        if let Some(Json::Array(chains)) = get("recv_chains") {
            for item in chains {
                let (key, chain) = chain_from_json(self.suite.b64u(), item)?;
                state.recv_chains.insert(key, chain);
            }
        } else if get("recv_chains").is_some() {
            return Err(EngineError::MalformedPersist);
        }
        if let Some(Json::Array(items)) = get("skipped_mks") {
            for item in items {
                let Json::Object(m) = item else {
                    return Err(EngineError::MalformedPersist);
                };
                let getm = |k: &str| m.iter().find(|(n, _)| n == k).map(|(_, v)| v);
                let key = decode_fold_bstr(
                    self.suite.b64u(),
                    getm("key").ok_or(EngineError::MalformedPersist)?,
                )?;
                let Json::Array(mks) = getm("mks").ok_or(EngineError::MalformedPersist)? else {
                    return Err(EngineError::MalformedPersist);
                };
                let mut entries = Vec::new();
                for mk in mks {
                    let Json::Object(mm) = mk else {
                        return Err(EngineError::MalformedPersist);
                    };
                    let gete = |k: &str| mm.iter().find(|(n, _)| n == k).map(|(_, v)| v);
                    let mk_v = decode_fold32(
                        self.suite.b64u(),
                        gete("mk").ok_or(EngineError::MalformedPersist)?,
                    )?;
                    let Json::Number(expires_at) =
                        gete("expires_at").ok_or(EngineError::MalformedPersist)?
                    else {
                        return Err(EngineError::MalformedPersist);
                    };
                    entries.push(CachedMk {
                        mk: mk_v,
                        expires_at: *expires_at,
                    });
                }
                state.skipped_mks.insert(key, entries);
            }
        } else if get("skipped_mks").is_some() {
            return Err(EngineError::MalformedPersist);
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
                    Some(Json::Number(n)) => Some(*n),
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
                    parts.insert(*i, frag);
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
                    Json::Number(n) => Some(*n),
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
                    completed.insert(*n);
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
        let mut fold_failed = BTreeMap::new();
        if let Some(Json::Array(items)) = get("failed") {
            for item in items {
                let (cid, reason) = parse_failed(self.suite.b64u(), item)?;
                fold_failed.insert(cid, reason);
            }
        } else if get("failed").is_some() {
            return Err(EngineError::MalformedPersist);
        }
        let mut fold_owners = BTreeMap::new();
        if let Some(Json::Array(items)) = get("owners") {
            for item in items {
                let Json::Object(m) = item else {
                    return Err(EngineError::MalformedPersist);
                };
                let getm = |k: &str| m.iter().find(|(n, _)| n == k).map(|(_, v)| v);
                #[rustfmt::skip]
                let cid = decode_fold32(self.suite.b64u(), getm("conversation_id").ok_or(EngineError::MalformedPersist)?)?;
                #[rustfmt::skip]
                let uid = decode_fold32(self.suite.b64u(), getm("user_id").ok_or(EngineError::MalformedPersist)?)?;
                #[rustfmt::skip]
                let iid = decode_fold32(self.suite.b64u(), getm("identity_id").ok_or(EngineError::MalformedPersist)?)?;
                fold_owners.insert(
                    ConversationId::from_bytes(cid),
                    (UserId::from_bytes(uid), IdentityId::from_bytes(iid)),
                );
            }
        } else if get("owners").is_some() {
            return Err(EngineError::MalformedPersist);
        }
        let mut fold_inviters = BTreeSet::new();
        if let Some(Json::Array(items)) = get("inviters") {
            for item in items {
                #[rustfmt::skip]
                fold_inviters.insert(ConversationId::from_bytes(decode_fold32(self.suite.b64u(), item)?));
            }
        } else if get("inviters").is_some() {
            return Err(EngineError::MalformedPersist);
        }
        let mut fold_intake = BTreeMap::new();
        if let Some(Json::Array(items)) = get("intake") {
            for item in items {
                let Json::Object(m) = item else {
                    return Err(EngineError::MalformedPersist);
                };
                let getm = |k: &str| m.iter().find(|(n, _)| n == k).map(|(_, v)| v);
                #[rustfmt::skip]
                let cid = decode_fold32(self.suite.b64u(), getm("conversation_id").ok_or(EngineError::MalformedPersist)?)?;
                #[rustfmt::skip]
                let pk = decode_fold_bstr(self.suite.b64u(), getm("pk").ok_or(EngineError::MalformedPersist)?)?;
                #[rustfmt::skip]
                let sk = decode_fold_bstr(self.suite.b64u(), getm("sk").ok_or(EngineError::MalformedPersist)?)?;
                fold_intake.insert(ConversationId::from_bytes(cid), KeyPair::from_parts(pk, sk));
            }
        } else if get("intake").is_some() {
            return Err(EngineError::MalformedPersist);
        }
        let mut fold_shared_inviter = BTreeMap::new();
        parse_fold_shared_map(
            self.suite.b64u(),
            get("shared_inviter"),
            &mut fold_shared_inviter,
        )?;
        let mut fold_shared_invitee = BTreeMap::new();
        parse_fold_shared_map(
            self.suite.b64u(),
            get("shared_invitee"),
            &mut fold_shared_invitee,
        )?;
        let mut fold_children = BTreeMap::new();
        let mut fold_established = Vec::new();
        if let Some(Json::Array(items)) = get("established") {
            for item in items {
                let Json::Object(m) = item else {
                    return Err(EngineError::MalformedPersist);
                };
                let getm = |k: &str| m.iter().find(|(n, _)| n == k).map(|(_, v)| v);
                #[rustfmt::skip]
                let child = decode_fold32(self.suite.b64u(), getm("conversation_id").ok_or(EngineError::MalformedPersist)?)?;
                #[rustfmt::skip]
                let handshake = decode_fold32(self.suite.b64u(), getm("handshake_id").ok_or(EngineError::MalformedPersist)?)?;
                #[rustfmt::skip]
                let secret = decode_fold32(self.suite.b64u(), getm("secret").ok_or(EngineError::MalformedPersist)?)?;
                let sync = match getm("sync") {
                    Some(Json::Bool(b)) => *b,
                    None => false,
                    _ => return Err(EngineError::MalformedPersist),
                };
                let child_id = ConversationId::from_bytes(child);
                let handshake_id = ConversationId::from_bytes(handshake);
                fold_children.insert(handshake_id, child_id);
                fold_established.push((child_id, handshake_id, Secret::from_bytes(secret), sync));
            }
        } else if get("established").is_some() {
            return Err(EngineError::MalformedPersist);
        }
        match get("device_enc") {
            Some(Json::Null) | None => {}
            Some(v) => {
                let (pk, sk) = parse_fold_keypair(self.suite.b64u(), v)?;
                state.device.enc = Some(KeyPair::from_parts(pk, sk));
            }
        }
        match get("device_sign") {
            Some(Json::Null) | None => {}
            Some(v) => {
                let (pk, sk) = parse_fold_keypair(self.suite.b64u(), v)?;
                state.device.sign = Some(SigningKeyPair::from_parts(pk, sk));
            }
        }
        state.install_from_fold(FoldDirectory {
            tickets: fold_tickets,
            owners: fold_owners,
            inviters: fold_inviters,
            intake: fold_intake,
            shared_inviter: fold_shared_inviter,
            shared_invitee: fold_shared_invitee,
            failed: fold_failed,
            children: fold_children,
            established: fold_established,
        });
        Ok(state)
    }
}
