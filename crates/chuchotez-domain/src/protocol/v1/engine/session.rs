//! Delete, confirm, group, and send.

use super::super::hmac::{HmacSha256, HmacSha256Key, expand};
use super::super::payload::{PACKET_NONCE_LEN, TxEdit, TxMedia, TxPayload, TxReaction};
use super::super::unicode::is_combining;
use super::super::{
    Address, AeadKey, AeadNonce, ConversationId, DisplayName, DurableChannel, EngineError,
    IdentityId, Kind, Tag, UserId,
};
use super::helpers::*;
use super::party::HandshakeFailure;
use super::query::*;
use super::{Engine, EngineState};
use crate::protocol::Rng;
impl Engine {
    /// Drop a conversation row.
    pub fn delete_conversation(
        &self,
        mut state: EngineState,
        ids: ConversationRef,
    ) -> Result<MutateOk, EngineError> {
        let cid = ids.conversation_id;
        if let Some(ok) = self.delete_group(state.clone(), &ids) {
            return Ok(ok);
        }
        if state.established_secret(cid).is_some() {
            if !state.is_sync(cid) {
                self.require_ids(&state, &ids)?;
            }
            let _ = state.drop_conversation(cid);
            return Ok(MutateOk {
                state,
                persist: Vec::new(),
                pings: Vec::new(),
            });
        }
        self.require_ids(&state, &ids)?;
        let ticket = state.ticket(cid).cloned().ok_or(EngineError::UnknownIds)?;
        let _ = state.drop_conversation(cid);
        state.frags.retain(|_, f| f.conversation_id != cid);
        let tag_key = handshake_tag_key(self.suite.hmac(), ticket.secret.as_bytes());
        for ch in &ticket.persistents {
            state.bin_progress.remove(&progress_key(ch, &tag_key));
        }
        Ok(MutateOk {
            state,
            persist: Vec::new(),
            pings: Vec::new(),
        })
    }

    /// Ingest a complete durable `list` snapshot. Completes that TimeBin in
    /// Confirm a handshake fingerprint. Spawns the child conversation.
    pub fn confirm_established(
        &self,
        state: EngineState,
        _rng: &dyn Rng,
        ids: ConversationRef,
    ) -> Result<MutateOk, EngineError> {
        self.require_confirming(&state, &ids)?;
        if state.is_sync(ids.conversation_id) {
            let secret = self.conv_secret(&state, &ids.conversation_id)?;
            let inviter = state.is_inviter(ids.conversation_id);
            #[rustfmt::skip]
            let mut ok = self.mutate_on(state, &secret, ids.conversation_id, vec![TxPayload::Confirm])?;
            #[rustfmt::skip]
            self.spawn_child(&mut ok.state, ids.conversation_id)?;
            if inviter {
                self.wrap_sync_dek(&mut ok.state, _rng, ids.conversation_id)?;
                let ct = ok
                    .state
                    .device
                    .dek_ct
                    .clone()
                    .ok_or(EngineError::WrongPhase)?;
                #[rustfmt::skip]
                let (tx_id, _, rec) = self.merge_tx(&mut ok.state, &secret, ids.conversation_id, TxPayload::SyncDek { ct })?;
                ok.persist.push(rec);
                #[rustfmt::skip]
                self.post_handshake_packets(&mut ok.state, _rng, ids.conversation_id, &secret, tx_id)?;
            }
            return Ok(ok);
        }
        let mut ok = self.mint_on(state, _rng, &ids, TxPayload::Confirm)?;
        self.spawn_child(&mut ok.state, ids.conversation_id)?;
        Ok(ok)
    }

    /// Reject a handshake fingerprint. Legal on `Confirming`.
    pub fn reject_established(
        &self,
        state: EngineState,
        _rng: &dyn Rng,
        ids: ConversationRef,
    ) -> Result<MutateOk, EngineError> {
        self.require_confirming(&state, &ids)?;
        if state.is_sync(ids.conversation_id) {
            let secret = self.conv_secret(&state, &ids.conversation_id)?;
            let mut ok =
                self.mutate_on(state, &secret, ids.conversation_id, vec![TxPayload::Reject])?;
            ok.state
                .fail(ids.conversation_id, HandshakeFailure::ConfirmationRejected);
            return Ok(ok);
        }
        let mut ok = self.mint_on(state, _rng, &ids, TxPayload::Reject)?;
        ok.state
            .fail(ids.conversation_id, HandshakeFailure::ConfirmationRejected);
        Ok(ok)
    }

    /// Set the group name (owner).
    pub fn set_group_name(
        &self,
        state: EngineState,
        _rng: &dyn Rng,
        ids: ConversationRef,
        name: &str,
    ) -> Result<MutateOk, EngineError> {
        let name = DisplayName::try_from(name).map_err(|_| EngineError::MalformedDisplayName)?;
        self.rename_group(state, _rng, ids, name)
    }

    /// Set the group photo (owner).
    pub fn set_group_photo(
        &self,
        state: EngineState,
        _rng: &dyn Rng,
        ids: ConversationRef,
        photo: Option<&[u8]>,
    ) -> Result<MutateOk, EngineError> {
        let profile_pic = match photo {
            None => None,
            Some(b) => Some(
                super::super::ProfilePic::try_from(b).map_err(|_| EngineError::MalformedPayload)?,
            ),
        };
        self.rephoto_group(state, _rng, ids, profile_pic)
    }

    /// Send a text message.
    pub fn send_text(
        &self,
        state: EngineState,
        _rng: &dyn Rng,
        ids: ConversationRef,
        body: &str,
        reply_to: Option<Tag>,
    ) -> Result<MutateOk, EngineError> {
        self.chat_text(body)?;
        self.gate_chat(&state, &ids)?;
        let secret = self.conv_secret(&state, &ids.conversation_id)?;
        let payload = self.text_payload(&state, ids.conversation_id, body.into(), reply_to);
        let ok = self.mint_on(state, _rng, &ids, payload.clone())?;
        self.finish_chat(ok, ids.conversation_id, &secret, &payload)
    }

    /// Send media pointers.
    pub fn send_media(
        &self,
        mut state: EngineState,
        rng: &dyn Rng,
        ids: ConversationRef,
        attachments: &[MediaDraft],
        reply_to: Option<Tag>,
        caption: Option<&str>,
    ) -> Result<MutateOk, EngineError> {
        if attachments.is_empty() || attachments.len() > 4 {
            return Err(EngineError::MalformedPayload);
        }
        if let Some(caption) = caption {
            self.chat_text(caption)?;
        }
        for att in attachments {
            self.media_name(&att.mime, 128)?;
            self.media_name(&att.filename, 256)?;
        }
        self.gate_chat(&state, &ids)?;
        let secret = self.conv_secret(&state, &ids.conversation_id)?;
        let mut payloads = Vec::new();
        for att in attachments {
            let hash = Tag::from_bytes(self.suite.hash().hash(&att.media_bytes));
            let tag = Tag::from(rng.random32());
            let kind = Kind::try_from("blossom").expect("kind");
            let address = Address::try_from("https://blob.example").expect("address");
            let body = seal_media(
                &self.suite,
                rng,
                secret.as_bytes(),
                hash.as_bytes(),
                &att.media_bytes,
            );
            state.blob_puts.push(BlobPut {
                kind: kind.clone(),
                address: address.clone(),
                tag,
                body,
            });
            payloads.push(TxPayload::Media(TxMedia {
                mime: att.mime.clone(),
                filename: att.filename.clone(),
                hash,
                kind,
                address,
                tag,
                caption: caption.map(str::to_owned),
                reply_to,
                expire_at: self.expire_at(&state, ids.conversation_id),
            }));
        }
        let mut ok = self.mutate_on(state, &secret, ids.conversation_id, payloads.clone())?;
        self.deliver_live(&mut ok.state, rng, ids.conversation_id, &secret, &payloads)?;
        for payload in &payloads {
            let tx_id = self.tx_id(&secret, payload);
            self.remember_sender(&mut ok.state, ids.conversation_id, tx_id);
        }
        ok.pings
            .extend(self.fill_ping(&ok.state, ids.conversation_id));
        Ok(ok)
    }

    /// Open a blob body and check it against `hash`.
    pub fn open_media(
        &self,
        state: &EngineState,
        conversation_id: ConversationId,
        hash: Tag,
        blob: &[u8],
    ) -> Result<Vec<u8>, EngineError> {
        let secret = self.conv_secret(state, &conversation_id)?;
        if blob.len() <= PACKET_NONCE_LEN {
            return Err(EngineError::MalformedPayload);
        }
        let mut nonce = [0u8; PACKET_NONCE_LEN];
        nonce.copy_from_slice(&blob[..PACKET_NONCE_LEN]);
        let key = media_key(self.suite.hmac(), secret.as_bytes(), hash.as_bytes());
        #[rustfmt::skip]
        let plain = self.suite.aead().open(&AeadKey::from_bytes(key), &AeadNonce::from_bytes(nonce), b"", &blob[PACKET_NONCE_LEN..]).map_err(|_| EngineError::MalformedPayload)?;
        let got = Tag::from_bytes(self.suite.hash().hash(&plain));
        if got != hash {
            return Err(EngineError::MalformedPayload);
        }
        Ok(plain)
    }

    fn media_name(&self, value: &str, max: usize) -> Result<(), EngineError> {
        if value.is_empty() || value.len() > max || value.chars().any(is_combining) {
            return Err(EngineError::MalformedPayload);
        }
        Ok(())
    }

    /// Edit a text message.
    pub fn edit_message(
        &self,
        state: EngineState,
        _rng: &dyn Rng,
        ids: ConversationRef,
        target: Tag,
        body: &str,
    ) -> Result<MutateOk, EngineError> {
        self.chat_text(body)?;
        self.gate_chat(&state, &ids)?;
        let secret = self.conv_secret(&state, &ids.conversation_id)?;
        let payload = TxPayload::Edit(TxEdit {
            target,
            body: body.into(),
        });
        let ok = self.mint_on(state, _rng, &ids, payload.clone())?;
        self.finish_chat(ok, ids.conversation_id, &secret, &payload)
    }

    /// Remove a message.
    pub fn remove_message(
        &self,
        state: EngineState,
        _rng: &dyn Rng,
        ids: ConversationRef,
        target: Tag,
    ) -> Result<MutateOk, EngineError> {
        self.gate_chat(&state, &ids)?;
        let secret = self.conv_secret(&state, &ids.conversation_id)?;
        let payload = TxPayload::Remove { target };
        let ok = self.mint_on(state, _rng, &ids, payload.clone())?;
        self.finish_chat(ok, ids.conversation_id, &secret, &payload)
    }

    /// Add or remove a reaction.
    pub fn send_reaction(
        &self,
        state: EngineState,
        _rng: &dyn Rng,
        ids: ConversationRef,
        target: Tag,
        emoji: &str,
        add: bool,
    ) -> Result<MutateOk, EngineError> {
        self.chat_emoji(emoji)?;
        self.gate_chat(&state, &ids)?;
        let secret = self.conv_secret(&state, &ids.conversation_id)?;
        let payload = TxPayload::Reaction(TxReaction {
            target,
            emoji: emoji.into(),
            add,
        });
        let ok = self.mint_on(state, _rng, &ids, payload.clone())?;
        self.finish_chat(ok, ids.conversation_id, &secret, &payload)
    }

    /// Send a typing packet.
    pub fn send_typing(
        &self,
        mut state: EngineState,
        _rng: &dyn Rng,
        ids: ConversationRef,
        composing: bool,
    ) -> Result<MutateOk, EngineError> {
        if !state.is_sync(ids.conversation_id) {
            self.require_ids(&state, &ids)?;
        }
        self.require_signal(&state, ids.conversation_id)?;
        let secret = self.conv_secret(&state, &ids.conversation_id)?;
        #[rustfmt::skip]
        self.post_signal(&mut state, _rng, ids.conversation_id, &secret, Some(composing))?;
        Ok(MutateOk {
            state,
            persist: Vec::new(),
            pings: Vec::new(),
        })
    }

    /// Send a read marker.
    pub fn send_read(
        &self,
        state: EngineState,
        _rng: &dyn Rng,
        ids: ConversationRef,
        up_to: Tag,
    ) -> Result<MutateOk, EngineError> {
        self.gate_chat(&state, &ids)?;
        let secret = self.conv_secret(&state, &ids.conversation_id)?;
        let payload = TxPayload::Read { up_to };
        let ok = self.mint_on(state, _rng, &ids, payload.clone())?;
        self.finish_chat(ok, ids.conversation_id, &secret, &payload)
    }

    /// Send a delivered marker.
    pub fn send_delivered(
        &self,
        state: EngineState,
        _rng: &dyn Rng,
        ids: ConversationRef,
        up_to: Tag,
    ) -> Result<MutateOk, EngineError> {
        self.gate_chat(&state, &ids)?;
        let secret = self.conv_secret(&state, &ids.conversation_id)?;
        let payload = TxPayload::Delivered { up_to };
        let ok = self.mint_on(state, _rng, &ids, payload.clone())?;
        self.finish_chat(ok, ids.conversation_id, &secret, &payload)
    }

    /// Send a presence packet.
    pub fn send_presence(
        &self,
        state: EngineState,
        _rng: &dyn Rng,
        ids: ConversationRef,
    ) -> Result<MutateOk, EngineError> {
        if !state.is_sync(ids.conversation_id) {
            self.require_ids(&state, &ids)?;
        }
        self.require_signal(&state, ids.conversation_id)?;
        let secret = self.conv_secret(&state, &ids.conversation_id)?;
        let mut state = state;
        self.post_signal(&mut state, _rng, ids.conversation_id, &secret, None)?;
        Ok(MutateOk {
            state,
            persist: Vec::new(),
            pings: Vec::new(),
        })
    }

    pub(super) fn finish_chat(
        &self,
        mut ok: MutateOk,
        cid: ConversationId,
        secret: &super::super::Secret,
        payload: &TxPayload,
    ) -> Result<MutateOk, EngineError> {
        let tx_id = self.tx_id(secret, payload);
        self.remember_sender(&mut ok.state, cid, tx_id);
        ok.pings.extend(self.fill_ping(&ok.state, cid));
        Ok(ok)
    }

    /// Query a conversation.
    pub fn get_conversation(
        &self,
        state: &EngineState,
        _user_id: UserId,
        _identity_id: IdentityId,
        conversation_id: ConversationId,
    ) -> Result<Conversation, EngineError> {
        self.conversation_at(state, conversation_id)
            .ok_or(EngineError::UnknownIds)
    }

    /// Confirmation digest as `text(fingerprint)`.
    pub fn confirmation_digest(
        &self,
        state: &EngineState,
        ids: &ConversationRef,
    ) -> Result<String, EngineError> {
        self.conv_secret(state, &ids.conversation_id)?;
        self.try_fingerprint(state, ids.conversation_id)
            .map(|(digest, _)| digest)
            .ok_or(EngineError::WrongPhase)
    }

    /// Ack a posted write.
    pub fn write_ack(
        &self,
        mut state: EngineState,
        channel: DurableChannel,
        tag: Tag,
        body: &[u8],
    ) -> Result<MutateOk, EngineError> {
        let before = state.writes.len();
        state
            .writes
            .retain(|w| !(w.channel == channel && w.tag == tag && w.body.as_slice() == body));
        if state.writes.len() == before {
            return Err(EngineError::UnknownWrite);
        }
        self.advance_ack_phases(&mut state);
        Ok(MutateOk {
            state,
            persist: Vec::new(),
            pings: Vec::new(),
        })
    }
}

fn media_key(hmac: &dyn HmacSha256, secret: &[u8; 32], hash: &[u8]) -> [u8; 32] {
    let mut info = b"chuchotez/1/media".to_vec();
    info.extend_from_slice(hash);
    expand(hmac, &HmacSha256Key::from_bytes(*secret), &info).into_bytes()
}

fn seal_media(
    suite: &super::super::Suite,
    rng: &dyn crate::protocol::Rng,
    secret: &[u8; 32],
    hash: &[u8],
    plain: &[u8],
) -> Vec<u8> {
    let key = media_key(suite.hmac(), secret, hash);
    let rnd = rng.random32();
    let mut nonce = [0u8; PACKET_NONCE_LEN];
    nonce.copy_from_slice(&rnd.as_bytes()[..PACKET_NONCE_LEN]);
    let ct = suite.aead().seal(
        &AeadKey::from_bytes(key),
        &AeadNonce::from_bytes(nonce),
        b"",
        plain,
    );
    let mut body = Vec::with_capacity(PACKET_NONCE_LEN + ct.len());
    body.extend_from_slice(&nonce);
    body.extend_from_slice(&ct);
    body
}
