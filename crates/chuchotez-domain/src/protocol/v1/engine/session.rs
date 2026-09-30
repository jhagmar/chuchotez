//! Delete, confirm, group, and send.

use super::super::payload::{TxEdit, TxMedia, TxPayload, TxReaction, TxText};
use super::super::{
    Address, ConversationId, DisplayName, DurableChannel, EngineError, IdentityId, Kind, Tag,
    UserId,
};
use super::helpers::*;
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
        if state.established(cid).is_some() {
            if !state.is_sync(cid) {
                self.require_ids(&state, &ids)?;
            }
            if let Some((_, super::state::ConversationNode::Established(es))) = state.take_node(cid)
                && let Some(hs) = state.handshake_mut(es.parent)
            {
                hs.clear_child_if(cid);
            }
            return Ok(MutateOk {
                state,
                persist: Vec::new(),
                pings: Vec::new(),
            });
        }
        self.require_ids(&state, &ids)?;
        let ticket = state.ticket(cid).cloned().ok_or(EngineError::UnknownIds)?;
        let _ = state.take_node(cid);
        state
            .send_chains
            .retain(|k, _| k.get(..32) != Some(cid.as_bytes().as_slice()));
        state
            .recv_chains
            .retain(|k, _| k.get(..32) != Some(cid.as_bytes().as_slice()));
        state
            .skipped_mks
            .retain(|k, _| k.get(..32) != Some(cid.as_bytes().as_slice()));
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
            #[rustfmt::skip]
            let mut ok = self.mutate_on(state, &secret, ids.conversation_id, vec![TxPayload::Confirm])?;
            #[rustfmt::skip]
            self.spawn_child(&mut ok.state, ids.conversation_id)?;
            return Ok(ok);
        }
        let mut ok = self.mint_on(state, &ids, TxPayload::Confirm)?;
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
            return self.mutate_on(state, &secret, ids.conversation_id, vec![TxPayload::Reject]);
        }
        self.mint_on(state, &ids, TxPayload::Reject)
    }

    /// Create a group from Established DMs.
    #[allow(clippy::too_many_arguments)]
    pub fn create_group(
        &self,
        _state: EngineState,
        _rng: &dyn Rng,
        _user_id: UserId,
        _identity_id: IdentityId,
        contact_conversation_ids: &[ConversationId],
        _name: &str,
        _photo: Option<&[u8]>,
    ) -> Result<(MutateOk, ConversationId), EngineError> {
        if contact_conversation_ids.is_empty() || contact_conversation_ids.len() > 31 {
            return Err(EngineError::MemberCap);
        }
        Err(EngineError::WrongPhase)
    }

    /// Invite another contact into a group.
    pub fn add_group_member(
        &self,
        _state: EngineState,
        _rng: &dyn Rng,
        _ids: ConversationRef,
        _contact_conversation_id: ConversationId,
    ) -> Result<MutateOk, EngineError> {
        Err(EngineError::WrongPhase)
    }

    /// Accept a group offer.
    pub fn accept_group(
        &self,
        state: EngineState,
        _rng: &dyn Rng,
        ids: ConversationRef,
    ) -> Result<MutateOk, EngineError> {
        self.mint_on(
            state,
            &ids,
            TxPayload::GroupAccept {
                group_id: ids.conversation_id,
            },
        )
    }

    /// Reject a group offer.
    pub fn reject_group(
        &self,
        state: EngineState,
        _rng: &dyn Rng,
        ids: ConversationRef,
    ) -> Result<MutateOk, EngineError> {
        self.mint_on(
            state,
            &ids,
            TxPayload::GroupReject {
                group_id: ids.conversation_id,
            },
        )
    }

    /// Kick a group member.
    pub fn kick_group_member(
        &self,
        state: EngineState,
        _rng: &dyn Rng,
        ids: ConversationRef,
        signing_pk: &[u8],
    ) -> Result<MutateOk, EngineError> {
        self.mint_on(
            state,
            &ids,
            TxPayload::GroupKick {
                signing_pk: signing_pk.to_vec(),
            },
        )
    }

    /// Leave a group.
    pub fn leave_group(
        &self,
        state: EngineState,
        _rng: &dyn Rng,
        ids: ConversationRef,
    ) -> Result<MutateOk, EngineError> {
        self.mint_on(state, &ids, TxPayload::GroupLeave)
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
        self.mint_on(state, &ids, TxPayload::Name { name })
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
        self.mint_on(state, &ids, TxPayload::Photo { profile_pic })
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
        if body.is_empty() || body.len() > 4096 {
            return Err(EngineError::MalformedPayload);
        }
        self.mint_on(
            state,
            &ids,
            TxPayload::Text(TxText {
                body: body.into(),
                reply_to,
                expire_at: None,
            }),
        )
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
        self.require_ids(&state, &ids)?;
        let secret = self.conv_secret(&state, &ids.conversation_id)?;
        let mut payloads = Vec::new();
        for att in attachments {
            if att.mime.is_empty() || att.filename.is_empty() {
                return Err(EngineError::MalformedPayload);
            }
            let hash = Tag::from_bytes(self.suite.hash().hash(&att.media_bytes));
            let tag = Tag::from(rng.random32());
            let kind = Kind::try_from("blossom").map_err(|_| EngineError::MalformedPayload)?;
            let address = Address::try_from("https://blob.example")
                .map_err(|_| EngineError::MalformedPayload)?;
            state.blob_puts.push(BlobPut {
                kind: kind.clone(),
                address: address.clone(),
                tag,
                body: att.media_bytes.clone(),
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
                expire_at: None,
            }));
        }
        self.mutate_on(state, &secret, ids.conversation_id, payloads)
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
        if body.is_empty() || body.len() > 4096 {
            return Err(EngineError::MalformedPayload);
        }
        self.mint_on(
            state,
            &ids,
            TxPayload::Edit(TxEdit {
                target,
                body: body.into(),
            }),
        )
    }

    /// Remove a message.
    pub fn remove_message(
        &self,
        state: EngineState,
        _rng: &dyn Rng,
        ids: ConversationRef,
        target: Tag,
    ) -> Result<MutateOk, EngineError> {
        self.mint_on(state, &ids, TxPayload::Remove { target })
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
        if emoji.is_empty() || emoji.len() > 16 {
            return Err(EngineError::MalformedPayload);
        }
        self.mint_on(
            state,
            &ids,
            TxPayload::Reaction(TxReaction {
                target,
                emoji: emoji.into(),
                add,
            }),
        )
    }

    /// Send a typing packet.
    pub fn send_typing(
        &self,
        mut state: EngineState,
        _rng: &dyn Rng,
        ids: ConversationRef,
        composing: bool,
    ) -> Result<MutateOk, EngineError> {
        self.require_ids(&state, &ids)?;
        let _ = composing;
        state.eph_writes.clear();
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
        self.mint_on(state, &ids, TxPayload::Read { up_to })
    }

    /// Send a delivered marker.
    pub fn send_delivered(
        &self,
        state: EngineState,
        _rng: &dyn Rng,
        ids: ConversationRef,
        up_to: Tag,
    ) -> Result<MutateOk, EngineError> {
        self.mint_on(state, &ids, TxPayload::Delivered { up_to })
    }

    /// Send a presence packet.
    pub fn send_presence(
        &self,
        state: EngineState,
        _rng: &dyn Rng,
        ids: ConversationRef,
    ) -> Result<MutateOk, EngineError> {
        self.require_ids(&state, &ids)?;
        Ok(MutateOk {
            state,
            persist: Vec::new(),
            pings: Vec::new(),
        })
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
        Ok(MutateOk {
            state,
            persist: Vec::new(),
            pings: Vec::new(),
        })
    }
}
