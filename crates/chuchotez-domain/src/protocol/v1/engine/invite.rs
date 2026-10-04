//! DM and Sync tickets.

use super::super::codec::{ticket_from_json, ticket_to_json};
use super::super::payload::{
    DurableBody, Hlc, TICKET_MAX_UNCOMPRESSED, Ticket, TxNotice, TxPayload, time_bin,
};
use super::super::{
    ConversationId, DeviceId, DisplayName, DurableChannel, EngineError, IdentityId, KemSeed,
    Policy, Secret, SignSeed, UnixSeconds, UserId,
};
use super::party::{InviteePhase, InviterPhase};
use super::query::*;
use super::state::DeviceKeys;
use super::{Engine, EngineState};
use crate::protocol::Rng;
impl Engine {
    /// Create a DM invite. Posts sealed `PacketTxFragLast` (and `More`) of the
    /// `TxNotice` at InviteTag. Handshake packets carry empty `actor_id`.
    pub fn create_invite(
        &self,
        mut state: EngineState,
        rng: &dyn Rng,
        user_id: UserId,
        identity_id: IdentityId,
        expires: u64,
        persistents: Option<Vec<DurableChannel>>,
    ) -> Result<(MutateOk, ConversationId), EngineError> {
        let now = Self::require_tick(&state)?;
        let expires = UnixSeconds::from_u64(expires);
        if expires <= now {
            return Err(EngineError::ExpiresNotAfterNow);
        }
        let persistents = persistents.unwrap_or_else(|| self.defaults.persistents().to_vec());
        super::super::defaults::check_channel_bounds(&persistents, &[])
            .map_err(|_| EngineError::ChannelBounds)?;
        let identity_policy = self.identity_policy(&state, &user_id, &identity_id)?;
        let conversation_id = ConversationId::from(rng.random32());
        let secret = Secret::from(rng.random32());
        let ticket = Ticket {
            secret,
            persistents: persistents.clone(),
            expires,
        };
        let intake = self
            .suite
            .kem()
            .generate(
                identity_policy,
                &KemSeed::from_pair(rng.random32(), rng.random32()),
            )
            .map_err(|_| EngineError::MalformedPayload)?;
        let payload = TxPayload::Notice(TxNotice {
            policy: identity_policy,
            intake_pk: crate::protocol::v1::EncryptionPublicKey::from_bytes(
                intake.public_bytes().to_vec(),
            ),
            persistents: persistents.clone(),
            ephemerals: self.defaults.ephemerals().to_vec(),
            expires,
        });
        let tx_id = self.tx_id(&secret, &payload);
        let body = DurableBody {
            conversation_id,
            hlc: Hlc {
                wall_ms: now.as_u64().saturating_mul(1000),
                counter: 0,
            },
            payload,
        };
        let persist = self.persist_record(state.next_seq, &body)?;
        state.next_seq = state.next_seq.saturating_add(1);
        state.put_dm_inviter(
            user_id,
            identity_id,
            conversation_id,
            InviterPhase::InviteCreated {
                ticket,
                intake,
                list_from: time_bin(now),
            },
        );
        state.insert_body(tx_id, body)?;
        #[rustfmt::skip]
        self.post_handshake_packets(&mut state, rng, conversation_id, &secret, tx_id)?;
        Ok((
            MutateOk {
                state,
                persist: vec![persist],
                pings: Vec::new(),
            },
            conversation_id,
        ))
    }

    pub(super) fn identity_policy(
        &self,
        state: &EngineState,
        user_id: &UserId,
        identity_id: &IdentityId,
    ) -> Result<Policy, EngineError> {
        state
            .bodies()
            .iter()
            .find_map(|tx| match &tx.payload {
                TxPayload::EngineCreateIdentity {
                    user_id: u,
                    identity_id: i,
                    policy,
                    ..
                } if u == user_id && i == identity_id => Some(*policy),
                _ => None,
            })
            .ok_or(EngineError::UnknownIds)
    }

    /// Ticket host string.
    pub fn ticket_host_string(
        &self,
        state: &EngineState,
        ids: &ConversationRef,
    ) -> Result<String, EngineError> {
        let ticket = state
            .ticket(ids.conversation_id)
            .ok_or(EngineError::UnknownIds)?;
        let json = ticket_to_json(self.suite.b64u(), ticket);
        let packed = self
            .suite
            .compress()
            .compress(&self.suite.canonical_json().encode(&json));
        (packed.len() <= TICKET_MAX_UNCOMPRESSED)
            .then_some(())
            .ok_or(EngineError::MalformedTicket)?;
        Ok(self.suite.b64u().encode(&packed))
    }

    /// Receive a ticket.
    pub fn receive_ticket(
        &self,
        mut state: EngineState,
        rng: &dyn Rng,
        user_id: UserId,
        identity_id: IdentityId,
        ticket_host_string: &str,
    ) -> Result<(MutateOk, ConversationId), EngineError> {
        let now = Self::require_tick(&state)?;
        let ticket = self.parse_ticket_host_string(ticket_host_string)?;
        let conversation_id = ConversationId::from(rng.random32());
        state.put_dm_invitee(
            user_id,
            identity_id,
            conversation_id,
            InviteePhase::TicketReceived {
                ticket,
                list_from: time_bin(now),
            },
        );
        Ok((
            MutateOk {
                state,
                persist: Vec::new(),
                pings: Vec::new(),
            },
            conversation_id,
        ))
    }

    /// List users.
    pub fn list_users(&self, state: &EngineState) -> Result<Vec<UserId>, EngineError> {
        let mut out = Vec::new();
        for tx in state.bodies().iter() {
            if let TxPayload::EngineCreateUser { user_id } = &tx.payload {
                out.push(*user_id);
            }
        }
        Ok(out)
    }

    /// List identities.
    pub fn list_identities(
        &self,
        state: &EngineState,
        user_id: UserId,
    ) -> Result<Vec<IdentityId>, EngineError> {
        let mut out = Vec::new();
        for tx in state.bodies().iter() {
            if let TxPayload::EngineCreateIdentity {
                user_id: u,
                identity_id,
                ..
            } = &tx.payload
                && u == &user_id
            {
                out.push(*identity_id);
            }
        }
        Ok(out)
    }

    /// Create a Sync invite. Posts sealed `PacketTxFragLast` (and `More`) of
    /// the `TxNotice` at InviteTag with empty `actor_id`.
    pub fn create_sync_invite(
        &self,
        mut state: EngineState,
        rng: &dyn Rng,
        policy: Policy,
        expires: u64,
        device_name: &str,
        persistents: Option<Vec<DurableChannel>>,
    ) -> Result<(MutateOk, ConversationId), EngineError> {
        let now = Self::require_tick(&state)?;
        if sync_peer_count(&state) >= 4 {
            return Err(EngineError::MemberCap);
        }
        let expires = UnixSeconds::from_u64(expires);
        if expires <= now {
            return Err(EngineError::ExpiresNotAfterNow);
        }
        let name =
            DisplayName::try_from(device_name).map_err(|_| EngineError::MalformedDisplayName)?;
        let persistents = persistents.unwrap_or_else(|| self.defaults.persistents().to_vec());
        super::super::defaults::check_channel_bounds(&persistents, &[])
            .map_err(|_| EngineError::ChannelBounds)?;
        let conversation_id = ConversationId::from(rng.random32());
        let secret = Secret::from(rng.random32());
        let device_id = state
            .device
            .keys
            .as_ref()
            .and_then(|k| k.id)
            .unwrap_or_else(|| DeviceId::from(rng.random32()));
        if state.device.keys.is_none() {
            state.device.keys = Some(DeviceKeys {
                id: Some(device_id),
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
        } else if let Some(keys) = state.device.keys.as_mut() {
            keys.id = Some(device_id);
        }
        let intake = self
            .suite
            .kem()
            .generate(policy, &KemSeed::from_pair(rng.random32(), rng.random32()))
            .map_err(|_| EngineError::MalformedPayload)?;
        let payload = TxPayload::Notice(TxNotice {
            policy,
            intake_pk: crate::protocol::v1::EncryptionPublicKey::from_bytes(
                intake.public_bytes().to_vec(),
            ),
            persistents: persistents.clone(),
            ephemerals: self.defaults.ephemerals().to_vec(),
            expires,
        });
        let tx_id = self.tx_id(&secret, &payload);
        let body = DurableBody {
            conversation_id,
            hlc: Hlc {
                wall_ms: now.as_u64().saturating_mul(1000),
                counter: 0,
            },
            payload,
        };
        let persist = self.persist_record(state.next_seq, &body)?;
        state.next_seq = state.next_seq.saturating_add(1);
        let ticket = Ticket {
            secret,
            persistents: persistents.clone(),
            expires,
        };
        state.put_sync_inviter(
            conversation_id,
            InviterPhase::InviteCreated {
                ticket,
                intake,
                list_from: time_bin(now),
            },
        );
        state.insert_body(tx_id, body)?;
        state.device.name = Some(name);
        #[rustfmt::skip]
        self.post_handshake_packets(&mut state, rng, conversation_id, &secret, tx_id)?;
        Ok((
            MutateOk {
                state,
                persist: vec![persist],
                pings: Vec::new(),
            },
            conversation_id,
        ))
    }

    /// Receive a Sync ticket on an empty engine.
    pub fn receive_sync_ticket(
        &self,
        state: EngineState,
        rng: &dyn Rng,
        ticket_host_string: &str,
    ) -> Result<(MutateOk, ConversationId), EngineError> {
        if state
            .bodies()
            .iter()
            .any(|t| matches!(t.payload, TxPayload::EngineCreateUser { .. }))
        {
            return Err(EngineError::EmptyEngineRequired);
        }
        let now = Self::require_tick(&state)?;
        let ticket = self.parse_ticket_host_string(ticket_host_string)?;
        let conversation_id = ConversationId::from(rng.random32());
        let mut state = state;
        state.put_sync_invitee(
            conversation_id,
            InviteePhase::TicketReceived {
                ticket,
                list_from: time_bin(now),
            },
        );
        Ok((
            MutateOk {
                state,
                persist: Vec::new(),
                pings: Vec::new(),
            },
            conversation_id,
        ))
    }
    pub(super) fn parse_ticket_host_string(
        &self,
        ticket_host_string: &str,
    ) -> Result<Ticket, EngineError> {
        let packed = self
            .suite
            .b64u()
            .decode(ticket_host_string)
            .map_err(|_| EngineError::MalformedTicket)?;
        let canonical = self
            .suite
            .compress()
            .decompress(&packed, TICKET_MAX_UNCOMPRESSED)
            .map_err(|_| EngineError::MalformedTicket)?;
        let json = self
            .suite
            .canonical_json()
            .decode(&canonical)
            .map_err(|_| EngineError::MalformedTicket)?;
        ticket_from_json(self.suite.b64u(), &json).map_err(|_| EngineError::MalformedTicket)
    }
}

fn sync_peer_count(state: &EngineState) -> usize {
    state
        .device
        .conversations
        .iter()
        .filter(|(cid, node)| match &node.kind {
            super::party::DeviceConversation::Synchronization { .. } => true,
            super::party::DeviceConversation::SyncHandshake { .. } => {
                state.child_of(**cid).is_none()
            }
        })
        .count()
}
