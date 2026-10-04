//! Group create, offer, accept, roster, kick, and leave.

use super::super::codec::payload_to_json;
use super::super::hmac::{HmacSha256Key, expand};
use super::super::payload::{
    GroupMember, PACKET_NONCE_LEN, TxGroupInvite, TxGroupRoster, TxGroupWrap, TxPayload,
};
use super::super::sign::sign_sig_len;
use super::super::{
    AeadKey, AeadNonce, ConversationId, DisplayName, EngineError, IdentityId, KemSeed, Policy,
    ProfilePic, Secret, TagKey, UserId,
};
use super::helpers::{invitee_intro_for, inviter_intro_for};
use super::party::{GroupLive, GroupOffer, GroupPending, GroupPhase, IdentityConversation};
use super::query::{
    Conversation, ConversationRef, GroupMemberView, GroupPendingView, GroupQuery, MutateOk,
};
use super::state::{EngineState, IdentityNode};
use super::{Engine, GroupEstablishedView, GroupOfferView};
use crate::protocol::Rng;

const GROUP_SECRET_INFO: &[u8] = b"chuchotez/1/group-secret";

type IdentityKeys = (Policy, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

impl Engine {
    /// Create a group from Established DMs.
    #[allow(clippy::too_many_arguments)]
    pub fn create_group(
        &self,
        mut state: EngineState,
        rng: &dyn Rng,
        user_id: UserId,
        identity_id: IdentityId,
        contact_conversation_ids: &[ConversationId],
        name: &str,
        photo: Option<&[u8]>,
    ) -> Result<(MutateOk, ConversationId), EngineError> {
        if contact_conversation_ids.is_empty() || contact_conversation_ids.len() > 31 {
            return Err(EngineError::MemberCap);
        }
        let ids = ConversationRef {
            user_id,
            identity_id,
            conversation_id: ConversationId::from_bytes([0; 32]),
        };
        self.require_ids(&state, &ids)?;
        if state.display_name(identity_id).is_none() {
            return Err(EngineError::WrongPhase);
        }
        let name = DisplayName::try_from(name).map_err(|_| EngineError::MalformedDisplayName)?;
        let photo = match photo {
            None => None,
            Some(bytes) => {
                Some(ProfilePic::try_from(bytes).map_err(|_| EngineError::MalformedPayload)?)
            }
        };
        let (policy, enc_pk, sign_pk, _enc_sk, _sign_sk) =
            self.identity_secret(&state, &user_id, &identity_id)?;
        let mut peers = Vec::new();
        for dm in contact_conversation_ids {
            let peer = dm_peer(&state, *dm, &sign_pk).ok_or(EngineError::WrongPhase)?;
            if peers.iter().any(|(pk, _, _)| pk == &peer.0) {
                return Err(EngineError::DuplicateMember);
            }
            peers.push((peer.0, peer.1, *dm));
        }
        let group_id = ConversationId::from(rng.random32());
        let secret = Secret::from(rng.random32());
        let owner = GroupMember {
            signing_pk: sign_pk.clone(),
            encryption_pk: enc_pk,
            send_tag_key: TagKey::from(rng.random32()),
            eph_send_tag_key: TagKey::from(rng.random32()),
        };
        let mut pending = Vec::new();
        let mut payloads_by_dm: Vec<(ConversationId, TxPayload)> = Vec::new();
        for (signing_pk, encryption_pk, dm) in &peers {
            #[rustfmt::skip]
            let group_secret_ct = seal_group_secret(self, rng, policy, encryption_pk, secret.as_bytes())?;
            pending.push(GroupPending {
                signing_pk: signing_pk.clone(),
                encryption_pk: encryption_pk.clone(),
                from_conversation_id: *dm,
                name: name.clone(),
                photo: photo.clone(),
            });
            payloads_by_dm.push((
                *dm,
                TxPayload::GroupInvite(TxGroupInvite {
                    group_id,
                    owner_signing_pk: sign_pk.clone(),
                    persistents: self.defaults.persistents().to_vec(),
                    ephemerals: self.defaults.ephemerals().to_vec(),
                    name: name.clone(),
                    photo: photo.clone(),
                    invitee_signing_pk: signing_pk.clone(),
                    group_secret_ct,
                }),
            ));
        }
        state.put_dm(
            user_id,
            identity_id,
            group_id,
            IdentityNode {
                kind: IdentityConversation::Group(GroupPhase::Live(GroupLive {
                    secret,
                    name,
                    photo,
                    owner_signing_pk: sign_pk,
                    persistents: self.defaults.persistents().to_vec(),
                    ephemerals: self.defaults.ephemerals().to_vec(),
                    members: vec![owner],
                    pending,
                    epoch: 0,
                })),
                chains: Default::default(),
            },
        );
        let mut ok = MutateOk {
            state,
            persist: Vec::new(),
            pings: Vec::new(),
        };
        for (dm, payload) in payloads_by_dm {
            let dm_ids = ConversationRef {
                user_id,
                identity_id,
                conversation_id: dm,
            };
            ok = self.mint_on(ok.state, rng, &dm_ids, payload)?;
        }
        Ok((ok, group_id))
    }

    /// Invite another contact into a group.
    pub fn add_group_member(
        &self,
        state: EngineState,
        rng: &dyn Rng,
        ids: ConversationRef,
        contact_conversation_id: ConversationId,
    ) -> Result<MutateOk, EngineError> {
        self.gate_chat(&state, &ids)?;
        let (policy, _, sign_pk, _, _) =
            self.identity_secret(&state, &ids.user_id, &ids.identity_id)?;
        let peer =
            dm_peer(&state, contact_conversation_id, &sign_pk).ok_or(EngineError::WrongPhase)?;
        let live = match group_phase(&state, ids.conversation_id) {
            Some(GroupPhase::Live(live)) if live.owner_signing_pk == sign_pk => live.clone(),
            Some(GroupPhase::Live(_)) => return Err(EngineError::NotOwner),
            _ => return Err(EngineError::WrongPhase),
        };
        if live.members.len() + live.pending.len() >= 32 {
            return Err(EngineError::MemberCap);
        }
        if live.pending.iter().any(|p| p.signing_pk == peer.0)
            || live.members.iter().any(|m| m.signing_pk == peer.0)
        {
            return Err(EngineError::WrongPhase);
        }
        #[rustfmt::skip]
        let group_secret_ct = seal_group_secret(self, rng, policy, &peer.1, live.secret.as_bytes())?;
        let payload = TxPayload::GroupInvite(TxGroupInvite {
            group_id: ids.conversation_id,
            owner_signing_pk: sign_pk,
            persistents: live.persistents.clone(),
            ephemerals: live.ephemerals.clone(),
            name: live.name.clone(),
            photo: live.photo.clone(),
            invitee_signing_pk: peer.0.clone(),
            group_secret_ct,
        });
        #[rustfmt::skip]
        let mut ok = self.mint_on(state, rng, &ConversationRef { conversation_id: contact_conversation_id, ..ids }, payload)?;
        if let Some(GroupPhase::Live(row)) = group_phase_mut(&mut ok.state, ids.conversation_id) {
            row.pending.push(GroupPending {
                signing_pk: peer.0,
                encryption_pk: peer.1,
                from_conversation_id: contact_conversation_id,
                name: row.name.clone(),
                photo: row.photo.clone(),
            });
        }
        Ok(ok)
    }

    /// Accept a group offer.
    pub fn accept_group(
        &self,
        state: EngineState,
        rng: &dyn Rng,
        ids: ConversationRef,
    ) -> Result<MutateOk, EngineError> {
        let offer = match group_phase(&state, ids.conversation_id) {
            Some(GroupPhase::Offer(offer)) => offer.clone(),
            _ => return Err(EngineError::WrongPhase),
        };
        let (_, enc_pk, sign_pk, _, _) =
            self.identity_secret(&state, &ids.user_id, &ids.identity_id)?;
        let payload = TxPayload::GroupAccept {
            group_id: ids.conversation_id,
        };
        #[rustfmt::skip]
        let mut ok = self.mint_on(state, rng, &ConversationRef { conversation_id: offer.from_conversation_id, ..ids }, payload)?;
        let member = GroupMember {
            signing_pk: sign_pk.clone(),
            encryption_pk: enc_pk,
            send_tag_key: TagKey::from(rng.random32()),
            eph_send_tag_key: TagKey::from(rng.random32()),
        };
        if let Some(phase) = group_phase_mut(&mut ok.state, ids.conversation_id) {
            *phase = GroupPhase::Live(GroupLive {
                secret: offer.secret,
                name: offer.name,
                photo: offer.photo,
                owner_signing_pk: offer.owner_signing_pk,
                persistents: self.defaults.persistents().to_vec(),
                ephemerals: self.defaults.ephemerals().to_vec(),
                members: vec![member],
                pending: Vec::new(),
                epoch: 0,
            });
        }
        let _ = sign_pk;
        Ok(ok)
    }

    /// Reject a group offer.
    pub fn reject_group(
        &self,
        state: EngineState,
        rng: &dyn Rng,
        ids: ConversationRef,
    ) -> Result<MutateOk, EngineError> {
        let offer = match group_phase(&state, ids.conversation_id) {
            Some(GroupPhase::Offer(offer)) => offer.clone(),
            _ => return Err(EngineError::WrongPhase),
        };
        let payload = TxPayload::GroupReject {
            group_id: ids.conversation_id,
        };
        #[rustfmt::skip]
        let mut ok = self.mint_on(state, rng, &ConversationRef { conversation_id: offer.from_conversation_id, ..ids }, payload)?;
        if let Some(phase) = group_phase_mut(&mut ok.state, ids.conversation_id) {
            *phase = GroupPhase::Failed(super::query::FailedReason::OfferRejected);
        }
        Ok(ok)
    }

    /// Kick a group member, or drop a group offer.
    pub fn kick_group_member(
        &self,
        mut state: EngineState,
        rng: &dyn Rng,
        ids: ConversationRef,
        signing_pk: &[u8],
    ) -> Result<MutateOk, EngineError> {
        match group_phase(&state, ids.conversation_id) {
            Some(GroupPhase::Offer(_)) => {
                let _ = state.drop_conversation(ids.conversation_id);
                return Ok(MutateOk {
                    state,
                    persist: Vec::new(),
                    pings: Vec::new(),
                });
            }
            Some(GroupPhase::Live(_)) => {}
            _ => return Err(EngineError::WrongPhase),
        }
        let (_, _, sign_pk, _, _) = self.identity_secret(&state, &ids.user_id, &ids.identity_id)?;
        let owner = group_live(&state, ids.conversation_id)
            .is_some_and(|live| live.owner_signing_pk == sign_pk);
        if !owner {
            return Err(EngineError::NotOwner);
        }
        if group_live(&state, ids.conversation_id)
            .is_some_and(|live| live.pending.iter().any(|p| p.signing_pk == signing_pk))
        {
            return Err(EngineError::WrongPhase);
        }
        let payload = TxPayload::GroupKick {
            signing_pk: signing_pk.to_vec(),
        };
        let mut ok = self.mint_on(state, rng, &ids, payload)?;
        let live = live_mut(&mut ok.state, ids.conversation_id).expect("live");
        live.members.retain(|m| m.signing_pk != signing_pk);
        live.epoch = live.epoch.saturating_add(1);
        self.post_roster(&mut ok.state, rng, ids)?;
        Ok(ok)
    }

    /// Leave a group.
    pub fn leave_group(
        &self,
        state: EngineState,
        rng: &dyn Rng,
        ids: ConversationRef,
    ) -> Result<MutateOk, EngineError> {
        if !matches!(
            group_phase(&state, ids.conversation_id),
            Some(GroupPhase::Live(_))
        ) {
            return Err(EngineError::WrongPhase);
        }
        let mut ok = self.mint_on(state, rng, &ids, TxPayload::GroupLeave)?;
        if let Some(phase) = group_phase_mut(&mut ok.state, ids.conversation_id) {
            *phase = GroupPhase::Failed(super::query::FailedReason::Left);
        }
        Ok(ok)
    }

    pub(super) fn rename_group(
        &self,
        mut state: EngineState,
        rng: &dyn Rng,
        ids: ConversationRef,
        name: DisplayName,
    ) -> Result<MutateOk, EngineError> {
        self.require_owner(&state, &ids)?;
        if let Some(GroupPhase::Live(live)) = group_phase_mut(&mut state, ids.conversation_id) {
            live.name = name.clone();
        }
        let payload = TxPayload::Name { name };
        let secret = self.conv_secret(&state, &ids.conversation_id)?;
        let ok = self.mint_on(state, rng, &ids, payload.clone())?;
        self.finish_chat(ok, ids.conversation_id, &secret, &payload)
    }

    pub(super) fn rephoto_group(
        &self,
        mut state: EngineState,
        rng: &dyn Rng,
        ids: ConversationRef,
        photo: Option<ProfilePic>,
    ) -> Result<MutateOk, EngineError> {
        self.require_owner(&state, &ids)?;
        if let Some(GroupPhase::Live(live)) = group_phase_mut(&mut state, ids.conversation_id) {
            live.photo = photo.clone();
        }
        let payload = TxPayload::Photo { profile_pic: photo };
        let secret = self.conv_secret(&state, &ids.conversation_id)?;
        let ok = self.mint_on(state, rng, &ids, payload.clone())?;
        self.finish_chat(ok, ids.conversation_id, &secret, &payload)
    }

    pub(super) fn delete_group(
        &self,
        state: EngineState,
        ids: &ConversationRef,
    ) -> Option<MutateOk> {
        if !matches!(
            group_phase(&state, ids.conversation_id),
            Some(GroupPhase::Live(_))
        ) {
            return None;
        }
        let secret = self.conv_secret(&state, &ids.conversation_id).ok()?;
        let mut ok = self
            .mutate_on(
                state,
                &secret,
                ids.conversation_id,
                vec![TxPayload::GroupLeave],
            )
            .ok()?;
        if let Some(phase) = group_phase_mut(&mut ok.state, ids.conversation_id) {
            *phase = GroupPhase::Failed(super::query::FailedReason::Left);
        }
        Some(ok)
    }

    pub(super) fn on_group_payload(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        cid: ConversationId,
        payload: &TxPayload,
    ) -> Result<(), EngineError> {
        match payload {
            TxPayload::GroupInvite(invite) => self.note_invite(state, invite),
            TxPayload::GroupAccept { group_id } => self.note_accept(state, rng, *group_id),
            TxPayload::GroupRoster(roster) => self.note_roster(state, cid, roster),
            _ => Ok(()),
        }
    }

    pub(super) fn group_view(
        &self,
        state: &EngineState,
        cid: ConversationId,
    ) -> Option<Conversation> {
        let phase = group_phase(state, cid)?;
        Some(Conversation::Group(match phase {
            GroupPhase::Offer(offer) => GroupQuery::GroupOffer(GroupOfferView {
                name: offer.name.clone(),
                photo: offer.photo.clone(),
                owner_signing_pk: offer.owner_signing_pk.clone(),
                from_conversation_id: offer.from_conversation_id,
            }),
            GroupPhase::Live(live) => GroupQuery::GroupEstablished(GroupEstablishedView {
                name: live.name.clone(),
                photo: live.photo.clone(),
                owner_signing_pk: live.owner_signing_pk.clone(),
                members: live
                    .members
                    .iter()
                    .map(|m| GroupMemberView {
                        signing_pk: m.signing_pk.clone(),
                        encryption_pk: m.encryption_pk.clone(),
                        name: live.name.clone(),
                        photo: live.photo.clone(),
                        typing: None,
                        presence: None,
                    })
                    .collect(),
                pending: live
                    .pending
                    .iter()
                    .map(|p| GroupPendingView {
                        signing_pk: p.signing_pk.clone(),
                        from_conversation_id: p.from_conversation_id,
                        name: p.name.clone(),
                        photo: p.photo.clone(),
                    })
                    .collect(),
                persistents: live.persistents.clone(),
                ephemerals: live.ephemerals.clone(),
                last_active: state.chains(cid).and_then(|chains| chains.presence_at),
                local_prefs: super::chat::local_prefs(self, state, cid),
                messages: self.dm_view(state, cid).messages,
            }),
            GroupPhase::Failed(reason) => GroupQuery::GroupFailed(*reason),
        }))
    }

    pub(super) fn group_disappear_blocked(
        &self,
        state: &EngineState,
        ids: &ConversationRef,
        disappear_after: Option<u64>,
    ) -> Result<(), EngineError> {
        if disappear_after.is_none() {
            return Ok(());
        }
        let Some(live) = group_live(state, ids.conversation_id) else {
            return Ok(());
        };
        let (_, _, sign_pk, _, _) = self.identity_secret(state, &ids.user_id, &ids.identity_id)?;
        if live.owner_signing_pk == sign_pk {
            Ok(())
        } else {
            Err(EngineError::NotOwner)
        }
    }

    fn require_owner(&self, state: &EngineState, ids: &ConversationRef) -> Result<(), EngineError> {
        let Some(live) = group_live(state, ids.conversation_id) else {
            return Err(EngineError::WrongPhase);
        };
        let (_, _, sign_pk, _, _) = self.identity_secret(state, &ids.user_id, &ids.identity_id)?;
        if live.owner_signing_pk == sign_pk {
            Ok(())
        } else {
            Err(EngineError::NotOwner)
        }
    }

    fn note_invite(
        &self,
        state: &mut EngineState,
        invite: &TxGroupInvite,
    ) -> Result<(), EngineError> {
        let Some((user, identity)) = self.identity_for_signing(state, &invite.invitee_signing_pk)
        else {
            return Ok(());
        };
        if group_phase(state, invite.group_id).is_some() {
            return Ok(());
        }
        let (_, _, _, enc_sk, _) = self.identity_secret(state, &user, &identity)?;
        let policy = self.identity_policy(state, &user, &identity)?;
        let secret = open_group_secret(self, policy, &enc_sk, &invite.group_secret_ct)?;
        state.put_dm(
            user,
            identity,
            invite.group_id,
            IdentityNode {
                kind: IdentityConversation::Group(GroupPhase::Offer(GroupOffer {
                    secret: Secret::from_bytes(secret),
                    name: invite.name.clone(),
                    photo: invite.photo.clone(),
                    owner_signing_pk: invite.owner_signing_pk.clone(),
                    from_conversation_id: self
                        .dm_with_peer(state, user, identity, &invite.owner_signing_pk)
                        .unwrap_or(invite.group_id),
                })),
                chains: Default::default(),
            },
        );
        Ok(())
    }

    fn note_accept(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        group_id: ConversationId,
    ) -> Result<(), EngineError> {
        let Some(live) = group_live(state, group_id) else {
            return Ok(());
        };
        if live.pending.is_empty() {
            return Ok(());
        }
        let pending = live.pending[0].clone();
        let member = GroupMember {
            signing_pk: pending.signing_pk.clone(),
            encryption_pk: pending.encryption_pk.clone(),
            send_tag_key: TagKey::from(rng.random32()),
            eph_send_tag_key: TagKey::from(rng.random32()),
        };
        let live = live_mut(state, group_id).expect("live");
        live.pending.retain(|p| p.signing_pk != pending.signing_pk);
        live.members.push(member);
        live.epoch = live.epoch.saturating_add(1);
        let (user, identity) = self.owner_ids(state, group_id).expect("owner");
        self.post_roster(
            state,
            rng,
            ConversationRef {
                user_id: user,
                identity_id: identity,
                conversation_id: group_id,
            },
        )
    }

    fn note_roster(
        &self,
        state: &mut EngineState,
        cid: ConversationId,
        roster: &TxGroupRoster,
    ) -> Result<(), EngineError> {
        let Some((user, identity)) = self.owner_ids(state, cid) else {
            return Ok(());
        };
        let (owner_signing_pk, secret, name, photo) = match group_phase(state, cid) {
            Some(GroupPhase::Live(live)) => (
                live.owner_signing_pk.clone(),
                live.secret,
                live.name.clone(),
                live.photo.clone(),
            ),
            Some(GroupPhase::Offer(offer)) => (
                offer.owner_signing_pk.clone(),
                offer.secret,
                offer.name.clone(),
                offer.photo.clone(),
            ),
            _ => return Ok(()),
        };
        self.verify_roster(&owner_signing_pk, roster)?;
        let (_, _, sign_pk, _, _) = self.identity_secret(state, &user, &identity)?;
        if !roster.members.iter().any(|m| m.signing_pk == sign_pk) {
            if let Some(phase) = group_phase_mut(state, cid) {
                *phase = GroupPhase::Failed(super::query::FailedReason::Kicked);
            }
            return Ok(());
        }
        if let Some(phase) = group_phase_mut(state, cid) {
            *phase = GroupPhase::Live(GroupLive {
                secret,
                name,
                photo,
                owner_signing_pk,
                persistents: self.defaults.persistents().to_vec(),
                ephemerals: self.defaults.ephemerals().to_vec(),
                members: roster.members.clone(),
                pending: Vec::new(),
                epoch: roster.epoch,
            });
        }
        Ok(())
    }

    pub(super) fn post_roster(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        ids: ConversationRef,
    ) -> Result<(), EngineError> {
        let Some(live) = group_live(state, ids.conversation_id) else {
            return Ok(());
        };
        let members = live.members.clone();
        let epoch = live.epoch;
        let secret = live.secret;
        let owner_pk = live.owner_signing_pk.clone();
        let (policy, _, _, _, sign_sk) =
            self.identity_secret(state, &ids.user_id, &ids.identity_id)?;
        let mut roster = TxGroupRoster {
            epoch,
            members: members.clone(),
            sig: vec![0; sign_sig_len(policy)],
        };
        let bytes = self.roster_bytes(&roster)?;
        roster.sig = self
            .suite
            .sign()
            .sign(policy, &sign_sk, &bytes, &rng.random32())
            .map_err(|_| EngineError::MalformedPayload)?;
        #[rustfmt::skip]
        let (tx_id, body, _) = self.merge_tx(state, &secret, ids.conversation_id, TxPayload::GroupRoster(roster))?;
        #[rustfmt::skip]
        self.post_live(state, rng, ids.conversation_id, &secret, tx_id, &body.payload)?;
        for member in members.into_iter().filter(|m| m.signing_pk != owner_pk) {
            #[rustfmt::skip]
            let kem_ct = seal_group_secret(self, rng, policy, &member.encryption_pk, secret.as_bytes())?;
            #[rustfmt::skip]
            let (tx_id, body, _) = self.merge_tx(state, &secret, ids.conversation_id, TxPayload::GroupWrap(TxGroupWrap { to: member.signing_pk, from: owner_pk.clone(), kem_ct }))?;
            #[rustfmt::skip]
            self.post_live(state, rng, ids.conversation_id, &secret, tx_id, &body.payload)?;
        }
        Ok(())
    }

    fn roster_bytes(&self, roster: &TxGroupRoster) -> Result<Vec<u8>, EngineError> {
        let json = payload_to_json(self.suite.b64u(), &TxPayload::GroupRoster(roster.clone()));
        Ok(self.suite.canonical_json().encode(&json))
    }

    fn verify_roster(&self, owner_pk: &[u8], roster: &TxGroupRoster) -> Result<(), EngineError> {
        for policy in [Policy::Classic, Policy::PostQuantum, Policy::Hybrid] {
            let mut body = roster.clone();
            body.sig = vec![0; sign_sig_len(policy)];
            let bytes = self.roster_bytes(&body)?;
            if self
                .suite
                .sign()
                .verify(policy, owner_pk, &bytes, &roster.sig)
                .is_ok()
            {
                return Ok(());
            }
        }
        Err(EngineError::MalformedPayload)
    }

    fn identity_secret(
        &self,
        state: &EngineState,
        user_id: &UserId,
        identity_id: &IdentityId,
    ) -> Result<IdentityKeys, EngineError> {
        state
            .txs
            .values()
            .find_map(|tx| match &tx.payload {
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
                    encryption.secret_bytes().to_vec(),
                    signing.secret_bytes().to_vec(),
                )),
                _ => None,
            })
            .ok_or(EngineError::UnknownIds)
    }

    fn identity_for_signing(
        &self,
        state: &EngineState,
        signing_pk: &[u8],
    ) -> Option<(UserId, IdentityId)> {
        state.txs.values().find_map(|tx| match &tx.payload {
            TxPayload::EngineCreateIdentity {
                user_id,
                identity_id,
                signing,
                ..
            } if signing.public_bytes() == signing_pk => Some((*user_id, *identity_id)),
            _ => None,
        })
    }

    fn dm_with_peer(
        &self,
        state: &EngineState,
        user: UserId,
        identity: IdentityId,
        peer_signing: &[u8],
    ) -> Option<ConversationId> {
        let (_, _, local, _, _) = self.identity_secret(state, &user, &identity).ok()?;
        state
            .identity(user, identity)?
            .conversations
            .iter()
            .find_map(|(cid, node)| {
                if matches!(node.kind, IdentityConversation::DirectMessage { .. })
                    && dm_peer(state, *cid, &local).is_some_and(|(pk, _)| pk == peer_signing)
                {
                    Some(*cid)
                } else {
                    None
                }
            })
    }

    fn owner_ids(&self, state: &EngineState, cid: ConversationId) -> Option<(UserId, IdentityId)> {
        state.owner(cid)
    }
}

fn group_phase(state: &EngineState, cid: ConversationId) -> Option<&GroupPhase> {
    for user in state.users.values() {
        for ident in user.identities.values() {
            if let Some(IdentityConversation::Group(phase)) =
                ident.conversations.get(&cid).map(|n| &n.kind)
            {
                return Some(phase);
            }
        }
    }
    None
}

pub(super) fn live_mut(state: &mut EngineState, cid: ConversationId) -> Option<&mut GroupLive> {
    match group_phase_mut(state, cid) {
        Some(GroupPhase::Live(live)) => Some(live),
        _ => None,
    }
}

#[cfg(test)]
pub(super) fn roster_body(payload: &TxPayload) -> Option<TxGroupRoster> {
    match payload {
        TxPayload::GroupRoster(body) => Some(body.clone()),
        _ => None,
    }
}

pub(super) fn group_phase_mut(
    state: &mut EngineState,
    cid: ConversationId,
) -> Option<&mut GroupPhase> {
    for user in state.users.values_mut() {
        for ident in user.identities.values_mut() {
            if let Some(node) = ident.conversations.get_mut(&cid)
                && let IdentityConversation::Group(phase) = &mut node.kind
            {
                return Some(phase);
            }
        }
    }
    None
}

pub(super) fn group_live(state: &EngineState, cid: ConversationId) -> Option<&GroupLive> {
    match group_phase(state, cid) {
        Some(GroupPhase::Live(live)) => Some(live),
        _ => None,
    }
}

pub(super) fn dm_peer(
    state: &EngineState,
    dm: ConversationId,
    local_sign: &[u8],
) -> Option<(Vec<u8>, Vec<u8>)> {
    let parent = state.established_parent(dm)?;
    let inviter = inviter_intro_for(state, parent)?;
    let invitee = invitee_intro_for(state, parent)?;
    if inviter.signing_pk == local_sign {
        Some((invitee.signing_pk.clone(), invitee.encryption_pk.clone()))
    } else if invitee.signing_pk == local_sign {
        Some((inviter.signing_pk.clone(), inviter.encryption_pk.clone()))
    } else {
        None
    }
}

fn seal_group_secret(
    engine: &Engine,
    rng: &dyn Rng,
    policy: Policy,
    pk: &[u8],
    group_secret: &[u8],
) -> Result<Vec<u8>, EngineError> {
    let seed = KemSeed::from_pair(rng.random32(), rng.random32());
    let (shared, ct) = engine
        .suite
        .kem()
        .wrap(policy, pk, &seed)
        .map_err(|_| EngineError::MalformedPayload)?;
    let key = expand(
        engine.suite.hmac(),
        &HmacSha256Key::from_bytes(shared32(&shared)),
        GROUP_SECRET_INFO,
    )
    .into_bytes();
    let rnd = rng.random32();
    let mut nonce = [0u8; PACKET_NONCE_LEN];
    nonce.copy_from_slice(&rnd.as_bytes()[..PACKET_NONCE_LEN]);
    let sealed = engine.suite.aead().seal(
        &AeadKey::from_bytes(key),
        &AeadNonce::from_bytes(nonce),
        b"",
        group_secret,
    );
    let mut out = ct;
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

fn open_group_secret(
    engine: &Engine,
    policy: Policy,
    sk: &[u8],
    packed: &[u8],
) -> Result<[u8; 32], EngineError> {
    let ct_len = super::super::kem::kem_ct_len(policy);
    if packed.len() <= ct_len + PACKET_NONCE_LEN {
        return Err(EngineError::MalformedPayload);
    }
    let (ct, rest) = packed.split_at(ct_len);
    let shared = engine
        .suite
        .kem()
        .unwrap(policy, sk, ct)
        .map_err(|_| EngineError::MalformedPayload)?;
    let key = expand(
        engine.suite.hmac(),
        &HmacSha256Key::from_bytes(shared32(&shared)),
        GROUP_SECRET_INFO,
    )
    .into_bytes();
    let (nonce_bytes, aead_ct) = rest.split_at(PACKET_NONCE_LEN);
    let mut nonce = [0u8; PACKET_NONCE_LEN];
    nonce.copy_from_slice(nonce_bytes);
    let plain = engine
        .suite
        .aead()
        .open(
            &AeadKey::from_bytes(key),
            &AeadNonce::from_bytes(nonce),
            b"",
            aead_ct,
        )
        .map_err(|_| EngineError::MalformedPayload)?;
    plain.try_into().map_err(|_| EngineError::MalformedPayload)
}

fn shared32(shared: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let n = shared.len().min(32);
    out[..n].copy_from_slice(&shared[..n]);
    out
}

pub(super) fn group_json(
    b64u: &dyn super::super::Base64Url,
    phase: &GroupPhase,
) -> super::super::Json {
    use super::super::Json;
    let bstr = |bytes: &[u8]| Json::String(b64u.encode(bytes));
    match phase {
        GroupPhase::Failed(reason) => {
            Json::Object(vec![("failed".into(), Json::String(format!("{reason:?}")))])
        }
        GroupPhase::Offer(offer) => Json::Object(vec![
            ("offer".into(), Json::Bool(true)),
            ("secret".into(), bstr(offer.secret.as_bytes())),
            ("name".into(), Json::String(offer.name.as_str().into())),
            ("owner".into(), bstr(&offer.owner_signing_pk)),
            ("from".into(), bstr(offer.from_conversation_id.as_bytes())),
        ]),
        GroupPhase::Live(live) => Json::Object(vec![
            ("secret".into(), bstr(live.secret.as_bytes())),
            ("name".into(), Json::String(live.name.as_str().into())),
            ("owner".into(), bstr(&live.owner_signing_pk)),
            ("epoch".into(), Json::Number(live.epoch)),
        ]),
    }
}

pub(super) fn parse_group(
    b64u: &dyn super::super::Base64Url,
    value: &super::super::Json,
) -> Result<GroupPhase, EngineError> {
    use super::super::Json;
    let Json::Object(m) = value else {
        return Err(EngineError::MalformedPersist);
    };
    let field = |name: &str| {
        m.iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v)
            .ok_or(EngineError::MalformedPersist)
    };
    if m.iter().any(|(k, _)| k == "failed") {
        return Ok(GroupPhase::Failed(super::query::FailedReason::Left));
    }
    let secret = Secret::from_bytes(decode32(b64u, field("secret")?)?);
    let name = match field("name")? {
        Json::String(s) => {
            DisplayName::try_from(s.as_str()).map_err(|_| EngineError::MalformedPersist)?
        }
        _ => return Err(EngineError::MalformedPersist),
    };
    let owner = decode_vec(b64u, field("owner")?)?;
    if m.iter().any(|(k, _)| k == "offer") {
        let from = ConversationId::from_bytes(decode32(b64u, field("from")?)?);
        return Ok(GroupPhase::Offer(GroupOffer {
            secret,
            name,
            photo: None,
            owner_signing_pk: owner,
            from_conversation_id: from,
        }));
    }
    let epoch = match field("epoch")? {
        Json::Number(n) => *n,
        _ => return Err(EngineError::MalformedPersist),
    };
    Ok(GroupPhase::Live(GroupLive {
        secret,
        name,
        photo: None,
        owner_signing_pk: owner,
        persistents: Vec::new(),
        ephemerals: Vec::new(),
        members: Vec::new(),
        pending: Vec::new(),
        epoch,
    }))
}

fn decode32(
    b64u: &dyn super::super::Base64Url,
    value: &super::super::Json,
) -> Result<[u8; 32], EngineError> {
    let super::super::Json::String(s) = value else {
        return Err(EngineError::MalformedPersist);
    };
    let bytes = b64u.decode(s).map_err(|_| EngineError::MalformedPersist)?;
    bytes.try_into().map_err(|_| EngineError::MalformedPersist)
}

fn decode_vec(
    b64u: &dyn super::super::Base64Url,
    value: &super::super::Json,
) -> Result<Vec<u8>, EngineError> {
    let super::super::Json::String(s) = value else {
        return Err(EngineError::MalformedPersist);
    };
    b64u.decode(s).map_err(|_| EngineError::MalformedPersist)
}

#[cfg(test)]
mod tests {
    use super::super::super::Json;
    use super::parse_group;
    use crate::protocol::v1::fixtures::test_engine;

    #[test]
    fn group_fold_rejects_bad_shapes() {
        let engine = test_engine();
        let b64 = engine.suite.b64u();
        assert!(parse_group(b64, &Json::Null).is_err());
        assert!(
            parse_group(
                b64,
                &Json::Object(vec![("failed".into(), Json::Bool(true))])
            )
            .is_ok()
        );
        assert!(
            parse_group(
                b64,
                &Json::Object(vec![
                    ("secret".into(), Json::String(b64.encode(&[1; 32]))),
                    ("name".into(), Json::Number(1)),
                    ("owner".into(), Json::String(b64.encode(&[2; 32]))),
                ])
            )
            .is_err()
        );
        assert!(
            parse_group(
                b64,
                &Json::Object(vec![
                    ("offer".into(), Json::Bool(true)),
                    ("secret".into(), Json::String(b64.encode(&[1; 32]))),
                    ("name".into(), Json::String("G".into())),
                    ("owner".into(), Json::String(b64.encode(&[2; 32]))),
                    ("from".into(), Json::String(b64.encode(&[3; 32]))),
                ])
            )
            .is_ok()
        );
        assert!(
            parse_group(
                b64,
                &Json::Object(vec![
                    ("secret".into(), Json::String(b64.encode(&[1; 32]))),
                    ("name".into(), Json::String("G".into())),
                    ("owner".into(), Json::String(b64.encode(&[2; 32]))),
                    ("epoch".into(), Json::String("no".into())),
                ])
            )
            .is_err()
        );
        assert!(parse_group(b64, &Json::Object(vec![("secret".into(), Json::Null)])).is_err());
        assert!(
            parse_group(
                b64,
                &Json::Object(vec![
                    ("secret".into(), Json::String(b64.encode(&[1; 32]))),
                    ("name".into(), Json::String("G".into())),
                    ("owner".into(), Json::Null),
                ])
            )
            .is_err()
        );
    }
}
