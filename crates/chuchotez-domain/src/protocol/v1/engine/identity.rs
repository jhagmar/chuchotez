//! Users, identities, names, and this device.

use super::super::hmac::{HmacSha256Key, expand};
use super::super::payload::{PACKET_NONCE_LEN, TxPayload};
use super::super::{
    AeadKey, AeadNonce, ConversationId, Defaults, DeviceId, DisplayName, EngineError, IdentityId,
    KemSeed, OnWirePrefs, Policy, Secret, SignSeed, UserId,
};
use super::helpers::{invitee_intro_for, notice_for};
use super::party::DeviceConversation;
use super::query::*;
use super::{Engine, EngineState};
use crate::protocol::Rng;
impl Engine {
    /// Constructor or last `TxEngineSetDefaults`.
    pub fn get_defaults(&self, _state: &EngineState) -> Result<Defaults, EngineError> {
        Ok(self.defaults.clone())
    }

    /// Mint `TxEngineSetDefaults`.
    pub fn set_defaults(
        &self,
        state: EngineState,
        defaults: Defaults,
    ) -> Result<MutateOk, EngineError> {
        let secret = self.engine_secret()?;
        let mut payloads = Vec::new();
        payloads.extend(
            (!state
                .bodies()
                .iter()
                .any(|t| matches!(t.payload, TxPayload::EngineInit)))
            .then_some(TxPayload::EngineInit),
        );
        payloads.push(TxPayload::EngineSetDefaults { defaults });
        self.mutate(state, None, &secret, payloads)
    }

    /// Mint a user.
    pub fn create_user(
        &self,
        state: EngineState,
        rng: &dyn Rng,
    ) -> Result<(MutateOk, UserId), EngineError> {
        let secret = self.engine_secret()?;
        let user_id = UserId::from(rng.random32());
        let mut payloads = Vec::new();
        if !state
            .bodies()
            .iter()
            .any(|t| matches!(t.payload, TxPayload::EngineInit))
        {
            payloads.push(TxPayload::EngineInit);
        }
        payloads.push(TxPayload::EngineCreateUser { user_id });
        let mut ok = self.mutate(state, Some(rng), &secret, payloads)?;
        ok.state.ensure_user(user_id);
        Ok((ok, user_id))
    }

    /// Mint an identity.
    pub fn create_identity(
        &self,
        state: EngineState,
        rng: &dyn Rng,
        user_id: UserId,
        policy: Policy,
    ) -> Result<(MutateOk, IdentityId), EngineError> {
        let secret = self.engine_secret()?;
        if !state.bodies().iter().any(
            |t| matches!(&t.payload, TxPayload::EngineCreateUser { user_id: u } if u == &user_id),
        ) {
            return Err(EngineError::UnknownIds);
        }
        let identity_id = IdentityId::from(rng.random32());
        let encryption = self
            .suite
            .kem()
            .generate(policy, &KemSeed::from_pair(rng.random32(), rng.random32()))
            .map_err(|_| EngineError::MalformedPayload)?;
        let signing = self
            .suite
            .sign()
            .generate(policy, &SignSeed::from_pair(rng.random32(), rng.random32()))
            .map_err(|_| EngineError::MalformedPayload)?;
        let mut ok = self.mutate(
            state,
            Some(rng),
            &secret,
            vec![TxPayload::EngineCreateIdentity {
                user_id,
                identity_id,
                policy,
                encryption,
                signing,
            }],
        )?;
        ok.state.ensure_identity(user_id, identity_id);
        Ok((ok, identity_id))
    }

    /// Delete a user.
    pub fn delete_user(
        &self,
        state: EngineState,
        user_id: UserId,
    ) -> Result<MutateOk, EngineError> {
        let secret = self.engine_secret()?;
        self.mutate(
            state,
            None,
            &secret,
            vec![TxPayload::EngineDeleteUser { user_id }],
        )
        .map(|mut ok| {
            ok.state.users.remove(&user_id);
            ok
        })
    }

    /// Delete an identity.
    pub fn delete_identity(
        &self,
        state: EngineState,
        user_id: UserId,
        identity_id: IdentityId,
    ) -> Result<MutateOk, EngineError> {
        let secret = self.engine_secret()?;
        self.mutate(
            state,
            None,
            &secret,
            vec![TxPayload::EngineDeleteIdentity {
                user_id,
                identity_id,
            }],
        )
        .map(|mut ok| {
            if let Some(user) = ok.state.users.get_mut(&user_id) {
                user.identities.remove(&identity_id);
            }
            ok
        })
    }

    /// Set a display name.
    pub fn set_display_name(
        &self,
        state: EngineState,
        rng: &dyn Rng,
        user_id: UserId,
        identity_id: IdentityId,
        name: &str,
    ) -> Result<MutateOk, EngineError> {
        let name = DisplayName::try_from(name).map_err(|_| EngineError::MalformedDisplayName)?;
        let secret = self.engine_secret()?;
        let mut ok = self.mutate(
            state,
            Some(rng),
            &secret,
            vec![TxPayload::EngineSetDisplayName {
                user_id,
                identity_id,
                name: name.clone(),
            }],
        )?;
        ok.state.ensure_identity(user_id, identity_id).name = Some(name);
        let extra = self.mint_pending_intros(&mut ok.state, rng)?;
        ok.persist.extend(extra);
        Ok(ok)
    }

    /// Clear a display name.
    pub fn unset_display_name(
        &self,
        state: EngineState,
        user_id: UserId,
        identity_id: IdentityId,
    ) -> Result<MutateOk, EngineError> {
        let secret = self.engine_secret()?;
        let mut ok = self.mutate(
            state,
            None,
            &secret,
            vec![TxPayload::EngineUnsetDisplayName {
                user_id,
                identity_id,
            }],
        )?;
        if let Some(ident) = ok.state.identity_mut(user_id, identity_id) {
            ident.name = None;
        }
        Ok(ok)
    }

    /// Create a DM invite. Posts sealed `PacketTxFragLast` (and `More`) of the
    /// Set this device name.
    pub fn set_device_name(
        &self,
        mut state: EngineState,
        rng: &dyn Rng,
        name: &str,
    ) -> Result<MutateOk, EngineError> {
        let name = DisplayName::try_from(name).map_err(|_| EngineError::MalformedDisplayName)?;
        let secret = self.engine_secret()?;
        let ok = self.mutate(
            state.clone(),
            Some(rng),
            &secret,
            vec![TxPayload::EngineSetDeviceName { name: name.clone() }],
        );
        match ok {
            Ok(mut m) => {
                m.state.device.name = Some(name);
                let extra = self.mint_pending_intros(&mut m.state, rng)?;
                m.persist.extend(extra);
                Ok(m)
            }
            Err(EngineError::NotTicked) => {
                state.device.name = Some(name);
                Ok(MutateOk {
                    state,
                    persist: Vec::new(),
                    pings: Vec::new(),
                })
            }
            Err(e) => Err(e),
        }
    }

    /// Kick a linked device. An id that is not a peer is `UnknownIds`.
    pub fn kick_device(
        &self,
        state: EngineState,
        _rng: &dyn Rng,
        device_id: DeviceId,
    ) -> Result<MutateOk, EngineError> {
        if state.device.keys.as_ref().and_then(|k| k.id) == Some(device_id) {
            return Err(EngineError::WrongPhase);
        }
        let known = state.device.conversations.values().any(|node| {
            matches!(
                &node.kind,
                DeviceConversation::Synchronization { peer, .. } if *peer == device_id
            )
        });
        if !known {
            return Err(EngineError::UnknownIds);
        }
        let secret = self.engine_secret()?;
        #[rustfmt::skip]
        let mut ok = self.mutate(state, Some(_rng), &secret, vec![TxPayload::EngineKickDevice { device_id }])?;
        #[rustfmt::skip]
        self.note_device_kick(&mut ok.state, device_id)?;
        Ok(ok)
    }

    /// Unlink this device from Sync.
    pub fn leave_sync(
        &self,
        mut state: EngineState,
        _rng: &dyn Rng,
    ) -> Result<MutateOk, EngineError> {
        state.device.conversations.clear();
        state.device.dek_ct = None;
        Ok(MutateOk {
            state,
            persist: Vec::new(),
            pings: Vec::new(),
        })
    }

    /// Set a profile picture.
    pub fn set_profile_pic(
        &self,
        state: EngineState,
        _rng: &dyn Rng,
        user_id: UserId,
        identity_id: IdentityId,
        profile_pic: Option<&[u8]>,
    ) -> Result<MutateOk, EngineError> {
        let pic = match profile_pic {
            None => None,
            Some(b) => Some(
                super::super::ProfilePic::try_from(b).map_err(|_| EngineError::MalformedPayload)?,
            ),
        };
        let secret = self.engine_secret()?;
        let mut ok = self.mutate(
            state,
            Some(_rng),
            &secret,
            vec![TxPayload::EngineSetProfilePic {
                user_id,
                identity_id,
                profile_pic: pic.clone(),
            }],
        )?;
        ok.state.ensure_identity(user_id, identity_id).pic = pic;
        Ok(ok)
    }

    pub(super) fn fan_engine_to_sync(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        payloads: &[TxPayload],
    ) -> Result<(), EngineError> {
        let engine_secret = self.engine_secret()?;
        let syncs: Vec<_> = state
            .device
            .conversations
            .iter()
            .filter_map(|(cid, node)| {
                matches!(node.kind, DeviceConversation::Synchronization { .. }).then_some(*cid)
            })
            .collect();
        if syncs.is_empty() {
            return Ok(());
        }
        for payload in payloads {
            let tx_id = self.tx_id(&engine_secret, payload);
            for cid in &syncs {
                let secret = state.established_secret(*cid).expect("sync");
                #[rustfmt::skip]
                self.post_live(state, rng, *cid, &secret, tx_id, payload)?;
            }
        }
        Ok(())
    }

    pub(super) fn note_device_kick(
        &self,
        state: &mut EngineState,
        device_id: DeviceId,
    ) -> Result<(), EngineError> {
        if state.device.kicked.contains(&device_id) {
            return Ok(());
        }
        state.device.kicked.push(device_id);
        if state.device.keys.as_ref().and_then(|keys| keys.id) == Some(device_id) {
            state
                .device
                .conversations
                .retain(|_, node| !matches!(node.kind, DeviceConversation::Synchronization { .. }));
            return Ok(());
        }
        let cids: Vec<_> = state.device.conversations.keys().copied().collect();
        let mut drop_ids = Vec::new();
        for cid in &cids {
            let node = state.device.conversations.get(cid).expect("row");
            if let DeviceConversation::Synchronization { peer, .. } = &node.kind
                && *peer == device_id
            {
                drop_ids.push(*cid);
            }
        }
        for cid in &drop_ids {
            state.device.conversations.remove(cid);
        }
        for cid in cids {
            if drop_ids.contains(&cid) {
                continue;
            }
            let node = state.device.conversations.get_mut(&cid).expect("row");
            let DeviceConversation::Synchronization { secret, .. } = &mut node.kind else {
                continue;
            };
            let mut info = b"chuchotez/1/sync-rekey".to_vec();
            info.extend_from_slice(device_id.as_bytes());
            let next = expand(
                self.suite.hmac(),
                &HmacSha256Key::from_bytes(*secret.as_bytes()),
                &info,
            )
            .into_bytes();
            *secret = Secret::from_bytes(next);
            node.chains.send.clear();
            node.chains.recv.clear();
            node.chains.skipped_mks.clear();
            node.chains.live_pending.clear();
        }
        Ok(())
    }

    pub(super) fn note_sync_peer(
        &self,
        state: &mut EngineState,
        cid: ConversationId,
        actor: &[u8],
    ) {
        let Ok(bytes) = <[u8; 32]>::try_from(actor) else {
            return;
        };
        let id = DeviceId::from_bytes(bytes);
        if state.device.keys.as_ref().and_then(|keys| keys.id) == Some(id) {
            return;
        }
        let Some(node) = state.device.conversations.get_mut(&cid) else {
            return;
        };
        let DeviceConversation::Synchronization { peer, .. } = &mut node.kind else {
            return;
        };
        *peer = id;
    }

    pub(super) fn wrap_sync_dek(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        handshake: super::super::ConversationId,
    ) -> Result<(), EngineError> {
        let policy = notice_for(state, handshake)
            .ok_or(EngineError::WrongPhase)?
            .policy;
        let pk = invitee_intro_for(state, handshake)
            .ok_or(EngineError::WrongPhase)?
            .encryption_pk
            .clone();
        let dek = self.require_dek()?.as_bytes().to_vec();
        state.device.dek_ct = Some(seal_sync_dek(self, rng, policy, &pk, &dek)?);
        Ok(())
    }

    /// Open a sync DEK wrap with this device encryption key and hold that DEK.
    pub fn open_sync_dek(&mut self, state: &EngineState, ct: &[u8]) -> Result<(), EngineError> {
        let policy = state
            .bodies()
            .iter()
            .find_map(|tx| match &tx.payload {
                TxPayload::Notice(notice) => Some(notice.policy),
                _ => None,
            })
            .ok_or(EngineError::WrongPhase)?;
        let sk = state
            .device
            .keys
            .as_ref()
            .ok_or(EngineError::WrongPhase)?
            .enc
            .secret_bytes()
            .to_vec();
        let dek = open_sync_dek(self, policy, &sk, ct)?;
        self.dek = Some(AeadKey::from_bytes(dek));
        Ok(())
    }

    pub(super) fn hold_sync_dek(
        &mut self,
        state: &EngineState,
        ct: &[u8],
    ) -> Result<(), EngineError> {
        self.open_sync_dek(state, ct)
    }

    /// Set conversation prefs.
    pub fn set_conversation_prefs(
        &self,
        state: EngineState,
        _rng: &dyn Rng,
        ids: ConversationRef,
        prefs: super::super::ConversationPrefs,
    ) -> Result<MutateOk, EngineError> {
        self.gate_chat(&state, &ids)?;
        self.group_disappear_blocked(&state, &ids, prefs.disappear_after)?;
        let payload = TxPayload::Prefs(OnWirePrefs {
            read_receipts: prefs.read_receipts,
            online_visible: prefs.online_visible,
            send_typing: prefs.send_typing,
            disappear_after: prefs.disappear_after,
            wake: prefs.wake,
        });
        let mut ok = self.mint_on(state, _rng, &ids, payload.clone())?;
        if super::group::group_live(&ok.state, ids.conversation_id).is_some() {
            let secret = self.conv_secret(&ok.state, &ids.conversation_id)?;
            ok = self.finish_chat(ok, ids.conversation_id, &secret, &payload)?;
        }
        Ok(ok)
    }
}

const SYNC_DEK_INFO: &[u8] = b"chuchotez/1/sync-dek";

fn seal_sync_dek(
    engine: &Engine,
    rng: &dyn Rng,
    policy: Policy,
    pk: &[u8],
    dek: &[u8],
) -> Result<Vec<u8>, EngineError> {
    let seed = KemSeed::from_pair(rng.random32(), rng.random32());
    #[rustfmt::skip]
    let (shared, ct) = engine.suite.kem().wrap(policy, pk, &seed).map_err(|_| EngineError::MalformedPayload)?;
    let key = expand(
        engine.suite.hmac(),
        &HmacSha256Key::from_bytes(shared32(&shared)),
        SYNC_DEK_INFO,
    )
    .into_bytes();
    let rnd = rng.random32();
    let mut nonce = [0u8; PACKET_NONCE_LEN];
    nonce.copy_from_slice(&rnd.as_bytes()[..PACKET_NONCE_LEN]);
    let sealed = engine.suite.aead().seal(
        &AeadKey::from_bytes(key),
        &AeadNonce::from_bytes(nonce),
        b"",
        dek,
    );
    let mut out = ct;
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

fn open_sync_dek(
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
    #[rustfmt::skip]
    let shared = engine.suite.kem().unwrap(policy, sk, ct).map_err(|_| EngineError::MalformedPayload)?;
    let key = expand(
        engine.suite.hmac(),
        &HmacSha256Key::from_bytes(shared32(&shared)),
        SYNC_DEK_INFO,
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
