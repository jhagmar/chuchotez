//! Users, identities, names, and this device.

use super::super::payload::TxPayload;
use super::super::{
    Defaults, DeviceId, DisplayName, EngineError, IdentityId, KemSeed, OnWirePrefs, Policy,
    SignSeed, UserId,
};
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
                .txs
                .values()
                .any(|t| matches!(t.payload, TxPayload::EngineInit)))
            .then_some(TxPayload::EngineInit),
        );
        payloads.push(TxPayload::EngineSetDefaults { defaults });
        self.mutate(state, &secret, payloads)
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
            .txs
            .values()
            .any(|t| matches!(t.payload, TxPayload::EngineInit))
        {
            payloads.push(TxPayload::EngineInit);
        }
        payloads.push(TxPayload::EngineCreateUser { user_id });
        let mut ok = self.mutate(state, &secret, payloads)?;
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
        if !state.txs.values().any(
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

    /// Kick a linked device.
    pub fn kick_device(
        &self,
        state: EngineState,
        _rng: &dyn Rng,
        device_id: DeviceId,
    ) -> Result<MutateOk, EngineError> {
        if state.device.keys.as_ref().and_then(|k| k.id) == Some(device_id) {
            return Err(EngineError::WrongPhase);
        }
        let secret = self.engine_secret()?;
        self.mutate(
            state,
            &secret,
            vec![TxPayload::EngineKickDevice { device_id }],
        )
    }

    /// Unlink this device from Sync.
    pub fn leave_sync(
        &self,
        mut state: EngineState,
        _rng: &dyn Rng,
    ) -> Result<MutateOk, EngineError> {
        state.device.conversations.clear();
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
