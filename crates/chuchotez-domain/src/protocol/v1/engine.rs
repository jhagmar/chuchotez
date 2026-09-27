//! Host-owned handle bound to a v1 [`Suite`] and [`Defaults`].

use super::codec::{
    durable_body_from_json, durable_body_to_json, ticket_from_json, ticket_to_json,
    vault_header_to_json,
};
use super::hmac::{HmacSha256Key, expand};
use super::payload::{
    DurableBody, Hlc, PACKET_LEN, PACKET_NONCE_LEN, PERSIST_MAX_UNCOMPRESSED,
    TICKET_MAX_UNCOMPRESSED, Ticket, TxEdit, TxMedia, TxNotice, TxPayload, TxReaction, TxText,
    UnlockSecret, VAULT_M, VAULT_P, VAULT_T, VaultHeader, time_bin,
};
use super::{
    AEAD_NONCE_LEN, AeadKey, AeadNonce, ConversationId, Defaults, DeviceId, DisplayName,
    DurableChannel, EngineError, EphemeralChannel, IdentityId, Json, KemSeed, Policy, Secret,
    SignSeed, Suite, Tag, UserId,
};
use crate::protocol::Rng;
use std::collections::BTreeMap;

/// Persist format version in the nonce high four bytes.
const PERSIST_VERSION: u32 = 1;

/// Folded snapshot format version.
const FOLD_VERSION: u32 = 2;

/// Conversation ids, user ids, identity ids.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConversationRef {
    /// User.
    pub user_id: UserId,
    /// Identity.
    pub identity_id: IdentityId,
    /// Conversation.
    pub conversation_id: ConversationId,
}

/// Successful mutation.
#[derive(Clone, Debug)]
pub struct MutateOk {
    /// Folded state.
    pub state: EngineState,
    persist: Vec<Vec<u8>>,
    pings: Vec<PingTarget>,
}

impl MutateOk {
    /// Persist records for the host log.
    #[must_use]
    pub fn persist(&self) -> &[Vec<u8>] {
        &self.persist
    }

    /// Wake POST targets.
    #[must_use]
    pub fn pings(&self) -> &[PingTarget] {
        &self.pings
    }
}

/// Web Push target from a peer Wake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PingTarget {
    /// Endpoint.
    pub endpoint: String,
    /// P-256 dh.
    pub p256dh: [u8; 65],
    /// Auth.
    pub auth: [u8; 16],
    /// Optional VAPID pk.
    pub vapid_pk: Option<Vec<u8>>,
}

/// Vault header bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WrapDekOk {
    /// Packed header.
    pub header: Vec<u8>,
}

/// Mapper work for the ticked now.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Poll {
    /// Durable list locators.
    pub list: Vec<DurableLocator>,
    /// Durable listen locators.
    pub listen_durable: Vec<DurableLocator>,
    /// Ephemeral listen locators.
    pub listen_ephemeral: Vec<EphemeralLocator>,
    /// Durable writes.
    pub write_durable: Vec<DurableWrite>,
    /// Ephemeral writes.
    pub write_ephemeral: Vec<EphemeralWrite>,
    /// Blob puts.
    pub blob_put: Vec<BlobPut>,
    /// Blob gets.
    pub blob_get: Vec<BlobGet>,
    /// Identities missing a display name.
    pub blocked: Vec<BlockedIdentity>,
}

/// Durable list/listen locator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableLocator {
    /// Channel.
    pub channel: DurableChannel,
    /// Tag.
    pub tag: Tag,
}

/// Ephemeral listen locator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EphemeralLocator {
    /// Channel.
    pub channel: EphemeralChannel,
    /// Tag.
    pub tag: Tag,
}

/// Durable write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableWrite {
    /// Channel.
    pub channel: DurableChannel,
    /// Tag.
    pub tag: Tag,
    /// 512-byte packet.
    pub body: Vec<u8>,
}

/// Ephemeral write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EphemeralWrite {
    /// Channel.
    pub channel: EphemeralChannel,
    /// Tag.
    pub tag: Tag,
    /// 512-byte packet.
    pub body: Vec<u8>,
}

/// Blob put.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobPut {
    /// Kind.
    pub kind: super::Kind,
    /// Address.
    pub address: super::Address,
    /// Tag.
    pub tag: Tag,
    /// Body.
    pub body: Vec<u8>,
}

/// Blob get.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobGet {
    /// Kind.
    pub kind: super::Kind,
    /// Address.
    pub address: super::Address,
    /// Tag.
    pub tag: Tag,
}

/// Why `poll.blocked` names an identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockedMissing {
    /// `DisplayName` is required before intro mint.
    DisplayName,
}

/// Identity missing a required display name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockedIdentity {
    /// User.
    pub user_id: UserId,
    /// Identity.
    pub identity_id: IdentityId,
    /// Required field that is absent.
    pub missing: BlockedMissing,
}

/// Query row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationListRow {
    /// Conversation.
    pub conversation_id: ConversationId,
    /// Query ADT for that row.
    pub conversation: Conversation,
}

/// Folded snapshot plus persist seq.
#[derive(Clone, Debug)]
pub struct FoldOk {
    /// Mutated state.
    pub state: EngineState,
    persist: Vec<Vec<u8>>,
    pings: Vec<PingTarget>,
    /// Sealed snapshot bytes.
    pub snapshot: Vec<u8>,
    /// Persist seq included in the snapshot.
    pub seq: u64,
}

impl FoldOk {
    /// Persist records for the host log.
    #[must_use]
    pub fn persist(&self) -> &[Vec<u8>] {
        &self.persist
    }

    /// Wake POST targets.
    #[must_use]
    pub fn pings(&self) -> &[PingTarget] {
        &self.pings
    }
}

/// Attachment for `send_media`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaDraft {
    /// Plaintext bytes.
    pub media_bytes: Vec<u8>,
    /// MIME type.
    pub mime: String,
    /// Filename.
    pub filename: String,
}

/// Inviter handshake query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandshakeInviter {
    /// Ticket minted; invite-tag writes still outstanding.
    InviteCreated {
        /// Expiry Unix seconds.
        expires: u64,
    },
    /// Invite-tag packet set acked.
    NoticePinned {
        /// Expiry Unix seconds.
        expires: u64,
    },
    /// Invitee intro ingested; inviter intro minted.
    IntroductionMinted {
        /// Expiry Unix seconds.
        expires: u64,
    },
    /// Intro packet set acked; waiting on confirm.
    Confirming {
        /// Expiry Unix seconds.
        expires: u64,
        /// `text(fingerprint)`.
        confirmation_digest: String,
    },
}

/// Invitee handshake query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandshakeInvitee {
    /// Ticket accepted; notice not yet ingested.
    TicketReceived,
    /// Valid notice ingested.
    InviteReceived {
        /// Notice Policy.
        policy: Policy,
        /// Expiry Unix seconds.
        expires: u64,
    },
    /// Invitee intro minted.
    IntroductionMinted {
        /// Notice Policy.
        policy: Policy,
        /// Expiry Unix seconds.
        expires: u64,
    },
    /// Invitee intro packet set acked.
    IntroductionSent {
        /// Notice Policy.
        policy: Policy,
        /// Expiry Unix seconds.
        expires: u64,
    },
    /// Inviter intro ingested; waiting on confirm.
    Confirming {
        /// Notice Policy.
        policy: Policy,
        /// Expiry Unix seconds.
        expires: u64,
        /// `text(fingerprint)`.
        confirmation_digest: String,
    },
}

/// Failed conversation query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailedReason {
    /// Notice Policy disagrees with the identity or Sync Policy.
    PolicyNotAccepted {
        /// Notice Policy.
        policy: Policy,
    },
    /// Ticked now is past `expires` pre-confirm.
    InviteExpired {
        /// Expiry Unix seconds.
        expires: u64,
    },
    /// Notice `open`, decompress, or parse refused.
    NoticeUnlockFailed,
    /// A second well-formed Notice disagrees with the stored one.
    NoticeConflict,
    /// Intro unlock refused.
    IntroUnlockFailed,
    /// Intro signature verify refused.
    IntroVerifyFailed,
    /// A second valid intro from that role arrived.
    DuplicateIntro,
    /// `rejectEstablished`.
    ConfirmationRejected,
    /// Same `tx_id` with a disagreeing payload.
    Equivocation,
    /// `rejectGroup`.
    OfferRejected,
    /// Roster omitted local `signing_pk`.
    Kicked,
    /// `TxGroupLeave` for self after local delete.
    Left,
}

/// Handshake query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Handshake {
    /// Inviter.
    Inviter(HandshakeInviter),
    /// Invitee.
    Invitee(HandshakeInvitee),
    /// Failed handshake.
    Failed(FailedReason),
}

/// Established or failed DM query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectMessageQuery {
    /// Child DM after both confirms.
    Established,
    /// Failed DM.
    Failed(FailedReason),
}

/// Group query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupQuery {
    /// Incoming group offer on a DM.
    GroupOffer,
    /// Owner or accepted member roster.
    GroupEstablished,
    /// Failed group.
    GroupFailed(FailedReason),
}

/// Synchronization query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SynchronizationQuery {
    /// Sync handshake.
    Handshake(Handshake),
    /// Linked devices.
    SyncEstablished,
    /// Failed Synchronization.
    Failed(FailedReason),
}

/// Query conversation ADT.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Conversation {
    /// DM handshake.
    HandshakeDm(Handshake),
    /// Sync handshake.
    HandshakeSync(Handshake),
    /// Established or failed DM.
    DirectMessage(DirectMessageQuery),
    /// Group.
    Group(GroupQuery),
    /// Synchronization.
    Synchronization(SynchronizationQuery),
}

/// Host-owned CRDT: engine transactions keyed by `tx_id`.
#[derive(Clone, Debug, Default)]
pub struct EngineState {
    txs: BTreeMap<[u8; 32], DurableBody>,
    next_seq: u64,
    ticked: Option<u64>,
    writes: Vec<DurableWrite>,
    eph_writes: Vec<EphemeralWrite>,
    blob_puts: Vec<BlobPut>,
    tickets: BTreeMap<[u8; 32], Ticket>,
    sync_tickets: BTreeMap<[u8; 32], Ticket>,
    names: BTreeMap<[u8; 32], DisplayName>,
    pics: BTreeMap<[u8; 32], Option<super::ProfilePic>>,
    device_name: Option<DisplayName>,
    device_id: Option<DeviceId>,
}

impl EngineState {
    /// Empty CRDT.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of durable txs.
    #[must_use]
    pub fn tx_count(&self) -> usize {
        self.txs.len()
    }

    #[cfg(test)]
    pub(crate) fn set_next_seq(&mut self, seq: u64) {
        self.next_seq = seq;
    }
}

/// Host-owned handle bound to a suite and Defaults.
#[derive(Clone)]
pub struct Engine {
    suite: Suite,
    defaults: Defaults,
    dek: Option<AeadKey>,
}

impl core::fmt::Debug for Engine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Engine")
            .field("locked", &self.dek.is_none())
            .finish()
    }
}

impl Engine {
    /// Bind this engine to `suite` and `defaults`.
    #[must_use]
    pub fn new(suite: Suite, defaults: Defaults) -> Self {
        Self {
            suite,
            defaults,
            dek: None,
        }
    }

    /// Constructor Defaults.
    #[must_use]
    pub fn defaults(&self) -> &Defaults {
        &self.defaults
    }

    /// Brand a display name.
    pub fn try_new_display_name(name: &str) -> Result<DisplayName, super::DisplayNameError> {
        DisplayName::try_from(name)
    }

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
            .decompress(header, super::payload::VAULT_MAX_UNCOMPRESSED)
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
            Some(super::Json::String(s)) => s,
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
                    Some(super::Json::String(s)) => s,
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
                    Some(super::Json::String(s)) => s,
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
                    Some(super::Json::String(s)) => s,
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
                    Some(super::Json::String(s)) => s,
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

    fn require_dek(&self) -> Result<&AeadKey, EngineError> {
        self.dek.as_ref().ok_or(EngineError::Locked)
    }

    fn require_tick(state: &EngineState) -> Result<u64, EngineError> {
        state.ticked.ok_or(EngineError::NotTicked)
    }

    fn engine_secret(&self) -> Result<[u8; 32], EngineError> {
        let dek = self.require_dek()?;
        Ok(expand(
            self.suite.hmac(),
            &HmacSha256Key::from_bytes(*dek.as_bytes()),
            b"chuchotez/1/engine",
        )
        .into_bytes())
    }

    fn engine_conversation_id(&self) -> Result<ConversationId, EngineError> {
        let secret = self.engine_secret()?;
        Ok(ConversationId::from_bytes(
            expand(
                self.suite.hmac(),
                &HmacSha256Key::from_bytes(secret),
                b"chuchotez/1/engine-id",
            )
            .into_bytes(),
        ))
    }

    fn tx_id(&self, conv_secret: &[u8; 32], payload: &TxPayload) -> [u8; 32] {
        let key = expand(
            self.suite.hmac(),
            &HmacSha256Key::from_bytes(*conv_secret),
            b"chuchotez/1/tx-id",
        );
        let json = super::codec::payload_to_json(self.suite.b64u(), payload);
        let canonical = self.suite.canonical_json().encode(&json);
        self.suite
            .hmac()
            .mac(&HmacSha256Key::from_bytes(key.into_bytes()), &canonical)
            .into_bytes()
    }

    fn persist_record(&self, seq: u64, body: &DurableBody) -> Result<Vec<u8>, EngineError> {
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

    fn merge_tx(
        &self,
        state: &mut EngineState,
        conv_secret: &[u8; 32],
        conversation_id: ConversationId,
        payload: TxPayload,
    ) -> Result<([u8; 32], DurableBody, Vec<u8>), EngineError> {
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

    fn mutate(
        &self,
        state: EngineState,
        conv_secret: &[u8; 32],
        payloads: Vec<TxPayload>,
    ) -> Result<MutateOk, EngineError> {
        let conversation_id = self.engine_conversation_id()?;
        self.mutate_on(state, conv_secret, conversation_id, payloads)
    }

    fn mutate_on(
        &self,
        mut state: EngineState,
        conv_secret: &[u8; 32],
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

    /// Advance the clock.
    pub fn tick(&self, mut state: EngineState, now: u64) -> Result<MutateOk, EngineError> {
        let _ = self.require_dek()?;
        if let Some(prev) = state.ticked
            && now < prev
        {
            return Err(EngineError::ClockWentBackwards);
        }
        state.ticked = Some(now);
        Ok(MutateOk {
            state,
            persist: Vec::new(),
            pings: Vec::new(),
        })
    }

    /// Mapper query for the ticked now.
    pub fn poll(&self, state: &EngineState) -> Result<Poll, EngineError> {
        let now = Self::require_tick(state)?;
        let _ = time_bin(now);
        let mut list = Vec::new();
        for ticket in state.tickets.values().chain(state.sync_tickets.values()) {
            let tag = Tag::from_bytes(
                expand(
                    self.suite.hmac(),
                    &HmacSha256Key::from_bytes(*ticket.secret.as_bytes()),
                    &[
                        b"chuchotez/1/handshake-invite".as_slice(),
                        &time_bin(now).to_be_bytes(),
                    ]
                    .concat(),
                )
                .into_bytes(),
            );
            for ch in &ticket.persistents {
                list.push(DurableLocator {
                    channel: ch.clone(),
                    tag,
                });
            }
        }
        let mut blocked = Vec::new();
        for tx in state.txs.values() {
            if let TxPayload::EngineCreateIdentity {
                user_id,
                identity_id,
                ..
            } = &tx.payload
                && !state.names.contains_key(identity_id.as_bytes())
            {
                blocked.push(BlockedIdentity {
                    user_id: *user_id,
                    identity_id: *identity_id,
                    missing: BlockedMissing::DisplayName,
                });
            }
        }
        Ok(Poll {
            list,
            write_durable: state.writes.clone(),
            write_ephemeral: state.eph_writes.clone(),
            blob_put: state.blob_puts.clone(),
            blocked,
            ..Poll::default()
        })
    }

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
        if !state
            .txs
            .values()
            .any(|t| matches!(t.payload, TxPayload::EngineInit))
        {
            payloads.push(TxPayload::EngineInit);
        }
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
        Ok((self.mutate(state, &secret, payloads)?, user_id))
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
        Ok((
            self.mutate(
                state,
                &secret,
                vec![TxPayload::EngineCreateIdentity {
                    user_id,
                    identity_id,
                    policy,
                    encryption,
                    signing,
                }],
            )?,
            identity_id,
        ))
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
    }

    /// Set a display name.
    pub fn set_display_name(
        &self,
        state: EngineState,
        _rng: &dyn Rng,
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
        ok.state.names.insert(*identity_id.as_bytes(), name);
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
        ok.state.names.remove(identity_id.as_bytes());
        Ok(ok)
    }

    /// Create a DM invite.
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
        if expires <= now {
            return Err(EngineError::ExpiresNotAfterNow);
        }
        let persistents = persistents.unwrap_or_else(|| self.defaults.persistents().to_vec());
        super::defaults::check_channel_bounds(&persistents, &[])
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
            intake_pk: intake.public_bytes().to_vec(),
            persistents: persistents.clone(),
            ephemerals: self.defaults.ephemerals().to_vec(),
            expires,
        });
        let conv_secret = *secret.as_bytes();
        let tx_id = self.tx_id(&conv_secret, &payload);
        let body = DurableBody {
            conversation_id,
            hlc: Hlc {
                wall_ms: now.saturating_mul(1000),
                counter: 0,
            },
            payload,
        };
        let persist = self.persist_record(state.next_seq, &body)?;
        state.next_seq = state.next_seq.saturating_add(1);
        state.txs.insert(tx_id, body);
        state.tickets.insert(*conversation_id.as_bytes(), ticket);
        let tag = Tag::from_bytes(
            expand(
                self.suite.hmac(),
                &HmacSha256Key::from_bytes(conv_secret),
                &[
                    b"chuchotez/1/handshake-invite".as_slice(),
                    &time_bin(now).to_be_bytes(),
                ]
                .concat(),
            )
            .into_bytes(),
        );
        for ch in persistents {
            state.writes.push(DurableWrite {
                channel: ch,
                tag,
                body: vec![0u8; PACKET_LEN],
            });
        }
        Ok((
            MutateOk {
                state,
                persist: vec![persist],
                pings: Vec::new(),
            },
            conversation_id,
        ))
    }

    fn identity_policy(
        &self,
        state: &EngineState,
        user_id: &UserId,
        identity_id: &IdentityId,
    ) -> Result<Policy, EngineError> {
        state
            .txs
            .values()
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
            .tickets
            .get(ids.conversation_id.as_bytes())
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
        let _ = (user_id, identity_id);
        let _ = Self::require_tick(&state)?;
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
        let ticket =
            ticket_from_json(self.suite.b64u(), &json).map_err(|_| EngineError::MalformedTicket)?;
        let conversation_id = ConversationId::from(rng.random32());
        state.tickets.insert(*conversation_id.as_bytes(), ticket);
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
        for tx in state.txs.values() {
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
        for tx in state.txs.values() {
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

    /// List conversations.
    pub fn list_conversations(
        &self,
        state: &EngineState,
        _user_id: UserId,
        _identity_id: IdentityId,
    ) -> Result<Vec<ConversationListRow>, EngineError> {
        let mut rows = Vec::new();
        for id in state.tickets.keys().chain(state.sync_tickets.keys()) {
            let conversation_id = ConversationId::from_bytes(*id);
            if let Some(conversation) = self.conversation_at(state, conversation_id) {
                rows.push(ConversationListRow {
                    conversation_id,
                    conversation,
                });
            }
        }
        Ok(rows)
    }

    fn conversation_at(
        &self,
        state: &EngineState,
        conversation_id: ConversationId,
    ) -> Option<Conversation> {
        if let Some(ticket) = state.tickets.get(conversation_id.as_bytes()) {
            let has_confirm = state.txs.values().any(|t| {
                matches!(t.payload, TxPayload::Confirm) && t.conversation_id == conversation_id
            });
            let has_reject = state.txs.values().any(|t| {
                matches!(t.payload, TxPayload::Reject) && t.conversation_id == conversation_id
            });
            if has_reject {
                return Some(Conversation::HandshakeDm(Handshake::Failed(
                    FailedReason::ConfirmationRejected,
                )));
            }
            if has_confirm {
                return Some(Conversation::DirectMessage(DirectMessageQuery::Established));
            }
            let inviter = if state.writes.is_empty() {
                HandshakeInviter::NoticePinned {
                    expires: ticket.expires,
                }
            } else {
                HandshakeInviter::InviteCreated {
                    expires: ticket.expires,
                }
            };
            return Some(Conversation::HandshakeDm(Handshake::Inviter(inviter)));
        }
        if let Some(ticket) = state.sync_tickets.get(conversation_id.as_bytes()) {
            return Some(Conversation::HandshakeSync(Handshake::Inviter(
                HandshakeInviter::InviteCreated {
                    expires: ticket.expires,
                },
            )));
        }
        None
    }

    fn conv_secret(
        &self,
        state: &EngineState,
        conversation_id: &ConversationId,
    ) -> Result<[u8; 32], EngineError> {
        state
            .tickets
            .get(conversation_id.as_bytes())
            .or_else(|| state.sync_tickets.get(conversation_id.as_bytes()))
            .map(|t| *t.secret.as_bytes())
            .ok_or(EngineError::UnknownIds)
    }

    fn require_ids(&self, state: &EngineState, ids: &ConversationRef) -> Result<(), EngineError> {
        self.identity_policy(state, &ids.user_id, &ids.identity_id)?;
        Ok(())
    }

    fn mint_on(
        &self,
        state: EngineState,
        ids: &ConversationRef,
        payload: TxPayload,
    ) -> Result<MutateOk, EngineError> {
        self.require_ids(&state, ids)?;
        let secret = self.conv_secret(&state, &ids.conversation_id)?;
        self.mutate_on(state, &secret, ids.conversation_id, vec![payload])
    }

    /// Fold watermark txs into a sealed snapshot.
    pub fn fold(&self, state: EngineState) -> Result<FoldOk, EngineError> {
        let dek = self.require_dek()?;
        let seq = state.next_seq;
        if seq == u64::MAX {
            return Err(EngineError::MalformedPersist);
        }
        let mut txs = Vec::new();
        for (id, body) in &state.txs {
            txs.push(Json::Object(vec![
                ("tx_id".into(), super::codec::bstr(self.suite.b64u(), id)),
                ("body".into(), durable_body_to_json(self.suite.b64u(), body)),
            ]));
        }
        let mut tickets = Vec::new();
        for (id, t) in state.tickets.iter().chain(state.sync_tickets.iter()) {
            tickets.push(Json::Object(vec![
                (
                    "conversation_id".into(),
                    super::codec::bstr(self.suite.b64u(), id),
                ),
                ("ticket".into(), ticket_to_json(self.suite.b64u(), t)),
                (
                    "sync".into(),
                    Json::Bool(state.sync_tickets.contains_key(id)),
                ),
            ]));
        }
        let json = Json::Object(vec![
            ("type".into(), Json::String("v1-engine-snapshot".into())),
            ("next_seq".into(), Json::Number(seq)),
            (
                "ticked".into(),
                state.ticked.map(Json::Number).unwrap_or(Json::Null),
            ),
            ("txs".into(), Json::Array(txs)),
            ("tickets".into(), Json::Array(tickets)),
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

    /// Drop a conversation row.
    pub fn delete_conversation(
        &self,
        mut state: EngineState,
        ids: ConversationRef,
    ) -> Result<MutateOk, EngineError> {
        self.require_ids(&state, &ids)?;
        let cid = *ids.conversation_id.as_bytes();
        if !state.tickets.contains_key(&cid) && !state.sync_tickets.contains_key(&cid) {
            return Err(EngineError::UnknownIds);
        }
        state.tickets.remove(&cid);
        state.sync_tickets.remove(&cid);
        Ok(MutateOk {
            state,
            persist: Vec::new(),
            pings: Vec::new(),
        })
    }

    /// Ingest a durable list snapshot.
    pub fn ingest_list(
        &self,
        state: EngineState,
        rng: &dyn Rng,
        channel: DurableChannel,
        tag: Tag,
        bodies: &[Vec<u8>],
    ) -> Result<MutateOk, EngineError> {
        let mut state = state;
        for body in bodies {
            state = self
                .ingest_packet(state, rng, channel.clone(), tag, body)?
                .state;
        }
        Ok(MutateOk {
            state,
            persist: Vec::new(),
            pings: Vec::new(),
        })
    }

    /// Ingest one mapper body.
    pub fn ingest_packet(
        &self,
        state: EngineState,
        _rng: &dyn Rng,
        _channel: DurableChannel,
        tag: Tag,
        body: &[u8],
    ) -> Result<MutateOk, EngineError> {
        let _ = Self::require_tick(&state)?;
        let _ = (tag, body);
        Err(EngineError::UnknownTag)
    }

    /// Ack a blob put.
    pub fn write_blob_ack(
        &self,
        mut state: EngineState,
        kind: super::Kind,
        address: super::Address,
        tag: Tag,
        body: &[u8],
    ) -> Result<MutateOk, EngineError> {
        let before = state.blob_puts.len();
        state.blob_puts.retain(|w| {
            !(w.kind == kind && w.address == address && w.tag == tag && w.body.as_slice() == body)
        });
        if state.blob_puts.len() == before {
            return Err(EngineError::UnknownWrite);
        }
        Ok(MutateOk {
            state,
            persist: Vec::new(),
            pings: Vec::new(),
        })
    }

    /// Create a Sync invite.
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
        if expires <= now {
            return Err(EngineError::ExpiresNotAfterNow);
        }
        let name =
            DisplayName::try_from(device_name).map_err(|_| EngineError::MalformedDisplayName)?;
        let persistents = persistents.unwrap_or_else(|| self.defaults.persistents().to_vec());
        super::defaults::check_channel_bounds(&persistents, &[])
            .map_err(|_| EngineError::ChannelBounds)?;
        let conversation_id = ConversationId::from(rng.random32());
        let secret = Secret::from(rng.random32());
        if state.device_id.is_none() {
            state.device_id = Some(DeviceId::from(rng.random32()));
        }
        let _ = self
            .suite
            .kem()
            .generate(policy, &KemSeed::from_pair(rng.random32(), rng.random32()))
            .map_err(|_| EngineError::MalformedPayload)?;
        let _ = self
            .suite
            .sign()
            .generate(policy, &SignSeed::from_pair(rng.random32(), rng.random32()))
            .map_err(|_| EngineError::MalformedPayload)?;
        state.sync_tickets.insert(
            *conversation_id.as_bytes(),
            Ticket {
                secret,
                persistents,
                expires,
            },
        );
        state.device_name = Some(name);
        Ok((
            MutateOk {
                state,
                persist: Vec::new(),
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
            .txs
            .values()
            .any(|t| matches!(t.payload, TxPayload::EngineCreateUser { .. }))
        {
            return Err(EngineError::EmptyEngineRequired);
        }
        self.receive_ticket(
            state,
            rng,
            UserId::from_bytes([0; 32]),
            IdentityId::from_bytes([0; 32]),
            ticket_host_string,
        )
    }

    /// Set this device name.
    pub fn set_device_name(
        &self,
        mut state: EngineState,
        _rng: &dyn Rng,
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
                m.state.device_name = Some(name);
                Ok(m)
            }
            Err(EngineError::NotTicked) => {
                state.device_name = Some(name);
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
        if state.device_id == Some(device_id) {
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
        state.sync_tickets.clear();
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
            Some(b) => {
                Some(super::ProfilePic::try_from(b).map_err(|_| EngineError::MalformedPayload)?)
            }
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
        ok.state.pics.insert(*identity_id.as_bytes(), pic);
        Ok(ok)
    }

    /// Set conversation prefs.
    pub fn set_conversation_prefs(
        &self,
        state: EngineState,
        _rng: &dyn Rng,
        ids: ConversationRef,
        prefs: super::ConversationPrefs,
    ) -> Result<MutateOk, EngineError> {
        self.mint_on(
            state,
            &ids,
            TxPayload::Prefs(super::OnWirePrefs {
                read_receipts: prefs.read_receipts,
                online_visible: prefs.online_visible,
                send_typing: prefs.send_typing,
                disappear_after: prefs.disappear_after,
                wake: prefs.wake,
            }),
        )
    }

    /// Confirm a handshake fingerprint.
    pub fn confirm_established(
        &self,
        state: EngineState,
        _rng: &dyn Rng,
        ids: ConversationRef,
    ) -> Result<MutateOk, EngineError> {
        self.mint_on(state, &ids, TxPayload::Confirm)
    }

    /// Reject a handshake fingerprint.
    pub fn reject_established(
        &self,
        state: EngineState,
        _rng: &dyn Rng,
        ids: ConversationRef,
    ) -> Result<MutateOk, EngineError> {
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
            Some(b) => {
                Some(super::ProfilePic::try_from(b).map_err(|_| EngineError::MalformedPayload)?)
            }
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
            let kind =
                super::Kind::try_from("blossom").map_err(|_| EngineError::MalformedPayload)?;
            let address = super::Address::try_from("https://blob.example")
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

    /// Confirmation digest as hex.
    pub fn confirmation_digest(
        &self,
        state: &EngineState,
        ids: &ConversationRef,
    ) -> Result<String, EngineError> {
        self.conv_secret(state, &ids.conversation_id)?;
        Ok(String::new())
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
                .unwrap_or(*body.conversation_id.as_bytes()),
        };
        let tx_id = self.tx_id(&secret, &body.payload);
        if let Some(existing) = state.txs.get(&tx_id)
            && existing.payload != body.payload
        {
            return Err(EngineError::Equivocation);
        }
        state.txs.insert(tx_id, body);
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
                let tx_id: [u8; 32] = id_v.try_into().map_err(|_| EngineError::MalformedPersist)?;
                let body = durable_body_from_json(
                    self.suite.b64u(),
                    getm("body").ok_or(EngineError::MalformedPersist)?,
                )
                .map_err(|_| EngineError::MalformedPersist)?;
                state.txs.insert(tx_id, body);
            }
        }
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
                let cid: [u8; 32] = id_v.try_into().map_err(|_| EngineError::MalformedPersist)?;
                let ticket = ticket_from_json(
                    self.suite.b64u(),
                    getm("ticket").ok_or(EngineError::MalformedPersist)?,
                )
                .map_err(|_| EngineError::MalformedPersist)?;
                let sync = matches!(getm("sync"), Some(Json::Bool(true)));
                if sync {
                    state.sync_tickets.insert(cid, ticket);
                } else {
                    state.tickets.insert(cid, ticket);
                }
            }
        }
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::{ConversationRef, Engine, EngineState, FOLD_VERSION};
    use crate::protocol::v1::fixtures::{CounterRng, test_engine};
    use crate::protocol::v1::payload::{DurableBody, Hlc, TxPayload};
    use crate::protocol::v1::{
        AEAD_NONCE_LEN, AeadNonce, ConversationId, EngineError, IdentityId, Json, Policy,
        UnlockSecret, UserId,
    };

    #[test]
    fn tick_user_identity_invite() {
        let mut engine = test_engine();
        let rng = CounterRng::new();
        assert_eq!(
            engine.tick(EngineState::new(), 10).unwrap_err(),
            EngineError::Locked
        );
        engine
            .wrap_dek(&rng, &UnlockSecret::Passphrase("passpass".into()))
            .expect("wrap");
        engine
            .wrap_dek(&rng, &UnlockSecret::Prf([8; 32]))
            .expect("prf");
        let ticked = engine
            .tick(EngineState::new(), 1_700_000_000)
            .expect("tick");
        assert_eq!(
            engine.tick(ticked.state.clone(), 1).unwrap_err(),
            EngineError::ClockWentBackwards
        );
        let poll = engine.poll(&ticked.state).expect("poll");
        assert!(poll.write_durable.is_empty());
        let defaults = engine.get_defaults(&ticked.state).expect("def");
        let set = engine
            .set_defaults(ticked.state.clone(), defaults)
            .expect("set");
        let (created, uid) = engine.create_user(set.state, &rng).expect("user");
        assert_eq!(engine.list_users(&created.state).expect("u")[0], uid);
        assert_eq!(
            engine
                .create_identity(
                    created.state.clone(),
                    &rng,
                    crate::protocol::v1::UserId::from_bytes([0; 32]),
                    Policy::Classic
                )
                .unwrap_err(),
            EngineError::UnknownIds
        );
        let (created, iid) = engine
            .create_identity(created.state, &rng, uid, Policy::Classic)
            .expect("id");
        assert_eq!(
            engine.list_identities(&created.state, uid).expect("i")[0],
            iid
        );
        engine
            .set_display_name(created.state.clone(), &rng, uid, iid, "")
            .unwrap_err();
        let named = engine
            .set_display_name(created.state.clone(), &rng, uid, iid, "Ada")
            .expect("name");
        let unnamed = engine
            .unset_display_name(named.state, uid, iid)
            .expect("unset");
        assert_eq!(
            engine
                .create_invite(unnamed.state.clone(), &rng, uid, iid, 1, None)
                .unwrap_err(),
            EngineError::ExpiresNotAfterNow
        );
        let (invited, cid) = engine
            .create_invite(unnamed.state, &rng, uid, iid, 1_800_000_000, None)
            .expect("inv");
        assert!(invited.state.tx_count() > 0);
        let ids = ConversationRef {
            user_id: uid,
            identity_id: iid,
            conversation_id: cid,
        };
        let ticket = engine.ticket_host_string(&invited.state, &ids).expect("t");
        assert!(!ticket.is_empty());
        let rows = engine
            .list_conversations(&invited.state, uid, iid)
            .expect("rows");
        assert!(matches!(
            rows[0].conversation,
            super::Conversation::HandshakeDm(super::Handshake::Inviter(
                super::HandshakeInviter::InviteCreated { .. }
            ))
        ));
        let poll = engine.poll(&invited.state).expect("p2");
        let w = &poll.write_durable[0];
        let acked = engine
            .write_ack(invited.state.clone(), w.channel.clone(), w.tag, &w.body)
            .expect("ack");
        assert!(
            engine
                .poll(&acked.state)
                .expect("p3")
                .write_durable
                .is_empty()
        );
        assert_eq!(
            engine
                .write_ack(acked.state.clone(), w.channel.clone(), w.tag, &w.body)
                .unwrap_err(),
            EngineError::UnknownWrite
        );
        let rec = invited.persist()[0].clone();
        let folded = engine.apply(acked.state.clone(), &rec).expect("apply");
        let snap = engine.fold(folded.clone()).expect("foldok");
        let _ = snap.persist();
        let _ = snap.pings();
        let restored = engine.apply_folded(&snap.snapshot).expect("fold");
        assert!(engine.apply(folded.clone(), &[]).is_err());
        let conv = engine
            .get_conversation(&acked.state, uid, iid, cid)
            .expect("q");
        assert!(matches!(
            conv,
            super::Conversation::HandshakeDm(super::Handshake::Inviter(
                super::HandshakeInviter::NoticePinned { .. }
            ))
        ));
        engine
            .confirm_established(acked.state.clone(), &rng, ids)
            .expect("conf");
        engine
            .reject_established(acked.state.clone(), &rng, ids)
            .expect("rej");
        engine
            .send_text(acked.state.clone(), &rng, ids, "hi", None)
            .expect("txt");
        assert_eq!(
            engine
                .send_text(acked.state.clone(), &rng, ids, "", None)
                .unwrap_err(),
            EngineError::MalformedPayload
        );
        engine
            .edit_message(
                acked.state.clone(),
                &rng,
                ids,
                crate::protocol::v1::Tag::from_bytes([1; 32]),
                "x",
            )
            .expect("ed");
        engine
            .remove_message(
                acked.state.clone(),
                &rng,
                ids,
                crate::protocol::v1::Tag::from_bytes([1; 32]),
            )
            .expect("rm");
        engine
            .send_reaction(
                acked.state.clone(),
                &rng,
                ids,
                crate::protocol::v1::Tag::from_bytes([1; 32]),
                "👍",
                true,
            )
            .expect("rx");
        engine
            .send_read(
                acked.state.clone(),
                &rng,
                ids,
                crate::protocol::v1::Tag::from_bytes([1; 32]),
            )
            .expect("rd");
        engine
            .send_delivered(
                acked.state.clone(),
                &rng,
                ids,
                crate::protocol::v1::Tag::from_bytes([1; 32]),
            )
            .expect("dv");
        engine
            .send_typing(acked.state.clone(), &rng, ids, true)
            .expect("ty");
        engine
            .send_presence(acked.state.clone(), &rng, ids)
            .expect("pr");
        engine
            .set_conversation_prefs(
                acked.state.clone(),
                &rng,
                ids,
                crate::protocol::v1::ConversationPrefs {
                    read_receipts: true,
                    online_visible: true,
                    send_typing: true,
                    disappear_after: None,
                    notification_privacy: crate::protocol::v1::NotificationPrivacy::Name,
                    wake: None,
                },
            )
            .expect("prefs");
        engine
            .set_profile_pic(acked.state.clone(), &rng, uid, iid, None)
            .expect("pic");
        engine
            .set_group_name(acked.state.clone(), &rng, ids, "G")
            .expect("gn");
        engine
            .set_group_photo(acked.state.clone(), &rng, ids, None)
            .expect("gp");
        engine
            .accept_group(acked.state.clone(), &rng, ids)
            .expect("ag");
        engine
            .reject_group(acked.state.clone(), &rng, ids)
            .expect("rg");
        engine
            .kick_group_member(acked.state.clone(), &rng, ids, &[1])
            .expect("kg");
        engine
            .leave_group(acked.state.clone(), &rng, ids)
            .expect("lg");
        assert_eq!(
            engine
                .create_group(acked.state.clone(), &rng, uid, iid, &[], "G", None)
                .unwrap_err(),
            EngineError::MemberCap
        );
        assert_eq!(
            engine
                .create_group(acked.state.clone(), &rng, uid, iid, &[cid], "G", None)
                .unwrap_err(),
            EngineError::WrongPhase
        );
        assert_eq!(
            engine
                .add_group_member(acked.state.clone(), &rng, ids, cid)
                .unwrap_err(),
            EngineError::WrongPhase
        );
        let _ = engine.confirmation_digest(&acked.state, &ids).expect("cd");
        engine
            .delete_conversation(acked.state.clone(), ids)
            .expect("dc");
        let (sync_ok, _sid) = engine
            .create_sync_invite(
                restored,
                &rng,
                Policy::Classic,
                1_900_000_000,
                "phone",
                None,
            )
            .expect("sync");
        engine
            .set_device_name(sync_ok.state.clone(), &rng, "phone")
            .expect("dn");
        engine
            .kick_device(
                sync_ok.state.clone(),
                &rng,
                crate::protocol::v1::DeviceId::from_bytes([9; 32]),
            )
            .expect("kd");
        let kicked = engine
            .kick_device(
                sync_ok.state.clone(),
                &rng,
                crate::protocol::v1::DeviceId::from_bytes([9; 32]),
            )
            .expect("kd2");
        let kick_fresh = engine.tick(EngineState::new(), 2_050_000_000).expect("tk");
        engine
            .apply(kick_fresh.state, &kicked.persist()[0])
            .expect("ak");
        engine.leave_sync(sync_ok.state, &rng).expect("ls");
        assert_eq!(
            engine
                .ingest_list(
                    invited.state.clone(),
                    &rng,
                    w.channel.clone(),
                    w.tag,
                    &[vec![1]]
                )
                .unwrap_err(),
            EngineError::UnknownTag
        );
        assert!(
            engine
                .ingest_list(invited.state.clone(), &rng, w.channel.clone(), w.tag, &[])
                .is_ok()
        );
        assert_eq!(
            engine
                .write_blob_ack(
                    invited.state.clone(),
                    crate::protocol::v1::Kind::try_from("blossom").expect("k"),
                    crate::protocol::v1::Address::try_from("https://blob.example").expect("a"),
                    crate::protocol::v1::Tag::from_bytes([1; 32]),
                    &[]
                )
                .unwrap_err(),
            EngineError::UnknownWrite
        );
        assert_eq!(
            engine
                .wrap_dek(&rng, &UnlockSecret::Passphrase("short".into()))
                .unwrap_err(),
            EngineError::UnlockFailed
        );
        assert_eq!(
            engine.unlock(b"null", &UnlockSecret::Passphrase("passpass".into())),
            Err(EngineError::UnlockFailed)
        );
        let header = engine
            .wrap_dek(&rng, &UnlockSecret::Prf([8; 32]))
            .expect("prfh");
        engine.lock();
        engine
            .unlock(&header.header, &UnlockSecret::Prf([8; 32]))
            .expect("prfu");
        let pass_h = engine
            .wrap_dek(&rng, &UnlockSecret::Passphrase("passpass".into()))
            .expect("ph");
        engine.lock();
        assert_eq!(
            engine.unlock(&pass_h.header, &UnlockSecret::Prf([8; 32])),
            Err(EngineError::UnlockFailed)
        );
        engine
            .unlock(&pass_h.header, &UnlockSecret::Passphrase("passpass".into()))
            .expect("pu");
        let prf_h = engine
            .wrap_dek(&rng, &UnlockSecret::Prf([8; 32]))
            .expect("pr2");
        engine.lock();
        assert_eq!(
            engine.unlock(&prf_h.header, &UnlockSecret::Passphrase("passpass".into())),
            Err(EngineError::UnlockFailed)
        );
        engine
            .unlock(&prf_h.header, &UnlockSecret::Prf([8; 32]))
            .expect("pru2");
        let salt = engine.suite.b64u().encode(&[9u8; 16]);
        let nonce = engine.suite.b64u().encode(&[8u8; 12]);
        let pass_missing_ct = engine.suite.canonical_json().encode(&Json::Object(vec![
            ("salt".into(), Json::String(salt.clone())),
            ("passphrase_nonce".into(), Json::String(nonce.clone())),
            ("passphrase_wrapped_dek".into(), Json::Null),
        ]));
        engine.lock();
        assert_eq!(
            engine.unlock(
                &pass_missing_ct,
                &UnlockSecret::Passphrase("passpass".into())
            ),
            Err(EngineError::UnlockFailed)
        );
        let prf_missing_ct = engine.suite.canonical_json().encode(&Json::Object(vec![
            ("salt".into(), Json::String(salt)),
            ("prf_nonce".into(), Json::String(nonce)),
            ("prf_wrapped_dek".into(), Json::Null),
        ]));
        assert_eq!(
            engine.unlock(&prf_missing_ct, &UnlockSecret::Prf([8; 32])),
            Err(EngineError::UnlockFailed)
        );
        engine
            .unlock(&prf_h.header, &UnlockSecret::Prf([8; 32]))
            .expect("pru3");
        assert!(Engine::try_new_display_name("Ada").is_ok());
        let received = engine
            .receive_ticket(folded, &rng, uid, iid, &ticket)
            .expect("recv");
        assert_eq!(
            engine
                .receive_sync_ticket(received.0.state.clone(), &rng, &ticket)
                .unwrap_err(),
            EngineError::EmptyEngineRequired
        );
        engine
            .delete_identity(received.0.state.clone(), uid, iid)
            .expect("di");
        engine.delete_user(received.0.state, uid).expect("du");
        engine.lock();
        assert_eq!(
            engine.poll(&EngineState::new()).unwrap_err(),
            EngineError::NotTicked
        );
        let _ = invited.pings();
        let _ = format!(
            "{:?}",
            ConversationRef {
                user_id: crate::protocol::v1::UserId::from_bytes([1; 32]),
                identity_id: crate::protocol::v1::IdentityId::from_bytes([2; 32]),
                conversation_id: crate::protocol::v1::ConversationId::from_bytes([3; 32]),
            }
        );
        let _ = format!(
            "{:?}",
            super::MediaDraft {
                media_bytes: vec![1],
                mime: "a".into(),
                filename: "b".into(),
            }
        );
    }

    #[test]
    fn library_edges() {
        let mut engine = test_engine();
        let rng = CounterRng::new();
        engine
            .wrap_dek(&rng, &UnlockSecret::Passphrase("passpass".into()))
            .expect("wrap");
        assert_eq!(
            engine.apply_folded(&[]).unwrap_err(),
            EngineError::MalformedPersist
        );
        let mut ticked = engine
            .tick(EngineState::new(), 1_700_000_000)
            .expect("tick");
        ticked.state.set_next_seq(u64::MAX);
        assert_eq!(
            engine.create_user(ticked.state.clone(), &rng).unwrap_err(),
            EngineError::MalformedPersist
        );
        ticked.state.set_next_seq(0);
        let (created, uid) = engine.create_user(ticked.state, &rng).expect("u");
        let (created, iid) = engine
            .create_identity(created.state, &rng, uid, Policy::Classic)
            .expect("i");
        let (invited, cid) = engine
            .create_invite(created.state, &rng, uid, iid, 1_800_000_000, None)
            .expect("inv");
        let ids = ConversationRef {
            user_id: uid,
            identity_id: iid,
            conversation_id: cid,
        };
        engine
            .confirm_established(invited.state.clone(), &rng, ids)
            .expect("c");
        let confirmed = engine
            .confirm_established(invited.state.clone(), &rng, ids)
            .expect("c2");
        assert!(matches!(
            engine
                .get_conversation(&confirmed.state, uid, iid, cid)
                .expect("q"),
            super::Conversation::DirectMessage(super::DirectMessageQuery::Established)
        ));
        let rejected = engine
            .reject_established(invited.state.clone(), &rng, ids)
            .expect("r");
        assert!(matches!(
            engine
                .get_conversation(&rejected.state, uid, iid, cid)
                .expect("qf"),
            super::Conversation::HandshakeDm(super::Handshake::Failed(
                super::FailedReason::ConfirmationRejected
            ))
        ));
        let media = engine
            .send_media(
                invited.state.clone(),
                &rng,
                ids,
                &[super::MediaDraft {
                    media_bytes: b"blob".to_vec(),
                    mime: "image/png".into(),
                    filename: "a.png".into(),
                }],
                None,
                Some("cap"),
            )
            .expect("media");
        let put = media.state.blob_puts[0].clone();
        engine
            .write_blob_ack(
                media.state.clone(),
                put.kind.clone(),
                put.address.clone(),
                put.tag,
                &put.body,
            )
            .expect("ba");
        assert_eq!(
            engine
                .send_media(invited.state.clone(), &rng, ids, &[], None, None)
                .unwrap_err(),
            EngineError::MalformedPayload
        );
        assert_eq!(
            engine
                .ticket_host_string(&EngineState::new(), &ids)
                .unwrap_err(),
            EngineError::UnknownIds
        );
        assert_eq!(
            engine
                .receive_ticket(invited.state.clone(), &rng, uid, iid, "!!")
                .unwrap_err(),
            EngineError::MalformedTicket
        );
        assert_eq!(
            engine
                .get_conversation(
                    &invited.state,
                    uid,
                    iid,
                    crate::protocol::v1::ConversationId::from_bytes([9; 32])
                )
                .unwrap_err(),
            EngineError::UnknownIds
        );
        let (sync_ok, sid) = engine
            .create_sync_invite(
                invited.state.clone(),
                &rng,
                Policy::Classic,
                1_900_000_000,
                "phone",
                None,
            )
            .expect("sy");
        assert!(matches!(
            engine
                .get_conversation(&sync_ok.state, uid, iid, sid)
                .expect("sq"),
            super::Conversation::HandshakeSync(super::Handshake::Inviter(
                super::HandshakeInviter::InviteCreated { .. }
            ))
        ));
        let sync_rows = engine
            .list_conversations(&sync_ok.state, uid, iid)
            .expect("srows");
        assert!(
            sync_rows
                .iter()
                .any(|row| matches!(row.conversation, super::Conversation::HandshakeSync(_)))
        );
        assert_eq!(
            engine
                .create_sync_invite(
                    invited.state.clone(),
                    &rng,
                    Policy::Classic,
                    1,
                    "phone",
                    None
                )
                .unwrap_err(),
            EngineError::ExpiresNotAfterNow
        );
        assert_eq!(
            engine
                .kick_device(
                    sync_ok.state.clone(),
                    &rng,
                    sync_ok.state.device_id.unwrap()
                )
                .unwrap_err(),
            EngineError::WrongPhase
        );
        assert_eq!(
            engine
                .set_group_photo(invited.state.clone(), &rng, ids, Some(&[1, 2, 3]))
                .unwrap_err(),
            EngineError::MalformedPayload
        );
        assert_eq!(
            engine
                .set_profile_pic(invited.state.clone(), &rng, uid, iid, Some(&[1]))
                .unwrap_err(),
            EngineError::MalformedPayload
        );
        engine
            .set_device_name(EngineState::new(), &rng, "")
            .unwrap_err();
        let rec = invited.persist()[0].clone();
        assert_eq!(
            engine.apply_folded(&rec).unwrap_err(),
            EngineError::MalformedPersist
        );
        let empty = engine.tick(EngineState::new(), 2_000_000_000).expect("t2");
        engine
            .receive_sync_ticket(empty.state, &rng, "aa")
            .unwrap_err();
        assert_eq!(
            engine
                .edit_message(
                    invited.state.clone(),
                    &rng,
                    ids,
                    crate::protocol::v1::Tag::from_bytes([1; 32]),
                    "",
                )
                .unwrap_err(),
            EngineError::MalformedPayload
        );
        assert_eq!(
            engine
                .send_reaction(
                    invited.state.clone(),
                    &rng,
                    ids,
                    crate::protocol::v1::Tag::from_bytes([1; 32]),
                    "",
                    true,
                )
                .unwrap_err(),
            EngineError::MalformedPayload
        );
        assert_eq!(
            engine
                .send_media(
                    invited.state.clone(),
                    &rng,
                    ids,
                    &[super::MediaDraft {
                        media_bytes: b"blob".to_vec(),
                        mime: String::new(),
                        filename: "a.png".into(),
                    }],
                    None,
                    None,
                )
                .unwrap_err(),
            EngineError::MalformedPayload
        );
        let named = engine
            .set_device_name(EngineState::new(), &rng, "phone")
            .expect("dev");
        assert!(named.state.device_name.is_some());
        assert_eq!(
            engine
                .unlock(b"[]", &UnlockSecret::Passphrase("passpass".into()))
                .unwrap_err(),
            EngineError::UnlockFailed
        );
        assert_eq!(
            engine
                .unlock(
                    br#"{"salt":1}"#,
                    &UnlockSecret::Passphrase("passpass".into())
                )
                .unwrap_err(),
            EngineError::UnlockFailed
        );
        engine
            .confirm_established(invited.state.clone(), &rng, ids)
            .expect("c3");
        engine
            .confirm_established(invited.state.clone(), &rng, ids)
            .expect("c4");
        let once = engine
            .send_text(invited.state.clone(), &rng, ids, "hi", None)
            .expect("txt1");
        engine
            .send_text(once.state, &rng, ids, "hi", None)
            .expect("txt2");
        let missing = ConversationRef {
            user_id: uid,
            identity_id: iid,
            conversation_id: ConversationId::from_bytes([7; 32]),
        };
        assert_eq!(
            engine
                .send_text(invited.state.clone(), &rng, missing, "hi", None)
                .unwrap_err(),
            EngineError::UnknownIds
        );
        assert_eq!(
            engine
                .delete_conversation(invited.state.clone(), missing)
                .unwrap_err(),
            EngineError::UnknownIds
        );
        let ghost = ConversationRef {
            user_id: uid,
            identity_id: IdentityId::from_bytes([7; 32]),
            conversation_id: cid,
        };
        assert_eq!(
            engine
                .send_text(invited.state.clone(), &rng, ghost, "hi", None)
                .unwrap_err(),
            EngineError::UnknownIds
        );
        let mut maxed = invited.state.clone();
        maxed.set_next_seq(u64::MAX);
        assert_eq!(
            engine.fold(maxed.clone()).unwrap_err(),
            EngineError::MalformedPersist
        );
        assert_eq!(
            engine
                .create_identity(maxed.clone(), &rng, uid, Policy::Classic)
                .unwrap_err(),
            EngineError::MalformedPersist
        );
        assert_eq!(
            engine
                .set_display_name(maxed.clone(), &rng, uid, iid, "Ada")
                .unwrap_err(),
            EngineError::MalformedPersist
        );
        assert_eq!(
            engine
                .unset_display_name(maxed.clone(), uid, iid)
                .unwrap_err(),
            EngineError::MalformedPersist
        );
        assert_eq!(
            engine
                .set_profile_pic(maxed.clone(), &rng, uid, iid, None)
                .unwrap_err(),
            EngineError::MalformedPersist
        );
        assert_eq!(
            engine.set_device_name(maxed, &rng, "phone").unwrap_err(),
            EngineError::MalformedPersist
        );
        let secret = engine.engine_secret().expect("es");
        let init = TxPayload::EngineInit;
        let init_id = engine.tx_id(&secret, &init);
        let mut collided = engine
            .tick(EngineState::new(), 2_100_000_000)
            .expect("t3")
            .state;
        collided.txs.insert(
            init_id,
            DurableBody {
                conversation_id: engine.engine_conversation_id().expect("eid"),
                hlc: Hlc {
                    wall_ms: 0,
                    counter: 0,
                },
                payload: TxPayload::EngineCreateUser {
                    user_id: UserId::from_bytes([0; 32]),
                },
            },
        );
        assert_eq!(
            engine
                .set_defaults(
                    collided,
                    engine.get_defaults(&EngineState::new()).expect("gd")
                )
                .unwrap_err(),
            EngineError::Equivocation
        );
        let fresh = engine.tick(EngineState::new(), 2_200_000_000).expect("t4");
        let rec0 = invited.persist()[0].clone();
        let applied = engine.apply(fresh.state, &rec0).expect("ap0");
        assert!(applied.tx_count() > 0);
        let mut collide_apply = applied.clone();
        let body = collide_apply.txs.values().next().expect("b").clone();
        let tx_id = *collide_apply.txs.keys().next().expect("k");
        collide_apply.txs.insert(
            tx_id,
            DurableBody {
                conversation_id: body.conversation_id,
                hlc: body.hlc,
                payload: TxPayload::EngineDeleteUser {
                    user_id: UserId::from_bytes([0; 32]),
                },
            },
        );
        assert_eq!(
            engine.apply(collide_apply, &rec0).unwrap_err(),
            EngineError::Equivocation
        );
        let sync_fold = engine.fold(sync_ok.state.clone()).expect("sfold");
        let restored_sync = engine.apply_folded(&sync_fold.snapshot).expect("as");
        assert!(!restored_sync.sync_tickets.is_empty());
        fn seal_fold(engine: &Engine, json: Json, seq: u64) -> Vec<u8> {
            let dek = engine.dek.as_ref().expect("dek");
            let canonical = engine.suite.canonical_json().encode(&json);
            let packed = engine.suite.compress().compress(&canonical);
            let mut nonce_bytes = [0u8; AEAD_NONCE_LEN];
            nonce_bytes[..4].copy_from_slice(&FOLD_VERSION.to_be_bytes());
            nonce_bytes[4..].copy_from_slice(&seq.to_be_bytes());
            let ct =
                engine
                    .suite
                    .aead()
                    .seal(dek, &AeadNonce::from_bytes(nonce_bytes), b"", &packed);
            let mut snapshot = Vec::with_capacity(AEAD_NONCE_LEN + ct.len());
            snapshot.extend_from_slice(&nonce_bytes);
            snapshot.extend_from_slice(&ct);
            snapshot
        }
        assert_eq!(
            engine
                .apply_folded(&seal_fold(&engine, Json::Array(Vec::new()), 0))
                .unwrap_err(),
            EngineError::MalformedPersist
        );
        assert_eq!(
            engine
                .apply_folded(&seal_fold(
                    &engine,
                    Json::Object(vec![("next_seq".into(), Json::String("1".into()))]),
                    0
                ))
                .unwrap_err(),
            EngineError::MalformedPersist
        );
        assert_eq!(
            engine
                .apply_folded(&seal_fold(
                    &engine,
                    Json::Object(vec![
                        ("next_seq".into(), Json::Number(1)),
                        ("ticked".into(), Json::Bool(true)),
                    ]),
                    0
                ))
                .unwrap_err(),
            EngineError::MalformedPersist
        );
        let with_null_tick = engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![
                    ("next_seq".into(), Json::Number(1)),
                    ("ticked".into(), Json::Null),
                ]),
                0,
            ))
            .expect("nulltick");
        assert!(with_null_tick.ticked.is_none());
        let omitted_tick = engine
            .apply_folded(&seal_fold(
                &engine,
                Json::Object(vec![("next_seq".into(), Json::Number(2))]),
                0,
            ))
            .expect("omit");
        assert!(omitted_tick.ticked.is_none());
        assert_eq!(
            engine
                .apply_folded(&seal_fold(
                    &engine,
                    Json::Object(vec![
                        ("next_seq".into(), Json::Number(1)),
                        ("txs".into(), Json::Array(vec![Json::Number(1)])),
                    ]),
                    0
                ))
                .unwrap_err(),
            EngineError::MalformedPersist
        );
        assert_eq!(
            engine
                .apply_folded(&seal_fold(
                    &engine,
                    Json::Object(vec![
                        ("next_seq".into(), Json::Number(1)),
                        (
                            "txs".into(),
                            Json::Array(vec![Json::Object(vec![(
                                "tx_id".into(),
                                Json::Number(1)
                            )])])
                        ),
                    ]),
                    0
                ))
                .unwrap_err(),
            EngineError::MalformedPersist
        );
        assert_eq!(
            engine
                .apply_folded(&seal_fold(
                    &engine,
                    Json::Object(vec![
                        ("next_seq".into(), Json::Number(1)),
                        ("tickets".into(), Json::Array(vec![Json::Number(1)])),
                    ]),
                    0
                ))
                .unwrap_err(),
            EngineError::MalformedPersist
        );
        assert_eq!(
            engine
                .apply_folded(&seal_fold(
                    &engine,
                    Json::Object(vec![
                        ("next_seq".into(), Json::Number(1)),
                        (
                            "tickets".into(),
                            Json::Array(vec![Json::Object(vec![(
                                "conversation_id".into(),
                                Json::Number(1)
                            )])])
                        ),
                    ]),
                    0
                ))
                .unwrap_err(),
            EngineError::MalformedPersist
        );
        engine.lock();
        assert_eq!(
            engine
                .set_device_name(invited.state.clone(), &rng, "phone")
                .unwrap_err(),
            EngineError::Locked
        );
    }

    #[test]
    fn query_adt_debug() {
        use super::{
            BlockedIdentity, BlockedMissing, Conversation, DirectMessageQuery, FailedReason,
            GroupQuery, Handshake, HandshakeInvitee, HandshakeInviter, SynchronizationQuery,
        };
        let expires = 1;
        let digest = String::new();
        let policy = Policy::Classic;
        for inviter in [
            HandshakeInviter::InviteCreated { expires },
            HandshakeInviter::NoticePinned { expires },
            HandshakeInviter::IntroductionMinted { expires },
            HandshakeInviter::Confirming {
                expires,
                confirmation_digest: digest.clone(),
            },
        ] {
            let _ = format!("{inviter:?}");
        }
        for invitee in [
            HandshakeInvitee::TicketReceived,
            HandshakeInvitee::InviteReceived { policy, expires },
            HandshakeInvitee::IntroductionMinted { policy, expires },
            HandshakeInvitee::IntroductionSent { policy, expires },
            HandshakeInvitee::Confirming {
                policy,
                expires,
                confirmation_digest: digest,
            },
        ] {
            let _ = format!("{invitee:?}");
        }
        for reason in [
            FailedReason::PolicyNotAccepted {
                policy: Policy::Hybrid,
            },
            FailedReason::InviteExpired { expires },
            FailedReason::NoticeUnlockFailed,
            FailedReason::NoticeConflict,
            FailedReason::IntroUnlockFailed,
            FailedReason::IntroVerifyFailed,
            FailedReason::DuplicateIntro,
            FailedReason::ConfirmationRejected,
            FailedReason::Equivocation,
            FailedReason::OfferRejected,
            FailedReason::Kicked,
            FailedReason::Left,
        ] {
            let _ = format!("{reason:?}");
        }
        let _ = format!(
            "{:?}",
            Handshake::Inviter(HandshakeInviter::InviteCreated { expires })
        );
        let _ = format!("{:?}", Handshake::Invitee(HandshakeInvitee::TicketReceived));
        let _ = format!("{:?}", Handshake::Failed(FailedReason::Left));
        let _ = format!("{:?}", DirectMessageQuery::Established);
        let _ = format!("{:?}", DirectMessageQuery::Failed(FailedReason::Left));
        let _ = format!("{:?}", GroupQuery::GroupOffer);
        let _ = format!("{:?}", GroupQuery::GroupEstablished);
        let _ = format!("{:?}", GroupQuery::GroupFailed(FailedReason::Kicked));
        let hs = Handshake::Invitee(HandshakeInvitee::TicketReceived);
        let _ = format!("{:?}", SynchronizationQuery::Handshake(hs));
        let _ = format!("{:?}", SynchronizationQuery::SyncEstablished);
        let _ = format!("{:?}", SynchronizationQuery::Failed(FailedReason::Left));
        let _ = format!(
            "{:?}",
            Conversation::HandshakeDm(Handshake::Inviter(HandshakeInviter::InviteCreated {
                expires
            }))
        );
        let _ = format!(
            "{:?}",
            Conversation::HandshakeSync(Handshake::Inviter(HandshakeInviter::InviteCreated {
                expires
            }))
        );
        let _ = format!(
            "{:?}",
            Conversation::DirectMessage(DirectMessageQuery::Established)
        );
        let _ = format!("{:?}", Conversation::Group(GroupQuery::GroupOffer));
        let _ = format!(
            "{:?}",
            Conversation::Synchronization(SynchronizationQuery::SyncEstablished)
        );
        let _ = format!(
            "{:?}",
            BlockedIdentity {
                user_id: crate::protocol::v1::UserId::from_bytes([1; 32]),
                identity_id: crate::protocol::v1::IdentityId::from_bytes([2; 32]),
                missing: BlockedMissing::DisplayName,
            }
        );
    }
}
