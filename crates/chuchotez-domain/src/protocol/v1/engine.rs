//! Host-owned handle bound to a v1 [`Suite`] and [`Defaults`].

use super::chain::{
    CachedMk, SendChain, chain_from_json, chain_key, chain_to_json, fragment_body, join, mk,
    open_skip_ahead, packed_tx, seal_packet, set_xor_for, step,
};
use super::codec::{
    durable_body_from_json, durable_body_to_json, durable_json, ticket_from_json, ticket_to_json,
    vault_header_to_json,
};
use super::hmac::{HmacSha256, HmacSha256Key, expand};
use super::kem::{KeyPair, kem_ct_len, kem_pk_len};
use super::payload::{
    BIN_WINDOW, ConversationSort, DurableBody, Hlc, PACKET_MAX_UNCOMPRESSED, PACKET_NONCE_LEN,
    PERSIST_MAX_UNCOMPRESSED, PacketPlain, TICKET_MAX_UNCOMPRESSED, Ticket, TxEdit, TxInviteeIntro,
    TxInviterIntro, TxMedia, TxNotice, TxPayload, TxReaction, TxText, UnlockSecret, VAULT_M,
    VAULT_P, VAULT_T, VaultHeader, parse_policy, policy_str, time_bin,
};
use super::sign::{SigningKeyPair, sign_pk_len};
use super::{
    AEAD_NONCE_LEN, Address, AeadKey, AeadNonce, ConversationId, Defaults, DeviceId, DisplayName,
    DurableChannel, EngineError, EphemeralChannel, IdentityId, Json, KemSeed, Kind, OnWirePrefs,
    Policy, Secret, SignSeed, Suite, Tag, TagKey, UserId,
};
use crate::protocol::Rng;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

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
    send_chains: BTreeMap<Vec<u8>, SendChain>,
    recv_chains: BTreeMap<Vec<u8>, SendChain>,
    skipped_mks: BTreeMap<Vec<u8>, Vec<CachedMk>>,
    frags: BTreeMap<[u8; 32], FragSet>,
    bin_progress: BTreeMap<(String, String, [u8; 32]), BinProgress>,
    names: BTreeMap<[u8; 32], DisplayName>,
    pics: BTreeMap<[u8; 32], Option<super::ProfilePic>>,
    device_name: Option<DisplayName>,
    device_id: Option<DeviceId>,
    failed: BTreeMap<[u8; 32], FailedReason>,
    owners: BTreeMap<[u8; 32], ([u8; 32], [u8; 32])>,
    inviters: BTreeSet<[u8; 32]>,
    device_enc: Option<KeyPair>,
    device_sign: Option<SigningKeyPair>,
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

    #[cfg(test)]
    pub(crate) fn send_chain_seq(&self, conversation_id: &ConversationId) -> Option<u64> {
        self.send_chains
            .get(&chain_key(conversation_id, &[]))
            .map(|c| c.packet_seq)
    }

    #[cfg(test)]
    pub(crate) fn recv_chain_seq(&self, conversation_id: &ConversationId) -> Option<u64> {
        self.recv_chains
            .get(&chain_key(conversation_id, &[]))
            .map(|c| c.packet_seq)
    }
}

#[derive(Clone, Debug)]
struct BinProgress {
    channel: DurableChannel,
    tag_key: [u8; 32],
    watermark: Option<u64>,
    completed: BTreeSet<u64>,
}

#[derive(Clone, Debug)]
struct FragSet {
    conversation_id: [u8; 32],
    parts: BTreeMap<u64, Vec<u8>>,
    last_i: Option<u64>,
}

type CallingParts = (DisplayName, Option<super::ProfilePic>, Vec<u8>, Vec<u8>);

struct HandshakeHit {
    cid: [u8; 32],
    secret: [u8; 32],
    sort: ConversationSort,
    bin: u64,
    tag_key: [u8; 32],
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

    fn post_handshake_packets(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        conversation_id: ConversationId,
        conv_secret: &[u8; 32],
        tx_id: Tag,
    ) -> Result<(), EngineError> {
        let now = Self::require_tick(state)?;
        let cid = *conversation_id.as_bytes();
        let (sort, persistents) = if let Some(t) = state.tickets.get(&cid) {
            (ConversationSort::HandshakeDm, t.persistents.clone())
        } else if let Some(t) = state.sync_tickets.get(&cid) {
            (ConversationSort::HandshakeSync, t.persistents.clone())
        } else {
            return Err(EngineError::UnknownIds);
        };
        let tag = Tag::from_bytes(
            expand(
                self.suite.hmac(),
                &HmacSha256Key::from_bytes(*conv_secret),
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
            .get(tx_id.as_bytes())
            .ok_or(EngineError::UnknownIds)?
            .clone();
        let packed = packed_tx(&self.suite, &body);
        let set_xor = set_xor_for(&state.txs, conversation_id);
        let key = chain_key(&conversation_id, &[]);
        let mut chain = match state.send_chains.get(&key) {
            Some(c) => c.clone(),
            None => join(self.suite.hmac(), conv_secret, sort, &[])?,
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

    /// Advance the clock. Stores `InviteExpired` when `now` is past `expires`
    /// and the handshake is still pre-confirm.
    pub fn tick(&self, mut state: EngineState, now: u64) -> Result<MutateOk, EngineError> {
        let _ = self.require_dek()?;
        if let Some(prev) = state.ticked
            && now < prev
        {
            return Err(EngineError::ClockWentBackwards);
        }
        state.ticked = Some(now);
        for entries in state.skipped_mks.values_mut() {
            entries.retain(|e| e.expires_at > now);
        }
        state.skipped_mks.retain(|_, e| !e.is_empty());
        let mut expired = Vec::new();
        for (cid, ticket, _) in handshake_rows(&state) {
            if state.failed.contains_key(&cid) || now <= ticket.expires {
                continue;
            }
            let conversation_id = ConversationId::from_bytes(cid);
            let confirmed = state.txs.values().any(|t| {
                matches!(t.payload, TxPayload::Confirm) && t.conversation_id == conversation_id
            });
            if !confirmed {
                expired.push((cid, ticket.expires));
            }
        }
        for (cid, expires) in expired {
            state
                .failed
                .insert(cid, FailedReason::InviteExpired { expires });
        }
        Ok(MutateOk {
            state,
            persist: Vec::new(),
            pings: Vec::new(),
        })
    }

    /// Mapper query for the ticked now.
    pub fn poll(&self, state: &EngineState) -> Result<Poll, EngineError> {
        let now = Self::require_tick(state)?;
        let w = time_bin(now);
        let start = window_start(w);
        let mut list = Vec::new();
        let mut listen_durable = Vec::new();
        for (_, ticket, _) in handshake_rows(state) {
            let secret = ticket.secret.as_bytes();
            let tag_key = handshake_tag_key(self.suite.hmac(), secret);
            for ch in &ticket.persistents {
                let progress = state.bin_progress.get(&progress_key(ch, &tag_key));
                let mut bins = BTreeSet::new();
                for bin in start..=w.saturating_add(1) {
                    if !bin_complete(progress, bin) {
                        bins.insert(bin);
                    }
                }
                for bin in listen_bins(w) {
                    bins.insert(bin);
                }
                for bin in bins {
                    list.push(DurableLocator {
                        channel: ch.clone(),
                        tag: invite_tag(self.suite.hmac(), secret, bin),
                    });
                }
                for bin in listen_bins(w) {
                    listen_durable.push(DurableLocator {
                        channel: ch.clone(),
                        tag: invite_tag(self.suite.hmac(), secret, bin),
                    });
                }
            }
        }
        sort_durable_locators(&mut list);
        list.dedup();
        sort_durable_locators(&mut listen_durable);
        listen_durable.dedup();
        let mut write_durable = state.writes.clone();
        sort_durable_writes(&mut write_durable);
        let mut write_ephemeral = state.eph_writes.clone();
        sort_ephemeral_writes(&mut write_ephemeral);
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
        if state.device_name.is_none()
            && state
                .txs
                .values()
                .all(|t| !matches!(t.payload, TxPayload::EngineCreateUser { .. }))
            && !state.sync_tickets.is_empty()
        {
            blocked.push(BlockedIdentity {
                user_id: UserId::from_bytes([0; 32]),
                identity_id: IdentityId::from_bytes([0; 32]),
                missing: BlockedMissing::DisplayName,
            });
        }
        Ok(Poll {
            list,
            listen_durable,
            write_durable,
            write_ephemeral,
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
        ok.state.names.insert(*identity_id.as_bytes(), name);
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
        ok.state.names.remove(identity_id.as_bytes());
        Ok(ok)
    }

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
        state.owners.insert(
            *conversation_id.as_bytes(),
            (*user_id.as_bytes(), *identity_id.as_bytes()),
        );
        state.inviters.insert(*conversation_id.as_bytes());
        #[rustfmt::skip]
        self.post_handshake_packets(&mut state, rng, conversation_id, &conv_secret, Tag::from_bytes(tx_id))?;
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
            .or_else(|| state.sync_tickets.get(ids.conversation_id.as_bytes()))
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
        let _ = Self::require_tick(&state)?;
        let ticket = self.parse_ticket_host_string(ticket_host_string)?;
        let conversation_id = ConversationId::from(rng.random32());
        state.tickets.insert(*conversation_id.as_bytes(), ticket);
        state.owners.insert(
            *conversation_id.as_bytes(),
            (*user_id.as_bytes(), *identity_id.as_bytes()),
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
        Ok(state
            .tickets
            .keys()
            .chain(state.sync_tickets.keys())
            .filter_map(|id| {
                let conversation_id = ConversationId::from_bytes(*id);
                self.conversation_at(state, conversation_id)
                    .map(|conversation| ConversationListRow {
                        conversation_id,
                        conversation,
                    })
            })
            .collect())
    }

    fn conversation_at(
        &self,
        state: &EngineState,
        conversation_id: ConversationId,
    ) -> Option<Conversation> {
        if let Some(ticket) = state.tickets.get(conversation_id.as_bytes()) {
            if let Some(reason) = state.failed.get(conversation_id.as_bytes()) {
                return Some(Conversation::HandshakeDm(Handshake::Failed(*reason)));
            }
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
            return Some(Conversation::HandshakeDm(self.handshake_at(
                state,
                conversation_id,
                ticket,
            )));
        }
        if let Some(ticket) = state.sync_tickets.get(conversation_id.as_bytes()) {
            if let Some(reason) = state.failed.get(conversation_id.as_bytes()) {
                return Some(Conversation::HandshakeSync(Handshake::Failed(*reason)));
            }
            let has_confirm = state.txs.values().any(|t| {
                matches!(t.payload, TxPayload::Confirm) && t.conversation_id == conversation_id
            });
            let has_reject = state.txs.values().any(|t| {
                matches!(t.payload, TxPayload::Reject) && t.conversation_id == conversation_id
            });
            if has_reject {
                return Some(Conversation::HandshakeSync(Handshake::Failed(
                    FailedReason::ConfirmationRejected,
                )));
            }
            if has_confirm {
                return Some(Conversation::Synchronization(
                    SynchronizationQuery::SyncEstablished,
                ));
            }
            return Some(Conversation::HandshakeSync(self.handshake_at(
                state,
                conversation_id,
                ticket,
            )));
        }
        None
    }

    fn handshake_at(
        &self,
        state: &EngineState,
        conversation_id: ConversationId,
        ticket: &Ticket,
    ) -> Handshake {
        let pending = state
            .writes
            .iter()
            .any(|w| ticket.persistents.iter().any(|ch| ch == &w.channel));
        let notice = notice_for(state, conversation_id);
        let invitee_intro = invitee_intro_for(state, conversation_id).is_some();
        let inviter_intro = inviter_intro_for(state, conversation_id).is_some();
        let is_inviter = state.inviters.contains(conversation_id.as_bytes());
        let digest = String::new();
        if is_inviter {
            let expires = ticket.expires;
            if inviter_intro {
                if pending {
                    return Handshake::Inviter(HandshakeInviter::IntroductionMinted { expires });
                }
                return Handshake::Inviter(HandshakeInviter::Confirming {
                    expires,
                    confirmation_digest: digest,
                });
            }
            if pending {
                return Handshake::Inviter(HandshakeInviter::InviteCreated { expires });
            }
            return Handshake::Inviter(HandshakeInviter::NoticePinned { expires });
        }
        match (notice, invitee_intro, inviter_intro) {
            (Some(n), _, true) => Handshake::Invitee(HandshakeInvitee::Confirming {
                policy: n.policy,
                expires: n.expires,
                confirmation_digest: digest,
            }),
            (Some(n), true, false) if pending => {
                Handshake::Invitee(HandshakeInvitee::IntroductionMinted {
                    policy: n.policy,
                    expires: n.expires,
                })
            }
            (Some(n), true, false) => Handshake::Invitee(HandshakeInvitee::IntroductionSent {
                policy: n.policy,
                expires: n.expires,
            }),
            (Some(n), false, false) => Handshake::Invitee(HandshakeInvitee::InviteReceived {
                policy: n.policy,
                expires: n.expires,
            }),
            _ => Handshake::Invitee(HandshakeInvitee::TicketReceived),
        }
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

    fn require_confirming(
        &self,
        state: &EngineState,
        ids: &ConversationRef,
    ) -> Result<(), EngineError> {
        match self.conversation_at(state, ids.conversation_id) {
            Some(Conversation::HandshakeDm(Handshake::Inviter(HandshakeInviter::Confirming {
                ..
            })))
            | Some(Conversation::HandshakeDm(Handshake::Invitee(HandshakeInvitee::Confirming {
                ..
            })))
            | Some(Conversation::HandshakeSync(Handshake::Inviter(
                HandshakeInviter::Confirming { .. },
            )))
            | Some(Conversation::HandshakeSync(Handshake::Invitee(
                HandshakeInvitee::Confirming { .. },
            ))) => Ok(()),
            _ => Err(EngineError::WrongPhase),
        }
    }

    fn on_wire_prefs(&self) -> OnWirePrefs {
        OnWirePrefs {
            read_receipts: self.defaults.read_receipts(),
            online_visible: self.defaults.online_visible(),
            send_typing: self.defaults.send_typing(),
            disappear_after: self.defaults.disappear_after(),
            wake: None,
        }
    }

    fn identity_keys(
        &self,
        state: &EngineState,
        user_id: &UserId,
        identity_id: &IdentityId,
    ) -> Option<(Policy, Vec<u8>, Vec<u8>)> {
        state.txs.values().find_map(|tx| match &tx.payload {
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
            )),
            _ => None,
        })
    }

    fn ensure_device_keys(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        policy: Policy,
    ) -> Result<(), EngineError> {
        if state.device_enc.is_none() {
            state.device_enc = Some(
                self.suite
                    .kem()
                    .generate(policy, &KemSeed::from_pair(rng.random32(), rng.random32()))
                    .map_err(|_| EngineError::MalformedPayload)?,
            );
        }
        if state.device_sign.is_none() {
            state.device_sign = Some(
                self.suite
                    .sign()
                    .generate(policy, &SignSeed::from_pair(rng.random32(), rng.random32()))
                    .map_err(|_| EngineError::MalformedPayload)?,
            );
        }
        Ok(())
    }

    fn local_calling(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        conversation_id: ConversationId,
        policy: Policy,
    ) -> Result<Option<CallingParts>, EngineError> {
        let cid = *conversation_id.as_bytes();
        if state.sync_tickets.contains_key(&cid) {
            #[rustfmt::skip]
            let Some(name) = state.device_name.clone() else { return Ok(None); };
            self.ensure_device_keys(state, rng, policy)?;
            #[rustfmt::skip]
            let enc = state.device_enc.as_ref().ok_or(EngineError::MalformedPayload)?;
            #[rustfmt::skip]
            let sign = state.device_sign.as_ref().ok_or(EngineError::MalformedPayload)?;
            return Ok(Some((
                name,
                None,
                enc.public_bytes().to_vec(),
                sign.public_bytes().to_vec(),
            )));
        }
        #[rustfmt::skip]
        let Some((uid, iid)) = state.owners.get(&cid).copied() else { return Ok(None); };
        #[rustfmt::skip]
        let Some(name) = state.names.get(&iid).cloned() else { return Ok(None); };
        #[rustfmt::skip]
        let Some((id_policy, enc, sign)) = self.identity_keys(state, &UserId::from_bytes(uid), &IdentityId::from_bytes(iid)) else { return Ok(None); };
        if id_policy != policy {
            state
                .failed
                .insert(cid, FailedReason::PolicyNotAccepted { policy });
            return Ok(None);
        }
        let pic = state.pics.get(&iid).cloned().flatten();
        Ok(Some((name, pic, enc, sign)))
    }

    fn mint_pending_intros(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
    ) -> Result<Vec<Vec<u8>>, EngineError> {
        let cids: Vec<ConversationId> = handshake_rows(state)
            .into_iter()
            .map(|(id, _, _)| ConversationId::from_bytes(id))
            .collect();
        let mut persist = Vec::new();
        for cid in cids {
            persist.extend(self.try_mint_invitee_intro(state, rng, cid)?);
            persist.extend(self.try_mint_inviter_intro(state, rng, cid)?);
        }
        Ok(persist)
    }

    fn try_mint_invitee_intro(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        conversation_id: ConversationId,
    ) -> Result<Vec<Vec<u8>>, EngineError> {
        let cid = *conversation_id.as_bytes();
        if state.failed.contains_key(&cid) || state.inviters.contains(&cid) {
            return Ok(Vec::new());
        }
        if invitee_intro_for(state, conversation_id).is_some() {
            return Ok(Vec::new());
        }
        #[rustfmt::skip]
        let Some(notice) = notice_for(state, conversation_id).cloned() else { return Ok(Vec::new()); };
        #[rustfmt::skip]
        let Some((name, pic, enc, sign)) = self.local_calling(state, rng, conversation_id, notice.policy)? else { return Ok(Vec::new()); };
        let intake = self
            .suite
            .kem()
            .generate(
                notice.policy,
                &KemSeed::from_pair(rng.random32(), rng.random32()),
            )
            .map_err(|_| EngineError::MalformedPayload)?;
        let seed = KemSeed::from_pair(rng.random32(), rng.random32());
        #[rustfmt::skip]
        let (_, seed_ct) = self.suite.kem().wrap(notice.policy, &notice.intake_pk, &seed).map_err(|_| EngineError::MalformedPayload)?;
        let payload = TxPayload::InviteeIntro(TxInviteeIntro {
            name,
            profile_pic: pic,
            send_tag_key: TagKey::from(rng.random32()),
            eph_send_tag_key: TagKey::from(rng.random32()),
            encryption_pk: enc,
            signing_pk: sign,
            intake_pk: intake.public_bytes().to_vec(),
            seed_ct,
            prefs: self.on_wire_prefs(),
        });
        let secret = self.conv_secret(state, &conversation_id)?;
        let (tx_id, _, rec) = self.merge_tx(state, &secret, conversation_id, payload)?;
        self.post_handshake_packets(state, rng, conversation_id, &secret, Tag::from_bytes(tx_id))?;
        Ok(vec![rec])
    }

    fn try_mint_inviter_intro(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        conversation_id: ConversationId,
    ) -> Result<Vec<Vec<u8>>, EngineError> {
        let cid = *conversation_id.as_bytes();
        if state.failed.contains_key(&cid) || !state.inviters.contains(&cid) {
            return Ok(Vec::new());
        }
        if inviter_intro_for(state, conversation_id).is_some() {
            return Ok(Vec::new());
        }
        #[rustfmt::skip]
        let Some(invitee) = invitee_intro_for(state, conversation_id).cloned() else { return Ok(Vec::new()); };
        #[rustfmt::skip]
        let Some(notice) = notice_for(state, conversation_id).cloned() else { return Ok(Vec::new()); };
        #[rustfmt::skip]
        let Some((name, pic, enc, sign)) = self.local_calling(state, rng, conversation_id, notice.policy)? else { return Ok(Vec::new()); };
        let seed = KemSeed::from_pair(rng.random32(), rng.random32());
        let (_, seed_ct) = match self
            .suite
            .kem()
            .wrap(notice.policy, &invitee.intake_pk, &seed)
        {
            Ok(v) => v,
            #[rustfmt::skip]
            Err(_) => { state.failed.insert(cid, FailedReason::IntroVerifyFailed); return Ok(Vec::new()); }
        };
        if let Some(ticket) = state
            .tickets
            .get(&cid)
            .or_else(|| state.sync_tickets.get(&cid))
            .cloned()
        {
            state
                .writes
                .retain(|w| !ticket.persistents.iter().any(|ch| ch == &w.channel));
        }
        let payload = TxPayload::InviterIntro(TxInviterIntro {
            name,
            profile_pic: pic,
            send_tag_key: TagKey::from(rng.random32()),
            eph_send_tag_key: TagKey::from(rng.random32()),
            encryption_pk: enc,
            signing_pk: sign,
            seed_ct,
            prefs: self.on_wire_prefs(),
        });
        let secret = self.conv_secret(state, &conversation_id)?;
        let (tx_id, _, rec) = self.merge_tx(state, &secret, conversation_id, payload)?;
        self.post_handshake_packets(state, rng, conversation_id, &secret, Tag::from_bytes(tx_id))?;
        Ok(vec![rec])
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
                    ("mk".into(), super::codec::bstr(self.suite.b64u(), &e.mk)),
                    ("expires_at".into(), Json::Number(e.expires_at)),
                ]));
            }
            skipped.push(Json::Object(vec![
                ("key".into(), super::codec::bstr(self.suite.b64u(), key)),
                ("mks".into(), Json::Array(mks)),
            ]));
        }
        let mut frags = Vec::new();
        for (tx_id, set) in &state.frags {
            let mut parts = Vec::new();
            for (i, frag) in &set.parts {
                parts.push(Json::Object(vec![
                    ("i".into(), Json::Number(*i)),
                    ("frag".into(), super::codec::bstr(self.suite.b64u(), frag)),
                ]));
            }
            frags.push(Json::Object(vec![
                ("tx_id".into(), super::codec::bstr(self.suite.b64u(), tx_id)),
                (
                    "conversation_id".into(),
                    super::codec::bstr(self.suite.b64u(), &set.conversation_id),
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
                    super::codec::bstr(self.suite.b64u(), &progress.tag_key),
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
        for (id, reason) in &state.failed {
            failed.push(failed_to_json(self.suite.b64u(), id, *reason));
        }
        let mut owners = Vec::new();
        for (id, (uid, iid)) in &state.owners {
            owners.push(Json::Object(vec![
                (
                    "conversation_id".into(),
                    super::codec::bstr(self.suite.b64u(), id),
                ),
                ("user_id".into(), super::codec::bstr(self.suite.b64u(), uid)),
                (
                    "identity_id".into(),
                    super::codec::bstr(self.suite.b64u(), iid),
                ),
            ]));
        }
        let inviters: Vec<Json> = state
            .inviters
            .iter()
            .map(|id| super::codec::bstr(self.suite.b64u(), id))
            .collect();
        let device_enc = state
            .device_enc
            .as_ref()
            .map(|k| keypair_json(self.suite.b64u(), k.public_bytes(), k.secret_bytes()))
            .unwrap_or(Json::Null);
        let device_sign = state
            .device_sign
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

    /// Drop a conversation row.
    pub fn delete_conversation(
        &self,
        mut state: EngineState,
        ids: ConversationRef,
    ) -> Result<MutateOk, EngineError> {
        self.require_ids(&state, &ids)?;
        let cid = *ids.conversation_id.as_bytes();
        let ticket = state
            .tickets
            .get(&cid)
            .or_else(|| state.sync_tickets.get(&cid))
            .cloned()
            .ok_or(EngineError::UnknownIds)?;
        state.tickets.remove(&cid);
        state.sync_tickets.remove(&cid);
        state
            .send_chains
            .retain(|k, _| k.get(..32) != Some(cid.as_slice()));
        state
            .recv_chains
            .retain(|k, _| k.get(..32) != Some(cid.as_slice()));
        state
            .skipped_mks
            .retain(|k, _| k.get(..32) != Some(cid.as_slice()));
        state.frags.retain(|_, f| f.conversation_id != cid);
        state.failed.remove(&cid);
        state.owners.remove(&cid);
        state.inviters.remove(&cid);
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
    /// `BinProgress`. A valid `TxNotice` is `InviteReceived`. A valid intro
    /// advances IntroductionMinted / Confirming. Unlock and policy failures
    /// store `FailedReason`.
    pub fn ingest_list(
        &self,
        state: EngineState,
        rng: &dyn Rng,
        channel: DurableChannel,
        tag: Tag,
        bodies: &[Vec<u8>],
    ) -> Result<MutateOk, EngineError> {
        let now = Self::require_tick(&state)?;
        let _ = self.require_dek()?;
        let hits = self.handshake_hits(&state, &channel, &tag, now);
        if hits.is_empty() {
            return Err(EngineError::UnknownTag);
        }
        let mut state = state;
        let mut persist = Vec::new();
        for body in bodies {
            persist.extend(self.ingest_known_body(&mut state, rng, &hits, body)?);
        }
        self.complete_list_bin(&mut state, &channel, &hits[0], now);
        Ok(MutateOk {
            state,
            persist,
            pings: Vec::new(),
        })
    }

    /// Ingest one 512-byte mapper body. Opens with skip-ahead `mk` and
    /// reassembles fragments.
    pub fn ingest_packet(
        &self,
        mut state: EngineState,
        rng: &dyn Rng,
        channel: DurableChannel,
        tag: Tag,
        body: &[u8],
    ) -> Result<MutateOk, EngineError> {
        let now = Self::require_tick(&state)?;
        let _ = self.require_dek()?;
        let hits = self.handshake_hits(&state, &channel, &tag, now);
        if hits.is_empty() {
            return Err(EngineError::UnknownTag);
        }
        let persist = self.ingest_known_body(&mut state, rng, &hits, body)?;
        Ok(MutateOk {
            state,
            persist,
            pings: Vec::new(),
        })
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
        state.device_id = Some(
            state
                .device_id
                .unwrap_or_else(|| DeviceId::from(rng.random32())),
        );
        let intake = self
            .suite
            .kem()
            .generate(policy, &KemSeed::from_pair(rng.random32(), rng.random32()))
            .map_err(|_| EngineError::MalformedPayload)?;
        if state.device_enc.is_none() {
            state.device_enc = Some(
                self.suite
                    .kem()
                    .generate(policy, &KemSeed::from_pair(rng.random32(), rng.random32()))
                    .map_err(|_| EngineError::MalformedPayload)?,
            );
        }
        if state.device_sign.is_none() {
            state.device_sign = Some(
                self.suite
                    .sign()
                    .generate(policy, &SignSeed::from_pair(rng.random32(), rng.random32()))
                    .map_err(|_| EngineError::MalformedPayload)?,
            );
        }
        let conv_secret = *secret.as_bytes();
        let payload = TxPayload::Notice(TxNotice {
            policy,
            intake_pk: intake.public_bytes().to_vec(),
            persistents: persistents.clone(),
            ephemerals: self.defaults.ephemerals().to_vec(),
            expires,
        });
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
        let ticket = Ticket {
            secret,
            persistents: persistents.clone(),
            expires,
        };
        state
            .sync_tickets
            .insert(*conversation_id.as_bytes(), ticket);
        state.inviters.insert(*conversation_id.as_bytes());
        state.device_name = Some(name);
        #[rustfmt::skip]
        self.post_handshake_packets(&mut state, rng, conversation_id, &conv_secret, Tag::from_bytes(tx_id))?;
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
            .txs
            .values()
            .any(|t| matches!(t.payload, TxPayload::EngineCreateUser { .. }))
        {
            return Err(EngineError::EmptyEngineRequired);
        }
        let _ = Self::require_tick(&state)?;
        let ticket = self.parse_ticket_host_string(ticket_host_string)?;
        let conversation_id = ConversationId::from(rng.random32());
        let mut state = state;
        state
            .sync_tickets
            .insert(*conversation_id.as_bytes(), ticket);
        Ok((
            MutateOk {
                state,
                persist: Vec::new(),
                pings: Vec::new(),
            },
            conversation_id,
        ))
    }

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
                m.state.device_name = Some(name);
                let extra = self.mint_pending_intros(&mut m.state, rng)?;
                m.persist.extend(extra);
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
        let sync_ids: Vec<[u8; 32]> = state.sync_tickets.keys().copied().collect();
        state.sync_tickets.clear();
        let drop_sync = |k: &Vec<u8>| {
            k.get(..32)
                .and_then(|id| id.try_into().ok())
                .is_none_or(|id: [u8; 32]| !sync_ids.contains(&id))
        };
        state.send_chains.retain(|k, _| drop_sync(k));
        state.recv_chains.retain(|k, _| drop_sync(k));
        state.skipped_mks.retain(|k, _| drop_sync(k));
        for id in &sync_ids {
            state.failed.remove(id);
            state.owners.remove(id);
            state.inviters.remove(id);
        }
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

    /// Confirm a handshake fingerprint. Legal on `Confirming`.
    pub fn confirm_established(
        &self,
        state: EngineState,
        _rng: &dyn Rng,
        ids: ConversationRef,
    ) -> Result<MutateOk, EngineError> {
        self.require_confirming(&state, &ids)?;
        if state
            .sync_tickets
            .contains_key(ids.conversation_id.as_bytes())
        {
            let secret = self.conv_secret(&state, &ids.conversation_id)?;
            return self.mutate_on(
                state,
                &secret,
                ids.conversation_id,
                vec![TxPayload::Confirm],
            );
        }
        self.mint_on(state, &ids, TxPayload::Confirm)
    }

    /// Reject a handshake fingerprint. Legal on `Confirming`.
    pub fn reject_established(
        &self,
        state: EngineState,
        _rng: &dyn Rng,
        ids: ConversationRef,
    ) -> Result<MutateOk, EngineError> {
        self.require_confirming(&state, &ids)?;
        if state
            .sync_tickets
            .contains_key(ids.conversation_id.as_bytes())
        {
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
                    tx_id,
                    FragSet {
                        conversation_id,
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
                let key = progress_key(&channel, &tag_key);
                state.bin_progress.insert(
                    key,
                    BinProgress {
                        channel,
                        tag_key,
                        watermark,
                        completed,
                    },
                );
            }
        } else if get("bins").is_some() {
            return Err(EngineError::MalformedPersist);
        }
        if let Some(Json::Array(items)) = get("failed") {
            for item in items {
                let (cid, reason) = parse_failed(self.suite.b64u(), item)?;
                state.failed.insert(cid, reason);
            }
        } else if get("failed").is_some() {
            return Err(EngineError::MalformedPersist);
        }
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
                state.owners.insert(cid, (uid, iid));
            }
        } else if get("owners").is_some() {
            return Err(EngineError::MalformedPersist);
        }
        if let Some(Json::Array(items)) = get("inviters") {
            for item in items {
                state
                    .inviters
                    .insert(decode_fold32(self.suite.b64u(), item)?);
            }
        } else if get("inviters").is_some() {
            return Err(EngineError::MalformedPersist);
        }
        match get("device_enc") {
            Some(Json::Null) | None => {}
            Some(v) => {
                let (pk, sk) = parse_fold_keypair(self.suite.b64u(), v)?;
                state.device_enc = Some(KeyPair::from_parts(pk, sk));
            }
        }
        match get("device_sign") {
            Some(Json::Null) | None => {}
            Some(v) => {
                let (pk, sk) = parse_fold_keypair(self.suite.b64u(), v)?;
                state.device_sign = Some(SigningKeyPair::from_parts(pk, sk));
            }
        }
        Ok(state)
    }

    fn parse_ticket_host_string(&self, ticket_host_string: &str) -> Result<Ticket, EngineError> {
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

    fn handshake_hits(
        &self,
        state: &EngineState,
        channel: &DurableChannel,
        tag: &Tag,
        now: u64,
    ) -> Vec<HandshakeHit> {
        let w = time_bin(now);
        let start = window_start(w);
        let end = w.saturating_add(1);
        let mut hits = Vec::new();
        for (cid, ticket, sort) in handshake_rows(state) {
            if !ticket.persistents.iter().any(|ch| ch == channel) {
                continue;
            }
            let secret = *ticket.secret.as_bytes();
            let tag_key = handshake_tag_key(self.suite.hmac(), &secret);
            for bin in start..=end {
                if invite_tag(self.suite.hmac(), &secret, bin) == *tag {
                    hits.push(HandshakeHit {
                        cid,
                        secret,
                        sort,
                        bin,
                        tag_key,
                    });
                }
            }
        }
        hits
    }

    fn ingest_known_body(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        hits: &[HandshakeHit],
        body: &[u8],
    ) -> Result<Vec<Vec<u8>>, EngineError> {
        let now = Self::require_tick(state)?;
        for hit in hits {
            match self.open_and_merge(state, rng, hit, now, body) {
                Ok(persist) => return Ok(persist),
                Err(EngineError::UnknownTag) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(Vec::new())
    }

    fn open_and_merge(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        hit: &HandshakeHit,
        now: u64,
        body: &[u8],
    ) -> Result<Vec<Vec<u8>>, EngineError> {
        if matches!(
            state.failed.get(&hit.cid),
            Some(FailedReason::InviteExpired { .. })
        ) {
            return Err(EngineError::WrongPhase);
        }
        if state.failed.contains_key(&hit.cid) {
            return Err(EngineError::UnknownTag);
        }
        let key = chain_key(&ConversationId::from_bytes(hit.cid), &[]);
        let start = join(self.suite.hmac(), &hit.secret, hit.sort, &[])?;
        let mut cached = state.skipped_mks.get(&key).cloned().unwrap_or_default();
        cached.retain(|e| e.expires_at > now);
        let opened = open_skip_ahead(&self.suite, &start, &cached, now, body)?;
        cached.extend(opened.skipped);
        cached.retain(|e| e.expires_at > now);
        if cached.is_empty() {
            state.skipped_mks.remove(&key);
        } else {
            state.skipped_mks.insert(key.clone(), cached);
        }
        if !opened.from_cache {
            state.recv_chains.insert(key, opened.chain);
        } else {
            state.recv_chains.entry(key).or_insert(start);
        }
        let Some(part) = frag_parts(&opened.packet) else {
            return Ok(Vec::new());
        };
        let set = state.frags.entry(part.tx_id).or_insert_with(|| FragSet {
            conversation_id: hit.cid,
            parts: BTreeMap::new(),
            last_i: None,
        });
        if let Some(existing) = set.parts.get(&part.frag_i)
            && existing != &part.frag
        {
            return Err(EngineError::Equivocation);
        }
        if let Some(prev_last) = set.last_i
            && let Some(new_last) = part.last_i
            && prev_last != new_last
        {
            return Err(EngineError::Equivocation);
        }
        set.parts.insert(part.frag_i, part.frag);
        if let Some(n) = part.last_i {
            set.last_i = Some(n);
        }
        let Some(last) = set.last_i else {
            return Ok(Vec::new());
        };
        for i in 0..=last {
            if !set.parts.contains_key(&i) {
                return Ok(Vec::new());
            }
        }
        let mut packed = Vec::new();
        for i in 0..=last {
            packed.extend_from_slice(&set.parts[&i]);
        }
        state.frags.remove(&part.tx_id);
        let canonical = match self
            .suite
            .compress()
            .decompress(&packed, PACKET_MAX_UNCOMPRESSED)
        {
            Ok(c) => c,
            #[rustfmt::skip]
            Err(_) => { store_unlock_failed(state, hit.cid); return Ok(Vec::new()); }
        };
        let json = match self.suite.canonical_json().decode(&canonical) {
            Ok(j) => j,
            #[rustfmt::skip]
            Err(_) => { store_unlock_failed(state, hit.cid); return Ok(Vec::new()); }
        };
        let durable = match durable_body_from_json(self.suite.b64u(), &json) {
            Ok(b) => b,
            #[rustfmt::skip]
            Err(()) => { store_unlock_failed(state, hit.cid); return Ok(Vec::new()); }
        };
        if *durable.conversation_id.as_bytes() != hit.cid {
            rekey_conversation(state, hit.cid, *durable.conversation_id.as_bytes());
        }
        if let Some(existing) = state.txs.get(&part.tx_id) {
            if existing.payload == durable.payload {
                return Ok(Vec::new());
            }
            return Err(EngineError::Equivocation);
        }
        let cid = *durable.conversation_id.as_bytes();
        if let Some(extra) = self.handshake_ingest_gate(state, cid, &durable.payload)? {
            return Ok(extra);
        }
        let persist = self.persist_record(state.next_seq, &durable)?;
        state.next_seq = state.next_seq.saturating_add(1);
        state.txs.insert(part.tx_id, durable);
        let conversation_id = ConversationId::from_bytes(cid);
        let mut out = vec![persist];
        out.extend(self.try_mint_invitee_intro(state, rng, conversation_id)?);
        out.extend(self.try_mint_inviter_intro(state, rng, conversation_id)?);
        Ok(out)
    }

    fn handshake_ingest_gate(
        &self,
        state: &mut EngineState,
        cid: [u8; 32],
        payload: &TxPayload,
    ) -> Result<Option<Vec<Vec<u8>>>, EngineError> {
        let conversation_id = ConversationId::from_bytes(cid);
        match payload {
            TxPayload::Notice(n) => {
                if let Some(existing) = notice_for(state, conversation_id)
                    && existing != n
                {
                    state.failed.insert(cid, FailedReason::NoticeConflict);
                    return Ok(Some(Vec::new()));
                }
                if let Some((uid, iid)) = state.owners.get(&cid).copied()
                    && let Ok(policy) = self.identity_policy(
                        state,
                        &UserId::from_bytes(uid),
                        &IdentityId::from_bytes(iid),
                    )
                    && policy != n.policy
                {
                    state
                        .failed
                        .insert(cid, FailedReason::PolicyNotAccepted { policy: n.policy });
                }
                Ok(None)
            }
            TxPayload::InviteeIntro(i) => {
                if invitee_intro_for(state, conversation_id).is_some() {
                    state.failed.insert(cid, FailedReason::DuplicateIntro);
                    return Ok(Some(Vec::new()));
                }
                let Some(notice) = notice_for(state, conversation_id) else {
                    state.failed.insert(cid, FailedReason::IntroVerifyFailed);
                    return Ok(Some(Vec::new()));
                };
                if !intro_keys_ok(
                    notice.policy,
                    &i.encryption_pk,
                    &i.signing_pk,
                    Some(&i.intake_pk),
                    &i.seed_ct,
                ) {
                    state.failed.insert(cid, FailedReason::IntroVerifyFailed);
                    return Ok(Some(Vec::new()));
                }
                Ok(None)
            }
            TxPayload::InviterIntro(i) => {
                if inviter_intro_for(state, conversation_id).is_some() {
                    state.failed.insert(cid, FailedReason::DuplicateIntro);
                    return Ok(Some(Vec::new()));
                }
                #[rustfmt::skip]
                let Some(notice) = notice_for(state, conversation_id) else { state.failed.insert(cid, FailedReason::IntroVerifyFailed); return Ok(Some(Vec::new())); };
                if !intro_keys_ok(
                    notice.policy,
                    &i.encryption_pk,
                    &i.signing_pk,
                    None,
                    &i.seed_ct,
                ) {
                    state.failed.insert(cid, FailedReason::IntroVerifyFailed);
                    return Ok(Some(Vec::new()));
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    fn complete_list_bin(
        &self,
        state: &mut EngineState,
        channel: &DurableChannel,
        hit: &HandshakeHit,
        now: u64,
    ) {
        let start = window_start(time_bin(now));
        let key = progress_key(channel, &hit.tag_key);
        let progress = state
            .bin_progress
            .entry(key)
            .or_insert_with(|| BinProgress {
                channel: channel.clone(),
                tag_key: hit.tag_key,
                watermark: None,
                completed: BTreeSet::new(),
            });
        prune_progress(progress, start);
        if progress.watermark.is_some_and(|w| hit.bin <= w) {
            return;
        }
        progress.completed.insert(hit.bin);
        loop {
            let next = match progress.watermark {
                None => start,
                Some(w) => w.saturating_add(1),
            };
            if progress.completed.remove(&next) {
                progress.watermark = Some(next);
            } else {
                break;
            }
        }
    }
}

fn notice_for(state: &EngineState, conversation_id: ConversationId) -> Option<&TxNotice> {
    state.txs.values().find_map(|t| match &t.payload {
        TxPayload::Notice(n) if t.conversation_id == conversation_id => Some(n),
        _ => None,
    })
}

fn invitee_intro_for(
    state: &EngineState,
    conversation_id: ConversationId,
) -> Option<&TxInviteeIntro> {
    state.txs.values().find_map(|t| match &t.payload {
        TxPayload::InviteeIntro(i) if t.conversation_id == conversation_id => Some(i),
        _ => None,
    })
}

fn inviter_intro_for(
    state: &EngineState,
    conversation_id: ConversationId,
) -> Option<&TxInviterIntro> {
    state.txs.values().find_map(|t| match &t.payload {
        TxPayload::InviterIntro(i) if t.conversation_id == conversation_id => Some(i),
        _ => None,
    })
}

fn intro_keys_ok(
    policy: Policy,
    encryption_pk: &[u8],
    signing_pk: &[u8],
    intake_pk: Option<&[u8]>,
    seed_ct: &[u8],
) -> bool {
    encryption_pk.len() == kem_pk_len(policy)
        && signing_pk.len() == sign_pk_len(policy)
        && seed_ct.len() == kem_ct_len(policy)
        && intake_pk.is_none_or(|pk| pk.len() == kem_pk_len(policy))
}

fn store_unlock_failed(state: &mut EngineState, cid: [u8; 32]) {
    if state.failed.contains_key(&cid) {
        return;
    }
    let conversation_id = ConversationId::from_bytes(cid);
    let reason = if notice_for(state, conversation_id).is_some() || state.inviters.contains(&cid) {
        FailedReason::IntroUnlockFailed
    } else {
        FailedReason::NoticeUnlockFailed
    };
    state.failed.insert(cid, reason);
}

fn handshake_rows(state: &EngineState) -> Vec<([u8; 32], Ticket, ConversationSort)> {
    let mut rows = Vec::new();
    for (id, ticket) in &state.tickets {
        rows.push((*id, ticket.clone(), ConversationSort::HandshakeDm));
    }
    for (id, ticket) in &state.sync_tickets {
        rows.push((*id, ticket.clone(), ConversationSort::HandshakeSync));
    }
    rows
}

fn window_start(w: u64) -> u64 {
    w.saturating_sub(BIN_WINDOW.saturating_sub(1))
}

fn listen_bins(w: u64) -> [u64; 3] {
    [w.saturating_sub(1), w, w.saturating_add(1)]
}

fn handshake_tag_key(hmac: &dyn HmacSha256, secret: &[u8; 32]) -> [u8; 32] {
    expand(
        hmac,
        &HmacSha256Key::from_bytes(*secret),
        b"chuchotez/1/handshake-invite",
    )
    .into_bytes()
}

fn invite_tag(hmac: &dyn HmacSha256, secret: &[u8; 32], bin: u64) -> Tag {
    Tag::from_bytes(
        expand(
            hmac,
            &HmacSha256Key::from_bytes(*secret),
            &[
                b"chuchotez/1/handshake-invite".as_slice(),
                &bin.to_be_bytes(),
            ]
            .concat(),
        )
        .into_bytes(),
    )
}

fn progress_key(channel: &DurableChannel, tag_key: &[u8; 32]) -> (String, String, [u8; 32]) {
    (
        channel.kind().as_str().into(),
        channel.address().as_str().into(),
        *tag_key,
    )
}

fn bin_complete(progress: Option<&BinProgress>, bin: u64) -> bool {
    let Some(p) = progress else {
        return false;
    };
    p.watermark.is_some_and(|w| bin <= w) || p.completed.contains(&bin)
}

fn prune_progress(progress: &mut BinProgress, start: u64) {
    if let Some(w) = progress.watermark
        && w < start
    {
        progress.watermark = None;
    }
    progress.completed.retain(|&b| b >= start);
    loop {
        let next = match progress.watermark {
            None => start,
            Some(w) => w.saturating_add(1),
        };
        if progress.completed.remove(&next) {
            progress.watermark = Some(next);
        } else {
            break;
        }
    }
}

fn locator_ord(a: &DurableLocator, b: &DurableLocator) -> Ordering {
    a.channel
        .kind()
        .as_str()
        .cmp(b.channel.kind().as_str())
        .then_with(|| {
            a.channel
                .address()
                .as_str()
                .cmp(b.channel.address().as_str())
        })
        .then_with(|| a.tag.as_bytes().cmp(b.tag.as_bytes()))
}

fn sort_durable_locators(locators: &mut [DurableLocator]) {
    locators.sort_by(locator_ord);
}

fn sort_durable_writes(writes: &mut [DurableWrite]) {
    writes.sort_by(|a, b| {
        locator_ord(
            &DurableLocator {
                channel: a.channel.clone(),
                tag: a.tag,
            },
            &DurableLocator {
                channel: b.channel.clone(),
                tag: b.tag,
            },
        )
    });
}

fn sort_ephemeral_writes(writes: &mut [EphemeralWrite]) {
    writes.sort_by(|a, b| {
        a.channel
            .kind()
            .as_str()
            .cmp(b.channel.kind().as_str())
            .then_with(|| {
                a.channel
                    .address()
                    .as_str()
                    .cmp(b.channel.address().as_str())
            })
            .then_with(|| a.tag.as_bytes().cmp(b.tag.as_bytes()))
    });
}

struct FragPart {
    tx_id: [u8; 32],
    frag_i: u64,
    frag: Vec<u8>,
    last_i: Option<u64>,
}

fn frag_parts(packet: &PacketPlain) -> Option<FragPart> {
    match packet {
        PacketPlain::TxFragMore(p) => Some(FragPart {
            tx_id: *p.tx_id.as_bytes(),
            frag_i: p.frag_i,
            frag: p.frag.clone(),
            last_i: None,
        }),
        PacketPlain::TxFragLast(p) => Some(FragPart {
            tx_id: *p.tx_id.as_bytes(),
            frag_i: p.frag_i,
            frag: p.frag.clone(),
            last_i: Some(p.frag_i),
        }),
        _ => None,
    }
}

fn rekey_conversation(state: &mut EngineState, from: [u8; 32], to: [u8; 32]) {
    if let Some(t) = state.tickets.remove(&from) {
        state.tickets.insert(to, t);
    }
    if let Some(t) = state.sync_tickets.remove(&from) {
        state.sync_tickets.insert(to, t);
    }
    if let Some(v) = state.failed.remove(&from) {
        state.failed.insert(to, v);
    }
    if let Some(v) = state.owners.remove(&from) {
        state.owners.insert(to, v);
    }
    if state.inviters.remove(&from) {
        state.inviters.insert(to);
    }
    rekey_prefix(&mut state.send_chains, from, to);
    rekey_prefix(&mut state.recv_chains, from, to);
    rekey_prefix(&mut state.skipped_mks, from, to);
    for frag in state.frags.values_mut() {
        frag.conversation_id = rekey_cid(frag.conversation_id, from, to);
    }
}

#[rustfmt::skip]
fn rekey_cid(cid: [u8; 32], from: [u8; 32], to: [u8; 32]) -> [u8; 32] {
    if cid == from { to } else { cid }
}

#[rustfmt::skip]
fn rekey_prefix<V>(map: &mut BTreeMap<Vec<u8>, V>, from: [u8; 32], to: [u8; 32]) {
    *map = std::mem::take(map).into_iter().map(|(k, v)| {
        if k.len() >= 32 && k[..32] == from { let mut nk = to.to_vec(); nk.extend_from_slice(&k[32..]); (nk, v) } else { (k, v) }
    }).collect();
}

fn decode_fold_bstr(b64u: &dyn super::Base64Url, value: &Json) -> Result<Vec<u8>, EngineError> {
    let Json::String(s) = value else {
        return Err(EngineError::MalformedPersist);
    };
    b64u.decode(s).map_err(|_| EngineError::MalformedPersist)
}

fn decode_fold32(b64u: &dyn super::Base64Url, value: &Json) -> Result<[u8; 32], EngineError> {
    decode_fold_bstr(b64u, value)?
        .try_into()
        .map_err(|_| EngineError::MalformedPersist)
}

fn keypair_json(b64u: &dyn super::Base64Url, pk: &[u8], sk: &[u8]) -> Json {
    Json::Object(vec![
        ("pk".into(), super::codec::bstr(b64u, pk)),
        ("sk".into(), super::codec::bstr(b64u, sk)),
    ])
}

fn parse_fold_keypair(
    b64u: &dyn super::Base64Url,
    value: &Json,
) -> Result<(Vec<u8>, Vec<u8>), EngineError> {
    let Json::Object(m) = value else {
        return Err(EngineError::MalformedPersist);
    };
    let get = |k: &str| m.iter().find(|(n, _)| n == k).map(|(_, v)| v);
    let pk = decode_fold_bstr(b64u, get("pk").ok_or(EngineError::MalformedPersist)?)?;
    let sk = decode_fold_bstr(b64u, get("sk").ok_or(EngineError::MalformedPersist)?)?;
    Ok((pk, sk))
}

fn failed_to_json(b64u: &dyn super::Base64Url, id: &[u8; 32], reason: FailedReason) -> Json {
    let mut members = vec![
        ("conversation_id".into(), super::codec::bstr(b64u, id)),
        (
            "reason".into(),
            Json::String(
                match reason {
                    FailedReason::PolicyNotAccepted { .. } => "PolicyNotAccepted",
                    FailedReason::InviteExpired { .. } => "InviteExpired",
                    FailedReason::NoticeUnlockFailed => "NoticeUnlockFailed",
                    FailedReason::NoticeConflict => "NoticeConflict",
                    FailedReason::IntroUnlockFailed => "IntroUnlockFailed",
                    FailedReason::IntroVerifyFailed => "IntroVerifyFailed",
                    FailedReason::DuplicateIntro => "DuplicateIntro",
                    FailedReason::ConfirmationRejected => "ConfirmationRejected",
                    FailedReason::Equivocation => "Equivocation",
                    FailedReason::OfferRejected => "OfferRejected",
                    FailedReason::Kicked => "Kicked",
                    FailedReason::Left => "Left",
                }
                .into(),
            ),
        ),
    ];
    match reason {
        FailedReason::PolicyNotAccepted { policy } => {
            members.push(("policy".into(), Json::String(policy_str(policy).into())));
        }
        FailedReason::InviteExpired { expires } => {
            members.push(("expires".into(), Json::Number(expires)));
        }
        _ => {}
    }
    Json::Object(members)
}

fn parse_failed(
    b64u: &dyn super::Base64Url,
    value: &Json,
) -> Result<([u8; 32], FailedReason), EngineError> {
    let Json::Object(m) = value else {
        return Err(EngineError::MalformedPersist);
    };
    let get = |k: &str| m.iter().find(|(n, _)| n == k).map(|(_, v)| v);
    #[rustfmt::skip]
    let cid = decode_fold32(b64u, get("conversation_id").ok_or(EngineError::MalformedPersist)?)?;
    let Json::String(reason) = get("reason").ok_or(EngineError::MalformedPersist)? else {
        return Err(EngineError::MalformedPersist);
    };
    let parsed = match reason.as_str() {
        "PolicyNotAccepted" => {
            let Json::String(p) = get("policy").ok_or(EngineError::MalformedPersist)? else {
                return Err(EngineError::MalformedPersist);
            };
            FailedReason::PolicyNotAccepted {
                policy: parse_policy(p).ok_or(EngineError::MalformedPersist)?,
            }
        }
        "InviteExpired" => {
            let Json::Number(expires) = get("expires").ok_or(EngineError::MalformedPersist)? else {
                return Err(EngineError::MalformedPersist);
            };
            FailedReason::InviteExpired { expires: *expires }
        }
        "NoticeUnlockFailed" => FailedReason::NoticeUnlockFailed,
        "NoticeConflict" => FailedReason::NoticeConflict,
        "IntroUnlockFailed" => FailedReason::IntroUnlockFailed,
        "IntroVerifyFailed" => FailedReason::IntroVerifyFailed,
        "DuplicateIntro" => FailedReason::DuplicateIntro,
        "ConfirmationRejected" => FailedReason::ConfirmationRejected,
        "Equivocation" => FailedReason::Equivocation,
        "OfferRejected" => FailedReason::OfferRejected,
        "Kicked" => FailedReason::Kicked,
        "Left" => FailedReason::Left,
        _ => return Err(EngineError::MalformedPersist),
    };
    Ok((cid, parsed))
}

fn parse_fold_channel(value: &Json) -> Result<DurableChannel, EngineError> {
    let Json::Object(m) = value else {
        return Err(EngineError::MalformedPersist);
    };
    let get = |k: &str| m.iter().find(|(n, _)| n == k).map(|(_, v)| v);
    let Json::String(kind) = get("kind").ok_or(EngineError::MalformedPersist)? else {
        return Err(EngineError::MalformedPersist);
    };
    let Json::String(address) = get("address").ok_or(EngineError::MalformedPersist)? else {
        return Err(EngineError::MalformedPersist);
    };
    let kind = Kind::try_from(kind.as_str()).map_err(|_| EngineError::MalformedPersist)?;
    let address = Address::try_from(address.as_str()).map_err(|_| EngineError::MalformedPersist)?;
    Ok(DurableChannel::new(kind, address))
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
        let set = engine
            .set_defaults(
                set.state,
                engine.get_defaults(&EngineState::new()).expect("gd2"),
            )
            .expect("set2");
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
        assert_eq!(w.body.len(), crate::protocol::v1::PACKET_LEN);
        let mut acked = engine
            .write_ack(invited.state.clone(), w.channel.clone(), w.tag, &w.body)
            .expect("ack");
        for write in poll.write_durable.iter().skip(1) {
            acked = engine
                .write_ack(acked.state, write.channel.clone(), write.tag, &write.body)
                .expect("ackn");
        }
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
        assert!(invited.state.send_chain_seq(&cid).unwrap() >= 1);
        assert_eq!(
            invited.state.send_chain_seq(&cid),
            restored.send_chain_seq(&cid)
        );
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
        assert_eq!(
            engine
                .confirm_established(acked.state.clone(), &rng, ids)
                .unwrap_err(),
            EngineError::WrongPhase
        );
        assert_eq!(
            engine
                .reject_established(acked.state.clone(), &rng, ids)
                .unwrap_err(),
            EngineError::WrongPhase
        );
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
        assert!(
            engine
                .ingest_list(
                    invited.state.clone(),
                    &rng,
                    w.channel.clone(),
                    w.tag,
                    &[vec![1]]
                )
                .is_ok()
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
        assert_eq!(
            engine
                .confirm_established(invited.state.clone(), &rng, ids)
                .unwrap_err(),
            EngineError::WrongPhase
        );
        assert_eq!(
            engine
                .reject_established(invited.state.clone(), &rng, ids)
                .unwrap_err(),
            EngineError::WrongPhase
        );
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
        let _ = engine
            .create_sync_invite(
                sync_ok.state.clone(),
                &rng,
                Policy::Classic,
                1_900_000_001,
                "phone2",
                None,
            )
            .expect("sy2");
        assert_eq!(
            engine.poll(&sync_ok.state).expect("sp").write_durable[0]
                .body
                .len(),
            crate::protocol::v1::PACKET_LEN
        );
        assert!(sync_ok.state.send_chain_seq(&sid).unwrap() >= 1);
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
        assert_eq!(
            engine
                .confirm_established(invited.state.clone(), &rng, ids)
                .unwrap_err(),
            EngineError::WrongPhase
        );
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
        assert_eq!(
            engine
                .apply_folded(&seal_fold(
                    &engine,
                    Json::Object(vec![
                        ("next_seq".into(), Json::Number(1)),
                        ("chains".into(), Json::Number(1)),
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
                        ("chains".into(), Json::Array(vec![Json::Null])),
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
                        ("recv_chains".into(), Json::Number(1)),
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
                        ("skipped_mks".into(), Json::Number(1)),
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
                        ("skipped_mks".into(), Json::Array(vec![Json::Null])),
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
                            "skipped_mks".into(),
                            Json::Array(vec![Json::Object(vec![("key".into(), Json::Number(1))])])
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
                        ("frags".into(), Json::Number(1)),
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
                        ("frags".into(), Json::Array(vec![Json::Null])),
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
                        ("bins".into(), Json::Number(1)),
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
                        ("bins".into(), Json::Array(vec![Json::Null])),
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
                            "bins".into(),
                            Json::Array(vec![Json::Object(vec![("channel".into(), Json::Null)])])
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
                        (
                            "skipped_mks".into(),
                            Json::Array(vec![Json::Object(vec![
                                ("key".into(), Json::String("00".repeat(32))),
                                ("mks".into(), Json::Number(1)),
                            ])])
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
                        (
                            "skipped_mks".into(),
                            Json::Array(vec![Json::Object(vec![
                                ("key".into(), Json::String("00".repeat(32))),
                                ("mks".into(), Json::Array(vec![Json::Null])),
                            ])])
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
                        (
                            "frags".into(),
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
                        (
                            "frags".into(),
                            Json::Array(vec![Json::Object(vec![
                                ("tx_id".into(), Json::String("00".repeat(32))),
                                ("conversation_id".into(), Json::String("00".repeat(32))),
                                ("last_i".into(), Json::Bool(true)),
                                ("parts".into(), Json::Array(Vec::new())),
                            ])])
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
                        (
                            "frags".into(),
                            Json::Array(vec![Json::Object(vec![
                                ("tx_id".into(), Json::String("00".repeat(32))),
                                ("conversation_id".into(), Json::String("00".repeat(32))),
                                ("last_i".into(), Json::Null),
                                ("parts".into(), Json::Number(1)),
                            ])])
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
                        (
                            "frags".into(),
                            Json::Array(vec![Json::Object(vec![
                                ("tx_id".into(), Json::String("00".repeat(32))),
                                ("conversation_id".into(), Json::String("00".repeat(32))),
                                ("last_i".into(), Json::Null),
                                ("parts".into(), Json::Array(vec![Json::Null])),
                            ])])
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
                        (
                            "bins".into(),
                            Json::Array(vec![Json::Object(vec![
                                (
                                    "channel".into(),
                                    Json::Object(vec![
                                        ("kind".into(), Json::Number(1)),
                                        ("address".into(), Json::String("x".into())),
                                    ])
                                ),
                                ("tag_key".into(), Json::String("00".repeat(32))),
                                ("watermark".into(), Json::Null),
                                ("completed".into(), Json::Array(Vec::new())),
                            ])])
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
                        (
                            "bins".into(),
                            Json::Array(vec![Json::Object(vec![
                                (
                                    "channel".into(),
                                    Json::Object(vec![
                                        ("kind".into(), Json::String("nostr".into())),
                                        ("address".into(), Json::Number(1)),
                                    ])
                                ),
                                ("tag_key".into(), Json::String("00".repeat(32))),
                                ("watermark".into(), Json::Null),
                                ("completed".into(), Json::Array(Vec::new())),
                            ])])
                        ),
                    ]),
                    0
                ))
                .unwrap_err(),
            EngineError::MalformedPersist
        );
        let hex32 = "00".repeat(32);
        assert_eq!(
            engine
                .apply_folded(&seal_fold(
                    &engine,
                    Json::Object(vec![
                        ("next_seq".into(), Json::Number(1)),
                        (
                            "skipped_mks".into(),
                            Json::Array(vec![Json::Object(vec![
                                ("key".into(), Json::String(hex32.clone())),
                                (
                                    "mks".into(),
                                    Json::Array(vec![Json::Object(vec![
                                        ("mk".into(), Json::String(hex32.clone())),
                                        ("expires_at".into(), Json::Bool(true)),
                                    ])])
                                ),
                            ])])
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
                        (
                            "skipped_mks".into(),
                            Json::Array(vec![Json::Object(vec![
                                ("key".into(), Json::String(hex32.clone())),
                                (
                                    "mks".into(),
                                    Json::Array(vec![Json::Object(vec![(
                                        "expires_at".into(),
                                        Json::Number(1)
                                    )])])
                                ),
                            ])])
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
                        (
                            "skipped_mks".into(),
                            Json::Array(vec![Json::Object(vec![
                                ("key".into(), Json::String(hex32.clone())),
                                (
                                    "mks".into(),
                                    Json::Array(vec![Json::Object(vec![
                                        ("mk".into(), Json::String("00".into())),
                                        ("expires_at".into(), Json::Number(1)),
                                    ])])
                                ),
                            ])])
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
                        (
                            "frags".into(),
                            Json::Array(vec![Json::Object(vec![
                                ("tx_id".into(), Json::String(hex32.clone())),
                                ("conversation_id".into(), Json::String("00".into())),
                            ])])
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
                        (
                            "frags".into(),
                            Json::Array(vec![Json::Object(vec![
                                ("tx_id".into(), Json::String(hex32.clone())),
                                ("conversation_id".into(), Json::String(hex32.clone())),
                                ("last_i".into(), Json::Null),
                                (
                                    "parts".into(),
                                    Json::Array(vec![Json::Object(vec![(
                                        "i".into(),
                                        Json::Bool(true)
                                    )])])
                                ),
                            ])])
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
                        (
                            "frags".into(),
                            Json::Array(vec![Json::Object(vec![
                                ("tx_id".into(), Json::String(hex32.clone())),
                                ("conversation_id".into(), Json::String(hex32.clone())),
                                ("last_i".into(), Json::Null),
                                (
                                    "parts".into(),
                                    Json::Array(vec![Json::Object(vec![
                                        ("i".into(), Json::Number(0)),
                                        ("frag".into(), Json::Number(1)),
                                    ])])
                                ),
                            ])])
                        ),
                    ]),
                    0
                ))
                .unwrap_err(),
            EngineError::MalformedPersist
        );
        let ch = Json::Object(vec![
            ("kind".into(), Json::String("nostr".into())),
            ("address".into(), Json::String("wss://relay.example".into())),
        ]);
        assert_eq!(
            engine
                .apply_folded(&seal_fold(
                    &engine,
                    Json::Object(vec![
                        ("next_seq".into(), Json::Number(1)),
                        (
                            "bins".into(),
                            Json::Array(vec![Json::Object(vec![
                                ("channel".into(), ch.clone()),
                                ("watermark".into(), Json::Null),
                                ("completed".into(), Json::Array(Vec::new())),
                            ])])
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
                        (
                            "bins".into(),
                            Json::Array(vec![Json::Object(vec![
                                ("channel".into(), ch.clone()),
                                ("tag_key".into(), Json::String("00".into())),
                                ("watermark".into(), Json::Null),
                                ("completed".into(), Json::Array(Vec::new())),
                            ])])
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
                        (
                            "bins".into(),
                            Json::Array(vec![Json::Object(vec![
                                ("channel".into(), ch.clone()),
                                ("tag_key".into(), Json::String(hex32.clone())),
                                ("watermark".into(), Json::Bool(true)),
                                ("completed".into(), Json::Array(Vec::new())),
                            ])])
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
                        (
                            "bins".into(),
                            Json::Array(vec![Json::Object(vec![
                                ("channel".into(), ch.clone()),
                                ("tag_key".into(), Json::String(hex32.clone())),
                                ("watermark".into(), Json::Null),
                                ("completed".into(), Json::Number(1)),
                            ])])
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
                        (
                            "bins".into(),
                            Json::Array(vec![Json::Object(vec![
                                ("channel".into(), ch),
                                ("tag_key".into(), Json::String(hex32.clone())),
                                ("watermark".into(), Json::Number(3)),
                                ("completed".into(), Json::Array(vec![Json::Bool(true)])),
                            ])])
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
                        ("failed".into(), Json::Bool(true)),
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
                        ("owners".into(), Json::Bool(true)),
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
                        ("inviters".into(), Json::Bool(true)),
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
                        ("failed".into(), Json::Array(vec![Json::Bool(true)])),
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
                        ("owners".into(), Json::Array(vec![Json::Bool(true)])),
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
                            "failed".into(),
                            Json::Array(vec![Json::Object(vec![
                                ("conversation_id".into(), Json::String(hex32.clone())),
                                ("reason".into(), Json::String("nope".into())),
                            ])])
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
                        (
                            "failed".into(),
                            Json::Array(vec![Json::Object(vec![
                                ("conversation_id".into(), Json::String(hex32.clone())),
                                ("reason".into(), Json::String("PolicyNotAccepted".into())),
                                ("policy".into(), Json::String("nope".into())),
                            ])])
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
                        ("device_enc".into(), Json::Bool(true)),
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
                            "failed".into(),
                            Json::Array(vec![Json::Object(vec![
                                ("conversation_id".into(), Json::String(hex32.clone())),
                                ("reason".into(), Json::Number(1)),
                            ])])
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
                        (
                            "failed".into(),
                            Json::Array(vec![Json::Object(vec![
                                ("conversation_id".into(), Json::String(hex32.clone())),
                                ("reason".into(), Json::String("InviteExpired".into())),
                            ])])
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
                        (
                            "failed".into(),
                            Json::Array(vec![Json::Object(vec![
                                ("conversation_id".into(), Json::String(hex32.clone())),
                                ("reason".into(), Json::String("PolicyNotAccepted".into())),
                            ])])
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

    #[test]
    fn invite_packets_open_from_ticket_secret() {
        use super::super::chain::{join, open_skip_ahead};
        use super::super::codec::ticket_from_json;
        use super::super::payload::{ConversationSort, PACKET_LEN, TICKET_MAX_UNCOMPRESSED};
        let mut engine = test_engine();
        let rng = CounterRng::new();
        engine
            .wrap_dek(&rng, &UnlockSecret::Passphrase("passpass".into()))
            .expect("wrap");
        let ticked = engine
            .tick(EngineState::new(), 1_700_000_000)
            .expect("tick");
        let (created, uid) = engine.create_user(ticked.state, &rng).expect("user");
        let (created, iid) = engine
            .create_identity(created.state, &rng, uid, Policy::Classic)
            .expect("id");
        let (invited, cid) = engine
            .create_invite(created.state, &rng, uid, iid, 1_800_000_000, None)
            .expect("inv");
        let ids = ConversationRef {
            user_id: uid,
            identity_id: iid,
            conversation_id: cid,
        };
        let ticket_s = engine.ticket_host_string(&invited.state, &ids).expect("t");
        let packed = engine.suite.b64u().decode(&ticket_s).expect("dec");
        let canonical = engine
            .suite
            .compress()
            .decompress(&packed, TICKET_MAX_UNCOMPRESSED)
            .expect("z");
        let json = engine.suite.canonical_json().decode(&canonical).expect("j");
        let ticket = ticket_from_json(engine.suite.b64u(), &json).expect("ticket");
        let chain = join(
            engine.suite.hmac(),
            ticket.secret.as_bytes(),
            ConversationSort::HandshakeDm,
            &[],
        )
        .expect("join");
        let poll = engine.poll(&invited.state).expect("p");
        assert_eq!(poll.write_durable[0].body.len(), PACKET_LEN);
        let opened = open_skip_ahead(
            &engine.suite,
            &chain,
            &[],
            1_700_000_000,
            &poll.write_durable[0].body,
        )
        .expect("open");
        assert!(!opened.from_cache);
        let tx_id = *invited
            .state
            .txs
            .iter()
            .find(|(_, b)| b.conversation_id == cid)
            .expect("tx")
            .0;
        let mut state = invited.state.clone();
        let seq0 = state.send_chain_seq(&cid).expect("seq");
        engine
            .post_handshake_packets(
                &mut state,
                &rng,
                cid,
                ticket.secret.as_bytes(),
                crate::protocol::v1::Tag::from_bytes(tx_id),
            )
            .expect("again");
        assert!(state.send_chain_seq(&cid).expect("seq2") > seq0);
        assert_eq!(
            engine
                .post_handshake_packets(
                    &mut EngineState::new(),
                    &rng,
                    cid,
                    ticket.secret.as_bytes(),
                    crate::protocol::v1::Tag::from_bytes(tx_id),
                )
                .unwrap_err(),
            EngineError::NotTicked
        );
        let mut unknown = invited.state.clone();
        assert_eq!(
            engine
                .post_handshake_packets(
                    &mut unknown,
                    &rng,
                    crate::protocol::v1::ConversationId::from_bytes([0; 32]),
                    ticket.secret.as_bytes(),
                    crate::protocol::v1::Tag::from_bytes(tx_id),
                )
                .unwrap_err(),
            EngineError::UnknownIds
        );
        let mut missing_tx = invited.state.clone();
        assert_eq!(
            engine
                .post_handshake_packets(
                    &mut missing_tx,
                    &rng,
                    cid,
                    ticket.secret.as_bytes(),
                    crate::protocol::v1::Tag::from_bytes([0; 32]),
                )
                .unwrap_err(),
            EngineError::UnknownIds
        );
        let dropped = engine.delete_conversation(state, ids).expect("dc");
        assert!(dropped.state.send_chain_seq(&cid).is_none());
    }

    #[test]
    fn ingest_list_merges_notice_and_completes_bin() {
        use super::super::chain::{join, mk, seal_packet, step};
        use super::super::codec::ticket_from_json;
        use super::super::payload::{
            ConversationSort, PacketPlain, PacketTxFragLast, PacketTxFragMore, PacketXorAck,
            TICKET_MAX_UNCOMPRESSED,
        };
        use super::{Conversation, FailedReason, Handshake, HandshakeInvitee, HandshakeInviter};
        use crate::protocol::v1::Tag;
        let mut engine = test_engine();
        let rng = CounterRng::new();
        engine
            .wrap_dek(&rng, &UnlockSecret::Passphrase("passpass".into()))
            .expect("wrap");
        let ticked = engine
            .tick(EngineState::new(), 1_700_000_000)
            .expect("tick");
        let (created, uid) = engine.create_user(ticked.state, &rng).expect("user");
        let (created, iid) = engine
            .create_identity(created.state, &rng, uid, Policy::Classic)
            .expect("id");
        let (invited, cid) = engine
            .create_invite(created.state, &rng, uid, iid, 1_800_000_000, None)
            .expect("inv");
        let ids = ConversationRef {
            user_id: uid,
            identity_id: iid,
            conversation_id: cid,
        };
        let ticket_s = engine.ticket_host_string(&invited.state, &ids).expect("t");
        let poll = engine.poll(&invited.state).expect("p");
        assert_eq!(poll.listen_durable.len(), 3);
        assert!(poll.listen_ephemeral.is_empty());
        assert!(poll.list.len() >= 3);
        for i in 1..poll.list.len() {
            let a = &poll.list[i - 1];
            let b = &poll.list[i];
            assert!(
                a.channel.kind().as_str() < b.channel.kind().as_str()
                    || a.channel.kind().as_str() == b.channel.kind().as_str()
                        && (a.channel.address().as_str() < b.channel.address().as_str()
                            || a.channel.address().as_str() == b.channel.address().as_str()
                                && a.tag.as_bytes() <= b.tag.as_bytes())
            );
        }
        let w = &poll.write_durable[0];
        let bodies: Vec<Vec<u8>> = poll.write_durable.iter().map(|x| x.body.clone()).collect();
        let invitee_tick = engine
            .tick(EngineState::new(), 1_700_000_000)
            .expect("itick");
        let (received, placeholder) = engine
            .receive_ticket(invitee_tick.state, &rng, uid, iid, &ticket_s)
            .expect("recv");
        assert!(matches!(
            engine
                .get_conversation(&received.state, uid, iid, placeholder)
                .expect("q0"),
            Conversation::HandshakeDm(Handshake::Invitee(HandshakeInvitee::TicketReceived))
        ));
        let empty = engine
            .ingest_list(received.state.clone(), &rng, w.channel.clone(), w.tag, &[])
            .expect("empty");
        assert!(matches!(
            engine
                .get_conversation(&empty.state, uid, iid, placeholder)
                .expect("q1"),
            Conversation::HandshakeDm(Handshake::Invitee(HandshakeInvitee::TicketReceived))
        ));
        assert_eq!(
            engine
                .ingest_packet(
                    empty.state.clone(),
                    &rng,
                    w.channel.clone(),
                    crate::protocol::v1::Tag::from_bytes([0; 32]),
                    &bodies[0]
                )
                .unwrap_err(),
            EngineError::UnknownTag
        );
        let ingested = engine
            .ingest_list(empty.state, &rng, w.channel.clone(), w.tag, &bodies)
            .expect("ing");
        assert!(!ingested.persist().is_empty());
        let rows = engine
            .list_conversations(&ingested.state, uid, iid)
            .expect("rows");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].conversation_id, cid);
        assert!(matches!(
            rows[0].conversation,
            Conversation::HandshakeDm(Handshake::Invitee(HandshakeInvitee::InviteReceived {
                policy: Policy::Classic,
                ..
            }))
        ));
        assert!(ingested.state.recv_chain_seq(&cid).is_some());
        let again = engine
            .ingest_list(
                ingested.state.clone(),
                &rng,
                w.channel.clone(),
                w.tag,
                &bodies,
            )
            .expect("dup");
        assert!(again.persist().is_empty());
        let snap = engine.fold(ingested.state.clone()).expect("fold");
        let restored = engine.apply_folded(&snap.snapshot).expect("af");
        assert_eq!(
            restored.recv_chain_seq(&cid),
            ingested.state.recv_chain_seq(&cid)
        );
        assert!(matches!(
            engine
                .get_conversation(&restored, uid, iid, cid)
                .expect("qr"),
            Conversation::HandshakeDm(Handshake::Invitee(HandshakeInvitee::InviteReceived { .. }))
        ));
        let mut collide = ingested.state.clone();
        let notice_id = *collide
            .txs
            .iter()
            .find(|(_, b)| matches!(b.payload, TxPayload::Notice(_)))
            .expect("nid")
            .0;
        collide.txs.insert(
            notice_id,
            DurableBody {
                conversation_id: cid,
                hlc: Hlc {
                    wall_ms: 0,
                    counter: 0,
                },
                payload: TxPayload::Confirm,
            },
        );
        assert_eq!(
            engine
                .ingest_list(collide, &rng, w.channel.clone(), w.tag, &bodies)
                .unwrap_err(),
            EngineError::Equivocation
        );
        let mut listed = ingested.state.clone();
        let locators = engine.poll(&listed).expect("pl").list;
        for loc in locators {
            listed = engine
                .ingest_list(listed, &rng, loc.channel, loc.tag, &[])
                .expect("catch")
                .state;
        }
        assert_eq!(engine.poll(&listed).expect("pl2").list.len(), 3);
        listed = engine
            .ingest_list(listed, &rng, w.channel.clone(), w.tag, &[])
            .expect("againw")
            .state;
        let far = engine.tick(listed, 1_700_000_000 + 80 * 3600).expect("far");
        let fp = engine.poll(&far.state).expect("fpoll");
        engine
            .ingest_list(
                far.state,
                &rng,
                fp.list[0].channel.clone(),
                fp.list[0].tag,
                &[],
            )
            .expect("prune");
        let packed = engine.suite.b64u().decode(&ticket_s).expect("dec");
        let canonical = engine
            .suite
            .compress()
            .decompress(&packed, TICKET_MAX_UNCOMPRESSED)
            .expect("z");
        let json = engine.suite.canonical_json().decode(&canonical).expect("j");
        let ticket = ticket_from_json(engine.suite.b64u(), &json).expect("ticket");
        let chain = join(
            engine.suite.hmac(),
            ticket.secret.as_bytes(),
            ConversationSort::HandshakeDm,
            &[],
        )
        .expect("join");
        let tx_id = Tag::from_bytes(notice_id);
        let more = PacketPlain::TxFragMore(PacketTxFragMore {
            actor_id: Vec::new(),
            packet_seq: 0,
            tx_id,
            frag_i: 0,
            frag: vec![1],
        });
        let last = PacketPlain::TxFragLast(PacketTxFragLast {
            actor_id: Vec::new(),
            packet_seq: 1,
            tx_id,
            frag_i: 1,
            frag: vec![2],
            set_xor: Tag::from_bytes([0; 32]),
        });
        let b_more =
            seal_packet(&engine.suite, &rng, &mk(engine.suite.hmac(), &chain), &more).expect("sm");
        let chain1 = step(engine.suite.hmac(), &chain);
        let b_last = seal_packet(
            &engine.suite,
            &rng,
            &mk(engine.suite.hmac(), &chain1),
            &last,
        )
        .expect("sl");
        let invitee2 = engine
            .tick(EngineState::new(), 1_700_000_000)
            .expect("t2")
            .state;
        let (recv2, ph2) = engine
            .receive_ticket(invitee2, &rng, uid, iid, &ticket_s)
            .expect("r2");
        let partial = engine
            .ingest_packet(recv2.state, &rng, w.channel.clone(), w.tag, &b_more)
            .expect("more");
        assert!(matches!(
            engine
                .get_conversation(&partial.state, uid, iid, ph2)
                .expect("qp"),
            Conversation::HandshakeDm(Handshake::Invitee(HandshakeInvitee::TicketReceived))
        ));
        let fold_partial = engine.fold(partial.state.clone()).expect("fp");
        let restored_partial = engine.apply_folded(&fold_partial.snapshot).expect("afp");
        let skip_first = engine
            .ingest_packet(restored_partial, &rng, w.channel.clone(), w.tag, &b_last)
            .expect("last");
        assert!(matches!(
            engine
                .get_conversation(&skip_first.state, uid, iid, ph2)
                .expect("ql"),
            Conversation::HandshakeDm(Handshake::Failed(FailedReason::NoticeUnlockFailed))
        ));
        let xor = PacketPlain::XorAck(PacketXorAck {
            actor_id: Vec::new(),
            packet_seq: 0,
            set_xor: Tag::from_bytes([1; 32]),
        });
        let b_xor =
            seal_packet(&engine.suite, &rng, &mk(engine.suite.hmac(), &chain), &xor).expect("sx");
        let invitee3 = engine
            .receive_ticket(
                engine
                    .tick(EngineState::new(), 1_700_000_000)
                    .expect("t3")
                    .state,
                &rng,
                uid,
                iid,
                &ticket_s,
            )
            .expect("r3");
        let skipped = engine
            .ingest_packet(invitee3.0.state, &rng, w.channel.clone(), w.tag, &b_xor)
            .expect("xor");
        assert!(matches!(
            engine
                .get_conversation(&skipped.state, uid, iid, invitee3.1)
                .expect("qx"),
            Conversation::HandshakeDm(Handshake::Invitee(HandshakeInvitee::TicketReceived))
        ));
        let bad_last = PacketPlain::TxFragLast(PacketTxFragLast {
            actor_id: Vec::new(),
            packet_seq: 0,
            tx_id: Tag::from_bytes([9; 32]),
            frag_i: 0,
            frag: b"not-json".to_vec(),
            set_xor: Tag::from_bytes([0; 32]),
        });
        let b_bad = seal_packet(
            &engine.suite,
            &rng,
            &mk(engine.suite.hmac(), &chain),
            &bad_last,
        )
        .expect("sb");
        let bad = engine
            .ingest_packet(skipped.state, &rng, w.channel.clone(), w.tag, &b_bad)
            .expect("bad");
        assert!(matches!(
            engine
                .get_conversation(&bad.state, uid, iid, invitee3.1)
                .expect("qbad"),
            Conversation::HandshakeDm(Handshake::Failed(FailedReason::NoticeUnlockFailed))
        ));
        let (sync_ok, sid) = engine
            .create_sync_invite(
                invited.state.clone(),
                &rng,
                Policy::Classic,
                1_900_000_000,
                "phone",
                None,
            )
            .expect("sync");
        let sync_ids = ConversationRef {
            user_id: uid,
            identity_id: iid,
            conversation_id: sid,
        };
        let sync_ticket = engine
            .ticket_host_string(&sync_ok.state, &sync_ids)
            .expect("st");
        let sync_poll = engine.poll(&sync_ok.state).expect("sp");
        let dm_tags: Vec<_> = poll.write_durable.iter().map(|w| w.tag).collect();
        let sync_writes: Vec<_> = sync_poll
            .write_durable
            .iter()
            .filter(|w| !dm_tags.iter().any(|t| t == &w.tag))
            .cloned()
            .collect();
        let mut acked = sync_ok.state.clone();
        for write in &sync_poll.write_durable {
            acked = engine
                .write_ack(acked, write.channel.clone(), write.tag, &write.body)
                .expect("sack")
                .state;
        }
        assert!(matches!(
            engine.get_conversation(&acked, uid, iid, sid).expect("sq"),
            Conversation::HandshakeSync(Handshake::Inviter(HandshakeInviter::NoticePinned { .. }))
        ));
        let sync_invitee = engine
            .tick(EngineState::new(), 1_700_000_000)
            .expect("stt")
            .state;
        let (sync_recv, _) = engine
            .receive_sync_ticket(sync_invitee, &rng, &sync_ticket)
            .expect("srt");
        let sw = &sync_writes[0];
        let sync_bodies: Vec<Vec<u8>> = sync_writes.iter().map(|x| x.body.clone()).collect();
        let sync_ing = engine
            .ingest_list(
                sync_recv.state,
                &rng,
                sw.channel.clone(),
                sw.tag,
                &sync_bodies,
            )
            .expect("si");
        let sync_rows = engine
            .list_conversations(
                &sync_ing.state,
                UserId::from_bytes([0; 32]),
                IdentityId::from_bytes([0; 32]),
            )
            .expect("srows");
        assert!(matches!(
            sync_rows[0].conversation,
            Conversation::HandshakeSync(Handshake::Invitee(HandshakeInvitee::InviteReceived {
                policy: Policy::Classic,
                ..
            }))
        ));
        let mut leave_state = sync_ing.state.clone();
        leave_state.skipped_mks.insert(
            sid.as_bytes().to_vec(),
            vec![super::super::chain::CachedMk {
                mk: [2; 32],
                expires_at: u64::MAX,
            }],
        );
        leave_state.skipped_mks.insert(
            vec![9],
            vec![super::super::chain::CachedMk {
                mk: [8; 32],
                expires_at: u64::MAX,
            }],
        );
        engine.leave_sync(leave_state, &rng).expect("lsing");
        let disagree = PacketPlain::TxFragMore(PacketTxFragMore {
            actor_id: Vec::new(),
            packet_seq: 0,
            tx_id,
            frag_i: 0,
            frag: b"aaaa".to_vec(),
        });
        let b_dis = seal_packet(
            &engine.suite,
            &rng,
            &mk(engine.suite.hmac(), &chain),
            &disagree,
        )
        .expect("sd");
        let (recv_dis, _) = engine
            .receive_ticket(
                engine
                    .tick(EngineState::new(), 1_700_000_000)
                    .expect("td")
                    .state,
                &rng,
                uid,
                iid,
                &ticket_s,
            )
            .expect("rd");
        let first_dis = engine
            .ingest_packet(recv_dis.state, &rng, w.channel.clone(), w.tag, &b_more)
            .expect("d1");
        let disagree2 = PacketPlain::TxFragMore(PacketTxFragMore {
            actor_id: Vec::new(),
            packet_seq: 0,
            tx_id,
            frag_i: 0,
            frag: b"bbbb".to_vec(),
        });
        let b_dis2 = seal_packet(
            &engine.suite,
            &rng,
            &mk(engine.suite.hmac(), &chain),
            &disagree2,
        )
        .expect("sd2");
        assert_eq!(
            engine
                .ingest_packet(first_dis.state, &rng, w.channel.clone(), w.tag, &b_dis2)
                .unwrap_err(),
            EngineError::Equivocation
        );
        let _ = b_dis;
        assert_eq!(
            engine
                .ingest_list(
                    ingested.state.clone(),
                    &rng,
                    w.channel.clone(),
                    crate::protocol::v1::Tag::from_bytes([2; 32]),
                    &[]
                )
                .unwrap_err(),
            EngineError::UnknownTag
        );
        let other = crate::protocol::v1::DurableChannel::new(
            crate::protocol::v1::Kind::try_from("blossom").expect("k"),
            crate::protocol::v1::Address::try_from("https://blob.example").expect("a"),
        );
        assert_eq!(
            engine
                .ingest_list(ingested.state.clone(), &rng, other, w.tag, &[])
                .unwrap_err(),
            EngineError::UnknownTag
        );
        let last_hi = PacketPlain::TxFragLast(PacketTxFragLast {
            actor_id: Vec::new(),
            packet_seq: 0,
            tx_id,
            frag_i: 2,
            frag: vec![1],
            set_xor: Tag::from_bytes([0; 32]),
        });
        let last_hi2 = PacketPlain::TxFragLast(PacketTxFragLast {
            actor_id: Vec::new(),
            packet_seq: 0,
            tx_id,
            frag_i: 3,
            frag: vec![1],
            set_xor: Tag::from_bytes([0; 32]),
        });
        let b_hi = seal_packet(
            &engine.suite,
            &rng,
            &mk(engine.suite.hmac(), &chain),
            &last_hi,
        )
        .expect("shi");
        let b_hi2 = seal_packet(
            &engine.suite,
            &rng,
            &mk(engine.suite.hmac(), &chain),
            &last_hi2,
        )
        .expect("shi2");
        let (recv_hi, _) = engine
            .receive_ticket(
                engine
                    .tick(EngineState::new(), 1_700_000_000)
                    .expect("thi")
                    .state,
                &rng,
                uid,
                iid,
                &ticket_s,
            )
            .expect("rhi");
        let partial_hi = engine
            .ingest_packet(recv_hi.state, &rng, w.channel.clone(), w.tag, &b_hi)
            .expect("hi");
        let _ = engine.fold(partial_hi.state.clone()).expect("fhi");
        engine
            .apply_folded(
                &engine
                    .fold(partial_hi.state.clone())
                    .expect("fhi2")
                    .snapshot,
            )
            .expect("afhi");
        assert_eq!(
            engine
                .ingest_packet(partial_hi.state, &rng, w.channel.clone(), w.tag, &b_hi2)
                .unwrap_err(),
            EngineError::Equivocation
        );
        let too_big = PacketPlain::TxFragLast(PacketTxFragLast {
            actor_id: Vec::new(),
            packet_seq: 0,
            tx_id: Tag::from_bytes([7; 32]),
            frag_i: super::super::chain::MAX_FRAGS,
            frag: vec![1],
            set_xor: Tag::from_bytes([0; 32]),
        });
        let b_big = seal_packet(
            &engine.suite,
            &rng,
            &mk(engine.suite.hmac(), &chain),
            &too_big,
        )
        .expect("sbig");
        let (recv_big, _) = engine
            .receive_ticket(
                engine
                    .tick(EngineState::new(), 1_700_000_000)
                    .expect("tbig")
                    .state,
                &rng,
                uid,
                iid,
                &ticket_s,
            )
            .expect("rbig");
        engine
            .ingest_packet(recv_big.state, &rng, w.channel.clone(), w.tag, &b_big)
            .expect("big");
        let b_null = seal_packet(
            &engine.suite,
            &rng,
            &mk(engine.suite.hmac(), &chain),
            &PacketPlain::TxFragLast(PacketTxFragLast {
                actor_id: Vec::new(),
                packet_seq: 0,
                tx_id: Tag::from_bytes([6; 32]),
                frag_i: 0,
                frag: b"null".to_vec(),
                set_xor: Tag::from_bytes([0; 32]),
            }),
        )
        .expect("snull");
        let (recv_null, _) = engine
            .receive_ticket(
                engine
                    .tick(EngineState::new(), 1_700_000_000)
                    .expect("tnull")
                    .state,
                &rng,
                uid,
                iid,
                &ticket_s,
            )
            .expect("rnull");
        engine
            .ingest_packet(recv_null.state, &rng, w.channel.clone(), w.tag, &b_null)
            .expect("inull");
        let (recv_cache, phc) = engine
            .receive_ticket(
                engine
                    .tick(EngineState::new(), 1_700_000_000)
                    .expect("tc")
                    .state,
                &rng,
                uid,
                iid,
                &ticket_s,
            )
            .expect("rc");
        let cached_first = engine
            .ingest_packet(recv_cache.state, &rng, w.channel.clone(), w.tag, &b_last)
            .expect("clast");
        let cached_second = engine
            .ingest_packet(cached_first.state, &rng, w.channel.clone(), w.tag, &b_more)
            .expect("cmore");
        assert!(matches!(
            engine
                .get_conversation(&cached_second.state, uid, iid, phc)
                .expect("qc"),
            Conversation::HandshakeDm(Handshake::Failed(FailedReason::NoticeUnlockFailed))
        ));
        engine
            .tick(cached_second.state, 1_700_000_000 + 172_801)
            .expect("texp");
        let mut named = ingested.state.clone();
        named.txs.insert(
            [0; 32],
            DurableBody {
                conversation_id: cid,
                hlc: Hlc {
                    wall_ms: 0,
                    counter: 0,
                },
                payload: TxPayload::EngineCreateUser { user_id: uid },
            },
        );
        assert!(matches!(
            engine.get_conversation(&named, uid, iid, cid).expect("qn"),
            Conversation::HandshakeDm(Handshake::Invitee(HandshakeInvitee::InviteReceived { .. }))
        ));
        let mut eph_state = ingested.state.clone();
        eph_state.eph_writes.push(super::EphemeralWrite {
            channel: crate::protocol::v1::EphemeralChannel::new(
                crate::protocol::v1::Kind::try_from("webrtc").expect("wk"),
                crate::protocol::v1::Address::try_from("https://eph.example").expect("wa"),
            ),
            tag: Tag::from_bytes([4; 32]),
            body: vec![0; crate::protocol::v1::PACKET_LEN],
        });
        eph_state.eph_writes.push(super::EphemeralWrite {
            channel: crate::protocol::v1::EphemeralChannel::new(
                crate::protocol::v1::Kind::try_from("webrtc").expect("wk2"),
                crate::protocol::v1::Address::try_from("wss://eph.example").expect("wa2"),
            ),
            tag: Tag::from_bytes([5; 32]),
            body: vec![0; crate::protocol::v1::PACKET_LEN],
        });
        eph_state.eph_writes.push(super::EphemeralWrite {
            channel: crate::protocol::v1::EphemeralChannel::new(
                crate::protocol::v1::Kind::try_from("webrtc").expect("wk3"),
                crate::protocol::v1::Address::try_from("https://eph.example").expect("wa3"),
            ),
            tag: Tag::from_bytes([6; 32]),
            body: vec![0; crate::protocol::v1::PACKET_LEN],
        });
        let _ = engine.poll(&eph_state).expect("peph");
        let mut drain = ingested.state.clone();
        for progress in drain.bin_progress.values_mut() {
            progress.watermark = Some(472_220);
            progress.completed.insert(472_221);
        }
        let drained = engine
            .ingest_list(drain, &rng, w.channel.clone(), w.tag, &[])
            .expect("drain");
        engine
            .apply_folded(&engine.fold(drained.state).expect("fdrain").snapshot)
            .expect("afdrain");
        assert_eq!(
            engine
                .reject_established(sync_ok.state.clone(), &rng, sync_ids)
                .unwrap_err(),
            EngineError::WrongPhase
        );
        let dummy_more = PacketPlain::TxFragMore(PacketTxFragMore {
            actor_id: Vec::new(),
            packet_seq: 1,
            tx_id: Tag::from_bytes([8; 32]),
            frag_i: 0,
            frag: vec![1],
        });
        let chain1 = step(engine.suite.hmac(), &chain);
        let b_dummy = seal_packet(
            &engine.suite,
            &rng,
            &mk(engine.suite.hmac(), &chain1),
            &dummy_more,
        )
        .expect("sdummy");
        let (recv_rk, ph_rk) = engine
            .receive_ticket(
                engine
                    .tick(EngineState::new(), 1_700_000_000)
                    .expect("trk")
                    .state,
                &rng,
                uid,
                iid,
                &ticket_s,
            )
            .expect("rrk");
        let with_frag = engine
            .ingest_packet(recv_rk.state, &rng, w.channel.clone(), w.tag, &b_dummy)
            .expect("idummy");
        assert!(!with_frag.state.frags.is_empty());
        let mut with_frag_state = with_frag.state;
        with_frag_state.frags.insert(
            [9; 32],
            super::FragSet {
                conversation_id: [1; 32],
                parts: std::collections::BTreeMap::new(),
                last_i: None,
            },
        );
        with_frag_state.skipped_mks.insert(
            ph_rk.as_bytes().to_vec(),
            vec![super::super::chain::CachedMk {
                mk: [3; 32],
                expires_at: u64::MAX,
            }],
        );
        let mut long_key = ph_rk.as_bytes().to_vec();
        long_key.extend_from_slice(&[7; 8]);
        with_frag_state.skipped_mks.insert(
            long_key,
            vec![super::super::chain::CachedMk {
                mk: [6; 32],
                expires_at: u64::MAX,
            }],
        );
        with_frag_state.skipped_mks.insert(
            [0xff; 32].to_vec(),
            vec![super::super::chain::CachedMk {
                mk: [4; 32],
                expires_at: u64::MAX,
            }],
        );
        with_frag_state.skipped_mks.insert(
            vec![1, 2],
            vec![super::super::chain::CachedMk {
                mk: [5; 32],
                expires_at: u64::MAX,
            }],
        );
        let rekeyed = engine
            .ingest_list(with_frag_state, &rng, w.channel.clone(), w.tag, &bodies)
            .expect("rekeyfrag");
        let mut drop_state = invited.state.clone();
        drop_state.recv_chains = rekeyed.state.recv_chains.clone();
        drop_state.skipped_mks = rekeyed.state.skipped_mks.clone();
        drop_state.frags = rekeyed.state.frags.clone();
        engine.delete_conversation(drop_state, ids).expect("deling");
        let eph_a = crate::protocol::v1::EphemeralChannel::new(
            crate::protocol::v1::Kind::try_from("webrtc").expect("ska"),
            crate::protocol::v1::Address::try_from("https://eph.example").expect("saa"),
        );
        let eph_b = crate::protocol::v1::EphemeralChannel::new(
            crate::protocol::v1::Kind::try_from("webrtc").expect("skb"),
            crate::protocol::v1::Address::try_from("wss://eph.example").expect("sab"),
        );
        let mut eph = vec![
            super::EphemeralWrite {
                channel: eph_a.clone(),
                tag: Tag::from_bytes([1; 32]),
                body: vec![0; crate::protocol::v1::PACKET_LEN],
            },
            super::EphemeralWrite {
                channel: eph_a,
                tag: Tag::from_bytes([2; 32]),
                body: vec![0; crate::protocol::v1::PACKET_LEN],
            },
            super::EphemeralWrite {
                channel: eph_b,
                tag: Tag::from_bytes([1; 32]),
                body: vec![0; crate::protocol::v1::PACKET_LEN],
            },
        ];
        super::sort_ephemeral_writes(&mut eph);
        engine.lock();
        assert_eq!(
            engine
                .ingest_list(ingested.state.clone(), &rng, w.channel.clone(), w.tag, &[])
                .unwrap_err(),
            EngineError::Locked
        );
    }

    fn ack_all(engine: &Engine, mut state: EngineState) -> EngineState {
        loop {
            let poll = engine.poll(&state).expect("p");
            if poll.write_durable.is_empty() {
                return state;
            }
            for w in poll.write_durable {
                state = engine
                    .write_ack(state, w.channel, w.tag, &w.body)
                    .expect("ack")
                    .state;
            }
        }
    }

    #[test]
    fn handshake_intros_confirming_and_failures() {
        use super::super::chain::{fragment_body, join, mk, packed_tx, seal_packet, step};
        use super::super::codec::ticket_from_json;
        use super::super::payload::{
            ConversationSort, PacketPlain, PacketTxFragLast, TxInviteeIntro, TxNotice,
        };
        use super::{
            Conversation, ConversationRef, DirectMessageQuery, FailedReason, Handshake,
            HandshakeInvitee, HandshakeInviter,
        };
        use crate::protocol::v1::{DisplayName, OnWirePrefs, Tag, TagKey};
        let mut engine = test_engine();
        let rng = CounterRng::new();
        engine
            .wrap_dek(&rng, &UnlockSecret::Passphrase("passpass".into()))
            .expect("wrap");
        let ticked = engine
            .tick(EngineState::new(), 1_700_000_000)
            .expect("tick");
        let (created, uid) = engine.create_user(ticked.state, &rng).expect("user");
        let (created, iid) = engine
            .create_identity(created.state, &rng, uid, Policy::Classic)
            .expect("id");
        let named = engine
            .set_display_name(created.state, &rng, uid, iid, "Ada")
            .expect("name");
        let (invited, cid) = engine
            .create_invite(named.state, &rng, uid, iid, 1_800_000_000, None)
            .expect("inv");
        let ids = ConversationRef {
            user_id: uid,
            identity_id: iid,
            conversation_id: cid,
        };
        let ticket_s = engine.ticket_host_string(&invited.state, &ids).expect("t");
        let notice_writes: Vec<_> = engine
            .poll(&invited.state)
            .expect("p")
            .write_durable
            .into_iter()
            .map(|w| (w.channel, w.tag, w.body))
            .collect();
        let mut pending_inviter = invited.state.clone();
        let inviter = ack_all(&engine, invited.state);
        assert!(matches!(
            engine.get_conversation(&inviter, uid, iid, cid).expect("q"),
            Conversation::HandshakeDm(Handshake::Inviter(HandshakeInviter::NoticePinned { .. }))
        ));
        let ie_tick = engine.tick(EngineState::new(), 1_700_000_000).expect("it");
        let (ie_user, ie_uid) = engine.create_user(ie_tick.state, &rng).expect("iu");
        let (ie_id, ie_iid) = engine
            .create_identity(ie_user.state, &rng, ie_uid, Policy::Classic)
            .expect("ii");
        let ie_named = engine
            .set_display_name(ie_id.state, &rng, ie_uid, ie_iid, "Bob")
            .expect("in");
        let (received, ie_cid) = engine
            .receive_ticket(ie_named.state, &rng, ie_uid, ie_iid, &ticket_s)
            .expect("recv");
        let mut ticket_recv = received.state.clone();
        let (ch, tag, _) = notice_writes[0].clone();
        let bodies: Vec<Vec<u8>> = notice_writes.iter().map(|w| w.2.clone()).collect();
        let minted = engine
            .ingest_list(received.state, &rng, ch.clone(), tag, &bodies)
            .expect("ing");
        assert!(matches!(
            engine
                .get_conversation(&minted.state, ie_uid, ie_iid, cid)
                .expect("ir"),
            Conversation::HandshakeDm(Handshake::Invitee(
                HandshakeInvitee::IntroductionMinted { .. }
            ))
        ));
        let intro_writes: Vec<_> = engine
            .poll(&minted.state)
            .expect("ip")
            .write_durable
            .into_iter()
            .map(|w| (w.channel, w.tag, w.body))
            .collect();
        let sent = ack_all(&engine, minted.state);
        assert!(matches!(
            engine
                .get_conversation(&sent, ie_uid, ie_iid, cid)
                .expect("is"),
            Conversation::HandshakeDm(Handshake::Invitee(
                HandshakeInvitee::IntroductionSent { .. }
            ))
        ));
        let intro_bodies: Vec<Vec<u8>> = intro_writes.iter().map(|w| w.2.clone()).collect();
        let pinned = inviter.clone();
        let inv_minted = engine
            .ingest_list(
                inviter,
                &rng,
                intro_writes[0].0.clone(),
                intro_writes[0].1,
                &intro_bodies,
            )
            .expect("iing");
        assert!(matches!(
            engine
                .get_conversation(&inv_minted.state, uid, iid, cid)
                .expect("im"),
            Conversation::HandshakeDm(Handshake::Inviter(
                HandshakeInviter::IntroductionMinted { .. }
            ))
        ));
        let inv_intro_writes: Vec<_> = engine
            .poll(&inv_minted.state)
            .expect("iip")
            .write_durable
            .into_iter()
            .map(|w| (w.channel, w.tag, w.body))
            .collect();
        let inv_conf = ack_all(&engine, inv_minted.state);
        assert!(matches!(
            engine
                .get_conversation(&inv_conf, uid, iid, cid)
                .expect("ic"),
            Conversation::HandshakeDm(Handshake::Inviter(HandshakeInviter::Confirming {
                confirmation_digest: ref d,
                ..
            })) if d.is_empty()
        ));
        let ie_conf = engine
            .ingest_list(
                sent,
                &rng,
                inv_intro_writes[0].0.clone(),
                inv_intro_writes[0].1,
                &inv_intro_writes
                    .iter()
                    .map(|w| w.2.clone())
                    .collect::<Vec<_>>(),
            )
            .expect("ieing");
        assert!(matches!(
            engine
                .get_conversation(&ie_conf.state, ie_uid, ie_iid, cid)
                .expect("iec"),
            Conversation::HandshakeDm(Handshake::Invitee(HandshakeInvitee::Confirming {
                confirmation_digest: ref d,
                ..
            })) if d.is_empty()
        ));
        let ie_ids = ConversationRef {
            user_id: ie_uid,
            identity_id: ie_iid,
            conversation_id: cid,
        };
        let rejected = engine
            .reject_established(ie_conf.state.clone(), &rng, ie_ids)
            .expect("rej");
        assert!(matches!(
            engine
                .get_conversation(&rejected.state, ie_uid, ie_iid, cid)
                .expect("rejq"),
            Conversation::HandshakeDm(Handshake::Failed(FailedReason::ConfirmationRejected))
        ));
        let confirmed = engine
            .confirm_established(inv_conf.clone(), &rng, ids)
            .expect("conf");
        assert!(matches!(
            engine
                .get_conversation(&confirmed.state, uid, iid, cid)
                .expect("est"),
            Conversation::DirectMessage(DirectMessageQuery::Established)
        ));
        let expired = engine.tick(inv_conf.clone(), 1_900_000_000).expect("exp");
        assert!(matches!(
            engine
                .get_conversation(&expired.state, uid, iid, cid)
                .expect("exq"),
            Conversation::HandshakeDm(Handshake::Failed(FailedReason::InviteExpired { .. }))
        ));
        assert_eq!(
            engine
                .confirm_established(expired.state.clone(), &rng, ids)
                .unwrap_err(),
            EngineError::WrongPhase
        );
        let epoll = engine.poll(&expired.state).expect("ep");
        assert_eq!(
            engine
                .ingest_packet(
                    expired.state,
                    &rng,
                    epoll.list[0].channel.clone(),
                    epoll.list[0].tag,
                    &bodies[0]
                )
                .unwrap_err(),
            EngineError::WrongPhase
        );

        let delayed = engine.tick(EngineState::new(), 1_700_000_000).expect("dt");
        let (du, duid) = engine.create_user(delayed.state, &rng).expect("du");
        let (di, diid) = engine
            .create_identity(du.state, &rng, duid, Policy::Classic)
            .expect("di");
        let (drecv, _dcid) = engine
            .receive_ticket(di.state, &rng, duid, diid, &ticket_s)
            .expect("drecv");
        let blocked = engine.poll(&drecv.state).expect("blk");
        assert!(blocked.blocked.iter().any(|b| b.identity_id == diid));
        let got_notice = engine
            .ingest_list(drecv.state, &rng, ch.clone(), tag, &bodies)
            .expect("dn");
        assert!(matches!(
            engine
                .get_conversation(&got_notice.state, duid, diid, cid)
                .expect("dnr"),
            Conversation::HandshakeDm(Handshake::Invitee(HandshakeInvitee::InviteReceived { .. }))
        ));
        let named_ie = engine
            .set_display_name(got_notice.state, &rng, duid, diid, "Cyd")
            .expect("setn");
        assert!(matches!(
            engine
                .get_conversation(&named_ie.state, duid, diid, cid)
                .expect("dnm"),
            Conversation::HandshakeDm(Handshake::Invitee(
                HandshakeInvitee::IntroductionMinted { .. }
            ))
        ));

        let mismatch_tick = engine.tick(EngineState::new(), 1_700_000_000).expect("mt");
        let (mu, muid) = engine.create_user(mismatch_tick.state, &rng).expect("mu");
        let (mi, miid) = engine
            .create_identity(mu.state, &rng, muid, Policy::Hybrid)
            .expect("mi");
        let mn = engine
            .set_display_name(mi.state, &rng, muid, miid, "Eve")
            .expect("mn");
        let (mrecv, mcid) = engine
            .receive_ticket(mn.state, &rng, muid, miid, &ticket_s)
            .expect("mrecv");
        let mut policy_mint = mrecv.state.clone();
        let mfail = engine
            .ingest_list(mrecv.state, &rng, ch.clone(), tag, &bodies)
            .expect("ming");
        assert!(matches!(
            engine
                .get_conversation(&mfail.state, muid, miid, cid)
                .expect("mfq"),
            Conversation::HandshakeDm(Handshake::Failed(FailedReason::PolicyNotAccepted { .. }))
        ));

        let mut folded_fail = named_ie.state.clone();
        for reason in [
            FailedReason::PolicyNotAccepted {
                policy: Policy::Hybrid,
            },
            FailedReason::InviteExpired { expires: 3 },
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
            folded_fail.failed.insert(*cid.as_bytes(), reason);
            let snap = engine.fold(folded_fail.clone()).expect("ff");
            let restored = engine.apply_folded(&snap.snapshot).expect("afr");
            assert_eq!(restored.failed.get(cid.as_bytes()), Some(&reason));
        }

        let packed = engine.suite.b64u().decode(&ticket_s).expect("dec");
        let canonical = engine
            .suite
            .compress()
            .decompress(&packed, super::super::payload::TICKET_MAX_UNCOMPRESSED)
            .expect("z");
        let json = engine.suite.canonical_json().decode(&canonical).expect("j");
        let ticket = ticket_from_json(engine.suite.b64u(), &json).expect("tk");
        let other_notice = TxPayload::Notice(TxNotice {
            policy: Policy::Classic,
            intake_pk: vec![0; 32],
            persistents: ticket.persistents.clone(),
            ephemerals: Vec::new(),
            expires: 1_800_000_001,
        });
        policy_mint.txs.insert(
            [0x22; 32],
            DurableBody {
                conversation_id: mcid,
                hlc: Hlc {
                    wall_ms: 0,
                    counter: 0,
                },
                payload: TxPayload::Notice(TxNotice {
                    policy: Policy::Classic,
                    intake_pk: vec![0; 32],
                    persistents: ticket.persistents.clone(),
                    ephemerals: Vec::new(),
                    expires: 1_800_000_000,
                }),
            },
        );
        engine
            .try_mint_invitee_intro(&mut policy_mint, &rng, mcid)
            .expect("pm");
        assert_eq!(
            policy_mint.failed.get(mcid.as_bytes()),
            Some(&FailedReason::PolicyNotAccepted {
                policy: Policy::Classic
            })
        );
        let mut clash_state = named_ie.state.clone();
        let gated = engine
            .handshake_ingest_gate(&mut clash_state, *cid.as_bytes(), &other_notice)
            .expect("gate");
        assert!(gated.is_some());
        assert_eq!(
            clash_state.failed.get(cid.as_bytes()),
            Some(&FailedReason::NoticeConflict)
        );
        let bad_intro = TxPayload::InviteeIntro(TxInviteeIntro {
            name: DisplayName::try_from("X").expect("dn"),
            profile_pic: None,
            send_tag_key: TagKey::from_bytes([1; 32]),
            eph_send_tag_key: TagKey::from_bytes([2; 32]),
            encryption_pk: vec![1],
            signing_pk: vec![2],
            intake_pk: vec![3],
            seed_ct: vec![4],
            prefs: OnWirePrefs {
                read_receipts: true,
                online_visible: true,
                send_typing: true,
                disappear_after: None,
                wake: None,
            },
        });
        let mut verify_state = pinned.clone();
        let gated = engine
            .handshake_ingest_gate(&mut verify_state, *cid.as_bytes(), &bad_intro)
            .expect("g2");
        assert!(gated.is_some());
        assert_eq!(
            verify_state.failed.get(cid.as_bytes()),
            Some(&FailedReason::IntroVerifyFailed)
        );
        let mut dup_state = named_ie.state.clone();
        let gated = engine
            .handshake_ingest_gate(&mut dup_state, *cid.as_bytes(), &bad_intro)
            .expect("g3");
        assert!(gated.is_some());
        assert_eq!(
            dup_state.failed.get(cid.as_bytes()),
            Some(&FailedReason::DuplicateIntro)
        );
        let no_notice = TxPayload::InviterIntro(super::super::payload::TxInviterIntro {
            name: DisplayName::try_from("Y").expect("dn2"),
            profile_pic: None,
            send_tag_key: TagKey::from_bytes([3; 32]),
            eph_send_tag_key: TagKey::from_bytes([4; 32]),
            encryption_pk: vec![1; 32],
            signing_pk: vec![1; 32],
            seed_ct: vec![1; 32],
            prefs: OnWirePrefs {
                read_receipts: true,
                online_visible: true,
                send_typing: true,
                disappear_after: None,
                wake: None,
            },
        });
        let mut empty_ticket = engine
            .tick(EngineState::new(), 1_700_000_000)
            .expect("et")
            .state;
        empty_ticket.tickets.insert(*cid.as_bytes(), ticket.clone());
        let gated = engine
            .handshake_ingest_gate(&mut empty_ticket, *cid.as_bytes(), &no_notice)
            .expect("g4");
        assert!(gated.is_some());
        assert_eq!(
            empty_ticket.failed.get(cid.as_bytes()),
            Some(&FailedReason::IntroVerifyFailed)
        );
        let mut unlock_inviter = pinned.clone();
        super::store_unlock_failed(&mut unlock_inviter, *cid.as_bytes());
        assert_eq!(
            unlock_inviter.failed.get(cid.as_bytes()),
            Some(&FailedReason::IntroUnlockFailed)
        );
        super::store_unlock_failed(&mut unlock_inviter, *cid.as_bytes());
        let mut unlock_invitee = EngineState::new();
        super::store_unlock_failed(&mut unlock_invitee, *cid.as_bytes());
        assert_eq!(
            unlock_invitee.failed.get(cid.as_bytes()),
            Some(&FailedReason::NoticeUnlockFailed)
        );
        let mut both_intros = ie_conf.state.clone();
        let gated = engine
            .handshake_ingest_gate(&mut both_intros, *cid.as_bytes(), &no_notice)
            .expect("g5");
        assert!(gated.is_some());
        assert_eq!(
            both_intros.failed.get(cid.as_bytes()),
            Some(&FailedReason::DuplicateIntro)
        );
        let (sync_ok, sid) = engine
            .create_sync_invite(
                confirmed.state,
                &rng,
                Policy::Classic,
                1_900_000_000,
                "phone",
                None,
            )
            .expect("sync");
        let snap = engine.fold(sync_ok.state.clone()).expect("sfold");
        let restored = engine.apply_folded(&snap.snapshot).expect("saf");
        assert!(restored.device_enc.is_some());
        assert!(restored.inviters.contains(sid.as_bytes()));
        let st = engine
            .tick(EngineState::new(), 1_700_000_000)
            .expect("st")
            .state;
        let (srecv, _) = engine
            .receive_sync_ticket(st, &rng, &ticket_s)
            .expect("srecv");
        let spoll = engine.poll(&srecv.state).expect("sp");
        assert!(
            spoll
                .blocked
                .iter()
                .any(|b| b.user_id.as_bytes() == &[0; 32])
        );
        let ie_no_notice = TxPayload::InviteeIntro(TxInviteeIntro {
            name: DisplayName::try_from("N").expect("dnn"),
            profile_pic: None,
            send_tag_key: TagKey::from_bytes([8; 32]),
            eph_send_tag_key: TagKey::from_bytes([9; 32]),
            encryption_pk: vec![1; 32],
            signing_pk: vec![1; 32],
            intake_pk: vec![1; 32],
            seed_ct: vec![1; 32],
            prefs: OnWirePrefs {
                read_receipts: true,
                online_visible: true,
                send_typing: true,
                disappear_after: None,
                wake: None,
            },
        });
        let mut empty_ie = engine
            .tick(EngineState::new(), 1_700_000_000)
            .expect("et2")
            .state;
        empty_ie.tickets.insert(*cid.as_bytes(), ticket.clone());
        let gated = engine
            .handshake_ingest_gate(&mut empty_ie, *cid.as_bytes(), &ie_no_notice)
            .expect("g6");
        assert!(gated.is_some());
        assert_eq!(
            empty_ie.failed.get(cid.as_bytes()),
            Some(&FailedReason::IntroVerifyFailed)
        );
        let bad_inviter_keys = TxPayload::InviterIntro(super::super::payload::TxInviterIntro {
            name: DisplayName::try_from("K").expect("dnk"),
            profile_pic: None,
            send_tag_key: TagKey::from_bytes([10; 32]),
            eph_send_tag_key: TagKey::from_bytes([11; 32]),
            encryption_pk: vec![1],
            signing_pk: vec![1],
            seed_ct: vec![1],
            prefs: OnWirePrefs {
                read_receipts: true,
                online_visible: true,
                send_typing: true,
                disappear_after: None,
                wake: None,
            },
        });
        let mut verify_inv = pinned.clone();
        let gated = engine
            .handshake_ingest_gate(&mut verify_inv, *cid.as_bytes(), &bad_inviter_keys)
            .expect("g7");
        assert!(gated.is_some());
        assert_eq!(
            verify_inv.failed.get(cid.as_bytes()),
            Some(&FailedReason::IntroVerifyFailed)
        );
        let mut wrap_fail = pinned.clone();
        wrap_fail.txs.insert(
            [0x11; 32],
            DurableBody {
                conversation_id: cid,
                hlc: Hlc {
                    wall_ms: 0,
                    counter: 0,
                },
                payload: TxPayload::InviteeIntro(TxInviteeIntro {
                    name: DisplayName::try_from("W").expect("dnw"),
                    profile_pic: None,
                    send_tag_key: TagKey::from_bytes([12; 32]),
                    eph_send_tag_key: TagKey::from_bytes([13; 32]),
                    encryption_pk: vec![1; 32],
                    signing_pk: vec![1; 32],
                    intake_pk: Vec::new(),
                    seed_ct: vec![1; 32],
                    prefs: OnWirePrefs {
                        read_receipts: true,
                        online_visible: true,
                        send_typing: true,
                        disappear_after: None,
                        wake: None,
                    },
                }),
            },
        );
        let extra = engine
            .try_mint_inviter_intro(&mut wrap_fail, &rng, cid)
            .expect("wrapf");
        assert!(extra.is_empty());
        assert_eq!(
            wrap_fail.failed.get(cid.as_bytes()),
            Some(&FailedReason::IntroVerifyFailed)
        );
        let mut no_ticket = pinned.clone();
        no_ticket.tickets.remove(cid.as_bytes());
        no_ticket.sync_tickets.remove(cid.as_bytes());
        no_ticket.txs.insert(
            [0x33; 32],
            DurableBody {
                conversation_id: cid,
                hlc: Hlc {
                    wall_ms: 0,
                    counter: 0,
                },
                payload: TxPayload::InviteeIntro(TxInviteeIntro {
                    name: DisplayName::try_from("T").expect("dnt"),
                    profile_pic: None,
                    send_tag_key: TagKey::from_bytes([14; 32]),
                    eph_send_tag_key: TagKey::from_bytes([15; 32]),
                    encryption_pk: vec![1; 32],
                    signing_pk: vec![1; 32],
                    intake_pk: vec![1; 32],
                    seed_ct: vec![1; 32],
                    prefs: OnWirePrefs {
                        read_receipts: true,
                        online_visible: true,
                        send_typing: true,
                        disappear_after: None,
                        wake: None,
                    },
                }),
            },
        );
        assert_eq!(
            engine
                .try_mint_inviter_intro(&mut no_ticket, &rng, cid)
                .unwrap_err(),
            EngineError::UnknownIds
        );
        pending_inviter.txs.insert(
            [0x34; 32],
            DurableBody {
                conversation_id: cid,
                hlc: Hlc {
                    wall_ms: 0,
                    counter: 0,
                },
                payload: TxPayload::InviteeIntro(TxInviteeIntro {
                    name: DisplayName::try_from("P").expect("dnp"),
                    profile_pic: None,
                    send_tag_key: TagKey::from_bytes([16; 32]),
                    eph_send_tag_key: TagKey::from_bytes([17; 32]),
                    encryption_pk: vec![1; 32],
                    signing_pk: vec![1; 32],
                    intake_pk: vec![1; 32],
                    seed_ct: vec![1; 32],
                    prefs: OnWirePrefs {
                        read_receipts: true,
                        online_visible: true,
                        send_typing: true,
                        disappear_after: None,
                        wake: None,
                    },
                }),
            },
        );
        engine
            .try_mint_inviter_intro(&mut pending_inviter, &rng, cid)
            .expect("pw");
        engine
            .try_mint_inviter_intro(&mut pinned.clone(), &rng, cid)
            .expect("noie");
        engine
            .try_mint_invitee_intro(&mut ticket_recv, &rng, ie_cid)
            .expect("nonotice");
        let mpoll = engine.poll(&mfail.state).expect("mp");
        let again = engine
            .ingest_packet(
                mfail.state,
                &rng,
                mpoll.list[0].channel.clone(),
                mpoll.list[0].tag,
                &bodies[0],
            )
            .expect("other-fail");
        assert!(again.persist.is_empty());
        let cid_j = super::super::codec::bstr(engine.suite.b64u(), cid.as_bytes());
        assert_eq!(
            super::parse_failed(
                engine.suite.b64u(),
                &Json::Object(vec![
                    ("conversation_id".into(), cid_j.clone()),
                    ("reason".into(), Json::String("PolicyNotAccepted".into())),
                    ("policy".into(), Json::Number(1)),
                ]),
            )
            .unwrap_err(),
            EngineError::MalformedPersist
        );
        assert_eq!(
            super::parse_failed(
                engine.suite.b64u(),
                &Json::Object(vec![
                    ("conversation_id".into(), cid_j),
                    ("reason".into(), Json::String("InviteExpired".into())),
                    ("expires".into(), Json::String("x".into())),
                ]),
            )
            .unwrap_err(),
            EngineError::MalformedPersist
        );
        let mut rk = EngineState::new();
        rk.failed.insert([1; 32], FailedReason::NoticeUnlockFailed);
        rk.inviters.insert([1; 32]);
        rk.skipped_mks.insert(
            [1; 32].to_vec(),
            vec![super::super::chain::CachedMk {
                mk: [2; 32],
                expires_at: 9,
            }],
        );
        rk.skipped_mks.insert(
            [9; 32].to_vec(),
            vec![super::super::chain::CachedMk {
                mk: [3; 32],
                expires_at: 9,
            }],
        );
        rk.frags.insert(
            [4; 32],
            super::FragSet {
                conversation_id: [9; 32],
                parts: Default::default(),
                last_i: None,
            },
        );
        let dummy = super::super::chain::SendChain {
            root: [0; 32],
            c: [0; 32],
            epoch: 0,
            packet_seq: 0,
        };
        rk.send_chains.insert([1; 32].to_vec(), dummy.clone());
        rk.send_chains.insert([8; 32].to_vec(), dummy.clone());
        rk.recv_chains.insert([1; 32].to_vec(), dummy.clone());
        rk.recv_chains.insert([8; 32].to_vec(), dummy);
        super::rekey_conversation(&mut rk, [1; 32], [2; 32]);
        assert_eq!(
            rk.failed.get(&[2; 32]),
            Some(&FailedReason::NoticeUnlockFailed)
        );
        assert!(rk.inviters.contains(&[2; 32]));
        engine
            .handshake_ingest_gate(&mut pinned.clone(), *cid.as_bytes(), &TxPayload::Confirm)
            .expect("g8");
        engine
            .try_mint_inviter_intro(&mut inv_conf.clone(), &rng, cid)
            .expect("hasintro");
        let secret = *ticket.secret.as_bytes();
        let key = super::super::chain::chain_key(&cid, &[]);
        let mut chain = named_ie.state.recv_chains.get(&key).cloned().expect("rc");
        let clash_body = DurableBody {
            conversation_id: cid,
            hlc: Hlc {
                wall_ms: 0,
                counter: 0,
            },
            payload: other_notice,
        };
        let packed_clash = packed_tx(&engine.suite, &clash_body);
        let pkts = fragment_body(
            &engine.suite,
            &packed_clash,
            Tag::from_bytes([0x44; 32]),
            Tag::from_bytes([0; 32]),
            chain.packet_seq,
            &[],
        )
        .expect("fr");
        let mut clash_ing = named_ie.state.clone();
        for pkt in pkts {
            let sealed = seal_packet(&engine.suite, &rng, &mk(engine.suite.hmac(), &chain), &pkt)
                .expect("sl");
            clash_ing = engine
                .ingest_packet(clash_ing, &rng, ch.clone(), tag, &sealed)
                .expect("cling")
                .state;
            chain = step(engine.suite.hmac(), &chain);
        }
        assert_eq!(
            clash_ing.failed.get(cid.as_bytes()),
            Some(&FailedReason::NoticeConflict)
        );
        let codec_chain = join(
            engine.suite.hmac(),
            &secret,
            ConversationSort::HandshakeDm,
            &[],
        )
        .expect("jnc");
        let b_codec = seal_packet(
            &engine.suite,
            &rng,
            &mk(engine.suite.hmac(), &codec_chain),
            &PacketPlain::TxFragLast(PacketTxFragLast {
                actor_id: Vec::new(),
                packet_seq: 0,
                tx_id: Tag::from_bytes([0x55; 32]),
                frag_i: 0,
                frag: vec![0xfe, 0xfd, 1],
                set_xor: Tag::from_bytes([0; 32]),
            }),
        )
        .expect("scodec");
        let (recv_codec, _) = engine
            .receive_ticket(
                engine
                    .tick(EngineState::new(), 1_700_000_000)
                    .expect("tco")
                    .state,
                &rng,
                uid,
                iid,
                &ticket_s,
            )
            .expect("rco");
        engine
            .ingest_packet(recv_codec.state, &rng, ch, tag, &b_codec)
            .expect("ico");
        engine.lock();
    }

    #[test]
    fn handshake_sync_intros() {
        use super::{
            Conversation, ConversationRef, FailedReason, Handshake, HandshakeInvitee,
            HandshakeInviter, SynchronizationQuery,
        };
        let mut engine = test_engine();
        let rng = CounterRng::new();
        engine
            .wrap_dek(&rng, &UnlockSecret::Passphrase("passpass".into()))
            .expect("wrap");
        let ticked = engine
            .tick(EngineState::new(), 1_700_000_000)
            .expect("tick");
        let (invited, sid) = engine
            .create_sync_invite(
                ticked.state,
                &rng,
                Policy::Classic,
                1_800_000_000,
                "phone",
                None,
            )
            .expect("sinv");
        let zeros = UserId::from_bytes([0; 32]);
        let zid = IdentityId::from_bytes([0; 32]);
        let ids = ConversationRef {
            user_id: zeros,
            identity_id: zid,
            conversation_id: sid,
        };
        let ticket_s = engine.ticket_host_string(&invited.state, &ids).expect("t");
        let notice_writes: Vec<_> = engine
            .poll(&invited.state)
            .expect("p")
            .write_durable
            .into_iter()
            .map(|w| (w.channel, w.tag, w.body))
            .collect();
        let inviter = ack_all(&engine, invited.state);
        let ie_tick = engine
            .tick(EngineState::new(), 1_700_000_000)
            .expect("it")
            .state;
        let (received, _) = engine
            .receive_sync_ticket(ie_tick, &rng, &ticket_s)
            .expect("recv");
        let named_ie = engine
            .set_device_name(received.state, &rng, "tablet")
            .expect("dn");
        let bodies: Vec<Vec<u8>> = notice_writes.iter().map(|w| w.2.clone()).collect();
        let minted = engine
            .ingest_list(
                named_ie.state,
                &rng,
                notice_writes[0].0.clone(),
                notice_writes[0].1,
                &bodies,
            )
            .expect("ing");
        assert!(matches!(
            engine
                .get_conversation(&minted.state, zeros, zid, sid)
                .expect("ir"),
            Conversation::HandshakeSync(Handshake::Invitee(
                HandshakeInvitee::IntroductionMinted { .. }
            ))
        ));
        let intro_writes: Vec<_> = engine
            .poll(&minted.state)
            .expect("ip")
            .write_durable
            .into_iter()
            .map(|w| (w.channel, w.tag, w.body))
            .collect();
        let sent = ack_all(&engine, minted.state);
        assert!(matches!(
            engine.get_conversation(&sent, zeros, zid, sid).expect("is"),
            Conversation::HandshakeSync(Handshake::Invitee(
                HandshakeInvitee::IntroductionSent { .. }
            ))
        ));
        let intro_bodies: Vec<Vec<u8>> = intro_writes.iter().map(|w| w.2.clone()).collect();
        let inv_minted = engine
            .ingest_list(
                inviter,
                &rng,
                intro_writes[0].0.clone(),
                intro_writes[0].1,
                &intro_bodies,
            )
            .expect("iing");
        assert!(matches!(
            engine
                .get_conversation(&inv_minted.state, zeros, zid, sid)
                .expect("im"),
            Conversation::HandshakeSync(Handshake::Inviter(
                HandshakeInviter::IntroductionMinted { .. }
            ))
        ));
        let inv_intro_writes: Vec<_> = engine
            .poll(&inv_minted.state)
            .expect("iip")
            .write_durable
            .into_iter()
            .map(|w| (w.channel, w.tag, w.body))
            .collect();
        let inv_conf = ack_all(&engine, inv_minted.state);
        assert!(matches!(
            engine
                .get_conversation(&inv_conf, zeros, zid, sid)
                .expect("ic"),
            Conversation::HandshakeSync(Handshake::Inviter(HandshakeInviter::Confirming {
                confirmation_digest: ref d,
                ..
            })) if d.is_empty()
        ));
        let ie_conf = engine
            .ingest_list(
                sent,
                &rng,
                inv_intro_writes[0].0.clone(),
                inv_intro_writes[0].1,
                &inv_intro_writes
                    .iter()
                    .map(|w| w.2.clone())
                    .collect::<Vec<_>>(),
            )
            .expect("ieing");
        assert!(matches!(
            engine
                .get_conversation(&ie_conf.state, zeros, zid, sid)
                .expect("iec"),
            Conversation::HandshakeSync(Handshake::Invitee(HandshakeInvitee::Confirming {
                confirmation_digest: ref d,
                ..
            })) if d.is_empty()
        ));
        let rejected = engine
            .reject_established(inv_conf.clone(), &rng, ids)
            .expect("rej");
        assert!(matches!(
            engine
                .get_conversation(&rejected.state, zeros, zid, sid)
                .expect("rejq"),
            Conversation::HandshakeSync(Handshake::Failed(FailedReason::ConfirmationRejected))
        ));
        let confirmed = engine
            .confirm_established(ie_conf.state, &rng, ids)
            .expect("conf");
        assert!(matches!(
            engine
                .get_conversation(&confirmed.state, zeros, zid, sid)
                .expect("est"),
            Conversation::Synchronization(SynchronizationQuery::SyncEstablished)
        ));
        let expired = engine.tick(inv_conf, 1_900_000_000).expect("exp");
        assert!(matches!(
            engine
                .get_conversation(&expired.state, zeros, zid, sid)
                .expect("exq"),
            Conversation::HandshakeSync(Handshake::Failed(FailedReason::InviteExpired { .. }))
        ));
        let _ = format!("{engine:?}");
        let _ = confirmed.persist();
        let _ = confirmed.pings();
        let _ = confirmed.state.tx_count();
        let _ = engine.defaults();
        let snap = engine.fold(expired.state.clone()).expect("foldp");
        let _ = snap.persist();
        let _ = snap.pings();
        engine.lock();
    }
}
