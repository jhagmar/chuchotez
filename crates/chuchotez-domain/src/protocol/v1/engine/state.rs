//! Folded engine CRDT and local identity directory.

use super::super::chain::{CachedMk, SendChain};
use super::super::kem::KeyPair;
use super::super::payload::{ConversationSort, DurableBody, Ticket};
use super::super::sign::SigningKeyPair;
use super::super::{
    ActorId, ConversationId, DeviceId, DisplayName, DurableChannel, FragIndex, IdentityId,
    PersistSeq, ProfilePic, Secret, Tag, TagKey, TimeBin, UnixSeconds, UserId,
};
use super::party::{
    DeviceConversation, DmParty, HandshakeFailure, IdentityConversation, InviteePhase,
    InviterPhase, PartyMut, PartyRef, SyncParty,
};
use super::query::{BlobPut, DurableWrite, EphemeralWrite, FailedReason};
use std::collections::{BTreeMap, BTreeSet};

/// List-bin progress keyed by durable channel and invite tag-key.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct BinKey {
    pub(super) kind: String,
    pub(super) address: String,
    pub(super) tag_key: TagKey,
}

/// Watermark and completed TimeBins for one invite-tag list.
#[derive(Clone, Debug)]
pub(super) struct BinProgress {
    pub(super) channel: DurableChannel,
    pub(super) tag_key: TagKey,
    pub(super) watermark: Option<TimeBin>,
    pub(super) completed: BTreeSet<TimeBin>,
}

/// Partial fragments of one `tx_id` until Last arrives.
#[derive(Clone, Debug)]
pub(super) struct FragSet {
    pub(super) conversation_id: ConversationId,
    pub(super) parts: BTreeMap<FragIndex, Vec<u8>>,
    pub(super) last_i: Option<FragIndex>,
}

/// A handshake ticket whose InviteTag matches an ingested packet.
pub(super) struct HandshakeHit {
    pub(super) cid: ConversationId,
    pub(super) secret: Secret,
    pub(super) sort: ConversationSort,
    pub(super) bin: TimeBin,
    pub(super) tag_key: TagKey,
}

/// Advertised encaps secret key not yet used to unwrap a wrap.
#[derive(Clone)]
pub(super) struct UnusedSk {
    pub(super) tx_id: Tag,
    pub(super) pk: Vec<u8>,
    pub(super) sk: Vec<u8>,
}

/// Shared secret from a wrap, waiting to mix or already recorded.
#[derive(Clone)]
pub(super) struct KnownShared {
    pub(super) wrap_tx: Tag,
    pub(super) shared: Secret,
    pub(super) ct_hash: Tag,
    pub(super) from_us: bool,
    pub(super) encaps_pk: Vec<u8>,
}

/// Advertise, wrap, ack, and mix bookkeeping for one conversation.
#[derive(Clone, Default)]
pub(super) struct Ratchet {
    /// Durable packets sealed since the last advertise, wrap, or ack we minted.
    pub(super) since: u64,
    /// Ratchet txs this device minted.
    pub(super) minted: BTreeSet<Tag>,
    /// Unused advertised secret keys, oldest first. Length at most 8.
    pub(super) unused: Vec<UnusedSk>,
    /// Shared secrets from wraps this device sent or unwrapped.
    pub(super) known: Vec<KnownShared>,
}

impl core::fmt::Debug for Ratchet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ratchet")
            .field("since", &self.since)
            .field("unused", &self.unused.len())
            .field("known", &self.known.len())
            .finish()
    }
}

/// One outstanding heal range. `hi` of all-`0xff` bytes is +∞.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum HealProbe {
    /// XOR of local ids in `[lo, hi)`.
    Half { lo: Tag, hi: Tag },
    /// Ids this device wants in `[lo, hi)`.
    Want { lo: Tag, hi: Tag, ids: Vec<Tag> },
    /// Ids this device has in `[lo, hi)`.
    Have { lo: Tag, hi: Tag, ids: Vec<Tag> },
}

/// Durable packet bodies held until a live XOR-ack or the 3-second fallback.
#[derive(Clone, Debug)]
pub(super) struct LivePending {
    pub(super) set_xor: Tag,
    pub(super) sent_at: UnixSeconds,
    pub(super) bodies: Vec<Vec<u8>>,
    pub(super) sealed_to: SendChain,
    pub(super) actor: ActorId,
    pub(super) acks: u8,
    pub(super) needed: u8,
}

/// Heal search waiting for an answer, plus durable bodies sealed for fallback.
#[derive(Clone, Debug, Default)]
pub(super) struct Heal {
    pub(super) probes: Vec<HealProbe>,
    pub(super) sent_at: Option<UnixSeconds>,
    /// In-flight probes were posted on Ephemeral.
    pub(super) on_ephemeral: bool,
    /// Fallback to Persistent already ran for this search.
    pub(super) fell_back: bool,
    /// Durable ciphertexts sealed at `sealed_from`, posted when the fallback is due.
    pub(super) ready: Vec<Vec<u8>>,
    pub(super) sealed_from: Option<SendChain>,
    pub(super) sealed_to: Option<SendChain>,
    pub(super) needs_reseal: bool,
}

/// Packet chains, skip-ahead `mk`s, last Persistent acks, and ratchet state.
#[derive(Clone, Debug, Default)]
pub(super) struct ConversationChains {
    pub(super) send: BTreeMap<ActorId, SendChain>,
    pub(super) recv: BTreeMap<ActorId, SendChain>,
    pub(super) skipped_mks: BTreeMap<ActorId, Vec<CachedMk>>,
    pub(super) last_acks: BTreeMap<ActorId, BTreeSet<Tag>>,
    pub(super) ratchet: Ratchet,
    /// Heal search still waiting for an answer.
    pub(super) heal: Heal,
    /// Ticked instant until which this conversation is live. `None` before a live ack.
    pub(super) live_until: Option<UnixSeconds>,
    /// Durable packet bodies waiting for a live XOR-ack.
    pub(super) live_pending: Vec<LivePending>,
    /// A presence probe was sent since this process came online.
    pub(super) presence_sent: bool,
    /// Sender of a chat tx, for query `messages`.
    pub(super) chat_senders: BTreeMap<Tag, Vec<u8>>,
    /// Latest composing signal. Not folded.
    pub(super) typing: Option<TypingNote>,
    /// Latest presence time. Not folded.
    pub(super) presence_at: Option<UnixSeconds>,
}

/// Ephemeral composing signal kept until query or reload.
#[derive(Clone, Debug)]
pub(super) struct TypingNote {
    pub(super) composing: bool,
    pub(super) at: UnixSeconds,
}

/// DM conversation row: phase plus packet chains.
#[derive(Clone, Debug)]
pub(super) struct IdentityNode {
    pub(super) kind: IdentityConversation,
    pub(super) chains: ConversationChains,
}

/// Sync conversation row: phase plus packet chains.
#[derive(Clone, Debug)]
pub(super) struct DeviceNode {
    pub(super) kind: DeviceConversation,
    pub(super) chains: ConversationChains,
}

impl IdentityNode {
    pub(super) fn handshake(party: DmParty) -> Self {
        Self {
            kind: IdentityConversation::DmHandshake(party),
            chains: ConversationChains::default(),
        }
    }

    pub(super) fn direct(secret: Secret, parent: ConversationId) -> Self {
        Self {
            kind: IdentityConversation::DirectMessage { secret, parent },
            chains: ConversationChains::default(),
        }
    }
}

impl DeviceNode {
    pub(super) fn handshake(party: SyncParty) -> Self {
        Self {
            kind: DeviceConversation::SyncHandshake(party),
            chains: ConversationChains::default(),
        }
    }

    pub(super) fn sync(secret: Secret, parent: ConversationId) -> Self {
        Self {
            kind: DeviceConversation::Synchronization { secret, parent },
            chains: ConversationChains::default(),
        }
    }
}

/// One identity: display name, picture, and that identity's conversations.
#[derive(Clone, Debug, Default)]
pub(super) struct Identity {
    pub(super) name: Option<DisplayName>,
    pub(super) pic: Option<ProfilePic>,
    pub(super) conversations: BTreeMap<ConversationId, IdentityNode>,
}

/// One user: identities keyed by `IdentityId`.
#[derive(Clone, Debug, Default)]
pub(super) struct User {
    pub(super) identities: BTreeMap<IdentityId, Identity>,
}

/// This device: Sync conversations, device keys, and device name.
#[derive(Clone, Debug, Default)]
pub(super) struct Device {
    pub(super) name: Option<DisplayName>,
    pub(super) keys: Option<DeviceKeys>,
    pub(super) conversations: BTreeMap<ConversationId, DeviceNode>,
}

/// Encryption and signing keys for this device. `id` is set when this device invites.
#[derive(Clone, Debug)]
pub(super) struct DeviceKeys {
    pub(super) id: Option<DeviceId>,
    pub(super) enc: KeyPair,
    pub(super) sign: SigningKeyPair,
}

/// Where a conversation row lives.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ConversationScope {
    Identity { user: UserId, identity: IdentityId },
    Device,
}

/// Host-owned CRDT plus the local identity directory.
///
/// `txs` is the protocol CRDT: one set of `DurableBody` keyed by `tx_id`. Merge,
/// persist, `set_xor`, and Sync gossip walk that set. Conversation query filters
/// it. Packet chains and last Persistent acks live on that row. Invite-tag
/// `BinProgress` stays keyed by channel and tag-key so ingest can match
/// InviteTag before a packet names an identity.
///
/// `users` and `device` are the local directory. An identity owns its DM
/// conversations. Sync conversations live on this device and appear on every
/// identity in `listConversations`. Each conversation value is either a
/// handshake (ticket, role, and open secrets or a failure) or an established
/// child (spawn secret and parent handshake id).
#[derive(Clone, Debug, Default)]
pub struct EngineState {
    /// Durable bodies keyed by `tx_id`.
    pub(super) txs: BTreeMap<Tag, DurableBody>,
    /// Next persist-record sequence number.
    pub(super) next_seq: PersistSeq,
    /// Last `tick` Unix seconds.
    pub(super) ticked: Option<UnixSeconds>,
    /// Outstanding durable 512-byte writes.
    pub(super) writes: Vec<DurableWrite>,
    /// Outstanding ephemeral 512-byte writes.
    pub(super) eph_writes: Vec<EphemeralWrite>,
    /// Outstanding blob puts.
    pub(super) blob_puts: Vec<BlobPut>,
    /// In-flight packet fragments keyed by `tx_id`.
    pub(super) frags: BTreeMap<Tag, FragSet>,
    /// Invite-tag list-bin watermarks.
    pub(super) bin_progress: BTreeMap<BinKey, BinProgress>,
    /// Persist seq to `tx_id` for fold watermark checks.
    pub(super) persist_log: BTreeMap<PersistSeq, Tag>,
    /// Users, identities, and DM conversations.
    pub(super) users: BTreeMap<UserId, User>,
    /// This device and its Sync conversations.
    pub(super) device: Device,
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

    pub(super) fn ensure_user(&mut self, user: UserId) -> &mut User {
        self.users.entry(user).or_default()
    }

    pub(super) fn ensure_identity(&mut self, user: UserId, identity: IdentityId) -> &mut Identity {
        self.ensure_user(user)
            .identities
            .entry(identity)
            .or_default()
    }

    pub(super) fn identity(&self, user: UserId, identity: IdentityId) -> Option<&Identity> {
        self.users.get(&user)?.identities.get(&identity)
    }

    pub(super) fn identity_mut(
        &mut self,
        user: UserId,
        identity: IdentityId,
    ) -> Option<&mut Identity> {
        self.users.get_mut(&user)?.identities.get_mut(&identity)
    }

    pub(super) fn display_name(&self, identity: IdentityId) -> Option<&DisplayName> {
        self.users.values().find_map(|user| {
            user.identities
                .get(&identity)
                .and_then(|row| row.name.as_ref())
        })
    }

    pub(super) fn profile_pic(&self, identity: IdentityId) -> Option<ProfilePic> {
        self.users.values().find_map(|user| {
            user.identities
                .get(&identity)
                .and_then(|row| row.pic.clone())
        })
    }

    pub(super) fn put_dm(
        &mut self,
        user: UserId,
        identity: IdentityId,
        cid: ConversationId,
        node: IdentityNode,
    ) {
        self.ensure_identity(user, identity)
            .conversations
            .insert(cid, node);
    }

    pub(super) fn put_sync(&mut self, cid: ConversationId, node: DeviceNode) {
        self.device.conversations.insert(cid, node);
    }

    pub(super) fn put_dm_inviter(
        &mut self,
        user: UserId,
        identity: IdentityId,
        cid: ConversationId,
        phase: InviterPhase,
    ) {
        self.put_dm(
            user,
            identity,
            cid,
            IdentityNode::handshake(DmParty::inviter(phase)),
        );
    }

    pub(super) fn put_dm_invitee(
        &mut self,
        user: UserId,
        identity: IdentityId,
        cid: ConversationId,
        phase: InviteePhase,
    ) {
        self.put_dm(
            user,
            identity,
            cid,
            IdentityNode::handshake(DmParty::invitee(phase)),
        );
    }

    pub(super) fn put_sync_inviter(&mut self, cid: ConversationId, phase: InviterPhase) {
        self.put_sync(cid, DeviceNode::handshake(SyncParty::inviter(phase)));
    }

    pub(super) fn put_sync_invitee(&mut self, cid: ConversationId, phase: InviteePhase) {
        self.put_sync(cid, DeviceNode::handshake(SyncParty::invitee(phase)));
    }

    pub(super) fn scope_of(&self, cid: ConversationId) -> Option<ConversationScope> {
        for (user_id, user) in &self.users {
            for (identity_id, ident) in &user.identities {
                if ident.conversations.contains_key(&cid) {
                    return Some(ConversationScope::Identity {
                        user: *user_id,
                        identity: *identity_id,
                    });
                }
            }
        }
        if self.device.conversations.contains_key(&cid) {
            Some(ConversationScope::Device)
        } else {
            None
        }
    }

    pub(super) fn party(&self, cid: ConversationId) -> Option<PartyRef<'_>> {
        for user in self.users.values() {
            for ident in user.identities.values() {
                if let Some(IdentityConversation::DmHandshake(party)) =
                    ident.conversations.get(&cid).map(|n| &n.kind)
                {
                    return Some(PartyRef::Dm(party));
                }
            }
        }
        match self.device.conversations.get(&cid).map(|n| &n.kind) {
            Some(DeviceConversation::SyncHandshake(party)) => Some(PartyRef::Sync(party)),
            _ => None,
        }
    }

    pub(super) fn party_mut(&mut self, cid: ConversationId) -> Option<PartyMut<'_>> {
        if let Some(party) = self.users.values_mut().find_map(|user| {
            user.identities.values_mut().find_map(|ident| {
                ident
                    .conversations
                    .get_mut(&cid)
                    .and_then(|node| match &mut node.kind {
                        IdentityConversation::DmHandshake(party) => Some(party),
                        IdentityConversation::DirectMessage { .. }
                        | IdentityConversation::Group(_) => None,
                    })
            })
        }) {
            return Some(PartyMut::Dm(party));
        }
        self.device
            .conversations
            .get_mut(&cid)
            .and_then(|node| match &mut node.kind {
                DeviceConversation::SyncHandshake(party) => Some(PartyMut::Sync(party)),
                DeviceConversation::Synchronization { .. } => None,
            })
    }

    pub(super) fn chains(&self, cid: ConversationId) -> Option<&ConversationChains> {
        for user in self.users.values() {
            for ident in user.identities.values() {
                if let Some(node) = ident.conversations.get(&cid) {
                    return Some(&node.chains);
                }
            }
        }
        self.device.conversations.get(&cid).map(|n| &n.chains)
    }

    pub(super) fn chains_mut(&mut self, cid: ConversationId) -> Option<&mut ConversationChains> {
        if let Some(chains) = self.users.values_mut().find_map(|user| {
            user.identities
                .values_mut()
                .find_map(|ident| ident.conversations.get_mut(&cid).map(|n| &mut n.chains))
        }) {
            return Some(chains);
        }
        self.device
            .conversations
            .get_mut(&cid)
            .map(|n| &mut n.chains)
    }

    pub(super) fn for_each_chains<F: FnMut(ConversationId, &ConversationChains)>(&self, mut f: F) {
        for user in self.users.values() {
            for ident in user.identities.values() {
                for (cid, node) in &ident.conversations {
                    f(*cid, &node.chains);
                }
            }
        }
        for (cid, node) in &self.device.conversations {
            f(*cid, &node.chains);
        }
    }

    pub(super) fn each_chains_mut<F: FnMut(&mut ConversationChains)>(&mut self, mut f: F) {
        for user in self.users.values_mut() {
            for ident in user.identities.values_mut() {
                for node in ident.conversations.values_mut() {
                    f(&mut node.chains);
                }
            }
        }
        for node in self.device.conversations.values_mut() {
            f(&mut node.chains);
        }
    }

    pub(super) fn ticket(&self, cid: ConversationId) -> Option<&Ticket> {
        if let Some(party) = self.dm_party(cid) {
            return Some(party.ticket());
        }
        self.sync_party(cid).map(|p| p.ticket())
    }

    fn dm_party(&self, cid: ConversationId) -> Option<&DmParty> {
        for user in self.users.values() {
            for ident in user.identities.values() {
                if let Some(IdentityConversation::DmHandshake(party)) =
                    ident.conversations.get(&cid).map(|n| &n.kind)
                {
                    return Some(party);
                }
            }
        }
        None
    }

    fn sync_party(&self, cid: ConversationId) -> Option<&SyncParty> {
        match self.device.conversations.get(&cid).map(|n| &n.kind) {
            Some(DeviceConversation::SyncHandshake(party)) => Some(party),
            _ => None,
        }
    }

    pub(super) fn intake_secret(&self, cid: ConversationId) -> Option<Vec<u8>> {
        let copy = |party: PartyRef<'_>| party.intake().map(|k| k.secret_bytes().to_vec());
        self.party(cid).and_then(copy)
    }

    pub(super) fn list_from(&self, cid: ConversationId) -> Option<TimeBin> {
        self.party(cid).map(|p| p.list_from())
    }

    pub(super) fn is_sync(&self, cid: ConversationId) -> bool {
        self.device.conversations.contains_key(&cid)
    }

    #[cfg(test)]
    pub(super) fn is_sync_established(&self, cid: ConversationId) -> bool {
        matches!(
            self.device.conversations.get(&cid).map(|n| &n.kind),
            Some(DeviceConversation::Synchronization { .. })
        )
    }

    pub(super) fn has_sync_handshake(&self) -> bool {
        self.device
            .conversations
            .values()
            .any(|n| matches!(n.kind, DeviceConversation::SyncHandshake(_)))
    }

    pub(super) fn is_inviter(&self, cid: ConversationId) -> bool {
        self.party(cid).is_some_and(|p| p.is_inviter())
    }

    pub(super) fn established_secret(&self, cid: ConversationId) -> Option<Secret> {
        for user in self.users.values() {
            for ident in user.identities.values() {
                match ident.conversations.get(&cid).map(|n| &n.kind) {
                    Some(IdentityConversation::DirectMessage { secret, .. }) => {
                        return Some(*secret);
                    }
                    Some(IdentityConversation::Group(super::party::GroupPhase::Live(live))) => {
                        return Some(live.secret);
                    }
                    _ => {}
                }
            }
        }
        match self.device.conversations.get(&cid).map(|n| &n.kind) {
            Some(DeviceConversation::Synchronization { secret, .. }) => Some(*secret),
            _ => None,
        }
    }

    pub(super) fn child_of(&self, handshake: ConversationId) -> Option<ConversationId> {
        for user in self.users.values() {
            for ident in user.identities.values() {
                for (cid, node) in &ident.conversations {
                    if let IdentityConversation::DirectMessage { parent, .. } = &node.kind
                        && *parent == handshake
                    {
                        return Some(*cid);
                    }
                }
            }
        }
        for (cid, node) in &self.device.conversations {
            if let DeviceConversation::Synchronization { parent, .. } = &node.kind
                && *parent == handshake
            {
                return Some(*cid);
            }
        }
        None
    }

    pub(super) fn established_parent(&self, cid: ConversationId) -> Option<ConversationId> {
        for user in self.users.values() {
            for ident in user.identities.values() {
                if let Some(IdentityConversation::DirectMessage { parent, .. }) =
                    ident.conversations.get(&cid).map(|n| &n.kind)
                {
                    return Some(*parent);
                }
            }
        }
        match self.device.conversations.get(&cid).map(|n| &n.kind) {
            Some(DeviceConversation::Synchronization { parent, .. }) => Some(*parent),
            _ => None,
        }
    }

    pub(super) fn owner(&self, cid: ConversationId) -> Option<(UserId, IdentityId)> {
        match self.scope_of(cid)? {
            ConversationScope::Identity { user, identity } => Some((user, identity)),
            ConversationScope::Device => None,
        }
    }

    pub(super) fn failed(&self, cid: ConversationId) -> Option<FailedReason> {
        self.party(cid).and_then(|p| p.failure()).map(Into::into)
    }

    pub(super) fn fail(&mut self, cid: ConversationId, reason: HandshakeFailure) {
        if let Some(mut party) = self.party_mut(cid) {
            party.fail(reason);
        }
    }

    pub(super) fn ack_posted(&mut self, cid: ConversationId) {
        if let Some(mut party) = self.party_mut(cid) {
            party.ack_posted();
        }
    }

    pub(super) fn spawn_established(
        &mut self,
        handshake: ConversationId,
        child: ConversationId,
        secret: Secret,
    ) {
        if self.child_of(handshake).is_some() {
            return;
        }
        match self.scope_of(handshake) {
            Some(ConversationScope::Identity { user, identity }) => {
                self.put_dm(
                    user,
                    identity,
                    child,
                    IdentityNode::direct(secret, handshake),
                );
            }
            Some(ConversationScope::Device) | None => {
                self.put_sync(child, DeviceNode::sync(secret, handshake));
            }
        }
    }

    /// Ticket, list origin, sort, and whether the row is still a handshake.
    pub(super) fn handshake_entries(&self) -> Vec<HandshakeEntry<'_>> {
        let mut rows = Vec::new();
        for user in self.users.values() {
            for ident in user.identities.values() {
                for (cid, node) in &ident.conversations {
                    if let IdentityConversation::DmHandshake(party) = &node.kind {
                        rows.push(HandshakeEntry {
                            cid: *cid,
                            party: PartyRef::Dm(party),
                            sort: ConversationSort::HandshakeDm,
                        });
                    }
                }
            }
        }
        for (cid, node) in &self.device.conversations {
            if let DeviceConversation::SyncHandshake(party) = &node.kind {
                rows.push(HandshakeEntry {
                    cid: *cid,
                    party: PartyRef::Sync(party),
                    sort: ConversationSort::HandshakeSync,
                });
            }
        }
        rows
    }

    pub(super) fn conversation_ids_for(
        &self,
        user: UserId,
        identity: IdentityId,
    ) -> Vec<ConversationId> {
        let mut ids = Vec::new();
        if let Some(ident) = self.identity(user, identity) {
            ids.extend(ident.conversations.keys().copied());
        }
        ids.extend(self.device.conversations.keys().copied());
        ids
    }

    pub(super) fn rekey_row(&mut self, from: ConversationId, to: ConversationId) {
        for user in self.users.values_mut() {
            for ident in user.identities.values_mut() {
                rekey_map(&mut ident.conversations, from, to);
                for node in ident.conversations.values_mut() {
                    if let IdentityConversation::DirectMessage { parent, .. } = &mut node.kind
                        && *parent == from
                    {
                        *parent = to;
                    }
                }
            }
        }
        rekey_map(&mut self.device.conversations, from, to);
        for node in self.device.conversations.values_mut() {
            if let DeviceConversation::Synchronization { parent, .. } = &mut node.kind
                && *parent == from
            {
                *parent = to;
            }
        }
    }

    pub(super) fn drop_conversation(&mut self, cid: ConversationId) -> bool {
        let identity = self.users.iter_mut().any(|(_, user)| {
            user.identities
                .iter_mut()
                .any(|(_, ident)| ident.conversations.remove(&cid).is_some())
        });
        let device = self.device.conversations.remove(&cid).is_some();
        identity || device
    }

    #[cfg(test)]
    pub(crate) fn set_next_seq(&mut self, seq: u64) {
        self.next_seq = PersistSeq::from_u64(seq);
    }

    #[cfg(test)]
    pub(crate) fn send_chain_seq(&self, conversation_id: &ConversationId) -> Option<u64> {
        self.chains(*conversation_id)
            .and_then(|c| c.send.get(&ActorId::handshake()))
            .map(|c| c.packet_seq.as_u64())
    }

    #[cfg(test)]
    pub(crate) fn recv_chain_seq(&self, conversation_id: &ConversationId) -> Option<u64> {
        self.chains(*conversation_id)
            .and_then(|c| c.recv.get(&ActorId::handshake()))
            .map(|c| c.packet_seq.as_u64())
    }

    #[cfg(test)]
    pub(crate) fn has_last_acks(&self) -> bool {
        self.users.values().any(|user| {
            user.identities.values().any(|ident| {
                ident
                    .conversations
                    .values()
                    .any(|n| !n.chains.last_acks.is_empty())
            })
        }) || self
            .device
            .conversations
            .values()
            .any(|n| !n.chains.last_acks.is_empty())
    }

    #[cfg(test)]
    pub(crate) fn put_skipped(&mut self, cid: ConversationId, actor: ActorId, entry: CachedMk) {
        if let Some(chains) = self.chains_mut(cid) {
            chains.skipped_mks.entry(actor).or_default().push(entry);
        }
    }

    #[cfg(test)]
    pub(crate) fn put_send_chain(&mut self, cid: ConversationId, actor: ActorId, chain: SendChain) {
        if let Some(chains) = self.chains_mut(cid) {
            chains.send.insert(actor, chain);
        }
    }

    #[cfg(test)]
    pub(crate) fn put_recv_chain(&mut self, cid: ConversationId, actor: ActorId, chain: SendChain) {
        if let Some(chains) = self.chains_mut(cid) {
            chains.recv.insert(actor, chain);
        }
    }

    #[cfg(test)]
    pub(crate) fn put_last_ack(&mut self, cid: ConversationId, actor: ActorId, ids: BTreeSet<Tag>) {
        if let Some(chains) = self.chains_mut(cid) {
            chains.last_acks.insert(actor, ids);
        }
    }

    #[cfg(test)]
    pub(crate) fn copy_chains_from(&mut self, src: &EngineState, cid: ConversationId) {
        if let Some(from) = src.chains(cid)
            && let Some(to) = self.chains_mut(cid)
        {
            *to = from.clone();
        }
    }

    #[cfg(test)]
    pub(crate) fn last_acks_snapshot(
        &self,
    ) -> BTreeMap<ConversationId, BTreeMap<ActorId, BTreeSet<Tag>>> {
        let mut out = BTreeMap::new();
        for user in self.users.values() {
            for ident in user.identities.values() {
                for (id, node) in &ident.conversations {
                    out.insert(*id, node.chains.last_acks.clone());
                }
            }
        }
        for (id, node) in &self.device.conversations {
            out.insert(*id, node.chains.last_acks.clone());
        }
        out
    }

    #[cfg(test)]
    pub(crate) fn cover_last_acks(&mut self) {
        let mut by_cid: BTreeMap<ConversationId, BTreeSet<Tag>> = BTreeMap::new();
        for (id, body) in &self.txs {
            by_cid.entry(body.conversation_id).or_default().insert(*id);
        }
        let apply = |cid: ConversationId, chains: &mut ConversationChains| {
            if let Some(ids) = by_cid.get(&cid) {
                for set in chains.last_acks.values_mut() {
                    *set = ids.clone();
                }
            }
        };
        for user in self.users.values_mut() {
            for ident in user.identities.values_mut() {
                for (cid, node) in ident.conversations.iter_mut() {
                    apply(*cid, &mut node.chains);
                }
            }
        }
        for (cid, node) in self.device.conversations.iter_mut() {
            apply(*cid, &mut node.chains);
        }
    }
}

/// One open or failed handshake row.
pub(super) struct HandshakeEntry<'a> {
    pub(super) cid: ConversationId,
    pub(super) party: PartyRef<'a>,
    pub(super) sort: ConversationSort,
}

fn rekey_map<V>(map: &mut BTreeMap<ConversationId, V>, from: ConversationId, to: ConversationId) {
    if let Some(v) = map.remove(&from) {
        map.insert(to, v);
    }
}
