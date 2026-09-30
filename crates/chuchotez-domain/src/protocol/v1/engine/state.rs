//! Folded engine CRDT and local identity directory.

#[cfg(test)]
use super::super::chain::chain_key;
use super::super::chain::{CachedMk, SendChain};
use super::super::kem::KeyPair;
use super::super::payload::{ConversationSort, DurableBody, Ticket};
use super::super::sign::SigningKeyPair;
use super::super::{
    ConversationId, DeviceId, DisplayName, DurableChannel, IdentityId, ProfilePic, Secret, Tag,
    TagKey, UserId,
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
    pub(super) watermark: Option<u64>,
    pub(super) completed: BTreeSet<u64>,
}

/// Partial fragments of one `tx_id` until Last arrives.
#[derive(Clone, Debug)]
pub(super) struct FragSet {
    pub(super) conversation_id: ConversationId,
    pub(super) parts: BTreeMap<u64, Vec<u8>>,
    pub(super) last_i: Option<u64>,
}

/// A handshake ticket whose InviteTag matches an ingested packet.
pub(super) struct HandshakeHit {
    pub(super) cid: ConversationId,
    pub(super) secret: Secret,
    pub(super) sort: ConversationSort,
    pub(super) bin: u64,
    pub(super) tag_key: TagKey,
}

/// Inviter minted the ticket; invitee received it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HandshakeRole {
    Inviter,
    Invitee,
}

/// Handshake secrets that live only while the row is still open.
#[derive(Clone, Debug)]
pub(super) struct HandshakeOpen {
    pub(super) intake: Option<KeyPair>,
    pub(super) shared_inviter: Option<Secret>,
    pub(super) shared_invitee: Option<Secret>,
    pub(super) child: Option<ConversationId>,
}

/// Open handshake, or a stored [`FailedReason`].
#[derive(Clone, Debug)]
pub(super) enum HandshakePhase {
    Open(HandshakeOpen),
    Failed(FailedReason),
}

/// One handshake conversation: ticket, role, and either open secrets or a failure.
#[derive(Clone, Debug)]
pub(super) struct HandshakeSession {
    pub(super) ticket: Ticket,
    pub(super) role: HandshakeRole,
    pub(super) phase: HandshakePhase,
}

impl HandshakeSession {
    pub(super) fn open(ticket: Ticket, role: HandshakeRole) -> Self {
        Self {
            ticket,
            role,
            phase: HandshakePhase::Open(HandshakeOpen {
                intake: None,
                shared_inviter: None,
                shared_invitee: None,
                child: None,
            }),
        }
    }

    pub(super) fn failed(ticket: Ticket, role: HandshakeRole, reason: FailedReason) -> Self {
        Self {
            ticket,
            role,
            phase: HandshakePhase::Failed(reason),
        }
    }

    pub(super) fn with_intake(mut self, intake: Option<KeyPair>) -> Self {
        self.set_intake_opt(intake);
        self
    }

    pub(super) fn with_shared_inviter(mut self, shared: Option<Secret>) -> Self {
        if let HandshakePhase::Open(open) = &mut self.phase {
            open.shared_inviter = shared;
        }
        self
    }

    pub(super) fn with_shared_invitee(mut self, shared: Option<Secret>) -> Self {
        if let HandshakePhase::Open(open) = &mut self.phase {
            open.shared_invitee = shared;
        }
        self
    }

    pub(super) fn with_child(mut self, child: Option<ConversationId>) -> Self {
        if let HandshakePhase::Open(open) = &mut self.phase {
            open.child = child;
        }
        self
    }

    pub(super) fn fail(&mut self, reason: FailedReason) {
        self.phase = HandshakePhase::Failed(reason);
    }

    pub(super) fn failed_reason(&self) -> Option<FailedReason> {
        match self.phase {
            HandshakePhase::Failed(reason) => Some(reason),
            HandshakePhase::Open(_) => None,
        }
    }

    pub(super) fn is_inviter(&self) -> bool {
        matches!(self.role, HandshakeRole::Inviter)
    }

    pub(super) fn open_mut(&mut self) -> Option<&mut HandshakeOpen> {
        match &mut self.phase {
            HandshakePhase::Open(open) => Some(open),
            HandshakePhase::Failed(_) => None,
        }
    }

    pub(super) fn open_ref(&self) -> Option<&HandshakeOpen> {
        match &self.phase {
            HandshakePhase::Open(open) => Some(open),
            HandshakePhase::Failed(_) => None,
        }
    }

    pub(super) fn intake(&self) -> Option<&KeyPair> {
        self.open_ref().and_then(|o| o.intake.as_ref())
    }

    pub(super) fn set_intake_opt(&mut self, intake: Option<KeyPair>) {
        if let Some(open) = self.open_mut() {
            open.intake = intake;
        }
    }

    pub(super) fn set_intake(&mut self, intake: KeyPair) {
        self.set_intake_opt(Some(intake));
    }

    pub(super) fn shared_inviter(&self) -> Option<&Secret> {
        self.open_ref().and_then(|o| o.shared_inviter.as_ref())
    }

    pub(super) fn set_shared_inviter(&mut self, shared: Secret) {
        if let Some(open) = self.open_mut() {
            open.shared_inviter = Some(shared);
        }
    }

    pub(super) fn shared_invitee(&self) -> Option<&Secret> {
        self.open_ref().and_then(|o| o.shared_invitee.as_ref())
    }

    pub(super) fn set_shared_invitee(&mut self, shared: Secret) {
        if let Some(open) = self.open_mut() {
            open.shared_invitee = Some(shared);
        }
    }

    #[cfg(test)]
    pub(super) fn clear_intake(&mut self) {
        self.set_intake_opt(None);
    }

    #[cfg(test)]
    pub(super) fn clear_shared(&mut self) {
        if let Some(open) = self.open_mut() {
            open.shared_inviter = None;
            open.shared_invitee = None;
        }
    }

    pub(super) fn child(&self) -> Option<ConversationId> {
        self.open_ref().and_then(|o| o.child)
    }

    pub(super) fn set_child(&mut self, child: ConversationId) {
        if let Some(open) = self.open_mut() {
            open.child = Some(child);
        }
    }

    pub(super) fn clear_child_if(&mut self, child: ConversationId) {
        if let Some(open) = self.open_mut()
            && open.child == Some(child)
        {
            open.child = None;
        }
    }
}

/// Spawned DM or Sync conversation whose secret is `spawn_secret`.
#[derive(Clone, Debug)]
pub(super) struct EstablishedSession {
    pub(super) secret: Secret,
    pub(super) parent: ConversationId,
}

/// Conversation row owned by an identity or by this device.
#[derive(Clone, Debug)]
pub(super) enum ConversationNode {
    Handshake(HandshakeSession),
    Established(EstablishedSession),
}

impl ConversationNode {
    fn handshake(&self) -> Option<&HandshakeSession> {
        match self {
            Self::Handshake(hs) => Some(hs),
            Self::Established(_) => None,
        }
    }

    fn handshake_mut(&mut self) -> Option<&mut HandshakeSession> {
        match self {
            Self::Handshake(hs) => Some(hs),
            Self::Established(_) => None,
        }
    }

    fn established(&self) -> Option<&EstablishedSession> {
        match self {
            Self::Established(es) => Some(es),
            Self::Handshake(_) => None,
        }
    }
}

/// One identity: display name, picture, and that identity's conversations.
#[derive(Clone, Debug, Default)]
pub(super) struct Identity {
    pub(super) name: Option<DisplayName>,
    pub(super) pic: Option<ProfilePic>,
    pub(super) conversations: BTreeMap<ConversationId, ConversationNode>,
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
    pub(super) id: Option<DeviceId>,
    pub(super) enc: Option<KeyPair>,
    pub(super) sign: Option<SigningKeyPair>,
    pub(super) conversations: BTreeMap<ConversationId, ConversationNode>,
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
/// it. Packet chain, fragment, and list-bin maps stay keyed for ingest that
/// matches InviteTag before a packet names an identity.
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
    pub(super) next_seq: u64,
    /// Last `tick` Unix seconds.
    pub(super) ticked: Option<u64>,
    /// Outstanding durable 512-byte writes.
    pub(super) writes: Vec<DurableWrite>,
    /// Outstanding ephemeral 512-byte writes.
    pub(super) eph_writes: Vec<EphemeralWrite>,
    /// Outstanding blob puts.
    pub(super) blob_puts: Vec<BlobPut>,
    /// Sending packet chains, keyed by `chain_key(conversation_id, actor_id)`.
    pub(super) send_chains: BTreeMap<Vec<u8>, SendChain>,
    /// Receiving packet chains, keyed by the same chain key.
    pub(super) recv_chains: BTreeMap<Vec<u8>, SendChain>,
    /// Skip-ahead `mk` cache, keyed by the same chain key.
    pub(super) skipped_mks: BTreeMap<Vec<u8>, Vec<CachedMk>>,
    /// In-flight packet fragments keyed by `tx_id`.
    pub(super) frags: BTreeMap<Tag, FragSet>,
    /// Invite-tag list-bin watermarks.
    pub(super) bin_progress: BTreeMap<BinKey, BinProgress>,
    /// Users, identities, and DM conversations.
    pub(super) users: BTreeMap<UserId, User>,
    /// This device and its Sync conversations.
    pub(super) device: Device,
}

/// Parsed fold arrays assembled into the identity directory.
pub(super) struct FoldDirectory {
    pub(super) tickets: Vec<(ConversationId, Ticket, bool)>,
    pub(super) owners: BTreeMap<ConversationId, (UserId, IdentityId)>,
    pub(super) inviters: BTreeSet<ConversationId>,
    pub(super) intake: BTreeMap<ConversationId, KeyPair>,
    pub(super) shared_inviter: BTreeMap<ConversationId, Secret>,
    pub(super) shared_invitee: BTreeMap<ConversationId, Secret>,
    pub(super) failed: BTreeMap<ConversationId, FailedReason>,
    pub(super) children: BTreeMap<ConversationId, ConversationId>,
    pub(super) established: Vec<(ConversationId, ConversationId, Secret, bool)>,
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
        node: ConversationNode,
    ) {
        self.ensure_identity(user, identity)
            .conversations
            .insert(cid, node);
    }

    pub(super) fn put_sync(&mut self, cid: ConversationId, node: ConversationNode) {
        self.device.conversations.insert(cid, node);
    }

    pub(super) fn put_handshake(
        &mut self,
        scope: ConversationScope,
        cid: ConversationId,
        session: HandshakeSession,
    ) {
        let node = ConversationNode::Handshake(session);
        match scope {
            ConversationScope::Identity { user, identity } => {
                self.put_dm(user, identity, cid, node);
            }
            ConversationScope::Device => self.put_sync(cid, node),
        }
    }

    fn find_node(&self, cid: ConversationId) -> Option<&ConversationNode> {
        for user in self.users.values() {
            for ident in user.identities.values() {
                if let Some(node) = ident.conversations.get(&cid) {
                    return Some(node);
                }
            }
        }
        self.device.conversations.get(&cid)
    }

    fn find_node_mut(&mut self, cid: ConversationId) -> Option<&mut ConversationNode> {
        self.users
            .values_mut()
            .find_map(|user| {
                user.identities
                    .values_mut()
                    .find_map(|ident| ident.conversations.get_mut(&cid))
            })
            .or_else(|| self.device.conversations.get_mut(&cid))
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

    pub(super) fn take_node(
        &mut self,
        cid: ConversationId,
    ) -> Option<(ConversationScope, ConversationNode)> {
        let from_identity = self.users.iter_mut().find_map(|(user_id, user)| {
            user.identities.iter_mut().find_map(|(identity_id, ident)| {
                ident.conversations.remove(&cid).map(|node| {
                    (
                        ConversationScope::Identity {
                            user: *user_id,
                            identity: *identity_id,
                        },
                        node,
                    )
                })
            })
        });
        from_identity.or_else(|| {
            self.device
                .conversations
                .remove(&cid)
                .map(|node| (ConversationScope::Device, node))
        })
    }

    pub(super) fn handshake(&self, cid: ConversationId) -> Option<&HandshakeSession> {
        self.find_node(cid).and_then(ConversationNode::handshake)
    }

    pub(super) fn handshake_mut(&mut self, cid: ConversationId) -> Option<&mut HandshakeSession> {
        self.find_node_mut(cid)
            .and_then(ConversationNode::handshake_mut)
    }

    pub(super) fn established(&self, cid: ConversationId) -> Option<&EstablishedSession> {
        self.find_node(cid).and_then(ConversationNode::established)
    }

    pub(super) fn ticket(&self, cid: ConversationId) -> Option<&Ticket> {
        self.handshake(cid).map(|hs| &hs.ticket)
    }

    pub(super) fn is_sync(&self, cid: ConversationId) -> bool {
        self.device.conversations.contains_key(&cid)
    }

    #[cfg(test)]
    pub(super) fn is_sync_established(&self, cid: ConversationId) -> bool {
        self.is_sync(cid) && self.established(cid).is_some()
    }

    pub(super) fn has_sync_handshake(&self) -> bool {
        self.device
            .conversations
            .values()
            .any(|n| n.handshake().is_some())
    }

    pub(super) fn is_inviter(&self, cid: ConversationId) -> bool {
        self.handshake(cid)
            .is_some_and(HandshakeSession::is_inviter)
    }

    pub(super) fn owner(&self, cid: ConversationId) -> Option<(UserId, IdentityId)> {
        match self.scope_of(cid)? {
            ConversationScope::Identity { user, identity } => Some((user, identity)),
            ConversationScope::Device => None,
        }
    }

    pub(super) fn failed(&self, cid: ConversationId) -> Option<FailedReason> {
        self.handshake(cid)
            .and_then(HandshakeSession::failed_reason)
    }

    pub(super) fn fail(&mut self, cid: ConversationId, reason: FailedReason) {
        if let Some(hs) = self.handshake_mut(cid) {
            hs.fail(reason);
        }
    }

    pub(super) fn set_intake(&mut self, cid: ConversationId, intake: KeyPair) {
        if let Some(hs) = self.handshake_mut(cid) {
            hs.set_intake(intake);
        }
    }

    pub(super) fn set_shared_inviter(&mut self, cid: ConversationId, shared: Secret) {
        if let Some(hs) = self.handshake_mut(cid) {
            hs.set_shared_inviter(shared);
        }
    }

    pub(super) fn set_shared_invitee(&mut self, cid: ConversationId, shared: Secret) {
        if let Some(hs) = self.handshake_mut(cid) {
            hs.set_shared_invitee(shared);
        }
    }

    #[cfg(test)]
    pub(super) fn clear_shared(&mut self, cid: ConversationId) {
        if let Some(hs) = self.handshake_mut(cid) {
            hs.clear_shared();
        }
    }

    #[cfg(test)]
    pub(super) fn clear_intake(&mut self, cid: ConversationId) {
        if let Some(hs) = self.handshake_mut(cid) {
            hs.clear_intake();
        }
    }

    pub(super) fn child_of(&self, handshake: ConversationId) -> Option<ConversationId> {
        self.handshake(handshake).and_then(HandshakeSession::child)
    }

    pub(super) fn spawn_established(
        &mut self,
        handshake: ConversationId,
        child: ConversationId,
        secret: Secret,
    ) {
        if self.child_of(handshake).is_some() {
            #[rustfmt::skip]
            return;
        }
        if let Some(hs) = self.handshake_mut(handshake) {
            hs.set_child(child);
        }
        let node = ConversationNode::Established(EstablishedSession {
            secret,
            parent: handshake,
        });
        match self.scope_of(handshake) {
            Some(ConversationScope::Identity { user, identity }) => {
                self.put_dm(user, identity, child, node);
            }
            Some(ConversationScope::Device) | None => self.put_sync(child, node),
        }
    }

    pub(super) fn established_entries(&self) -> Vec<(ConversationId, &EstablishedSession, bool)> {
        let mut rows = Vec::new();
        for user in self.users.values() {
            for ident in user.identities.values() {
                for (cid, node) in &ident.conversations {
                    if let ConversationNode::Established(es) = node {
                        rows.push((*cid, es, false));
                    }
                }
            }
        }
        for (cid, node) in &self.device.conversations {
            if let ConversationNode::Established(es) = node {
                rows.push((*cid, es, true));
            }
        }
        rows
    }

    pub(super) fn handshake_entries(
        &self,
    ) -> Vec<(ConversationId, &HandshakeSession, ConversationSort)> {
        let mut rows = Vec::new();
        for user in self.users.values() {
            for ident in user.identities.values() {
                for (cid, node) in &ident.conversations {
                    if let ConversationNode::Handshake(hs) = node {
                        rows.push((*cid, hs, ConversationSort::HandshakeDm));
                    }
                }
            }
        }
        for (cid, node) in &self.device.conversations {
            if let ConversationNode::Handshake(hs) = node {
                rows.push((*cid, hs, ConversationSort::HandshakeSync));
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
                    rekey_node_refs(node, from, to);
                }
            }
        }
        rekey_map(&mut self.device.conversations, from, to);
        for node in self.device.conversations.values_mut() {
            rekey_node_refs(node, from, to);
        }
    }

    pub(super) fn install_from_fold(&mut self, fold: FoldDirectory) {
        let FoldDirectory {
            tickets,
            owners,
            inviters,
            intake,
            shared_inviter,
            shared_invitee,
            failed,
            children,
            established,
        } = fold;
        for (cid, ticket, sync) in tickets {
            let role = if inviters.contains(&cid) {
                HandshakeRole::Inviter
            } else {
                HandshakeRole::Invitee
            };
            let hs = if let Some(reason) = failed.get(&cid).copied() {
                HandshakeSession::failed(ticket, role, reason)
            } else {
                HandshakeSession::open(ticket, role)
                    .with_intake(intake.get(&cid).cloned())
                    .with_shared_inviter(shared_inviter.get(&cid).copied())
                    .with_shared_invitee(shared_invitee.get(&cid).copied())
                    .with_child(children.get(&cid).copied())
            };
            if sync {
                self.put_sync(cid, ConversationNode::Handshake(hs));
            } else if let Some((user, identity)) = owners.get(&cid).copied() {
                self.put_dm(user, identity, cid, ConversationNode::Handshake(hs));
            }
        }
        for (child, handshake, secret, sync) in established {
            if let Some(hs) = self.handshake_mut(handshake) {
                hs.set_child(child);
            }
            let node = ConversationNode::Established(EstablishedSession {
                secret,
                parent: handshake,
            });
            if sync {
                self.put_sync(child, node);
            } else if let Some((user, identity)) = owners
                .get(&child)
                .or_else(|| owners.get(&handshake))
                .copied()
                .or_else(|| self.owner(handshake))
            {
                self.put_dm(user, identity, child, node);
            }
        }
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

fn rekey_map<V>(map: &mut BTreeMap<ConversationId, V>, from: ConversationId, to: ConversationId) {
    if let Some(v) = map.remove(&from) {
        map.insert(to, v);
    }
}

fn rekey_node_refs(node: &mut ConversationNode, from: ConversationId, to: ConversationId) {
    match node {
        ConversationNode::Handshake(hs) => {
            if let Some(open) = hs.open_mut()
                && open.child == Some(from)
            {
                open.child = Some(to);
            }
        }
        ConversationNode::Established(es) if es.parent == from => es.parent = to,
        ConversationNode::Established(_) => {}
    }
}
