//! Ephemeral-first durable sends on an established DM or Sync conversation.

use super::super::chain::{
    SendChain, eph_mk, join, mk, open_at, open_plain, seal_packet, set_xor_for, step,
};
use super::super::codec::durable_body_from_json;
use super::super::hmac::{HmacSha256, HmacSha256Key, expand};
use super::super::payload::{
    ConversationSort, PACKET_MAX_UNCOMPRESSED, PacketPlain, PacketPresence, PacketPresenceActive,
    PacketTyping, PacketTypingActive, TxPayload, time_bin,
};
use super::super::{
    Actor, ConversationId, DurableChannel, EngineError, EphemeralChannel, FragIndex, Secret, Tag,
    TagKey, TimeBin, UnixSeconds,
};
use super::Engine;
use super::heal::{FALLBACK_SECS, LIVE_SECS};
use super::helpers::{
    frag_parts, invitee_intro_for, inviter_intro_for, listen_bins, notice_for,
    store_durable_last_ack,
};
use super::party::{DeviceConversation, IdentityConversation};
use super::query::{DurableWrite, EphemeralWrite, MutateOk};
use super::state::{EngineState, LivePending};
use crate::protocol::Rng;

/// Channel an established packet was posted on.
pub(super) enum LiveChannel<'a> {
    Durable(&'a DurableChannel),
    Eph(&'a EphemeralChannel),
}

struct LiveRoute {
    sort: ConversationSort,
    persistents: Vec<DurableChannel>,
    ephemerals: Vec<EphemeralChannel>,
    send_tag_key: TagKey,
    eph_send_tag_key: TagKey,
    actor: Actor,
}

pub(super) fn live_persistent_only(sort: ConversationSort, payload: &TxPayload) -> bool {
    matches!(sort, ConversationSort::Group)
        || matches!(
            payload,
            TxPayload::Advertise { .. } | TxPayload::Wrap { .. } | TxPayload::Ack { .. }
        )
}

fn presence_plain(
    visible: bool,
    actor: &[u8],
    seq: u64,
    cid: ConversationId,
    now: u64,
) -> PacketPlain {
    if visible {
        PacketPlain::PresenceActive(PacketPresenceActive {
            actor_id: actor.to_vec(),
            packet_seq: seq,
            conversation_id: cid,
            last_active: now,
        })
    } else {
        PacketPlain::Presence(PacketPresence {
            actor_id: actor.to_vec(),
            packet_seq: seq,
            conversation_id: cid,
        })
    }
}

pub(super) fn bin_tag(hmac: &dyn HmacSha256, key: TagKey, label: &[u8], bin: TimeBin) -> Tag {
    let mut info = label.to_vec();
    info.extend_from_slice(&bin.as_u64().to_be_bytes());
    Tag::from_bytes(expand(hmac, &HmacSha256Key::from_bytes(*key.as_bytes()), &info).into_bytes())
}

fn established_cids(state: &EngineState) -> Vec<ConversationId> {
    let mut out = Vec::new();
    for user in state.users.values() {
        for ident in user.identities.values() {
            for (cid, node) in &ident.conversations {
                if matches!(node.kind, IdentityConversation::DirectMessage { .. }) {
                    out.push(*cid);
                }
            }
        }
    }
    for (cid, node) in &state.device.conversations {
        if matches!(node.kind, DeviceConversation::Synchronization { .. }) {
            out.push(*cid);
        }
    }
    out
}

impl Engine {
    pub(super) fn deliver_live(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        cid: ConversationId,
        secret: &Secret,
        payloads: &[TxPayload],
    ) -> Result<(), EngineError> {
        if state.established_secret(cid).is_none() {
            return Ok(());
        }
        for payload in payloads {
            let tx_id = self.tx_id(secret, payload);
            self.post_live(state, rng, cid, secret, tx_id, payload)?;
        }
        Ok(())
    }

    pub(super) fn settle_live(
        &self,
        state: &mut EngineState,
        cid: ConversationId,
        set_xor: Tag,
        now: UnixSeconds,
    ) {
        let chains = state.chains_mut(cid).expect("row");
        for pending in &mut chains.live_pending {
            if pending.set_xor == set_xor {
                pending.acks = pending.acks.saturating_add(1);
            }
        }
        let before = chains.live_pending.len();
        chains
            .live_pending
            .retain(|pending| pending.acks < pending.needed);
        if chains.live_pending.len() < before {
            chains.live_until = Some(now.saturating_add(LIVE_SECS));
        }
    }

    pub(super) fn flush_live(&self, state: &mut EngineState) {
        let now = state.ticked.expect("ticked");
        for cid in established_cids(state) {
            let due: Vec<LivePending> = state
                .chains(cid)
                .expect("row")
                .live_pending
                .iter()
                .filter(|pending| now >= pending.sent_at.saturating_add(FALLBACK_SECS))
                .cloned()
                .collect();
            if due.is_empty() {
                continue;
            }
            let Some(route) = self.live_route(state, cid) else {
                continue;
            };
            let tag = bin_tag(
                self.suite.hmac(),
                route.send_tag_key,
                route.sort.persist_label().expect("label"),
                time_bin(now),
            );
            for pending in &due {
                for body in &pending.bodies {
                    for channel in &route.persistents {
                        state.writes.push(DurableWrite {
                            channel: channel.clone(),
                            tag,
                            body: body.clone(),
                        });
                    }
                }
            }
            let chains = state.chains_mut(cid).expect("row");
            if let Some(last) = due.last() {
                chains
                    .send
                    .insert(last.actor.clone(), last.sealed_to.clone());
            }
            chains
                .live_pending
                .retain(|pending| now < pending.sent_at.saturating_add(FALLBACK_SECS));
        }
    }

    pub(super) fn post_live(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        cid: ConversationId,
        secret: &Secret,
        tx_id: Tag,
        payload: &TxPayload,
    ) -> Result<(), EngineError> {
        let Some(route) = self.live_route(state, cid) else {
            return Ok(());
        };
        let now = state.ticked.expect("ticked");
        let wait = !live_persistent_only(route.sort, payload) && !route.ephemerals.is_empty();
        let mut chain = self.sending_chain(state, cid, secret, &route)?;
        if wait {
            self.probe_presence(state, rng, cid, &route, &chain, now)?;
        }
        let body = state.txs.get(&tx_id).expect("tx").clone();
        let mut packed = super::super::chain::packed_tx(&self.suite, &body);
        let set_xor = set_xor_for(&state.txs, cid);
        let eph_key = eph_mk(self.suite.hmac(), &chain);
        let mut frag_i = 0u64;
        let mut durable = Vec::new();
        loop {
            #[rustfmt::skip]
            let (packet, n) = super::super::chain::next_fragment(&self.suite, &packed, tx_id, set_xor, chain.packet_seq.as_u64(), frag_i, route.actor.as_bytes())?;
            let finished = matches!(packet, PacketPlain::TxFragLast(_));
            if wait || !route.ephemerals.is_empty() {
                let sealed = seal_packet(&self.suite, rng, &eph_key, &packet)?;
                self.push_eph(state, &route, now, sealed);
            }
            let sealed = seal_packet(&self.suite, rng, &mk(self.suite.hmac(), &chain), &packet)?;
            if wait {
                durable.push(sealed);
            } else {
                self.push_durable(state, &route, now, sealed);
            }
            chain = step(self.suite.hmac(), &chain);
            self.note_sent_packet(state, cid);
            packed = packed.get(n..).unwrap_or_default().to_vec();
            frag_i = frag_i.saturating_add(1);
            if finished {
                break;
            }
        }
        if wait {
            let pending = LivePending {
                set_xor,
                sent_at: now,
                bodies: durable,
                sealed_to: chain,
                actor: route.actor,
                acks: 0,
                needed: 1,
            };
            state
                .chains_mut(cid)
                .expect("row")
                .live_pending
                .push(pending);
        } else if let Some(chains) = state.chains_mut(cid) {
            chains.send.insert(route.actor, chain);
        }
        Ok(())
    }

    pub(super) fn finish_established(
        &self,
        mut state: EngineState,
        rng: &dyn Rng,
        channel: LiveChannel<'_>,
        tag: &Tag,
        body: &[u8],
    ) -> Result<MutateOk, EngineError> {
        let now = Self::require_tick(&state)?;
        let _ = self.require_dek()?;
        self.reseal_due(&mut state, rng)?;
        let persist = self.ingest_established(&mut state, rng, channel, tag, body, now)?;
        Ok(MutateOk {
            state,
            persist,
            pings: Vec::new(),
        })
    }

    fn probe_presence(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        cid: ConversationId,
        route: &LiveRoute,
        chain: &SendChain,
        now: UnixSeconds,
    ) -> Result<(), EngineError> {
        let chains = state.chains(cid).expect("row");
        let live = chains.live_until.is_some_and(|until| now < until);
        if live || chains.presence_sent {
            return Ok(());
        }
        let packet = presence_plain(
            self.defaults.online_visible(),
            route.actor.as_bytes(),
            chain.packet_seq.as_u64(),
            cid,
            now.as_u64(),
        );
        let sealed = seal_packet(&self.suite, rng, &eph_mk(self.suite.hmac(), chain), &packet)?;
        self.push_eph(state, route, now, sealed);
        state.chains_mut(cid).expect("row").presence_sent = true;
        Ok(())
    }

    /// Post a typing or presence packet on every ephemeral channel.
    /// `composing` `None` is presence.
    pub(super) fn post_signal(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        cid: ConversationId,
        secret: &Secret,
        composing: Option<bool>,
    ) -> Result<(), EngineError> {
        let route = self.live_route(state, cid).expect("route");
        let now = state.ticked.expect("ticked");
        let chain = self.sending_chain(state, cid, secret, &route)?;
        let actor = route.actor.as_bytes().to_vec();
        let seq = chain.packet_seq.as_u64();
        let packet = match (composing, self.shows_online(state, cid)) {
            (Some(composing), true) => PacketPlain::TypingActive(PacketTypingActive {
                actor_id: actor,
                packet_seq: seq,
                conversation_id: cid,
                last_active: now.as_u64(),
                composing,
            }),
            (Some(composing), false) => PacketPlain::Typing(PacketTyping {
                actor_id: actor,
                packet_seq: seq,
                conversation_id: cid,
                composing,
            }),
            (None, true) => PacketPlain::PresenceActive(PacketPresenceActive {
                actor_id: actor,
                packet_seq: seq,
                conversation_id: cid,
                last_active: now.as_u64(),
            }),
            (None, false) => PacketPlain::Presence(PacketPresence {
                actor_id: actor,
                packet_seq: seq,
                conversation_id: cid,
            }),
        };
        #[rustfmt::skip]
        let sealed = seal_packet(&self.suite, rng, &eph_mk(self.suite.hmac(), &chain), &packet)?;
        self.push_eph(state, &route, now, sealed);
        Ok(())
    }

    fn sending_chain(
        &self,
        state: &EngineState,
        cid: ConversationId,
        secret: &Secret,
        route: &LiveRoute,
    ) -> Result<SendChain, EngineError> {
        if let Some(tip) = state.chains(cid).and_then(|chains| {
            chains
                .live_pending
                .last()
                .map(|pending| pending.sealed_to.clone())
        }) {
            return Ok(tip);
        }
        if let Some(existing) = state
            .chains(cid)
            .and_then(|chains| chains.send.get(&route.actor).cloned())
        {
            return Ok(existing);
        }
        join(
            self.suite.hmac(),
            secret.as_bytes(),
            route.sort,
            route.actor.as_bytes(),
        )
    }

    fn push_eph(
        &self,
        state: &mut EngineState,
        route: &LiveRoute,
        now: UnixSeconds,
        body: Vec<u8>,
    ) {
        let tag = bin_tag(
            self.suite.hmac(),
            route.eph_send_tag_key,
            route.sort.eph_label().expect("label"),
            time_bin(now),
        );
        for channel in &route.ephemerals {
            state.eph_writes.push(EphemeralWrite {
                channel: channel.clone(),
                tag,
                body: body.clone(),
            });
        }
    }

    fn push_durable(
        &self,
        state: &mut EngineState,
        route: &LiveRoute,
        now: UnixSeconds,
        body: Vec<u8>,
    ) {
        let tag = bin_tag(
            self.suite.hmac(),
            route.send_tag_key,
            route.sort.persist_label().expect("label"),
            time_bin(now),
        );
        for channel in &route.persistents {
            state.writes.push(DurableWrite {
                channel: channel.clone(),
                tag,
                body: body.clone(),
            });
        }
    }

    fn live_route(&self, state: &EngineState, cid: ConversationId) -> Option<LiveRoute> {
        if let Some(route) = self.group_route(state, cid) {
            return Some(route);
        }
        let parent = state.established_parent(cid)?;
        let notice = notice_for(state, parent)?;
        let (actor, signing) = local_material(self, state, cid)?;
        let (send_tag_key, eph_send_tag_key) = intro_tag_keys(state, parent, &signing)?;
        let sort = if state.is_sync(cid) {
            ConversationSort::Synchronization
        } else {
            ConversationSort::DirectMessage
        };
        Some(LiveRoute {
            sort,
            persistents: notice.persistents.clone(),
            ephemerals: notice.ephemerals.clone(),
            send_tag_key,
            eph_send_tag_key,
            actor,
        })
    }

    fn ingest_established(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        channel: LiveChannel<'_>,
        tag: &Tag,
        body: &[u8],
        now: UnixSeconds,
    ) -> Result<Vec<Vec<u8>>, EngineError> {
        let persistent = matches!(channel, LiveChannel::Durable(_));
        let Some((cid, secret, sort)) = self.established_match(state, &channel, tag, now) else {
            return Err(EngineError::UnknownTag);
        };
        if let Some(persist) =
            self.open_established(state, rng, cid, &secret, sort, body, persistent, now)?
        {
            return Ok(persist);
        }
        Err(EngineError::UnknownTag)
    }

    fn group_route(&self, state: &EngineState, cid: ConversationId) -> Option<LiveRoute> {
        let live = super::group::group_live(state, cid)?;
        let (actor, signing) = local_material(self, state, cid)?;
        let member = live
            .members
            .iter()
            .find(|member| member.signing_pk.as_bytes() == signing.as_slice())?;
        Some(LiveRoute {
            sort: ConversationSort::Group,
            persistents: live.persistents.clone(),
            ephemerals: Vec::new(),
            send_tag_key: member.send_tag_key,
            eph_send_tag_key: member.eph_send_tag_key,
            actor,
        })
    }

    fn established_match(
        &self,
        state: &EngineState,
        channel: &LiveChannel<'_>,
        tag: &Tag,
        now: UnixSeconds,
    ) -> Option<(ConversationId, Secret, ConversationSort)> {
        if let Some(hit) = self.group_match(state, channel, tag, now) {
            return Some(hit);
        }
        for cid in established_cids(state) {
            let parent = state.established_parent(cid)?;
            let notice = notice_for(state, parent)?;
            let matches_ch = match channel {
                LiveChannel::Durable(channel) => notice.persistents.iter().any(|ch| ch == *channel),
                LiveChannel::Eph(channel) => notice.ephemerals.iter().any(|ch| ch == *channel),
            };
            let sort = if state.is_sync(cid) {
                ConversationSort::Synchronization
            } else {
                ConversationSort::DirectMessage
            };
            let persistent = matches!(channel, LiveChannel::Durable(_));
            if matches_ch && self.tag_hits(state, parent, sort, persistent, tag, now) {
                return Some((cid, state.established_secret(cid)?, sort));
            }
        }
        None
    }

    fn group_match(
        &self,
        state: &EngineState,
        channel: &LiveChannel<'_>,
        tag: &Tag,
        now: UnixSeconds,
    ) -> Option<(ConversationId, Secret, ConversationSort)> {
        let LiveChannel::Durable(durable) = channel else {
            return None;
        };
        let label = ConversationSort::Group.persist_label()?;
        let bins = listen_bins(time_bin(now));
        for user in state.users.values() {
            for ident in user.identities.values() {
                for (cid, node) in &ident.conversations {
                    let live = match &node.kind {
                        super::party::IdentityConversation::Group(
                            super::party::GroupPhase::Live(live),
                        ) => live,
                        _ => continue,
                    };
                    if !live.persistents.iter().any(|item| item == *durable) {
                        continue;
                    }
                    for member in &live.members {
                        for bin in bins {
                            if bin_tag(self.suite.hmac(), member.send_tag_key, label, bin) == *tag {
                                return Some((*cid, live.secret, ConversationSort::Group));
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn tag_hits(
        &self,
        state: &EngineState,
        parent: ConversationId,
        sort: ConversationSort,
        persistent: bool,
        tag: &Tag,
        now: UnixSeconds,
    ) -> bool {
        let label = if persistent {
            sort.persist_label()
        } else {
            sort.eph_label()
        }
        .expect("label");
        let mut keys = Vec::new();
        keys.extend(inviter_intro_for(state, parent).map(|intro| {
            if persistent {
                intro.send_tag_key
            } else {
                intro.eph_send_tag_key
            }
        }));
        keys.extend(invitee_intro_for(state, parent).map(|intro| {
            if persistent {
                intro.send_tag_key
            } else {
                intro.eph_send_tag_key
            }
        }));
        let bins = listen_bins(time_bin(now));
        for key in keys {
            for bin in bins {
                if bin_tag(self.suite.hmac(), key, label, bin) == *tag {
                    return true;
                }
            }
        }
        false
    }

    #[allow(clippy::too_many_arguments)]
    fn open_established(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        cid: ConversationId,
        secret: &Secret,
        sort: ConversationSort,
        body: &[u8],
        persistent: bool,
        now: UnixSeconds,
    ) -> Result<Option<Vec<Vec<u8>>>, EngineError> {
        let actors = if sort == ConversationSort::Group {
            group_member_actors(state, cid)
        } else if sort == ConversationSort::Synchronization {
            sync_open_actors(state, cid)
        } else {
            let parent = state.established_parent(cid).expect("parent");
            open_actors(state, parent, sort)
        };
        for actor_bytes in actors {
            let actor = super::helpers::actor_for(sort, &actor_bytes).expect("actor");
            #[rustfmt::skip]
            let joined = join(self.suite.hmac(), secret.as_bytes(), sort, &actor_bytes)?;
            let start = state
                .chains(cid)
                .and_then(|chains| chains.recv.get(&actor).cloned())
                .unwrap_or(joined);
            if !persistent {
                let mut cursor = start.clone();
                for _ in 0..64 {
                    let key = eph_mk(self.suite.hmac(), &cursor);
                    if let Ok(packet) = open_plain(&self.suite, &key, body) {
                        let persist = self.on_established(state, rng, cid, now, &packet, false)?;
                        return Ok(Some(persist));
                    }
                    cursor = step(self.suite.hmac(), &cursor);
                }
            } else if let Ok(opened) = open_at(&self.suite, &start, None, &[], now.as_u64(), body) {
                state
                    .chains_mut(cid)
                    .expect("row")
                    .recv
                    .insert(actor, opened.chain);
                let persist = self.on_established(state, rng, cid, now, &opened.packet, true)?;
                return Ok(Some(persist));
            }
        }
        Ok(None)
    }

    fn on_established(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        cid: ConversationId,
        now: UnixSeconds,
        packet: &PacketPlain,
        persistent: bool,
    ) -> Result<Vec<Vec<u8>>, EngineError> {
        if !persistent {
            self.observe_ephemeral(state, rng, cid, now, packet)?;
        } else if let PacketPlain::XorAck(ack) = packet {
            store_durable_last_ack(state, cid, &ack.actor_id, ack.set_xor);
            self.note_set_xor(state, rng, cid, ack.set_xor)?;
            return Ok(Vec::new());
        }
        self.note_packet_signal(state, cid, now, packet);
        self.accept_fragment(state, rng, cid, packet, persistent)
    }

    fn accept_fragment(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        cid: ConversationId,
        packet: &PacketPlain,
        persistent: bool,
    ) -> Result<Vec<Vec<u8>>, EngineError> {
        let Some(part) = frag_parts(packet) else {
            return Ok(Vec::new());
        };
        let set = state
            .frags
            .entry(part.tx_id)
            .or_insert_with(|| super::state::FragSet {
                conversation_id: cid,
                parts: std::collections::BTreeMap::new(),
                last_i: None,
            });
        set.parts.insert(part.frag_i, part.frag);
        if let Some(last) = part.last_i {
            set.last_i = Some(last);
        }
        let mut out = Vec::new();
        let last = state.frags.get(&part.tx_id).and_then(|set| set.last_i);
        if let Some(last) = last {
            let ready = (0..=last.as_u64()).all(|n| {
                state
                    .frags
                    .get(&part.tx_id)
                    .and_then(|set| set.parts.get(&FragIndex::from_u64(n)))
                    .is_some()
            });
            if !ready {
                return Ok(out);
            }
            let parts: Vec<Vec<u8>> = (0..=last.as_u64())
                .map(|n| {
                    state
                        .frags
                        .get(&part.tx_id)
                        .and_then(|set| set.parts.get(&FragIndex::from_u64(n)))
                        .expect("frag")
                        .clone()
                })
                .collect();
            state.frags.remove(&part.tx_id);
            let mut packed = Vec::new();
            for frag in &parts {
                packed.extend_from_slice(frag);
            }
            #[rustfmt::skip]
        let canonical = self.suite.compress().decompress(&packed, PACKET_MAX_UNCOMPRESSED).map_err(|_| EngineError::MalformedPayload)?;
            #[rustfmt::skip]
        let json = self.suite.canonical_json().decode(&canonical).map_err(|_| EngineError::MalformedPayload)?;
            #[rustfmt::skip]
        let durable = durable_body_from_json(self.suite.b64u(), &json).map_err(|_| EngineError::MalformedPayload)?;
            if state
                .txs
                .get(&part.tx_id)
                .is_some_and(|existing| existing.payload == durable.payload)
            {
                return Ok(Vec::new());
            }
            #[rustfmt::skip]
        let _gate = self.handshake_ingest_gate(state, cid, &durable.payload)?;
            let seq = state.next_seq;
            #[rustfmt::skip]
        let rec = self.persist_record(seq, &durable)?;
            state.persist_log.insert(seq, part.tx_id);
            state.next_seq = state.next_seq.saturating_add(1);
            state.txs.insert(part.tx_id, durable.clone());
            self.on_group_payload(state, rng, cid, &durable.payload)?;
            let sender = state
                .sort_of(cid)
                .and_then(|sort| super::helpers::actor_for(sort, &packet_actor(packet)))
                .unwrap_or_else(Actor::handshake);
            state
                .chains_mut(cid)
                .expect("row")
                .chat_senders
                .insert(part.tx_id, sender);
            if persistent && let PacketPlain::TxFragLast(last) = packet {
                store_durable_last_ack(state, cid, &last.actor_id, last.set_xor);
                self.note_set_xor(state, rng, cid, last.set_xor)?;
            }
            self.note_sync_peer(state, cid, &packet_actor(packet));
            if let TxPayload::EngineKickDevice { device_id } = &durable.payload {
                #[rustfmt::skip]
                self.note_device_kick(state, *device_id)?;
            }
            out.push(rec);
        }
        Ok(out)
    }
}

fn packet_actor(packet: &PacketPlain) -> Vec<u8> {
    match packet {
        PacketPlain::TxFragMore(packet) => packet.actor_id.clone(),
        PacketPlain::TxFragLast(packet) => packet.actor_id.clone(),
        _ => Vec::new(),
    }
}

pub(super) fn local_material(
    engine: &Engine,
    state: &EngineState,
    cid: ConversationId,
) -> Option<(Actor, Vec<u8>)> {
    if state.is_sync(cid) {
        let keys = state.device.keys.as_ref()?;
        let id = keys.id?;
        return Some((Actor::device(id), keys.sign.public_bytes().to_vec()));
    }
    let (user, identity) = state.owner(cid)?;
    let (_, _, signing) = engine.identity_keys(state, &user, &identity)?;
    Some((Actor::signing(signing.clone()), signing))
}

fn intro_tag_keys(
    state: &EngineState,
    parent: ConversationId,
    signing: &[u8],
) -> Option<(TagKey, TagKey)> {
    if let Some(intro) = inviter_intro_for(state, parent)
        && intro.signing_pk == crate::protocol::v1::SigningPublicKey::from_bytes(signing)
    {
        return Some((intro.send_tag_key, intro.eph_send_tag_key));
    }
    let intro = invitee_intro_for(state, parent)?;
    (intro.signing_pk.as_bytes() == signing).then_some((intro.send_tag_key, intro.eph_send_tag_key))
}

fn group_member_actors(state: &EngineState, cid: ConversationId) -> Vec<Vec<u8>> {
    super::group::group_live(state, cid)
        .map(|live| {
            live.members
                .iter()
                .map(|member| member.signing_pk.as_bytes().to_vec())
                .collect()
        })
        .unwrap_or_default()
}

fn sync_open_actors(state: &EngineState, cid: ConversationId) -> Vec<Vec<u8>> {
    let mut actors = Vec::new();
    if let Some(id) = state.device.keys.as_ref().and_then(|keys| keys.id) {
        actors.push(id.as_bytes().to_vec());
    }
    if let Some(node) = state.device.conversations.get(&cid)
        && let DeviceConversation::Synchronization { peer, .. } = &node.kind
    {
        actors.push(peer.as_bytes().to_vec());
    }
    actors
}

fn open_actors(
    state: &EngineState,
    parent: ConversationId,
    sort: ConversationSort,
) -> Vec<Vec<u8>> {
    let mut actors = Vec::new();
    if let Some(intro) = invitee_intro_for(state, parent) {
        actors.push(intro.signing_pk.as_bytes().to_vec());
    }
    if let Some(intro) = inviter_intro_for(state, parent) {
        actors.push(intro.signing_pk.as_bytes().to_vec());
    }
    let _ = sort;
    actors
}

#[cfg(test)]
mod tests {
    use super::super::super::payload::{ConversationSort, PacketPlain, TxPayload};
    use super::super::super::{ConversationId, Tag};
    use super::live_persistent_only;
    use super::presence_plain;

    #[test]
    fn persistent_payloads_and_presence() {
        assert!(live_persistent_only(
            ConversationSort::Group,
            &TxPayload::Confirm
        ));
        assert!(live_persistent_only(
            ConversationSort::DirectMessage,
            &TxPayload::Advertise {
                encaps_pk: crate::protocol::v1::EncryptionPublicKey::from_bytes(vec![])
            }
        ));
        assert!(live_persistent_only(
            ConversationSort::Synchronization,
            &TxPayload::Wrap { kem_ct: vec![] }
        ));
        assert!(live_persistent_only(
            ConversationSort::DirectMessage,
            &TxPayload::Ack {
                ratchet_ack: Tag::from_bytes([1; 32])
            }
        ));
        assert!(!live_persistent_only(
            ConversationSort::DirectMessage,
            &TxPayload::Confirm
        ));
        let cid = ConversationId::from_bytes([2; 32]);
        assert!(matches!(
            presence_plain(true, &[3], 1, cid, 9),
            PacketPlain::PresenceActive(_)
        ));
        assert!(matches!(
            presence_plain(false, &[3], 1, cid, 9),
            PacketPlain::Presence(_)
        ));
        for sort in [
            ConversationSort::HandshakeDm,
            ConversationSort::HandshakeSync,
            ConversationSort::DirectMessage,
            ConversationSort::Group,
            ConversationSort::Synchronization,
            ConversationSort::Engine,
        ] {
            let _ = sort.persist_label();
            let _ = sort.eph_label();
        }
        let more = PacketPlain::TxFragMore(super::super::super::payload::PacketTxFragMore {
            actor_id: vec![1],
            packet_seq: 0,
            tx_id: Tag::from_bytes([1; 32]),
            frag_i: 0,
            frag: vec![2],
        });
        assert_eq!(super::packet_actor(&more), vec![1]);
        let last = PacketPlain::TxFragLast(super::super::super::payload::PacketTxFragLast {
            actor_id: vec![3],
            packet_seq: 1,
            tx_id: Tag::from_bytes([1; 32]),
            frag_i: 1,
            frag: vec![4],
            set_xor: Tag::from_bytes([2; 32]),
        });
        assert_eq!(super::packet_actor(&last), vec![3]);
        let ack = PacketPlain::XorAck(super::super::super::payload::PacketXorAck {
            actor_id: vec![5],
            packet_seq: 0,
            set_xor: Tag::from_bytes([2; 32]),
        });
        assert!(super::packet_actor(&ack).is_empty());
    }
}
