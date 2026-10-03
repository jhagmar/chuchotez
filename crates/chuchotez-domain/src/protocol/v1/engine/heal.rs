//! XOR binary search for a mismatched transaction set.

use super::super::ActorId;
use super::super::chain::{SendChain, eph_mk, join, mk, seal_packet, set_xor_for, step};
use super::super::payload::{
    ConversationSort, PacketHealHalfXor, PacketHealHave, PacketHealWant, PacketPlain, time_bin,
};
use super::super::{
    ConversationId, DurableChannel, EngineError, EphemeralChannel, Tag, UnixSeconds,
};
use super::Engine;
use super::helpers::{invite_tag, notice_for};
use super::query::{DurableWrite, EphemeralWrite};
use super::state::{EngineState, Heal, HealProbe};
use crate::protocol::Rng;

pub(super) const FALLBACK_SECS: u64 = 3;
pub(super) const LIVE_SECS: u64 = 30;
const ID_CAP: usize = 32;

impl Engine {
    pub(super) fn observe_ephemeral(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        cid: ConversationId,
        now: UnixSeconds,
        packet: &PacketPlain,
    ) -> Result<(), EngineError> {
        let already = state.chains(cid).is_some_and(|c| c.live_until.is_some());
        if let PacketPlain::XorAck(ack) = packet {
            self.settle_live(state, cid, ack.set_xor, now);
            if set_xor_for(&state.txs, cid) == ack.set_xor {
                self.note_live(state, cid, now);
            }
            self.note_set_xor(state, rng, cid, ack.set_xor)?;
        } else if already {
            self.note_live(state, cid, now);
        }
        if matches!(
            packet,
            PacketPlain::HealHalfXor(_) | PacketPlain::HealWant(_) | PacketPlain::HealHave(_)
        ) {
            self.on_heal_packet(state, rng, cid, packet)?;
        }
        Ok(())
    }

    pub(super) fn note_live(&self, state: &mut EngineState, cid: ConversationId, now: UnixSeconds) {
        if let Some(chains) = state.chains_mut(cid) {
            chains.live_until = Some(now.saturating_add(LIVE_SECS));
        }
    }

    pub(super) fn reseal_due(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
    ) -> Result<(), EngineError> {
        let now = state.ticked;
        let cids = heal_cids(state);
        for cid in cids {
            let needs = state.chains(cid).is_some_and(|c| {
                c.heal.needs_reseal
                    || now
                        .is_some_and(|now| fallback_due(state, cid, now) && c.heal.ready.is_empty())
            });
            if needs {
                self.reseal_heal(state, rng, cid)?;
            }
        }
        Ok(())
    }

    pub(super) fn note_set_xor(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        cid: ConversationId,
        remote: Tag,
    ) -> Result<(), EngineError> {
        let local = set_xor_for(&state.txs, cid);
        if local == remote {
            if let Some(chains) = state.chains_mut(cid) {
                chains.heal = Heal::default();
            }
            return Ok(());
        }
        let idle = state.chains(cid).is_none_or(|c| c.heal.probes.is_empty());
        if idle {
            if let Some(chains) = state.chains_mut(cid) {
                chains.heal.probes.push(HealProbe::Half {
                    lo: Tag::from_bytes([0; 32]),
                    hi: Tag::from_bytes([0xff; 32]),
                });
                chains.heal.fell_back = false;
            }
            self.post_heal(state, rng, cid)?;
        }
        Ok(())
    }

    pub(super) fn on_heal_packet(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        cid: ConversationId,
        packet: &PacketPlain,
    ) -> Result<(), EngineError> {
        let now = state.ticked.ok_or(EngineError::NotTicked)?;
        if let Some(chains) = state.chains_mut(cid)
            && chains.heal.on_ephemeral
        {
            chains.heal.sent_at = Some(now);
        }
        match packet {
            PacketPlain::HealHalfXor(p) => self.on_half(state, rng, cid, p),
            PacketPlain::HealWant(p) => self.on_want(state, rng, cid, p),
            PacketPlain::HealHave(p) => self.on_have(state, rng, cid, p),
            _ => Ok(()),
        }
    }

    /// Post stashed durable heal bodies once the ephemeral answer window has passed.
    pub(super) fn flush_heal(&self, state: &mut EngineState) {
        let Some(now) = state.ticked else {
            return;
        };
        let cids = heal_cids(state);
        for cid in cids {
            if !fallback_due(state, cid, now) {
                continue;
            }
            let chains = state.chains(cid).expect("heal row");
            if chains.heal.ready.is_empty() || !sealed_matches(chains) {
                if let Some(chains) = state.chains_mut(cid) {
                    chains.heal.needs_reseal = true;
                }
                continue;
            }
            self.commit_ready(state, cid);
        }
    }

    /// Reseal a due heal search when the sending chain moved or the stash is empty.
    pub(super) fn reseal_heal(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        cid: ConversationId,
    ) -> Result<(), EngineError> {
        let Some(now) = state.ticked else {
            return Ok(());
        };
        let due = state.chains(cid).is_some_and(|c| {
            c.heal.needs_reseal || (fallback_due(state, cid, now) && c.heal.ready.is_empty())
        });
        if due {
            self.post_heal(state, rng, cid)?;
        }
        Ok(())
    }

    fn on_half(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        cid: ConversationId,
        packet: &PacketHealHalfXor,
    ) -> Result<(), EngineError> {
        let ours = range_xor(&conv_ids(state, cid), &packet.lo, &packet.hi);
        if ours == packet.xor {
            return Ok(());
        }
        let probes = if single_id(&packet.lo, &packet.hi) {
            let id = packet.lo;
            if ours == id {
                vec![HealProbe::Have {
                    lo: packet.lo,
                    hi: packet.hi,
                    ids: vec![id],
                }]
            } else {
                vec![HealProbe::Want {
                    lo: packet.lo,
                    hi: packet.hi,
                    ids: vec![id],
                }]
            }
        } else {
            let Some(mid) = midpoint(&packet.lo, &packet.hi) else {
                return self.have_local(state, rng, cid, &packet.lo, &packet.hi);
            };
            vec![
                HealProbe::Half {
                    lo: packet.lo,
                    hi: mid,
                },
                HealProbe::Half {
                    lo: mid,
                    hi: packet.hi,
                },
            ]
        };
        self.replace_probes(state, rng, cid, probes)
    }

    fn have_local(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        cid: ConversationId,
        lo: &Tag,
        hi: &Tag,
    ) -> Result<(), EngineError> {
        let ids: Vec<Tag> = conv_ids(state, cid)
            .into_iter()
            .filter(|id| in_range(id, lo, hi))
            .take(ID_CAP)
            .collect();
        self.replace_probes(
            state,
            rng,
            cid,
            vec![HealProbe::Have {
                lo: *lo,
                hi: *hi,
                ids,
            }],
        )
    }

    fn on_want(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        cid: ConversationId,
        packet: &PacketHealWant,
    ) -> Result<(), EngineError> {
        if packet.ids.len() > ID_CAP {
            return Ok(());
        }
        if let Some(chains) = state.chains_mut(cid) {
            chains.heal.probes.clear();
            chains.heal.ready.clear();
            chains.heal.on_ephemeral = false;
        }
        let ids: Vec<Tag> = packet
            .ids
            .iter()
            .copied()
            .filter(|id| {
                state
                    .txs
                    .get(id)
                    .is_some_and(|body| body.conversation_id == cid)
            })
            .collect();
        self.retransmit(state, rng, cid, &ids)
    }

    fn on_have(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        cid: ConversationId,
        packet: &PacketHealHave,
    ) -> Result<(), EngineError> {
        if packet.ids.len() > ID_CAP {
            return Ok(());
        }
        let missing: Vec<Tag> = packet
            .ids
            .iter()
            .copied()
            .filter(|id| {
                !state
                    .txs
                    .get(id)
                    .is_some_and(|body| body.conversation_id == cid)
            })
            .take(ID_CAP)
            .collect();
        if missing.is_empty() {
            if let Some(chains) = state.chains_mut(cid) {
                chains.heal = Heal::default();
            }
            return Ok(());
        }
        self.replace_probes(
            state,
            rng,
            cid,
            vec![HealProbe::Want {
                lo: packet.lo,
                hi: packet.hi,
                ids: missing,
            }],
        )
    }

    fn replace_probes(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        cid: ConversationId,
        probes: Vec<HealProbe>,
    ) -> Result<(), EngineError> {
        if let Some(chains) = state.chains_mut(cid) {
            chains.heal.probes = probes;
            chains.heal.fell_back = false;
        }
        self.post_heal(state, rng, cid)
    }

    fn post_heal(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        cid: ConversationId,
    ) -> Result<(), EngineError> {
        let now = state.ticked.ok_or(EngineError::NotTicked)?;
        let Some(secret) = state.ticket(cid).map(|t| t.secret) else {
            return Ok(());
        };
        let (durable_ch, eph_ch) = channels(state, cid);
        let probes = state
            .chains(cid)
            .map(|c| c.heal.probes.clone())
            .unwrap_or_default();
        if probes.is_empty() || (durable_ch.is_empty() && eph_ch.is_empty()) {
            return Ok(());
        }
        let sort = if state.is_sync(cid) {
            ConversationSort::HandshakeSync
        } else {
            ConversationSort::HandshakeDm
        };
        let actor = ActorId::handshake();
        let tag = invite_tag(self.suite.hmac(), secret.as_bytes(), time_bin(now));
        let origin = match state.chains(cid).and_then(|c| c.send.get(&actor).cloned()) {
            Some(chain) => chain,
            None => join(self.suite.hmac(), secret.as_bytes(), sort, &[])?,
        };
        let live = state
            .chains(cid)
            .and_then(|c| c.live_until)
            .is_some_and(|until| now < until);
        let fell_back = state.chains(cid).is_some_and(|c| c.heal.fell_back);
        let force_durable = state.chains(cid).is_some_and(|c| c.heal.needs_reseal);
        let use_eph = live && !eph_ch.is_empty() && !fell_back && !force_durable;
        let ids = conv_ids(state, cid);
        let mut cursor = origin.clone();
        let mut ready = Vec::new();
        for probe in &probes {
            let mut plain = probe_plain(probe, cursor.packet_seq.as_u64(), actor.as_bytes());
            if let PacketPlain::HealHalfXor(packet) = &mut plain {
                packet.xor = range_xor(&ids, &packet.lo, &packet.hi);
            }
            if use_eph {
                let key = eph_mk(self.suite.hmac(), &origin);
                let sealed = seal_packet(&self.suite, rng, &key, &plain)?;
                for ch in &eph_ch {
                    state.eph_writes.push(EphemeralWrite {
                        channel: ch.clone(),
                        tag,
                        body: sealed.clone(),
                    });
                }
                let durable_key = mk(self.suite.hmac(), &cursor);
                ready.push(seal_packet(&self.suite, rng, &durable_key, &plain)?);
                cursor = step(self.suite.hmac(), &cursor);
            } else {
                let key = mk(self.suite.hmac(), &cursor);
                let sealed = seal_packet(&self.suite, rng, &key, &plain)?;
                for ch in &durable_ch {
                    state.writes.push(DurableWrite {
                        channel: ch.clone(),
                        tag,
                        body: sealed.clone(),
                    });
                }
                cursor = step(self.suite.hmac(), &cursor);
            }
        }
        let chains = state.chains_mut(cid).expect("heal row");
        chains.heal.sent_at = Some(now);
        chains.heal.on_ephemeral = use_eph;
        chains.heal.needs_reseal = false;
        if use_eph {
            chains.heal.ready = ready;
            chains.heal.sealed_from = Some(origin);
            chains.heal.sealed_to = Some(cursor);
        } else {
            chains.heal.ready.clear();
            chains.heal.sealed_from = None;
            chains.heal.sealed_to = None;
            chains.heal.fell_back = true;
            chains.send.insert(actor, cursor);
        }
        Ok(())
    }

    fn commit_ready(&self, state: &mut EngineState, cid: ConversationId) {
        let chains = state.chains(cid).expect("heal row");
        let ready = chains.heal.ready.clone();
        let sealed_to = chains.heal.sealed_to.clone();
        let (durable_ch, _) = channels(state, cid);
        let secret = state.ticket(cid).map(|t| t.secret).expect("ticket");
        let now = state.ticked.expect("ticked");
        let tag = invite_tag(self.suite.hmac(), secret.as_bytes(), time_bin(now));
        for body in ready {
            for ch in &durable_ch {
                state.writes.push(DurableWrite {
                    channel: ch.clone(),
                    tag,
                    body: body.clone(),
                });
            }
        }
        let chains = state.chains_mut(cid).expect("heal row");
        chains
            .send
            .insert(ActorId::handshake(), sealed_to.expect("sealed"));
        chains.heal.ready.clear();
        chains.heal.sealed_from = None;
        chains.heal.sealed_to = None;
        chains.heal.on_ephemeral = false;
        chains.heal.fell_back = true;
        chains.heal.needs_reseal = false;
    }

    fn retransmit(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        cid: ConversationId,
        ids: &[Tag],
    ) -> Result<(), EngineError> {
        let now = state.ticked.expect("ticked");
        let secret = state.ticket(cid).expect("ticket").secret;
        let (durable_ch, _) = channels(state, cid);
        if durable_ch.is_empty() {
            return Ok(());
        }
        let sort = if state.is_sync(cid) {
            ConversationSort::HandshakeSync
        } else {
            ConversationSort::HandshakeDm
        };
        let tag = invite_tag(self.suite.hmac(), secret.as_bytes(), time_bin(now));
        let actor = ActorId::handshake();
        for id in ids {
            #[rustfmt::skip]
            self.write_chain_packets(state, rng, cid, sort, &durable_ch, tag, *id, actor.clone(), false)?;
        }
        Ok(())
    }
}

fn fallback_due(state: &EngineState, cid: ConversationId, now: UnixSeconds) -> bool {
    state.chains(cid).is_some_and(|c| {
        c.heal.on_ephemeral
            && !c.heal.fell_back
            && c.heal
                .sent_at
                .is_some_and(|sent| now >= sent.saturating_add(FALLBACK_SECS))
    })
}

fn sealed_matches(chains: &super::state::ConversationChains) -> bool {
    let Some(from) = &chains.heal.sealed_from else {
        return false;
    };
    match chains.send.get(&ActorId::handshake()) {
        Some(chain) => same_chain(chain, from),
        None => true,
    }
}

fn same_chain(a: &SendChain, b: &SendChain) -> bool {
    a.root == b.root && a.c == b.c && a.epoch == b.epoch && a.packet_seq == b.packet_seq
}

fn heal_cids(state: &EngineState) -> Vec<ConversationId> {
    let mut ids = Vec::new();
    state.for_each_chains(|cid, chains| {
        if chains.heal.on_ephemeral {
            ids.push(cid);
        }
    });
    ids
}

fn channels(
    state: &EngineState,
    cid: ConversationId,
) -> (Vec<DurableChannel>, Vec<EphemeralChannel>) {
    let durable = state
        .ticket(cid)
        .map(|t| t.persistents.clone())
        .unwrap_or_default();
    let ephemeral = notice_for(state, cid)
        .map(|n| n.ephemerals.clone())
        .unwrap_or_default();
    (durable, ephemeral)
}

fn conv_ids(state: &EngineState, cid: ConversationId) -> Vec<Tag> {
    let mut ids: Vec<Tag> = state
        .txs
        .iter()
        .filter(|(_, body)| body.conversation_id == cid)
        .map(|(id, _)| *id)
        .collect();
    ids.sort();
    ids
}

fn range_xor(ids: &[Tag], lo: &Tag, hi: &Tag) -> Tag {
    let mut acc = [0u8; 32];
    for id in ids {
        if in_range(id, lo, hi) {
            for (a, b) in acc.iter_mut().zip(id.as_bytes()) {
                *a ^= *b;
            }
        }
    }
    Tag::from_bytes(acc)
}

fn in_range(id: &Tag, lo: &Tag, hi: &Tag) -> bool {
    id >= lo && (is_inf(hi) || id < hi)
}

fn is_inf(hi: &Tag) -> bool {
    hi.as_bytes() == &[0xff; 32]
}

fn single_id(lo: &Tag, hi: &Tag) -> bool {
    successor(lo).is_some_and(|next| next == *hi)
}

fn successor(lo: &Tag) -> Option<Tag> {
    let mut bytes = *lo.as_bytes();
    for byte in bytes.iter_mut().rev() {
        if *byte != 0xff {
            *byte += 1;
            return Some(Tag::from_bytes(bytes));
        }
        *byte = 0;
    }
    None
}

fn midpoint(lo: &Tag, hi: &Tag) -> Option<Tag> {
    let inf = is_inf(hi);
    let mid = if inf {
        let mut out = [0u8; 32];
        let mut carry = 0u8;
        for i in (0..32).rev() {
            let v = lo.as_bytes()[i];
            out[i] = (v >> 1) | (carry << 7);
            carry = v & 1;
        }
        out[0] |= 0x80;
        out
    } else {
        let mut wide = [0u8; 33];
        let mut carry = 0u16;
        for i in (0..32).rev() {
            let sum = u16::from(lo.as_bytes()[i]) + u16::from(hi.as_bytes()[i]) + carry;
            wide[i + 1] = (sum & 0xff) as u8;
            carry = sum >> 8;
        }
        wide[0] = carry as u8;
        let mut out = [0u8; 32];
        let mut bit = 0u8;
        for i in 0..33 {
            let v = wide[i];
            if i > 0 {
                out[i - 1] = (bit << 7) | (v >> 1);
            }
            bit = v & 1;
        }
        out
    };
    let mid = Tag::from_bytes(mid);
    (mid > *lo && (inf || mid < *hi)).then_some(mid)
}

fn probe_plain(probe: &HealProbe, packet_seq: u64, actor_id: &[u8]) -> PacketPlain {
    match probe {
        HealProbe::Half { lo, hi } => PacketPlain::HealHalfXor(PacketHealHalfXor {
            actor_id: actor_id.to_vec(),
            packet_seq,
            lo: *lo,
            hi: *hi,
            xor: Tag::from_bytes([0; 32]),
        }),
        HealProbe::Want { lo, hi, ids } => PacketPlain::HealWant(PacketHealWant {
            actor_id: actor_id.to_vec(),
            packet_seq,
            lo: *lo,
            hi: *hi,
            ids: ids.clone(),
        }),
        HealProbe::Have { lo, hi, ids } => PacketPlain::HealHave(PacketHealHave {
            actor_id: actor_id.to_vec(),
            packet_seq,
            lo: *lo,
            hi: *hi,
            ids: ids.clone(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{midpoint, range_xor, single_id, successor};
    use crate::protocol::v1::Tag;

    #[test]
    fn range_edges() {
        let lo = Tag::from_bytes([0; 32]);
        let hi = Tag::from_bytes([0xff; 32]);
        assert!(midpoint(&lo, &hi).is_some());
        assert!(!single_id(&lo, &hi));
        assert!(successor(&hi).is_none());
        let id = Tag::from_bytes([4; 32]);
        assert_eq!(range_xor(&[id], &lo, &hi), id);
        assert_eq!(range_xor(&[], &lo, &hi), Tag::from_bytes([0; 32]));
        assert!(midpoint(&id, &id).is_none());
    }
}
