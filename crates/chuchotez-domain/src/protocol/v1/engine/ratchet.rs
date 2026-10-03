//! Advertise, wrap, ack, and mix on a conversation sending chain.

use super::super::chain::{SendChain, mix};
use super::super::kem::{KemSeed, kem_ct_len, kem_pk_len};
use super::super::payload::{ConversationSort, TxPayload};
use super::super::{ConversationId, EngineError, Policy, Secret, Tag};
use super::Engine;
use super::helpers::{notice_for, tx_watermarked};
use super::state::{EngineState, KnownShared, UnusedSk};
use crate::protocol::Rng;

const OWED_PACKETS: u64 = 50;
const MIX_STRIDE: u64 = 8;
const MIX_READY: usize = 8;
const UNUSED_CAP: usize = 8;

struct Minted {
    payload: TxPayload,
    effect: Effect,
}

enum Effect {
    Advertise {
        pk: Vec<u8>,
        sk: Vec<u8>,
    },
    Wrap {
        shared: Secret,
        ct_hash: Tag,
        encaps_pk: Vec<u8>,
    },
    Ack,
}

impl Engine {
    pub(super) fn absorb_peer_wraps(&self, state: &mut EngineState, cid: ConversationId) {
        let Some(policy) = conversation_policy(state, cid) else {
            return;
        };
        let minted = state
            .chains(cid)
            .map(|c| c.ratchet.minted.clone())
            .unwrap_or_default();
        let known: Vec<Tag> = state
            .chains(cid)
            .map(|c| c.ratchet.known.iter().map(|k| k.wrap_tx).collect())
            .unwrap_or_default();
        let wraps: Vec<(Tag, Vec<u8>)> = state
            .txs
            .iter()
            .filter_map(|(id, body)| match &body.payload {
                TxPayload::Wrap { kem_ct }
                    if body.conversation_id == cid
                        && !minted.contains(id)
                        && !known.contains(id) =>
                {
                    Some((*id, kem_ct.clone()))
                }
                _ => None,
            })
            .collect();
        for (wrap_tx, ct) in wraps {
            if ct.len() != kem_ct_len(policy) {
                continue;
            }
            let unused = state
                .chains(cid)
                .map(|c| c.ratchet.unused.clone())
                .unwrap_or_default();
            for (index, sk) in unused.iter().enumerate() {
                let Ok(shared) = self.suite.kem().unwrap(policy, &sk.sk, &ct) else {
                    continue;
                };
                if shared.len() != super::super::kem::KEM_SHARED_LEN {
                    continue;
                }
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&shared);
                if let Some(chains) = state.chains_mut(cid) {
                    chains.ratchet.unused.remove(index);
                    chains.ratchet.known.push(KnownShared {
                        wrap_tx,
                        shared: Secret::from_bytes(bytes),
                        ct_hash: digest_tag(self, &ct),
                        from_us: false,
                        encaps_pk: Vec::new(),
                    });
                }
                break;
            }
        }
    }

    pub(super) fn mint_if_owed(
        &self,
        state: &mut EngineState,
        rng: &dyn Rng,
        cid: ConversationId,
        secret: &Secret,
    ) -> Result<Option<Tag>, EngineError> {
        let since = state.chains(cid).map(|c| c.ratchet.since).unwrap_or(0);
        if since < OWED_PACKETS {
            return Ok(None);
        }
        let Some(policy) = conversation_policy(state, cid) else {
            return Ok(None);
        };
        let Some(minted) = self.choose_owed(state, rng, cid, policy)? else {
            return Ok(None);
        };
        let (tx_id, _, _) = self.merge_tx(state, secret, cid, minted.payload)?;
        let chains = state.chains_mut(cid).expect("conversation");
        chains.ratchet.since = 0;
        chains.ratchet.minted.insert(tx_id);
        match minted.effect {
            Effect::Advertise { pk, sk } => {
                if chains.ratchet.unused.len() >= UNUSED_CAP {
                    chains.ratchet.unused.remove(0);
                }
                chains.ratchet.unused.push(UnusedSk { tx_id, pk, sk });
            }
            Effect::Wrap {
                shared,
                ct_hash,
                encaps_pk,
            } => chains.ratchet.known.push(KnownShared {
                wrap_tx: tx_id,
                shared,
                ct_hash,
                from_us: true,
                encaps_pk,
            }),
            Effect::Ack => {}
        }
        Ok(Some(tx_id))
    }

    pub(super) fn mixed_chain(
        &self,
        state: &EngineState,
        cid: ConversationId,
        sort: ConversationSort,
        chain: &SendChain,
        from_us: bool,
    ) -> Option<SendChain> {
        if !mix_due(chain) {
            return None;
        }
        let shared = next_shared(state, cid, from_us, chain.epoch.as_u64())?;
        mix(self.suite.hmac(), chain, sort, shared.as_bytes()).ok()
    }

    pub(super) fn note_sent_packet(&self, state: &mut EngineState, cid: ConversationId) {
        if let Some(chains) = state.chains_mut(cid) {
            chains.ratchet.since = chains.ratchet.since.saturating_add(1);
        }
    }

    fn choose_owed(
        &self,
        state: &EngineState,
        rng: &dyn Rng,
        cid: ConversationId,
        policy: Policy,
    ) -> Result<Option<Minted>, EngineError> {
        if let Some(payload) = self.ack_of_wrap(state, cid) {
            return Ok(Some(Minted {
                payload,
                effect: Effect::Ack,
            }));
        }
        if let Some(payload) = self.ack_of_advertise(state, cid, policy) {
            return Ok(Some(Minted {
                payload,
                effect: Effect::Ack,
            }));
        }
        if let Some(minted) = self.wrap_to_peer(state, rng, cid, policy) {
            return Ok(Some(minted));
        }
        self.advertise(rng, policy)
    }

    fn ack_of_wrap(&self, state: &EngineState, cid: ConversationId) -> Option<TxPayload> {
        let chains = state.chains(cid)?;
        for known in &chains.ratchet.known {
            if known.from_us || !tx_watermarked(state, known.wrap_tx) {
                continue;
            }
            if ack_watermarked(state, cid, known.ct_hash) {
                continue;
            }
            if ack_exists(state, cid, known.ct_hash) {
                continue;
            }
            return Some(TxPayload::Ack {
                ratchet_ack: known.ct_hash,
            });
        }
        None
    }

    fn ack_of_advertise(
        &self,
        state: &EngineState,
        cid: ConversationId,
        policy: Policy,
    ) -> Option<TxPayload> {
        let minted = &state.chains(cid)?.ratchet.minted;
        for (id, body) in &state.txs {
            let TxPayload::Advertise { encaps_pk } = &body.payload else {
                continue;
            };
            if body.conversation_id != cid || minted.contains(id) {
                continue;
            }
            if encaps_pk.len() != kem_pk_len(policy) || !tx_watermarked(state, *id) {
                continue;
            }
            let tag = digest_tag(self, encaps_pk);
            if ack_exists(state, cid, tag) {
                continue;
            }
            return Some(TxPayload::Ack { ratchet_ack: tag });
        }
        None
    }

    fn wrap_to_peer(
        &self,
        state: &EngineState,
        rng: &dyn Rng,
        cid: ConversationId,
        policy: Policy,
    ) -> Option<Minted> {
        let chains = state.chains(cid)?;
        let minted = chains.ratchet.minted.clone();
        let wrapped: Vec<Vec<u8>> = chains
            .ratchet
            .known
            .iter()
            .filter(|k| k.from_us)
            .map(|k| k.encaps_pk.clone())
            .collect();
        for (id, body) in &state.txs {
            let TxPayload::Advertise { encaps_pk } = &body.payload else {
                continue;
            };
            if body.conversation_id != cid || minted.contains(id) {
                continue;
            }
            if encaps_pk.len() != kem_pk_len(policy) || !tx_watermarked(state, *id) {
                continue;
            }
            if wrapped.iter().any(|pk| pk == encaps_pk) {
                continue;
            }
            let seed = KemSeed::from_pair(rng.random32(), rng.random32());
            let Ok((shared, kem_ct)) = self.suite.kem().wrap(policy, encaps_pk, &seed) else {
                continue;
            };
            if shared.len() != super::super::kem::KEM_SHARED_LEN {
                continue;
            }
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&shared);
            return Some(Minted {
                payload: TxPayload::Wrap {
                    kem_ct: kem_ct.clone(),
                },
                effect: Effect::Wrap {
                    shared: Secret::from_bytes(bytes),
                    ct_hash: digest_tag(self, &kem_ct),
                    encaps_pk: encaps_pk.clone(),
                },
            });
        }
        None
    }

    fn advertise(&self, rng: &dyn Rng, policy: Policy) -> Result<Option<Minted>, EngineError> {
        let seed = KemSeed::from_pair(rng.random32(), rng.random32());
        let Ok(keys) = self.suite.kem().generate(policy, &seed) else {
            return Ok(None);
        };
        Ok(Some(Minted {
            payload: TxPayload::Advertise {
                encaps_pk: keys.public_bytes().to_vec(),
            },
            effect: Effect::Advertise {
                pk: keys.public_bytes().to_vec(),
                sk: keys.secret_bytes().to_vec(),
            },
        }))
    }
}

fn mix_due(chain: &SendChain) -> bool {
    let seq = chain.packet_seq.as_u64();
    seq > 0 && seq.is_multiple_of(MIX_STRIDE)
}

fn next_shared(
    state: &EngineState,
    cid: ConversationId,
    from_us: bool,
    epoch: u64,
) -> Option<Secret> {
    let agreed = agreed_shareds(state, cid, from_us);
    let epoch = usize::try_from(epoch).ok()?;
    if agreed.len() < epoch.saturating_add(MIX_READY) {
        return None;
    }
    agreed.into_iter().nth(epoch)
}

fn agreed_shareds(state: &EngineState, cid: ConversationId, from_us: bool) -> Vec<Secret> {
    let Some(chains) = state.chains(cid) else {
        return Vec::new();
    };
    let mut rows: Vec<(Tag, Secret)> = chains
        .ratchet
        .known
        .iter()
        .filter(|k| k.from_us == from_us && tx_watermarked(state, k.wrap_tx))
        .filter(|k| ack_watermarked(state, cid, k.ct_hash))
        .map(|k| (k.wrap_tx, k.shared))
        .collect();
    rows.sort_by_key(|(id, _)| *id);
    rows.into_iter().map(|(_, shared)| shared).collect()
}

fn ack_exists(state: &EngineState, cid: ConversationId, tag: Tag) -> bool {
    state.txs.values().any(|body| {
        body.conversation_id == cid
            && matches!(
                &body.payload,
                TxPayload::Ack { ratchet_ack } if *ratchet_ack == tag
            )
    })
}

fn ack_watermarked(state: &EngineState, cid: ConversationId, tag: Tag) -> bool {
    state.txs.iter().any(|(id, body)| {
        body.conversation_id == cid
            && matches!(
                &body.payload,
                TxPayload::Ack { ratchet_ack } if *ratchet_ack == tag
            )
            && tx_watermarked(state, *id)
    })
}

fn digest_tag(engine: &Engine, bytes: &[u8]) -> Tag {
    Tag::from_bytes(engine.suite.hash().hash(bytes))
}

pub(super) fn conversation_policy(state: &EngineState, cid: ConversationId) -> Option<Policy> {
    if let Some(notice) = notice_for(state, cid) {
        return Some(notice.policy);
    }
    if let Some(parent) = state.established_parent(cid)
        && let Some(notice) = notice_for(state, parent)
    {
        return Some(notice.policy);
    }
    let (user, identity) = state.owner(cid)?;
    state.txs.values().find_map(|body| match &body.payload {
        TxPayload::EngineCreateIdentity {
            user_id,
            identity_id,
            policy,
            ..
        } if *user_id == user && *identity_id == identity => Some(*policy),
        _ => None,
    })
}
