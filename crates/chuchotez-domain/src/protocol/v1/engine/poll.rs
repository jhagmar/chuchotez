//! Tick and mapper poll.

use super::super::payload::{TxPayload, time_bin};
use super::super::{EngineError, IdentityId, TimeBin, UnixSeconds, UserId};
use super::helpers::*;
use super::party::HandshakeFailure;
use super::query::*;
use super::{Engine, EngineState};
use std::collections::BTreeSet;
impl Engine {
    /// Advance the clock. Stores `InviteExpired` when `now` is past `expires`
    /// pre-confirm.
    pub fn tick(&self, mut state: EngineState, now: u64) -> Result<MutateOk, EngineError> {
        let now = UnixSeconds::from_u64(now);
        let _ = self.require_dek()?;
        if let Some(prev) = state.ticked
            && now < prev
        {
            return Err(EngineError::ClockWentBackwards);
        }
        state.ticked = Some(now);
        state.each_chains_mut(|chains| {
            for entries in chains.skipped_mks.values_mut() {
                entries.retain(|e| e.expires_at > now);
            }
            chains.skipped_mks.retain(|_, e| !e.is_empty());
        });
        let mut expired = Vec::new();
        for (cid, ticket, _) in handshake_rows(&state) {
            if state.failed(cid).is_some() || now <= ticket.expires {
                continue;
            }
            let conversation_id = cid;
            let confirmed = state.txs.values().any(|t| {
                matches!(t.payload, TxPayload::Confirm) && t.conversation_id == conversation_id
            });
            if !confirmed {
                expired.push((cid, ticket.expires));
            }
        }
        for (cid, expires) in expired {
            state.fail(cid, HandshakeFailure::InviteExpired { expires });
        }
        self.flush_heal(&mut state);
        self.flush_live(&mut state);
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
        let mut list = Vec::new();
        let mut listen_durable = Vec::new();
        for row in state.handshake_entries() {
            let cid = row.cid;
            if row.party.failure().is_none() && intro_watermarked(state, cid) {
                continue;
            }
            let secret = row.party.ticket().secret.as_bytes();
            let tag_key = handshake_tag_key(self.suite.hmac(), secret);
            let list_from = row.party.list_from();
            for ch in &row.party.ticket().persistents {
                let progress = state.bin_progress.get(&progress_key(ch, &tag_key));
                let start = catch_up_start(progress, list_from);
                let mut bins = BTreeSet::new();
                for n in start.as_u64()..=w.saturating_add(1).as_u64() {
                    let bin = TimeBin::from_u64(n);
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
        self.append_group_listen(state, w, &mut listen_durable);
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
                && state.display_name(*identity_id).is_none()
            {
                blocked.push(BlockedIdentity {
                    user_id: *user_id,
                    identity_id: *identity_id,
                    missing: BlockedMissing::DisplayName,
                });
            }
        }
        if state.device.name.is_none()
            && state
                .txs
                .values()
                .all(|t| !matches!(t.payload, TxPayload::EngineCreateUser { .. }))
            && state.has_sync_handshake()
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
            blob_get: blob_gets(state),
            blocked,
            ..Poll::default()
        })
    }

    fn append_group_listen(
        &self,
        state: &EngineState,
        now: TimeBin,
        listen: &mut Vec<DurableLocator>,
    ) {
        let label = super::super::payload::ConversationSort::Group
            .persist_label()
            .expect("group label");
        for user in state.users.values() {
            for ident in user.identities.values() {
                for node in ident.conversations.values() {
                    let super::party::IdentityConversation::Group(super::party::GroupPhase::Live(
                        live,
                    )) = &node.kind
                    else {
                        continue;
                    };
                    for member in &live.members {
                        for channel in &live.persistents {
                            for bin in listen_bins(now) {
                                listen.push(DurableLocator {
                                    channel: channel.clone(),
                                    tag: super::live::bin_tag(
                                        self.suite.hmac(),
                                        member.send_tag_key,
                                        label,
                                        bin,
                                    ),
                                });
                            }
                        }
                    }
                }
            }
        }
        sort_durable_locators(listen);
        listen.dedup();
    }
}

fn blob_gets(state: &EngineState) -> Vec<BlobGet> {
    let mut out = Vec::new();
    for tx in state.txs.values() {
        let TxPayload::Media(media) = &tx.payload else {
            continue;
        };
        let pending = state.blob_puts.iter().any(|put| {
            put.kind == media.kind && put.address == media.address && put.tag == media.tag
        });
        if pending {
            continue;
        }
        out.push(BlobGet {
            kind: media.kind.clone(),
            address: media.address.clone(),
            tag: media.tag,
        });
    }
    out
}
