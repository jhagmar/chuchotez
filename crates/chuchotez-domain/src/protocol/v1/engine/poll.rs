//! Tick and mapper poll.

use super::super::payload::{TxPayload, time_bin};
use super::super::{EngineError, IdentityId, UserId};
use super::helpers::*;
use super::query::*;
use super::{Engine, EngineState};
use std::collections::BTreeSet;
impl Engine {
    /// Advance the clock. Stores `InviteExpired` when `now` is past `expires`
    /// pre-confirm.
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
            state.fail(cid, FailedReason::InviteExpired { expires });
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
            blocked,
            ..Poll::default()
        })
    }
}
