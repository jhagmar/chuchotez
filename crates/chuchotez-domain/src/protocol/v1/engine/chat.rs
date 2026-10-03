//! Established chat bounds, history, typing, presence, and wake pings.

use super::super::payload::{TxPayload, TxText};
use super::super::unicode::is_combining;
use super::super::{ConversationId, EngineError, Tag, UnixSeconds, Wake};
use super::Engine;
use super::helpers::{invitee_intro_for, inviter_intro_for};
use super::live::local_material;
use super::query::{DmEstablished, HistoryItem, PingTarget, PresenceView, TypingView};
use super::state::{EngineState, TypingNote};

const HISTORY_CAP: usize = 1000;
const TYPING_SECS: u64 = 6;

impl Engine {
    pub(super) fn gate_chat(
        &self,
        state: &EngineState,
        ids: &super::query::ConversationRef,
    ) -> Result<(), EngineError> {
        if state.is_sync(ids.conversation_id) {
            return self.require_dm_chat(state, ids.conversation_id);
        }
        self.require_ids(state, ids)?;
        self.require_dm_chat(state, ids.conversation_id)
    }

    pub(super) fn require_dm_chat(
        &self,
        state: &EngineState,
        conversation_id: ConversationId,
    ) -> Result<(), EngineError> {
        if state.established_secret(conversation_id).is_some() && !state.is_sync(conversation_id) {
            return Ok(());
        }
        Err(EngineError::WrongPhase)
    }

    pub(super) fn require_signal(
        &self,
        state: &EngineState,
        conversation_id: ConversationId,
    ) -> Result<(), EngineError> {
        if state.established_secret(conversation_id).is_some() {
            return Ok(());
        }
        Err(EngineError::WrongPhase)
    }

    pub(super) fn chat_text(&self, value: &str) -> Result<(), EngineError> {
        let chars = value.chars().count();
        if value.is_empty()
            || value.len() > 16_384
            || chars > 4096
            || value.chars().any(is_combining)
        {
            return Err(EngineError::MalformedPayload);
        }
        Ok(())
    }

    pub(super) fn chat_emoji(&self, emoji: &str) -> Result<(), EngineError> {
        if emoji.is_empty() || emoji.len() > 32 || emoji.chars().any(is_combining) {
            return Err(EngineError::MalformedPayload);
        }
        Ok(())
    }

    pub(super) fn expire_at(
        &self,
        state: &EngineState,
        cid: ConversationId,
    ) -> Option<UnixSeconds> {
        let secs = latest_disappear(state, cid).unwrap_or_else(|| self.defaults.disappear_after());
        let now = state.ticked?;
        secs.map(|secs| now.saturating_add(secs))
    }

    pub(super) fn text_payload(
        &self,
        state: &EngineState,
        cid: ConversationId,
        body: String,
        reply_to: Option<Tag>,
    ) -> TxPayload {
        TxPayload::Text(TxText {
            body,
            reply_to,
            expire_at: self.expire_at(state, cid),
        })
    }

    pub(super) fn remember_sender(&self, state: &mut EngineState, cid: ConversationId, tx_id: Tag) {
        let (actor, _) = local_material(self, state, cid).expect("actor");
        state
            .chains_mut(cid)
            .expect("row")
            .chat_senders
            .insert(tx_id, actor);
    }

    pub(super) fn fill_ping(&self, state: &EngineState, cid: ConversationId) -> Option<PingTarget> {
        let wake = peer_wake(self, state, cid)?;
        Some(PingTarget {
            endpoint: wake.endpoint().to_owned(),
            p256dh: *wake.p256dh(),
            auth: *wake.auth(),
            vapid_pk: wake.vapid_pk().map(|bytes| bytes.to_vec()),
        })
    }

    pub(super) fn note_typing(
        &self,
        state: &mut EngineState,
        cid: ConversationId,
        composing: bool,
        at: UnixSeconds,
    ) {
        state.chains_mut(cid).expect("row").typing = Some(TypingNote { composing, at });
    }

    pub(super) fn note_presence(
        &self,
        state: &mut EngineState,
        cid: ConversationId,
        at: UnixSeconds,
    ) {
        state.chains_mut(cid).expect("row").presence_at = Some(at);
    }

    pub(super) fn note_packet_signal(
        &self,
        state: &mut EngineState,
        cid: ConversationId,
        now: UnixSeconds,
        packet: &super::super::payload::PacketPlain,
    ) {
        match packet {
            super::super::payload::PacketPlain::Typing(packet) => {
                self.note_typing(state, cid, packet.composing, now);
            }
            super::super::payload::PacketPlain::TypingActive(packet) => {
                self.note_typing(
                    state,
                    cid,
                    packet.composing,
                    UnixSeconds::from_u64(packet.last_active),
                );
            }
            super::super::payload::PacketPlain::Presence(_) => {
                self.note_presence(state, cid, now);
            }
            super::super::payload::PacketPlain::PresenceActive(packet) => {
                self.note_presence(state, cid, UnixSeconds::from_u64(packet.last_active));
            }
            _ => {}
        }
    }

    pub(super) fn dm_view(&self, state: &EngineState, cid: ConversationId) -> DmEstablished {
        let now = state.ticked.unwrap_or(UnixSeconds::from_u64(0));
        let chains = state.chains(cid).expect("row");
        let typing = chains.typing.as_ref().and_then(|note| {
            (now < note.at.saturating_add(TYPING_SECS)).then_some(TypingView {
                composing: note.composing,
                last_active: note.at,
            })
        });
        let presence = chains
            .presence_at
            .map(|at| PresenceView { last_active: at });
        DmEstablished {
            messages: history(state, cid, now),
            typing,
            presence,
        }
    }

    pub(super) fn shows_online(&self, state: &EngineState, cid: ConversationId) -> bool {
        latest_online(state, cid).unwrap_or_else(|| self.defaults.online_visible())
    }
}

fn latest_disappear(state: &EngineState, cid: ConversationId) -> Option<Option<u64>> {
    let mut best: Option<(u64, u64, [u8; 32], Option<u64>)> = None;
    for (id, tx) in &state.txs {
        if tx.conversation_id != cid {
            continue;
        }
        let TxPayload::Prefs(prefs) = &tx.payload else {
            continue;
        };
        let idb = *id.as_bytes();
        let replace = best.as_ref().is_none_or(|(wall, counter, prev, _)| {
            (tx.hlc.wall_ms, tx.hlc.counter, idb) > (*wall, *counter, *prev)
        });
        if replace {
            best = Some((tx.hlc.wall_ms, tx.hlc.counter, idb, prefs.disappear_after));
        }
    }
    best.map(|(_, _, _, secs)| secs)
}

fn latest_online(state: &EngineState, cid: ConversationId) -> Option<bool> {
    let mut best: Option<(u64, u64, [u8; 32], bool)> = None;
    for (id, tx) in &state.txs {
        if tx.conversation_id != cid {
            continue;
        }
        let TxPayload::Prefs(prefs) = &tx.payload else {
            continue;
        };
        let idb = *id.as_bytes();
        let replace = best.as_ref().is_none_or(|(wall, counter, prev, _)| {
            (tx.hlc.wall_ms, tx.hlc.counter, idb) > (*wall, *counter, *prev)
        });
        if replace {
            best = Some((tx.hlc.wall_ms, tx.hlc.counter, idb, prefs.online_visible));
        }
    }
    best.map(|(_, _, _, online)| online)
}

fn peer_wake(engine: &Engine, state: &EngineState, cid: ConversationId) -> Option<Wake> {
    let parent = state.established_parent(cid)?;
    let (_, signing) = local_material(engine, state, cid)?;
    if let Some(intro) = inviter_intro_for(state, parent)
        && intro.signing_pk != signing
    {
        return intro.prefs.wake.clone();
    }
    invitee_intro_for(state, parent).and_then(|intro| intro.prefs.wake.clone())
}

fn history(state: &EngineState, cid: ConversationId, now: UnixSeconds) -> Vec<HistoryItem> {
    let senders = state
        .chains(cid)
        .map(|chains| &chains.chat_senders)
        .expect("row");
    let mut items = Vec::new();
    for (id, tx) in &state.txs {
        if tx.conversation_id != cid || !in_history(&tx.payload) || expired(&tx.payload, now) {
            continue;
        }
        items.push(HistoryItem {
            tx_id: *id,
            sender: senders.get(id).cloned().unwrap_or_default(),
            hlc: tx.hlc,
            payload: tx.payload.clone(),
            expire_at: expire_of(&tx.payload),
        });
    }
    trim_recent(items)
}

fn in_history(payload: &TxPayload) -> bool {
    matches!(
        payload,
        TxPayload::Text(_)
            | TxPayload::Edit(_)
            | TxPayload::Remove { .. }
            | TxPayload::Reaction(_)
            | TxPayload::Read { .. }
            | TxPayload::Delivered { .. }
            | TxPayload::Media(_)
    )
}

fn expire_of(payload: &TxPayload) -> Option<UnixSeconds> {
    match payload {
        TxPayload::Text(text) => text.expire_at,
        TxPayload::Media(media) => media.expire_at,
        _ => None,
    }
}

fn expired(payload: &TxPayload, now: UnixSeconds) -> bool {
    expire_of(payload).is_some_and(|at| at <= now)
}

pub(super) fn trim_recent(mut items: Vec<HistoryItem>) -> Vec<HistoryItem> {
    items.sort_by(|left, right| {
        left.hlc
            .wall_ms
            .cmp(&right.hlc.wall_ms)
            .then(left.hlc.counter.cmp(&right.hlc.counter))
            .then(left.tx_id.as_bytes().cmp(right.tx_id.as_bytes()))
    });
    let extra = items.len().saturating_sub(HISTORY_CAP);
    items.drain(..extra);
    items
}

#[cfg(test)]
mod tests {
    use super::super::super::Tag;
    use super::super::super::payload::{Hlc, TxPayload};
    use super::super::query::HistoryItem;
    use super::trim_recent;

    #[test]
    fn history_keeps_the_newest_thousand() {
        let items: Vec<_> = (0..1001)
            .map(|n| HistoryItem {
                tx_id: Tag::from_bytes([u8::try_from(n & 0xff).unwrap_or(0); 32]),
                sender: Vec::new(),
                hlc: Hlc {
                    wall_ms: n,
                    counter: 0,
                },
                payload: TxPayload::Confirm,
                expire_at: None,
            })
            .collect();
        let kept = trim_recent(items);
        assert_eq!(kept.len(), 1000);
        assert_eq!(kept[0].hlc.wall_ms, 1);
        assert_eq!(kept[999].hlc.wall_ms, 1000);
    }

    #[test]
    fn later_prefs_replace_earlier_ones() {
        use super::super::super::payload::DurableBody;
        use super::super::super::{ConversationId, OnWirePrefs};
        use super::super::state::EngineState;
        use super::latest_disappear;
        use super::latest_online;
        let cid = ConversationId::from_bytes([4; 32]);
        let other = ConversationId::from_bytes([5; 32]);
        let mut state = EngineState::default();
        let prefs = |wall, disappear, online| DurableBody {
            conversation_id: cid,
            hlc: Hlc {
                wall_ms: wall,
                counter: 0,
            },
            payload: TxPayload::Prefs(OnWirePrefs {
                read_receipts: true,
                online_visible: online,
                send_typing: true,
                disappear_after: disappear,
                wake: None,
            }),
        };
        state
            .txs
            .insert(Tag::from_bytes([1; 32]), prefs(10, Some(1), true));
        state
            .txs
            .insert(Tag::from_bytes([2; 32]), prefs(20, Some(9), false));
        state
            .txs
            .insert(Tag::from_bytes([0; 32]), prefs(5, Some(3), true));
        state.txs.insert(
            Tag::from_bytes([3; 32]),
            DurableBody {
                conversation_id: cid,
                hlc: Hlc {
                    wall_ms: 30,
                    counter: 0,
                },
                payload: TxPayload::Confirm,
            },
        );
        state.txs.insert(
            Tag::from_bytes([4; 32]),
            DurableBody {
                conversation_id: other,
                hlc: Hlc {
                    wall_ms: 40,
                    counter: 0,
                },
                payload: TxPayload::Prefs(OnWirePrefs {
                    read_receipts: false,
                    online_visible: true,
                    send_typing: false,
                    disappear_after: Some(100),
                    wake: None,
                }),
            },
        );
        assert_eq!(latest_disappear(&state, cid), Some(Some(9)));
        assert_eq!(latest_online(&state, cid), Some(false));
        assert_eq!(latest_disappear(&state, other), Some(Some(100)));
        let media = TxPayload::Media(super::super::super::payload::TxMedia {
            mime: "image/png".into(),
            filename: "a.png".into(),
            hash: Tag::from_bytes([9; 32]),
            kind: super::super::super::Kind::try_from("blossom").expect("k"),
            address: super::super::super::Address::try_from("https://blob.example").expect("a"),
            tag: Tag::from_bytes([8; 32]),
            caption: None,
            reply_to: None,
            expire_at: Some(super::super::super::UnixSeconds::from_u64(4)),
        });
        assert_eq!(
            super::expire_of(&media),
            Some(super::super::super::UnixSeconds::from_u64(4))
        );
        assert!(super::expired(
            &media,
            super::super::super::UnixSeconds::from_u64(4)
        ));
    }

    #[test]
    fn online_uses_defaults_without_prefs() {
        use super::super::state::EngineState;
        use crate::protocol::v1::fixtures::test_engine;
        let engine = test_engine();
        let state = EngineState::new();
        let cid = super::super::super::ConversationId::from_bytes([1; 32]);
        assert!(engine.shows_online(&state, cid));
    }
}
