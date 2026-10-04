//! Established chat bounds, history, typing, presence, and wake pings.

use super::super::payload::{TxPayload, TxText};
use super::super::unicode::is_combining;
use super::super::{ConversationId, EngineError, Tag, UnixSeconds, Wake};
use super::Engine;
use super::helpers::{invitee_intro_for, inviter_intro_for};
use super::live::local_material;
use super::query::{DmEstablished, HistoryItem, PingTarget, PresenceView, TypingView};
use super::state::{EngineState, TypingNote};
use super::{QueryLocalPrefs, QueryPeerPrefs};

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

    pub(super) fn fill_ping(&self, state: &EngineState, cid: ConversationId) -> Vec<PingTarget> {
        if super::group::group_live(state, cid).is_some() {
            return group_member_pings(state, cid);
        }
        peer_wake(self, state, cid)
            .map(ping_target)
            .into_iter()
            .collect()
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
        let card = peer_card(self, state, cid);
        let parent = state.established_parent(cid);
        let notice = parent.and_then(|id| super::helpers::notice_for(state, id));
        DmEstablished {
            name: card.name,
            profile_pic: card.profile_pic,
            encryption_pk: card.encryption_pk,
            signing_pk: card.signing_pk,
            persistents: notice.map(|n| n.persistents.clone()).unwrap_or_default(),
            ephemerals: notice.map(|n| n.ephemerals.clone()).unwrap_or_default(),
            confirmation_digest: parent
                .and_then(|id| self.try_fingerprint(state, id).map(|(digest, _)| digest))
                .unwrap_or_default(),
            last_active: chains.presence_at,
            typing,
            presence,
            read_up_to: latest_marker(state, cid, true),
            delivered_up_to: latest_marker(state, cid, false),
            local_prefs: local_prefs(self, state, cid),
            peer_prefs: peer_prefs(&card.prefs),
            messages: history(state, cid, now),
        }
    }

    pub(super) fn shows_online(&self, state: &EngineState, cid: ConversationId) -> bool {
        latest_online(state, cid).unwrap_or_else(|| self.defaults.online_visible())
    }
}

fn peer_prefs(prefs: &super::super::OnWirePrefs) -> QueryPeerPrefs {
    QueryPeerPrefs {
        read_receipts: prefs.read_receipts,
        online_visible: prefs.online_visible,
        send_typing: prefs.send_typing,
        disappear_after: prefs.disappear_after,
        wake_endpoint: prefs.wake.as_ref().map(|wake| wake.endpoint().to_owned()),
        vapid_pk: prefs
            .wake
            .as_ref()
            .and_then(|wake| wake.vapid_pk().map(|bytes| bytes.to_vec())),
    }
}

pub(super) fn local_prefs(
    engine: &Engine,
    state: &EngineState,
    cid: ConversationId,
) -> QueryLocalPrefs {
    let wire = latest_wire(state, cid).unwrap_or_else(|| engine.on_wire_prefs());
    let peer = peer_prefs(&wire);
    QueryLocalPrefs {
        read_receipts: peer.read_receipts,
        online_visible: peer.online_visible,
        send_typing: peer.send_typing,
        disappear_after: peer.disappear_after,
        wake_endpoint: peer.wake_endpoint,
        vapid_pk: peer.vapid_pk,
        notification_privacy: engine.defaults.notification_privacy(),
    }
}

struct PeerCard {
    name: super::super::DisplayName,
    profile_pic: Option<super::super::ProfilePic>,
    encryption_pk: super::super::EncryptionPublicKey,
    signing_pk: super::super::SigningPublicKey,
    prefs: super::super::OnWirePrefs,
}

fn peer_card(engine: &Engine, state: &EngineState, cid: ConversationId) -> PeerCard {
    let fallback = || PeerCard {
        name: super::super::DisplayName::try_from(".").expect("dot"),
        profile_pic: None,
        encryption_pk: crate::protocol::v1::EncryptionPublicKey::from_bytes(Vec::new()),
        signing_pk: crate::protocol::v1::SigningPublicKey::from_bytes(Vec::new()),
        prefs: engine.on_wire_prefs(),
    };
    let Some(parent) = state.established_parent(cid) else {
        return fallback();
    };
    let local = state.owner(cid).and_then(|(user, identity)| {
        engine
            .identity_keys(state, &user, &identity)
            .map(|(_, _, signing)| signing)
    });
    if let Some(intro) = super::helpers::inviter_intro_for(state, parent)
        && local
            .as_ref()
            .is_none_or(|signing| signing.as_slice() != intro.signing_pk.as_bytes())
    {
        return PeerCard {
            name: intro.name.clone(),
            profile_pic: intro.profile_pic.clone(),
            encryption_pk: intro.encryption_pk.clone(),
            signing_pk: intro.signing_pk.clone(),
            prefs: intro.prefs.clone(),
        };
    }
    if let Some(intro) = super::helpers::invitee_intro_for(state, parent) {
        return PeerCard {
            name: intro.name.clone(),
            profile_pic: intro.profile_pic.clone(),
            encryption_pk: intro.encryption_pk.clone(),
            signing_pk: intro.signing_pk.clone(),
            prefs: intro.prefs.clone(),
        };
    }
    fallback()
}

fn latest_wire(state: &EngineState, cid: ConversationId) -> Option<super::super::OnWirePrefs> {
    let mut best: Option<(u64, u64, [u8; 32], super::super::OnWirePrefs)> = None;
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
            best = Some((tx.hlc.wall_ms, tx.hlc.counter, idb, prefs.clone()));
        }
    }
    best.map(|(_, _, _, prefs)| prefs)
}

fn latest_marker(state: &EngineState, cid: ConversationId, read: bool) -> Option<Tag> {
    let mut best: Option<(u64, u64, [u8; 32], Tag)> = None;
    for (id, tx) in &state.txs {
        if tx.conversation_id != cid {
            continue;
        }
        let up_to = match &tx.payload {
            TxPayload::Read { up_to } if read => Some(*up_to),
            TxPayload::Delivered { up_to } if !read => Some(*up_to),
            _ => None,
        };
        let Some(up_to) = up_to else {
            continue;
        };
        let idb = *id.as_bytes();
        let replace = best.as_ref().is_none_or(|(wall, counter, prev, _)| {
            (tx.hlc.wall_ms, tx.hlc.counter, idb) > (*wall, *counter, *prev)
        });
        if replace {
            best = Some((tx.hlc.wall_ms, tx.hlc.counter, idb, up_to));
        }
    }
    best.map(|(_, _, _, up_to)| up_to)
}

fn ping_target(wake: Wake) -> PingTarget {
    PingTarget {
        endpoint: wake.endpoint().to_owned(),
        p256dh: *wake.p256dh(),
        auth: *wake.auth(),
        vapid_pk: wake.vapid_pk().map(|bytes| bytes.to_vec()),
    }
}

struct PrefsSeen {
    id: Tag,
    sender: super::super::Actor,
    wall: u64,
    counter: u64,
    wake: Option<Wake>,
}

struct LatestWake {
    sender: super::super::Actor,
    key: (u64, u64, [u8; 32]),
    wake: Option<Wake>,
}

fn group_member_pings(state: &EngineState, cid: ConversationId) -> Vec<PingTarget> {
    let members: Vec<Vec<u8>> = super::group::group_live(state, cid)
        .expect("group")
        .members
        .iter()
        .map(|member| member.signing_pk.as_bytes().to_vec())
        .collect();
    let senders = state.chains(cid).expect("row").chat_senders.clone();
    let mut rows = Vec::new();
    for (id, tx) in &state.txs {
        if tx.conversation_id != cid {
            continue;
        }
        let TxPayload::Prefs(prefs) = &tx.payload else {
            continue;
        };
        let Some(sender) = senders.get(id) else {
            continue;
        };
        rows.push(PrefsSeen {
            id: *id,
            sender: sender.clone(),
            wall: tx.hlc.wall_ms,
            counter: tx.hlc.counter,
            wake: prefs.wake.clone(),
        });
    }
    rows.sort_by_key(|row| *row.id.as_bytes());
    let mut best: Vec<LatestWake> = Vec::new();
    for row in rows {
        if !members
            .iter()
            .any(|member| member.as_slice() == row.sender.as_bytes())
        {
            continue;
        }
        let key = (row.wall, row.counter, *row.id.as_bytes());
        if let Some(kept) = best.iter_mut().find(|kept| kept.sender == row.sender) {
            if key > kept.key {
                kept.key = key;
                kept.wake = row.wake;
            }
        } else {
            best.push(LatestWake {
                sender: row.sender,
                key,
                wake: row.wake,
            });
        }
    }
    best.into_iter()
        .filter_map(|kept| kept.wake.map(ping_target))
        .collect()
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
        && intro.signing_pk != crate::protocol::v1::SigningPublicKey::from_bytes(signing)
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
            sender: senders
                .get(id)
                .cloned()
                .unwrap_or_else(super::super::Actor::handshake),
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
                sender: super::super::super::Actor::handshake(),
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
        assert!(super::latest_wire(&state, cid).is_some());
        state.txs.insert(
            Tag::from_bytes([11; 32]),
            DurableBody {
                conversation_id: cid,
                hlc: Hlc {
                    wall_ms: 1,
                    counter: 0,
                },
                payload: TxPayload::Read {
                    up_to: Tag::from_bytes([1; 32]),
                },
            },
        );
        state.txs.insert(
            Tag::from_bytes([12; 32]),
            DurableBody {
                conversation_id: cid,
                hlc: Hlc {
                    wall_ms: 2,
                    counter: 0,
                },
                payload: TxPayload::Read {
                    up_to: Tag::from_bytes([2; 32]),
                },
            },
        );
        state.txs.insert(
            Tag::from_bytes([13; 32]),
            DurableBody {
                conversation_id: cid,
                hlc: Hlc {
                    wall_ms: 1,
                    counter: 0,
                },
                payload: TxPayload::Delivered {
                    up_to: Tag::from_bytes([1; 32]),
                },
            },
        );
        state.txs.insert(
            Tag::from_bytes([14; 32]),
            DurableBody {
                conversation_id: cid,
                hlc: Hlc {
                    wall_ms: 3,
                    counter: 0,
                },
                payload: TxPayload::Delivered {
                    up_to: Tag::from_bytes([2; 32]),
                },
            },
        );
        assert_eq!(
            super::latest_marker(&state, cid, true),
            Some(Tag::from_bytes([2; 32]))
        );
        assert_eq!(
            super::latest_marker(&state, cid, false),
            Some(Tag::from_bytes([2; 32]))
        );
        assert_eq!(latest_disappear(&state, other), Some(Some(100)));
        let with_wake = OnWirePrefs {
            read_receipts: true,
            online_visible: true,
            send_typing: true,
            disappear_after: None,
            wake: Some(
                crate::protocol::v1::Wake::try_new(
                    "https://push.example/q",
                    &[3u8; 65],
                    &[4u8; 16],
                    Some(vec![9, 9, 9]),
                )
                .expect("wake"),
            ),
        };
        let shown = super::peer_prefs(&with_wake);
        assert_eq!(
            shown.wake_endpoint.as_deref(),
            Some("https://push.example/q")
        );
        assert_eq!(shown.vapid_pk.as_deref(), Some(&[9, 9, 9][..]));
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

    #[test]
    fn missing_peer_intro_uses_a_placeholder_name() {
        use super::super::state::{DeviceNode, EngineState, IdentityNode};
        use crate::protocol::v1::fixtures::test_engine;
        use crate::protocol::v1::{ConversationId, IdentityId, Secret, UserId};
        let engine = test_engine();
        let cid = ConversationId::from_bytes([2; 32]);
        let mut state = EngineState::new();
        state.put_dm(
            UserId::from_bytes([3; 32]),
            IdentityId::from_bytes([4; 32]),
            cid,
            IdentityNode::direct(
                Secret::from_bytes([5; 32]),
                ConversationId::from_bytes([1; 32]),
            ),
        );
        assert_eq!(super::peer_card(&engine, &state, cid).name.as_str(), ".");
        state.put_sync(
            ConversationId::from_bytes([8; 32]),
            DeviceNode::sync(
                Secret::from_bytes([6; 32]),
                ConversationId::from_bytes([9; 32]),
                crate::protocol::v1::DeviceId::from_bytes([0; 32]),
            ),
        );
        let named = engine.sync_view(&state, ConversationId::from_bytes([8; 32]));
        assert!(named.members.is_empty());
        let empty = engine.sync_view(&EngineState::new(), ConversationId::from_bytes([1; 32]));
        assert_eq!(empty.device_name.as_str(), ".");
    }

    #[test]
    fn group_pings_keep_each_members_latest_wake() {
        use super::super::super::payload::{DurableBody, GroupMember, Hlc};
        use super::super::party::{GroupLive, GroupPhase, IdentityConversation};
        use super::super::state::{EngineState, IdentityNode};
        use super::group_member_pings;
        use crate::protocol::v1::{
            ConversationId, DisplayName, IdentityId, OnWirePrefs, Secret, Tag, TagKey, UserId, Wake,
        };
        let cid = ConversationId::from_bytes([7; 32]);
        let owner = vec![1u8];
        let other = vec![2u8];
        let member = |pk: Vec<u8>, n: u8| GroupMember {
            signing_pk: crate::protocol::v1::SigningPublicKey::from_bytes(pk),
            encryption_pk: super::super::super::EncryptionPublicKey::from_bytes(vec![1]),
            send_tag_key: TagKey::from_bytes([n; 32]),
            eph_send_tag_key: TagKey::from_bytes([n.wrapping_add(1); 32]),
        };
        let mut state = EngineState::new();
        state.put_dm(
            UserId::from_bytes([3; 32]),
            IdentityId::from_bytes([4; 32]),
            cid,
            IdentityNode {
                kind: IdentityConversation::Group(GroupPhase::Live(GroupLive {
                    secret: Secret::from_bytes([5; 32]),
                    name: DisplayName::try_from("G").expect("n"),
                    photo: None,
                    owner_signing_pk: crate::protocol::v1::SigningPublicKey::from_bytes(
                        owner.clone(),
                    ),
                    persistents: Vec::new(),
                    ephemerals: Vec::new(),
                    members: vec![member(owner.clone(), 6), member(other.clone(), 8)],
                    pending: Vec::new(),
                    epoch: 0,
                })),
                chains: Default::default(),
            },
        );
        let wake = |endpoint: &str| {
            Wake::try_new(endpoint, &[3u8; 65], &[4u8; 16], Some(vec![9, 9, 9])).expect("w")
        };
        let prefs = |wall, wake| DurableBody {
            conversation_id: cid,
            hlc: Hlc {
                wall_ms: wall,
                counter: 0,
            },
            payload: TxPayload::Prefs(OnWirePrefs {
                read_receipts: true,
                online_visible: false,
                send_typing: true,
                disappear_after: None,
                wake,
            }),
        };
        let id = |byte: u8| Tag::from_bytes([byte; 32]);
        state
            .txs
            .insert(id(0), prefs(10, Some(wake("https://push.example/a"))));
        state
            .txs
            .insert(id(1), prefs(30, Some(wake("https://push.example/b"))));
        state
            .txs
            .insert(id(2), prefs(20, Some(wake("https://push.example/c"))));
        state
            .txs
            .insert(id(3), prefs(40, Some(wake("https://push.example/d"))));
        state
            .txs
            .insert(id(4), prefs(50, Some(wake("https://push.example/e"))));
        state.txs.insert(id(8), prefs(1, None));
        state.txs.insert(
            id(6),
            DurableBody {
                conversation_id: cid,
                hlc: Hlc {
                    wall_ms: 1,
                    counter: 0,
                },
                payload: TxPayload::Confirm,
            },
        );
        state.txs.insert(
            id(5),
            DurableBody {
                conversation_id: ConversationId::from_bytes([9; 32]),
                hlc: Hlc {
                    wall_ms: 1,
                    counter: 0,
                },
                payload: TxPayload::Prefs(OnWirePrefs {
                    read_receipts: true,
                    online_visible: false,
                    send_typing: true,
                    disappear_after: None,
                    wake: None,
                }),
            },
        );
        let chains = state.chains_mut(cid).expect("chains");
        chains
            .chat_senders
            .insert(id(0), super::super::super::Actor::signing(owner.clone()));
        chains
            .chat_senders
            .insert(id(1), super::super::super::Actor::signing(owner.clone()));
        chains
            .chat_senders
            .insert(id(2), super::super::super::Actor::signing(owner));
        chains
            .chat_senders
            .insert(id(3), super::super::super::Actor::signing(vec![9]));
        chains
            .chat_senders
            .insert(id(8), super::super::super::Actor::signing(other));
        let pings = group_member_pings(&state, cid);
        assert_eq!(pings.len(), 1);
        assert_eq!(pings[0].endpoint, "https://push.example/b");
    }
}
