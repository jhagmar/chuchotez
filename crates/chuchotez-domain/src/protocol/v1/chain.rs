//! Packet sending chain: join, `mk`, step, skip-ahead, and 512-byte seal.

use super::codec::{packed_durable_body, packed_packet, packet_from_json};
use super::hmac::{HmacSha256, HmacSha256Key, expand};
use super::payload::{
    ConversationSort, DurableBody, PACKET_LEN, PACKET_MAX_UNCOMPRESSED, PACKET_NONCE_LEN,
    PACKET_PAD_LEN, PacketPlain, PacketTxFragLast, PacketTxFragMore, unpad,
};
use super::{AeadKey, AeadNonce, Base64Url, ConversationId, EngineError, Json, Suite, Tag};
use crate::protocol::Rng;

pub(crate) const MK_LABEL: &[u8] = b"chuchotez/1/packet-mk";
pub(crate) const STEP_LABEL: &[u8] = b"chuchotez/1/packet-step";
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const EPH_MK_LABEL: &[u8] = b"chuchotez/1/eph-mk";
pub(crate) const SKIP_AHEAD: u64 = 50;
pub(crate) const LATER_EPOCHS: u64 = 8;
pub(crate) const MK_CACHE_SECS: u64 = 172_800;
pub(crate) const MAX_FRAGS: u64 = 64;

/// One direction of packet keys on a conversation.
#[derive(Clone)]
pub(crate) struct SendChain {
    pub root: [u8; 32],
    pub c: [u8; 32],
    pub epoch: u64,
    pub packet_seq: u64,
}

impl core::fmt::Debug for SendChain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SendChain")
            .field("epoch", &self.epoch)
            .field("packet_seq", &self.packet_seq)
            .finish_non_exhaustive()
    }
}

/// A skipped `mk` kept until `expires_at` ticked seconds.
#[derive(Clone)]
pub(crate) struct CachedMk {
    pub mk: [u8; 32],
    pub expires_at: u64,
}

impl core::fmt::Debug for CachedMk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CachedMk")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Successful skip-ahead open.
#[derive(Debug)]
pub(crate) struct Opened {
    pub packet: PacketPlain,
    pub chain: SendChain,
    pub skipped: Vec<CachedMk>,
    pub from_cache: bool,
}

pub(crate) fn chain_key(conversation_id: &ConversationId, actor_id: &[u8]) -> Vec<u8> {
    let mut key = conversation_id.as_bytes().to_vec();
    key.extend_from_slice(actor_id);
    key
}

pub(crate) fn join(
    hmac: &dyn HmacSha256,
    conv_secret: &[u8; 32],
    sort: ConversationSort,
    actor_id: &[u8],
) -> Result<SendChain, EngineError> {
    let root_label = sort.chain_root_label().ok_or(EngineError::WrongPhase)?;
    let mut info = root_label.to_vec();
    if !sort.omits_actor_id() {
        info.extend_from_slice(actor_id);
    }
    let root = expand(hmac, &HmacSha256Key::from_bytes(*conv_secret), &info).into_bytes();
    let c = expand(
        hmac,
        &HmacSha256Key::from_bytes(root),
        sort.chain_c_label().unwrap_or(b""),
    )
    .into_bytes();
    Ok(SendChain {
        root,
        c,
        epoch: 0,
        packet_seq: 0,
    })
}

pub(crate) fn mk(hmac: &dyn HmacSha256, chain: &SendChain) -> [u8; 32] {
    labeled_expand(hmac, &chain.c, MK_LABEL, chain.epoch, chain.packet_seq)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn eph_mk(hmac: &dyn HmacSha256, chain: &SendChain) -> [u8; 32] {
    labeled_expand(hmac, &chain.c, EPH_MK_LABEL, chain.epoch, chain.packet_seq)
}

pub(crate) fn step(hmac: &dyn HmacSha256, chain: &SendChain) -> SendChain {
    let c = labeled_expand(hmac, &chain.c, STEP_LABEL, chain.epoch, chain.packet_seq);
    SendChain {
        root: chain.root,
        c,
        epoch: chain.epoch,
        packet_seq: chain.packet_seq.saturating_add(1),
    }
}

fn labeled_expand(
    hmac: &dyn HmacSha256,
    c: &[u8; 32],
    label: &[u8],
    epoch: u64,
    packet_seq: u64,
) -> [u8; 32] {
    let mut info = Vec::with_capacity(label.len() + 16);
    info.extend_from_slice(label);
    info.extend_from_slice(&epoch.to_be_bytes());
    info.extend_from_slice(&packet_seq.to_be_bytes());
    expand(hmac, &HmacSha256Key::from_bytes(*c), &info).into_bytes()
}

pub(crate) fn seal_packet(
    suite: &Suite,
    rng: &dyn Rng,
    mk_bytes: &[u8; 32],
    packet: &PacketPlain,
) -> Result<Vec<u8>, EngineError> {
    #[rustfmt::skip]
    let packed = packed_packet(suite.canonical_json(), suite.b64u(), suite.compress(), packet)?;
    let mut padded = packed;
    padded.resize(PACKET_PAD_LEN, 0);
    let rnd = rng.random32();
    let mut nonce = [0u8; PACKET_NONCE_LEN];
    nonce.copy_from_slice(&rnd.as_bytes()[..PACKET_NONCE_LEN]);
    let ct = suite.aead().seal(
        &AeadKey::from_bytes(*mk_bytes),
        &AeadNonce::from_bytes(nonce),
        b"",
        &padded,
    );
    let mut body = Vec::with_capacity(PACKET_NONCE_LEN + ct.len());
    body.extend_from_slice(&nonce);
    body.extend_from_slice(&ct);
    (body.len() == PACKET_LEN)
        .then_some(body)
        .ok_or(EngineError::MalformedPayload)
}

fn open_plain(suite: &Suite, mk_bytes: &[u8; 32], body: &[u8]) -> Result<PacketPlain, EngineError> {
    if body.len() != PACKET_LEN {
        return Err(EngineError::UnknownTag);
    }
    let nonce: [u8; PACKET_NONCE_LEN] = body[..PACKET_NONCE_LEN]
        .try_into()
        .unwrap_or([0; PACKET_NONCE_LEN]);
    let pt = suite
        .aead()
        .open(
            &AeadKey::from_bytes(*mk_bytes),
            &AeadNonce::from_bytes(nonce),
            b"",
            &body[PACKET_NONCE_LEN..],
        )
        .map_err(|_| EngineError::UnknownTag)?;
    let packed = unpad(&pt);
    let raw = suite
        .compress()
        .decompress(packed, PACKET_MAX_UNCOMPRESSED)
        .unwrap_or_default();
    let json = suite
        .canonical_json()
        .decode(&raw)
        .map_err(|_| EngineError::UnknownTag)?;
    packet_from_json(suite.b64u(), &json).map_err(|_| EngineError::UnknownTag)
}

pub(crate) fn open_skip_ahead(
    suite: &Suite,
    start: &SendChain,
    cached: &[CachedMk],
    now: u64,
    body: &[u8],
) -> Result<Opened, EngineError> {
    for entry in cached {
        if entry.expires_at > now
            && let Ok(packet) = open_plain(suite, &entry.mk, body)
        {
            return Ok(Opened {
                packet,
                chain: start.clone(),
                skipped: Vec::new(),
                from_cache: true,
            });
        }
    }
    let hmac = suite.hmac();
    let mut chain = start.clone();
    let mut skipped = Vec::new();
    for _ in 0..=SKIP_AHEAD {
        let key = mk(hmac, &chain);
        if let Ok(packet) = open_plain(suite, &key, body) {
            let next = step(hmac, &chain);
            return Ok(Opened {
                packet,
                chain: next,
                skipped,
                from_cache: false,
            });
        }
        skipped.push(CachedMk {
            mk: key,
            expires_at: now.saturating_add(MK_CACHE_SECS),
        });
        chain = step(hmac, &chain);
    }
    for de in 1..=LATER_EPOCHS {
        for seq in 0..=SKIP_AHEAD {
            let probe = SendChain {
                root: start.root,
                c: start.c,
                epoch: start.epoch.saturating_add(de),
                packet_seq: seq,
            };
            let key = mk(hmac, &probe);
            if let Ok(packet) = open_plain(suite, &key, body) {
                return Ok(Opened {
                    packet,
                    chain: step(hmac, &probe),
                    skipped: Vec::new(),
                    from_cache: false,
                });
            }
        }
    }
    Err(EngineError::UnknownTag)
}

fn largest_frag<F>(suite: &Suite, mut build: F) -> usize
where
    F: FnMut(Vec<u8>) -> PacketPlain,
{
    let mut lo = 0;
    let mut hi = PACKET_PAD_LEN;
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        let packet = build(vec![0x5a; mid]);
        match packed_packet(
            suite.canonical_json(),
            suite.b64u(),
            suite.compress(),
            &packet,
        ) {
            Ok(p) if p.len() <= PACKET_PAD_LEN => lo = mid,
            _ => hi = mid.saturating_sub(1),
        }
    }
    lo
}

pub(crate) fn fragment_body(
    suite: &Suite,
    packed_body: &[u8],
    tx_id: Tag,
    set_xor: Tag,
    start_seq: u64,
    actor_id: &[u8],
) -> Result<Vec<PacketPlain>, EngineError> {
    let mut remaining = packed_body;
    let mut packets = Vec::new();
    loop {
        if u64::try_from(packets.len()).unwrap_or(u64::MAX) >= MAX_FRAGS {
            return Err(EngineError::BodyTooLarge);
        }
        let frag_i = u64::try_from(packets.len()).unwrap_or(0);
        let packet_seq = start_seq.saturating_add(frag_i);
        let max_last = largest_frag(suite, |frag| {
            PacketPlain::TxFragLast(PacketTxFragLast {
                actor_id: actor_id.to_vec(),
                packet_seq,
                tx_id,
                frag_i,
                frag,
                set_xor,
            })
        });
        if remaining.len() <= max_last {
            packets.push(PacketPlain::TxFragLast(PacketTxFragLast {
                actor_id: actor_id.to_vec(),
                packet_seq,
                tx_id,
                frag_i,
                frag: remaining.to_vec(),
                set_xor,
            }));
            return Ok(packets);
        }
        let max_more = largest_frag(suite, |frag| {
            PacketPlain::TxFragMore(PacketTxFragMore {
                actor_id: actor_id.to_vec(),
                packet_seq,
                tx_id,
                frag_i,
                frag,
            })
        });
        if max_more == 0 {
            return Err(EngineError::BodyTooLarge);
        }
        let take = remaining.len().min(max_more);
        packets.push(PacketPlain::TxFragMore(PacketTxFragMore {
            actor_id: actor_id.to_vec(),
            packet_seq,
            tx_id,
            frag_i,
            frag: remaining[..take].to_vec(),
        }));
        remaining = &remaining[take..];
    }
}

pub(crate) fn packed_tx(suite: &Suite, body: &DurableBody) -> Vec<u8> {
    packed_durable_body(suite.canonical_json(), suite.b64u(), suite.compress(), body)
}

pub(crate) fn set_xor_for(
    txs: &std::collections::BTreeMap<[u8; 32], DurableBody>,
    conversation_id: ConversationId,
) -> Tag {
    let mut acc = [0u8; 32];
    for (id, body) in txs {
        if body.conversation_id == conversation_id {
            for (a, b) in acc.iter_mut().zip(id.iter()) {
                *a ^= *b;
            }
        }
    }
    Tag::from_bytes(acc)
}

pub(crate) fn chain_to_json(b64u: &dyn Base64Url, key: &[u8], chain: &SendChain) -> Json {
    let (cid, actor_id) = if key.len() >= 32 {
        (&key[..32], &key[32..])
    } else {
        (key, &[][..])
    };
    Json::Object(vec![
        ("conversation_id".into(), super::codec::bstr(b64u, cid)),
        ("actor_id".into(), super::codec::bstr(b64u, actor_id)),
        ("root".into(), super::codec::bstr(b64u, &chain.root)),
        ("c".into(), super::codec::bstr(b64u, &chain.c)),
        ("epoch".into(), Json::Number(chain.epoch)),
        ("packet_seq".into(), Json::Number(chain.packet_seq)),
    ])
}

pub(crate) fn chain_from_json(
    b64u: &dyn Base64Url,
    value: &Json,
) -> Result<(Vec<u8>, SendChain), EngineError> {
    let Json::Object(members) = value else {
        return Err(EngineError::MalformedPersist);
    };
    let get = |k: &str| members.iter().find(|(n, _)| n == k).map(|(_, v)| v);
    let cid = decode_bstr(
        b64u,
        get("conversation_id").ok_or(EngineError::MalformedPersist)?,
    )?;
    if cid.len() != 32 {
        return Err(EngineError::MalformedPersist);
    }
    let actor_id = decode_bstr(b64u, get("actor_id").ok_or(EngineError::MalformedPersist)?)?;
    let root = decode32(b64u, get("root").ok_or(EngineError::MalformedPersist)?)?;
    let c = decode32(b64u, get("c").ok_or(EngineError::MalformedPersist)?)?;
    let Json::Number(epoch) = get("epoch").ok_or(EngineError::MalformedPersist)? else {
        return Err(EngineError::MalformedPersist);
    };
    let Json::Number(packet_seq) = get("packet_seq").ok_or(EngineError::MalformedPersist)? else {
        return Err(EngineError::MalformedPersist);
    };
    let mut key = cid;
    key.extend_from_slice(&actor_id);
    Ok((
        key,
        SendChain {
            root,
            c,
            epoch: *epoch,
            packet_seq: *packet_seq,
        },
    ))
}

fn decode_bstr(b64u: &dyn Base64Url, value: &Json) -> Result<Vec<u8>, EngineError> {
    let Json::String(s) = value else {
        return Err(EngineError::MalformedPersist);
    };
    b64u.decode(s).map_err(|_| EngineError::MalformedPersist)
}

fn decode32(b64u: &dyn Base64Url, value: &Json) -> Result<[u8; 32], EngineError> {
    decode_bstr(b64u, value)?
        .try_into()
        .map_err(|_| EngineError::MalformedPersist)
}

#[cfg(test)]
mod tests {
    use super::{
        CachedMk, ConversationSort, EPH_MK_LABEL, LATER_EPOCHS, MAX_FRAGS, MK_CACHE_SECS, MK_LABEL,
        PACKET_LEN, PACKET_NONCE_LEN, PACKET_PAD_LEN, SKIP_AHEAD, STEP_LABEL, chain_from_json,
        chain_key, chain_to_json, eph_mk, fragment_body, join, mk, open_skip_ahead, seal_packet,
        set_xor_for, step,
    };
    use crate::protocol::v1::fixtures::{CounterRng, test_suite};
    use crate::protocol::v1::payload::{
        DurableBody, Hlc, PacketPlain, PacketTxFragLast, TxPayload,
    };
    use crate::protocol::v1::{ConversationId, EngineError, Json, Tag};
    use std::collections::BTreeMap;

    fn suite() -> crate::protocol::v1::Suite {
        test_suite()
    }

    #[test]
    fn handshake_join_omits_actor_id() {
        let s = suite();
        let secret = [7u8; 32];
        let a = join(s.hmac(), &secret, ConversationSort::HandshakeDm, &[]).expect("a");
        let b = join(s.hmac(), &secret, ConversationSort::HandshakeDm, &[1u8; 32]).expect("b");
        assert_eq!(a.root, b.root);
        assert_eq!(a.c, b.c);
        let dm = join(
            s.hmac(),
            &secret,
            ConversationSort::DirectMessage,
            &[1u8; 32],
        )
        .expect("dm");
        assert_ne!(a.root, dm.root);
        let dm2 = join(
            s.hmac(),
            &secret,
            ConversationSort::DirectMessage,
            &[2u8; 32],
        )
        .expect("dm2");
        assert_ne!(dm.root, dm2.root);
        assert!(join(s.hmac(), &secret, ConversationSort::Engine, &[]).is_err());
        assert_eq!(
            join(s.hmac(), &secret, ConversationSort::HandshakeSync, &[])
                .expect("sy")
                .epoch,
            0
        );
        assert_eq!(
            join(s.hmac(), &secret, ConversationSort::Group, &[3u8; 32])
                .expect("g")
                .packet_seq,
            0
        );
        assert_eq!(
            join(
                s.hmac(),
                &secret,
                ConversationSort::Synchronization,
                &[4u8; 32]
            )
            .expect("sc")
            .epoch,
            0
        );
    }

    #[test]
    fn step_changes_c_and_seq() {
        let s = suite();
        let chain = join(s.hmac(), &[9u8; 32], ConversationSort::HandshakeDm, &[]).expect("j");
        let mk0 = mk(s.hmac(), &chain);
        let e0 = eph_mk(s.hmac(), &chain);
        assert_ne!(mk0, e0);
        let next = step(s.hmac(), &chain);
        assert_eq!(next.packet_seq, 1);
        assert_ne!(next.c, chain.c);
        assert_eq!(next.root, chain.root);
        assert!(format!("{:?}", chain).contains("SendChain"));
        let _ = MK_LABEL;
        let _ = STEP_LABEL;
        let _ = EPH_MK_LABEL;
        let _ = SKIP_AHEAD;
        let _ = LATER_EPOCHS;
        let _ = MK_CACHE_SECS;
        let _ = MAX_FRAGS;
    }

    #[test]
    fn seal_open_and_skip_ahead() {
        let s = suite();
        let rng = CounterRng::new();
        let mut chain = join(s.hmac(), &[3u8; 32], ConversationSort::HandshakeDm, &[]).expect("j");
        let p0 = PacketPlain::TxFragLast(PacketTxFragLast {
            actor_id: Vec::new(),
            packet_seq: 0,
            tx_id: Tag::from_bytes([1; 32]),
            frag_i: 0,
            frag: b"one".to_vec(),
            set_xor: Tag::from_bytes([1; 32]),
        });
        let b0 = seal_packet(&s, &rng, &mk(s.hmac(), &chain), &p0).expect("s0");
        assert_eq!(b0.len(), PACKET_LEN);
        chain = step(s.hmac(), &chain);
        let p1 = PacketPlain::TxFragLast(PacketTxFragLast {
            actor_id: Vec::new(),
            packet_seq: 1,
            tx_id: Tag::from_bytes([2; 32]),
            frag_i: 0,
            frag: b"two".to_vec(),
            set_xor: Tag::from_bytes([3; 32]),
        });
        let b1 = seal_packet(&s, &rng, &mk(s.hmac(), &chain), &p1).expect("s1");
        let start = join(s.hmac(), &[3u8; 32], ConversationSort::HandshakeDm, &[]).expect("r");
        let opened0 = open_skip_ahead(&s, &start, &[], 10, &b0).expect("o0");
        assert!(!opened0.from_cache);
        assert_eq!(opened0.packet, p0);
        assert_eq!(opened0.chain.packet_seq, 1);
        let opened1 = open_skip_ahead(&s, &start, &[], 10, &b1).expect("o1");
        assert_eq!(opened1.skipped.len(), 1);
        assert_eq!(opened1.packet, p1);
        let cached = open_skip_ahead(&s, &start, &opened1.skipped, 10, &b0).expect("cache");
        assert!(cached.from_cache);
        let late = open_skip_ahead(&s, &start, &opened1.skipped, 10 + MK_CACHE_SECS, &b0)
            .expect("expired cache still skip-ahead");
        assert!(!late.from_cache);
        assert_eq!(
            open_skip_ahead(&s, &start, &[], 10, &[0u8; PACKET_LEN]).unwrap_err(),
            EngineError::UnknownTag
        );
        assert_eq!(
            open_skip_ahead(&s, &start, &[], 10, &[1, 2, 3]).unwrap_err(),
            EngineError::UnknownTag
        );
        let expired = CachedMk {
            mk: opened1.skipped[0].mk,
            expires_at: 10,
        };
        assert!(format!("{:?}", expired).contains("CachedMk"));
        let late_chain = super::SendChain {
            root: start.root,
            c: start.c,
            epoch: 1,
            packet_seq: 0,
        };
        let b_late = seal_packet(&s, &rng, &mk(s.hmac(), &late_chain), &p0).expect("slate");
        let opened_late = open_skip_ahead(&s, &start, &[], 10, &b_late).expect("ol");
        assert!(!opened_late.from_cache);
        let mk0 = mk(s.hmac(), &start);
        let nonce = [9u8; PACKET_NONCE_LEN];
        let mut ct = vec![0u8; PACKET_PAD_LEN];
        for (i, byte) in ct.iter_mut().enumerate() {
            *byte = mk0[i % 32] ^ nonce[i % PACKET_NONCE_LEN];
        }
        ct.extend_from_slice(&mk0[..16]);
        let mut zeros = nonce.to_vec();
        zeros.extend_from_slice(&ct);
        assert_eq!(
            open_skip_ahead(&s, &start, &[], 10, &zeros).unwrap_err(),
            EngineError::UnknownTag
        );
    }

    #[test]
    fn fragments_and_fold_json() {
        let s = suite();
        let tx_id = Tag::from_bytes([9; 32]);
        let xor = Tag::from_bytes([9; 32]);
        let one = fragment_body(&s, b"hi", tx_id, xor, 0, &[]).expect("one");
        assert_eq!(one.len(), 1);
        let big = vec![7u8; 8_000];
        let many = fragment_body(&s, &big, tx_id, xor, 0, &[]).expect("many");
        assert!(many.len() > 1);
        assert!(many.len() <= MAX_FRAGS as usize);
        let huge = vec![7u8; 200_000];
        assert_eq!(
            fragment_body(&s, &huge, tx_id, xor, 0, &[]).unwrap_err(),
            EngineError::BodyTooLarge
        );
        let cid = ConversationId::from_bytes([4; 32]);
        let mut txs = BTreeMap::new();
        txs.insert(
            [9; 32],
            DurableBody {
                conversation_id: cid,
                hlc: Hlc {
                    wall_ms: 0,
                    counter: 0,
                },
                payload: TxPayload::Confirm,
            },
        );
        assert_eq!(set_xor_for(&txs, cid), tx_id);
        let key = chain_key(&cid, &[]);
        let chain = join(s.hmac(), &[1u8; 32], ConversationSort::HandshakeDm, &[]).expect("j");
        let json = chain_to_json(s.b64u(), &key, &chain);
        let (k2, c2) = chain_from_json(s.b64u(), &json).expect("parse");
        assert_eq!(k2, key);
        assert_eq!(c2.root, chain.root);
        assert_eq!(c2.packet_seq, 0);
        assert!(chain_from_json(s.b64u(), &Json::Null).is_err());
        assert!(chain_from_json(s.b64u(), &Json::Object(vec![])).is_err());
        assert!(
            chain_from_json(
                s.b64u(),
                &Json::Object(vec![("conversation_id".into(), Json::Number(1))])
            )
            .is_err()
        );
        let short = Json::Object(vec![
            (
                "conversation_id".into(),
                super::super::codec::bstr(s.b64u(), &[1, 2]),
            ),
            ("actor_id".into(), super::super::codec::bstr(s.b64u(), &[])),
            ("root".into(), super::super::codec::bstr(s.b64u(), &[0; 32])),
            ("c".into(), super::super::codec::bstr(s.b64u(), &[0; 32])),
            ("epoch".into(), Json::Number(0)),
            ("packet_seq".into(), Json::Number(0)),
        ]);
        assert!(chain_from_json(s.b64u(), &short).is_err());
        let short_root = Json::Object(vec![
            (
                "conversation_id".into(),
                super::super::codec::bstr(s.b64u(), &[4; 32]),
            ),
            ("actor_id".into(), super::super::codec::bstr(s.b64u(), &[])),
            ("root".into(), super::super::codec::bstr(s.b64u(), &[0; 8])),
            ("c".into(), super::super::codec::bstr(s.b64u(), &[0; 32])),
            ("epoch".into(), Json::Number(0)),
            ("packet_seq".into(), Json::Number(0)),
        ]);
        assert!(chain_from_json(s.b64u(), &short_root).is_err());
        let bad_epoch = Json::Object(vec![
            (
                "conversation_id".into(),
                super::super::codec::bstr(s.b64u(), &[4; 32]),
            ),
            ("actor_id".into(), super::super::codec::bstr(s.b64u(), &[])),
            ("root".into(), super::super::codec::bstr(s.b64u(), &[0; 32])),
            ("c".into(), super::super::codec::bstr(s.b64u(), &[0; 32])),
            ("epoch".into(), Json::Bool(true)),
            ("packet_seq".into(), Json::Number(0)),
        ]);
        assert!(chain_from_json(s.b64u(), &bad_epoch).is_err());
        let bad_seq = Json::Object(vec![
            (
                "conversation_id".into(),
                super::super::codec::bstr(s.b64u(), &[4; 32]),
            ),
            ("actor_id".into(), super::super::codec::bstr(s.b64u(), &[])),
            ("root".into(), super::super::codec::bstr(s.b64u(), &[0; 32])),
            ("c".into(), super::super::codec::bstr(s.b64u(), &[0; 32])),
            ("epoch".into(), Json::Number(0)),
            ("packet_seq".into(), Json::Bool(true)),
        ]);
        assert!(chain_from_json(s.b64u(), &bad_seq).is_err());
        let tiny = chain_to_json(s.b64u(), &[1, 2, 3], &chain);
        assert!(chain_from_json(s.b64u(), &tiny).is_err());
        let huge_actor = fragment_body(&s, b"hi", tx_id, xor, 0, &[0u8; 400]);
        assert!(huge_actor.is_err());
    }
}
