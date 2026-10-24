//! One direction of packet keys for a conversation.
//!
//! `join` turns the conversation secret into a root and a stepping key. Each
//! packet is sealed under a message key taken from the stepping key, and
//! `step` then replaces that stepping key so the next packet cannot reuse it.
//! The root stays until `mix` folds in a shared secret from a key wrap and
//! starts the next epoch. A receiver who has fallen behind tries a bounded
//! run of later message keys, and keeps the ones it skipped so a late packet
//! can still open.

use super::codec::{packed_durable_body, packed_packet, packet_from_json};
use super::hmac::{HmacSha256, HmacSha256Key, expand};
use super::payload::{
    ConversationSort, DurableBody, PACKET_LEN, PACKET_MAX_UNCOMPRESSED, PACKET_NONCE_LEN,
    PACKET_PAD_LEN, PacketPlain, PacketTxFragLast, PacketTxFragMore, unpad,
};
use super::{
    Actor, AeadKey, AeadNonce, Base64Url, ConversationId, EngineError, Json, PacketEpoch,
    PacketSeq, Secret, Suite, Tag, UnixSeconds,
};
use crate::protocol::Rng;

macro_rules! role32 {
    ($name:ident, $debug:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Eq)]
        pub(crate) struct $name([u8; 32]);

        impl $name {
            /// Wrap 32 bytes that already have this role.
            #[must_use]
            pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Raw bytes for an expand input, an AEAD key, or a fold field.
            #[must_use]
            pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                crate::protocol::bytes32::ct_eq(&self.0, &other.0)
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str($debug)
            }
        }
    };
}

role32!(
    ChainRoot,
    "ChainRoot(..)",
    "Long-lived key for one sending direction. Stepping leaves it in place. Mixing replaces it."
);
role32!(
    ChainKey,
    "ChainKey(..)",
    "Stepping key. The message key for the current packet is derived from it, and step then replaces it."
);
role32!(
    MessageKey,
    "MessageKey(..)",
    "AEAD key for one durable 512-byte packet."
);
role32!(
    EphMessageKey,
    "EphMessageKey(..)",
    "AEAD key for the ephemeral copy of one packet. It is derived beside the durable message key, from the same stepping key, under its own label."
);

/// Bytes a packet sealer can use as an AEAD key.
pub(crate) trait PacketAeadKey {
    /// Key bytes for AES-256-GCM.
    fn as_aead_bytes(&self) -> &[u8; 32];
}

impl PacketAeadKey for MessageKey {
    fn as_aead_bytes(&self) -> &[u8; 32] {
        self.as_bytes()
    }
}

impl PacketAeadKey for EphMessageKey {
    fn as_aead_bytes(&self) -> &[u8; 32] {
        self.as_bytes()
    }
}

pub(crate) const MK_LABEL: &[u8] = b"chuchotez/1/packet-mk";
pub(crate) const STEP_LABEL: &[u8] = b"chuchotez/1/packet-step";
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const EPH_MK_LABEL: &[u8] = b"chuchotez/1/eph-mk";
pub(crate) const SKIP_AHEAD: u64 = 50;
pub(crate) const LATER_EPOCHS: u64 = 8;
pub(crate) const MK_CACHE_SECS: u64 = 172_800;
pub(crate) const MAX_FRAGS: u64 = 64;

/// Root, stepping key, and how far this direction has sent.
#[derive(Clone)]
pub(crate) struct SendChain {
    pub root: ChainRoot,
    pub c: ChainKey,
    pub epoch: PacketEpoch,
    pub packet_seq: PacketSeq,
}

impl core::fmt::Debug for SendChain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SendChain")
            .field("epoch", &self.epoch)
            .field("packet_seq", &self.packet_seq)
            .finish_non_exhaustive()
    }
}

/// A message key we derived while looking ahead, kept until `expires_at`.
///
/// The receiver stores it so a packet that arrives out of order can open
/// without walking the chain again. `tx_id` is filled in once the packet
/// that used this key has been reassembled.
#[derive(Clone)]
pub(crate) struct CachedMk {
    pub mk: MessageKey,
    pub expires_at: UnixSeconds,
    pub tx_id: Option<Tag>,
}

impl core::fmt::Debug for CachedMk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CachedMk")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Successful skip-ahead open.
pub(crate) struct Opened {
    pub packet: PacketPlain,
    pub chain: SendChain,
    pub skipped: Vec<CachedMk>,
    pub from_cache: bool,
    pub mk: MessageKey,
}

impl core::fmt::Debug for Opened {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Opened")
            .field("from_cache", &self.from_cache)
            .finish_non_exhaustive()
    }
}

/// Start a sending chain from the conversation secret.
///
/// Handshake chains leave the actor out of the derivation, because the
/// invitee does not know the inviter's signing key yet and must be able to
/// reach the same root from the ticket secret alone. An established
/// conversation mixes the actor in, so two peers on the same secret still
/// get distinct chains.
pub(crate) fn join(
    hmac: &dyn HmacSha256,
    conv_secret: &Secret,
    sort: ConversationSort,
    actor_id: &[u8],
) -> Result<SendChain, EngineError> {
    let root_label = sort.chain_root_label().ok_or(EngineError::WrongPhase)?;
    let mut info = root_label.to_vec();
    if !sort.omits_actor_id() {
        info.extend_from_slice(actor_id);
    }
    let root = ChainRoot::from_bytes(expand_mac(hmac, conv_secret.as_bytes(), &info));
    let c = ChainKey::from_bytes(expand_mac(
        hmac,
        root.as_bytes(),
        sort.chain_c_label().unwrap_or(b""),
    ));
    Ok(SendChain {
        root,
        c,
        epoch: PacketEpoch::from_u64(0),
        packet_seq: PacketSeq::from_u64(0),
    })
}

/// Durable message key for the packet this chain is about to send or open.
pub(crate) fn mk(hmac: &dyn HmacSha256, chain: &SendChain) -> MessageKey {
    MessageKey::from_bytes(labeled_expand(
        hmac,
        &chain.c,
        MK_LABEL,
        chain.epoch.as_u64(),
        chain.packet_seq.as_u64(),
    ))
}

/// Ephemeral message key at the same chain position as [`mk`].
///
/// The live path seals a copy under this key. It is a different key from the
/// durable one, so a relay that sees the ephemeral packet cannot open the
/// durable copy, and the other way around.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn eph_mk(hmac: &dyn HmacSha256, chain: &SendChain) -> EphMessageKey {
    EphMessageKey::from_bytes(labeled_expand(
        hmac,
        &chain.c,
        EPH_MK_LABEL,
        chain.epoch.as_u64(),
        chain.packet_seq.as_u64(),
    ))
}

/// Fold a shared secret from a key wrap into the chain and start the next epoch.
///
/// After a mix, earlier message keys cannot open later packets. The packet
/// sequence restarts because the new epoch is a new chain.
pub(crate) fn mix(
    hmac: &dyn HmacSha256,
    chain: &SendChain,
    sort: ConversationSort,
    shared: &Secret,
) -> Result<SendChain, EngineError> {
    let mix_label = sort.mix_label().ok_or(EngineError::WrongPhase)?;
    let c_label = sort.chain_c_label().ok_or(EngineError::WrongPhase)?;
    let mut info = mix_label.to_vec();
    info.extend_from_slice(shared.as_bytes());
    let root = ChainRoot::from_bytes(expand_mac(hmac, chain.root.as_bytes(), &info));
    let c = ChainKey::from_bytes(expand_mac(hmac, root.as_bytes(), c_label));
    Ok(SendChain {
        root,
        c,
        epoch: chain.epoch.saturating_add(1),
        packet_seq: PacketSeq::from_u64(0),
    })
}

/// Advance to the next packet on this epoch.
///
/// The root stays. The stepping key is replaced, and the sequence moves by
/// one, so the message key just used cannot seal another packet.
pub(crate) fn step(hmac: &dyn HmacSha256, chain: &SendChain) -> SendChain {
    let c = ChainKey::from_bytes(labeled_expand(
        hmac,
        &chain.c,
        STEP_LABEL,
        chain.epoch.as_u64(),
        chain.packet_seq.as_u64(),
    ));
    SendChain {
        root: chain.root,
        c,
        epoch: chain.epoch,
        packet_seq: chain.packet_seq.saturating_add(1),
    }
}

/// Derive the next chain value from the stepping key, the role label, and this packet's position.
///
/// Epoch and sequence are part of the derivation so two positions on the same
/// stepping key still produce different outputs.
fn labeled_expand(
    hmac: &dyn HmacSha256,
    c: &ChainKey,
    label: &[u8],
    epoch: u64,
    packet_seq: u64,
) -> [u8; 32] {
    let mut info = Vec::with_capacity(label.len() + 16);
    info.extend_from_slice(label);
    info.extend_from_slice(&epoch.to_be_bytes());
    info.extend_from_slice(&packet_seq.to_be_bytes());
    expand_mac(hmac, c.as_bytes(), &info)
}

fn expand_mac(hmac: &dyn HmacSha256, key: &[u8; 32], info: &[u8]) -> [u8; 32] {
    expand(hmac, &HmacSha256Key::from_bytes(*key), info).into_bytes()
}

/// Seal one packet to a fixed 512-byte body.
///
/// The plaintext is padded out to the same length every time, so a relay
/// learns the packet size and not how much of it was the message. The AEAD
/// associated data is empty because the key itself was derived under a label
/// that already names this use.
pub(crate) fn seal_packet(
    suite: &Suite,
    rng: &dyn Rng,
    key: &impl PacketAeadKey,
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
        &AeadKey::from_bytes(*key.as_aead_bytes()),
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

/// Open one 512-byte body with a message key.
///
/// A body that does not decrypt is `UnknownTag`. The caller treats that as
/// "this was not the key", and tries the next one, rather than as a broken
/// conversation.
pub(crate) fn open_plain(
    suite: &Suite,
    key: &impl PacketAeadKey,
    body: &[u8],
) -> Result<PacketPlain, EngineError> {
    if body.len() != PACKET_LEN {
        return Err(EngineError::UnknownTag);
    }
    let nonce: [u8; PACKET_NONCE_LEN] = body[..PACKET_NONCE_LEN]
        .try_into()
        .unwrap_or([0; PACKET_NONCE_LEN]);
    let pt = suite
        .aead()
        .open(
            &AeadKey::from_bytes(*key.as_aead_bytes()),
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

/// Open a packet that may be ahead of the chain we have stored.
///
/// Cached keys are tried first, so a reordered packet does not make us walk
/// the chain a second time. Then we try the next 50 positions on this epoch.
/// Each key that fails is remembered until it expires. If this epoch does not
/// open the body, we try the next few epoch numbers with the stepping key we
/// still hold. The walk is bounded so a garbage packet cannot force unbounded
/// work.
pub(crate) fn open_skip_ahead(
    suite: &Suite,
    start: &SendChain,
    cached: &[CachedMk],
    now: u64,
    body: &[u8],
) -> Result<Opened, EngineError> {
    // A key we already derived can open a late packet without another walk.
    for entry in cached {
        if entry.expires_at.as_u64() > now
            && let Ok(packet) = open_plain(suite, &entry.mk, body)
        {
            return Ok(Opened {
                packet,
                chain: start.clone(),
                skipped: Vec::new(),
                from_cache: true,
                mk: entry.mk,
            });
        }
    }
    let hmac = suite.hmac();
    let mut chain = start.clone();
    let mut skipped = Vec::new();
    // The sender may be up to 50 packets ahead. Stop there so a wrong body cannot run forever.
    for _ in 0..=SKIP_AHEAD {
        let key = mk(hmac, &chain);
        if let Ok(packet) = open_plain(suite, &key, body) {
            let next = step(hmac, &chain);
            return Ok(Opened {
                packet,
                chain: next,
                skipped,
                from_cache: false,
                mk: key,
            });
        }
        skipped.push(CachedMk {
            mk: key,
            expires_at: UnixSeconds::from_u64(now.saturating_add(MK_CACHE_SECS)),
            tx_id: None,
        });
        chain = step(hmac, &chain);
    }
    // Same stepping key, labeled with a later epoch. A mix this device already
    // computed is tried by the caller before this search.
    for de in 1..=LATER_EPOCHS {
        for seq in 0..=SKIP_AHEAD {
            let probe = SendChain {
                root: start.root,
                c: start.c,
                epoch: start.epoch.saturating_add(de),
                packet_seq: PacketSeq::from_u64(seq),
            };
            let key = mk(hmac, &probe);
            if let Ok(packet) = open_plain(suite, &key, body) {
                return Ok(Opened {
                    packet,
                    chain: step(hmac, &probe),
                    skipped: Vec::new(),
                    from_cache: false,
                    mk: key,
                });
            }
        }
    }
    Err(EngineError::UnknownTag)
}

/// Open a packet, preferring a chain this device has already mixed.
///
/// A mix changes the stepping key, so the skip-ahead walk on the old chain
/// cannot see those packets. The caller passes the mixed chain when it has one.
pub(crate) fn open_at(
    suite: &Suite,
    start: &SendChain,
    mixed: Option<&SendChain>,
    cached: &[CachedMk],
    now: u64,
    body: &[u8],
) -> Result<Opened, EngineError> {
    if let Some(mixed) = mixed {
        let key = mk(suite.hmac(), mixed);
        if let Ok(packet) = open_plain(suite, &key, body) {
            return Ok(Opened {
                packet,
                chain: step(suite.hmac(), mixed),
                skipped: Vec::new(),
                from_cache: false,
                mk: key,
            });
        }
    }
    open_skip_ahead(suite, start, cached, now, body)
}

/// Largest fragment that still fits in one packet after JSON and compression.
///
/// Those encodings add bytes around the raw fragment, so the budget is not a
/// fixed count of payload bytes. The search finds the biggest fragment this
/// packet shape can carry.
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

/// Cut the next fragment off a durable body that may be larger than one packet.
///
/// The last fragment carries the set-XOR, which the receiver checks once the
/// body is complete. Earlier fragments omit it. A body that would need more
/// than 64 fragments is refused.
pub(crate) fn next_fragment(
    suite: &Suite,
    remaining: &[u8],
    tx_id: Tag,
    set_xor: Tag,
    packet_seq: u64,
    frag_i: u64,
    actor_id: &[u8],
) -> Result<(PacketPlain, usize), EngineError> {
    if frag_i >= MAX_FRAGS {
        return Err(EngineError::BodyTooLarge);
    }
    // Last fragments carry the set-XOR, so they have less room for payload than earlier ones.
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
        let n = remaining.len();
        return Ok((
            PacketPlain::TxFragLast(PacketTxFragLast {
                actor_id: actor_id.to_vec(),
                packet_seq,
                tx_id,
                frag_i,
                frag: remaining.to_vec(),
                set_xor,
            }),
            n,
        ));
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
    Ok((
        PacketPlain::TxFragMore(PacketTxFragMore {
            actor_id: actor_id.to_vec(),
            packet_seq,
            tx_id,
            frag_i,
            frag: remaining[..take].to_vec(),
        }),
        take,
    ))
}

/// Split a packed durable body into the packets that will carry it.
#[cfg_attr(not(test), allow(dead_code))]
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
        let frag_i = u64::try_from(packets.len()).unwrap_or(u64::MAX);
        let packet_seq = start_seq.saturating_add(u64::try_from(packets.len()).unwrap_or(0));
        let (packet, n) = next_fragment(
            suite, remaining, tx_id, set_xor, packet_seq, frag_i, actor_id,
        )?;
        let finished = matches!(packet, PacketPlain::TxFragLast(_));
        remaining = &remaining[n..];
        packets.push(packet);
        if finished {
            return Ok(packets);
        }
    }
}

/// Canonical bytes of one durable transaction, before they are split into packets.
pub(crate) fn packed_tx(suite: &Suite, body: &DurableBody) -> Vec<u8> {
    packed_durable_body(suite.canonical_json(), suite.b64u(), suite.compress(), body)
}

/// Fingerprint of the transaction ids stored for one conversation.
///
/// Each id is XOR-ed in. One missing or extra id changes the result, which
/// is how the two sides notice their sets disagree without sending the list.
pub(crate) fn set_xor_for(
    txs: impl IntoIterator<Item = (Tag, DurableBody)>,
    conversation_id: ConversationId,
) -> Tag {
    let mut acc = [0u8; 32];
    for (id, body) in txs {
        if body.conversation_id == conversation_id {
            for (a, b) in acc.iter_mut().zip(id.as_bytes().iter()) {
                *a ^= *b;
            }
        }
    }
    Tag::from_bytes(acc)
}

/// Fold one sending chain. The root and stepping key are stored so a reload
/// can keep sending and opening without deriving the chain from scratch.
pub(crate) fn chain_to_json(
    b64u: &dyn Base64Url,
    conversation_id: ConversationId,
    actor_id: &Actor,
    chain: &SendChain,
) -> Json {
    Json::Object(vec![
        (
            "conversation_id".into(),
            super::codec::bstr(b64u, conversation_id.as_bytes()),
        ),
        (
            "actor_id".into(),
            super::codec::bstr(b64u, actor_id.as_bytes()),
        ),
        ("actor_role".into(), Json::String(actor_id.role().into())),
        (
            "root".into(),
            super::codec::bstr(b64u, chain.root.as_bytes()),
        ),
        ("c".into(), super::codec::bstr(b64u, chain.c.as_bytes())),
        ("epoch".into(), Json::Number(chain.epoch.as_u64())),
        ("packet_seq".into(), Json::Number(chain.packet_seq.as_u64())),
    ])
}

/// Restore a sending chain from a fold. A field that is not 32 bytes is a
/// damaged snapshot.
pub(crate) fn chain_from_json(
    b64u: &dyn Base64Url,
    value: &Json,
) -> Result<(ConversationId, Actor, SendChain), EngineError> {
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
    let role = match get("actor_role") {
        Some(Json::String(role)) => Some(role.as_str()),
        Some(_) => return Err(EngineError::MalformedPersist),
        None => None,
    };
    #[rustfmt::skip]
    let root = ChainRoot::from_bytes(decode32(b64u, get("root").ok_or(EngineError::MalformedPersist)?)?);
    #[rustfmt::skip]
    let c = ChainKey::from_bytes(decode32(b64u, get("c").ok_or(EngineError::MalformedPersist)?)?);
    let Json::Number(epoch) = get("epoch").ok_or(EngineError::MalformedPersist)? else {
        return Err(EngineError::MalformedPersist);
    };
    let Json::Number(packet_seq) = get("packet_seq").ok_or(EngineError::MalformedPersist)? else {
        return Err(EngineError::MalformedPersist);
    };
    let cid =
        ConversationId::from_bytes(cid.try_into().map_err(|_| EngineError::MalformedPersist)?);
    Ok((
        cid,
        Actor::from_stored(role, actor_id).ok_or(EngineError::MalformedPersist)?,
        SendChain {
            root,
            c,
            epoch: PacketEpoch::from_u64(*epoch),
            packet_seq: PacketSeq::from_u64(*packet_seq),
        },
    ))
}

/// Read one base64url string from a fold object.
fn decode_bstr(b64u: &dyn Base64Url, value: &Json) -> Result<Vec<u8>, EngineError> {
    let Json::String(s) = value else {
        return Err(EngineError::MalformedPersist);
    };
    b64u.decode(s).map_err(|_| EngineError::MalformedPersist)
}

/// Read a 32-byte fold field. A short or long value is a damaged snapshot.
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
        chain_to_json, eph_mk, fragment_body, join, mix, mk, next_fragment, open_at,
        open_skip_ahead, seal_packet, set_xor_for, step,
    };
    use crate::protocol::v1::fixtures::{CounterRng, test_suite};
    use crate::protocol::v1::payload::{
        DurableBody, Hlc, PacketPlain, PacketTxFragLast, PacketXorAck, TxPayload,
    };
    use crate::protocol::v1::{Actor, PacketEpoch, PacketSeq, Secret, UnixSeconds};
    use crate::protocol::v1::{ConversationId, EngineError, Json, Tag};
    use std::collections::BTreeMap;

    fn suite() -> crate::protocol::v1::Suite {
        test_suite()
    }

    #[test]
    fn handshake_join_omits_actor_id() {
        let s = suite();
        let secret = Secret::from_bytes([7; 32]);
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
            PacketEpoch::from_u64(0)
        );
        assert_eq!(
            join(s.hmac(), &secret, ConversationSort::Group, &[3u8; 32])
                .expect("g")
                .packet_seq,
            PacketSeq::from_u64(0)
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
            PacketEpoch::from_u64(0)
        );
    }

    #[test]
    fn step_changes_c_and_seq() {
        let s = suite();
        let chain = join(
            s.hmac(),
            &Secret::from_bytes([9; 32]),
            ConversationSort::HandshakeDm,
            &[],
        )
        .expect("j");
        let mk0 = mk(s.hmac(), &chain);
        let e0 = eph_mk(s.hmac(), &chain);
        assert_ne!(mk0.as_bytes(), e0.as_bytes());
        let next = step(s.hmac(), &chain);
        assert_eq!(next.packet_seq, PacketSeq::from_u64(1));
        assert_ne!(next.c, chain.c);
        assert_eq!(next.root, chain.root);
        assert!(format!("{:?}", chain).contains("SendChain"));
        let _ = format!("{:?}", chain.root);
        let _ = format!("{:?}", chain.c);
        let _ = format!("{mk0:?}");
        let _ = format!("{e0:?}");
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
        let mut chain = join(
            s.hmac(),
            &Secret::from_bytes([3; 32]),
            ConversationSort::HandshakeDm,
            &[],
        )
        .expect("j");
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
        let start = join(
            s.hmac(),
            &Secret::from_bytes([3; 32]),
            ConversationSort::HandshakeDm,
            &[],
        )
        .expect("r");
        let opened0 = open_skip_ahead(&s, &start, &[], 10, &b0).expect("o0");
        let _ = format!("{opened0:?}");
        assert!(!opened0.from_cache);
        assert_eq!(opened0.packet, p0);
        assert_eq!(opened0.chain.packet_seq, PacketSeq::from_u64(1));
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
            expires_at: UnixSeconds::from_u64(10),
            tx_id: None,
        };
        assert!(format!("{:?}", expired).contains("CachedMk"));
        let late_chain = super::SendChain {
            root: start.root,
            c: start.c,
            epoch: PacketEpoch::from_u64(1),
            packet_seq: PacketSeq::from_u64(0),
        };
        let b_late = seal_packet(&s, &rng, &mk(s.hmac(), &late_chain), &p0).expect("slate");
        let opened_late = open_skip_ahead(&s, &start, &[], 10, &b_late).expect("ol");
        assert!(!opened_late.from_cache);
        let mk0 = mk(s.hmac(), &start);
        let nonce = [9u8; PACKET_NONCE_LEN];
        let mut ct = vec![0u8; PACKET_PAD_LEN];
        for (i, byte) in ct.iter_mut().enumerate() {
            *byte = mk0.as_bytes()[i % 32] ^ nonce[i % PACKET_NONCE_LEN];
        }
        ct.extend_from_slice(&mk0.as_bytes()[..16]);
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
            tx_id,
            DurableBody {
                conversation_id: cid,
                hlc: Hlc {
                    wall_ms: 0,
                    counter: 0,
                },
                payload: TxPayload::Confirm,
            },
        );
        assert_eq!(set_xor_for(txs, cid), tx_id);
        let chain = join(
            s.hmac(),
            &Secret::from_bytes([1; 32]),
            ConversationSort::HandshakeDm,
            &[],
        )
        .expect("j");
        let json = chain_to_json(s.b64u(), cid, &Actor::handshake(), &chain);
        let (cid2, actor, c2) = chain_from_json(s.b64u(), &json).expect("parse");
        assert_eq!(cid2, cid);
        assert_eq!(actor, Actor::handshake());
        let bad_role = Json::Object(vec![
            (
                "conversation_id".into(),
                Json::String(s.b64u().encode(cid.as_bytes())),
            ),
            ("actor_id".into(), Json::String(s.b64u().encode(&[]))),
            ("actor_role".into(), Json::Number(1)),
        ]);
        assert!(chain_from_json(s.b64u(), &bad_role).is_err());
        assert_eq!(c2.root, chain.root);
        assert_eq!(c2.packet_seq, PacketSeq::from_u64(0));
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
        let huge_actor = fragment_body(&s, b"hi", tx_id, xor, 0, &[0u8; 400]);
        assert!(huge_actor.is_err());
        let rng = CounterRng::new();
        assert!(next_fragment(&s, b"hi", tx_id, xor, 0, MAX_FRAGS, &[]).is_err());
        let empty = fragment_body(&s, b"", tx_id, xor, 0, &[]).expect("empty");
        assert!(matches!(empty[0], PacketPlain::TxFragLast(_)));
        let mixed = mix(
            s.hmac(),
            &chain,
            ConversationSort::HandshakeDm,
            &Secret::from_bytes([2; 32]),
        )
        .expect("mix");
        assert_eq!(mixed.epoch, PacketEpoch::from_u64(1));
        assert_eq!(mixed.packet_seq, PacketSeq::from_u64(0));
        assert_ne!(mixed.root, chain.root);
        assert!(
            mix(
                s.hmac(),
                &chain,
                ConversationSort::Engine,
                &Secret::from_bytes([2; 32])
            )
            .is_err()
        );
        let plain = PacketPlain::XorAck(PacketXorAck {
            actor_id: Vec::new(),
            packet_seq: 0,
            set_xor: Tag::from_bytes([3; 32]),
        });
        let mixed_body = seal_packet(&s, &rng, &mk(s.hmac(), &mixed), &plain).expect("seal");
        let opened = open_at(&s, &chain, Some(&mixed), &[], 10, &mixed_body).expect("mixed");
        assert_eq!(opened.chain.epoch, PacketEpoch::from_u64(1));
        assert_eq!(opened.chain.packet_seq, PacketSeq::from_u64(1));
        let plain_body = seal_packet(&s, &rng, &mk(s.hmac(), &chain), &plain).expect("seal0");
        let opened0 = open_at(&s, &chain, Some(&mixed), &[], 10, &plain_body).expect("plain");
        assert_eq!(opened0.chain.packet_seq, PacketSeq::from_u64(1));
        assert_eq!(opened0.chain.epoch, PacketEpoch::from_u64(0));
    }
}
