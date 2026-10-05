//! Packet chains on a handshake, and the extra state an established row keeps.

use super::super::chain::{CachedMk, SendChain};
use super::super::{Actor, Secret, Tag, UnixSeconds};
use std::collections::{BTreeMap, BTreeSet};

/// Advertised encaps secret key not yet used to unwrap a wrap.
#[derive(Clone)]
pub(super) struct UnusedSk {
    pub(super) tx_id: Tag,
    pub(super) pk: super::super::EncryptionPublicKey,
    pub(super) sk: Vec<u8>,
}

/// Shared secret from a wrap, waiting to mix or already recorded.
#[derive(Clone)]
pub(super) struct KnownShared {
    pub(super) wrap_tx: Tag,
    pub(super) shared: Secret,
    pub(super) ct_hash: Tag,
    pub(super) from_us: bool,
    pub(super) encaps_pk: super::super::EncryptionPublicKey,
}

/// Advertise, wrap, ack, and mix bookkeeping for one established conversation.
#[derive(Clone, Default)]
pub(super) struct Ratchet {
    /// Durable packets sealed since the last advertise, wrap, or ack we minted.
    pub(super) since: u64,
    /// Ratchet txs this device minted.
    pub(super) minted: BTreeSet<Tag>,
    /// Unused advertised secret keys, oldest first. Length at most 8.
    pub(super) unused: Vec<UnusedSk>,
    /// Shared secrets from wraps this device sent or unwrapped.
    pub(super) known: Vec<KnownShared>,
}

impl core::fmt::Debug for Ratchet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ratchet")
            .field("since", &self.since)
            .field("unused", &self.unused.len())
            .field("known", &self.known.len())
            .finish()
    }
}

/// One outstanding heal range. `hi` of all-`0xff` bytes is +∞.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum HealProbe {
    /// XOR of local ids in `[lo, hi)`.
    Half { lo: Tag, hi: Tag },
    /// Ids this device wants in `[lo, hi)`.
    Want { lo: Tag, hi: Tag, ids: Vec<Tag> },
    /// Ids this device has in `[lo, hi)`.
    Have { lo: Tag, hi: Tag, ids: Vec<Tag> },
}

/// Durable packet bodies held until a live XOR-ack or the 3-second fallback.
#[derive(Clone, Debug)]
pub(super) struct LivePending {
    pub(super) set_xor: Tag,
    pub(super) sent_at: UnixSeconds,
    pub(super) bodies: Vec<Vec<u8>>,
    pub(super) sealed_to: SendChain,
    pub(super) actor: Actor,
    pub(super) acks: u8,
    pub(super) needed: u8,
}

/// Heal search waiting for an answer, plus durable bodies sealed for fallback.
#[derive(Clone, Debug, Default)]
pub(super) struct Heal {
    pub(super) probes: Vec<HealProbe>,
    pub(super) sent_at: Option<UnixSeconds>,
    /// In-flight probes were posted on Ephemeral.
    pub(super) on_ephemeral: bool,
    /// Fallback to Persistent already ran for this search.
    pub(super) fell_back: bool,
    /// Durable ciphertexts sealed at `sealed_from`, posted when the fallback is due.
    pub(super) ready: Vec<Vec<u8>>,
    pub(super) sealed_from: Option<SendChain>,
    pub(super) sealed_to: Option<SendChain>,
    pub(super) needs_reseal: bool,
}

/// Ephemeral composing signal kept until query or reload.
#[derive(Clone, Debug)]
pub(super) struct TypingNote {
    pub(super) composing: bool,
    pub(super) at: UnixSeconds,
}

/// Send and receive chains, skip-ahead `mk`s, and last Persistent acks.
#[derive(Clone, Debug, Default)]
pub(super) struct PacketChains {
    pub(super) send: BTreeMap<Actor, SendChain>,
    pub(super) recv: BTreeMap<Actor, SendChain>,
    pub(super) skipped_mks: BTreeMap<Actor, Vec<CachedMk>>,
    pub(super) last_acks: BTreeMap<Actor, BTreeSet<Tag>>,
    /// Set-XOR search for this row's packet log.
    pub(super) heal: Heal,
    /// Ticked instant until which this conversation is live. `None` before a live ack.
    pub(super) live_until: Option<UnixSeconds>,
    /// Durable packet bodies waiting for a live XOR-ack.
    pub(super) live_pending: Vec<LivePending>,
}

/// Packet chains plus the ratchet, heal, live path, and chat notes of an established row.
#[derive(Clone, Debug, Default)]
pub(super) struct EstablishedChains {
    pub(super) packet: PacketChains,
    pub(super) ratchet: Ratchet,
    /// A presence probe was sent since this process came online.
    pub(super) presence_sent: bool,
    /// Sender of a chat tx, for query `messages`.
    pub(super) chat_senders: BTreeMap<Tag, Actor>,
    /// Latest composing signal. Not folded.
    pub(super) typing: Option<TypingNote>,
    /// Latest presence time. Not folded.
    pub(super) presence_at: Option<UnixSeconds>,
}

impl std::ops::Deref for EstablishedChains {
    type Target = PacketChains;

    fn deref(&self) -> &PacketChains {
        &self.packet
    }
}

impl std::ops::DerefMut for EstablishedChains {
    fn deref_mut(&mut self) -> &mut PacketChains {
        &mut self.packet
    }
}
