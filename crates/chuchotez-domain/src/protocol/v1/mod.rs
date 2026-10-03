//! First on-wire layout.

mod aead;
mod argon;
mod b64u;
mod chain;
mod channel;
mod codec;
mod compress;
mod defaults;
mod engine;
mod error;
mod hash;
mod hmac;
mod ids;
mod json;
mod kem;
mod payload;
mod sign;
mod suite;
mod unicode;

#[cfg(test)]
pub(crate) mod fixtures;

pub use crate::protocol::Policy;
pub use aead::{AEAD_KEY_LEN, AEAD_NONCE_LEN, Aead, AeadError, AeadKey, AeadNonce};
pub use argon::{Argon2Error, Argon2id};
pub use b64u::{Base64Url, Base64UrlError};
pub use channel::{Address, AddressError, DurableChannel, EphemeralChannel, Kind, KindError};
pub use compress::{Compress, CompressError};
pub use defaults::{
    ConversationPrefs, DISPLAY_NAME_MAX_LEN, Defaults, DefaultsError, DisplayName,
    DisplayNameError, EPHEMERAL_MAX_COUNT, NotificationPrivacy, OnWirePrefs, PERSISTENT_MAX_COUNT,
    PERSISTENT_MIN_COUNT, PROFILE_PIC_MAX_LEN, ProfilePic, ProfilePicError, Wake, WakeError,
};
pub use engine::{
    BlobGet, BlobPut, BlockedIdentity, BlockedMissing, Conversation, ConversationListRow,
    ConversationRef, DirectMessageQuery, DmEstablished, DurableLocator, DurableWrite, Engine,
    EngineState, EphemeralLocator, EphemeralWrite, FailedReason, FoldOk, GroupQuery, Handshake,
    HandshakeInvitee, HandshakeInviter, HistoryItem, MediaDraft, MutateOk, PingTarget, Poll,
    PresenceView, SynchronizationQuery, TypingView, WrapDekOk,
};
pub use error::EngineError;
pub use hash::{HashBytes, Sha256};
pub use hmac::{HmacSha256, HmacSha256Key, HmacSha256Mac};
pub use ids::{
    ActorId, ConversationId, DeviceId, FragIndex, IdentityId, PacketEpoch, PacketSeq, PersistSeq,
    Secret, Tag, TagKey, TimeBin, UnixSeconds, UserId,
};
pub use json::{CanonicalJson, CanonicalJsonError, Json};
pub use kem::{
    CLASSIC_KEM_CT_LEN, CLASSIC_KEM_PK_LEN, CLASSIC_KEM_SK_LEN, KEM_SEED_LEN, KEM_SHARED_LEN, Kem,
    KemError, KemSeed, KemSeedBytes, KeyPair, MLKEM768_KEM_CT_LEN, MLKEM768_KEM_PK_LEN,
    MLKEM768_KEM_SK_LEN, XWING_KEM_CT_LEN, XWING_KEM_PK_LEN, XWING_KEM_SK_LEN, kem_ct_len,
    kem_pk_len, kem_sk_len,
};
pub use payload::{
    AEAD_TAG_LEN, ConversationSort, DurableBody, GroupMember, Hlc, PACKET_LEN,
    PACKET_MAX_UNCOMPRESSED, PACKET_PAD_LEN, PacketHealHalfXor, PacketHealHave, PacketHealWant,
    PacketPlain, PacketPresence, PacketPresenceActive, PacketTxFragLast, PacketTxFragMore,
    PacketTyping, PacketTypingActive, PacketXorAck, Ticket, TxEdit, TxGroupInvite, TxGroupRoster,
    TxGroupWrap, TxInviteeIntro, TxInviterIntro, TxMedia, TxNotice, TxPayload, TxReaction, TxText,
    UnlockSecret, VAULT_M, VAULT_P, VAULT_T, VaultHeader,
};
pub use sign::{
    CLASSIC_SIGN_PK_LEN, CLASSIC_SIGN_SIG_LEN, CLASSIC_SIGN_SK_LEN, HYBRID_SIGN_PK_LEN,
    HYBRID_SIGN_SIG_LEN, HYBRID_SIGN_SK_LEN, MLDSA65_SIGN_PK_LEN, MLDSA65_SIGN_SIG_LEN,
    MLDSA65_SIGN_SK_LEN, SIGN_SEED_LEN, Sign, SignError, SignSeed, SignSeedBytes, SigningKeyPair,
    sign_pk_len, sign_sig_len, sign_sk_len,
};
pub use suite::Suite;

use hmac::DIGEST_LEN;

/// Length of v1 secrets, tags, and derived keys.
pub const SECRET_LEN: usize = DIGEST_LEN;

/// Maximum UTF-8 byte length of a mapper kind.
pub const KIND_MAX_LEN: usize = 32;

/// Maximum UTF-8 byte length of a mapper address.
pub const ADDRESS_MAX_LEN: usize = 256;
