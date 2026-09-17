//! First on-wire layout.
//!
//! Pins [`SECRET_LEN`] secrets, HMAC-SHA-256 as the HKDF PRF, raw Deflate plus
//! unpadded base64url for the Ticket envelope, AES-256-GCM and RFC 8785 for the
//! Notice, and one-hour Mailbox Message bins.

mod aead;
mod b64u;
mod billboard;
mod channel;
mod compress;
mod engine;
mod hmac;
mod invite;
mod json;
mod kem;
mod mailbox;
mod notice;
mod state;
mod suite;
mod ticket;
mod unicode;
mod wire;

#[cfg(test)]
pub(crate) mod fixtures;

pub use crate::protocol::Policy;
pub use aead::{AEAD_KEY_LEN, AEAD_NONCE_LEN, Aead, AeadError, AeadKey, AeadNonce};
pub use b64u::{Base64Url, Base64UrlError};
pub use billboard::{
    Billboard, BillboardAddress, BillboardAddressError, BillboardKind, BillboardKindError,
};
pub use channel::{AddressError, KindError};
pub use compress::{Compress, CompressError};
pub use engine::Engine;
pub use hmac::{HmacSha256, HmacSha256Key, HmacSha256Mac};
pub use invite::{Invite, InviteError};
pub use json::{CanonicalJson, CanonicalJsonError, Json};
pub use kem::{
    CLASSIC_INTAKE_PK_LEN, Intake, IntakeError, IntakeKeypair, KEM_SEED_LEN, Kem, KemError,
    KemSeed, KemSeedBytes, MLKEM768_INTAKE_PK_LEN, XWING_INTAKE_PK_LEN, intake_pk_len,
};
pub use mailbox::{Mailbox, MailboxAddress, MailboxAddressError, MailboxKind, MailboxKindError};
pub use notice::{Notice, NoticeError};
pub use state::{
    ApplyError, COMMAND_MAX_COMPRESSED, COMMAND_MAX_PERSIST_LEN, COMMAND_MAX_UNCOMPRESSED,
    COMMAND_PERSIST_VERSION, COMMAND_SCHEMA_VERSION, Command, Conversation, ConversationId,
    ConversationPhase, CreateIdentityError, CreateIdentityOk, CreateInviteError, CreateInviteOk,
    CreateUserError, CreateUserOk, DISPLAY_NAME_MAX_LEN, DeleteConversationError,
    DeleteIdentityError, DeleteUserError, DirectMessage, DisplayName, DisplayNameError,
    EngineState, Established, Failed, Group, Identity, IdentityId, Invitee, Inviter,
    MarkNoticesPinnedError, PersistError, PersistOk, PersistedCommand, ReceiveNoticeError,
    ReceiveNoticeOk, ReceiveTicketError, ReceiveTicketOk, SetDisplayNameError, Synchronization,
    UnsetDisplayNameError, User, UserId,
};
pub use suite::Suite;
pub use ticket::{
    BillboardTag, EnvelopeError, MailboxTagKey, PayloadError, Ticket, TicketError, TicketSecret,
};
pub use wire::{Wire, WireAddress, WireAddressError, WireKind, WireKindError};

use hmac::DIGEST_LEN;

/// Length of v1 secrets, tags, and derived keys. Same as HMAC-SHA-256 output.
pub const SECRET_LEN: usize = DIGEST_LEN;

/// Maximum UTF-8 byte length of a mapper kind.
pub const KIND_MAX_LEN: usize = 32;

/// Maximum UTF-8 byte length of a mapper address.
pub const ADDRESS_MAX_LEN: usize = 128;

/// Maximum number of Billboards on one [`Ticket`].
pub const BILLBOARD_MAX_COUNT: usize = 8;

/// Maximum number of Mailboxes on one [`Intake`].
pub const MAILBOX_MAX_COUNT: usize = 8;

/// Maximum number of Wires on one [`Intake`].
pub const WIRE_MAX_COUNT: usize = 8;

/// Inner uncompressed payload version (first byte of the canonical Ticket payload).
pub const PAYLOAD_VERSION: u8 = 1;

/// Envelope version byte before the invite kind and raw Deflate (`0xC1`).
pub const ENVELOPE_VERSION: u8 = 0xC1;

/// Compact-envelope invite kind for a DM Conversation (`0x01`).
pub const INVITE_KIND_DM: u8 = 0x01;

/// Cap on uncompressed canonical Ticket bytes (zip-bomb brake).
pub const TICKET_MAX_UNCOMPRESSED: usize =
    1 + SECRET_LEN + 1 + BILLBOARD_MAX_COUNT * (1 + KIND_MAX_LEN + 1 + ADDRESS_MAX_LEN);

/// Cap on the Ticket Deflate body (incompressible secrets may expand slightly).
pub const TICKET_MAX_COMPRESSED: usize = TICKET_MAX_UNCOMPRESSED.saturating_add(16);

/// Cap on the Ticket host string (`b64u(version || kind || compressed)`).
pub const TICKET_MAX_B64U_LEN: usize = ((2 + TICKET_MAX_COMPRESSED) * 4).div_ceil(3);

/// Cap on uncompressed Notice JSON bytes.
pub const NOTICE_MAX_UNCOMPRESSED: usize = 8192;

/// Cap on the Notice Deflate body.
pub const NOTICE_MAX_COMPRESSED: usize = NOTICE_MAX_UNCOMPRESSED.saturating_add(16);

/// Cap on the Notice host string (`b64u(ciphertext)` including the GCM tag).
pub const NOTICE_MAX_B64U_LEN: usize = ((NOTICE_MAX_COMPRESSED + 16) * 4).div_ceil(3);

/// HKDF-Expand `info` for the Billboard [`BillboardTag`].
///
/// Wire bytes stay `chuchotez/1/invite-tag`.
pub const INFO_BILLBOARD_TAG: &[u8] = b"chuchotez/1/invite-tag";

/// HKDF-Expand `info` for the Mailbox [`MailboxTagKey`].
pub const INFO_MAILBOX_TAG_KEY: &[u8] = b"chuchotez/1/mailbox-tag-key";

/// HKDF-Expand `info` for the Notice AEAD key.
pub const INFO_NOTICE_AEAD_KEY: &[u8] = b"chuchotez/1/notice-aead-key";

/// HKDF-Expand `info` for the Notice AEAD nonce.
pub const INFO_NOTICE_AEAD_NONCE: &[u8] = b"chuchotez/1/notice-aead-nonce";
