//! First on-wire layout.
//!
//! Pins [`SECRET_LEN`] secrets, HMAC-SHA-256 as the HKDF PRF, raw Deflate plus
//! unpadded base64url for the QR envelope, and one-hour Mailbox Message bins.
//! A later layout is a sibling module (`v2`) with its own `Engine` contract.

mod b64u;
mod billboard;
mod compress;
mod hkdf;
mod invite;
mod payload;
mod suite;

#[cfg(test)]
pub(crate) mod fixtures;

pub use crate::protocol::Policy;
pub use b64u::{Base64Url, Base64UrlError};
pub use billboard::{
    Billboard, BillboardAddress, BillboardAddressError, BillboardKind, BillboardKindError,
};
pub use compress::{Compress, CompressError};
pub use hkdf::{EXPAND_LEN, EXPAND_T1_COUNTER, HmacSha256, HmacSha256Key, HmacSha256Mac};
pub use invite::{InviteSecret, InviteSecretError, InviteTag, MailboxTagKey};
pub use payload::{EnvelopeError, PayloadError};
pub use suite::{Engine, Suite};

use hkdf::DIGEST_LEN;

/// Length of v1 secrets, tags, and derived keys. Same as HMAC-SHA-256 output.
pub const SECRET_LEN: usize = DIGEST_LEN;

/// Maximum UTF-8 byte length of a [`BillboardKind`].
pub const KIND_MAX_LEN: usize = 32;

/// Maximum UTF-8 byte length of a [`BillboardAddress`].
pub const ADDRESS_MAX_LEN: usize = 128;

/// Maximum number of Billboards on one [`InviteSecret`].
pub const BILLBOARD_MAX_COUNT: usize = 8;

/// Inner uncompressed payload version (first byte of the canonical invite payload).
pub const PAYLOAD_VERSION: u8 = 1;

/// Envelope version byte before the invite kind and raw Deflate (`0xC1`).
pub const ENVELOPE_VERSION: u8 = 0xC1;

/// Compact-envelope invite kind for a DM Thread (`0x01`).
pub const INVITE_KIND_DM: u8 = 0x01;

/// Cap on uncompressed canonical bytes (zip-bomb brake).
pub const MAX_UNCOMPRESSED: usize =
    1 + SECRET_LEN + 1 + BILLBOARD_MAX_COUNT * (1 + KIND_MAX_LEN + 1 + ADDRESS_MAX_LEN);

/// Cap on the Deflate body (incompressible secrets may expand slightly).
pub const MAX_COMPRESSED: usize = MAX_UNCOMPRESSED.saturating_add(16);

/// Cap on the host string (`b64u(version || kind || compressed)`).
pub const MAX_B64U_LEN: usize = ((2 + MAX_COMPRESSED) * 4).div_ceil(3);

/// HKDF-Expand `info` for the Billboard [`InviteTag`].
pub const INFO_INVITE_TAG: &[u8] = b"chuchotez/1/invite-tag";

/// HKDF-Expand `info` for the Mailbox [`MailboxTagKey`].
pub const INFO_MAILBOX_TAG_KEY: &[u8] = b"chuchotez/1/mailbox-tag-key";
