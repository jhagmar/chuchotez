//! Ticket, DurableBody, TxPayload, PacketPlain, and JSON mapping `J`.

use super::channel::{Address, DurableChannel, EphemeralChannel, Kind};
use super::defaults::{Defaults, DisplayName, OnWirePrefs, ProfilePic};
use super::{
    ConversationId, DeviceId, IdentityId, KeyPair, Policy, Secret, SigningKeyPair, Tag, TagKey,
    UserId,
};
use crate::protocol::Policy as PolicyEnum;

/// Ticket uncompressed cap.
pub const TICKET_MAX_UNCOMPRESSED: usize = 4096;

/// Packet / DurableBody uncompressed cap.
pub const PACKET_MAX_UNCOMPRESSED: usize = 65536;

/// Persist tx uncompressed cap.
pub const PERSIST_MAX_UNCOMPRESSED: usize = 1_048_576;

/// Vault header uncompressed cap.
pub const VAULT_MAX_UNCOMPRESSED: usize = 4096;

/// Mapper packet length.
pub const PACKET_LEN: usize = 512;

/// Packet nonce length.
pub const PACKET_NONCE_LEN: usize = 12;

/// Padded PacketPlain length.
pub const PACKET_PAD_LEN: usize = 484;

/// Hour in seconds.
pub const TIME_BIN_SECONDS: u64 = 3600;

/// Catch-up window in hour bins.
pub const BIN_WINDOW: u64 = 72;

/// Which allowed payloads and secret-evolution rules apply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversationSort {
    /// DM handshake.
    HandshakeDm,
    /// Sync handshake.
    HandshakeSync,
    /// Established DM.
    DirectMessage,
    /// Group.
    Group,
    /// Linked devices.
    Synchronization,
    /// Engine txs.
    Engine,
}

impl ConversationSort {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::HandshakeDm => "HandshakeDm",
            Self::HandshakeSync => "HandshakeSync",
            Self::DirectMessage => "DirectMessage",
            Self::Group => "Group",
            Self::Synchronization => "Synchronization",
            Self::Engine => "Engine",
        }
    }
}

impl core::fmt::Display for ConversationSort {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Capability that locates a handshake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ticket {
    /// Ticket secret.
    pub secret: Secret,
    /// Inviter persistent locators.
    pub persistents: Vec<DurableChannel>,
    /// Expiry Unix seconds.
    pub expires: u64,
}

/// Presentation timestamp. Merge ignores `Hlc`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hlc {
    /// Wall milliseconds.
    pub wall_ms: u64,
    /// Tie counter.
    pub counter: u64,
}

/// Reassembled durable transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableBody {
    /// Conversation this tx belongs to.
    pub conversation_id: ConversationId,
    /// Presentation timestamp.
    pub hlc: Hlc,
    /// Inner payload.
    pub payload: TxPayload,
}

/// Sort-constrained inner value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TxPayload {
    /// Handshake advertisement.
    Notice(TxNotice),
    /// Inviter calling information.
    InviterIntro(TxInviterIntro),
    /// Invitee calling information.
    InviteeIntro(TxInviteeIntro),
    /// Handshake confirm.
    Confirm,
    /// Handshake reject.
    Reject,
    /// Chat text.
    Text(TxText),
    /// Edit.
    Edit(TxEdit),
    /// Remove.
    Remove {
        /// Target tx id.
        target: Tag,
    },
    /// Reaction.
    Reaction(TxReaction),
    /// Read up to.
    Read {
        /// Target tx id.
        up_to: Tag,
    },
    /// Delivered up to.
    Delivered {
        /// Target tx id.
        up_to: Tag,
    },
    /// Media pointer.
    Media(TxMedia),
    /// Encaps advertise.
    Advertise {
        /// Encaps public key.
        encaps_pk: Vec<u8>,
    },
    /// Encaps wrap.
    Wrap {
        /// KEM ciphertext.
        kem_ct: Vec<u8>,
    },
    /// Ratchet ack.
    Ack {
        /// Hash of encaps_pk or kem_ct.
        ratchet_ack: Tag,
    },
    /// Name.
    Name {
        /// Display name.
        name: DisplayName,
    },
    /// Photo.
    Photo {
        /// Profile picture.
        profile_pic: Option<ProfilePic>,
    },
    /// Prefs.
    Prefs(OnWirePrefs),
    /// Group invite on a DM.
    GroupInvite(TxGroupInvite),
    /// Group accept.
    GroupAccept {
        /// Group id.
        group_id: ConversationId,
    },
    /// Group reject.
    GroupReject {
        /// Group id.
        group_id: ConversationId,
    },
    /// Group roster.
    GroupRoster(TxGroupRoster),
    /// Group wrap.
    GroupWrap(TxGroupWrap),
    /// Group leave.
    GroupLeave,
    /// Group kick.
    GroupKick {
        /// Member signing pk.
        signing_pk: Vec<u8>,
    },
    /// Engine init.
    EngineInit,
    /// Set defaults.
    EngineSetDefaults {
        /// New defaults.
        defaults: Defaults,
    },
    /// Create user.
    EngineCreateUser {
        /// User id.
        user_id: UserId,
    },
    /// Create identity.
    EngineCreateIdentity {
        /// Parent user.
        user_id: UserId,
        /// Identity id.
        identity_id: IdentityId,
        /// Policy.
        policy: Policy,
        /// Encryption keypair.
        encryption: KeyPair,
        /// Signing keypair.
        signing: SigningKeyPair,
    },
    /// Delete user.
    EngineDeleteUser {
        /// User id.
        user_id: UserId,
    },
    /// Delete identity.
    EngineDeleteIdentity {
        /// Parent user.
        user_id: UserId,
        /// Identity id.
        identity_id: IdentityId,
    },
    /// Set display name.
    EngineSetDisplayName {
        /// Parent user.
        user_id: UserId,
        /// Identity.
        identity_id: IdentityId,
        /// Name.
        name: DisplayName,
    },
    /// Unset display name.
    EngineUnsetDisplayName {
        /// Parent user.
        user_id: UserId,
        /// Identity.
        identity_id: IdentityId,
    },
    /// Set profile pic.
    EngineSetProfilePic {
        /// Parent user.
        user_id: UserId,
        /// Identity.
        identity_id: IdentityId,
        /// Picture.
        profile_pic: Option<ProfilePic>,
    },
    /// Set device name.
    EngineSetDeviceName {
        /// Device name.
        name: DisplayName,
    },
    /// Kick device.
    EngineKickDevice {
        /// Device id.
        device_id: DeviceId,
    },
}

/// Handshake advertisement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxNotice {
    /// Policy.
    pub policy: Policy,
    /// Intake public key.
    pub intake_pk: Vec<u8>,
    /// Persistent channels.
    pub persistents: Vec<DurableChannel>,
    /// Ephemeral channels.
    pub ephemerals: Vec<EphemeralChannel>,
    /// Expiry.
    pub expires: u64,
}

/// Inviter intro.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxInviterIntro {
    /// Name.
    pub name: DisplayName,
    /// Picture.
    pub profile_pic: Option<ProfilePic>,
    /// Persist tag key.
    pub send_tag_key: TagKey,
    /// Eph tag key.
    pub eph_send_tag_key: TagKey,
    /// Encryption pk.
    pub encryption_pk: Vec<u8>,
    /// Signing pk.
    pub signing_pk: Vec<u8>,
    /// Wrap of seed to invitee intake.
    pub seed_ct: Vec<u8>,
    /// Prefs.
    pub prefs: OnWirePrefs,
}

/// Invitee intro.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxInviteeIntro {
    /// Name.
    pub name: DisplayName,
    /// Picture.
    pub profile_pic: Option<ProfilePic>,
    /// Persist tag key.
    pub send_tag_key: TagKey,
    /// Eph tag key.
    pub eph_send_tag_key: TagKey,
    /// Encryption pk.
    pub encryption_pk: Vec<u8>,
    /// Signing pk.
    pub signing_pk: Vec<u8>,
    /// Invitee intake pk.
    pub intake_pk: Vec<u8>,
    /// Wrap of seed to inviter notice intake.
    pub seed_ct: Vec<u8>,
    /// Prefs.
    pub prefs: OnWirePrefs,
}

/// Chat text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxText {
    /// Body.
    pub body: String,
    /// Reply target.
    pub reply_to: Option<Tag>,
    /// Expire at.
    pub expire_at: Option<u64>,
}

/// Edit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxEdit {
    /// Target.
    pub target: Tag,
    /// Body.
    pub body: String,
}

/// Reaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxReaction {
    /// Target.
    pub target: Tag,
    /// Emoji.
    pub emoji: String,
    /// Add or remove.
    pub add: bool,
}

/// Media pointer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxMedia {
    /// Mime.
    pub mime: String,
    /// Filename.
    pub filename: String,
    /// Hash of plaintext.
    pub hash: Tag,
    /// Blob kind.
    pub kind: Kind,
    /// Blob address.
    pub address: Address,
    /// Blob tag.
    pub tag: Tag,
    /// Caption.
    pub caption: Option<String>,
    /// Reply target.
    pub reply_to: Option<Tag>,
    /// Expire at.
    pub expire_at: Option<u64>,
}

/// Group invite on a DM.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxGroupInvite {
    /// Group id.
    pub group_id: ConversationId,
    /// Owner signing pk.
    pub owner_signing_pk: Vec<u8>,
    /// Persistents.
    pub persistents: Vec<DurableChannel>,
    /// Ephemerals.
    pub ephemerals: Vec<EphemeralChannel>,
    /// Name.
    pub name: DisplayName,
    /// Photo.
    pub photo: Option<ProfilePic>,
    /// Invitee signing pk.
    pub invitee_signing_pk: Vec<u8>,
    /// Wrap of group secret.
    pub group_secret_ct: Vec<u8>,
}

/// Group member on a roster.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupMember {
    /// Signing pk.
    pub signing_pk: Vec<u8>,
    /// Encryption pk.
    pub encryption_pk: Vec<u8>,
    /// Persist tag key.
    pub send_tag_key: TagKey,
    /// Eph tag key.
    pub eph_send_tag_key: TagKey,
}

/// Signed roster.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxGroupRoster {
    /// Epoch.
    pub epoch: u64,
    /// Members.
    pub members: Vec<GroupMember>,
    /// Signature.
    pub sig: Vec<u8>,
}

/// Per-member group wrap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxGroupWrap {
    /// Recipient signing pk.
    pub to: Vec<u8>,
    /// Sender signing pk.
    pub from: Vec<u8>,
    /// Wrap ciphertext.
    pub kem_ct: Vec<u8>,
}

/// Vault header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultHeader {
    /// Salt.
    pub salt: [u8; 16],
    /// Memory kibibytes.
    pub m: u32,
    /// Iterations.
    pub t: u32,
    /// Lanes.
    pub p: u32,
    /// Passphrase nonce.
    pub passphrase_nonce: Option<[u8; 12]>,
    /// Passphrase wrapped DEK.
    pub passphrase_wrapped_dek: Option<Vec<u8>>,
    /// PRF nonce.
    pub prf_nonce: Option<[u8; 12]>,
    /// PRF wrapped DEK.
    pub prf_wrapped_dek: Option<Vec<u8>>,
}

/// v1 Argon2id memory kibibytes.
pub const VAULT_M: u32 = 19456;

/// v1 Argon2id iterations.
pub const VAULT_T: u32 = 2;

/// v1 Argon2id lanes.
pub const VAULT_P: u32 = 1;

/// Unlock secret.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UnlockSecret {
    /// Passphrase.
    Passphrase(String),
    /// WebAuthn PRF output.
    Prf([u8; 32]),
}

pub(crate) fn policy_str(policy: Policy) -> &'static str {
    match policy {
        PolicyEnum::Classic => "Classic",
        PolicyEnum::PostQuantum => "PostQuantum",
        PolicyEnum::Hybrid => "Hybrid",
    }
}

#[allow(dead_code)]
pub(crate) fn parse_policy(s: &str) -> Option<Policy> {
    match s {
        "Classic" => Some(PolicyEnum::Classic),
        "PostQuantum" => Some(PolicyEnum::PostQuantum),
        "Hybrid" => Some(PolicyEnum::Hybrid),
        _ => None,
    }
}

pub(crate) fn time_bin(unix_seconds: u64) -> u64 {
    unix_seconds / TIME_BIN_SECONDS
}

#[allow(dead_code)]
pub(crate) fn pad484(bytes: &[u8]) -> Result<Vec<u8>, ()> {
    if bytes.len() > PACKET_PAD_LEN {
        return Err(());
    }
    let mut out = bytes.to_vec();
    out.resize(PACKET_PAD_LEN, 0);
    Ok(out)
}

#[allow(dead_code)]
pub(crate) fn unpad484(bytes: &[u8]) -> &[u8] {
    let mut n = bytes.len();
    while n > 0 && bytes[n - 1] == 0 {
        n -= 1;
    }
    &bytes[..n]
}

#[cfg(test)]
mod tests {
    use super::{
        BIN_WINDOW, ConversationSort, PACKET_LEN, PACKET_PAD_LEN, pad484, parse_policy, policy_str,
        time_bin, unpad484,
    };
    use crate::protocol::Policy;

    #[test]
    fn helpers() {
        assert_eq!(time_bin(3600), 1);
        assert_eq!(BIN_WINDOW, 72);
        assert_eq!(PACKET_LEN, 512);
        assert_eq!(policy_str(Policy::Classic), "Classic");
        assert_eq!(policy_str(Policy::PostQuantum), "PostQuantum");
        assert_eq!(policy_str(Policy::Hybrid), "Hybrid");
        assert_eq!(parse_policy("Hybrid"), Some(Policy::Hybrid));
        assert_eq!(parse_policy("x"), None);
        assert_eq!(ConversationSort::Engine.as_str(), "Engine");
        assert_eq!(ConversationSort::HandshakeDm.as_str(), "HandshakeDm");
        assert_eq!(ConversationSort::HandshakeSync.as_str(), "HandshakeSync");
        assert_eq!(ConversationSort::DirectMessage.as_str(), "DirectMessage");
        assert_eq!(ConversationSort::Group.as_str(), "Group");
        assert_eq!(
            ConversationSort::Synchronization.as_str(),
            "Synchronization"
        );
        assert_eq!(ConversationSort::Engine.to_string(), "Engine");
        let p = pad484(b"hi").expect("pad");
        assert_eq!(p.len(), PACKET_PAD_LEN);
        assert_eq!(unpad484(&p), b"hi");
        assert!(pad484(&[0u8; PACKET_PAD_LEN + 1]).is_err());
    }
}
