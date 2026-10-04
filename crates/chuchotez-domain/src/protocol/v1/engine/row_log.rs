//! Payloads a conversation row is allowed to store.

use super::super::payload::{
    SyncInviteeIntro, SyncInviterIntro, TxGroupInvite, TxGroupRoster, TxGroupWrap, TxInviteeIntro,
    TxInviterIntro, TxMedia, TxNotice, TxPayload, TxReaction, TxText,
};
use super::super::{
    ConversationId, Defaults, DeviceId, DisplayName, Hlc, IdentityId, KeyPair, OnWirePrefs, Policy,
    ProfilePic, SigningKeyPair, Tag, UserId,
};
use std::collections::BTreeMap;

/// One durable transaction on a row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TxRow<T> {
    pub(super) conversation_id: ConversationId,
    pub(super) hlc: Hlc,
    pub(super) payload: T,
}

pub(super) type TxLog<T> = BTreeMap<Tag, TxRow<T>>;

/// DM handshake transactions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum DmHandshakeTx {
    Notice(TxNotice),
    InviterIntro(TxInviterIntro),
    InviteeIntro(TxInviteeIntro),
    Confirm,
    Reject,
}

/// Sync handshake transactions, including the sealed vault key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum SyncHandshakeTx {
    Notice(TxNotice),
    InviterIntro(SyncInviterIntro),
    InviteeIntro(SyncInviteeIntro),
    Confirm,
    Reject,
    Dek { ct: Vec<u8> },
}

/// Chat transactions on an established direct message or a live group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ChatTx {
    Text(TxText),
    Edit(super::super::payload::TxEdit),
    Remove { target: Tag },
    Reaction(TxReaction),
    Read { up_to: Tag },
    Delivered { up_to: Tag },
    Media(TxMedia),
    Name { name: DisplayName },
    Photo { profile_pic: Option<ProfilePic> },
    Prefs(OnWirePrefs),
}

/// Ratchet advertise, wrap, and ack.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RatchetTx {
    Advertise {
        encaps_pk: super::super::EncryptionPublicKey,
    },
    Wrap {
        kem_ct: Vec<u8>,
    },
    Ack {
        ratchet_ack: Tag,
    },
}

/// Group roster, wrap, leave, and kick.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum GroupTx {
    Roster(TxGroupRoster),
    Wrap(TxGroupWrap),
    Leave,
    Kick {
        signing_pk: super::super::SigningPublicKey,
    },
}

/// Transactions on an established direct message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum DmTx {
    Chat(ChatTx),
    Ratchet(RatchetTx),
    GroupInvite(TxGroupInvite),
    GroupAccept { group_id: ConversationId },
    GroupReject { group_id: ConversationId },
}

/// Transactions on a live group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum LiveGroupTx {
    Chat(ChatTx),
    Ratchet(RatchetTx),
    Group(GroupTx),
}

/// Vault transactions. One id is shared by every linked device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum EngineTx {
    Init,
    SetDefaults {
        defaults: Defaults,
    },
    CreateUser {
        user_id: UserId,
    },
    CreateIdentity {
        user_id: UserId,
        identity_id: IdentityId,
        policy: Policy,
        encryption: KeyPair,
        signing: SigningKeyPair,
    },
    DeleteUser {
        user_id: UserId,
    },
    DeleteIdentity {
        user_id: UserId,
        identity_id: IdentityId,
    },
    SetDisplayName {
        user_id: UserId,
        identity_id: IdentityId,
        name: DisplayName,
    },
    UnsetDisplayName {
        user_id: UserId,
        identity_id: IdentityId,
    },
    SetProfilePic {
        user_id: UserId,
        identity_id: IdentityId,
        profile_pic: Option<ProfilePic>,
    },
    SetDeviceName {
        name: DisplayName,
    },
    KickDevice {
        device_id: DeviceId,
    },
}

/// Transactions stored on an established sync row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum SyncTx {
    Engine(EngineTx),
    Name { name: DisplayName },
}

impl DmHandshakeTx {
    pub(super) fn from_payload(payload: TxPayload) -> Option<Self> {
        match payload {
            TxPayload::Notice(notice) => Some(Self::Notice(notice)),
            TxPayload::InviterIntro(intro) => Some(Self::InviterIntro(intro)),
            TxPayload::InviteeIntro(intro) => Some(Self::InviteeIntro(intro)),
            TxPayload::Confirm => Some(Self::Confirm),
            TxPayload::Reject => Some(Self::Reject),
            _ => None,
        }
    }

    pub(super) fn to_payload(&self) -> TxPayload {
        match self {
            Self::Notice(notice) => TxPayload::Notice(notice.clone()),
            Self::InviterIntro(intro) => TxPayload::InviterIntro(intro.clone()),
            Self::InviteeIntro(intro) => TxPayload::InviteeIntro(intro.clone()),
            Self::Confirm => TxPayload::Confirm,
            Self::Reject => TxPayload::Reject,
        }
    }
}

impl SyncHandshakeTx {
    pub(super) fn from_payload(payload: TxPayload) -> Option<Self> {
        match payload {
            TxPayload::Notice(notice) => Some(Self::Notice(notice)),
            TxPayload::SyncInviterIntro(intro) => Some(Self::InviterIntro(intro)),
            TxPayload::SyncInviteeIntro(intro) => Some(Self::InviteeIntro(intro)),
            TxPayload::Confirm => Some(Self::Confirm),
            TxPayload::Reject => Some(Self::Reject),
            TxPayload::SyncDek { ct } => Some(Self::Dek { ct }),
            _ => None,
        }
    }

    pub(super) fn to_payload(&self) -> TxPayload {
        match self {
            Self::Notice(notice) => TxPayload::Notice(notice.clone()),
            Self::InviterIntro(intro) => TxPayload::SyncInviterIntro(intro.clone()),
            Self::InviteeIntro(intro) => TxPayload::SyncInviteeIntro(intro.clone()),
            Self::Confirm => TxPayload::Confirm,
            Self::Reject => TxPayload::Reject,
            Self::Dek { ct } => TxPayload::SyncDek { ct: ct.clone() },
        }
    }
}

impl ChatTx {
    pub(super) fn from_payload(payload: TxPayload) -> Option<Self> {
        match payload {
            TxPayload::Text(text) => Some(Self::Text(text)),
            TxPayload::Edit(edit) => Some(Self::Edit(edit)),
            TxPayload::Remove { target } => Some(Self::Remove { target }),
            TxPayload::Reaction(reaction) => Some(Self::Reaction(reaction)),
            TxPayload::Read { up_to } => Some(Self::Read { up_to }),
            TxPayload::Delivered { up_to } => Some(Self::Delivered { up_to }),
            TxPayload::Media(media) => Some(Self::Media(media)),
            TxPayload::Name { name } => Some(Self::Name { name }),
            TxPayload::Photo { profile_pic } => Some(Self::Photo { profile_pic }),
            TxPayload::Prefs(prefs) => Some(Self::Prefs(prefs)),
            _ => None,
        }
    }

    pub(super) fn to_payload(&self) -> TxPayload {
        match self {
            Self::Text(text) => TxPayload::Text(text.clone()),
            Self::Edit(edit) => TxPayload::Edit(edit.clone()),
            Self::Remove { target } => TxPayload::Remove { target: *target },
            Self::Reaction(reaction) => TxPayload::Reaction(reaction.clone()),
            Self::Read { up_to } => TxPayload::Read { up_to: *up_to },
            Self::Delivered { up_to } => TxPayload::Delivered { up_to: *up_to },
            Self::Media(media) => TxPayload::Media(media.clone()),
            Self::Name { name } => TxPayload::Name { name: name.clone() },
            Self::Photo { profile_pic } => TxPayload::Photo {
                profile_pic: profile_pic.clone(),
            },
            Self::Prefs(prefs) => TxPayload::Prefs(prefs.clone()),
        }
    }
}

impl RatchetTx {
    pub(super) fn from_payload(payload: TxPayload) -> Option<Self> {
        match payload {
            TxPayload::Advertise { encaps_pk } => Some(Self::Advertise { encaps_pk }),
            TxPayload::Wrap { kem_ct } => Some(Self::Wrap { kem_ct }),
            TxPayload::Ack { ratchet_ack } => Some(Self::Ack { ratchet_ack }),
            _ => None,
        }
    }

    pub(super) fn to_payload(&self) -> TxPayload {
        match self {
            Self::Advertise { encaps_pk } => TxPayload::Advertise {
                encaps_pk: encaps_pk.clone(),
            },
            Self::Wrap { kem_ct } => TxPayload::Wrap {
                kem_ct: kem_ct.clone(),
            },
            Self::Ack { ratchet_ack } => TxPayload::Ack {
                ratchet_ack: *ratchet_ack,
            },
        }
    }
}

impl GroupTx {
    pub(super) fn from_payload(payload: TxPayload) -> Option<Self> {
        match payload {
            TxPayload::GroupRoster(roster) => Some(Self::Roster(roster)),
            TxPayload::GroupWrap(wrap) => Some(Self::Wrap(wrap)),
            TxPayload::GroupLeave => Some(Self::Leave),
            TxPayload::GroupKick { signing_pk } => Some(Self::Kick { signing_pk }),
            _ => None,
        }
    }

    pub(super) fn to_payload(&self) -> TxPayload {
        match self {
            Self::Roster(roster) => TxPayload::GroupRoster(roster.clone()),
            Self::Wrap(wrap) => TxPayload::GroupWrap(wrap.clone()),
            Self::Leave => TxPayload::GroupLeave,
            Self::Kick { signing_pk } => TxPayload::GroupKick {
                signing_pk: signing_pk.clone(),
            },
        }
    }
}

impl DmTx {
    pub(super) fn from_payload(payload: TxPayload) -> Option<Self> {
        if let Some(chat) = ChatTx::from_payload(payload.clone()) {
            return Some(Self::Chat(chat));
        }
        if let Some(ratchet) = RatchetTx::from_payload(payload.clone()) {
            return Some(Self::Ratchet(ratchet));
        }
        match payload {
            TxPayload::GroupInvite(invite) => Some(Self::GroupInvite(invite)),
            TxPayload::GroupAccept { group_id } => Some(Self::GroupAccept { group_id }),
            TxPayload::GroupReject { group_id } => Some(Self::GroupReject { group_id }),
            _ => None,
        }
    }

    pub(super) fn to_payload(&self) -> TxPayload {
        match self {
            Self::Chat(chat) => chat.to_payload(),
            Self::Ratchet(ratchet) => ratchet.to_payload(),
            Self::GroupInvite(invite) => TxPayload::GroupInvite(invite.clone()),
            Self::GroupAccept { group_id } => TxPayload::GroupAccept {
                group_id: *group_id,
            },
            Self::GroupReject { group_id } => TxPayload::GroupReject {
                group_id: *group_id,
            },
        }
    }
}

impl LiveGroupTx {
    pub(super) fn from_payload(payload: TxPayload) -> Option<Self> {
        if let Some(chat) = ChatTx::from_payload(payload.clone()) {
            return Some(Self::Chat(chat));
        }
        if let Some(ratchet) = RatchetTx::from_payload(payload.clone()) {
            return Some(Self::Ratchet(ratchet));
        }
        GroupTx::from_payload(payload).map(Self::Group)
    }

    pub(super) fn to_payload(&self) -> TxPayload {
        match self {
            Self::Chat(chat) => chat.to_payload(),
            Self::Ratchet(ratchet) => ratchet.to_payload(),
            Self::Group(group) => group.to_payload(),
        }
    }
}

impl EngineTx {
    pub(super) fn from_payload(payload: TxPayload) -> Option<Self> {
        match payload {
            TxPayload::EngineInit => Some(Self::Init),
            TxPayload::EngineSetDefaults { defaults } => Some(Self::SetDefaults { defaults }),
            TxPayload::EngineCreateUser { user_id } => Some(Self::CreateUser { user_id }),
            TxPayload::EngineCreateIdentity {
                user_id,
                identity_id,
                policy,
                encryption,
                signing,
            } => Some(Self::CreateIdentity {
                user_id,
                identity_id,
                policy,
                encryption,
                signing,
            }),
            TxPayload::EngineDeleteUser { user_id } => Some(Self::DeleteUser { user_id }),
            TxPayload::EngineDeleteIdentity {
                user_id,
                identity_id,
            } => Some(Self::DeleteIdentity {
                user_id,
                identity_id,
            }),
            TxPayload::EngineSetDisplayName {
                user_id,
                identity_id,
                name,
            } => Some(Self::SetDisplayName {
                user_id,
                identity_id,
                name,
            }),
            TxPayload::EngineUnsetDisplayName {
                user_id,
                identity_id,
            } => Some(Self::UnsetDisplayName {
                user_id,
                identity_id,
            }),
            TxPayload::EngineSetProfilePic {
                user_id,
                identity_id,
                profile_pic,
            } => Some(Self::SetProfilePic {
                user_id,
                identity_id,
                profile_pic,
            }),
            TxPayload::EngineSetDeviceName { name } => Some(Self::SetDeviceName { name }),
            TxPayload::EngineKickDevice { device_id } => Some(Self::KickDevice { device_id }),
            _ => None,
        }
    }

    pub(super) fn to_payload(&self) -> TxPayload {
        match self {
            Self::Init => TxPayload::EngineInit,
            Self::SetDefaults { defaults } => TxPayload::EngineSetDefaults {
                defaults: defaults.clone(),
            },
            Self::CreateUser { user_id } => TxPayload::EngineCreateUser { user_id: *user_id },
            Self::CreateIdentity {
                user_id,
                identity_id,
                policy,
                encryption,
                signing,
            } => TxPayload::EngineCreateIdentity {
                user_id: *user_id,
                identity_id: *identity_id,
                policy: *policy,
                encryption: encryption.clone(),
                signing: signing.clone(),
            },
            Self::DeleteUser { user_id } => TxPayload::EngineDeleteUser { user_id: *user_id },
            Self::DeleteIdentity {
                user_id,
                identity_id,
            } => TxPayload::EngineDeleteIdentity {
                user_id: *user_id,
                identity_id: *identity_id,
            },
            Self::SetDisplayName {
                user_id,
                identity_id,
                name,
            } => TxPayload::EngineSetDisplayName {
                user_id: *user_id,
                identity_id: *identity_id,
                name: name.clone(),
            },
            Self::UnsetDisplayName {
                user_id,
                identity_id,
            } => TxPayload::EngineUnsetDisplayName {
                user_id: *user_id,
                identity_id: *identity_id,
            },
            Self::SetProfilePic {
                user_id,
                identity_id,
                profile_pic,
            } => TxPayload::EngineSetProfilePic {
                user_id: *user_id,
                identity_id: *identity_id,
                profile_pic: profile_pic.clone(),
            },
            Self::SetDeviceName { name } => TxPayload::EngineSetDeviceName { name: name.clone() },
            Self::KickDevice { device_id } => TxPayload::EngineKickDevice {
                device_id: *device_id,
            },
        }
    }
}

impl SyncTx {
    pub(super) fn from_payload(payload: TxPayload) -> Option<Self> {
        if let Some(engine) = EngineTx::from_payload(payload.clone()) {
            return Some(Self::Engine(engine));
        }
        match payload {
            TxPayload::Name { name } => Some(Self::Name { name }),
            _ => None,
        }
    }

    pub(super) fn to_payload(&self) -> TxPayload {
        match self {
            Self::Engine(engine) => engine.to_payload(),
            Self::Name { name } => TxPayload::Name { name: name.clone() },
        }
    }
}

pub(super) fn durable(
    conversation_id: ConversationId,
    hlc: Hlc,
    payload: TxPayload,
) -> super::super::payload::DurableBody {
    super::super::payload::DurableBody {
        conversation_id,
        hlc,
        payload,
    }
}
