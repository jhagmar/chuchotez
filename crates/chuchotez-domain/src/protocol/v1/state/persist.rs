//! RFC 8785 Command payload sealed as AEAD(deflate(jcs)).

use super::{
    COMMAND_MAX_COMPRESSED, COMMAND_MAX_PERSIST_LEN, COMMAND_MAX_UNCOMPRESSED,
    COMMAND_PERSIST_VERSION, COMMAND_SCHEMA_VERSION, CallingCard, Command, ConversationId,
    DisplayName, Failed, IdentityId, PersistError, UserId,
};
use crate::protocol::v1::{
    AEAD_NONCE_LEN, AeadKey, AeadNonce, Engine, IdentityKemKeypair, IdentitySignKeypair, Intake,
    IntakeKeypair, Invite, Json, Mailbox, MailboxAddress, MailboxKind, MailboxTagKey, SECRET_LEN,
    Wire, WireAddress, WireKind, notice,
};

const KEY_V: &str = "v";
const KEY_OP: &str = "op";
const KEY_USER_ID: &str = "user_id";
const KEY_IDENTITY_ID: &str = "identity_id";
const KEY_CONVERSATION_ID: &str = "conversation_id";
const KEY_NAME: &str = "name";
const KEY_TICKET: &str = "ticket";
const KEY_INTAKE_PK: &str = "intake_pk";
const KEY_INTAKE_SK: &str = "intake_sk";
const KEY_MAILBOXES: &str = "mailboxes";
const KEY_WIRES: &str = "wires";
const KEY_NOTICE: &str = "notice";
const KEY_REASON: &str = "reason";
const KEY_KIND: &str = "kind";
const KEY_ADDRESS: &str = "address";
const KEY_ENCRYPTION_PK: &str = "encryption_pk";
const KEY_ENCRYPTION_SK: &str = "encryption_sk";
const KEY_SIGNING_PK: &str = "signing_pk";
const KEY_SIGNING_SK: &str = "signing_sk";
const KEY_MAILBOX_TAG_KEY: &str = "mailbox_tag_key";

const OP_CREATE_USER: &str = "create_user";
const OP_CREATE_IDENTITY: &str = "create_identity";
const OP_DELETE_USER: &str = "delete_user";
const OP_DELETE_IDENTITY: &str = "delete_identity";
const OP_DELETE_CONVERSATION: &str = "delete_conversation";
const OP_SET_DISPLAY_NAME: &str = "set_display_name";
const OP_UNSET_DISPLAY_NAME: &str = "unset_display_name";
const OP_CREATE_INVITE: &str = "create_invite";
const OP_MARK_NOTICES_PINNED: &str = "mark_notices_pinned";
const OP_RECEIVE_TICKET: &str = "receive_ticket";
const OP_RECEIVE_NOTICE: &str = "receive_notice";
const OP_FAIL_CONVERSATION: &str = "fail_conversation";
const OP_CREATE_CALLING_CARD: &str = "create_calling_card";
const REASON_POLICY_NOT_ACCEPTED: &str = "policy_not_accepted";

/// Sealed Command bytes: `nonce || AES-256-GCM(deflate(RFC 8785))`.
#[derive(Clone, Eq, PartialEq)]
pub struct PersistedCommand(Vec<u8>);

impl PersistedCommand {
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Record bytes for the host to append.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume the wrapper.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl core::fmt::Debug for PersistedCommand {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PersistedCommand(..)")
    }
}

impl Engine {
    pub(crate) fn seal_command(
        &self,
        dek: &AeadKey,
        seq: u64,
        command: &Command,
    ) -> Result<PersistedCommand, PersistError> {
        if seq == u64::MAX {
            return Err(PersistError::SeqOverflow);
        }
        let json = command_to_json(self, command);
        let canonical = self.canonical_json().encode(&json);
        if canonical.len() > COMMAND_MAX_UNCOMPRESSED {
            return Err(PersistError::TooLong);
        }
        let plain = self.compress().compress(&canonical);
        if plain.len() > COMMAND_MAX_COMPRESSED {
            return Err(PersistError::TooLong);
        }
        let nonce = nonce_from_seq(seq);
        let aad = aad_from_seq(seq);
        let ct = self.aead().seal(dek, &nonce, &aad, &plain);
        let mut blob = Vec::with_capacity(AEAD_NONCE_LEN + ct.len());
        blob.extend_from_slice(nonce.as_bytes());
        blob.extend_from_slice(&ct);
        if blob.len() > COMMAND_MAX_PERSIST_LEN {
            return Err(PersistError::TooLong);
        }
        Ok(PersistedCommand::from_bytes(blob))
    }

    #[cfg(test)]
    pub(crate) fn seal_raw_json(
        &self,
        dek: &AeadKey,
        seq: u64,
        json: &Json,
    ) -> Result<PersistedCommand, PersistError> {
        let canonical = self.canonical_json().encode(json);
        let plain = self.compress().compress(&canonical);
        let nonce = nonce_from_seq(seq);
        let aad = aad_from_seq(seq);
        let ct = self.aead().seal(dek, &nonce, &aad, &plain);
        let mut blob = Vec::with_capacity(AEAD_NONCE_LEN + ct.len());
        blob.extend_from_slice(nonce.as_bytes());
        blob.extend_from_slice(&ct);
        Ok(PersistedCommand::from_bytes(blob))
    }

    #[cfg(test)]
    pub(crate) fn seal_raw_plain(&self, dek: &AeadKey, seq: u64, plain: &[u8]) -> PersistedCommand {
        let nonce = nonce_from_seq(seq);
        let aad = aad_from_seq(seq);
        let ct = self.aead().seal(dek, &nonce, &aad, plain);
        let mut blob = Vec::with_capacity(AEAD_NONCE_LEN + ct.len());
        blob.extend_from_slice(nonce.as_bytes());
        blob.extend_from_slice(&ct);
        PersistedCommand::from_bytes(blob)
    }

    /// Open a sealed Command record with the host DEK.
    pub fn try_open_command(&self, dek: &AeadKey, blob: &[u8]) -> Result<Command, PersistError> {
        if blob.len() > COMMAND_MAX_PERSIST_LEN {
            return Err(PersistError::TooLong);
        }
        if blob.len() < AEAD_NONCE_LEN {
            return Err(PersistError::TooShort);
        }
        let (nonce_bytes, ct) = blob.split_at(AEAD_NONCE_LEN);
        if ct.is_empty() {
            return Err(PersistError::TooShort);
        }
        let nonce_arr: [u8; AEAD_NONCE_LEN] =
            nonce_bytes.try_into().map_err(|_| PersistError::TooShort)?;
        let nonce = AeadNonce::from_bytes(nonce_arr);
        let seq = seq_from_nonce(&nonce_arr);
        let aad = aad_from_seq(seq);
        let plain = self
            .aead()
            .open(dek, &nonce, &aad, ct)
            .map_err(PersistError::Aead)?;
        if plain.len() > COMMAND_MAX_COMPRESSED {
            return Err(PersistError::Compress(
                crate::protocol::v1::CompressError::Oversize,
            ));
        }
        let canonical = self
            .compress()
            .decompress(&plain, COMMAND_MAX_UNCOMPRESSED)
            .map_err(PersistError::Compress)?;
        let json = self
            .canonical_json()
            .decode(&canonical)
            .map_err(PersistError::Json)?;
        command_from_json(self, json)
    }
}

fn nonce_from_seq(seq: u64) -> AeadNonce {
    let mut bytes = [0u8; AEAD_NONCE_LEN];
    bytes[AEAD_NONCE_LEN - 8..].copy_from_slice(&seq.to_be_bytes());
    AeadNonce::from_bytes(bytes)
}

fn seq_from_nonce(nonce: &[u8; AEAD_NONCE_LEN]) -> u64 {
    let mut seq = [0u8; 8];
    seq.copy_from_slice(&nonce[AEAD_NONCE_LEN - 8..]);
    u64::from_be_bytes(seq)
}

fn aad_from_seq(seq: u64) -> [u8; 9] {
    let mut aad = [0u8; 9];
    aad[0] = COMMAND_PERSIST_VERSION;
    aad[1..].copy_from_slice(&seq.to_be_bytes());
    aad
}

fn command_to_json(engine: &Engine, command: &Command) -> Json {
    let mut members = vec![
        (KEY_V.into(), Json::String(COMMAND_SCHEMA_VERSION.into())),
        (KEY_OP.into(), Json::String(op_str(command).into())),
    ];
    match command {
        Command::CreateUser { user_id } => {
            members.push(id_member(engine, KEY_USER_ID, user_id.as_bytes()));
        }
        Command::CreateIdentity {
            user_id,
            identity_id,
            encryption,
            signing,
        } => {
            members.push(id_member(engine, KEY_USER_ID, user_id.as_bytes()));
            members.push(id_member(engine, KEY_IDENTITY_ID, identity_id.as_bytes()));
            members.push((
                KEY_ENCRYPTION_PK.into(),
                Json::String(engine.b64u().encode(encryption.public_bytes())),
            ));
            members.push((
                KEY_ENCRYPTION_SK.into(),
                Json::String(engine.b64u().encode(encryption.secret_bytes())),
            ));
            members.push((
                KEY_SIGNING_PK.into(),
                Json::String(engine.b64u().encode(signing.public_bytes())),
            ));
            members.push((
                KEY_SIGNING_SK.into(),
                Json::String(engine.b64u().encode(signing.secret_bytes())),
            ));
        }
        Command::DeleteUser { user_id } => {
            members.push(id_member(engine, KEY_USER_ID, user_id.as_bytes()));
        }
        Command::DeleteIdentity {
            user_id,
            identity_id,
        } => {
            members.push(id_member(engine, KEY_USER_ID, user_id.as_bytes()));
            members.push(id_member(engine, KEY_IDENTITY_ID, identity_id.as_bytes()));
        }
        Command::DeleteConversation {
            user_id,
            identity_id,
            conversation_id,
        }
        | Command::MarkNoticesPinned {
            user_id,
            identity_id,
            conversation_id,
        } => {
            members.push(id_member(engine, KEY_USER_ID, user_id.as_bytes()));
            members.push(id_member(engine, KEY_IDENTITY_ID, identity_id.as_bytes()));
            members.push(id_member(
                engine,
                KEY_CONVERSATION_ID,
                conversation_id.as_bytes(),
            ));
        }
        Command::SetDisplayName {
            user_id,
            identity_id,
            name,
        } => {
            members.push(id_member(engine, KEY_USER_ID, user_id.as_bytes()));
            members.push(id_member(engine, KEY_IDENTITY_ID, identity_id.as_bytes()));
            members.push((KEY_NAME.into(), Json::String(name.as_str().into())));
        }
        Command::UnsetDisplayName {
            user_id,
            identity_id,
        } => {
            members.push(id_member(engine, KEY_USER_ID, user_id.as_bytes()));
            members.push(id_member(engine, KEY_IDENTITY_ID, identity_id.as_bytes()));
        }
        Command::CreateInvite {
            user_id,
            identity_id,
            conversation_id,
            invite,
        } => {
            members.push(id_member(engine, KEY_USER_ID, user_id.as_bytes()));
            members.push(id_member(engine, KEY_IDENTITY_ID, identity_id.as_bytes()));
            members.push(id_member(
                engine,
                KEY_CONVERSATION_ID,
                conversation_id.as_bytes(),
            ));
            members.push((
                KEY_TICKET.into(),
                Json::String(invite.ticket().serialize(engine)),
            ));
            members.push((
                KEY_INTAKE_PK.into(),
                Json::String(engine.b64u().encode(invite.intake().public_bytes())),
            ));
            members.push((
                KEY_INTAKE_SK.into(),
                Json::String(engine.b64u().encode(invite.intake().secret_bytes())),
            ));
            members.push((
                KEY_MAILBOXES.into(),
                channels_json(invite.intake().mailboxes(), |m| {
                    (m.kind().as_str(), m.address().as_str())
                }),
            ));
            members.push((
                KEY_WIRES.into(),
                channels_json(invite.intake().wires(), |w| {
                    (w.kind().as_str(), w.address().as_str())
                }),
            ));
        }
        Command::ReceiveTicket {
            user_id,
            identity_id,
            conversation_id,
            ticket,
        } => {
            members.push(id_member(engine, KEY_USER_ID, user_id.as_bytes()));
            members.push(id_member(engine, KEY_IDENTITY_ID, identity_id.as_bytes()));
            members.push(id_member(
                engine,
                KEY_CONVERSATION_ID,
                conversation_id.as_bytes(),
            ));
            members.push((KEY_TICKET.into(), Json::String(ticket.serialize(engine))));
        }
        Command::ReceiveNotice {
            user_id,
            identity_id,
            conversation_id,
            notice,
        } => {
            members.push(id_member(engine, KEY_USER_ID, user_id.as_bytes()));
            members.push(id_member(engine, KEY_IDENTITY_ID, identity_id.as_bytes()));
            members.push(id_member(
                engine,
                KEY_CONVERSATION_ID,
                conversation_id.as_bytes(),
            ));
            members.push((KEY_NOTICE.into(), notice.to_json(engine)));
        }
        Command::FailConversation {
            user_id,
            identity_id,
            conversation_id,
            failed,
        } => {
            members.push(id_member(engine, KEY_USER_ID, user_id.as_bytes()));
            members.push(id_member(engine, KEY_IDENTITY_ID, identity_id.as_bytes()));
            members.push(id_member(
                engine,
                KEY_CONVERSATION_ID,
                conversation_id.as_bytes(),
            ));
            members.push((
                KEY_REASON.into(),
                Json::String(REASON_POLICY_NOT_ACCEPTED.into()),
            ));
            let Failed::PolicyNotAccepted { ticket, notice } = failed;
            members.push((KEY_TICKET.into(), Json::String(ticket.serialize(engine))));
            members.push((KEY_NOTICE.into(), notice.to_json(engine)));
        }
        Command::CreateCallingCard {
            user_id,
            identity_id,
            conversation_id,
            card,
        } => {
            members.push(id_member(engine, KEY_USER_ID, user_id.as_bytes()));
            members.push(id_member(engine, KEY_IDENTITY_ID, identity_id.as_bytes()));
            members.push(id_member(
                engine,
                KEY_CONVERSATION_ID,
                conversation_id.as_bytes(),
            ));
            members.push((
                KEY_NAME.into(),
                Json::String(card.display_name().as_str().into()),
            ));
            members.push((
                KEY_ENCRYPTION_PK.into(),
                Json::String(engine.b64u().encode(card.encryption_pk())),
            ));
            members.push((
                KEY_SIGNING_PK.into(),
                Json::String(engine.b64u().encode(card.signing_pk())),
            ));
            members.push((
                KEY_MAILBOX_TAG_KEY.into(),
                Json::String(engine.b64u().encode(card.mailbox_tag_key().as_bytes())),
            ));
            members.push((
                KEY_MAILBOXES.into(),
                channels_json(card.mailboxes(), |m| {
                    (m.kind().as_str(), m.address().as_str())
                }),
            ));
            members.push((
                KEY_WIRES.into(),
                channels_json(card.wires(), |w| (w.kind().as_str(), w.address().as_str())),
            ));
        }
    }
    Json::Object(members)
}

fn op_str(command: &Command) -> &'static str {
    match command {
        Command::CreateUser { .. } => OP_CREATE_USER,
        Command::CreateIdentity { .. } => OP_CREATE_IDENTITY,
        Command::DeleteUser { .. } => OP_DELETE_USER,
        Command::DeleteIdentity { .. } => OP_DELETE_IDENTITY,
        Command::DeleteConversation { .. } => OP_DELETE_CONVERSATION,
        Command::SetDisplayName { .. } => OP_SET_DISPLAY_NAME,
        Command::UnsetDisplayName { .. } => OP_UNSET_DISPLAY_NAME,
        Command::CreateInvite { .. } => OP_CREATE_INVITE,
        Command::MarkNoticesPinned { .. } => OP_MARK_NOTICES_PINNED,
        Command::ReceiveTicket { .. } => OP_RECEIVE_TICKET,
        Command::ReceiveNotice { .. } => OP_RECEIVE_NOTICE,
        Command::FailConversation { .. } => OP_FAIL_CONVERSATION,
        Command::CreateCallingCard { .. } => OP_CREATE_CALLING_CARD,
    }
}

fn id_member(engine: &Engine, key: &str, bytes: &[u8; 32]) -> (String, Json) {
    (key.into(), Json::String(engine.b64u().encode(bytes)))
}

fn channels_json<T>(items: &[T], parts: impl Fn(&T) -> (&str, &str)) -> Json {
    Json::Array(
        items
            .iter()
            .map(|item| {
                let (kind, address) = parts(item);
                Json::Object(vec![
                    (KEY_KIND.into(), Json::String(kind.into())),
                    (KEY_ADDRESS.into(), Json::String(address.into())),
                ])
            })
            .collect(),
    )
}

fn command_from_json(engine: &Engine, json: Json) -> Result<Command, PersistError> {
    let Json::Object(members) = json else {
        return Err(PersistError::Type);
    };
    let mut v = None;
    let mut op = None;
    let mut user_id = None;
    let mut identity_id = None;
    let mut conversation_id = None;
    let mut name = None;
    let mut ticket = None;
    let mut intake_pk = None;
    let mut intake_sk = None;
    let mut mailboxes = None;
    let mut wires = None;
    let mut notice = None;
    let mut reason = None;
    let mut encryption_pk = None;
    let mut encryption_sk = None;
    let mut signing_pk = None;
    let mut signing_sk = None;
    let mut mailbox_tag_key = None;
    for (key, value) in members {
        match key.as_str() {
            KEY_V => v = Some(expect_string(value)?),
            KEY_OP => op = Some(expect_string(value)?),
            KEY_USER_ID => user_id = Some(parse_id(engine, value)?),
            KEY_IDENTITY_ID => identity_id = Some(parse_id(engine, value)?),
            KEY_CONVERSATION_ID => conversation_id = Some(parse_id(engine, value)?),
            KEY_NAME => name = Some(expect_string(value)?),
            KEY_TICKET => ticket = Some(expect_string(value)?),
            KEY_INTAKE_PK => intake_pk = Some(parse_b64(engine, value)?),
            KEY_INTAKE_SK => intake_sk = Some(parse_b64(engine, value)?),
            KEY_MAILBOXES => mailboxes = Some(parse_mailboxes(value)?),
            KEY_WIRES => wires = Some(parse_wires(value)?),
            KEY_NOTICE => notice = Some(value),
            KEY_REASON => reason = Some(expect_string(value)?),
            KEY_ENCRYPTION_PK => encryption_pk = Some(parse_b64(engine, value)?),
            KEY_ENCRYPTION_SK => encryption_sk = Some(parse_b64(engine, value)?),
            KEY_SIGNING_PK => signing_pk = Some(parse_b64(engine, value)?),
            KEY_SIGNING_SK => signing_sk = Some(parse_b64(engine, value)?),
            KEY_MAILBOX_TAG_KEY => mailbox_tag_key = Some(parse_tag_key(engine, value)?),
            _ => return Err(PersistError::UnknownField),
        }
    }
    let v = v.ok_or(PersistError::MissingField)?;
    if v != COMMAND_SCHEMA_VERSION {
        return Err(PersistError::InvalidVersion);
    }
    let op = op.ok_or(PersistError::MissingField)?;
    match op.as_str() {
        OP_CREATE_USER => Ok(Command::CreateUser {
            user_id: UserId::from_bytes(user_id.ok_or(PersistError::MissingField)?),
        }),
        OP_CREATE_IDENTITY => Ok(Command::CreateIdentity {
            user_id: UserId::from_bytes(user_id.ok_or(PersistError::MissingField)?),
            identity_id: IdentityId::from_bytes(identity_id.ok_or(PersistError::MissingField)?),
            encryption: IdentityKemKeypair::from_parts(
                encryption_pk.ok_or(PersistError::MissingField)?,
                encryption_sk.ok_or(PersistError::MissingField)?,
            ),
            signing: IdentitySignKeypair::from_parts(
                signing_pk.ok_or(PersistError::MissingField)?,
                signing_sk.ok_or(PersistError::MissingField)?,
            ),
        }),
        OP_DELETE_USER => Ok(Command::DeleteUser {
            user_id: UserId::from_bytes(user_id.ok_or(PersistError::MissingField)?),
        }),
        OP_DELETE_IDENTITY => Ok(Command::DeleteIdentity {
            user_id: UserId::from_bytes(user_id.ok_or(PersistError::MissingField)?),
            identity_id: IdentityId::from_bytes(identity_id.ok_or(PersistError::MissingField)?),
        }),
        OP_DELETE_CONVERSATION => Ok(Command::DeleteConversation {
            user_id: UserId::from_bytes(user_id.ok_or(PersistError::MissingField)?),
            identity_id: IdentityId::from_bytes(identity_id.ok_or(PersistError::MissingField)?),
            conversation_id: ConversationId::from_bytes(
                conversation_id.ok_or(PersistError::MissingField)?,
            ),
        }),
        OP_SET_DISPLAY_NAME => Ok(Command::SetDisplayName {
            user_id: UserId::from_bytes(user_id.ok_or(PersistError::MissingField)?),
            identity_id: IdentityId::from_bytes(identity_id.ok_or(PersistError::MissingField)?),
            name: DisplayName::try_from(name.ok_or(PersistError::MissingField)?.as_str())
                .map_err(PersistError::DisplayName)?,
        }),
        OP_UNSET_DISPLAY_NAME => Ok(Command::UnsetDisplayName {
            user_id: UserId::from_bytes(user_id.ok_or(PersistError::MissingField)?),
            identity_id: IdentityId::from_bytes(identity_id.ok_or(PersistError::MissingField)?),
        }),
        OP_CREATE_INVITE => {
            let ticket = engine
                .try_parse_ticket(&ticket.ok_or(PersistError::MissingField)?)
                .map_err(PersistError::Ticket)?;
            let keys = IntakeKeypair::from_parts(
                intake_pk.ok_or(PersistError::MissingField)?,
                intake_sk.ok_or(PersistError::MissingField)?,
            );
            let intake = Intake::from_parts(
                keys,
                mailboxes.ok_or(PersistError::MissingField)?,
                wires.ok_or(PersistError::MissingField)?,
            )
            .map_err(PersistError::Intake)?;
            Ok(Command::CreateInvite {
                user_id: UserId::from_bytes(user_id.ok_or(PersistError::MissingField)?),
                identity_id: IdentityId::from_bytes(identity_id.ok_or(PersistError::MissingField)?),
                conversation_id: ConversationId::from_bytes(
                    conversation_id.ok_or(PersistError::MissingField)?,
                ),
                invite: Invite::from_parts(ticket, intake),
            })
        }
        OP_MARK_NOTICES_PINNED => Ok(Command::MarkNoticesPinned {
            user_id: UserId::from_bytes(user_id.ok_or(PersistError::MissingField)?),
            identity_id: IdentityId::from_bytes(identity_id.ok_or(PersistError::MissingField)?),
            conversation_id: ConversationId::from_bytes(
                conversation_id.ok_or(PersistError::MissingField)?,
            ),
        }),
        OP_RECEIVE_TICKET => {
            let ticket = engine
                .try_parse_ticket(&ticket.ok_or(PersistError::MissingField)?)
                .map_err(PersistError::Ticket)?;
            Ok(Command::ReceiveTicket {
                user_id: UserId::from_bytes(user_id.ok_or(PersistError::MissingField)?),
                identity_id: IdentityId::from_bytes(identity_id.ok_or(PersistError::MissingField)?),
                conversation_id: ConversationId::from_bytes(
                    conversation_id.ok_or(PersistError::MissingField)?,
                ),
                ticket,
            })
        }
        OP_RECEIVE_NOTICE => {
            let notice =
                notice::notice_from_json(engine, notice.ok_or(PersistError::MissingField)?)
                    .map_err(PersistError::Notice)?;
            Ok(Command::ReceiveNotice {
                user_id: UserId::from_bytes(user_id.ok_or(PersistError::MissingField)?),
                identity_id: IdentityId::from_bytes(identity_id.ok_or(PersistError::MissingField)?),
                conversation_id: ConversationId::from_bytes(
                    conversation_id.ok_or(PersistError::MissingField)?,
                ),
                notice,
            })
        }
        OP_FAIL_CONVERSATION => {
            let reason = reason.ok_or(PersistError::MissingField)?;
            if reason != REASON_POLICY_NOT_ACCEPTED {
                return Err(PersistError::UnknownOp);
            }
            let ticket = engine
                .try_parse_ticket(&ticket.ok_or(PersistError::MissingField)?)
                .map_err(PersistError::Ticket)?;
            let notice =
                notice::notice_from_json(engine, notice.ok_or(PersistError::MissingField)?)
                    .map_err(PersistError::Notice)?;
            Ok(Command::FailConversation {
                user_id: UserId::from_bytes(user_id.ok_or(PersistError::MissingField)?),
                identity_id: IdentityId::from_bytes(identity_id.ok_or(PersistError::MissingField)?),
                conversation_id: ConversationId::from_bytes(
                    conversation_id.ok_or(PersistError::MissingField)?,
                ),
                failed: Failed::PolicyNotAccepted { ticket, notice },
            })
        }
        OP_CREATE_CALLING_CARD => {
            let card = CallingCard::from_parts(
                DisplayName::try_from(name.ok_or(PersistError::MissingField)?.as_str())
                    .map_err(PersistError::DisplayName)?,
                encryption_pk.ok_or(PersistError::MissingField)?,
                signing_pk.ok_or(PersistError::MissingField)?,
                mailbox_tag_key.ok_or(PersistError::MissingField)?,
                mailboxes.ok_or(PersistError::MissingField)?,
                wires.ok_or(PersistError::MissingField)?,
            )
            .map_err(PersistError::CallingCard)?;
            Ok(Command::CreateCallingCard {
                user_id: UserId::from_bytes(user_id.ok_or(PersistError::MissingField)?),
                identity_id: IdentityId::from_bytes(identity_id.ok_or(PersistError::MissingField)?),
                conversation_id: ConversationId::from_bytes(
                    conversation_id.ok_or(PersistError::MissingField)?,
                ),
                card,
            })
        }
        _ => Err(PersistError::UnknownOp),
    }
}

fn expect_string(value: Json) -> Result<String, PersistError> {
    match value {
        Json::String(s) => Ok(s),
        _ => Err(PersistError::Type),
    }
}

fn parse_id(engine: &Engine, value: Json) -> Result<[u8; 32], PersistError> {
    let bytes = parse_b64(engine, value)?;
    bytes.try_into().map_err(|_| PersistError::InvalidId)
}

fn parse_b64(engine: &Engine, value: Json) -> Result<Vec<u8>, PersistError> {
    let s = expect_string(value)?;
    engine
        .b64u()
        .decode(&s)
        .map_err(|_| PersistError::InvalidId)
}

fn parse_tag_key(engine: &Engine, value: Json) -> Result<MailboxTagKey, PersistError> {
    let bytes = parse_b64(engine, value)?;
    let arr: [u8; SECRET_LEN] = bytes.try_into().map_err(|_| PersistError::InvalidId)?;
    Ok(MailboxTagKey::from_bytes(arr))
}

fn parse_mailboxes(value: Json) -> Result<Vec<Mailbox>, PersistError> {
    let Json::Array(items) = value else {
        return Err(PersistError::Type);
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let (kind, address) = parse_channel_object(item)?;
        let kind = MailboxKind::try_from(kind.as_str()).map_err(|_| PersistError::Type)?;
        let address = MailboxAddress::try_from(address.as_str()).map_err(|_| PersistError::Type)?;
        out.push(Mailbox::new(kind, address));
    }
    Ok(out)
}

fn parse_wires(value: Json) -> Result<Vec<Wire>, PersistError> {
    let Json::Array(items) = value else {
        return Err(PersistError::Type);
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let (kind, address) = parse_channel_object(item)?;
        let kind = WireKind::try_from(kind.as_str()).map_err(|_| PersistError::Type)?;
        let address = WireAddress::try_from(address.as_str()).map_err(|_| PersistError::Type)?;
        out.push(Wire::new(kind, address));
    }
    Ok(out)
}

fn parse_channel_object(value: Json) -> Result<(String, String), PersistError> {
    let Json::Object(members) = value else {
        return Err(PersistError::Type);
    };
    let mut kind = None;
    let mut address = None;
    for (key, value) in members {
        match key.as_str() {
            KEY_KIND => kind = Some(expect_string(value)?),
            KEY_ADDRESS => address = Some(expect_string(value)?),
            _ => return Err(PersistError::UnknownField),
        }
    }
    Ok((
        kind.ok_or(PersistError::MissingField)?,
        address.ok_or(PersistError::MissingField)?,
    ))
}
