//! Notice: Billboard body sealed with keys derived from a [`Ticket`].

use super::{
    AeadError, AeadKey, AeadNonce, CanonicalJsonError, CompressError, ENVELOPE_VERSION, Engine,
    INFO_NOTICE_AEAD_KEY, INFO_NOTICE_AEAD_NONCE, INVITE_KIND_DM, Intake, Json, MAILBOX_MAX_COUNT,
    Mailbox, MailboxAddress, MailboxKind, NOTICE_MAX_B64U_LEN, NOTICE_MAX_COMPRESSED,
    NOTICE_MAX_UNCOMPRESSED, Ticket, WIRE_MAX_COUNT, Wire, WireAddress, WireKind, hmac,
    intake_pk_len,
};
use crate::protocol::Policy;

const POLICY_CLASSIC: &str = "Classic";
const POLICY_POST_QUANTUM: &str = "PostQuantum";
const POLICY_HYBRID: &str = "Hybrid";
const KEY_POLICY: &str = "policy";
const KEY_INTAKE_PK: &str = "intake_pk";
const KEY_MAILBOXES: &str = "mailboxes";
const KEY_WIRES: &str = "wires";
const KEY_KIND: &str = "kind";
const KEY_ADDRESS: &str = "address";

/// Failure while constructing or parsing a [`Notice`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NoticeError {
    /// Host string longer than [`NOTICE_MAX_B64U_LEN`].
    TooLong,
    /// Empty after base64url decode.
    Empty,
    /// Base64url decode failed.
    Base64(super::Base64UrlError),
    /// AEAD open failed.
    Aead(AeadError),
    /// Inflate failed.
    Compress(super::CompressError),
    /// Canonical JSON failed.
    Json(CanonicalJsonError),
    /// `policy` does not match the bound engine.
    PolicyMismatch,
    /// `policy` was missing or not a known variant.
    InvalidPolicy,
    /// A required member was missing.
    MissingField,
    /// An unknown member was present.
    UnknownField,
    /// Mailbox list is empty.
    EmptyMailboxes,
    /// Mailbox count exceeds [`MAILBOX_MAX_COUNT`].
    TooManyMailboxes,
    /// Wire count exceeds [`WIRE_MAX_COUNT`].
    TooManyWires,
    /// A mailbox kind/address failed branding.
    Mailbox,
    /// A wire kind/address failed branding.
    Wire,
    /// `intake_pk` was missing or not valid b64u.
    IntakePk,
    /// JSON root was not an object, or a member had the wrong type.
    Type,
}

impl core::fmt::Display for NoticeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLong => write!(f, "notice blob longer than {NOTICE_MAX_B64U_LEN} chars"),
            Self::Empty => f.write_str("notice blob is empty"),
            Self::Base64(err) => write!(f, "notice blob: {err}"),
            Self::Aead(err) => write!(f, "notice blob: {err}"),
            Self::Compress(err) => write!(f, "notice blob: {err}"),
            Self::Json(err) => write!(f, "notice blob: {err}"),
            Self::PolicyMismatch => f.write_str("notice policy does not match engine"),
            Self::InvalidPolicy => f.write_str("notice policy is invalid"),
            Self::MissingField => f.write_str("notice json is missing a member"),
            Self::UnknownField => f.write_str("notice json has an unknown member"),
            Self::EmptyMailboxes => f.write_str("notice has no Mailboxes"),
            Self::TooManyMailboxes => f.write_str("notice has too many Mailboxes"),
            Self::TooManyWires => f.write_str("notice has too many Wires"),
            Self::Mailbox => f.write_str("notice mailbox is invalid"),
            Self::Wire => f.write_str("notice wire is invalid"),
            Self::IntakePk => f.write_str("notice intake_pk is invalid"),
            Self::Type => f.write_str("notice json has the wrong type"),
        }
    }
}

impl std::error::Error for NoticeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Base64(err) => Some(err),
            Self::Aead(err) => Some(err),
            Self::Compress(err) => Some(err),
            Self::Json(err) => Some(err),
            Self::TooLong
            | Self::Empty
            | Self::PolicyMismatch
            | Self::InvalidPolicy
            | Self::MissingField
            | Self::UnknownField
            | Self::EmptyMailboxes
            | Self::TooManyMailboxes
            | Self::TooManyWires
            | Self::Mailbox
            | Self::Wire
            | Self::IntakePk
            | Self::Type => None,
        }
    }
}

/// Billboard plaintext: Policy, Intake public key, Mailboxes, and Wires.
#[derive(Clone)]
pub struct Notice {
    policy: Policy,
    intake_pk: Vec<u8>,
    mailboxes: Vec<Mailbox>,
    wires: Vec<Wire>,
}

impl Notice {
    pub(crate) fn from_parts(
        policy: Policy,
        intake_pk: Vec<u8>,
        mailboxes: Vec<Mailbox>,
        wires: Vec<Wire>,
    ) -> Result<Self, NoticeError> {
        if mailboxes.is_empty() {
            return Err(NoticeError::EmptyMailboxes);
        }
        if mailboxes.len() > MAILBOX_MAX_COUNT {
            return Err(NoticeError::TooManyMailboxes);
        }
        if wires.len() > WIRE_MAX_COUNT {
            return Err(NoticeError::TooManyWires);
        }
        Ok(Self {
            policy,
            intake_pk,
            mailboxes,
            wires,
        })
    }

    pub(crate) fn from_intake(policy: Policy, intake: &Intake) -> Self {
        Self::from_parts(
            policy,
            intake.public_bytes().to_vec(),
            intake.mailboxes().to_vec(),
            intake.wires().to_vec(),
        )
        .expect("Intake already checked mailbox and wire counts")
    }

    /// Crypto policy published in this Notice.
    #[must_use]
    pub const fn policy(&self) -> Policy {
        self.policy
    }

    /// Intake public-key bytes.
    #[must_use]
    pub fn intake_pk(&self) -> &[u8] {
        &self.intake_pk
    }

    /// Mailboxes the invitee uses for the calling card.
    #[must_use]
    pub fn mailboxes(&self) -> &[Mailbox] {
        &self.mailboxes
    }

    /// Wires the invitee may open.
    #[must_use]
    pub fn wires(&self) -> &[Wire] {
        &self.wires
    }

    /// `b64u(AES-256-GCM(deflate(RFC 8785 JSON)))`.
    #[must_use]
    pub(crate) fn serialize(&self, engine: &Engine, ticket: &Ticket) -> String {
        let json = self.to_json(engine);
        let canonical = engine.canonical_json().encode(&json);
        let plain = engine.compress().compress(&canonical);
        let ct = engine.aead().seal(
            &notice_key(engine, ticket),
            &notice_nonce(engine, ticket),
            &notice_aad(),
            &plain,
        );
        engine.b64u().encode(&ct)
    }

    fn to_json(&self, engine: &Engine) -> Json {
        let b64u = engine.b64u();
        Json::Object(vec![
            (
                KEY_POLICY.into(),
                Json::String(policy_str(self.policy).into()),
            ),
            (
                KEY_INTAKE_PK.into(),
                Json::String(b64u.encode(&self.intake_pk)),
            ),
            (
                KEY_MAILBOXES.into(),
                channels_json(&self.mailboxes, |m| {
                    (m.kind().as_str(), m.address().as_str())
                }),
            ),
            (
                KEY_WIRES.into(),
                channels_json(&self.wires, |w| (w.kind().as_str(), w.address().as_str())),
            ),
        ])
    }
}

impl PartialEq for Notice {
    fn eq(&self, other: &Self) -> bool {
        self.policy == other.policy
            && self.intake_pk == other.intake_pk
            && self.mailboxes == other.mailboxes
            && self.wires == other.wires
    }
}

impl Eq for Notice {}

impl core::fmt::Debug for Notice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Notice")
            .field("policy", &self.policy)
            .field("intake_pk", &"..")
            .field("mailboxes", &self.mailboxes)
            .field("wires", &self.wires)
            .finish()
    }
}

pub(crate) fn try_parse_notice(
    engine: &Engine,
    ticket: &Ticket,
    s: &str,
) -> Result<Notice, NoticeError> {
    if s.len() > NOTICE_MAX_B64U_LEN {
        return Err(NoticeError::TooLong);
    }
    let ct = engine.b64u().decode(s).map_err(NoticeError::Base64)?;
    if ct.is_empty() {
        return Err(NoticeError::Empty);
    }
    let plain = engine
        .aead()
        .open(
            &notice_key(engine, ticket),
            &notice_nonce(engine, ticket),
            &notice_aad(),
            &ct,
        )
        .map_err(NoticeError::Aead)?;
    if plain.len() > NOTICE_MAX_COMPRESSED {
        return Err(NoticeError::Compress(CompressError::Oversize));
    }
    let canonical = engine
        .compress()
        .decompress(&plain, NOTICE_MAX_UNCOMPRESSED)
        .map_err(NoticeError::Compress)?;
    let json = engine
        .canonical_json()
        .decode(&canonical)
        .map_err(NoticeError::Json)?;
    let notice = notice_from_json(engine, json)?;
    if notice.policy != engine.policy() {
        return Err(NoticeError::PolicyMismatch);
    }
    if notice.intake_pk.len() != intake_pk_len(notice.policy) {
        return Err(NoticeError::IntakePk);
    }
    Ok(notice)
}

fn notice_from_json(engine: &Engine, json: Json) -> Result<Notice, NoticeError> {
    let Json::Object(members) = json else {
        return Err(NoticeError::Type);
    };
    let mut policy = None;
    let mut intake_pk = None;
    let mut mailboxes = None;
    let mut wires = None;
    for (key, value) in members {
        match key.as_str() {
            KEY_POLICY => policy = Some(parse_policy(value)?),
            KEY_INTAKE_PK => intake_pk = Some(parse_intake_pk(engine, value)?),
            KEY_MAILBOXES => mailboxes = Some(parse_mailboxes(value)?),
            KEY_WIRES => wires = Some(parse_wires(value)?),
            _ => return Err(NoticeError::UnknownField),
        }
    }
    let policy = policy.ok_or(NoticeError::MissingField)?;
    let intake_pk = intake_pk.ok_or(NoticeError::MissingField)?;
    let mailboxes = mailboxes.ok_or(NoticeError::MissingField)?;
    let wires = wires.ok_or(NoticeError::MissingField)?;
    Notice::from_parts(policy, intake_pk, mailboxes, wires)
}

fn parse_policy(value: Json) -> Result<Policy, NoticeError> {
    let Json::String(s) = value else {
        return Err(NoticeError::Type);
    };
    match s.as_str() {
        POLICY_CLASSIC => Ok(Policy::Classic),
        POLICY_POST_QUANTUM => Ok(Policy::PostQuantum),
        POLICY_HYBRID => Ok(Policy::Hybrid),
        _ => Err(NoticeError::InvalidPolicy),
    }
}

fn parse_intake_pk(engine: &Engine, value: Json) -> Result<Vec<u8>, NoticeError> {
    let Json::String(s) = value else {
        return Err(NoticeError::Type);
    };
    engine.b64u().decode(&s).map_err(|_| NoticeError::IntakePk)
}

fn parse_mailboxes(value: Json) -> Result<Vec<Mailbox>, NoticeError> {
    let Json::Array(items) = value else {
        return Err(NoticeError::Type);
    };
    if items.len() > MAILBOX_MAX_COUNT {
        return Err(NoticeError::TooManyMailboxes);
    }
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let (kind, address) = parse_channel_object(item)?;
        let kind = MailboxKind::try_from(kind.as_str()).map_err(|_| NoticeError::Mailbox)?;
        let address =
            MailboxAddress::try_from(address.as_str()).map_err(|_| NoticeError::Mailbox)?;
        out.push(Mailbox::new(kind, address));
    }
    Ok(out)
}

fn parse_wires(value: Json) -> Result<Vec<Wire>, NoticeError> {
    let Json::Array(items) = value else {
        return Err(NoticeError::Type);
    };
    if items.len() > WIRE_MAX_COUNT {
        return Err(NoticeError::TooManyWires);
    }
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let (kind, address) = parse_channel_object(item)?;
        let kind = WireKind::try_from(kind.as_str()).map_err(|_| NoticeError::Wire)?;
        let address = WireAddress::try_from(address.as_str()).map_err(|_| NoticeError::Wire)?;
        out.push(Wire::new(kind, address));
    }
    Ok(out)
}

fn parse_channel_object(value: Json) -> Result<(String, String), NoticeError> {
    let Json::Object(members) = value else {
        return Err(NoticeError::Type);
    };
    let mut kind = None;
    let mut address = None;
    for (key, value) in members {
        match key.as_str() {
            KEY_KIND => {
                let Json::String(s) = value else {
                    return Err(NoticeError::Type);
                };
                kind = Some(s);
            }
            KEY_ADDRESS => {
                let Json::String(s) = value else {
                    return Err(NoticeError::Type);
                };
                address = Some(s);
            }
            _ => return Err(NoticeError::UnknownField),
        }
    }
    Ok((
        kind.ok_or(NoticeError::MissingField)?,
        address.ok_or(NoticeError::MissingField)?,
    ))
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

fn policy_str(policy: Policy) -> &'static str {
    match policy {
        Policy::Classic => POLICY_CLASSIC,
        Policy::PostQuantum => POLICY_POST_QUANTUM,
        Policy::Hybrid => POLICY_HYBRID,
    }
}

fn notice_key(engine: &Engine, ticket: &Ticket) -> AeadKey {
    AeadKey::from_bytes(
        *hmac::expand(engine.hmac(), &ticket.hmac_key(), INFO_NOTICE_AEAD_KEY).as_bytes(),
    )
}

fn notice_nonce(engine: &Engine, ticket: &Ticket) -> AeadNonce {
    let mac = hmac::expand(engine.hmac(), &ticket.hmac_key(), INFO_NOTICE_AEAD_NONCE);
    AeadNonce::from_bytes(core::array::from_fn(|i| mac.as_bytes()[i]))
}

fn notice_aad() -> [u8; 2] {
    [ENVELOPE_VERSION, INVITE_KIND_DM]
}

#[cfg(test)]
mod tests {
    use super::{NoticeError, notice_aad, parse_policy};
    use crate::protocol::v1::{Json, MAILBOX_MAX_COUNT, WIRE_MAX_COUNT};

    #[test]
    fn notice_error_display() {
        assert_eq!(format!("{}", NoticeError::Empty), "notice blob is empty");
        assert_eq!(
            format!("{}", NoticeError::PolicyMismatch),
            "notice policy does not match engine"
        );
        assert_eq!(
            format!("{}", NoticeError::InvalidPolicy),
            "notice policy is invalid"
        );
        assert_eq!(
            format!("{}", NoticeError::MissingField),
            "notice json is missing a member"
        );
        assert_eq!(
            format!("{}", NoticeError::UnknownField),
            "notice json has an unknown member"
        );
        assert_eq!(
            format!("{}", NoticeError::EmptyMailboxes),
            "notice has no Mailboxes"
        );
        assert_eq!(
            format!("{}", NoticeError::TooManyMailboxes),
            "notice has too many Mailboxes"
        );
        assert_eq!(
            format!("{}", NoticeError::TooManyWires),
            "notice has too many Wires"
        );
        assert_eq!(
            format!("{}", NoticeError::Mailbox),
            "notice mailbox is invalid"
        );
        assert_eq!(format!("{}", NoticeError::Wire), "notice wire is invalid");
        assert_eq!(
            format!("{}", NoticeError::IntakePk),
            "notice intake_pk is invalid"
        );
        assert_eq!(
            format!("{}", NoticeError::Type),
            "notice json has the wrong type"
        );
        assert!(std::error::Error::source(&NoticeError::Empty).is_none());
        assert_eq!(notice_aad(), [0xC1, 0x01]);
        assert!(parse_policy(Json::Bool(true)).is_err());
        assert_eq!(
            parse_policy(Json::String("nope".into())).unwrap_err(),
            NoticeError::InvalidPolicy
        );
        let _ = MAILBOX_MAX_COUNT;
        let _ = WIRE_MAX_COUNT;
        let _ = NoticeError::TooLong;
    }

    #[test]
    fn notice_from_json_error_table() {
        use super::{notice_from_json, parse_channel_object, parse_mailboxes, parse_wires};
        use crate::protocol::v1::fixtures;
        let engine = fixtures::test_engine();
        assert_eq!(
            notice_from_json(&engine, Json::Null).unwrap_err(),
            NoticeError::Type
        );
        assert_eq!(
            notice_from_json(&engine, Json::Object(vec![("nope".into(), Json::Null)])).unwrap_err(),
            NoticeError::UnknownField
        );
        assert_eq!(
            notice_from_json(&engine, Json::Object(Vec::new())).unwrap_err(),
            NoticeError::MissingField
        );
        let mailbox = Json::Object(vec![
            ("kind".into(), Json::String("nostr".into())),
            (
                "address".into(),
                Json::String("wss://mailbox.example".into()),
            ),
        ]);
        let body = Json::Object(vec![
            ("policy".into(), Json::String("Hybrid".into())),
            ("intake_pk".into(), Json::String("00".into())),
            ("mailboxes".into(), Json::Array(vec![mailbox.clone()])),
            ("wires".into(), Json::Array(Vec::new())),
        ]);
        let notice = notice_from_json(&engine, body).expect("notice");
        assert_eq!(notice.policy(), crate::protocol::Policy::Hybrid);
        assert_eq!(notice.intake_pk(), &[0x00]);
        assert_eq!(notice.mailboxes().len(), 1);
        assert!(notice.wires().is_empty());
        assert_eq!(
            parse_mailboxes(Json::Bool(true)).unwrap_err(),
            NoticeError::Type
        );
        assert_eq!(
            parse_wires(Json::Bool(true)).unwrap_err(),
            NoticeError::Type
        );
        assert_eq!(
            parse_channel_object(Json::Null).unwrap_err(),
            NoticeError::Type
        );
        assert_eq!(
            parse_channel_object(Json::Object(vec![("x".into(), Json::Null)])).unwrap_err(),
            NoticeError::UnknownField
        );
        assert_eq!(
            parse_mailboxes(Json::Array(vec![Json::Object(vec![(
                "kind".into(),
                Json::Bool(true)
            ),])]))
            .unwrap_err(),
            NoticeError::Type
        );
        assert_eq!(
            parse_mailboxes(Json::Array(vec![Json::Object(vec![
                ("kind".into(), Json::String("Nostr".into())),
                (
                    "address".into(),
                    Json::String("wss://mailbox.example".into())
                ),
            ])]))
            .unwrap_err(),
            NoticeError::Mailbox
        );
        assert_eq!(
            parse_wires(Json::Array(vec![Json::Object(vec![
                ("kind".into(), Json::String("webrtc".into())),
                ("address".into(), Json::String(String::new())),
            ])]))
            .unwrap_err(),
            NoticeError::Wire
        );
        assert_eq!(
            parse_wires(Json::Array(vec![Json::Object(vec![
                ("kind".into(), Json::String("webrtc".into())),
                ("address".into(), Json::String("stun:stun.example".into())),
            ])]))
            .expect("wire")
            .len(),
            1
        );
        let many_m = vec![fixtures::sample_mailbox(); MAILBOX_MAX_COUNT + 1];
        assert_eq!(
            super::Notice::from_parts(
                crate::protocol::Policy::Hybrid,
                vec![0],
                many_m,
                Vec::new(),
            )
            .unwrap_err(),
            NoticeError::TooManyMailboxes
        );
        let many_w = vec![fixtures::sample_wire(); WIRE_MAX_COUNT + 1];
        assert_eq!(
            super::Notice::from_parts(
                crate::protocol::Policy::Hybrid,
                vec![0],
                vec![fixtures::sample_mailbox()],
                many_w,
            )
            .unwrap_err(),
            NoticeError::TooManyWires
        );
        assert_eq!(
            format!(
                "{}",
                NoticeError::Aead(crate::protocol::v1::AeadError::Open)
            ),
            format!("notice blob: {}", crate::protocol::v1::AeadError::Open)
        );
        assert_eq!(
            format!(
                "{}",
                NoticeError::Compress(crate::protocol::v1::CompressError::Codec)
            ),
            format!("notice blob: {}", crate::protocol::v1::CompressError::Codec)
        );
        assert_eq!(
            format!(
                "{}",
                NoticeError::Json(crate::protocol::v1::CanonicalJsonError::Invalid)
            ),
            format!(
                "notice blob: {}",
                crate::protocol::v1::CanonicalJsonError::Invalid
            )
        );
        let _ = notice.clone();
        assert_eq!(notice, notice.clone());
        let too_many = vec![mailbox; MAILBOX_MAX_COUNT + 1];
        assert_eq!(
            parse_mailboxes(Json::Array(too_many)).unwrap_err(),
            NoticeError::TooManyMailboxes
        );
        let wire = Json::Object(vec![
            ("kind".into(), Json::String("webrtc".into())),
            ("address".into(), Json::String("stun:stun.example".into())),
        ]);
        let too_many_w = vec![wire; WIRE_MAX_COUNT + 1];
        assert_eq!(
            parse_wires(Json::Array(too_many_w)).unwrap_err(),
            NoticeError::TooManyWires
        );
        assert_eq!(
            parse_mailboxes(Json::Array(Vec::new()))
                .expect("empty list parses")
                .len(),
            0
        );
        assert!(
            std::error::Error::source(&NoticeError::Base64(
                crate::protocol::v1::Base64UrlError::Invalid
            ))
            .is_some()
        );
        assert!(
            std::error::Error::source(&NoticeError::Aead(crate::protocol::v1::AeadError::Open))
                .is_some()
        );
        assert!(
            std::error::Error::source(&NoticeError::Compress(
                crate::protocol::v1::CompressError::Codec
            ))
            .is_some()
        );
        assert!(
            std::error::Error::source(&NoticeError::Json(
                crate::protocol::v1::CanonicalJsonError::Invalid
            ))
            .is_some()
        );
        assert_eq!(
            format!("{}", NoticeError::TooLong),
            format!(
                "notice blob longer than {} chars",
                crate::protocol::v1::NOTICE_MAX_B64U_LEN
            )
        );
        assert!(
            format!(
                "{}",
                NoticeError::Base64(crate::protocol::v1::Base64UrlError::Invalid)
            )
            .contains("notice blob:")
        );
        assert_eq!(
            notice_from_json(
                &engine,
                Json::Object(vec![
                    ("policy".into(), Json::String("Classic".into())),
                    ("intake_pk".into(), Json::String("00".into())),
                    ("mailboxes".into(), Json::Array(Vec::new())),
                    ("wires".into(), Json::Array(Vec::new())),
                ])
            )
            .unwrap_err(),
            NoticeError::EmptyMailboxes
        );
        assert_eq!(
            super::parse_intake_pk(&engine, Json::Bool(true)).unwrap_err(),
            NoticeError::Type
        );
        assert_eq!(
            super::parse_intake_pk(&engine, Json::String("0g".into())).unwrap_err(),
            NoticeError::IntakePk
        );
        assert_eq!(
            parse_channel_object(Json::Object(vec![(
                "kind".into(),
                Json::String("nostr".into())
            )]))
            .unwrap_err(),
            NoticeError::MissingField
        );
        assert_eq!(
            parse_channel_object(Json::Object(vec![("address".into(), Json::Bool(true))]))
                .unwrap_err(),
            NoticeError::Type
        );
        assert_eq!(
            parse_policy(Json::String("Classic".into())).expect("classic"),
            crate::protocol::Policy::Classic
        );
        assert_eq!(
            parse_policy(Json::String("PostQuantum".into())).expect("pq"),
            crate::protocol::Policy::PostQuantum
        );
    }

    #[test]
    fn notice_rejects_oversize_compressed_plain() {
        use crate::protocol::Policy;
        use crate::protocol::v1::{
            Aead, AeadError, AeadKey, AeadNonce, NOTICE_MAX_COMPRESSED, Suite, Ticket, fixtures,
        };
        use std::sync::Arc;

        struct ExpandingOpenAead;

        impl Aead for ExpandingOpenAead {
            fn seal(
                &self,
                _key: &AeadKey,
                _nonce: &AeadNonce,
                _aad: &[u8],
                plaintext: &[u8],
            ) -> Vec<u8> {
                plaintext.to_vec()
            }

            fn open(
                &self,
                _key: &AeadKey,
                _nonce: &AeadNonce,
                _aad: &[u8],
                _ciphertext: &[u8],
            ) -> Result<Vec<u8>, AeadError> {
                Ok(vec![0; NOTICE_MAX_COMPRESSED + 1])
            }
        }

        let nonce = AeadNonce::from_bytes(core::array::from_fn(|i| i as u8));
        let _ = ExpandingOpenAead.seal(&AeadKey::from_bytes([7u8; 32]), &nonce, b"", b"x");

        let engine = crate::protocol::v1::Engine::new(
            Suite::new(
                Arc::new(fixtures::XorHmac),
                Arc::new(fixtures::IdentityCompress),
                Arc::new(fixtures::HexB64),
                Arc::new(ExpandingOpenAead),
                Arc::new(fixtures::DetJson),
                Arc::new(fixtures::EchoKem),
            ),
            Policy::Hybrid,
        );
        let ticket = Ticket::from_parts(fixtures::fill(1), vec![fixtures::sample_billboard()])
            .expect("ticket");
        let blob = engine.b64u().encode(&[0x01]);
        assert_eq!(
            engine.try_parse_notice(&ticket, &blob).unwrap_err(),
            NoticeError::Compress(crate::protocol::v1::CompressError::Oversize)
        );
    }

    #[test]
    fn parse_rejects_wrong_intake_pk_len() {
        use crate::protocol::Policy;
        use crate::protocol::v1::fixtures;
        let engine = fixtures::test_engine();
        let ticket = crate::protocol::v1::Ticket::from_parts(
            fixtures::fill(1),
            vec![fixtures::sample_billboard()],
        )
        .expect("ticket");
        let notice = super::Notice::from_parts(
            Policy::Hybrid,
            vec![0x00],
            vec![fixtures::sample_mailbox()],
            Vec::new(),
        )
        .expect("notice");
        assert_eq!(notice, notice);
        let debug = format!("{notice:?}");
        assert!(debug.starts_with("Notice {"));
        assert!(debug.contains("policy: Hybrid"));
        assert!(debug.contains("intake_pk: \"..\""));
        let blob = notice.serialize(&engine, &ticket);
        assert_eq!(
            engine.try_parse_notice(&ticket, &blob).unwrap_err(),
            NoticeError::IntakePk
        );
    }
}
