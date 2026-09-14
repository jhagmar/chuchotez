//! Ticket, Billboard Tag, Mailbox Tag Key, and the compact Ticket envelope.

use super::{
    ADDRESS_MAX_LEN, BILLBOARD_MAX_COUNT, Billboard, BillboardAddress, BillboardAddressError,
    BillboardKind, BillboardKindError, ENVELOPE_VERSION, Engine, HmacSha256Key, HmacSha256Mac,
    INFO_BILLBOARD_TAG, INFO_MAILBOX_TAG_KEY, INVITE_KIND_DM, KIND_MAX_LEN, PAYLOAD_VERSION,
    SECRET_LEN, TICKET_MAX_B64U_LEN, TICKET_MAX_COMPRESSED, TICKET_MAX_UNCOMPRESSED, hmac,
};
use crate::protocol::bytes32;

/// Why constructing a [`Ticket`] rejected the Billboard list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TicketError {
    /// No Billboard (hosts must pass at least one).
    EmptyBillboards,
    /// More than [`BILLBOARD_MAX_COUNT`].
    TooManyBillboards,
}

impl core::fmt::Display for TicketError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyBillboards => f.write_str("ticket needs at least one Billboard"),
            Self::TooManyBillboards => {
                write!(f, "ticket has more than {BILLBOARD_MAX_COUNT} Billboards")
            }
        }
    }
}

impl std::error::Error for TicketError {}

/// QR capability secret. Used as the HMAC-SHA-256 key for Expand.
#[derive(Clone, Eq)]
pub struct TicketSecret([u8; SECRET_LEN]);

impl TicketSecret {
    /// Wrap [`SECRET_LEN`] capability-secret bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SECRET_LEN]) -> Self {
        Self(bytes)
    }

    /// Secret bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SECRET_LEN] {
        &self.0
    }

    pub(crate) fn as_hmac_key(&self) -> HmacSha256Key {
        HmacSha256Key::from_bytes(self.0)
    }
}

impl PartialEq for TicketSecret {
    fn eq(&self, other: &Self) -> bool {
        bytes32::ct_eq(&self.0, &other.0)
    }
}

impl core::fmt::Debug for TicketSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TicketSecret(..)")
    }
}

/// QR capability: secret bytes plus the Billboards the invitee should fetch.
///
/// Equality compares secret bytes and Billboards.
#[derive(Clone)]
pub struct Ticket {
    secret: TicketSecret,
    billboards: Vec<Billboard>,
}

impl Ticket {
    /// Wrap [`SECRET_LEN`] bytes and a nonempty Billboard list.
    pub(crate) fn from_parts(
        bytes: [u8; SECRET_LEN],
        billboards: Vec<Billboard>,
    ) -> Result<Self, TicketError> {
        if billboards.is_empty() {
            return Err(TicketError::EmptyBillboards);
        }
        if billboards.len() > BILLBOARD_MAX_COUNT {
            return Err(TicketError::TooManyBillboards);
        }
        Ok(Self {
            secret: TicketSecret::from_bytes(bytes),
            billboards,
        })
    }

    pub(crate) const fn secret_bytes(&self) -> &[u8; SECRET_LEN] {
        self.secret.as_bytes()
    }

    pub(crate) fn hmac_key(&self) -> HmacSha256Key {
        self.secret.as_hmac_key()
    }

    /// Billboards the invitee tries in list order.
    #[must_use]
    pub fn billboards(&self) -> &[Billboard] {
        &self.billboards
    }

    /// Billboard Tag via `engine`.
    #[must_use]
    pub fn billboard_tag(&self, engine: &Engine) -> BillboardTag {
        BillboardTag::from_mac(hmac::expand(
            engine.hmac(),
            &self.hmac_key(),
            INFO_BILLBOARD_TAG,
        ))
    }

    /// Mailbox Tag Key via `engine`.
    #[must_use]
    pub fn mailbox_tag_key(&self, engine: &Engine) -> MailboxTagKey {
        MailboxTagKey::from_mac(hmac::expand(
            engine.hmac(),
            &self.hmac_key(),
            INFO_MAILBOX_TAG_KEY,
        ))
    }
}

impl PartialEq for Ticket {
    fn eq(&self, other: &Self) -> bool {
        self.secret == other.secret && self.billboards == other.billboards
    }
}

impl Eq for Ticket {}

impl core::fmt::Debug for Ticket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Ticket(..)")
    }
}

/// Billboard Tag for the Notice, derived from [`Ticket`].
#[derive(Clone, Eq)]
pub struct BillboardTag {
    mac: HmacSha256Mac,
}

impl BillboardTag {
    /// Wrap a derived (or round-tripped) Billboard Tag.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SECRET_LEN]) -> Self {
        Self {
            mac: HmacSha256Mac::from_bytes(bytes),
        }
    }

    pub(crate) const fn from_mac(mac: HmacSha256Mac) -> Self {
        Self { mac }
    }

    /// Billboard Tag bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SECRET_LEN] {
        self.mac.as_bytes()
    }
}

impl PartialEq for BillboardTag {
    fn eq(&self, other: &Self) -> bool {
        self.mac == other.mac
    }
}

impl core::fmt::Debug for BillboardTag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("BillboardTag(..)")
    }
}

/// Mailbox Tag Key: identifies a Message stream. Bins are this key and binned time.
#[derive(Clone, Eq)]
pub struct MailboxTagKey {
    mac: HmacSha256Mac,
}

impl MailboxTagKey {
    /// Wrap a derived Mailbox Tag Key.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SECRET_LEN]) -> Self {
        Self {
            mac: HmacSha256Mac::from_bytes(bytes),
        }
    }

    pub(crate) const fn from_mac(mac: HmacSha256Mac) -> Self {
        Self { mac }
    }

    /// Tag Key bytes for later per-bin Message-bin Expand.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SECRET_LEN] {
        self.mac.as_bytes()
    }
}

impl PartialEq for MailboxTagKey {
    fn eq(&self, other: &Self) -> bool {
        self.mac == other.mac
    }
}

impl core::fmt::Debug for MailboxTagKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MailboxTagKey(..)")
    }
}

/// Failure while parsing canonical uncompressed Ticket bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PayloadError {
    /// No bytes.
    Empty,
    /// First byte is not [`PAYLOAD_VERSION`].
    UnknownVersion(u8),
    /// Input ended before a field.
    Truncated,
    /// Bytes remain after the last Billboard.
    TrailingBytes,
    /// Billboard list is empty.
    EmptyBillboards,
    /// Billboard count exceeds [`BILLBOARD_MAX_COUNT`].
    TooManyBillboards,
    /// A kind field failed [`BillboardKind::try_from`].
    Kind(BillboardKindError),
    /// An address field failed [`BillboardAddress::try_from`].
    Address(BillboardAddressError),
}

impl core::fmt::Display for PayloadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => f.write_str("ticket payload is empty"),
            Self::UnknownVersion(v) => write!(f, "unknown ticket payload version {v}"),
            Self::Truncated => f.write_str("ticket payload is truncated"),
            Self::TrailingBytes => f.write_str("ticket payload has trailing bytes"),
            Self::EmptyBillboards => f.write_str("ticket payload has no Billboards"),
            Self::TooManyBillboards => f.write_str("ticket payload has too many Billboards"),
            Self::Kind(err) => write!(f, "ticket payload kind: {err}"),
            Self::Address(err) => write!(f, "ticket payload address: {err}"),
        }
    }
}

impl std::error::Error for PayloadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Kind(err) => Some(err),
            Self::Address(err) => Some(err),
            Self::Empty
            | Self::UnknownVersion(_)
            | Self::Truncated
            | Self::TrailingBytes
            | Self::EmptyBillboards
            | Self::TooManyBillboards => None,
        }
    }
}

/// Failure while parsing a compact DM Ticket blob.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnvelopeError {
    /// Host string longer than [`TICKET_MAX_B64U_LEN`].
    TooLong,
    /// Empty after base64url decode, or shorter than version plus kind.
    Empty,
    /// First envelope byte is not [`ENVELOPE_VERSION`].
    UnknownVersion(u8),
    /// Kind byte is not [`INVITE_KIND_DM`].
    UnknownKind(u8),
    /// Deflate body longer than [`TICKET_MAX_COMPRESSED`].
    CompressedTooLarge,
    /// Base64url decode failed.
    Base64(super::Base64UrlError),
    /// Inflate failed.
    Compress(super::CompressError),
    /// Inner payload failed.
    Payload(PayloadError),
}

impl core::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLong => write!(f, "ticket blob longer than {TICKET_MAX_B64U_LEN} chars"),
            Self::Empty => f.write_str("ticket blob is empty"),
            Self::UnknownVersion(v) => write!(f, "unknown ticket envelope version {v}"),
            Self::UnknownKind(k) => write!(f, "unknown ticket kind {k}"),
            Self::CompressedTooLarge => f.write_str("ticket compressed body exceeds cap"),
            Self::Base64(err) => write!(f, "ticket blob: {err}"),
            Self::Compress(err) => write!(f, "ticket blob: {err}"),
            Self::Payload(err) => write!(f, "ticket blob: {err}"),
        }
    }
}

impl std::error::Error for EnvelopeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Base64(err) => Some(err),
            Self::Compress(err) => Some(err),
            Self::Payload(err) => Some(err),
            Self::TooLong
            | Self::Empty
            | Self::UnknownVersion(_)
            | Self::UnknownKind(_)
            | Self::CompressedTooLarge => None,
        }
    }
}

struct Cursor<'a> {
    rest: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    fn u8(&mut self) -> Result<u8, PayloadError> {
        let (b, rest) = self.rest.split_first().ok_or(PayloadError::Truncated)?;
        self.rest = rest;
        Ok(*b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], PayloadError> {
        if self.rest.len() < n {
            return Err(PayloadError::Truncated);
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Ok(head)
    }
}

impl Ticket {
    /// Canonical uncompressed bytes (inner version, secret, Billboards).
    #[must_use]
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(TICKET_MAX_UNCOMPRESSED);
        out.push(PAYLOAD_VERSION);
        out.extend_from_slice(self.secret_bytes());
        out.push(u8::try_from(self.billboards().len()).expect("count fits u8"));
        for board in self.billboards() {
            let kind = board.kind().as_str().as_bytes();
            out.push(u8::try_from(kind.len()).expect("kind fits u8"));
            out.extend_from_slice(kind);
            let address = board.address().as_str().as_bytes();
            out.push(u8::try_from(address.len()).expect("address fits u8"));
            out.extend_from_slice(address);
        }
        out
    }

    /// Parse canonical uncompressed bytes.
    pub(crate) fn try_from_bytes(bytes: &[u8]) -> Result<Self, PayloadError> {
        if bytes.is_empty() {
            return Err(PayloadError::Empty);
        }
        if bytes.len() > TICKET_MAX_UNCOMPRESSED {
            return Err(PayloadError::TrailingBytes);
        }
        let mut cur = Cursor::new(bytes);
        let version = cur.u8()?;
        if version != PAYLOAD_VERSION {
            return Err(PayloadError::UnknownVersion(version));
        }
        let secret = cur.take(SECRET_LEN)?;
        let secret: [u8; SECRET_LEN] = secret
            .try_into()
            .expect("take(SECRET_LEN) is SECRET_LEN bytes");
        let count = usize::from(cur.u8()?);
        if count == 0 {
            return Err(PayloadError::EmptyBillboards);
        }
        if count > BILLBOARD_MAX_COUNT {
            return Err(PayloadError::TooManyBillboards);
        }
        let mut billboards = Vec::with_capacity(count);
        for _ in 0..count {
            let kind_len = usize::from(cur.u8()?);
            if kind_len > KIND_MAX_LEN {
                return Err(PayloadError::Kind(BillboardKindError::TooLong));
            }
            let kind_bytes = cur.take(kind_len)?;
            let kind_str = core::str::from_utf8(kind_bytes)
                .map_err(|_| PayloadError::Kind(BillboardKindError::InvalidChar))?;
            let kind = BillboardKind::try_from(kind_str).map_err(PayloadError::Kind)?;
            let addr_len = usize::from(cur.u8()?);
            if addr_len > ADDRESS_MAX_LEN {
                return Err(PayloadError::Address(BillboardAddressError::TooLong));
            }
            let addr_bytes = cur.take(addr_len)?;
            let addr_str = core::str::from_utf8(addr_bytes)
                .map_err(|_| PayloadError::Address(BillboardAddressError::InvalidUtf8))?;
            let address = BillboardAddress::try_from(addr_str).map_err(PayloadError::Address)?;
            billboards.push(Billboard::new(kind, address));
        }
        if !cur.rest.is_empty() {
            return Err(PayloadError::TrailingBytes);
        }
        Ok(Ticket::from_parts(secret, billboards).expect("count already checked"))
    }

    /// QR / link string: unpadded b64u of version, DM kind, and raw Deflate.
    #[must_use]
    pub fn serialize(&self, engine: &Engine) -> String {
        let payload = self.to_bytes();
        let compressed = engine.compress().compress(&payload);
        let mut framed = Vec::with_capacity(2 + compressed.len());
        framed.push(ENVELOPE_VERSION);
        framed.push(INVITE_KIND_DM);
        framed.extend_from_slice(&compressed);
        engine.b64u().encode(&framed)
    }

    /// Parse a compact DM Ticket blob using `engine` codecs.
    pub(crate) fn try_parse(engine: &Engine, s: &str) -> Result<Self, EnvelopeError> {
        if s.len() > TICKET_MAX_B64U_LEN {
            return Err(EnvelopeError::TooLong);
        }
        let framed = engine.b64u().decode(s).map_err(EnvelopeError::Base64)?;
        if framed.len() < 2 {
            return Err(EnvelopeError::Empty);
        }
        let version = framed[0];
        if version != ENVELOPE_VERSION {
            return Err(EnvelopeError::UnknownVersion(version));
        }
        let kind = framed[1];
        if kind != INVITE_KIND_DM {
            return Err(EnvelopeError::UnknownKind(kind));
        }
        let compressed = &framed[2..];
        if compressed.len() > TICKET_MAX_COMPRESSED {
            return Err(EnvelopeError::CompressedTooLarge);
        }
        let payload = engine
            .compress()
            .decompress(compressed, TICKET_MAX_UNCOMPRESSED)
            .map_err(EnvelopeError::Compress)?;
        Self::try_from_bytes(&payload).map_err(EnvelopeError::Payload)
    }
}

#[cfg(test)]
mod tests {
    use super::hmac;
    use super::{BillboardTag, MailboxTagKey, Ticket, TicketError, TicketSecret};
    use crate::protocol::v1::{
        BILLBOARD_MAX_COUNT, Base64Url, Compress, CompressError, SECRET_LEN, fixtures,
    };

    #[test]
    fn from_parts_requires_billboards() {
        assert_eq!(
            Ticket::from_parts(fixtures::fill(1), Vec::new()).unwrap_err(),
            TicketError::EmptyBillboards
        );
        let too_many = vec![fixtures::sample_billboard(); BILLBOARD_MAX_COUNT + 1];
        assert_eq!(
            Ticket::from_parts(fixtures::fill(1), too_many).unwrap_err(),
            TicketError::TooManyBillboards
        );
        let ticket = Ticket::from_parts(fixtures::fill(0xab), vec![fixtures::sample_billboard()])
            .expect("ticket");
        assert_eq!(ticket.secret_bytes(), &fixtures::fill(0xab));
        assert_eq!(ticket.billboards().len(), 1);
        assert_eq!(format!("{ticket:?}"), "Ticket(..)");
        assert!(!format!("{ticket:?}").contains("ab"));
        assert_eq!(
            format!("{}", TicketError::EmptyBillboards),
            "ticket needs at least one Billboard"
        );
        assert_eq!(
            format!("{}", TicketError::TooManyBillboards),
            format!("ticket has more than {BILLBOARD_MAX_COUNT} Billboards")
        );
        let _ = &TicketError::EmptyBillboards as &dyn std::error::Error;
        let _ = ticket.clone();
        let engine = fixtures::test_engine();
        let blob = ticket.serialize(&engine);
        assert_eq!(engine.try_parse_ticket(&blob).expect("parse"), ticket);
        assert!(fixtures::HexB64.decode("a").is_err());
        assert!(fixtures::HexB64.decode("0g").is_err());
        assert_eq!(
            fixtures::IdentityCompress
                .decompress(&[0; 8], 1)
                .unwrap_err(),
            CompressError::Oversize
        );
        let secret = TicketSecret::from_bytes(fixtures::fill(0x11));
        assert_eq!(secret, TicketSecret::from_bytes(fixtures::fill(0x11)));
        assert_ne!(secret, TicketSecret::from_bytes(fixtures::fill(0x22)));
        assert_eq!(secret.as_bytes(), &fixtures::fill(0x11));
        assert_eq!(format!("{secret:?}"), "TicketSecret(..)");
        assert_eq!(secret.clone(), secret);
        let _ = secret.as_hmac_key();
    }

    #[test]
    fn debug_redacts_payloads() {
        let ticket = Ticket::from_parts(fixtures::fill(0xab), vec![fixtures::sample_billboard()])
            .expect("ticket");
        let tag = BillboardTag::from_bytes(fixtures::fill(0xcd));
        let key = MailboxTagKey::from_bytes(fixtures::fill(0xef));
        assert_eq!(format!("{ticket:?}"), "Ticket(..)");
        assert_eq!(format!("{tag:?}"), "BillboardTag(..)");
        assert_eq!(format!("{key:?}"), "MailboxTagKey(..)");
        assert!(!format!("{ticket:?}").contains("ab"));
        assert!(!format!("{tag:?}").contains("cd"));
        assert!(!format!("{key:?}").contains("ef"));
    }

    #[test]
    fn mailbox_tag_key_eq() {
        let a = MailboxTagKey::from_bytes([1; SECRET_LEN]);
        let b = MailboxTagKey::from_bytes([1; SECRET_LEN]);
        let c = MailboxTagKey::from_bytes([2; SECRET_LEN]);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.as_bytes(), &[1; SECRET_LEN]);
        let _ = a.clone();
        let tag_a = BillboardTag::from_bytes([1; SECRET_LEN]);
        let tag_b = BillboardTag::from_bytes([1; SECRET_LEN]);
        let tag_c = BillboardTag::from_bytes([2; SECRET_LEN]);
        assert_eq!(tag_a, tag_b);
        assert_ne!(tag_a, tag_c);
        assert_eq!(tag_a.as_bytes(), &[1; SECRET_LEN]);
        let _ = tag_a.clone();
    }

    #[test]
    fn tag_passes_invite_tag_info_and_counter() {
        use crate::protocol::v1::INFO_BILLBOARD_TAG;
        let hmac = fixtures::RecordingHmac::new();
        let engine = fixtures::engine_with_hmac(hmac.clone());
        let ticket = fixtures::sample_ticket(0x22);
        let _ = ticket.billboard_tag(&engine);
        let recorded = hmac.data.lock().expect("record");
        assert_eq!(&recorded[..INFO_BILLBOARD_TAG.len()], INFO_BILLBOARD_TAG);
        assert_eq!(recorded[INFO_BILLBOARD_TAG.len()], hmac::EXPAND_T1_COUNTER);
    }

    #[test]
    fn mailbox_key_passes_mailbox_info_and_counter() {
        use crate::protocol::v1::INFO_MAILBOX_TAG_KEY;
        let hmac = fixtures::RecordingHmac::new();
        let engine = fixtures::engine_with_hmac(hmac.clone());
        let ticket = fixtures::sample_ticket(0x22);
        let _ = ticket.mailbox_tag_key(&engine);
        let recorded = hmac.data.lock().expect("record");
        assert_eq!(
            &recorded[..INFO_MAILBOX_TAG_KEY.len()],
            INFO_MAILBOX_TAG_KEY
        );
        assert_eq!(
            recorded[INFO_MAILBOX_TAG_KEY.len()],
            hmac::EXPAND_T1_COUNTER
        );
    }

    #[test]
    fn tag_and_mailbox_key_use_distinct_infos() {
        let engine = fixtures::test_engine();
        let ticket = fixtures::sample_ticket(0x22);
        let tag = ticket.billboard_tag(&engine);
        let mailbox_key = ticket.mailbox_tag_key(&engine);
        assert_ne!(tag.as_bytes(), mailbox_key.as_bytes());
        assert_ne!(tag.as_bytes(), &fixtures::fill(0x22));
        let blob = ticket.serialize(&engine);
        assert_eq!(engine.try_parse_ticket(&blob).expect("roundtrip"), ticket);
    }

    #[test]
    fn equal_tickets_compare_equal() {
        let a = fixtures::sample_ticket(7);
        let b = fixtures::sample_ticket(7);
        let c = fixtures::sample_ticket(8);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}

#[cfg(test)]
mod codec_tests {
    use super::{Cursor, EnvelopeError, PayloadError};
    use crate::protocol::v1::{
        ADDRESS_MAX_LEN, BILLBOARD_MAX_COUNT, Base64Url, Base64UrlError, Billboard,
        BillboardAddress, BillboardAddressError, BillboardKind, BillboardKindError, Compress,
        CompressError, ENVELOPE_VERSION, Engine, INVITE_KIND_DM, KIND_MAX_LEN, PAYLOAD_VERSION,
        TICKET_MAX_B64U_LEN, TICKET_MAX_COMPRESSED, TICKET_MAX_UNCOMPRESSED, Ticket, fixtures,
    };
    use std::sync::Arc;

    struct ExpandingCompress;

    impl Compress for ExpandingCompress {
        fn compress(&self, _src: &[u8]) -> Vec<u8> {
            vec![0; TICKET_MAX_COMPRESSED + 1]
        }

        fn decompress(
            &self,
            _src: &[u8],
            _max_uncompressed: usize,
        ) -> Result<Vec<u8>, CompressError> {
            Err(CompressError::Codec)
        }
    }

    struct CodecCompress;

    impl Compress for CodecCompress {
        fn compress(&self, src: &[u8]) -> Vec<u8> {
            src.to_vec()
        }

        fn decompress(
            &self,
            _src: &[u8],
            _max_uncompressed: usize,
        ) -> Result<Vec<u8>, CompressError> {
            Err(CompressError::Codec)
        }
    }

    struct FailB64;

    impl Base64Url for FailB64 {
        fn encode(&self, _src: &[u8]) -> String {
            String::new()
        }

        fn decode(&self, _src: &str) -> Result<Vec<u8>, Base64UrlError> {
            Err(Base64UrlError::Invalid)
        }
    }

    struct HugeDecodeB64;

    impl Base64Url for HugeDecodeB64 {
        fn encode(&self, src: &[u8]) -> String {
            fixtures::HexB64.encode(src)
        }

        fn decode(&self, _src: &str) -> Result<Vec<u8>, Base64UrlError> {
            let mut out = vec![ENVELOPE_VERSION, INVITE_KIND_DM];
            out.extend(vec![0; TICKET_MAX_COMPRESSED + 1]);
            Ok(out)
        }
    }

    fn engine() -> Engine {
        fixtures::test_engine()
    }

    fn secret_on(_engine: &Engine) -> Ticket {
        Ticket::from_parts(fixtures::fill(0x22), vec![fixtures::sample_billboard()])
            .expect("secret")
    }

    fn parse(_engine: &Engine, bytes: &[u8]) -> Result<Ticket, PayloadError> {
        Ticket::try_from_bytes(bytes)
    }

    #[test]
    fn bytes_roundtrip() {
        let engine = engine();
        let secret = secret_on(&engine);
        let bytes = secret.to_bytes();
        assert_eq!(bytes[0], PAYLOAD_VERSION);
        let parsed = parse(&engine, &bytes).expect("parse");
        assert_eq!(parsed, secret);
        let two = Ticket::from_parts(
            fixtures::fill(0x33),
            vec![
                fixtures::sample_billboard(),
                Billboard::new(
                    BillboardKind::try_from("https").expect("kind"),
                    BillboardAddress::try_from("https://billboard.example").expect("addr"),
                ),
            ],
        )
        .expect("two");
        assert_eq!(parse(&engine, &two.to_bytes()).expect("parse"), two);
    }

    #[test]
    fn bytes_error_table() {
        let engine = engine();
        assert_eq!(parse(&engine, &[]).unwrap_err(), PayloadError::Empty);
        assert_eq!(
            parse(&engine, &[2]).unwrap_err(),
            PayloadError::UnknownVersion(2)
        );
        assert_eq!(
            parse(&engine, &[PAYLOAD_VERSION, 1]).unwrap_err(),
            PayloadError::Truncated
        );
        let mut short = vec![PAYLOAD_VERSION];
        short.extend_from_slice(&fixtures::fill(1));
        assert_eq!(parse(&engine, &short).unwrap_err(), PayloadError::Truncated);
        let mut empty_list = vec![PAYLOAD_VERSION];
        empty_list.extend_from_slice(&fixtures::fill(1));
        empty_list.push(0);
        assert_eq!(
            parse(&engine, &empty_list).unwrap_err(),
            PayloadError::EmptyBillboards
        );
        let mut too_many = vec![PAYLOAD_VERSION];
        too_many.extend_from_slice(&fixtures::fill(1));
        too_many.push(u8::try_from(BILLBOARD_MAX_COUNT + 1).expect("count"));
        assert_eq!(
            parse(&engine, &too_many).unwrap_err(),
            PayloadError::TooManyBillboards
        );
        let mut kind_too_long = secret_on(&engine).to_bytes();
        kind_too_long[34] = u8::try_from(KIND_MAX_LEN + 1).expect("len");
        assert_eq!(
            parse(&engine, &kind_too_long).unwrap_err(),
            PayloadError::Kind(BillboardKindError::TooLong)
        );
        let mut bad_kind = vec![PAYLOAD_VERSION];
        bad_kind.extend_from_slice(&fixtures::fill(1));
        bad_kind.push(1);
        bad_kind.push(1);
        bad_kind.push(b'N');
        bad_kind.push(1);
        bad_kind.push(b'x');
        assert_eq!(
            parse(&engine, &bad_kind).unwrap_err(),
            PayloadError::Kind(BillboardKindError::InvalidChar)
        );
        let mut empty_kind = vec![PAYLOAD_VERSION];
        empty_kind.extend_from_slice(&fixtures::fill(1));
        empty_kind.push(1);
        empty_kind.push(0);
        empty_kind.push(1);
        empty_kind.push(b'x');
        assert_eq!(
            parse(&engine, &empty_kind).unwrap_err(),
            PayloadError::Kind(BillboardKindError::Empty)
        );
        let mut addr_too_long = secret_on(&engine).to_bytes();
        let kind_len = usize::from(addr_too_long[34]);
        addr_too_long[35 + kind_len] = u8::try_from(ADDRESS_MAX_LEN + 1).expect("len");
        assert_eq!(
            parse(&engine, &addr_too_long).unwrap_err(),
            PayloadError::Address(BillboardAddressError::TooLong)
        );
        let mut empty_addr = vec![PAYLOAD_VERSION];
        empty_addr.extend_from_slice(&fixtures::fill(1));
        empty_addr.push(1);
        empty_addr.push(1);
        empty_addr.push(b'a');
        empty_addr.push(0);
        assert_eq!(
            parse(&engine, &empty_addr).unwrap_err(),
            PayloadError::Address(BillboardAddressError::Empty)
        );
        let mut nfd = vec![PAYLOAD_VERSION];
        nfd.extend_from_slice(&fixtures::fill(1));
        nfd.push(1);
        nfd.push(1);
        nfd.push(b'a');
        let combining = "e\u{0301}";
        nfd.push(u8::try_from(combining.len()).expect("len"));
        nfd.extend_from_slice(combining.as_bytes());
        assert_eq!(
            parse(&engine, &nfd).unwrap_err(),
            PayloadError::Address(BillboardAddressError::CombiningMark)
        );
        let mut trailing = secret_on(&engine).to_bytes();
        trailing.push(0);
        assert_eq!(
            parse(&engine, &trailing).unwrap_err(),
            PayloadError::TrailingBytes
        );
        let huge = vec![0; TICKET_MAX_UNCOMPRESSED + 1];
        assert_eq!(
            parse(&engine, &huge).unwrap_err(),
            PayloadError::TrailingBytes
        );
        let mut invalid_utf8_kind = vec![PAYLOAD_VERSION];
        invalid_utf8_kind.extend_from_slice(&fixtures::fill(1));
        invalid_utf8_kind.push(1);
        invalid_utf8_kind.push(1);
        invalid_utf8_kind.push(0xff);
        invalid_utf8_kind.push(1);
        invalid_utf8_kind.push(b'x');
        assert_eq!(
            parse(&engine, &invalid_utf8_kind).unwrap_err(),
            PayloadError::Kind(BillboardKindError::InvalidChar)
        );
        let mut invalid_utf8_addr = vec![PAYLOAD_VERSION];
        invalid_utf8_addr.extend_from_slice(&fixtures::fill(1));
        invalid_utf8_addr.push(1);
        invalid_utf8_addr.push(1);
        invalid_utf8_addr.push(b'a');
        invalid_utf8_addr.push(1);
        invalid_utf8_addr.push(0xff);
        assert_eq!(
            parse(&engine, &invalid_utf8_addr).unwrap_err(),
            PayloadError::Address(BillboardAddressError::InvalidUtf8)
        );
        let mut truncated_kind = vec![PAYLOAD_VERSION];
        truncated_kind.extend_from_slice(&fixtures::fill(1));
        truncated_kind.push(1);
        truncated_kind.push(4);
        truncated_kind.extend_from_slice(b"ab");
        assert_eq!(
            parse(&engine, &truncated_kind).unwrap_err(),
            PayloadError::Truncated
        );
        let mut truncated_addr = vec![PAYLOAD_VERSION];
        truncated_addr.extend_from_slice(&fixtures::fill(1));
        truncated_addr.push(1);
        truncated_addr.push(1);
        truncated_addr.push(b'a');
        truncated_addr.push(4);
        truncated_addr.extend_from_slice(b"ab");
        assert_eq!(
            parse(&engine, &truncated_addr).unwrap_err(),
            PayloadError::Truncated
        );
        assert_eq!(
            format!("{}", PayloadError::Empty),
            "ticket payload is empty"
        );
        assert_eq!(
            format!("{}", PayloadError::UnknownVersion(9)),
            "unknown ticket payload version 9"
        );
        assert_eq!(
            format!("{}", PayloadError::Truncated),
            "ticket payload is truncated"
        );
        assert_eq!(
            format!("{}", PayloadError::TrailingBytes),
            "ticket payload has trailing bytes"
        );
        assert_eq!(
            format!("{}", PayloadError::EmptyBillboards),
            "ticket payload has no Billboards"
        );
        assert_eq!(
            format!("{}", PayloadError::TooManyBillboards),
            "ticket payload has too many Billboards"
        );
        assert_eq!(
            format!("{}", PayloadError::Kind(BillboardKindError::Empty)),
            format!("ticket payload kind: {}", BillboardKindError::Empty)
        );
        assert_eq!(
            format!("{}", PayloadError::Address(BillboardAddressError::Empty)),
            format!("ticket payload address: {}", BillboardAddressError::Empty)
        );
        assert!(
            std::error::Error::source(&PayloadError::Kind(BillboardKindError::Empty)).is_some()
        );
        assert!(
            std::error::Error::source(&PayloadError::Address(BillboardAddressError::Empty))
                .is_some()
        );
        assert!(std::error::Error::source(&PayloadError::Empty).is_none());
        let _ = Cursor::new(&[]).u8().unwrap_err();
    }

    #[test]
    fn envelope_roundtrip_and_errors() {
        let engine = engine();
        let secret = secret_on(&engine);
        let blob = secret.serialize(&engine);
        assert!(blob.len() <= TICKET_MAX_B64U_LEN);
        assert_eq!(Ticket::try_parse(&engine, &blob).expect("decode"), secret);

        let fail_b64 =
            fixtures::engine_with(Arc::new(fixtures::IdentityCompress), Arc::new(FailB64));
        assert_eq!(
            Ticket::try_parse(&fail_b64, "aa").unwrap_err(),
            EnvelopeError::Base64(Base64UrlError::Invalid)
        );

        let long = "a".repeat(TICKET_MAX_B64U_LEN + 1);
        assert_eq!(
            Ticket::try_parse(&engine, &long).unwrap_err(),
            EnvelopeError::TooLong
        );

        let empty_blob = engine.b64u().encode(&[]);
        assert_eq!(
            Ticket::try_parse(&engine, &empty_blob).unwrap_err(),
            EnvelopeError::Empty
        );

        let one_byte = engine.b64u().encode(&[ENVELOPE_VERSION]);
        assert_eq!(
            Ticket::try_parse(&engine, &one_byte).unwrap_err(),
            EnvelopeError::Empty
        );

        let bad_ver = engine.b64u().encode(&[0x00, 1, 2, 3]);
        assert_eq!(
            Ticket::try_parse(&engine, &bad_ver).unwrap_err(),
            EnvelopeError::UnknownVersion(0x00)
        );

        let bad_kind = engine.b64u().encode(&[ENVELOPE_VERSION, 0x02]);
        assert_eq!(
            Ticket::try_parse(&engine, &bad_kind).unwrap_err(),
            EnvelopeError::UnknownKind(0x02)
        );

        let huge = fixtures::engine_with(
            Arc::new(fixtures::IdentityCompress),
            Arc::new(HugeDecodeB64),
        );
        assert_eq!(
            Ticket::try_parse(&huge, "aa").unwrap_err(),
            EnvelopeError::CompressedTooLarge
        );

        let expanding =
            fixtures::engine_with(Arc::new(ExpandingCompress), Arc::new(fixtures::HexB64));
        let expanding_secret = secret_on(&expanding);
        let huge_blob = expanding_secret.serialize(&expanding);
        assert!(huge_blob.len() > 2);

        let codec = fixtures::engine_with(Arc::new(CodecCompress), Arc::new(fixtures::HexB64));
        let framed = engine.b64u().encode(&[ENVELOPE_VERSION, INVITE_KIND_DM]);
        assert_eq!(
            Ticket::try_parse(&codec, &framed).unwrap_err(),
            EnvelopeError::Compress(CompressError::Codec)
        );

        let oversize = fixtures::IdentityCompress
            .decompress(&[0; TICKET_MAX_UNCOMPRESSED + 1], TICKET_MAX_UNCOMPRESSED)
            .unwrap_err();
        assert_eq!(oversize, CompressError::Oversize);

        let payload_err = Ticket::try_parse(
            &engine,
            &engine
                .b64u()
                .encode(&[ENVELOPE_VERSION, INVITE_KIND_DM, PAYLOAD_VERSION]),
        );
        assert!(matches!(payload_err, Err(EnvelopeError::Payload(_))));

        assert_eq!(
            format!("{}", EnvelopeError::TooLong),
            format!("ticket blob longer than {TICKET_MAX_B64U_LEN} chars")
        );
        assert_eq!(format!("{}", EnvelopeError::Empty), "ticket blob is empty");
        assert_eq!(
            format!("{}", EnvelopeError::UnknownVersion(3)),
            "unknown ticket envelope version 3"
        );
        assert_eq!(
            format!("{}", EnvelopeError::UnknownKind(2)),
            "unknown ticket kind 2"
        );
        assert_eq!(
            format!("{}", EnvelopeError::CompressedTooLarge),
            "ticket compressed body exceeds cap"
        );
        assert_eq!(
            format!("{}", EnvelopeError::Base64(Base64UrlError::Invalid)),
            format!("ticket blob: {}", Base64UrlError::Invalid)
        );
        assert_eq!(
            format!("{}", EnvelopeError::Compress(CompressError::Codec)),
            format!("ticket blob: {}", CompressError::Codec)
        );
        assert_eq!(
            format!("{}", EnvelopeError::Payload(PayloadError::Empty)),
            format!("ticket blob: {}", PayloadError::Empty)
        );
        assert!(
            std::error::Error::source(&EnvelopeError::Base64(Base64UrlError::Invalid)).is_some()
        );
        assert!(
            std::error::Error::source(&EnvelopeError::Compress(CompressError::Codec)).is_some()
        );
        assert!(std::error::Error::source(&EnvelopeError::Payload(PayloadError::Empty)).is_some());
        assert!(std::error::Error::source(&EnvelopeError::Empty).is_none());
        assert!(std::error::Error::source(&EnvelopeError::UnknownKind(1)).is_none());

        assert!(fixtures::HexB64.decode("%").is_err());
        assert!(fixtures::HexB64.decode("a").is_err());
        assert!(fixtures::HexB64.decode("0g").is_err());
        let one = fixtures::HexB64.encode(&[0x00]);
        assert_eq!(fixtures::HexB64.decode(&one).expect("one"), vec![0x00]);
        let two = fixtures::HexB64.encode(&[0x00, 0xab]);
        assert_eq!(
            fixtures::HexB64.decode(&two).expect("two"),
            vec![0x00, 0xab]
        );
        let three = fixtures::HexB64.encode(&[0x00, 0x01, 0x02]);
        assert_eq!(
            fixtures::HexB64.decode(&three).expect("three"),
            vec![0x00, 0x01, 0x02]
        );
        let _ = FailB64.encode(&[]);
        let _ = HugeDecodeB64.encode(&[]);
        let _ = ExpandingCompress.decompress(&[], 1);
        let _ = CodecCompress.compress(b"x");
    }
}
