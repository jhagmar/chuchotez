//! Host-owned handle bound to a v1 [`Suite`] and a [`Policy`].

use super::{
    AddressError, Billboard, BillboardAddress, BillboardKind, DisplayName, DisplayNameError,
    EnvelopeError, Intake, Invite, InviteError, KemSeed, KindError, Mailbox, MailboxAddress,
    MailboxKind, Notice, NoticeError, Suite, Ticket, Wire, WireAddress, WireKind, notice,
};
use crate::protocol::{Policy, Rng};

/// Host-owned handle bound to a v1 [`Suite`] and a [`Policy`].
///
/// Named methods drive and query [`super::EngineState`]. Protocol helpers stay
/// crate-private. Tag and envelope mapping take `&Engine` on [`Ticket`].
#[derive(Clone)]
pub struct Engine {
    suite: Suite,
    policy: Policy,
}

impl Engine {
    /// Bind this engine to `suite` and `policy`. The caller keeps the engine.
    #[must_use]
    pub fn new(suite: Suite, policy: Policy) -> Self {
        Self { suite, policy }
    }

    /// Crypto policy this engine was constructed with.
    #[must_use]
    pub fn policy(&self) -> Policy {
        self.policy
    }

    /// Brand a preferred display name with the address gate.
    pub fn try_new_display_name(&self, name: &str) -> Result<DisplayName, DisplayNameError> {
        let _ = self;
        DisplayName::try_from(name)
    }

    /// HMAC-SHA-256 capability.
    #[must_use]
    pub(crate) fn hmac(&self) -> &dyn super::HmacSha256 {
        self.suite.hmac()
    }

    /// Raw DEFLATE capability.
    #[must_use]
    pub(crate) fn compress(&self) -> &dyn super::Compress {
        self.suite.compress()
    }

    /// Unpadded base64url capability.
    #[must_use]
    pub(crate) fn b64u(&self) -> &dyn super::Base64Url {
        self.suite.b64u()
    }

    /// AES-256-GCM capability.
    #[must_use]
    pub(crate) fn aead(&self) -> &dyn super::Aead {
        self.suite.aead()
    }

    /// RFC 8785 capability.
    #[must_use]
    pub(crate) fn canonical_json(&self) -> &dyn super::CanonicalJson {
        self.suite.canonical_json()
    }

    /// Intake keypair generator.
    #[must_use]
    pub(crate) fn kem(&self) -> &dyn super::Kem {
        self.suite.kem()
    }

    /// Parse and brand a Billboard mapper key.
    #[allow(dead_code)]
    pub(crate) fn try_new_billboard_kind(&self, kind: &str) -> Result<BillboardKind, KindError> {
        BillboardKind::try_from(kind)
    }

    /// Parse and brand a Billboard address.
    #[allow(dead_code)]
    pub(crate) fn try_new_billboard_address(
        &self,
        address: &str,
    ) -> Result<BillboardAddress, AddressError> {
        BillboardAddress::try_from(address)
    }

    /// Bind a validated kind to a validated address.
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn new_billboard(
        &self,
        kind: BillboardKind,
        address: BillboardAddress,
    ) -> Billboard {
        Billboard::new(kind, address)
    }

    /// Parse and brand a Mailbox mapper key.
    #[allow(dead_code)]
    pub(crate) fn try_new_mailbox_kind(&self, kind: &str) -> Result<MailboxKind, KindError> {
        MailboxKind::try_from(kind)
    }

    /// Parse and brand a Mailbox address.
    #[allow(dead_code)]
    pub(crate) fn try_new_mailbox_address(
        &self,
        address: &str,
    ) -> Result<MailboxAddress, AddressError> {
        MailboxAddress::try_from(address)
    }

    /// Bind a validated Mailbox kind to a validated address.
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn new_mailbox(&self, kind: MailboxKind, address: MailboxAddress) -> Mailbox {
        Mailbox::new(kind, address)
    }

    /// Parse and brand a Wire mapper key.
    #[allow(dead_code)]
    pub(crate) fn try_new_wire_kind(&self, kind: &str) -> Result<WireKind, KindError> {
        WireKind::try_from(kind)
    }

    /// Parse and brand a Wire address.
    #[allow(dead_code)]
    pub(crate) fn try_new_wire_address(&self, address: &str) -> Result<WireAddress, AddressError> {
        WireAddress::try_from(address)
    }

    /// Bind a validated Wire kind to a validated address.
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn new_wire(&self, kind: WireKind, address: WireAddress) -> Wire {
        Wire::new(kind, address)
    }

    /// Mint an Invite: Ticket secret and Intake [`KemSeed`] from `rng`.
    pub(crate) fn try_new_invite(
        &self,
        rng: &dyn Rng,
        billboards: &[Billboard],
        mailboxes: &[Mailbox],
        wires: &[Wire],
    ) -> Result<Invite, InviteError> {
        let ticket = Ticket::from_parts(rng.random32().into_bytes(), billboards.to_vec())?;
        let seed = KemSeed::from_pair(rng.random32(), rng.random32());
        let keys = self.kem().generate(self.policy, &seed)?;
        let intake = Intake::from_parts(keys, mailboxes.to_vec(), wires.to_vec())?;
        Ok(Invite::from_parts(ticket, intake))
    }

    /// Parse a compact DM Ticket blob using this engine's codecs.
    pub(crate) fn try_parse_ticket(&self, s: &str) -> Result<Ticket, EnvelopeError> {
        Ticket::try_parse(self, s)
    }

    /// Seal Intake public fields as a Notice blob keyed by `ticket`.
    #[must_use]
    pub(crate) fn serialize_notice(&self, ticket: &Ticket, intake: &Intake) -> String {
        Notice::from_intake(self.policy, intake).serialize(self, ticket)
    }

    /// Parse a Notice blob with keys derived from `ticket`.
    ///
    /// `policy` must match this engine. `intake_pk` length must match that Policy.
    #[allow(dead_code)]
    pub(crate) fn try_parse_notice(&self, ticket: &Ticket, s: &str) -> Result<Notice, NoticeError> {
        notice::try_parse_notice(self, ticket, s)
    }
}

impl core::fmt::Debug for Engine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Engine { suite: .. }")
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::v1::{
        AddressError, InviteError, KindError, SECRET_LEN, TicketError, fixtures,
    };
    use crate::protocol::{Policy, Random32, Rng};

    struct SeedRng([u8; SECRET_LEN]);

    impl Rng for SeedRng {
        fn random32(&self) -> Random32 {
            Random32::from_bytes(self.0)
        }
    }

    #[test]
    fn factory_brands_channel_parts() {
        let engine = fixtures::test_engine();
        assert_eq!(format!("{engine:?}"), "Engine { suite: .. }");
        assert_eq!(engine.policy(), Policy::Hybrid);
        let kind = engine.try_new_billboard_kind("nostr").expect("kind");
        let address = engine
            .try_new_billboard_address("wss://relay.example")
            .expect("addr");
        assert_eq!(
            engine.try_new_display_name("Ada").expect("name").as_str(),
            "Ada"
        );
        let board = engine.new_billboard(kind, address);
        assert_eq!(board.kind().as_str(), "nostr");
        assert_eq!(
            engine.try_new_billboard_kind("").unwrap_err(),
            KindError::Empty
        );
        assert_eq!(
            engine.try_new_billboard_address("").unwrap_err(),
            AddressError::Empty
        );
        let mailbox = engine.new_mailbox(
            engine.try_new_mailbox_kind("nostr").expect("kind"),
            engine
                .try_new_mailbox_address("wss://mailbox.example")
                .expect("addr"),
        );
        assert_eq!(mailbox.kind().as_str(), "nostr");
        let wire = engine.new_wire(
            engine.try_new_wire_kind("webrtc").expect("kind"),
            engine
                .try_new_wire_address("stun:stun.example")
                .expect("addr"),
        );
        assert_eq!(wire.kind().as_str(), "webrtc");
        assert_eq!(
            engine
                .try_new_invite(
                    &SeedRng([3; SECRET_LEN]),
                    &[],
                    std::slice::from_ref(&mailbox),
                    &[]
                )
                .unwrap_err(),
            InviteError::Ticket(TicketError::EmptyBillboards)
        );
        assert_eq!(
            engine
                .try_new_invite(
                    &SeedRng([3; SECRET_LEN]),
                    std::slice::from_ref(&board),
                    &[],
                    &[]
                )
                .unwrap_err(),
            InviteError::Intake(crate::protocol::v1::IntakeError::EmptyMailboxes)
        );
        let _ = engine.clone();
        let key = crate::protocol::v1::HmacSha256Key::from_bytes([0; SECRET_LEN]);
        let _ = engine.hmac().mac(&key, b"");
        let _ = engine.compress().compress(b"");
        let _ = engine.b64u().encode(b"");
        let nonce = crate::protocol::v1::AeadNonce::from_bytes([0; 12]);
        let aead_key = crate::protocol::v1::AeadKey::from_bytes([0; 32]);
        let _ = engine.aead().seal(&aead_key, &nonce, b"", b"");
        let _ = engine
            .canonical_json()
            .encode(&crate::protocol::v1::Json::Null);
    }
}
