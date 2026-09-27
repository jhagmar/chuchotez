//! Defaults, prefs, Wake, and related host-chosen records.

use super::channel::{
    Address, AddressError, DurableChannel, EphemeralChannel, Kind, KindError, parse_address,
    parse_kind,
};
use super::unicode::is_combining;

/// UTF-8 byte cap for [`DisplayName`].
pub const DISPLAY_NAME_MAX_LEN: usize = 64;

/// WebP avatar byte cap.
pub const PROFILE_PIC_MAX_LEN: usize = 4096;

/// DurableChannel list length on Defaults, Ticket, and Notice.
pub const PERSISTENT_MIN_COUNT: usize = 1;

/// DurableChannel list length on Defaults, Ticket, and Notice.
pub const PERSISTENT_MAX_COUNT: usize = 4;

/// EphemeralChannel list length on Defaults and Notice.
pub const EPHEMERAL_MAX_COUNT: usize = 4;

/// Why a display-name string was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisplayNameError {
    /// Empty string.
    Empty,
    /// Longer than [`DISPLAY_NAME_MAX_LEN`] UTF-8 bytes.
    TooLong,
    /// Contains a NUL scalar.
    Nul,
    /// Contains a combining mark.
    CombiningMark,
}

impl core::fmt::Display for DisplayNameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => f.write_str("display name is empty"),
            Self::TooLong => {
                write!(f, "display name longer than {DISPLAY_NAME_MAX_LEN} bytes")
            }
            Self::Nul => f.write_str("display name contains NUL"),
            Self::CombiningMark => f.write_str("display name contains a combining mark"),
        }
    }
}

impl std::error::Error for DisplayNameError {}

/// A name shown for a user or device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayName(String);

impl DisplayName {
    /// UTF-8 bytes.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for DisplayName {
    type Error = DisplayNameError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(DisplayNameError::Empty);
        }
        if value.len() > DISPLAY_NAME_MAX_LEN {
            return Err(DisplayNameError::TooLong);
        }
        if value.chars().any(|c| c == '\0') {
            return Err(DisplayNameError::Nul);
        }
        if value.chars().any(is_combining) {
            return Err(DisplayNameError::CombiningMark);
        }
        Ok(Self(value.to_owned()))
    }
}

/// Why a profile picture was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfilePicError {
    /// Empty or longer than [`PROFILE_PIC_MAX_LEN`].
    Length,
    /// Bytes `[0..4]` are not `RIFF` or `[8..12]` are not `WEBP`.
    Header,
}

impl core::fmt::Display for ProfilePicError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Length => f.write_str("profile pic length"),
            Self::Header => f.write_str("profile pic header"),
        }
    }
}

impl std::error::Error for ProfilePicError {}

/// Static WebP avatar bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfilePic(Vec<u8>);

impl ProfilePic {
    /// Raw WebP bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for ProfilePic {
    type Error = ProfilePicError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.is_empty() || value.len() > PROFILE_PIC_MAX_LEN {
            return Err(ProfilePicError::Length);
        }
        if value.len() < 12 || &value[0..4] != b"RIFF" || &value[8..12] != b"WEBP" {
            return Err(ProfilePicError::Header);
        }
        Ok(Self(value.to_vec()))
    }
}

/// How a notification names the chat and whether it includes a preview.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotificationPrivacy {
    /// Show the conversation name.
    Name,
    /// Show the conversation name and a preview.
    Preview,
    /// Silent.
    Silent,
}

impl NotificationPrivacy {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Preview => "preview",
            Self::Silent => "silent",
        }
    }

    #[allow(dead_code)]
    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s {
            "name" => Some(Self::Name),
            "preview" => Some(Self::Preview),
            "silent" => Some(Self::Silent),
            _ => None,
        }
    }
}

/// Why a [`Wake`] was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WakeError {
    /// Endpoint failed `https:`, printable ASCII, NFC, or length 1..=2048.
    Endpoint,
    /// `p256dh` length is not 65.
    P256dh,
    /// `auth` length is not 16.
    Auth,
}

impl core::fmt::Display for WakeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Endpoint => f.write_str("wake endpoint"),
            Self::P256dh => f.write_str("wake p256dh"),
            Self::Auth => f.write_str("wake auth"),
        }
    }
}

impl std::error::Error for WakeError {}

/// Web Push subscription the peer’s host POSTs to in order to wake this device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Wake {
    endpoint: String,
    p256dh: [u8; 65],
    auth: [u8; 16],
    vapid_pk: Option<Vec<u8>>,
}

impl Wake {
    /// Construct a Wake after the protocol gates.
    pub fn try_new(
        endpoint: &str,
        p256dh: &[u8],
        auth: &[u8],
        vapid_pk: Option<Vec<u8>>,
    ) -> Result<Self, WakeError> {
        if endpoint.is_empty() || endpoint.len() > 2048 {
            return Err(WakeError::Endpoint);
        }
        if !endpoint.starts_with("https:") {
            return Err(WakeError::Endpoint);
        }
        if endpoint
            .chars()
            .any(|c| c == ' ' || c == '\0' || !c.is_ascii() || is_combining(c))
        {
            return Err(WakeError::Endpoint);
        }
        let p256dh: [u8; 65] = p256dh.try_into().map_err(|_| WakeError::P256dh)?;
        let auth: [u8; 16] = auth.try_into().map_err(|_| WakeError::Auth)?;
        Ok(Self {
            endpoint: endpoint.to_owned(),
            p256dh,
            auth,
            vapid_pk,
        })
    }

    /// Push endpoint URL.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Uncompressed P-256 public key.
    #[must_use]
    pub fn p256dh(&self) -> &[u8; 65] {
        &self.p256dh
    }

    /// Auth secret.
    #[must_use]
    pub fn auth(&self) -> &[u8; 16] {
        &self.auth
    }

    /// Optional VAPID public key.
    #[must_use]
    pub fn vapid_pk(&self) -> Option<&[u8]> {
        self.vapid_pk.as_deref()
    }
}

/// Preference snapshot that travels on handshake intros and on `TxPrefs`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnWirePrefs {
    /// Read receipts.
    pub read_receipts: bool,
    /// Online visible.
    pub online_visible: bool,
    /// Send typing.
    pub send_typing: bool,
    /// Disappear after seconds, or never.
    pub disappear_after: Option<u64>,
    /// Wake subscription, or unpublished.
    pub wake: Option<Wake>,
}

/// Local conversation prefs including notification privacy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationPrefs {
    /// Read receipts.
    pub read_receipts: bool,
    /// Online visible.
    pub online_visible: bool,
    /// Send typing.
    pub send_typing: bool,
    /// Disappear after seconds, or never.
    pub disappear_after: Option<u64>,
    /// Notification privacy.
    pub notification_privacy: NotificationPrivacy,
    /// Wake subscription, or unpublished.
    pub wake: Option<Wake>,
}

/// Why [`Defaults::try_new`] failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DefaultsError {
    /// Channel list length or uniqueness failed.
    ChannelBounds,
    /// Kind grammar failed.
    Kind(KindError),
    /// Address grammar failed.
    Address(AddressError),
}

impl core::fmt::Display for DefaultsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ChannelBounds => f.write_str("channel bounds"),
            Self::Kind(e) => write!(f, "{e}"),
            Self::Address(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for DefaultsError {}

/// Host-chosen factory for a new [`super::EngineState`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Defaults {
    persistents: Vec<DurableChannel>,
    ephemerals: Vec<EphemeralChannel>,
    read_receipts: bool,
    online_visible: bool,
    send_typing: bool,
    disappear_after: Option<u64>,
    publish_wake: bool,
    notification_privacy: NotificationPrivacy,
}

impl Defaults {
    /// Bind channel lists and preference factory values.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        persistents: Vec<DurableChannel>,
        ephemerals: Vec<EphemeralChannel>,
        read_receipts: bool,
        online_visible: bool,
        send_typing: bool,
        disappear_after: Option<u64>,
        publish_wake: bool,
        notification_privacy: NotificationPrivacy,
    ) -> Result<Self, DefaultsError> {
        check_channel_bounds(&persistents, &ephemerals)?;
        Ok(Self {
            persistents,
            ephemerals,
            read_receipts,
            online_visible,
            send_typing,
            disappear_after,
            publish_wake,
            notification_privacy,
        })
    }

    /// Persistent mapper destinations.
    #[must_use]
    pub fn persistents(&self) -> &[DurableChannel] {
        &self.persistents
    }

    /// Ephemeral mapper destinations.
    #[must_use]
    pub fn ephemerals(&self) -> &[EphemeralChannel] {
        &self.ephemerals
    }

    /// Read receipts factory.
    #[must_use]
    pub fn read_receipts(&self) -> bool {
        self.read_receipts
    }

    /// Online-visible factory.
    #[must_use]
    pub fn online_visible(&self) -> bool {
        self.online_visible
    }

    /// Send-typing factory.
    #[must_use]
    pub fn send_typing(&self) -> bool {
        self.send_typing
    }

    /// Disappear-after factory.
    #[must_use]
    pub fn disappear_after(&self) -> Option<u64> {
        self.disappear_after
    }

    /// Publish-wake factory.
    #[must_use]
    pub fn publish_wake(&self) -> bool {
        self.publish_wake
    }

    /// Notification privacy factory.
    #[must_use]
    pub fn notification_privacy(&self) -> NotificationPrivacy {
        self.notification_privacy
    }
}

/// Channel lists freeze at mint; uniqueness is within each list.
pub(crate) fn check_channel_bounds(
    persistents: &[DurableChannel],
    ephemerals: &[EphemeralChannel],
) -> Result<(), DefaultsError> {
    if persistents.len() < PERSISTENT_MIN_COUNT || persistents.len() > PERSISTENT_MAX_COUNT {
        return Err(DefaultsError::ChannelBounds);
    }
    if ephemerals.len() > EPHEMERAL_MAX_COUNT {
        return Err(DefaultsError::ChannelBounds);
    }
    for (i, a) in persistents.iter().enumerate() {
        for b in persistents.iter().skip(i + 1) {
            if a.kind().as_str() != b.kind().as_str()
                || a.address().as_str() != b.address().as_str()
            {
                continue;
            }
            return Err(DefaultsError::ChannelBounds);
        }
    }
    for (i, a) in ephemerals.iter().enumerate() {
        for b in ephemerals.iter().skip(i + 1) {
            if a.kind().as_str() != b.kind().as_str()
                || a.address().as_str() != b.address().as_str()
            {
                continue;
            }
            return Err(DefaultsError::ChannelBounds);
        }
    }
    Ok(())
}

#[allow(dead_code)]
pub(crate) fn durable_from_parts(
    kind: &str,
    address: &str,
) -> Result<DurableChannel, DefaultsError> {
    let kind = Kind::try_from(kind).map_err(DefaultsError::Kind)?;
    let address = Address::try_from(address).map_err(DefaultsError::Address)?;
    let _ = (parse_kind(kind.as_str()), parse_address(address.as_str()));
    Ok(DurableChannel::new(kind, address))
}

#[cfg(test)]
mod tests {
    use super::{
        Address, AddressError, DISPLAY_NAME_MAX_LEN, Defaults, DefaultsError, DisplayName,
        DisplayNameError, DurableChannel, EphemeralChannel, Kind, KindError, NotificationPrivacy,
        PERSISTENT_MAX_COUNT, PROFILE_PIC_MAX_LEN, ProfilePic, ProfilePicError, Wake, WakeError,
        check_channel_bounds, durable_from_parts,
    };

    fn board() -> DurableChannel {
        DurableChannel::new(
            Kind::try_from("nostr").expect("k"),
            Address::try_from("wss://relay.example").expect("a"),
        )
    }

    #[test]
    fn display_name_and_pic() {
        assert_eq!(DisplayName::try_from("Ada").expect("n").as_str(), "Ada");
        assert_eq!(
            DisplayName::try_from("").unwrap_err(),
            DisplayNameError::Empty
        );
        let long = "a".repeat(DISPLAY_NAME_MAX_LEN + 1);
        assert_eq!(
            DisplayName::try_from(long.as_str()).unwrap_err(),
            DisplayNameError::TooLong
        );
        assert_eq!(
            DisplayName::try_from("a\0b").unwrap_err(),
            DisplayNameError::Nul
        );
        assert_eq!(
            DisplayName::try_from("cafe\u{0301}").unwrap_err(),
            DisplayNameError::CombiningMark
        );
        assert_eq!(
            format!("{}", DisplayNameError::Empty),
            "display name is empty"
        );
        assert_eq!(
            format!("{}", DisplayNameError::TooLong),
            format!("display name longer than {DISPLAY_NAME_MAX_LEN} bytes")
        );
        assert_eq!(
            format!("{}", DisplayNameError::Nul),
            "display name contains NUL"
        );
        assert_eq!(
            format!("{}", DisplayNameError::CombiningMark),
            "display name contains a combining mark"
        );
        let _ = &DisplayNameError::Empty as &dyn std::error::Error;
        let mut webp = vec![0u8; 12];
        webp[0..4].copy_from_slice(b"RIFF");
        webp[8..12].copy_from_slice(b"WEBP");
        assert_eq!(
            ProfilePic::try_from(webp.as_slice())
                .expect("p")
                .as_bytes()
                .len(),
            12
        );
        assert_eq!(
            ProfilePic::try_from(&[][..]).unwrap_err(),
            ProfilePicError::Length
        );
        assert_eq!(
            ProfilePic::try_from(&[0u8; 12][..]).unwrap_err(),
            ProfilePicError::Header
        );
        let too = vec![0u8; PROFILE_PIC_MAX_LEN + 1];
        assert_eq!(
            ProfilePic::try_from(too.as_slice()).unwrap_err(),
            ProfilePicError::Length
        );
        assert_eq!(format!("{}", ProfilePicError::Length), "profile pic length");
        assert_eq!(format!("{}", ProfilePicError::Header), "profile pic header");
        let _ = &ProfilePicError::Header as &dyn std::error::Error;
    }

    #[test]
    fn defaults_wake_privacy() {
        assert_eq!(NotificationPrivacy::Preview.as_str(), "preview");
        assert_eq!(NotificationPrivacy::Silent.as_str(), "silent");
        assert_eq!(
            NotificationPrivacy::parse("preview"),
            Some(NotificationPrivacy::Preview)
        );
        assert_eq!(
            NotificationPrivacy::parse("silent"),
            Some(NotificationPrivacy::Silent)
        );
        assert_eq!(NotificationPrivacy::parse("x"), None);
        let wake = Wake::try_new(
            "https://push.example/x",
            &[3u8; 65],
            &[4u8; 16],
            Some(vec![1, 2]),
        )
        .expect("w");
        assert_eq!(wake.endpoint(), "https://push.example/x");
        assert_eq!(wake.p256dh()[0], 3);
        assert_eq!(wake.auth()[0], 4);
        assert_eq!(wake.vapid_pk(), Some(&[1, 2][..]));
        assert_eq!(
            Wake::try_new("http://x", &[3u8; 65], &[4u8; 16], None).unwrap_err(),
            WakeError::Endpoint
        );
        assert_eq!(
            Wake::try_new("", &[3u8; 65], &[4u8; 16], None).unwrap_err(),
            WakeError::Endpoint
        );
        assert_eq!(
            Wake::try_new("https://x y", &[3u8; 65], &[4u8; 16], None).unwrap_err(),
            WakeError::Endpoint
        );
        assert_eq!(
            Wake::try_new("https://x", &[3u8; 4], &[4u8; 16], None).unwrap_err(),
            WakeError::P256dh
        );
        assert_eq!(
            Wake::try_new("https://x", &[3u8; 65], &[4u8; 2], None).unwrap_err(),
            WakeError::Auth
        );
        assert_eq!(format!("{}", WakeError::Endpoint), "wake endpoint");
        assert_eq!(format!("{}", WakeError::P256dh), "wake p256dh");
        assert_eq!(format!("{}", WakeError::Auth), "wake auth");
        let _ = &WakeError::Auth as &dyn std::error::Error;
        let d = Defaults::try_new(
            vec![board()],
            Vec::new(),
            true,
            true,
            true,
            None,
            false,
            NotificationPrivacy::Name,
        )
        .expect("d");
        assert_eq!(d.persistents().len(), 1);
        assert!(d.ephemerals().is_empty());
        assert!(d.read_receipts());
        assert!(d.online_visible());
        assert!(d.send_typing());
        assert_eq!(d.disappear_after(), None);
        assert!(!d.publish_wake());
        assert_eq!(d.notification_privacy(), NotificationPrivacy::Name);
        assert_eq!(d, d.clone());
        assert_eq!(
            Defaults::try_new(
                Vec::new(),
                Vec::new(),
                false,
                false,
                false,
                None,
                false,
                NotificationPrivacy::Silent,
            )
            .unwrap_err(),
            DefaultsError::ChannelBounds
        );
        let many = vec![board(); PERSISTENT_MAX_COUNT + 1];
        assert_eq!(
            check_channel_bounds(&many, &[]).unwrap_err(),
            DefaultsError::ChannelBounds
        );
        let dup = vec![board(), board()];
        assert_eq!(
            check_channel_bounds(&dup, &[]).unwrap_err(),
            DefaultsError::ChannelBounds
        );
        let other = durable_from_parts("nostr", "wss://relay-b.example").expect("ch");
        assert!(check_channel_bounds(&[board(), other], &[]).is_ok());
        let eph = EphemeralChannel::new(
            Kind::try_from("webrtc").expect("k"),
            Address::try_from("stun:stun.example").expect("a"),
        );
        let eph_b = EphemeralChannel::new(
            Kind::try_from("webrtc").expect("k"),
            Address::try_from("stun:other.example").expect("a"),
        );
        assert!(check_channel_bounds(&[board()], &[eph.clone(), eph_b]).is_ok());
        let many_e = vec![eph.clone(); super::EPHEMERAL_MAX_COUNT + 1];
        assert_eq!(
            check_channel_bounds(&[board()], &many_e).unwrap_err(),
            DefaultsError::ChannelBounds
        );
        assert_eq!(
            check_channel_bounds(&[board()], &[eph.clone(), eph]).unwrap_err(),
            DefaultsError::ChannelBounds
        );
        assert!(durable_from_parts("nostr", "wss://relay.example").is_ok());
        assert!(durable_from_parts("NOSTR", "wss://relay.example").is_err());
        assert_eq!(
            format!("{}", DefaultsError::ChannelBounds),
            "channel bounds"
        );
        let _ = &DefaultsError::ChannelBounds as &dyn std::error::Error;
        assert!(format!("{}", DefaultsError::Kind(KindError::Empty)).contains("kind"));
        assert!(format!("{}", DefaultsError::Address(AddressError::Empty)).contains("address"));
    }
}
