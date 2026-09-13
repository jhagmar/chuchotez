//! Host-owned handle bound to a [`Suite`](crate::Suite).
//!
//! The host constructs one [`Engine`] per process or test and passes it into
//! protocol methods. Chuchotez stores no suite of its own.

use crate::protocol::{InviteSecret, InviteTag, MailboxTagKey};
use crate::suite::Suite;

/// Protocol operations that need the pure crypto suite.
#[derive(Clone)]
pub struct Engine {
    suite: Suite,
}

impl Engine {
    /// Bind this engine to `suite`. The caller keeps the engine.
    #[must_use]
    pub fn new(suite: Suite) -> Self {
        Self { suite }
    }

    /// Suite this engine was constructed with.
    #[must_use]
    pub fn suite(&self) -> &Suite {
        &self.suite
    }

    /// Invite-document locator tag (HKDF-Expand).
    #[must_use]
    pub fn tag(&self, secret: &InviteSecret) -> InviteTag {
        secret.tag_with(self.suite.hmac())
    }

    /// Mailbox tag key (HKDF-Expand).
    #[must_use]
    pub fn mailbox_tag_key(&self, secret: &InviteSecret) -> MailboxTagKey {
        secret.mailbox_tag_key_with(self.suite.hmac())
    }
}

impl core::fmt::Debug for Engine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Engine { suite: .. }")
    }
}

#[cfg(test)]
mod tests {
    use super::Engine;
    use crate::protocol::{
        HmacSha256, HmacSha256Key, HmacSha256Mac, InviteSecret, InviteTag, MailboxTagKey, v1,
    };
    use crate::suite::Suite;
    use std::sync::Arc;

    struct XorHmac;

    impl HmacSha256 for XorHmac {
        fn mac(&self, key: &HmacSha256Key, data: &[u8]) -> HmacSha256Mac {
            let mut out = *key.as_bytes();
            for (i, byte) in data.iter().enumerate() {
                let slot = i % out.len();
                out[slot] ^= byte;
            }
            HmacSha256Mac::from_bytes(out)
        }
    }

    fn fill(byte: u8) -> [u8; v1::SECRET_LEN] {
        [byte; v1::SECRET_LEN]
    }

    #[test]
    fn tag_matches_tag_with() {
        let engine = Engine::new(Suite::new(Arc::new(XorHmac)));
        let secret = InviteSecret::V1(v1::InviteSecret::from_bytes(fill(0x22)));
        assert_eq!(engine.tag(&secret), secret.tag_with(&XorHmac));
        assert_eq!(
            engine.mailbox_tag_key(&secret),
            secret.mailbox_tag_key_with(&XorHmac)
        );
        match (engine.tag(&secret), engine.mailbox_tag_key(&secret)) {
            (InviteTag::V1(tag), MailboxTagKey::V1(key)) => {
                assert_ne!(tag.as_bytes(), key.as_bytes());
            }
        }
        assert_eq!(format!("{engine:?}"), "Engine { suite: .. }");
        let _ = engine.suite();
        let _ = engine.clone();
    }
}
