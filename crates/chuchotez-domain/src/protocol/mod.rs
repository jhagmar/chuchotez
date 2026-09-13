//! Wire objects and pure transforms.
//!
//! Layout version is the module: [`v1`] today, a sibling `v2` later. Each
//! layout has its own `Engine` contract. Types inside [`v1`] use ordinary names
//! (`InviteSecret`, `Engine`).

pub mod v1;

mod bytes32;
mod policy;

pub use policy::Policy;

/// Length of [`Random32`] CSPRNG output.
pub const RANDOM32_LEN: usize = 32;

/// [`RANDOM32_LEN`] bytes as an array.
pub type Random32Bytes = [u8; RANDOM32_LEN];

/// [`RANDOM32_LEN`] cryptographically random bytes from [`Rng`].
///
/// Branded so a hash digest or a key cannot be passed where fresh entropy is
/// required. [`v1::Engine::try_new_invite_secret`] is the step that assigns those
/// bytes the invite-secret role.
#[derive(Clone, Eq)]
pub struct Random32(Random32Bytes);

impl Random32 {
    /// Wrap output that is already [`RANDOM32_LEN`] cryptographically random bytes.
    #[must_use]
    pub const fn from_bytes(bytes: Random32Bytes) -> Self {
        Self(bytes)
    }

    /// Raw bytes for a constructor that consumes entropy.
    #[must_use]
    pub const fn as_bytes(&self) -> &Random32Bytes {
        &self.0
    }

    /// Consume the wrapper and return the array.
    #[must_use]
    pub const fn into_bytes(self) -> Random32Bytes {
        self.0
    }
}

impl PartialEq for Random32 {
    fn eq(&self, other: &Self) -> bool {
        bytes32::ct_eq(&self.0, &other.0)
    }
}

impl core::fmt::Debug for Random32 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Entropy is about to become a secret; keep it out of logs.
        f.write_str("Random32(..)")
    }
}

/// Cryptographic randomness. The host supplies a CSPRNG on every call that
/// needs entropy. Tests inject a seed.
pub trait Rng {
    /// [`RANDOM32_LEN`] cryptographically random bytes.
    fn random32(&self) -> Random32;
}

#[cfg(test)]
mod tests {
    use super::v1::EXPAND_T1_COUNTER;
    use super::v1::fixtures::{self, HexB64, IdentityCompress, RecordingHmac, XorHmac};
    use super::{Policy, Random32, Rng, v1};
    use std::sync::Arc;
    use v1::Base64Url;

    const SECRET_LEN: usize = v1::SECRET_LEN;

    struct SeedRng([u8; SECRET_LEN]);

    impl Rng for SeedRng {
        fn random32(&self) -> Random32 {
            Random32::from_bytes(self.0)
        }
    }

    fn secret_on(engine: &v1::Engine, byte: u8) -> v1::InviteSecret {
        v1::InviteSecret::from_parts(
            engine.clone(),
            fixtures::fill(byte),
            vec![fixtures::sample_board()],
        )
        .expect("secret")
    }

    #[test]
    fn try_new_invite_secret_uses_entropy() {
        let rng = SeedRng(fixtures::fill(0x11));
        let engine = fixtures::test_engine();
        let secret = engine
            .try_new_invite_secret(&rng, &[fixtures::sample_board()])
            .expect("secret");
        let expected = v1::InviteSecret::from_parts(
            engine.clone(),
            fixtures::fill(0x11),
            vec![fixtures::sample_board()],
        )
        .expect("expected");
        assert_eq!(secret, expected);
        assert_eq!(secret.billboards().len(), 1);
        assert_eq!(
            engine.try_new_invite_secret(&rng, &[]).unwrap_err(),
            v1::InviteSecretError::EmptyBillboards
        );
    }

    #[test]
    fn every_policy_constructs_v1() {
        for policy in [Policy::Classic, Policy::PostQuantum, Policy::Hybrid] {
            let engine = fixtures::engine_with_policy(policy);
            assert_eq!(engine.policy(), policy);
            let board = engine.new_billboard(
                engine.try_new_billboard_kind("nostr").expect("kind"),
                engine
                    .try_new_billboard_address("wss://relay.example")
                    .expect("addr"),
            );
            let secret = engine
                .try_new_invite_secret(&SeedRng(fixtures::fill(0x11)), &[board])
                .expect("secret");
            let blob = secret.serialize();
            let parsed = engine.try_parse_invite_secret(&blob).expect("parse");
            assert_eq!(parsed, secret);
        }
    }

    #[test]
    fn tag_passes_invite_tag_info_and_counter() {
        let hmac = RecordingHmac::new();
        let engine = fixtures::engine_with_hmac(hmac.clone());
        let secret = secret_on(&engine, 0x22);
        let _ = secret.billboard_tag();
        let recorded = hmac.data.lock().expect("record");
        assert_eq!(&recorded[..v1::INFO_INVITE_TAG.len()], v1::INFO_INVITE_TAG);
        assert_eq!(recorded[v1::INFO_INVITE_TAG.len()], EXPAND_T1_COUNTER);
    }

    #[test]
    fn mailbox_key_passes_mailbox_info_and_counter() {
        let hmac = RecordingHmac::new();
        let engine = fixtures::engine_with_hmac(hmac.clone());
        let secret = secret_on(&engine, 0x22);
        let _ = secret.mailbox_tag_key();
        let recorded = hmac.data.lock().expect("record");
        assert_eq!(
            &recorded[..v1::INFO_MAILBOX_TAG_KEY.len()],
            v1::INFO_MAILBOX_TAG_KEY
        );
        assert_eq!(recorded[v1::INFO_MAILBOX_TAG_KEY.len()], EXPAND_T1_COUNTER);
    }

    #[test]
    fn tag_and_mailbox_key_use_distinct_infos() {
        let secret = secret_on(&fixtures::test_engine(), 0x22);
        let engine = fixtures::test_engine();
        let tag = secret.billboard_tag();
        let mailbox_key = secret.mailbox_tag_key();
        assert_ne!(tag.as_bytes(), mailbox_key.as_bytes());
        assert_ne!(tag.as_bytes(), &fixtures::fill(0x22));
        let blob = secret.serialize();
        assert_eq!(
            engine.try_parse_invite_secret(&blob).expect("roundtrip"),
            secret
        );
    }

    #[test]
    fn equal_secrets_compare_equal() {
        let a = secret_on(&fixtures::test_engine(), 7);
        let b = secret_on(&fixtures::engine_with_policy(Policy::Classic), 7);
        let c = secret_on(&fixtures::test_engine(), 8);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn debug_omits_secret_bytes() {
        let secret = secret_on(&fixtures::test_engine(), 0xde);
        assert_eq!(format!("{secret:?}"), "InviteSecret(..)");
        assert!(!format!("{secret:?}").contains("dead"));
        assert_eq!(
            format!("{:?}", fixtures::test_engine()),
            "Engine { suite: .. }"
        );
        assert_eq!(
            format!(
                "{:?}",
                v1::Suite::new(
                    Arc::new(XorHmac),
                    Arc::new(IdentityCompress),
                    Arc::new(HexB64),
                )
            ),
            "Suite { hmac: .., compress: .., b64u: .. }"
        );
        let _ = fixtures::test_engine().clone();
        let _ = HexB64.decode("gg").unwrap_err();
        let _ = HexB64.decode("0").unwrap_err();
        assert_eq!(HexB64.decode("0a").expect("hex"), vec![0x0a]);
        assert_eq!(
            v1::Compress::decompress(&IdentityCompress, &[0; 4], 1).unwrap_err(),
            v1::CompressError::Oversize
        );
    }

    #[test]
    fn random32_eq_and_debug() {
        let a = Random32::from_bytes(fixtures::fill(0xab));
        let b = Random32::from_bytes(fixtures::fill(0xab));
        let c = Random32::from_bytes(fixtures::fill(0xcd));
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.as_bytes(), &fixtures::fill(0xab));
        assert_eq!(a.clone().into_bytes(), fixtures::fill(0xab));
        assert_eq!(format!("{a:?}"), "Random32(..)");
        assert!(!format!("{a:?}").contains("ab"));
    }
}
