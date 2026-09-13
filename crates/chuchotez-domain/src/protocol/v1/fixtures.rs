//! Shared v1 test doubles. Not compiled into the library.

use super::{
    Base64Url, Base64UrlError, Billboard, BillboardAddress, BillboardKind, Compress, CompressError,
    Engine, HmacSha256, HmacSha256Key, HmacSha256Mac, Policy, SECRET_LEN, Suite,
};
use std::sync::{Arc, Mutex};

pub(crate) fn fill(byte: u8) -> [u8; SECRET_LEN] {
    [byte; SECRET_LEN]
}

pub(crate) fn sample_board() -> Billboard {
    Billboard::new(
        BillboardKind::try_from("nostr").expect("kind"),
        BillboardAddress::try_from("wss://relay.example").expect("addr"),
    )
}

/// Mixes `key` and `data` so distinct infos yield distinct outputs.
pub(crate) struct XorHmac;

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

pub(crate) struct IdentityCompress;

impl Compress for IdentityCompress {
    fn compress(&self, src: &[u8]) -> Vec<u8> {
        src.to_vec()
    }

    fn decompress(&self, src: &[u8], max_uncompressed: usize) -> Result<Vec<u8>, CompressError> {
        if src.len() > max_uncompressed {
            return Err(CompressError::Oversize);
        }
        Ok(src.to_vec())
    }
}

/// Hex stand-in so domain tests cover envelope composition without a b64u crate.
pub(crate) struct HexB64;

impl Base64Url for HexB64 {
    fn encode(&self, src: &[u8]) -> String {
        src.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn decode(&self, src: &str) -> Result<Vec<u8>, Base64UrlError> {
        if !src.len().is_multiple_of(2) {
            return Err(Base64UrlError::Invalid);
        }
        let bytes = src.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            let hi = hex_nibble(bytes[i])?;
            let lo = hex_nibble(bytes[i + 1])?;
            out.push((hi << 4) | lo);
            i += 2;
        }
        Ok(out)
    }
}

fn hex_nibble(b: u8) -> Result<u8, Base64UrlError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(Base64UrlError::Invalid),
    }
}

pub(crate) fn engine_with(
    compress: Arc<dyn Compress + Send + Sync>,
    b64u: Arc<dyn Base64Url + Send + Sync>,
) -> Engine {
    Engine::new(
        Suite::new(Arc::new(XorHmac), compress, b64u),
        Policy::Hybrid,
    )
}

pub(crate) fn test_engine() -> Engine {
    engine_with(Arc::new(IdentityCompress), Arc::new(HexB64))
}

pub(crate) fn engine_with_policy(policy: Policy) -> Engine {
    Engine::new(
        Suite::new(
            Arc::new(XorHmac),
            Arc::new(IdentityCompress),
            Arc::new(HexB64),
        ),
        policy,
    )
}

/// Records the last HMAC `data` so Expand info strings can be asserted.
pub(crate) struct RecordingHmac {
    pub data: Mutex<Vec<u8>>,
}

impl RecordingHmac {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            data: Mutex::new(Vec::new()),
        })
    }
}

impl HmacSha256 for RecordingHmac {
    fn mac(&self, _key: &HmacSha256Key, data: &[u8]) -> HmacSha256Mac {
        *self.data.lock().expect("record") = data.to_vec();
        HmacSha256Mac::from_bytes([0; SECRET_LEN])
    }
}

pub(crate) fn engine_with_hmac(hmac: Arc<dyn HmacSha256 + Send + Sync>) -> Engine {
    Engine::new(
        Suite::new(hmac, Arc::new(IdentityCompress), Arc::new(HexB64)),
        Policy::Hybrid,
    )
}
