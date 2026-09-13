//! Pure adapters for [`chuchotez_domain`] v1 capabilities.
//!
//! Side effects (`Rng`, clocks, IO) stay in the host.

use base64ct::{Base64UrlUnpadded, Encoding};
use chuchotez_domain::Random32Bytes;
use chuchotez_domain::v1::{
    Base64Url, Base64UrlError, Compress, CompressError, HmacSha256, HmacSha256Key, HmacSha256Mac,
};
use flate2::Compression;
use flate2::write::{DeflateDecoder, DeflateEncoder};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// HMAC-SHA-256 over RustCrypto `hmac` + `sha2`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sha2;

impl HmacSha256 for Sha2 {
    fn mac(&self, key: &HmacSha256Key, data: &[u8]) -> HmacSha256Mac {
        let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
            .expect("HMAC-SHA-256 accepts any key length");
        mac.update(data);
        let digest = mac.finalize().into_bytes();
        let bytes: Random32Bytes = digest.into();
        HmacSha256Mac::from_bytes(bytes)
    }
}

/// Writer that fails closed when output would exceed `max`.
struct Capped {
    buf: Vec<u8>,
    max: usize,
    oversize: Arc<AtomicBool>,
}

impl Capped {
    fn new(max: usize, oversize: Arc<AtomicBool>) -> Self {
        Self {
            buf: Vec::new(),
            max,
            oversize,
        }
    }
}

impl Write for Capped {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.buf.len().saturating_add(buf.len()) > self.max {
            self.oversize.store(true, Ordering::Relaxed);
            return Err(io::Error::other("oversize"));
        }
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Raw RFC 1951 Deflate via `flate2` (`miniz_oxide`), `Compression::best()`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Deflate;

impl Compress for Deflate {
    fn compress(&self, src: &[u8]) -> Vec<u8> {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
        encoder
            .write_all(src)
            .expect("deflate honors compress contract");
        encoder.finish().expect("deflate honors compress contract")
    }

    fn decompress(&self, src: &[u8], max_uncompressed: usize) -> Result<Vec<u8>, CompressError> {
        let oversize = Arc::new(AtomicBool::new(false));
        let mut decoder = DeflateDecoder::new(Capped::new(max_uncompressed, oversize.clone()));
        let write_res = decoder.write_all(src);
        let _ = decoder.flush();
        match decoder.finish() {
            Ok(capped) if !oversize.load(Ordering::Relaxed) && write_res.is_ok() => Ok(capped.buf),
            _ if oversize.load(Ordering::Relaxed) => Err(CompressError::Oversize),
            _ => Err(CompressError::Codec),
        }
    }
}

/// Unpadded base64url over RustCrypto `base64ct`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Base64Ct;

impl Base64Url for Base64Ct {
    fn encode(&self, src: &[u8]) -> String {
        Base64UrlUnpadded::encode_string(src)
    }

    fn decode(&self, src: &str) -> Result<Vec<u8>, Base64UrlError> {
        Base64UrlUnpadded::decode_vec(src).map_err(|_| Base64UrlError::Invalid)
    }
}

/// Portable v1 adapters: HMAC-SHA-256, raw Deflate, unpadded base64url.
pub mod v1 {
    use super::{Arc, Base64Ct, Deflate, Sha2};
    use chuchotez_domain::Policy;
    use chuchotez_domain::v1::{Engine, Suite};

    /// Default portable v1 suite: [`Sha2`], [`Deflate`], [`Base64Ct`].
    #[must_use]
    pub fn std_suite() -> Suite {
        Suite::new(Arc::new(Sha2), Arc::new(Deflate), Arc::new(Base64Ct))
    }

    /// [`Engine`] bound to [`std_suite`] for `policy`.
    #[must_use]
    pub fn std_engine(policy: Policy) -> Engine {
        Engine::new(std_suite(), policy)
    }
}

#[cfg(test)]
mod tests {
    use super::{Base64Ct, Deflate, Sha2, v1};
    use chuchotez_domain::Policy;
    use chuchotez_domain::v1::{
        Base64Url, Base64UrlError, Compress, CompressError, HmacSha256, HmacSha256Key,
        HmacSha256Mac,
    };
    use hmac::{Hmac, KeyInit, Mac};

    #[test]
    fn sha2_matches_hmac_crate() {
        let key = HmacSha256Key::from_bytes([0x0b; 32]);
        let data = b"Hi There";
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key.as_bytes()).expect("key");
        mac.update(data);
        let expected: [u8; 32] = mac.finalize().into_bytes().into();
        let port = Sha2;
        assert_eq!(port.mac(&key, data), HmacSha256Mac::from_bytes(expected));
        assert_eq!(port.mac(&key, data), Sha2.mac(&key, data));
        assert_eq!(port, Sha2);
        assert_eq!(format!("{port:?}"), "Sha2");
        let _ = v1::std_suite();
        assert_eq!(v1::std_engine(Policy::Hybrid).policy(), Policy::Hybrid);
        assert_eq!(v1::std_engine(Policy::Classic).policy(), Policy::Classic);
        assert_eq!(
            v1::std_engine(Policy::PostQuantum).policy(),
            Policy::PostQuantum
        );
    }

    #[test]
    fn deflate_roundtrip_and_errors() {
        let port = Deflate;
        let src = b"wss://relay.example/nostr-billboard";
        let compressed = port.compress(src);
        assert_ne!(compressed, src);
        let out = port.decompress(&compressed, 1024).expect("inflate");
        assert_eq!(out, src);
        assert_eq!(
            port.decompress(&compressed, 4).unwrap_err(),
            CompressError::Oversize
        );
        assert_eq!(
            port.decompress(b"not-deflate", 1024).unwrap_err(),
            CompressError::Codec
        );
        let empty = port.compress(b"");
        assert_eq!(port.decompress(&empty, 8).expect("empty"), b"");
        assert_eq!(port, Deflate);
        assert_eq!(format!("{port:?}"), "Deflate");
        let _ = CompressError::Codec;
    }

    #[test]
    fn b64ct_roundtrip_and_errors() {
        let port = Base64Ct;
        let src = [ENVELOPE_SAMPLE, 1, 2, 255];
        let encoded = port.encode(&src);
        assert!(!encoded.contains('='));
        assert_eq!(port.decode(&encoded).expect("decode"), src);
        assert_eq!(port.decode("%").unwrap_err(), Base64UrlError::Invalid);
        assert_eq!(port, Base64Ct);
        assert_eq!(format!("{port:?}"), "Base64Ct");
        assert_eq!(port.encode(&[]), "");
        assert_eq!(port.decode("").expect("empty"), Vec::<u8>::new());
    }

    const ENVELOPE_SAMPLE: u8 = 0xC1;
}
