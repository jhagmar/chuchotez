//! Raw RFC 1951 Deflate via `flate2` (`miniz_oxide`), `Compression::best()`.

use chuchotez_domain::v1::{Compress, CompressError};
use flate2::Compression;
use flate2::write::{DeflateDecoder, DeflateEncoder};
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

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

/// Raw RFC 1951 Deflate.
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

#[cfg(test)]
mod tests {
    use super::Deflate;
    use chuchotez_domain::v1::{Compress, CompressError};

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
}
