//! Pure adapters for [`chuchotez_domain`] v1 capabilities.
//!
//! Side effects (`Rng`, clocks, IO) stay in the host.

mod aead;
mod b64u;
mod compress;
mod hmac;
mod json;
mod kem;
pub mod v1;

pub use aead::AesGcm;
pub use b64u::Base64Ct;
pub use compress::Deflate;
pub use hmac::LibcruxHmac;
pub use json::Rfc8785;
pub use kem::LibcruxKem;
