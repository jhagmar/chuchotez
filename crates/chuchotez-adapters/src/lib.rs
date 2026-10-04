//! Pure adapters for [`chuchotez_domain`] v1 capabilities.
//!
//! Side effects (`Rng`, clocks, IO) stay in the host.

mod aead;
mod argon;
mod b64u;
mod compress;
mod hash;
mod hmac;
mod json;
mod kem;
mod nfc;
mod sign;
pub mod v1;

pub use aead::AesGcm;
pub use argon::RustcryptoArgon2id;
pub use b64u::Base64Ct;
pub use compress::Deflate;
pub use hash::LibcruxSha256;
pub use hmac::LibcruxHmac;
pub use json::Rfc8785;
pub use kem::LibcruxKem;
pub use nfc::nfc;
pub use sign::LibcruxSign;
