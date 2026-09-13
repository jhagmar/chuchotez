//! Domain crate: protocol types, ports, suites, and [`Engine`].
//!
//! Zero third-party dependencies. Hosts depend on the `chuchotez` facade, keep
//! an [`Engine`] bound to a suite, and supply [`Rng`] on every entropy call.
//!
//! Wire objects live in [`protocol`]. Version is an enum variant
//! (`InviteSecret::V1`); layout-specific types live in [`protocol::v1`].

mod engine;
pub mod protocol;
mod suite;

pub use engine::Engine;
pub use protocol::{
    EXPAND_LEN, HmacSha256, HmacSha256Key, HmacSha256Mac, InviteSecret, InviteTag, MailboxTagKey,
    RANDOM32_LEN, Random32, Random32Bytes, Rng, v1,
};
pub use suite::Suite;

/// Crate version from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn version_matches_package() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
    }
}
