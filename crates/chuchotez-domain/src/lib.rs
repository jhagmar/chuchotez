//! Domain crate: protocol types, ports, suites, and versioned engines.
//!
//! Zero third-party dependencies. Hosts depend on the `chuchotez` facade, keep
//! a [`v1::Engine`] constructed with [`Policy`], and supply [`Rng`] on every
//! entropy call.
//!
//! Wire objects live in [`protocol`]. Layout version is the module ([`v1`]
//! today). Hosts use factory methods on that module’s `Engine`.

pub mod protocol;

pub use protocol::{Policy, RANDOM32_LEN, Random32, Random32Bytes, Rng, v1};

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
