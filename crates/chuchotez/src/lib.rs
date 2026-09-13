//! Chuchotez is a communications backend the app author does not operate.
//!
//! Pairwise streams, a group mesh, Hold (billboard and mailbox), and a live
//! ladder compile for `wasm32-unknown-unknown` with the Rust standard library.
//! Chat and turn-based games are application mappings. Crypto suite is policy:
//! `hybrid` for a messenger host, `classical` when a game asks for it.
//!
//! This crate is the domain. It depends on `std` and ports. Hosts inject
//! adapters. A WASM facade, when it exists, maps JavaScript values through
//! narrowers into domain types.

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
