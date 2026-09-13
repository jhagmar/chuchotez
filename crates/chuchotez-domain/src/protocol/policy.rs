//! Layout version is the module (`v1`, later `v2`). Crypto policy is selected
//! when constructing that module’s engine.

/// Crypto policy the engine honors for handshake and wrapping.
///
/// Every v1 engine accepts every variant. Tag Expand is HMAC-SHA-256 for all
/// three; KEM and signatures branch on this value when those ports ship.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Policy {
    /// X25519 and Ed25519.
    Classic,
    /// ML-KEM-768 and ML-DSA-65.
    PostQuantum,
    /// X-Wing wrap; Ed25519 and ML-DSA-65 both verify.
    Hybrid,
}

#[cfg(test)]
mod tests {
    use super::Policy;

    #[test]
    fn policy_is_copy() {
        let p = Policy::Hybrid;
        let _ = (p, Policy::Classic, Policy::PostQuantum);
        assert_eq!(format!("{:?}", Policy::Classic), "Classic");
        assert_eq!(format!("{:?}", Policy::PostQuantum), "PostQuantum");
        assert_eq!(format!("{:?}", Policy::Hybrid), "Hybrid");
        assert_ne!(Policy::Classic, Policy::Hybrid);
    }
}
