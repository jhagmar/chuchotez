//! Layout version is the module (`v1`, later `v2`). Crypto policy is selected
//! when constructing that module’s engine.

/// Crypto policy the engine honors for Intake KEM.
///
/// Every v1 engine accepts every variant. Tag Expand is HMAC-SHA-256 for all
/// three. Intake KEM follows this value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Policy {
    /// X25519.
    Classic,
    /// ML-KEM-768.
    PostQuantum,
    /// X-Wing.
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
