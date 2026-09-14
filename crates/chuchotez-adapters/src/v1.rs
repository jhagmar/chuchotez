//! Default portable v1 suite and engine.

use crate::{AesGcm, Base64Ct, Deflate, LibcruxHmac, LibcruxKem, Rfc8785};
use chuchotez_domain::Policy;
use chuchotez_domain::v1::{Engine, Suite};
use std::sync::Arc;

/// Default portable v1 suite.
#[must_use]
pub fn std_suite() -> Suite {
    Suite::new(
        Arc::new(LibcruxHmac),
        Arc::new(Deflate),
        Arc::new(Base64Ct),
        Arc::new(AesGcm),
        Arc::new(Rfc8785),
        Arc::new(LibcruxKem),
    )
}

/// [`Engine`] bound to [`std_suite`] for `policy`.
#[must_use]
pub fn std_engine(policy: Policy) -> Engine {
    Engine::new(std_suite(), policy)
}

#[cfg(test)]
mod tests {
    use super::{std_engine, std_suite};
    use chuchotez_domain::Policy;

    #[test]
    fn std_engine_binds_policy() {
        let _ = std_suite();
        assert_eq!(std_engine(Policy::Hybrid).policy(), Policy::Hybrid);
        assert_eq!(std_engine(Policy::Classic).policy(), Policy::Classic);
        assert_eq!(
            std_engine(Policy::PostQuantum).policy(),
            Policy::PostQuantum
        );
    }
}
