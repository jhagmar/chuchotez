//! Default portable v1 suite and engine.

use crate::{
    AesGcm, Base64Ct, Deflate, LibcruxHmac, LibcruxKem, LibcruxSha256, LibcruxSign, Rfc8785,
    RustcryptoArgon2id,
};
use chuchotez_domain::v1::{Defaults, Engine, Suite};
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
        Arc::new(LibcruxSign),
        Arc::new(LibcruxSha256),
        Arc::new(RustcryptoArgon2id),
    )
}

/// [`Engine`] bound to [`std_suite`] and `defaults`.
#[must_use]
pub fn std_engine(defaults: Defaults) -> Engine {
    Engine::new(std_suite(), defaults)
}

#[cfg(test)]
mod tests {
    use super::{std_engine, std_suite};
    use chuchotez_domain::v1::{Address, Defaults, DurableChannel, Kind, NotificationPrivacy};

    #[test]
    fn std_engine_binds_defaults() {
        let _ = std_suite();
        let d = Defaults::try_new(
            vec![DurableChannel::new(
                Kind::try_from("nostr").expect("k"),
                Address::try_from("wss://relay.example").expect("a"),
            )],
            Vec::new(),
            true,
            false,
            true,
            None,
            false,
            NotificationPrivacy::Name,
        )
        .expect("d");
        assert_eq!(std_engine(d.clone()).defaults(), &d);
    }
}
