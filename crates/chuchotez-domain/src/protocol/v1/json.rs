//! RFC 8785 JSON values and the canonicalization port.

/// A JSON value the domain can build and narrow.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Json {
    /// JSON null.
    Null,
    /// JSON boolean.
    Bool(bool),
    /// JSON string.
    String(String),
    /// JSON array.
    Array(Vec<Json>),
    /// JSON object as a list of members.
    Object(Vec<(String, Json)>),
}

/// Failure from [`CanonicalJson::decode`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalJsonError {
    /// The bytes were not RFC 8785 JSON this port accepts.
    Invalid,
}

impl core::fmt::Display for CanonicalJsonError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("invalid canonical json")
    }
}

impl std::error::Error for CanonicalJsonError {}

/// RFC 8785 emit and parse. Adapters supply the primitive; tests inject a fake.
pub trait CanonicalJson {
    /// Encode `value` as RFC 8785 bytes.
    fn encode(&self, value: &Json) -> Vec<u8>;

    /// Decode RFC 8785 bytes into [`Json`].
    fn decode(&self, bytes: &[u8]) -> Result<Json, CanonicalJsonError>;
}

#[cfg(test)]
mod tests {
    use super::{CanonicalJsonError, Json};

    #[test]
    fn json_eq_and_error() {
        let a = Json::String("x".into());
        assert_eq!(a, Json::String("x".into()));
        assert_ne!(a, Json::Bool(true));
        assert_eq!(Json::Null, Json::Null);
        assert_eq!(Json::Array(Vec::new()), Json::Array(Vec::new()));
        assert_eq!(
            Json::Object(vec![("k".into(), Json::Bool(false))]),
            Json::Object(vec![("k".into(), Json::Bool(false))])
        );
        let _ = a.clone();
        assert!(format!("{a:?}").contains("x"));
        assert_eq!(
            format!("{}", CanonicalJsonError::Invalid),
            "invalid canonical json"
        );
        assert_eq!(CanonicalJsonError::Invalid, CanonicalJsonError::Invalid);
        let _ = &CanonicalJsonError::Invalid as &dyn std::error::Error;
    }
}
