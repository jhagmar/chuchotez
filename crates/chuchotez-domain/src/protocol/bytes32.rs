//! Constant-time equality for fixed-length byte arrays.

/// Equality that does not return early on the first differing byte.
///
/// Secrets and tags are compared on protocol paths. A variable-time `==` on a
/// byte array leaks how far two values match.
pub(super) fn ct_eq<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use super::ct_eq;

    const SAMPLE_LEN: usize = 4;

    #[test]
    fn ct_eq_all_bytes() {
        let mut a = [0u8; SAMPLE_LEN];
        let mut b = [0u8; SAMPLE_LEN];
        assert!(ct_eq(&a, &b));
        a[SAMPLE_LEN - 1] = 1;
        assert!(!ct_eq(&a, &b));
        b[SAMPLE_LEN - 1] = 1;
        assert!(ct_eq(&a, &b));
        a[0] = 2;
        assert!(!ct_eq(&a, &b));
    }
}
