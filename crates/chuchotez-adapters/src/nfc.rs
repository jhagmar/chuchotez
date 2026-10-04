//! Unicode Normalization Form C for host strings.

use unicode_normalization::UnicodeNormalization;

/// Normalize `text` to Unicode NFC.
///
/// The host applies this to display names, addresses, ticket text,
/// passphrases, and chat text before the engine gates.
#[must_use]
pub fn nfc(text: &str) -> String {
    text.nfc().collect()
}

#[cfg(test)]
mod tests {
    use super::nfc;

    #[test]
    fn composed_and_decomposed_names_match() {
        let composed = nfc("caf\u{e9}");
        let decomposed = nfc("cafe\u{0301}");
        assert_eq!(composed, decomposed);
        assert_eq!(composed, "caf\u{e9}");
    }
}
