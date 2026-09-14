//! RFC 8785 emit and parse for domain [`Json`].

use chuchotez_domain::v1::{CanonicalJson, CanonicalJsonError, Json};

/// RFC 8785 canonical JSON.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rfc8785;

impl CanonicalJson for Rfc8785 {
    fn encode(&self, value: &Json) -> Vec<u8> {
        let mut out = String::new();
        write_json(value, &mut out);
        out.into_bytes()
    }

    fn decode(&self, bytes: &[u8]) -> Result<Json, CanonicalJsonError> {
        let text = core::str::from_utf8(bytes).map_err(|_| CanonicalJsonError::Invalid)?;
        let mut p = Parser { rest: text };
        let value = p.value()?;
        p.skip_ws();
        if !p.rest.is_empty() {
            return Err(CanonicalJsonError::Invalid);
        }
        Ok(value)
    }
}

fn write_json(value: &Json, out: &mut String) {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(true) => out.push_str("true"),
        Json::Bool(false) => out.push_str("false"),
        Json::String(s) => write_string(s, out),
        Json::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json(item, out);
            }
            out.push(']');
        }
        Json::Object(members) => {
            let mut sorted = members.clone();
            sorted.sort_by(|a, b| utf16_cmp(&a.0, &b.0));
            out.push('{');
            for (i, (k, v)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(k, out);
                out.push(':');
                write_json(v, out);
            }
            out.push('}');
        }
    }
}

fn utf16_cmp(a: &str, b: &str) -> core::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", u32::from(c)));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

struct Parser<'a> {
    rest: &'a str,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        self.rest = self.rest.trim_start();
    }

    fn value(&mut self) -> Result<Json, CanonicalJsonError> {
        self.skip_ws();
        if let Some(rest) = self.rest.strip_prefix("null") {
            self.rest = rest;
            return Ok(Json::Null);
        }
        if let Some(rest) = self.rest.strip_prefix("true") {
            self.rest = rest;
            return Ok(Json::Bool(true));
        }
        if let Some(rest) = self.rest.strip_prefix("false") {
            self.rest = rest;
            return Ok(Json::Bool(false));
        }
        if self.rest.starts_with('"') {
            return self.string().map(Json::String);
        }
        if self.rest.starts_with('[') {
            return self.array();
        }
        if self.rest.starts_with('{') {
            return self.object();
        }
        Err(CanonicalJsonError::Invalid)
    }

    fn string(&mut self) -> Result<String, CanonicalJsonError> {
        let mut chars = self.rest.chars();
        if chars.next() != Some('"') {
            return Err(CanonicalJsonError::Invalid);
        }
        let mut out = String::new();
        loop {
            match chars.next() {
                Some('"') => {
                    self.rest = chars.as_str();
                    return Ok(out);
                }
                Some('\\') => match chars.next() {
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some('/') => out.push('/'),
                    Some('b') => out.push('\u{0008}'),
                    Some('f') => out.push('\u{000c}'),
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    Some('t') => out.push('\t'),
                    Some('u') => {
                        let mut hex = String::new();
                        for _ in 0..4 {
                            hex.push(chars.next().ok_or(CanonicalJsonError::Invalid)?);
                        }
                        let code = u32::from_str_radix(&hex, 16)
                            .map_err(|_| CanonicalJsonError::Invalid)?;
                        out.push(char::from_u32(code).ok_or(CanonicalJsonError::Invalid)?);
                    }
                    _ => return Err(CanonicalJsonError::Invalid),
                },
                Some(c) => out.push(c),
                None => return Err(CanonicalJsonError::Invalid),
            }
        }
    }

    fn array(&mut self) -> Result<Json, CanonicalJsonError> {
        self.rest = self.rest.get(1..).ok_or(CanonicalJsonError::Invalid)?;
        self.skip_ws();
        let mut items = Vec::new();
        if self.rest.starts_with(']') {
            self.rest = &self.rest[1..];
            return Ok(Json::Array(items));
        }
        loop {
            items.push(self.value()?);
            self.skip_ws();
            if self.rest.starts_with(',') {
                self.rest = &self.rest[1..];
                continue;
            }
            if self.rest.starts_with(']') {
                self.rest = &self.rest[1..];
                return Ok(Json::Array(items));
            }
            return Err(CanonicalJsonError::Invalid);
        }
    }

    fn object(&mut self) -> Result<Json, CanonicalJsonError> {
        self.rest = self.rest.get(1..).ok_or(CanonicalJsonError::Invalid)?;
        self.skip_ws();
        let mut members = Vec::new();
        if self.rest.starts_with('}') {
            self.rest = &self.rest[1..];
            return Ok(Json::Object(members));
        }
        loop {
            self.skip_ws();
            let key = self.string()?;
            self.skip_ws();
            if !self.rest.starts_with(':') {
                return Err(CanonicalJsonError::Invalid);
            }
            self.rest = &self.rest[1..];
            let value = self.value()?;
            members.push((key, value));
            self.skip_ws();
            if self.rest.starts_with(',') {
                self.rest = &self.rest[1..];
                continue;
            }
            if self.rest.starts_with('}') {
                self.rest = &self.rest[1..];
                return Ok(Json::Object(members));
            }
            return Err(CanonicalJsonError::Invalid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Rfc8785;
    use chuchotez_domain::v1::{CanonicalJson, CanonicalJsonError, Json};

    #[test]
    fn rfc8785_roundtrip_and_errors() {
        let port = Rfc8785;
        let value = Json::Object(vec![
            ("policy".into(), Json::String("Classic".into())),
            (
                "mailboxes".into(),
                Json::Array(vec![Json::Object(vec![
                    ("kind".into(), Json::String("nostr".into())),
                    ("address".into(), Json::String("wss://m.example".into())),
                ])]),
            ),
            ("wires".into(), Json::Array(Vec::new())),
            ("intake_pk".into(), Json::String("YQ".into())),
        ]);
        let bytes = port.encode(&value);
        let text = core::str::from_utf8(&bytes).expect("utf8");
        assert!(text.starts_with('{'));
        assert!(!text.contains(' '));
        let parsed = port.decode(&bytes).expect("decode");
        assert_eq!(port.encode(&parsed), bytes);
        assert_eq!(port.decode(b"{").unwrap_err(), CanonicalJsonError::Invalid);
        assert_eq!(
            port.decode(&[0xff]).unwrap_err(),
            CanonicalJsonError::Invalid
        );
        assert_eq!(port.decode(b"1").unwrap_err(), CanonicalJsonError::Invalid);
        assert_eq!(
            port.decode(b"{,}").unwrap_err(),
            CanonicalJsonError::Invalid
        );
        assert_eq!(port.decode(b"[}").unwrap_err(), CanonicalJsonError::Invalid);
        assert_eq!(
            port.decode(b"nul").unwrap_err(),
            CanonicalJsonError::Invalid
        );
        let empty_obj = port.encode(&Json::Object(Vec::new()));
        assert_eq!(empty_obj, b"{}");
        let empty_arr = port.encode(&Json::Array(Vec::new()));
        assert_eq!(empty_arr, b"[]");
        assert_eq!(port.encode(&Json::Null), b"null");
        assert_eq!(port.encode(&Json::Bool(true)), b"true");
        assert_eq!(port.encode(&Json::Bool(false)), b"false");
        let escaped = port.encode(&Json::String("a\"b\\c\n".into()));
        assert_eq!(
            port.decode(&escaped).expect("esc"),
            Json::String("a\"b\\c\n".into())
        );
        assert_eq!(port, Rfc8785);
        assert_eq!(format!("{port:?}"), "Rfc8785");
        assert_eq!(
            port.decode(b"{}x").unwrap_err(),
            CanonicalJsonError::Invalid
        );
        assert_eq!(port.decode(b"null").expect("n"), Json::Null);
        assert_eq!(port.decode(b"true").expect("t"), Json::Bool(true));
        assert_eq!(port.decode(b"false").expect("f"), Json::Bool(false));
        let with_escapes = port.encode(&Json::String("\"\\\u{0008}\u{000c}\n\r\t\u{0001}".into()));
        assert_eq!(
            port.decode(&with_escapes).expect("esc2"),
            Json::String("\"\\\u{0008}\u{000c}\n\r\t\u{0001}".into())
        );
        assert_eq!(
            port.decode(br#""\/""#).expect("slash"),
            Json::String("/".into())
        );
        assert_eq!(
            port.decode(br#""\uD800""#).unwrap_err(),
            CanonicalJsonError::Invalid
        );
        assert_eq!(
            port.decode(br#"{a:1}"#).unwrap_err(),
            CanonicalJsonError::Invalid
        );
        assert_eq!(
            port.decode(b"[true x]").unwrap_err(),
            CanonicalJsonError::Invalid
        );
        assert_eq!(
            port.decode(br#"{"a":true x}"#).unwrap_err(),
            CanonicalJsonError::Invalid
        );
        let _ = port.encode(&Json::Object(vec![
            ("é".into(), Json::Bool(true)),
            ("e".into(), Json::Bool(false)),
        ]));
        assert_eq!(
            port.decode(b"\"unterminated").unwrap_err(),
            CanonicalJsonError::Invalid
        );
        assert_eq!(
            port.decode(br#""\u""#).unwrap_err(),
            CanonicalJsonError::Invalid
        );
        assert_eq!(
            port.decode(br#""\q""#).unwrap_err(),
            CanonicalJsonError::Invalid
        );
        assert_eq!(
            port.decode(br#""\u00zz""#).unwrap_err(),
            CanonicalJsonError::Invalid
        );
        assert_eq!(
            port.encode(&Json::Array(vec![Json::Bool(true), Json::Bool(false)])),
            br#"[true,false]"#
        );
        assert_eq!(
            port.decode(br#"[true,false]"#).expect("two"),
            Json::Array(vec![Json::Bool(true), Json::Bool(false)])
        );
        assert_eq!(
            port.decode(br#"{"a" true}"#).unwrap_err(),
            CanonicalJsonError::Invalid
        );
        assert_eq!(
            port.decode(br#"{"a":true,"b":false}"#).expect("obj2"),
            Json::Object(vec![
                ("a".into(), Json::Bool(true)),
                ("b".into(), Json::Bool(false)),
            ])
        );
    }
}
