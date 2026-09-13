//! Shared v1 test doubles. Not compiled into the library.

use super::{
    Aead, AeadError, AeadKey, AeadNonce, Base64Url, Base64UrlError, Billboard, BillboardAddress,
    BillboardKind, CanonicalJson, CanonicalJsonError, Compress, CompressError, Engine, HmacSha256,
    HmacSha256Key, HmacSha256Mac, IntakeKeypair, Json, Kem, KemError, KemSeed, Mailbox,
    MailboxAddress, MailboxKind, Policy, SECRET_LEN, Suite, Ticket, Wire, WireAddress, WireKind,
};
use crate::protocol::{Random32, Rng};
use std::sync::{Arc, Mutex};

pub(crate) fn fill(byte: u8) -> [u8; SECRET_LEN] {
    [byte; SECRET_LEN]
}

/// Repeats `bytes` on every [`Rng::random32`] call.
pub(crate) struct SeedRng(pub [u8; SECRET_LEN]);

impl Rng for SeedRng {
    fn random32(&self) -> Random32 {
        Random32::from_bytes(self.0)
    }
}

pub(crate) fn sample_ticket(byte: u8) -> Ticket {
    Ticket::from_parts(fill(byte), vec![sample_billboard()]).expect("ticket")
}

pub(crate) fn sample_billboard() -> Billboard {
    Billboard::new(
        BillboardKind::try_from("nostr").expect("kind"),
        BillboardAddress::try_from("wss://relay.example").expect("addr"),
    )
}

pub(crate) fn sample_mailbox() -> Mailbox {
    Mailbox::new(
        MailboxKind::try_from("nostr").expect("kind"),
        MailboxAddress::try_from("wss://mailbox.example").expect("addr"),
    )
}

pub(crate) fn sample_wire() -> Wire {
    Wire::new(
        WireKind::try_from("webrtc").expect("kind"),
        WireAddress::try_from("stun:stun.example").expect("addr"),
    )
}

/// Mixes `key` and `data` so distinct infos yield distinct outputs.
pub(crate) struct XorHmac;

impl HmacSha256 for XorHmac {
    fn mac(&self, key: &HmacSha256Key, data: &[u8]) -> HmacSha256Mac {
        let mut out = *key.as_bytes();
        for (i, byte) in data.iter().enumerate() {
            let slot = i % out.len();
            out[slot] ^= byte;
        }
        HmacSha256Mac::from_bytes(out)
    }
}

pub(crate) struct IdentityCompress;

impl Compress for IdentityCompress {
    fn compress(&self, src: &[u8]) -> Vec<u8> {
        src.to_vec()
    }

    fn decompress(&self, src: &[u8], max_uncompressed: usize) -> Result<Vec<u8>, CompressError> {
        if src.len() > max_uncompressed {
            return Err(CompressError::Oversize);
        }
        Ok(src.to_vec())
    }
}

/// Hex stand-in so domain tests cover envelope composition without a b64u crate.
pub(crate) struct HexB64;

impl Base64Url for HexB64 {
    fn encode(&self, src: &[u8]) -> String {
        src.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn decode(&self, src: &str) -> Result<Vec<u8>, Base64UrlError> {
        if !src.len().is_multiple_of(2) {
            return Err(Base64UrlError::Invalid);
        }
        let bytes = src.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            let hi = hex_nibble(bytes[i])?;
            let lo = hex_nibble(bytes[i + 1])?;
            out.push((hi << 4) | lo);
            i += 2;
        }
        Ok(out)
    }
}

fn hex_nibble(b: u8) -> Result<u8, Base64UrlError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(Base64UrlError::Invalid),
    }
}

/// Mixes key, nonce, and AAD into the ciphertext so a different Ticket fails open.
pub(crate) struct XorAead;

impl Aead for XorAead {
    fn seal(&self, key: &AeadKey, nonce: &AeadNonce, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let aad_len = u16::try_from(aad.len()).expect("aad fits u16");
        let mut out = Vec::with_capacity(2 + aad.len() + plaintext.len());
        out.extend_from_slice(&aad_len.to_be_bytes());
        out.extend_from_slice(aad);
        for (i, byte) in plaintext.iter().enumerate() {
            out.push(
                byte ^ key.as_bytes()[i % key.as_bytes().len()]
                    ^ nonce.as_bytes()[i % nonce.as_bytes().len()],
            );
        }
        out.extend_from_slice(key.as_bytes());
        out.extend_from_slice(nonce.as_bytes());
        out
    }

    fn open(
        &self,
        key: &AeadKey,
        nonce: &AeadNonce,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        let tag = key.as_bytes().len() + nonce.as_bytes().len();
        if ciphertext.len() < 2 + tag {
            return Err(AeadError::Open);
        }
        let aad_len = usize::from(u16::from_be_bytes([ciphertext[0], ciphertext[1]]));
        if ciphertext.len() < 2 + aad_len + tag {
            return Err(AeadError::Open);
        }
        let (head, tail) = ciphertext.split_at(ciphertext.len() - tag);
        if &tail[..key.as_bytes().len()] != key.as_bytes()
            || &tail[key.as_bytes().len()..] != nonce.as_bytes()
        {
            return Err(AeadError::Open);
        }
        if &head[2..2 + aad_len] != aad {
            return Err(AeadError::Open);
        }
        let body = &head[2 + aad_len..];
        Ok(body
            .iter()
            .enumerate()
            .map(|(i, byte)| {
                byte ^ key.as_bytes()[i % key.as_bytes().len()]
                    ^ nonce.as_bytes()[i % nonce.as_bytes().len()]
            })
            .collect())
    }
}

/// Deterministic JSON for domain tests (sorted object names, no whitespace).
pub(crate) struct DetJson;

impl CanonicalJson for DetJson {
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
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
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

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
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

/// Echoes seed bytes as a policy-sized keypair.
pub(crate) struct EchoKem;

impl Kem for EchoKem {
    fn generate(&self, policy: Policy, seed: &KemSeed) -> Result<IntakeKeypair, KemError> {
        let seed32 = &seed.as_bytes()[..SECRET_LEN];
        let n = super::intake_pk_len(policy);
        let mut public = vec![0u8; n];
        for (i, byte) in public.iter_mut().enumerate() {
            *byte = seed32[i % SECRET_LEN];
        }
        Ok(IntakeKeypair::from_parts(public, seed32.to_vec()))
    }
}

pub(crate) fn engine_with(
    compress: Arc<dyn Compress + Send + Sync>,
    b64u: Arc<dyn Base64Url + Send + Sync>,
) -> Engine {
    Engine::new(
        Suite::new(
            Arc::new(XorHmac),
            compress,
            b64u,
            Arc::new(XorAead),
            Arc::new(DetJson),
            Arc::new(EchoKem),
        ),
        Policy::Hybrid,
    )
}

pub(crate) fn test_engine() -> Engine {
    engine_with(Arc::new(IdentityCompress), Arc::new(HexB64))
}

pub(crate) fn engine_with_policy(policy: Policy) -> Engine {
    Engine::new(
        Suite::new(
            Arc::new(XorHmac),
            Arc::new(IdentityCompress),
            Arc::new(HexB64),
            Arc::new(XorAead),
            Arc::new(DetJson),
            Arc::new(EchoKem),
        ),
        policy,
    )
}

/// Records the last HMAC `data` so Expand info strings can be asserted.
pub(crate) struct RecordingHmac {
    pub data: Mutex<Vec<u8>>,
}

impl RecordingHmac {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            data: Mutex::new(Vec::new()),
        })
    }
}

impl HmacSha256 for RecordingHmac {
    fn mac(&self, _key: &HmacSha256Key, data: &[u8]) -> HmacSha256Mac {
        *self.data.lock().expect("record") = data.to_vec();
        HmacSha256Mac::from_bytes([0; SECRET_LEN])
    }
}

pub(crate) fn engine_with_hmac(hmac: Arc<dyn HmacSha256 + Send + Sync>) -> Engine {
    Engine::new(
        Suite::new(
            hmac,
            Arc::new(IdentityCompress),
            Arc::new(HexB64),
            Arc::new(XorAead),
            Arc::new(DetJson),
            Arc::new(EchoKem),
        ),
        Policy::Hybrid,
    )
}

#[cfg(test)]
mod tests {
    use super::{CanonicalJson, DetJson, Json, XorAead};
    use crate::protocol::v1::{Aead, AeadError, AeadKey, AeadNonce, CanonicalJsonError};

    #[test]
    fn xor_aead_rejects_short_and_wrong_key() {
        let aead = XorAead;
        let key = AeadKey::from_bytes([1u8; 32]);
        let nonce = AeadNonce::from_bytes(core::array::from_fn(|i| 2u8.wrapping_add(i as u8)));
        let ct = aead.seal(&key, &nonce, b"ad", b"pt");
        assert_eq!(aead.open(&key, &nonce, b"ad", &ct).expect("ok"), b"pt");
        let other = AeadKey::from_bytes([3u8; 32]);
        assert_eq!(
            aead.open(&other, &nonce, b"ad", &ct).unwrap_err(),
            AeadError::Open
        );
        assert_eq!(
            aead.open(&key, &nonce, b"xx", &ct).unwrap_err(),
            AeadError::Open
        );
        assert_eq!(
            aead.open(&key, &nonce, b"ad", &[]).unwrap_err(),
            AeadError::Open
        );
        assert_eq!(
            aead.open(&key, &nonce, b"ad", &[0, 10]).unwrap_err(),
            AeadError::Open
        );
        let mut short_aad = aead.seal(&key, &nonce, b"ad", b"pt");
        short_aad[0] = 0xff;
        short_aad[1] = 0xff;
        assert_eq!(
            aead.open(&key, &nonce, b"ad", &short_aad).unwrap_err(),
            AeadError::Open
        );
    }

    #[test]
    fn det_json_roundtrip_and_errors() {
        let port = DetJson;
        assert_eq!(port.decode(b"null").expect("n"), Json::Null);
        assert_eq!(port.decode(b" true ").expect("t"), Json::Bool(true));
        assert_eq!(port.decode(b"false").expect("f"), Json::Bool(false));
        assert_eq!(
            port.decode(br#""hi""#).expect("s"),
            Json::String("hi".into())
        );
        assert_eq!(
            port.decode(br#""a\"b\\c\n\r\t\u0020""#).expect("esc"),
            Json::String("a\"b\\c\n\r\t ".into())
        );
        assert_eq!(port.decode(b"[]").expect("a"), Json::Array(Vec::new()));
        assert_eq!(port.decode(b"{}").expect("o"), Json::Object(Vec::new()));
        assert_eq!(
            port.decode(b"[1]").unwrap_err(),
            CanonicalJsonError::Invalid
        );
        assert_eq!(
            port.decode(b"{,}").unwrap_err(),
            CanonicalJsonError::Invalid
        );
        assert_eq!(port.decode(b"{").unwrap_err(), CanonicalJsonError::Invalid);
        assert_eq!(port.decode(b"[").unwrap_err(), CanonicalJsonError::Invalid);
        assert_eq!(
            port.decode(b"\"unterminated").unwrap_err(),
            CanonicalJsonError::Invalid
        );
        assert_eq!(
            port.decode(&[0xff]).unwrap_err(),
            CanonicalJsonError::Invalid
        );
        assert_eq!(
            port.decode(b"nullx").unwrap_err(),
            CanonicalJsonError::Invalid
        );
        let obj = Json::Object(vec![
            ("b".into(), Json::Bool(false)),
            ("a".into(), Json::Null),
        ]);
        let encoded = port.encode(&obj);
        assert_eq!(encoded, br#"{"a":null,"b":false}"#);
        assert_eq!(
            port.decode(br#"{"k":[]}"#).expect("nested"),
            Json::Object(vec![("k".into(), Json::Array(Vec::new()))])
        );
        assert_eq!(
            port.decode(b"{\"a\":1}").unwrap_err(),
            CanonicalJsonError::Invalid
        );
        assert_eq!(
            port.decode(br#""\uD800""#).unwrap_err(),
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
            port.decode(br#"{"a"}"#).unwrap_err(),
            CanonicalJsonError::Invalid
        );
        assert_eq!(
            port.decode(br#"[true,]"#).unwrap_err(),
            CanonicalJsonError::Invalid
        );
        assert_eq!(
            port.decode(br#"{"a":true,}"#).unwrap_err(),
            CanonicalJsonError::Invalid
        );
        let _ = port.encode(&Json::String("\u{0001}".into()));
        let _ = port.encode(&Json::Bool(true));
        let _ = port.encode(&Json::Bool(false));
        let _ = port.encode(&Json::Array(vec![Json::Null, Json::Bool(true)]));
        let _ = port.encode(&Json::String("\"\\\n\r\t".into()));
        assert_eq!(
            port.decode(b"[true x]").unwrap_err(),
            CanonicalJsonError::Invalid
        );
        assert_eq!(
            port.decode(br#"{"a":true x}"#).unwrap_err(),
            CanonicalJsonError::Invalid
        );
        assert_eq!(
            port.decode(br#"{a:true}"#).unwrap_err(),
            CanonicalJsonError::Invalid
        );
        assert_eq!(
            port.decode(br#"[true,false]"#).expect("two"),
            Json::Array(vec![Json::Bool(true), Json::Bool(false)])
        );
        assert_eq!(
            port.decode(br#"{"a":true,"b":false}"#).expect("two keys"),
            Json::Object(vec![
                ("a".into(), Json::Bool(true)),
                ("b".into(), Json::Bool(false)),
            ])
        );
        assert_eq!(
            port.decode(br#""\u00zz""#).unwrap_err(),
            CanonicalJsonError::Invalid
        );
    }
}
