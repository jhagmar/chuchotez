//! Shared v1 test doubles.

use super::{
    Address, Aead, AeadError, AeadKey, AeadNonce, Argon2Error, Argon2id, Base64Url, Base64UrlError,
    CanonicalJson, CanonicalJsonError, Compress, CompressError, Defaults, DurableChannel, Engine,
    HmacSha256, HmacSha256Key, HmacSha256Mac, Json, Kem, KemError, KemSeed, KeyPair, Kind,
    NotificationPrivacy, Policy, SECRET_LEN, Sha256, Sign, SignError, SignSeed, SigningKeyPair,
    Suite, kem_ct_len, kem_pk_len, sign_pk_len, sign_sig_len,
};
use crate::protocol::{Random32, Rng};
use std::cell::Cell;
use std::sync::Arc;

pub(crate) fn fill(byte: u8) -> [u8; SECRET_LEN] {
    [byte; SECRET_LEN]
}

pub(crate) struct SeedRng(pub [u8; SECRET_LEN]);

impl Rng for SeedRng {
    fn random32(&self) -> Random32 {
        Random32::from_bytes(self.0)
    }
}

pub(crate) struct CounterRng {
    n: Cell<u64>,
}

impl CounterRng {
    pub(crate) fn new() -> Self {
        Self { n: Cell::new(0) }
    }
}

impl Rng for CounterRng {
    fn random32(&self) -> Random32 {
        let i = self.n.get();
        self.n.set(i + 1);
        let mut bytes = [0u8; SECRET_LEN];
        bytes[SECRET_LEN - 8..].copy_from_slice(&i.to_be_bytes());
        Random32::from_bytes(bytes)
    }
}

pub(crate) fn sample_durable() -> DurableChannel {
    DurableChannel::new(
        Kind::try_from("nostr").expect("kind"),
        Address::try_from("wss://relay.example").expect("addr"),
    )
}

pub(crate) fn sample_defaults() -> Defaults {
    Defaults::try_new(
        vec![sample_durable()],
        Vec::new(),
        true,
        true,
        true,
        None,
        false,
        NotificationPrivacy::Name,
    )
    .expect("defaults")
}

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
        if src.starts_with(&[0xfe, 0xfd]) {
            return Err(CompressError::Codec);
        }
        let n = src.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
        Ok(src[..n].to_vec())
    }
}

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

pub(crate) struct XorAead;

impl Aead for XorAead {
    fn seal(&self, key: &AeadKey, nonce: &AeadNonce, _aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(plaintext.len() + 16);
        for (i, byte) in plaintext.iter().enumerate() {
            out.push(
                byte ^ key.as_bytes()[i % key.as_bytes().len()]
                    ^ nonce.as_bytes()[i % nonce.as_bytes().len()],
            );
        }
        out.extend_from_slice(&key.as_bytes()[..16]);
        out
    }

    fn open(
        &self,
        key: &AeadKey,
        nonce: &AeadNonce,
        _aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        if ciphertext.len() < 16 {
            return Err(AeadError::Open);
        }
        let (body, tag) = ciphertext.split_at(ciphertext.len() - 16);
        if tag != &key.as_bytes()[..16] {
            return Err(AeadError::Open);
        }
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

pub(crate) struct DetJson;

impl CanonicalJson for DetJson {
    fn encode(&self, value: &Json) -> Vec<u8> {
        let mut out = String::new();
        write_json(value, &mut out);
        out.into_bytes()
    }

    fn decode(&self, bytes: &[u8]) -> Result<Json, CanonicalJsonError> {
        decode_json(bytes)
    }
}

fn decode_json(bytes: &[u8]) -> Result<Json, CanonicalJsonError> {
    let text = core::str::from_utf8(bytes).map_err(|_| CanonicalJsonError::Invalid)?;
    let mut p = Parser { rest: text };
    let value = p.value()?;
    p.skip_ws();
    if !p.rest.is_empty() {
        return Err(CanonicalJsonError::Invalid);
    }
    Ok(value)
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
        if self
            .rest
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_digit())
        {
            let bytes = self.rest.as_bytes();
            let mut i = 0;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            let n = self.rest[..i]
                .parse::<u64>()
                .map_err(|_| CanonicalJsonError::Invalid)?;
            self.rest = &self.rest[i..];
            return Ok(Json::Number(n));
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

fn write_json(value: &Json, out: &mut String) {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(true) => out.push_str("true"),
        Json::Bool(false) => out.push_str("false"),
        Json::Number(n) => out.push_str(&n.to_string()),
        Json::String(s) => {
            out.push('"');
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    c => out.push(c),
                }
            }
            out.push('"');
        }
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
                out.push('"');
                out.push_str(k);
                out.push_str("\":");
                write_json(v, out);
            }
            out.push('}');
        }
    }
}

pub(crate) struct EchoKem;

impl Kem for EchoKem {
    fn generate(&self, policy: Policy, seed: &KemSeed) -> Result<KeyPair, KemError> {
        let n = kem_pk_len(policy);
        let mut public = vec![0u8; n];
        let seed32 = &seed.as_bytes()[..SECRET_LEN];
        for (i, byte) in public.iter_mut().enumerate() {
            *byte = seed32[i % SECRET_LEN];
        }
        Ok(KeyPair::from_parts(public, seed32.to_vec()))
    }

    fn wrap(
        &self,
        policy: Policy,
        pk: &[u8],
        seed: &KemSeed,
    ) -> Result<(Vec<u8>, Vec<u8>), KemError> {
        if pk.len() != kem_pk_len(policy) {
            return Err(KemError::Wrap);
        }
        let mut shared = [0u8; 32];
        shared.copy_from_slice(&seed.as_bytes()[..32]);
        if let Some(p) = pk.first() {
            shared[0] ^= p;
        }
        let mut ct = vec![0u8; kem_ct_len(policy)];
        let n = 32.min(ct.len());
        ct[..n].copy_from_slice(&shared[..n]);
        Ok((shared.to_vec(), ct))
    }

    fn unwrap(&self, _policy: Policy, _sk: &[u8], kem_ct: &[u8]) -> Result<Vec<u8>, KemError> {
        if kem_ct.len() >= 2 && kem_ct[0] == 0xee && kem_ct[1] == 0xfd {
            return Err(KemError::Wrap);
        }
        if kem_ct.len() >= 2 && kem_ct[0] == 0xee && kem_ct[1] == 0xfe {
            return Ok(vec![0u8; 31]);
        }
        let mut shared = vec![0u8; 32];
        let n = 32.min(kem_ct.len());
        shared[..n].copy_from_slice(&kem_ct[..n]);
        Ok(shared)
    }
}

pub(crate) struct EchoSign;

impl Sign for EchoSign {
    fn generate(&self, policy: Policy, seed: &SignSeed) -> Result<SigningKeyPair, SignError> {
        let n = sign_pk_len(policy);
        let mut public = vec![0u8; n];
        let seed32 = &seed.as_bytes()[..SECRET_LEN];
        for (i, byte) in public.iter_mut().enumerate() {
            *byte = seed32[i % SECRET_LEN];
        }
        Ok(SigningKeyPair::from_parts(public, seed32.to_vec()))
    }

    fn sign(
        &self,
        policy: Policy,
        sk: &[u8],
        message: &[u8],
        _seed: &Random32,
    ) -> Result<Vec<u8>, SignError> {
        let n = sign_sig_len(policy);
        let mut sig = vec![0u8; n];
        for (i, byte) in sig.iter_mut().enumerate() {
            *byte = sk.get(i % sk.len()).copied().unwrap_or(0)
                ^ message.get(i % message.len().max(1)).copied().unwrap_or(0);
        }
        Ok(sig)
    }

    fn verify(
        &self,
        policy: Policy,
        pk: &[u8],
        message: &[u8],
        sig: &[u8],
    ) -> Result<(), SignError> {
        let expect = self.sign(policy, pk, message, &Random32::from_bytes([0; 32]))?;
        if expect == sig {
            Ok(())
        } else {
            Err(SignError::Sign)
        }
    }
}

pub(crate) struct XorHash;

impl Sha256 for XorHash {
    fn hash(&self, data: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in data.iter().enumerate() {
            out[i % 32] ^= b;
        }
        out
    }
}

pub(crate) struct EchoArgon;

impl Argon2id for EchoArgon {
    fn hash(
        &self,
        passphrase: &[u8],
        salt: &[u8; 16],
        _m: u32,
        _t: u32,
        _p: u32,
    ) -> Result<[u8; 32], Argon2Error> {
        let mut out = [0u8; 32];
        for (i, b) in passphrase.iter().chain(salt.iter()).enumerate() {
            out[i % 32] ^= b;
        }
        Ok(out)
    }
}

pub(crate) fn test_suite() -> Suite {
    Suite::new(
        Arc::new(XorHmac),
        Arc::new(IdentityCompress),
        Arc::new(HexB64),
        Arc::new(XorAead),
        Arc::new(DetJson),
        Arc::new(EchoKem),
        Arc::new(EchoSign),
        Arc::new(XorHash),
        Arc::new(EchoArgon),
    )
}

pub(crate) fn test_engine() -> Engine {
    Engine::new(test_suite(), sample_defaults())
}

#[cfg(test)]
mod tests {
    use super::{
        CounterRng, EchoArgon, EchoKem, EchoSign, IdentityCompress, SeedRng, XorAead, XorHash,
        XorHmac, fill, sample_defaults, test_engine,
    };
    use crate::protocol::Rng;
    use crate::protocol::v1::{
        Aead, Argon2id, Base64Url, CanonicalJson, Compress, HmacSha256, Kem, Policy, Sha256, Sign,
        UnlockSecret,
    };

    #[test]
    fn doubles() {
        let rng = CounterRng::new();
        assert_ne!(
            rng.random32().as_bytes(),
            SeedRng(fill(1)).random32().as_bytes()
        );
        assert_eq!(XorHash.hash(b"ab")[0], b'a');
        assert!(
            EchoArgon
                .hash(b"passpass", &super::super::argon::fixture_salt(), 8, 1, 1)
                .is_ok()
        );
        let seed = crate::protocol::v1::KemSeed::from_bytes([2; 64]);
        let keys = EchoKem.generate(Policy::Classic, &seed).expect("k");
        let (ss, ct) = EchoKem
            .wrap(Policy::Classic, keys.public_bytes(), &seed)
            .expect("w");
        assert!(EchoKem.wrap(Policy::Classic, &[], &seed).is_err());
        assert_eq!(
            EchoKem
                .unwrap(Policy::Classic, keys.secret_bytes(), &ct)
                .expect("u")
                .len(),
            32
        );
        let _ = ss;
        let sseed = crate::protocol::v1::SignSeed::from_bytes([3; 64]);
        let sk = EchoSign.generate(Policy::Classic, &sseed).expect("s");
        let sig = EchoSign
            .sign(Policy::Classic, sk.secret_bytes(), b"m", &rng.random32())
            .expect("sig");
        assert!(
            EchoSign
                .verify(Policy::Classic, sk.secret_bytes(), b"m", &sig)
                .is_ok()
        );
        assert_eq!(IdentityCompress.compress(b"x"), b"x");
        assert!(IdentityCompress.decompress(&[0; 8], 4).is_err());
        assert!(IdentityCompress.decompress(&[0xfe, 0xfd], 8).is_err());
        assert_eq!(
            IdentityCompress.decompress(&[b'a', 0, 0], 8).expect("z"),
            b"a"
        );
        assert!(super::HexB64.decode("zz").is_err());
        assert!(super::HexB64.decode("0g").is_err());
        assert!(super::HexB64.decode("0").is_err());
        let key = crate::protocol::v1::AeadKey::from_bytes([1; 32]);
        let nonce = crate::protocol::v1::AeadNonce::from_bytes([2; 12]);
        let ct = XorAead.seal(&key, &nonce, b"", b"pt");
        assert_eq!(XorAead.open(&key, &nonce, b"", &ct).expect("o"), b"pt");
        assert!(XorAead.open(&key, &nonce, b"", b"x").is_err());
        assert!(XorAead.open(&key, &nonce, b"", &[0; 40]).is_err());
        let json = super::DetJson;
        assert!(json.decode(b"{").is_err());
        assert_eq!(
            json.decode(b"null").expect("n"),
            crate::protocol::v1::Json::Null
        );
        assert_eq!(
            json.decode(b"true").expect("t"),
            crate::protocol::v1::Json::Bool(true)
        );
        assert_eq!(
            json.decode(b"false").expect("f"),
            crate::protocol::v1::Json::Bool(false)
        );
        assert_eq!(
            json.decode(b"[]").expect("a"),
            crate::protocol::v1::Json::Array(Vec::new())
        );
        assert_eq!(
            json.decode(b"{}").expect("o"),
            crate::protocol::v1::Json::Object(Vec::new())
        );
        assert_eq!(
            json.decode(br#""hi""#).expect("s"),
            crate::protocol::v1::Json::String("hi".into())
        );
        let escaped = json.encode(&crate::protocol::v1::Json::String("a\"b\\c".into()));
        assert_eq!(
            json.decode(&escaped).expect("esc"),
            crate::protocol::v1::Json::String("a\"b\\c".into())
        );
        assert!(json.decode(b"null x").is_err());
        assert!(json.decode(&[0xff]).is_err());
        assert!(json.decode(b"nope").is_err());
        assert!(json.decode(b"\"unterminated").is_err());
        assert!(json.decode(br#""\q""#).is_err());
        assert!(json.decode(b"[true x]").is_err());
        assert!(json.decode(b"{,}").is_err());
        assert!(json.decode(br#"{"a" true}"#).is_err());
        assert!(json.decode(b"[true,false").is_err());
        assert!(json.decode(br#"{"a":true"#).is_err());
        assert_eq!(
            json.decode(br#"[true,false]"#).expect("arr2"),
            crate::protocol::v1::Json::Array(vec![
                crate::protocol::v1::Json::Bool(true),
                crate::protocol::v1::Json::Bool(false)
            ])
        );
        assert_eq!(
            json.decode(br#"{"a":true,"b":false}"#).expect("obj2"),
            crate::protocol::v1::Json::Object(vec![
                ("a".into(), crate::protocol::v1::Json::Bool(true)),
                ("b".into(), crate::protocol::v1::Json::Bool(false)),
            ])
        );
        assert!(EchoSign.verify(Policy::Classic, &[1], b"m", &[0]).is_err());
        let _ = sample_defaults();
        let mut engine = test_engine();
        let header = engine
            .wrap_dek(&rng, &UnlockSecret::Passphrase("passpass".into()))
            .expect("wrap");
        engine.lock();
        engine
            .unlock(&header.header, &UnlockSecret::Passphrase("passpass".into()))
            .expect("un");
        let mac = XorHmac.mac(
            &crate::protocol::v1::HmacSha256Key::from_bytes([1; 32]),
            b"x",
        );
        assert_eq!(mac.as_bytes()[0], 1 ^ b'x');
    }
}
