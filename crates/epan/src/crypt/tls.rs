//! TLS 1.2 / 1.3 record-layer decryption driven by an [`crate::crypt::KeyLog`].
//!
//! Owns the per-conversation TLS state machine: which secret is current,
//! which cipher-suite is negotiated, the record sequence number.

use super::keylog::{KeyLog, KeyLogSecret};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Tls10,
    Tls11,
    Tls12,
    Tls13,
    Dtls10,
    Dtls12,
    Dtls13,
}

impl TlsVersion {
    pub fn parse(v: u16) -> Option<Self> {
        Some(match v {
            0x0301 => TlsVersion::Tls10,
            0x0302 => TlsVersion::Tls11,
            0x0303 => TlsVersion::Tls12,
            0x0304 => TlsVersion::Tls13,
            0xfeff => TlsVersion::Dtls10,
            0xfefd => TlsVersion::Dtls12,
            0xfefc => TlsVersion::Dtls13,
            _ => return None,
        })
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            TlsVersion::Tls10 => "TLS 1.0",
            TlsVersion::Tls11 => "TLS 1.1",
            TlsVersion::Tls12 => "TLS 1.2",
            TlsVersion::Tls13 => "TLS 1.3",
            TlsVersion::Dtls10 => "DTLS 1.0",
            TlsVersion::Dtls12 => "DTLS 1.2",
            TlsVersion::Dtls13 => "DTLS 1.3",
        }
    }
}

/// Derive secret via TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1).
pub fn hkdf_expand_label(prk: &[u8], label: &str, context: &[u8], length: usize) -> Vec<u8> {
    let label_full = [b"tls13 ", label.as_bytes()].concat();
    let mut info = Vec::with_capacity(2 + 1 + label_full.len() + 1 + context.len());
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push(label_full.len() as u8);
    info.extend_from_slice(&label_full);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hkdf_expand(prk, &info, length)
}

pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(salt).unwrap();
    mac.update(ikm);
    mac.finalize().into_bytes().to_vec()
}

pub fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    // RFC 5869, T(0)=empty, T(i) = HMAC(prk, T(i-1) || info || i)
    let mut out = Vec::with_capacity(length);
    let mut t_prev: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while out.len() < length {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(prk).unwrap();
        mac.update(&t_prev);
        mac.update(info);
        mac.update(&[counter]);
        let t_i = mac.finalize().into_bytes().to_vec();
        out.extend_from_slice(&t_i);
        t_prev = t_i;
        counter = counter.wrapping_add(1);
    }
    out.truncate(length);
    out
}

/// Compute master secret from CLIENT_RANDOM-style entry (TLS 1.2 PRF).
/// Uses the SHA-256 PRF; TLS 1.2 with SHA-384 PRF cipher suites would need a SHA-384 variant.
pub fn tls12_master_secret(pre_master: &[u8], client_random: &[u8], server_random: &[u8]) -> Vec<u8> {
    let mut seed = Vec::with_capacity(13 + client_random.len() + server_random.len());
    seed.extend_from_slice(b"master secret");
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);
    prf_sha256(pre_master, &seed, 48)
}

pub fn prf_sha256(secret: &[u8], seed: &[u8], length: usize) -> Vec<u8> {
    // P_hash with SHA-256: A(0)=seed, A(i)=HMAC(secret, A(i-1)); output = HMAC(secret, A(i) || seed)
    let mut out = Vec::with_capacity(length);
    let mut a: Vec<u8> = {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).unwrap();
        mac.update(seed);
        mac.finalize().into_bytes().to_vec()
    };
    while out.len() < length {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).unwrap();
        mac.update(&a);
        mac.update(seed);
        out.extend_from_slice(&mac.finalize().into_bytes());
        let mut mac2 = <Hmac<Sha256> as Mac>::new_from_slice(secret).unwrap();
        mac2.update(&a);
        a = mac2.finalize().into_bytes().to_vec();
    }
    out.truncate(length);
    out
}

/// Convenience wrapper used by the TLS dissector: given the client_random
/// it received in ClientHello, find the matching secret in the keylog.
pub struct TlsDecryptor<'a> {
    pub keylog: &'a KeyLog,
}

impl<'a> TlsDecryptor<'a> {
    pub fn new(keylog: &'a KeyLog) -> Self {
        Self { keylog }
    }

    pub fn lookup_tls12(&self, client_random: &[u8]) -> Option<Vec<u8>> {
        self.keylog
            .find(&KeyLogSecret::Tls12ClientRandom, client_random)
            .map(|e| e.secret.clone())
    }

    pub fn lookup_tls13(&self, label: &KeyLogSecret, client_random: &[u8]) -> Option<Vec<u8>> {
        self.keylog.find(label, client_random).map(|e| e.secret.clone())
    }
}

/// Compute a transcript SHA-256 digest from a list of handshake message bytes.
pub fn transcript_sha256(messages: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha256::new();
    for m in messages {
        h.update(m);
    }
    h.finalize().to_vec()
}

pub fn transcript_sha384(messages: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha384::new();
    for m in messages {
        h.update(m);
    }
    h.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_extract_smoke() {
        // RFC 5869 test vector 1 (truncated)
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let prk = hkdf_extract(&salt, &ikm);
        // Expected PRK in RFC 5869 §A.1
        assert_eq!(
            hex::encode(&prk),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
    }

    #[test]
    fn expand_label_lengths() {
        let prk = vec![0u8; 32];
        let out = hkdf_expand_label(&prk, "key", &[], 16);
        assert_eq!(out.len(), 16);
    }
}
