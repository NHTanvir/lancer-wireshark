//! JA3 / JA4 TLS fingerprint computation.
//!
//! JA3 string = SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
//! JA4 string = QTcd_<hex of first 12 chars of SHA256(cipher_csv)>_<hex of first 12 chars of SHA256(extension_csv)>
//!
//! We compute the JA3 string for the ClientHello at `hs_off` and an
//! abbreviated JA4-style identifier.

use sha2::{Digest, Sha256};

pub fn md5_hex(s: &str) -> String {
    // Use SHA-256 truncated to 32 hex chars rather than pulling in `md-5`.
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(&h.finalize()[..16])
}

pub fn compute_ja3(buf: &[u8], hs_off: usize) -> Option<String> {
    let hs = buf.get(hs_off..)?;
    // ClientHello: 1 type + 3 length + 2 version + 32 random + sid + cs + comp + ext
    if hs.len() < 4 { return None; }
    let total = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | hs[3] as usize;
    if hs.len() < 4 + total { return None; }
    let body = &hs[4..4 + total];
    if body.len() < 2 + 32 + 1 { return None; }
    let version = u16::from_be_bytes([body[0], body[1]]);
    let mut p = 2 + 32;
    let sid_len = body[p] as usize;
    p += 1 + sid_len;
    if p + 2 > body.len() { return None; }
    let cs_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    if p + cs_len > body.len() { return None; }
    let ciphers: Vec<u16> = body[p..p + cs_len]
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .filter(|v| !is_grease(*v))
        .collect();
    p += cs_len;
    if p >= body.len() { return None; }
    let comp_len = body[p] as usize;
    p += 1 + comp_len;
    if p + 2 > body.len() { return None; }
    let ext_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let ext_end = p + ext_len;
    let mut ext_types: Vec<u16> = Vec::new();
    let mut curves: Vec<u16> = Vec::new();
    let mut formats: Vec<u8> = Vec::new();
    while p + 4 <= ext_end && p + 4 <= body.len() {
        let et = u16::from_be_bytes([body[p], body[p + 1]]);
        let el = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
        p += 4;
        if !is_grease(et) {
            ext_types.push(et);
        }
        if et == 0x000A && el >= 2 && p + el <= body.len() {
            let curve_list_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
            let start = p + 2;
            for c in body.get(start..start + curve_list_len)?.chunks_exact(2) {
                let v = u16::from_be_bytes([c[0], c[1]]);
                if !is_grease(v) {
                    curves.push(v);
                }
            }
        }
        if et == 0x000B && el >= 1 && p + el <= body.len() {
            let l = body[p] as usize;
            for &b in body.get(p + 1..p + 1 + l)? {
                formats.push(b);
            }
        }
        p += el;
    }
    Some(format!(
        "{},{},{},{},{}",
        version,
        ciphers.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("-"),
        ext_types.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("-"),
        curves.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("-"),
        formats.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("-"),
    ))
}

pub fn compute_ja4(buf: &[u8], hs_off: usize) -> Option<String> {
    let raw = compute_ja3(buf, hs_off)?;
    let parts: Vec<&str> = raw.split(',').collect();
    if parts.len() < 5 { return None; }
    let ciphers = parts[1];
    let exts = parts[2];
    let cipher_count = if ciphers.is_empty() { 0 } else { ciphers.split('-').count() };
    let ext_count = if exts.is_empty() { 0 } else { exts.split('-').count() };
    let mut hc = Sha256::new();
    hc.update(ciphers.as_bytes());
    let cipher_hash = hex::encode(&hc.finalize()[..6]);
    let mut he = Sha256::new();
    he.update(exts.as_bytes());
    let ext_hash = hex::encode(&he.finalize()[..6]);
    Some(format!("t13d{cipher_count:02}{ext_count:02}_{cipher_hash}_{ext_hash}"))
}

fn is_grease(v: u16) -> bool {
    matches!(
        v,
        0x0a0a | 0x1a1a | 0x2a2a | 0x3a3a | 0x4a4a | 0x5a5a | 0x6a6a | 0x7a7a |
        0x8a8a | 0x9a9a | 0xaaaa | 0xbaba | 0xcaca | 0xdada | 0xeaea | 0xfafa
    )
}
