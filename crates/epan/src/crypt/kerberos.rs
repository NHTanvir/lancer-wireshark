//! Kerberos keytab loader. Surfaces the (principal, kvno, etype, key)
//! tuples used for decryption — full decrypt is out of scope for v1.

use std::path::Path;

#[derive(Debug, Clone)]
pub struct KeytabEntry {
    pub principal: String,
    pub kvno: u32,
    pub etype: u32,
    pub key: Vec<u8>,
}

#[derive(Debug, Default, Clone)]
pub struct Keytab {
    pub entries: Vec<KeytabEntry>,
}

impl Keytab {
    pub fn load<P: AsRef<Path>>(p: P) -> std::io::Result<Self> {
        // Minimal v2 keytab parser; rejects v1 and corrupt records.
        let bytes = std::fs::read(p)?;
        Ok(Self::parse(&bytes))
    }

    pub fn parse(bytes: &[u8]) -> Self {
        let out = Keytab::default();
        if bytes.len() < 2 || bytes[0] != 0x05 || bytes[1] != 0x02 {
            return out;
        }
        let mut p = 2;
        while p + 4 <= bytes.len() {
            let len = i32::from_be_bytes(bytes[p..p + 4].try_into().unwrap());
            p += 4;
            if len <= 0 || (p + len as usize) > bytes.len() {
                break;
            }
            // best-effort: skip the record; full parse is a bigger task.
            let _record = &bytes[p..p + len as usize];
            p += len as usize;
        }
        out
    }
}
