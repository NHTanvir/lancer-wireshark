//! `--decode-as` overrides. Persisted in the profile's `decode_as_entries` file.

use parking_lot::RwLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeAsEntry {
    pub table: String,
    pub key: DecodeAsKey,
    pub dissector_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeAsKey {
    Uint(u32),
    String(String),
}

#[derive(Default)]
pub struct DecodeAsTable {
    entries: RwLock<Vec<DecodeAsEntry>>,
}

impl DecodeAsTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse the `tcp.port==8443,tls` form (or alternative `tcp.port,8443,tls`).
    pub fn parse(s: &str) -> Result<DecodeAsEntry, String> {
        let s = s.trim();
        // Allow both `table==key,dissector` and `table,key,dissector`.
        if let Some((left, dissector)) = s.rsplit_once(',') {
            if let Some((table, key)) = left.split_once("==") {
                return Ok(DecodeAsEntry {
                    table: table.trim().to_string(),
                    key: parse_key(key.trim()),
                    dissector_name: dissector.trim().to_string(),
                });
            }
            if let Some((table, key)) = left.split_once(',') {
                return Ok(DecodeAsEntry {
                    table: table.trim().to_string(),
                    key: parse_key(key.trim()),
                    dissector_name: dissector.trim().to_string(),
                });
            }
        }
        Err(format!("could not parse --decode-as expression {s:?}"))
    }

    pub fn insert(&self, entry: DecodeAsEntry) {
        let mut g = self.entries.write();
        g.retain(|e| !(e.table == entry.table && e.key == entry.key));
        g.push(entry);
    }

    pub fn entries(&self) -> Vec<DecodeAsEntry> {
        self.entries.read().clone()
    }

    pub fn for_table_uint(&self, table: &str, key: u32) -> Option<String> {
        self.entries.read().iter().find_map(|e| {
            if e.table == table {
                if let DecodeAsKey::Uint(k) = e.key {
                    if k == key {
                        return Some(e.dissector_name.clone());
                    }
                }
            }
            None
        })
    }
}

fn parse_key(s: &str) -> DecodeAsKey {
    if let Ok(v) = s.parse::<u32>() {
        return DecodeAsKey::Uint(v);
    }
    if let Some(stripped) = s.strip_prefix("0x") {
        if let Ok(v) = u32::from_str_radix(stripped, 16) {
            return DecodeAsKey::Uint(v);
        }
    }
    DecodeAsKey::String(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_canonical() {
        let e = DecodeAsTable::parse("tcp.port==8443,tls").unwrap();
        assert_eq!(e.table, "tcp.port");
        assert_eq!(e.key, DecodeAsKey::Uint(8443));
        assert_eq!(e.dissector_name, "tls");
    }
}
