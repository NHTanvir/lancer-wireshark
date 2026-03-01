//! `/etc/ethers`-style MAC → name file parser, lazy-loaded.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Default)]
pub struct EthersFile {
    table: RwLock<HashMap<[u8; 6], String>>,
}

impl EthersFile {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an entry, replacing any existing one.
    pub fn insert(&self, mac: [u8; 6], name: String) {
        self.table.write().insert(mac, name);
    }

    pub fn lookup(&self, mac: [u8; 6]) -> Option<String> {
        self.table.read().get(&mac).cloned()
    }

    /// Load entries from `/etc/ethers` (or `%APPDATA%\Wireshark\ethers`).
    pub fn load_default(&self) {
        for path in default_paths() {
            if let Ok(s) = std::fs::read_to_string(&path) {
                self.load_str(&s);
            }
        }
    }

    pub fn load_str(&self, contents: &str) {
        let mut map = self.table.write();
        for line in contents.lines() {
            let trimmed = line.split('#').next().unwrap_or("").trim();
            if trimmed.is_empty() {
                continue;
            }
            let mut parts = trimmed.split_whitespace();
            let mac_str = match parts.next() {
                Some(s) => s,
                None => continue,
            };
            let name = match parts.next() {
                Some(s) => s.to_string(),
                None => continue,
            };
            if let Some(mac) = crate::mac::parse_mac(mac_str) {
                map.insert(mac, name);
            }
        }
    }
}

fn default_paths() -> Vec<PathBuf> {
    let mut v = vec![PathBuf::from("/etc/ethers")];
    if let Some(d) = directories_paths::config_dir() {
        v.push(d.join("ethers"));
    }
    v
}

mod directories_paths {
    use std::path::PathBuf;
    pub fn config_dir() -> Option<PathBuf> {
        #[cfg(windows)]
        {
            std::env::var_os("APPDATA").map(|s| PathBuf::from(s).join("Wireshark"))
        }
        #[cfg(not(windows))]
        {
            std::env::var_os("HOME").map(|s| PathBuf::from(s).join(".config").join("wireshark"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple() {
        let f = EthersFile::new();
        f.load_str("00:11:22:33:44:55 router\n# comment\n  aa:bb:cc:dd:ee:ff laptop\n");
        assert_eq!(
            f.lookup([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]).as_deref(),
            Some("router")
        );
        assert_eq!(
            f.lookup([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]).as_deref(),
            Some("laptop")
        );
    }
}
