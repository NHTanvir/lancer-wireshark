//! VLAN ID → name file parser (`vlans` file alongside hosts/ethers).

use parking_lot::RwLock;
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct VlansFile {
    table: RwLock<HashMap<u16, String>>,
}

impl VlansFile {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn insert(&self, id: u16, name: String) {
        self.table.write().insert(id, name);
    }
    pub fn lookup(&self, id: u16) -> Option<String> {
        self.table.read().get(&id).cloned()
    }
    pub fn load_str(&self, contents: &str) {
        let mut t = self.table.write();
        for line in contents.lines() {
            let trimmed = line.split('#').next().unwrap_or("").trim();
            if trimmed.is_empty() {
                continue;
            }
            let mut parts = trimmed.split_whitespace();
            let id = parts.next().and_then(|s| s.parse::<u16>().ok());
            let name = parts.next();
            if let (Some(id), Some(name)) = (id, name) {
                t.insert(id, name.to_string());
            }
        }
    }
}
