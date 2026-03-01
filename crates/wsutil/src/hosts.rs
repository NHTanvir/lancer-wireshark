//! `/etc/hosts`-style IP → name file parser.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

#[derive(Debug, Default)]
pub struct HostsFile {
    v4: RwLock<HashMap<Ipv4Addr, String>>,
    v6: RwLock<HashMap<Ipv6Addr, String>>,
}

impl HostsFile {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn lookup_v4(&self, ip: Ipv4Addr) -> Option<String> {
        self.v4.read().get(&ip).cloned()
    }

    pub fn lookup_v6(&self, ip: Ipv6Addr) -> Option<String> {
        self.v6.read().get(&ip).cloned()
    }

    pub fn insert_v4(&self, ip: Ipv4Addr, name: String) {
        self.v4.write().insert(ip, name);
    }

    pub fn insert_v6(&self, ip: Ipv6Addr, name: String) {
        self.v6.write().insert(ip, name);
    }

    pub fn load_default(&self) {
        for path in default_paths() {
            if let Ok(s) = std::fs::read_to_string(&path) {
                self.load_str(&s);
            }
        }
    }

    pub fn load_str(&self, contents: &str) {
        let mut v4 = self.v4.write();
        let mut v6 = self.v6.write();
        for line in contents.lines() {
            let trimmed = line.split('#').next().unwrap_or("").trim();
            if trimmed.is_empty() {
                continue;
            }
            let mut parts = trimmed.split_whitespace();
            let ip_str = match parts.next() {
                Some(s) => s,
                None => continue,
            };
            let name = match parts.next() {
                Some(s) => s.to_string(),
                None => continue,
            };
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                match ip {
                    IpAddr::V4(a) => {
                        v4.insert(a, name);
                    }
                    IpAddr::V6(a) => {
                        v6.insert(a, name);
                    }
                }
            }
        }
    }
}

fn default_paths() -> Vec<PathBuf> {
    let mut v = vec![PathBuf::from("/etc/hosts")];
    if cfg!(windows) {
        if let Some(d) = std::env::var_os("SystemRoot") {
            v.push(PathBuf::from(d).join("System32/drivers/etc/hosts"));
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_v4() {
        let h = HostsFile::new();
        h.load_str("127.0.0.1 localhost\n10.0.0.1 router\n");
        assert_eq!(
            h.lookup_v4("127.0.0.1".parse().unwrap()).as_deref(),
            Some("localhost")
        );
    }
}
