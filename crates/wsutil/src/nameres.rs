//! Name resolution caches mirroring upstream Wireshark's `-N` flag semantics.
//!
//! `m` (MAC), `n` (network), `t` (transport), `N` (external DNS), `d` (captured DNS).
//! Each resolver is bounded by an LRU cap; entries time out via a TTL.

use dashmap::DashMap;
use parking_lot::RwLock;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct NameResolveFlags: u32 {
        const MAC      = 0b0000_0001; // m
        const NETWORK  = 0b0000_0010; // n
        const TRANSPORT= 0b0000_0100; // t
        const EXT_DNS  = 0b0000_1000; // N
        const CAPTURED = 0b0001_0000; // d
        const VLAN     = 0b0010_0000; // v
        const SS7      = 0b0100_0000; // s
        const ALL = 0xFFFF_FFFF;
        const NONE = 0;
    }
}

impl Default for NameResolveFlags {
    fn default() -> Self {
        NameResolveFlags::MAC | NameResolveFlags::TRANSPORT
    }
}

impl NameResolveFlags {
    pub fn parse(s: &str) -> Self {
        let mut f = NameResolveFlags::NONE;
        for ch in s.chars() {
            match ch {
                'm' => f |= NameResolveFlags::MAC,
                'n' => f |= NameResolveFlags::NETWORK,
                't' => f |= NameResolveFlags::TRANSPORT,
                'N' => f |= NameResolveFlags::EXT_DNS,
                'd' => f |= NameResolveFlags::CAPTURED,
                'v' => f |= NameResolveFlags::VLAN,
                's' => f |= NameResolveFlags::SS7,
                _ => {}
            }
        }
        f
    }
}

/// A simple, bounded, TTL-respecting map.
struct Cache<K: Eq + std::hash::Hash, V: Clone> {
    inner: DashMap<K, (V, Instant)>,
    ttl: Duration,
    cap: usize,
}

impl<K: Eq + std::hash::Hash + Clone, V: Clone> Cache<K, V> {
    fn new(cap: usize, ttl: Duration) -> Self {
        Self {
            inner: DashMap::with_capacity(cap),
            ttl,
            cap,
        }
    }
    fn get(&self, k: &K) -> Option<V> {
        let entry = self.inner.get(k)?;
        let (v, ts) = entry.value().clone();
        if ts.elapsed() > self.ttl {
            drop(entry);
            self.inner.remove(k);
            None
        } else {
            Some(v)
        }
    }
    fn put(&self, k: K, v: V) {
        if self.inner.len() >= self.cap {
            // crude eviction — drop a few oldest entries
            let to_drop: Vec<_> = self
                .inner
                .iter()
                .take(self.cap / 32 + 1)
                .map(|r| r.key().clone())
                .collect();
            for k in to_drop {
                self.inner.remove(&k);
            }
        }
        self.inner.insert(k, (v, Instant::now()));
    }
}

pub struct NameResolver {
    flags: RwLock<NameResolveFlags>,
    mac: Cache<[u8; 6], String>,
    ipv4: Cache<Ipv4Addr, String>,
    ipv6: Cache<Ipv6Addr, String>,
    hosts: Arc<crate::hosts::HostsFile>,
    ethers: Arc<crate::ethers::EthersFile>,
}

impl NameResolver {
    pub fn new() -> Self {
        let ttl = Duration::from_secs(600);
        Self {
            flags: RwLock::new(NameResolveFlags::default()),
            mac: Cache::new(8192, ttl),
            ipv4: Cache::new(8192, ttl),
            ipv6: Cache::new(8192, ttl),
            hosts: Arc::new(crate::hosts::HostsFile::default()),
            ethers: Arc::new(crate::ethers::EthersFile::default()),
        }
    }

    pub fn with_flags(self, flags: NameResolveFlags) -> Self {
        *self.flags.write() = flags;
        self
    }

    pub fn set_flags(&self, flags: NameResolveFlags) {
        *self.flags.write() = flags;
    }

    pub fn flags(&self) -> NameResolveFlags {
        *self.flags.read()
    }

    pub fn disable_all(&self) {
        *self.flags.write() = NameResolveFlags::NONE;
    }

    /// MAC → label. Falls back to OUI-prefixed short form, then raw hex.
    pub fn resolve_mac(&self, mac: [u8; 6]) -> String {
        if !self.flags().contains(NameResolveFlags::MAC) {
            return crate::mac::format_mac(mac);
        }
        if let Some(v) = self.mac.get(&mac) {
            return v;
        }
        if let Some(name) = self.ethers.lookup(mac) {
            self.mac.put(mac, name.clone());
            return name;
        }
        let label = if let Some(vendor) = crate::oui::lookup(mac) {
            format!("{}_{:02x}:{:02x}:{:02x}", vendor.split_whitespace().next().unwrap_or(vendor), mac[3], mac[4], mac[5])
        } else {
            crate::mac::format_mac(mac)
        };
        self.mac.put(mac, label.clone());
        label
    }

    pub fn resolve_ipv4(&self, ip: Ipv4Addr) -> String {
        if !self.flags().intersects(NameResolveFlags::NETWORK | NameResolveFlags::EXT_DNS | NameResolveFlags::CAPTURED) {
            return ip.to_string();
        }
        if let Some(v) = self.ipv4.get(&ip) {
            return v;
        }
        if let Some(name) = self.hosts.lookup_v4(ip) {
            self.ipv4.put(ip, name.clone());
            return name;
        }
        ip.to_string()
    }

    pub fn resolve_ipv6(&self, ip: Ipv6Addr) -> String {
        if !self.flags().intersects(NameResolveFlags::NETWORK | NameResolveFlags::EXT_DNS | NameResolveFlags::CAPTURED) {
            return ip.to_string();
        }
        if let Some(v) = self.ipv6.get(&ip) {
            return v;
        }
        if let Some(name) = self.hosts.lookup_v6(ip) {
            self.ipv6.put(ip, name.clone());
            return name;
        }
        ip.to_string()
    }

    pub fn resolve_ip(&self, ip: IpAddr) -> String {
        match ip {
            IpAddr::V4(v) => self.resolve_ipv4(v),
            IpAddr::V6(v) => self.resolve_ipv6(v),
        }
    }

    pub fn record_captured_dns_v4(&self, ip: Ipv4Addr, name: String) {
        if self.flags().contains(NameResolveFlags::CAPTURED) {
            self.ipv4.put(ip, name);
        }
    }

    pub fn record_captured_dns_v6(&self, ip: Ipv6Addr, name: String) {
        if self.flags().contains(NameResolveFlags::CAPTURED) {
            self.ipv6.put(ip, name);
        }
    }

    /// Look up the IANA short service-name for a TCP/UDP port if transport
    /// resolution is enabled — otherwise the numeric string.
    pub fn resolve_port(&self, port: u16, proto: crate::ports::L4Proto) -> String {
        if !self.flags().contains(NameResolveFlags::TRANSPORT) {
            return port.to_string();
        }
        crate::ports::lookup(port, proto)
            .map(|s| s.to_string())
            .unwrap_or_else(|| port.to_string())
    }
}

impl Default for NameResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_flags() {
        let r = NameResolver::new();
        assert!(r.flags().contains(NameResolveFlags::MAC));
    }

    #[test]
    fn disable_works() {
        let r = NameResolver::new();
        r.disable_all();
        assert_eq!(r.flags(), NameResolveFlags::NONE);
    }

    #[test]
    fn parse_flag_str() {
        let f = NameResolveFlags::parse("mNt");
        assert!(f.contains(NameResolveFlags::MAC));
        assert!(f.contains(NameResolveFlags::EXT_DNS));
        assert!(f.contains(NameResolveFlags::TRANSPORT));
        assert!(!f.contains(NameResolveFlags::CAPTURED));
    }
}
