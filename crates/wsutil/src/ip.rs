//! IP-address property tests used by dfilter functions
//! (`is_loopback`, `is_multicast`, `is_link_local`, `is_unicast`).

use std::net::{Ipv4Addr, Ipv6Addr};

pub fn is_loopback_v4(a: Ipv4Addr) -> bool {
    a.octets()[0] == 127
}

pub fn is_loopback_v6(a: Ipv6Addr) -> bool {
    a.is_loopback()
}

pub fn is_multicast_v4(a: Ipv4Addr) -> bool {
    (a.octets()[0] & 0xF0) == 0xE0
}

pub fn is_multicast_v6(a: Ipv6Addr) -> bool {
    a.segments()[0] & 0xff00 == 0xff00
}

pub fn is_link_local_v4(a: Ipv4Addr) -> bool {
    let o = a.octets();
    o[0] == 169 && o[1] == 254
}

pub fn is_link_local_v6(a: Ipv6Addr) -> bool {
    (a.segments()[0] & 0xffc0) == 0xfe80
}

pub fn is_unicast_v4(a: Ipv4Addr) -> bool {
    !(is_multicast_v4(a) || a.is_broadcast() || a.is_unspecified())
}

pub fn is_unicast_v6(a: Ipv6Addr) -> bool {
    !(is_multicast_v6(a) || a.is_unspecified())
}

pub fn is_private_v4(a: Ipv4Addr) -> bool {
    let o = a.octets();
    o[0] == 10
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
}

pub fn in_subnet_v4(a: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix > 32 {
        return false;
    }
    let mask: u32 = u32::MAX.checked_shl(32 - prefix as u32).unwrap_or(0);
    u32::from(a) & mask == u32::from(network) & mask
}

pub fn in_subnet_v6(a: Ipv6Addr, network: Ipv6Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix > 128 {
        return false;
    }
    let a = u128::from(a);
    let n = u128::from(network);
    let mask: u128 = u128::MAX.checked_shl(128 - prefix as u32).unwrap_or(0);
    a & mask == n & mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multicast_v4() {
        assert!(is_multicast_v4("224.0.0.1".parse().unwrap()));
        assert!(!is_multicast_v4("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn link_local_v4() {
        assert!(is_link_local_v4("169.254.1.2".parse().unwrap()));
        assert!(!is_link_local_v4("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn subnet_v4_works() {
        let net: Ipv4Addr = "10.0.0.0".parse().unwrap();
        let ip1: Ipv4Addr = "10.5.6.7".parse().unwrap();
        let ip2: Ipv4Addr = "11.5.6.7".parse().unwrap();
        assert!(in_subnet_v4(ip1, net, 8));
        assert!(!in_subnet_v4(ip2, net, 8));
    }
}
