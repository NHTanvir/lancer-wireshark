//! MAC address parsing and formatting.

pub fn format_mac(m: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let s = s.trim();
    let sep = if s.contains(':') {
        ':'
    } else if s.contains('-') {
        '-'
    } else {
        return parse_mac_compact(s);
    };
    let parts: Vec<_> = s.split(sep).collect();
    if parts.len() != 6 {
        return None;
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(out)
}

fn parse_mac_compact(s: &str) -> Option<[u8; 6]> {
    let s = s.trim();
    if s.len() != 12 {
        return None;
    }
    let mut out = [0u8; 6];
    for i in 0..6 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

pub fn is_multicast(m: [u8; 6]) -> bool {
    m[0] & 0x01 != 0
}

pub fn is_broadcast(m: [u8; 6]) -> bool {
    m == [0xff; 6]
}

pub fn is_locally_administered(m: [u8; 6]) -> bool {
    m[0] & 0x02 != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_roundtrip() {
        let m = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
        assert_eq!(format_mac(m), "00:1a:2b:3c:4d:5e");
        assert_eq!(parse_mac("00:1a:2b:3c:4d:5e"), Some(m));
        assert_eq!(parse_mac("00-1A-2B-3C-4D-5E"), Some(m));
        assert_eq!(parse_mac("001A2B3C4D5E"), Some(m));
    }

    #[test]
    fn broadcast_check() {
        assert!(is_broadcast([0xff; 6]));
        assert!(is_multicast([0xff; 6]));
    }
}
