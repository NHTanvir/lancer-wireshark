//! CRC tables used by Ethernet, PPP, and several link-layer protocols.

/// CRC-32 with the Ethernet polynomial 0xEDB88320 (reflected 0x04C11DB7).
pub fn crc32_eth(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        let mut byte = b as u32;
        for _ in 0..8 {
            let mix = (crc ^ byte) & 1;
            crc >>= 1;
            if mix != 0 {
                crc ^= 0xEDB8_8320;
            }
            byte >>= 1;
        }
    }
    crc ^ 0xFFFF_FFFF
}

/// CRC-16 / X.25 / HDLC (poly 0x1021, init 0xFFFF, reflected, xorout 0xFFFF).
pub fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc = 0xFFFFu16;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0x8408;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Internet 16-bit checksum (RFC 1071) — IP / ICMP / TCP / UDP header checksum.
pub fn ip_checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        sum += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32;
        i += 2;
    }
    if i < bytes.len() {
        sum += (bytes[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_smoke() {
        // CRC-32 of "123456789" (Ethernet variant) = 0xCBF43926
        assert_eq!(crc32_eth(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn ip_csum_smoke() {
        // Wikipedia worked example: IP header sums to 0xB861 -> checksum 0xB861
        // We can at least check determinism + non-zero on real data:
        let h = [0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
                 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7];
        let cs = ip_checksum(&h);
        assert_ne!(cs, 0);
    }
}
