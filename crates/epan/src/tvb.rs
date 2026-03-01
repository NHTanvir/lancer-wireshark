//! Tvbuff — Testy Virtual Buffer. A zero-copy slice over a packet's bytes
//! (or a reassembled buffer) with range-checked typed accessors.

use byteorder::{BigEndian, ByteOrder, LittleEndian};

/// A view into one packet's bytes, possibly nested at an offset for child
/// dissectors. Cheap to clone (it's just three machine words).
#[derive(Debug, Clone, Copy)]
pub struct Tvb<'a> {
    bytes: &'a [u8],
    /// Absolute offset into the original (root) buffer, for tree back-references.
    pub abs_off: usize,
}

impl<'a> Tvb<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, abs_off: 0 }
    }

    pub fn with_abs(bytes: &'a [u8], abs_off: usize) -> Self {
        Self { bytes, abs_off }
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
    pub fn as_slice(&self) -> &'a [u8] {
        self.bytes
    }

    /// Sub-range; out-of-range produces an empty Tvb.
    pub fn subset(&self, off: usize, len: usize) -> Tvb<'a> {
        let end = (off + len).min(self.bytes.len());
        let off = off.min(self.bytes.len());
        Tvb {
            bytes: &self.bytes[off..end],
            abs_off: self.abs_off + off,
        }
    }

    /// Tail starting at `off`.
    pub fn tail(&self, off: usize) -> Tvb<'a> {
        let off = off.min(self.bytes.len());
        Tvb {
            bytes: &self.bytes[off..],
            abs_off: self.abs_off + off,
        }
    }

    pub fn u8(&self, off: usize) -> Result<u8, TvbError> {
        self.bytes.get(off).copied().ok_or(TvbError::ShortBuffer)
    }
    pub fn u16_be(&self, off: usize) -> Result<u16, TvbError> {
        self.read::<2>(off).map(|s| BigEndian::read_u16(&s))
    }
    pub fn u16_le(&self, off: usize) -> Result<u16, TvbError> {
        self.read::<2>(off).map(|s| LittleEndian::read_u16(&s))
    }
    pub fn u24_be(&self, off: usize) -> Result<u32, TvbError> {
        let s = self.read::<3>(off)?;
        Ok(((s[0] as u32) << 16) | ((s[1] as u32) << 8) | s[2] as u32)
    }
    pub fn u32_be(&self, off: usize) -> Result<u32, TvbError> {
        self.read::<4>(off).map(|s| BigEndian::read_u32(&s))
    }
    pub fn u32_le(&self, off: usize) -> Result<u32, TvbError> {
        self.read::<4>(off).map(|s| LittleEndian::read_u32(&s))
    }
    pub fn u64_be(&self, off: usize) -> Result<u64, TvbError> {
        self.read::<8>(off).map(|s| BigEndian::read_u64(&s))
    }
    pub fn u64_le(&self, off: usize) -> Result<u64, TvbError> {
        self.read::<8>(off).map(|s| LittleEndian::read_u64(&s))
    }

    pub fn bytes(&self, off: usize, len: usize) -> Result<&'a [u8], TvbError> {
        self.bytes.get(off..off + len).ok_or(TvbError::ShortBuffer)
    }

    /// Read a `len`-byte ASCII string. Stops at NUL.
    pub fn string_ascii(&self, off: usize, len: usize) -> Result<&'a str, TvbError> {
        let s = self.bytes(off, len)?;
        let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
        std::str::from_utf8(&s[..end]).map_err(|_| TvbError::InvalidString)
    }

    /// Read a NUL-terminated ASCII string starting at `off` (up to remaining length).
    pub fn cstring(&self, off: usize) -> Result<&'a str, TvbError> {
        if off >= self.bytes.len() {
            return Err(TvbError::ShortBuffer);
        }
        let rest = &self.bytes[off..];
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        std::str::from_utf8(&rest[..end]).map_err(|_| TvbError::InvalidString)
    }

    fn read<const N: usize>(&self, off: usize) -> Result<[u8; N], TvbError> {
        let s = self.bytes.get(off..off + N).ok_or(TvbError::ShortBuffer)?;
        let mut out = [0u8; N];
        out.copy_from_slice(s);
        Ok(out)
    }

    pub fn ipv4(&self, off: usize) -> Result<std::net::Ipv4Addr, TvbError> {
        let s = self.read::<4>(off)?;
        Ok(std::net::Ipv4Addr::new(s[0], s[1], s[2], s[3]))
    }

    pub fn ipv6(&self, off: usize) -> Result<std::net::Ipv6Addr, TvbError> {
        let s = self.read::<16>(off)?;
        Ok(std::net::Ipv6Addr::from(s))
    }

    pub fn mac(&self, off: usize) -> Result<[u8; 6], TvbError> {
        self.read::<6>(off)
    }
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum TvbError {
    #[error("short buffer / read past end")]
    ShortBuffer,
    #[error("invalid utf-8 / ascii string")]
    InvalidString,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_reads() {
        let buf = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let t = Tvb::new(&buf);
        assert_eq!(t.u8(0).unwrap(), 0xAA);
        assert_eq!(t.u16_be(0).unwrap(), 0xAABB);
        assert_eq!(t.u16_le(0).unwrap(), 0xBBAA);
        assert_eq!(t.u24_be(0).unwrap(), 0xAABBCC);
        assert_eq!(t.u32_be(0).unwrap(), 0xAABBCCDD);
        assert!(t.u64_be(0).is_err());
    }

    #[test]
    fn ip_reads() {
        let buf = [0xC0, 0xA8, 0x01, 0x01];
        let t = Tvb::new(&buf);
        assert_eq!(t.ipv4(0).unwrap().to_string(), "192.168.1.1");
    }

    #[test]
    fn subset_keeps_abs() {
        let buf = [0u8; 100];
        let t = Tvb::new(&buf);
        let s = t.subset(10, 20);
        assert_eq!(s.abs_off, 10);
        assert_eq!(s.len(), 20);
    }

    #[test]
    fn cstring_stops_at_nul() {
        let buf = b"hello\0extra";
        let t = Tvb::new(buf);
        assert_eq!(t.cstring(0).unwrap(), "hello");
    }
}
