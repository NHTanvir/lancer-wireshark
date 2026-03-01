//! Endian-aware byte access helpers.

use byteorder::{BigEndian, ByteOrder, LittleEndian};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Big,
    Little,
}

pub trait BytesExt {
    fn read_u8_at(&self, off: usize) -> Option<u8>;
    fn read_u16_at(&self, off: usize, e: Endian) -> Option<u16>;
    fn read_u32_at(&self, off: usize, e: Endian) -> Option<u32>;
    fn read_u64_at(&self, off: usize, e: Endian) -> Option<u64>;
    fn read_i16_at(&self, off: usize, e: Endian) -> Option<i16>;
    fn read_i32_at(&self, off: usize, e: Endian) -> Option<i32>;
    fn read_i64_at(&self, off: usize, e: Endian) -> Option<i64>;
    fn read_slice_at(&self, off: usize, len: usize) -> Option<&[u8]>;
}

impl BytesExt for [u8] {
    fn read_u8_at(&self, off: usize) -> Option<u8> {
        self.get(off).copied()
    }
    fn read_u16_at(&self, off: usize, e: Endian) -> Option<u16> {
        if off + 2 > self.len() {
            return None;
        }
        Some(match e {
            Endian::Big => BigEndian::read_u16(&self[off..off + 2]),
            Endian::Little => LittleEndian::read_u16(&self[off..off + 2]),
        })
    }
    fn read_u32_at(&self, off: usize, e: Endian) -> Option<u32> {
        if off + 4 > self.len() {
            return None;
        }
        Some(match e {
            Endian::Big => BigEndian::read_u32(&self[off..off + 4]),
            Endian::Little => LittleEndian::read_u32(&self[off..off + 4]),
        })
    }
    fn read_u64_at(&self, off: usize, e: Endian) -> Option<u64> {
        if off + 8 > self.len() {
            return None;
        }
        Some(match e {
            Endian::Big => BigEndian::read_u64(&self[off..off + 8]),
            Endian::Little => LittleEndian::read_u64(&self[off..off + 8]),
        })
    }
    fn read_i16_at(&self, off: usize, e: Endian) -> Option<i16> {
        self.read_u16_at(off, e).map(|v| v as i16)
    }
    fn read_i32_at(&self, off: usize, e: Endian) -> Option<i32> {
        self.read_u32_at(off, e).map(|v| v as i32)
    }
    fn read_i64_at(&self, off: usize, e: Endian) -> Option<i64> {
        self.read_u64_at(off, e).map(|v| v as i64)
    }
    fn read_slice_at(&self, off: usize, len: usize) -> Option<&[u8]> {
        self.get(off..off + len)
    }
}

/// XOR every byte of `dst` with the corresponding byte of `key`,
/// cycling through `key` when it is shorter.
pub fn xor_inplace(dst: &mut [u8], key: &[u8]) {
    if key.is_empty() {
        return;
    }
    for (i, b) in dst.iter_mut().enumerate() {
        *b ^= key[i % key.len()];
    }
}
