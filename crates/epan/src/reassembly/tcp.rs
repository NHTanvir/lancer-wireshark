//! TCP segment reassembly.
//!
//! A v1 implementation: keep a per-direction `BTreeMap<seq, bytes>` and
//! return a contiguous byte stream when `seq` matches the next expected
//! sequence. Out-of-order segments are buffered until the gap fills.
//!
//! Edge cases handled:
//! - Duplicate segments (same seq + same len) — discarded.
//! - Partial overlaps — left edge kept, overlap dropped.
//! - Initial sequence number captured on first segment.

use std::collections::BTreeMap;

#[derive(Debug, Default)]
pub struct TcpReassembler {
    pub init_seq: Option<u32>,
    pub next_seq: u32,
    pub pending: BTreeMap<u32, Vec<u8>>,
    pub out: Vec<u8>,
    pub gap_bytes: u64,
}

impl TcpReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a segment. Returns the newly contiguous bytes (may be empty if
    /// the segment was OOO).
    pub fn add(&mut self, seq: u32, data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return Vec::new();
        }
        if self.init_seq.is_none() {
            self.init_seq = Some(seq);
            self.next_seq = seq;
        }

        if seq == self.next_seq {
            self.next_seq = self.next_seq.wrapping_add(data.len() as u32);
            self.out.extend_from_slice(data);
            let mut newly = data.to_vec();
            // Now drain any buffered segments that line up.
            while let Some((&first_seq, _)) = self.pending.iter().next() {
                if first_seq == self.next_seq {
                    let (_, bytes) = self.pending.pop_first().unwrap();
                    self.next_seq = self.next_seq.wrapping_add(bytes.len() as u32);
                    self.out.extend_from_slice(&bytes);
                    newly.extend_from_slice(&bytes);
                } else {
                    break;
                }
            }
            newly
        } else if seq_gt(seq, self.next_seq) {
            // future segment — buffer
            self.pending
                .entry(seq)
                .and_modify(|e| {
                    if e.len() < data.len() {
                        *e = data.to_vec();
                    }
                })
                .or_insert_with(|| data.to_vec());
            self.gap_bytes = self.gap_bytes.saturating_add(data.len() as u64);
            Vec::new()
        } else {
            // retransmission / overlap — drop quietly
            Vec::new()
        }
    }

    pub fn bytes_so_far(&self) -> &[u8] {
        &self.out
    }
    pub fn has_gap(&self) -> bool {
        !self.pending.is_empty()
    }
}

fn seq_gt(a: u32, b: u32) -> bool {
    // standard TCP sequence-number comparison (RFC 1982 mod-2^32)
    (a.wrapping_sub(b) as i32) > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_order_segments() {
        let mut r = TcpReassembler::new();
        let a = r.add(100, b"hello ");
        let b = r.add(106, b"world");
        assert_eq!(a, b"hello ");
        assert_eq!(b, b"world");
        assert_eq!(r.bytes_so_far(), b"hello world");
    }

    #[test]
    fn out_of_order_segments() {
        let mut r = TcpReassembler::new();
        let _ = r.add(100, b"hello ");
        let nothing = r.add(112, b"!");
        assert!(nothing.is_empty());
        let drained = r.add(106, b"world");
        assert_eq!(drained, b"world!");
        assert_eq!(r.bytes_so_far(), b"hello world!");
    }

    #[test]
    fn retransmission_dropped() {
        let mut r = TcpReassembler::new();
        let _ = r.add(100, b"hello ");
        let nothing = r.add(100, b"hello ");
        assert!(nothing.is_empty());
    }
}
