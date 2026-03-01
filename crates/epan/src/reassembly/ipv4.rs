//! IPv4 fragment reassembly.
//!
//! Keyed by (src, dst, proto, id). Reassembles when all fragments arrive
//! contiguously; otherwise tracks a per-key fragment list with a TTL.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FragKey {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub proto: u8,
    pub id: u16,
}

#[derive(Debug)]
struct FragState {
    fragments: Vec<(u16, Vec<u8>, bool)>, // (offset_in_bytes, data, last_flag)
    started: Instant,
    total_len_seen: Option<u16>,
}

#[derive(Debug, Default)]
pub struct Ipv4Defragmenter {
    by_key: HashMap<FragKey, FragState>,
    ttl: Duration,
}

impl Ipv4Defragmenter {
    pub fn new() -> Self {
        Self {
            by_key: HashMap::new(),
            ttl: Duration::from_secs(30),
        }
    }

    pub fn add(&mut self, k: FragKey, offset: u16, more_fragments: bool, payload: &[u8]) -> Option<Vec<u8>> {
        self.gc();
        let entry = self.by_key.entry(k).or_insert_with(|| FragState {
            fragments: Vec::new(),
            started: Instant::now(),
            total_len_seen: None,
        });
        entry.fragments.push((offset, payload.to_vec(), !more_fragments));
        if !more_fragments {
            entry.total_len_seen = Some(offset + payload.len() as u16);
        }

        if entry.fragments.iter().any(|(_, _, last)| *last) {
            // try to assemble
            let mut frags = entry.fragments.clone();
            frags.sort_by_key(|f| f.0);
            let mut out = Vec::new();
            let mut expected: u16 = 0;
            for (off, data, _) in frags {
                if off != expected {
                    return None;
                }
                out.extend_from_slice(&data);
                expected = expected.saturating_add(data.len() as u16);
            }
            self.by_key.remove(&k);
            return Some(out);
        }
        None
    }

    fn gc(&mut self) {
        let ttl = self.ttl;
        self.by_key.retain(|_, s| s.started.elapsed() < ttl);
    }
}
