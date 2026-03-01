//! IPv6 fragment reassembly via the Fragment Extension Header (next_header=44).

use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FragKey {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub id: u32,
}

#[derive(Debug)]
struct FragState {
    fragments: Vec<(u16, Vec<u8>, bool)>,
    started: Instant,
}

#[derive(Debug, Default)]
pub struct Ipv6Defragmenter {
    by_key: HashMap<FragKey, FragState>,
    ttl: Duration,
}

impl Ipv6Defragmenter {
    pub fn new() -> Self {
        Self {
            by_key: HashMap::new(),
            ttl: Duration::from_secs(60),
        }
    }

    pub fn add(&mut self, k: FragKey, offset: u16, more: bool, payload: &[u8]) -> Option<Vec<u8>> {
        self.gc();
        let entry = self.by_key.entry(k).or_insert_with(|| FragState {
            fragments: Vec::new(),
            started: Instant::now(),
        });
        entry.fragments.push((offset, payload.to_vec(), !more));
        if entry.fragments.iter().any(|(_, _, last)| *last) {
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
