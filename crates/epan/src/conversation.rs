//! Per-flow state stash. Each `Conversation` is keyed by an n-tuple
//! (addr+port both directions, with proto and vlan disambiguating).
//!
//! Stores generic byte segments (used by TCP reassembly + follow-stream),
//! arbitrary typed state via `dyn Any`, and aggregate counters.

use dashmap::DashMap;
use parking_lot::Mutex;
use std::any::Any;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConvKey {
    pub a_addr: IpAddrKey,
    pub a_port: u16,
    pub b_addr: IpAddrKey,
    pub b_port: u16,
    pub proto: u8,
    pub vlan: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpAddrKey {
    V4([u8; 4]),
    V6([u8; 16]),
    None,
}

impl From<Option<IpAddr>> for IpAddrKey {
    fn from(v: Option<IpAddr>) -> Self {
        match v {
            Some(IpAddr::V4(a)) => IpAddrKey::V4(a.octets()),
            Some(IpAddr::V6(a)) => IpAddrKey::V6(a.octets()),
            None => IpAddrKey::None,
        }
    }
}

impl ConvKey {
    /// Build a canonical (sorted) key so both directions hash to the same bucket.
    pub fn canonical(
        a_addr: Option<IpAddr>,
        a_port: u16,
        b_addr: Option<IpAddr>,
        b_port: u16,
        proto: u8,
        vlan: Option<u16>,
    ) -> Self {
        let (a_addr, a_port, b_addr, b_port) = if (a_addr, a_port) <= (b_addr, b_port) {
            (a_addr, a_port, b_addr, b_port)
        } else {
            (b_addr, b_port, a_addr, a_port)
        };
        Self {
            a_addr: IpAddrKey::from(a_addr),
            a_port,
            b_addr: IpAddrKey::from(b_addr),
            b_port,
            proto,
            vlan: vlan.unwrap_or(0),
        }
    }
}

pub struct Conversation {
    pub id: u64,
    pub key: ConvKey,
    pub first_frame: u64,
    pub last_frame: u64,
    pub packets_a_to_b: u64,
    pub packets_b_to_a: u64,
    pub bytes_a_to_b: u64,
    pub bytes_b_to_a: u64,
    pub state: Mutex<ConvState>,
}

#[derive(Default)]
pub struct ConvState {
    pub tcp_a_to_b: BTreeMap<u32, Vec<u8>>, // seq → segment
    pub tcp_b_to_a: BTreeMap<u32, Vec<u8>>,
    pub tcp_init_seq_a: Option<u32>,
    pub tcp_init_seq_b: Option<u32>,
    pub tls_handshake_done: bool,
    pub follow_payload: Vec<FollowChunk>,
    pub extras: Vec<Box<dyn Any + Send>>,
}

#[derive(Debug, Clone)]
pub struct FollowChunk {
    pub direction: Direction,
    pub bytes: Vec<u8>,
    pub frame_number: u64,
    pub timestamp_secs: i64,
    pub timestamp_nanos: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    AtoB,
    BtoA,
}

pub struct ConvTable {
    table: DashMap<ConvKey, Arc<Conversation>>,
    next_id: std::sync::atomic::AtomicU64,
}

impl ConvTable {
    pub fn new() -> Self {
        Self {
            table: DashMap::new(),
            next_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    pub fn get_or_create(&self, key: ConvKey, frame: u64) -> Arc<Conversation> {
        if let Some(c) = self.table.get(&key) {
            return c.clone();
        }
        let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let conv = Arc::new(Conversation {
            id,
            key,
            first_frame: frame,
            last_frame: frame,
            packets_a_to_b: 0,
            packets_b_to_a: 0,
            bytes_a_to_b: 0,
            bytes_b_to_a: 0,
            state: Mutex::new(ConvState::default()),
        });
        self.table.insert(key, conv.clone());
        conv
    }

    pub fn get(&self, key: ConvKey) -> Option<Arc<Conversation>> {
        self.table.get(&key).map(|r| r.clone())
    }

    pub fn iter(&self) -> Vec<Arc<Conversation>> {
        self.table.iter().map(|r| r.value().clone()).collect()
    }

    pub fn len(&self) -> usize {
        self.table.len()
    }

    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }
}

impl Default for ConvTable {
    fn default() -> Self {
        Self::new()
    }
}
