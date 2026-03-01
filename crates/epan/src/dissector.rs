//! The [`Dissector`] trait and the [`DissectorTable`] dispatch type.
//!
//! Concrete protocol dissectors live under [`crate::dissect`] and register
//! themselves at engine startup.

use crate::pinfo::PInfo;
use crate::proto::ProtoTree;
use crate::tvb::Tvb;
use dashmap::DashMap;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DissectResult {
    /// Successfully dissected `n` bytes.
    Ok(usize),
    /// Could not dissect (handed back to caller / heuristic to try next).
    NotForUs,
    /// Buffer is shorter than the protocol header — caller may try reassembly.
    NeedMoreData,
}

pub trait Dissector: Send + Sync {
    fn name(&self) -> &'static str;
    fn register(&self, reg: &mut crate::register::Registry);
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult;
}

pub type DissectorRef = Arc<dyn Dissector>;

/// Per-port / per-string dispatch table (e.g. `tcp.port` → `https` → TLS).
pub struct DissectorTable {
    pub name: String,
    by_uint: DashMap<u32, DissectorRef>,
    by_string: DashMap<String, DissectorRef>,
    default: parking_lot::RwLock<Option<DissectorRef>>,
}

impl DissectorTable {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            by_uint: DashMap::new(),
            by_string: DashMap::new(),
            default: parking_lot::RwLock::new(None),
        }
    }

    pub fn add_uint(&self, key: u32, d: DissectorRef) {
        self.by_uint.insert(key, d);
    }
    pub fn add_string(&self, key: impl Into<String>, d: DissectorRef) {
        self.by_string.insert(key.into(), d);
    }
    pub fn set_default(&self, d: DissectorRef) {
        *self.default.write() = Some(d);
    }

    pub fn lookup_uint(&self, key: u32) -> Option<DissectorRef> {
        self.by_uint.get(&key).map(|r| r.clone()).or_else(|| self.default.read().clone())
    }
    pub fn lookup_string(&self, key: &str) -> Option<DissectorRef> {
        self.by_string.get(key).map(|r| r.clone()).or_else(|| self.default.read().clone())
    }

    pub fn list_uint(&self) -> Vec<(u32, String)> {
        self.by_uint
            .iter()
            .map(|r| (*r.key(), r.value().name().to_string()))
            .collect()
    }
    pub fn list_string(&self) -> Vec<(String, String)> {
        self.by_string
            .iter()
            .map(|r| (r.key().clone(), r.value().name().to_string()))
            .collect()
    }
}
