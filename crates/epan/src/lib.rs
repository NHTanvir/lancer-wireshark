//! `epan` — Enhanced Packet ANalyzer.
//!
//! Hosts the dissection engine, display-filter DSL, reassembly,
//! decryption hooks, expert info, conversation tracking and the
//! per-protocol dissector modules under [`dissect`].
//!
//! Top-level types:
//! - [`tvb::Tvb`]               — zero-copy buffer over a captured packet
//! - [`proto::ProtoTree`]       — labeled span tree built by dissectors
//! - [`register::Registry`]     — field + dissector-table registry
//! - [`dissector::Dissector`]   — trait every protocol implements
//! - [`pinfo::PInfo`]           — per-packet metadata + summary line
//! - [`conversation::ConvTable`] — per-flow state stash
//! - [`expert::Expert`]         — expert-info severity collector
//! - [`tap::TapBus`]            — fan-out for statistics commands
//! - [`dfilter`]                — display-filter compile + eval

pub mod tvb;
pub mod proto;
pub mod register;
pub mod dissector;
pub mod pinfo;
pub mod conversation;
pub mod expert;
pub mod tap;
pub mod dfilter;
pub mod reassembly;
pub mod crypt;
pub mod dissect;
pub mod heuristic;
pub mod decode_as;
pub mod follow;

pub use tvb::Tvb;
pub use proto::{ProtoTree, ProtoItem, ProtoField, FieldType, FieldDisplay};
pub use register::{Registry, FieldId, ProtoId};
pub use dissector::{Dissector, DissectorRef, DissectorTable, DissectResult};
pub use pinfo::PInfo;
pub use conversation::{Conversation, ConvKey, ConvTable};
pub use expert::{Expert, ExpertSeverity, ExpertGroup};
pub use tap::{Tap, TapBus, TapEvent};
pub use dfilter::{Dfilter, DfilterError};
pub use heuristic::HeuristicDissector;
pub use decode_as::{DecodeAsEntry, DecodeAsTable};
pub use follow::{FollowStream, FollowMode, FollowProto, FollowExtractor};

/// Convenience handle returned by [`Engine::new`] — owns the registry,
/// conversation table, name resolver, expert collector and tap bus.
pub struct Engine {
    pub registry: register::Registry,
    pub conversations: conversation::ConvTable,
    pub names: std::sync::Arc<wsutil::NameResolver>,
    pub tap: tap::TapBus,
    pub decode_as: decode_as::DecodeAsTable,
    pub disabled_protos: parking_lot::RwLock<std::collections::HashSet<String>>,
    pub disabled_heuristics: parking_lot::RwLock<std::collections::HashSet<String>>,
    pub frame_count: std::sync::atomic::AtomicU64,
}

impl Engine {
    pub fn new() -> Self {
        let mut reg = register::Registry::new();
        dissect::register_builtin(&mut reg);
        Self {
            registry: reg,
            conversations: conversation::ConvTable::new(),
            names: std::sync::Arc::new(wsutil::NameResolver::new()),
            tap: tap::TapBus::new(),
            decode_as: decode_as::DecodeAsTable::new(),
            disabled_protos: parking_lot::RwLock::new(Default::default()),
            disabled_heuristics: parking_lot::RwLock::new(Default::default()),
            frame_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn disable_protocol(&self, name: &str) {
        self.disabled_protos.write().insert(name.to_string());
    }

    pub fn enable_protocol(&self, name: &str) {
        self.disabled_protos.write().remove(name);
    }

    pub fn is_disabled(&self, name: &str) -> bool {
        self.disabled_protos.read().contains(name)
    }

    pub fn disable_heuristic(&self, name: &str) {
        self.disabled_heuristics.write().insert(name.to_string());
    }

    pub fn enable_heuristic(&self, name: &str) {
        self.disabled_heuristics.write().remove(name);
    }

    pub fn is_heuristic_disabled(&self, name: &str) -> bool {
        self.disabled_heuristics.read().contains(name)
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}
