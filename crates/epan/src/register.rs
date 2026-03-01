//! Field + dissector-table registry. One-time-init populated at startup
//! by [`crate::dissect::register_builtin`].

use crate::dissector::{DissectorRef, DissectorTable};
use crate::proto::ProtoField;
use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

/// Numeric handle for a registered field. Cheap to copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct FieldId(pub u32);

/// Numeric handle for a registered protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ProtoId(pub u32);

#[derive(Debug)]
pub struct ProtocolMeta {
    pub id: ProtoId,
    pub name: String,        // "TCP"
    pub short_name: String,  // "tcp"
    pub filter_name: String, // "tcp"
    pub fields: Vec<FieldId>,
    pub description: String,
}

pub struct Registry {
    fields: RwLock<Vec<ProtoField>>,
    abbr_to_id: DashMap<String, FieldId>,
    protocols: RwLock<Vec<ProtocolMeta>>,
    short_to_proto: DashMap<String, ProtoId>,
    /// Named dispatch tables (`tcp.port`, `udp.port`, `tls.handshake.type`, …).
    tables: DashMap<String, Arc<DissectorTable>>,
    /// Dissectors indexed by name (for `--decode-as` and Lua scripts).
    dissectors_by_name: DashMap<String, DissectorRef>,
    /// Heuristic dissector lists per table (`tcp.heur`, `udp.heur`, …).
    heuristics: DashMap<String, RwLock<Vec<(String, DissectorRef)>>>,
    /// Post-dissectors run after every full dissection.
    post_dissectors: RwLock<Vec<DissectorRef>>,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            fields: RwLock::new(Vec::with_capacity(8192)),
            abbr_to_id: DashMap::new(),
            protocols: RwLock::new(Vec::with_capacity(256)),
            short_to_proto: DashMap::new(),
            tables: DashMap::new(),
            dissectors_by_name: DashMap::new(),
            heuristics: DashMap::new(),
            post_dissectors: RwLock::new(Vec::new()),
        }
    }

    pub fn register_field(&mut self, f: ProtoField) -> FieldId {
        let mut fields = self.fields.write();
        let id = FieldId(fields.len() as u32);
        let abbr = f.abbr.to_string();
        fields.push(f);
        drop(fields);
        self.abbr_to_id.insert(abbr, id);
        id
    }

    pub fn field(&self, id: FieldId) -> Option<ProtoField> {
        self.fields.read().get(id.0 as usize).cloned()
    }
    pub fn field_abbr(&self, id: FieldId) -> Option<&'static str> {
        // The original `abbr` is `&'static str`, but stored ProtoField copies
        // it — we re-borrow the static via the registered field record.
        let lock = self.fields.read();
        lock.get(id.0 as usize).map(|f| f.abbr)
    }
    pub fn field_id_by_abbr(&self, abbr: &str) -> Option<FieldId> {
        self.abbr_to_id.get(abbr).map(|r| *r.value())
    }
    pub fn fields_iter(&self) -> Vec<(FieldId, ProtoField)> {
        self.fields
            .read()
            .iter()
            .enumerate()
            .map(|(i, f)| (FieldId(i as u32), f.clone()))
            .collect()
    }

    pub fn register_protocol(&mut self, name: &str, short: &str, filter: &str) -> ProtoId {
        let mut p = self.protocols.write();
        let id = ProtoId(p.len() as u32);
        p.push(ProtocolMeta {
            id,
            name: name.into(),
            short_name: short.into(),
            filter_name: filter.into(),
            fields: Vec::new(),
            description: String::new(),
        });
        drop(p);
        self.short_to_proto.insert(short.to_string(), id);
        id
    }

    pub fn protocol(&self, id: ProtoId) -> Option<ProtocolMeta> {
        let p = self.protocols.read();
        p.get(id.0 as usize).map(|m| ProtocolMeta {
            id: m.id,
            name: m.name.clone(),
            short_name: m.short_name.clone(),
            filter_name: m.filter_name.clone(),
            fields: m.fields.clone(),
            description: m.description.clone(),
        })
    }

    pub fn proto_id_by_short(&self, short: &str) -> Option<ProtoId> {
        self.short_to_proto.get(short).map(|r| *r.value())
    }

    pub fn protocols_iter(&self) -> Vec<(ProtoId, String, String)> {
        self.protocols
            .read()
            .iter()
            .map(|p| (p.id, p.short_name.clone(), p.name.clone()))
            .collect()
    }

    pub fn table(&self, name: &str) -> Arc<DissectorTable> {
        if let Some(t) = self.tables.get(name) {
            return t.clone();
        }
        let t = Arc::new(DissectorTable::new(name));
        self.tables.insert(name.to_string(), t.clone());
        t
    }

    pub fn tables_iter(&self) -> Vec<String> {
        let mut v: Vec<_> = self.tables.iter().map(|r| r.key().clone()).collect();
        v.sort();
        v
    }

    pub fn register_dissector(&self, name: &str, d: DissectorRef) {
        self.dissectors_by_name.insert(name.to_string(), d);
    }

    pub fn dissector(&self, name: &str) -> Option<DissectorRef> {
        self.dissectors_by_name.get(name).map(|r| r.clone())
    }

    pub fn register_heuristic(&self, table: &str, name: &str, d: DissectorRef) {
        self.heuristics
            .entry(table.to_string())
            .or_insert_with(|| RwLock::new(Vec::new()))
            .write()
            .push((name.to_string(), d));
    }

    pub fn heuristics(&self, table: &str) -> Vec<(String, DissectorRef)> {
        self.heuristics
            .get(table)
            .map(|r| r.read().clone())
            .unwrap_or_default()
    }

    pub fn heuristic_tables(&self) -> Vec<String> {
        let mut v: Vec<_> = self.heuristics.iter().map(|r| r.key().clone()).collect();
        v.sort();
        v
    }

    pub fn register_post(&self, d: DissectorRef) {
        self.post_dissectors.write().push(d);
    }
    pub fn post_dissectors(&self) -> Vec<DissectorRef> {
        self.post_dissectors.read().clone()
    }

    /// Render a `-G fields` / `-G protocols` style report.
    pub fn report_fields(&self) -> String {
        let mut out = String::new();
        for (id, f) in self.fields_iter() {
            out.push_str(&format!(
                "F\t{}\t{}\t{:?}\t{:?}\t0x{:x}\n",
                f.abbr, f.display_name, f.ty, f.display, f.mask
            ));
            let _ = id;
        }
        out
    }
    pub fn report_protocols(&self) -> String {
        let mut out = String::new();
        for (_id, short, name) in self.protocols_iter() {
            out.push_str(&format!("{name}\t{short}\n"));
        }
        out
    }
    pub fn report_tables(&self) -> String {
        let mut out = String::new();
        for t in self.tables_iter() {
            out.push_str(&format!("T\t{t}\n"));
        }
        out
    }

    /// Field-paths in a stable order — used by `-G fields` consumers and by
    /// the dfilter autocomplete in the GUI.
    pub fn field_paths(&self) -> Vec<String> {
        let lock = self.fields.read();
        let mut v: Vec<_> = lock.iter().map(|f| f.abbr.to_string()).collect();
        v.sort();
        v
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

// keep an explicit import marker for the HashMap-based lookups built above.
#[allow(dead_code)]
fn _hash_import_marker(_: HashMap<String, FieldId>) {}
