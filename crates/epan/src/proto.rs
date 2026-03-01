//! `ProtoTree`, `ProtoItem`, `ProtoField` — the labeled-tree structure
//! every dissector builds.
//!
//! Each leaf carries:
//! - a `FieldId` (looked up in [`crate::Registry`]),
//! - a value (typed),
//! - the absolute byte range it covers in the original capture.
//!
//! Both display and the display-filter DSL evaluate against this tree.

use crate::register::FieldId;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldType {
    None,
    Boolean,
    U8,
    U16,
    U24,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    Float,
    Double,
    String,
    Bytes,
    Ipv4,
    Ipv6,
    Ether,
    AbsoluteTime,
    RelativeTime,
    Guid,
    Oid,
    Protocol,
    Framenum,
    Eui64,
    Uint64Hex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldDisplay {
    BaseNone,
    BaseDec,
    BaseHex,
    BaseOct,
    BaseBin,
    BaseDecHex,
    BaseHexDec,
    StrAscii,
    StrUnicode,
    SepDot,
    SepDash,
    SepColon,
}

#[derive(Debug, Clone)]
pub struct ProtoField {
    pub abbr: &'static str,
    pub display_name: &'static str,
    pub ty: FieldType,
    pub display: FieldDisplay,
    pub mask: u64,
    pub blurb: &'static str,
    pub vals: Option<&'static [wsutil::ValStr]>,
}

impl ProtoField {
    pub const fn simple(
        abbr: &'static str,
        display_name: &'static str,
        ty: FieldType,
        display: FieldDisplay,
    ) -> Self {
        ProtoField {
            abbr,
            display_name,
            ty,
            display,
            mask: 0,
            blurb: "",
            vals: None,
        }
    }
    pub const fn with_vals(mut self, vals: &'static [wsutil::ValStr]) -> Self {
        self.vals = Some(vals);
        self
    }
    pub const fn with_mask(mut self, mask: u64) -> Self {
        self.mask = mask;
        self
    }
    pub const fn with_blurb(mut self, blurb: &'static str) -> Self {
        self.blurb = blurb;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FieldValue {
    None,
    Bool(bool),
    U64(u64),
    I64(i64),
    F64(f64),
    Str(String),
    Bytes(Vec<u8>),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Ether([u8; 6]),
    Time { secs: i64, nanos: u32 },
    Oid(Vec<u32>),
    Frame(u32),
    Eui64([u8; 8]),
    Guid([u8; 16]),
}

impl FieldValue {
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            FieldValue::Bool(b) => Some(*b as u64),
            FieldValue::U64(v) => Some(*v),
            FieldValue::I64(v) if *v >= 0 => Some(*v as u64),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            FieldValue::Bool(b) => Some(*b as i64),
            FieldValue::U64(v) if *v <= i64::MAX as u64 => Some(*v as i64),
            FieldValue::I64(v) => Some(*v),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            FieldValue::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            FieldValue::Bytes(b) => Some(b),
            FieldValue::Str(s) => Some(s.as_bytes()),
            _ => None,
        }
    }
    pub fn as_ipv4(&self) -> Option<Ipv4Addr> {
        match self {
            FieldValue::Ipv4(a) => Some(*a),
            _ => None,
        }
    }
    pub fn as_ipv6(&self) -> Option<Ipv6Addr> {
        match self {
            FieldValue::Ipv6(a) => Some(*a),
            _ => None,
        }
    }
    pub fn display(&self, display: FieldDisplay, vals: Option<&[wsutil::ValStr]>) -> String {
        match self {
            FieldValue::None => String::new(),
            FieldValue::Bool(b) => if *b { "True".into() } else { "False".into() },
            FieldValue::U64(v) => match display {
                FieldDisplay::BaseHex => format!("0x{v:x}"),
                FieldDisplay::BaseOct => format!("0o{v:o}"),
                FieldDisplay::BaseBin => format!("0b{v:b}"),
                FieldDisplay::BaseDecHex => format!("{v} (0x{v:x})"),
                FieldDisplay::BaseHexDec => format!("0x{v:x} ({v})"),
                _ => {
                    if let Some(vs) = vals {
                        if let Some(s) = wsutil::valstr::val_to_str(*v as u32, vs) {
                            return format!("{s} ({v})");
                        }
                    }
                    format!("{v}")
                }
            },
            FieldValue::I64(v) => format!("{v}"),
            FieldValue::F64(v) => format!("{v}"),
            FieldValue::Str(s) => s.clone(),
            FieldValue::Bytes(b) => hex::encode(b),
            FieldValue::Ipv4(a) => a.to_string(),
            FieldValue::Ipv6(a) => a.to_string(),
            FieldValue::Ether(m) => wsutil::mac::format_mac(*m),
            FieldValue::Time { secs, nanos } => {
                wsutil::time::format_timestamp(*secs, *nanos, (0, 0), (0, 0), wsutil::time::TimeFmt::AbsoluteWithDate)
            }
            FieldValue::Oid(o) => o.iter().map(|p| p.to_string()).collect::<Vec<_>>().join("."),
            FieldValue::Frame(f) => format!("{f}"),
            FieldValue::Eui64(b) => hex::encode(b),
            FieldValue::Guid(b) => hex::encode(b),
        }
    }
}

/// A single labelled node in the tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtoItem {
    pub field: FieldId,
    pub value: FieldValue,
    /// Absolute byte offset in the original packet.
    pub abs_offset: usize,
    pub length: usize,
    pub label: Option<String>,
    pub children: Vec<ProtoItem>,
    /// True if this item is a synthetic "header" item that should display
    /// as an expandable subtree with no value.
    pub is_subtree: bool,
}

impl ProtoItem {
    pub fn new(field: FieldId, value: FieldValue, abs_offset: usize, length: usize) -> Self {
        Self {
            field,
            value,
            abs_offset,
            length,
            label: None,
            children: Vec::new(),
            is_subtree: false,
        }
    }
    pub fn subtree(field: FieldId, label: String, abs_offset: usize, length: usize) -> Self {
        Self {
            field,
            value: FieldValue::None,
            abs_offset,
            length,
            label: Some(label),
            children: Vec::new(),
            is_subtree: true,
        }
    }
    pub fn with_label(mut self, label: String) -> Self {
        self.label = Some(label);
        self
    }
    pub fn push(&mut self, child: ProtoItem) {
        self.children.push(child);
    }
    pub fn append_child(&mut self, child: ProtoItem) -> &mut ProtoItem {
        self.children.push(child);
        self.children.last_mut().unwrap()
    }
}

/// The root of one packet's dissection tree.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtoTree {
    pub items: Vec<ProtoItem>,
    /// Stack of protocol names in dispatch order (eth, ip, tcp, tls, http, ...).
    pub proto_stack: Vec<String>,
}

impl ProtoTree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, item: ProtoItem) {
        self.items.push(item);
    }
    pub fn append_proto(&mut self, name: &str) {
        self.proto_stack.push(name.to_string());
    }

    /// Recursively visit every item with `f`.
    pub fn walk(&self, mut f: impl FnMut(&ProtoItem)) {
        fn rec(item: &ProtoItem, f: &mut dyn FnMut(&ProtoItem)) {
            f(item);
            for c in &item.children {
                rec(c, f);
            }
        }
        for it in &self.items {
            rec(it, &mut f);
        }
    }

    /// Collect every field value whose registered abbreviation matches `abbr`.
    pub fn find_all<'a>(&'a self, reg: &'a crate::register::Registry, abbr: &str) -> Vec<&'a ProtoItem> {
        let mut out = Vec::new();
        let target_id = reg.field_id_by_abbr(abbr);
        self.walk(|item| {
            if let Some(id) = target_id {
                if item.field == id {
                    out.push(item as *const _);
                }
            } else if let Some(name) = reg.field_abbr(item.field) {
                if name == abbr {
                    out.push(item as *const _);
                }
            }
        });
        // SAFETY: we only used pointers inside the closure to escape lifetime
        // checks; convert back to references tied to `&self`.
        out.into_iter().map(|p| unsafe { &*p }).collect()
    }

    pub fn first_layer(&self) -> Option<&str> {
        self.proto_stack.first().map(|s| s.as_str())
    }
    pub fn last_layer(&self) -> Option<&str> {
        self.proto_stack.last().map(|s| s.as_str())
    }
    pub fn contains_proto(&self, name: &str) -> bool {
        self.proto_stack.iter().any(|s| s == name)
    }
}
