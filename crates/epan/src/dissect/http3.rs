//! HTTP/3 frame header (over QUIC).

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { ty: FieldId, len: FieldId }

#[derive(Default)] pub struct Http3Dissector;
impl Dissector for Http3Dissector {
    fn name(&self) -> &'static str { "http3" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("HyperText Transfer Protocol 3", "http3", "http3");
        let f = Fields {
            ty: reg.register_field(ProtoField::simple("http3.frame_type", "Frame Type", FieldType::U64, FieldDisplay::BaseDec)),
            len: reg.register_field(ProtoField::simple("http3.frame_length", "Frame Length", FieldType::U64, FieldDisplay::BaseDec)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        let f = F.get().unwrap();
        pinfo.current_proto = "http3".into();
        tree.append_proto("http3");
        let mut root = ProtoItem::subtree(f.ty, "HTTP/3".into(), 0, tvb.len());
        let (ty, n1) = read_varint(tvb.as_slice(), 0);
        let (len, n2) = read_varint(tvb.as_slice(), n1);
        root.push(ProtoItem::new(f.ty, FieldValue::U64(ty), 0, n1));
        root.push(ProtoItem::new(f.len, FieldValue::U64(len), n1, n2));
        tree.push(root);
        DissectResult::Ok(tvb.len())
    }
}

fn read_varint(b: &[u8], off: usize) -> (u64, usize) {
    if off >= b.len() { return (0, 0); }
    let first = b[off];
    let tag = first >> 6;
    let len = 1usize << tag;
    if off + len > b.len() { return (0, len); }
    let mut v = (first & 0x3F) as u64;
    for i in 1..len {
        v = (v << 8) | b[off + i] as u64;
    }
    (v, len)
}
