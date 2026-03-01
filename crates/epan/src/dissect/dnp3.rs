//! DNP3 (Distributed Network Protocol 3) — minimal data-link header.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { start: FieldId, length: FieldId, ctrl: FieldId, dst: FieldId, src: FieldId }

#[derive(Default)] pub struct Dnp3Dissector;
impl Dissector for Dnp3Dissector {
    fn name(&self) -> &'static str { "dnp3" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Distributed Network Protocol 3.0", "dnp3", "dnp3");
        let f = Fields {
            start: reg.register_field(ProtoField::simple("dnp3.start", "Start", FieldType::U16, FieldDisplay::BaseHex)),
            length: reg.register_field(ProtoField::simple("dnp3.len", "Length", FieldType::U8, FieldDisplay::BaseDec)),
            ctrl: reg.register_field(ProtoField::simple("dnp3.ctl", "Control", FieldType::U8, FieldDisplay::BaseHex)),
            dst: reg.register_field(ProtoField::simple("dnp3.dst", "Destination", FieldType::U16, FieldDisplay::BaseDec)),
            src: reg.register_field(ProtoField::simple("dnp3.src", "Source", FieldType::U16, FieldDisplay::BaseDec)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 8 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "dnp3".into();
        tree.append_proto("dnp3");
        let mut root = ProtoItem::subtree(f.start, "DNP3".into(), 0, 8);
        root.push(ProtoItem::new(f.start, FieldValue::U64(tvb.u16_be(0).unwrap_or(0) as u64), 0, 2));
        root.push(ProtoItem::new(f.length, FieldValue::U64(tvb.u8(2).unwrap_or(0) as u64), 2, 1));
        root.push(ProtoItem::new(f.ctrl, FieldValue::U64(tvb.u8(3).unwrap_or(0) as u64), 3, 1));
        root.push(ProtoItem::new(f.dst, FieldValue::U64(tvb.u16_le(4).unwrap_or(0) as u64), 4, 2));
        root.push(ProtoItem::new(f.src, FieldValue::U64(tvb.u16_le(6).unwrap_or(0) as u64), 6, 2));
        tree.push(root);
        DissectResult::Ok(8)
    }
}
