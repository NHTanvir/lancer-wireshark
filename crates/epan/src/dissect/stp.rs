//! Spanning Tree Protocol — minimal BPDU header dissector.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { proto_id: FieldId, version: FieldId, ty: FieldId }

#[derive(Default)] pub struct StpDissector;
impl Dissector for StpDissector {
    fn name(&self) -> &'static str { "stp" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Spanning Tree Protocol", "stp", "stp");
        let f = Fields {
            proto_id: reg.register_field(ProtoField::simple("stp.protocol", "Protocol Identifier", FieldType::U16, FieldDisplay::BaseHex)),
            version: reg.register_field(ProtoField::simple("stp.version", "Version", FieldType::U8, FieldDisplay::BaseDec)),
            ty: reg.register_field(ProtoField::simple("stp.type", "BPDU Type", FieldType::U8, FieldDisplay::BaseHex)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 4 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "stp".into();
        tree.append_proto("stp");
        let mut root = ProtoItem::subtree(f.proto_id, "Spanning Tree Protocol".into(), 0, tvb.len());
        root.push(ProtoItem::new(f.proto_id, FieldValue::U64(tvb.u16_be(0).unwrap_or(0) as u64), 0, 2));
        root.push(ProtoItem::new(f.version, FieldValue::U64(tvb.u8(2).unwrap_or(0) as u64), 2, 1));
        root.push(ProtoItem::new(f.ty, FieldValue::U64(tvb.u8(3).unwrap_or(0) as u64), 3, 1));
        tree.push(root);
        DissectResult::Ok(tvb.len())
    }
}
