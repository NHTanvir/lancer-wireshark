//! DCCP — generic short header decoding.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { srcport: FieldId, dstport: FieldId, ty: FieldId }

#[derive(Default)] pub struct DccpDissector;
impl Dissector for DccpDissector {
    fn name(&self) -> &'static str { "dccp" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Datagram Congestion Control Protocol", "dccp", "dccp");
        let f = Fields {
            srcport: reg.register_field(ProtoField::simple("dccp.srcport", "Source Port", FieldType::U16, FieldDisplay::BaseDec)),
            dstport: reg.register_field(ProtoField::simple("dccp.dstport", "Destination Port", FieldType::U16, FieldDisplay::BaseDec)),
            ty: reg.register_field(ProtoField::simple("dccp.type", "Packet Type", FieldType::U8, FieldDisplay::BaseDec)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 12 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "dccp".into();
        tree.append_proto("dccp");
        let mut root = ProtoItem::subtree(f.srcport, "DCCP".into(), 0, 12);
        root.push(ProtoItem::new(f.srcport, FieldValue::U64(tvb.u16_be(0).unwrap_or(0) as u64), 0, 2));
        root.push(ProtoItem::new(f.dstport, FieldValue::U64(tvb.u16_be(2).unwrap_or(0) as u64), 2, 2));
        root.push(ProtoItem::new(f.ty, FieldValue::U64(((tvb.u8(8).unwrap_or(0) >> 1) & 0x0F) as u64), 8, 1));
        tree.push(root);
        DissectResult::Ok(12)
    }
}
