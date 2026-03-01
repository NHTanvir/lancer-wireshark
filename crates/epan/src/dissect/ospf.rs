//! OSPF — header only.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { version: FieldId, ty: FieldId, length: FieldId, router_id: FieldId, area_id: FieldId }

#[derive(Default)] pub struct OspfDissector;
impl Dissector for OspfDissector {
    fn name(&self) -> &'static str { "ospf" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Open Shortest Path First", "ospf", "ospf");
        let f = Fields {
            version: reg.register_field(ProtoField::simple("ospf.version", "Version", FieldType::U8, FieldDisplay::BaseDec)),
            ty: reg.register_field(ProtoField::simple("ospf.msg", "Message Type", FieldType::U8, FieldDisplay::BaseDec)),
            length: reg.register_field(ProtoField::simple("ospf.packet_length", "Packet Length", FieldType::U16, FieldDisplay::BaseDec)),
            router_id: reg.register_field(ProtoField::simple("ospf.srcrouter", "Source Router", FieldType::Ipv4, FieldDisplay::BaseNone)),
            area_id: reg.register_field(ProtoField::simple("ospf.area_id", "Area ID", FieldType::Ipv4, FieldDisplay::BaseNone)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 24 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "ospf".into();
        tree.append_proto("ospf");
        let mut root = ProtoItem::subtree(f.version, "OSPF".into(), 0, 24);
        root.push(ProtoItem::new(f.version, FieldValue::U64(tvb.u8(0).unwrap_or(0) as u64), 0, 1));
        root.push(ProtoItem::new(f.ty, FieldValue::U64(tvb.u8(1).unwrap_or(0) as u64), 1, 1));
        root.push(ProtoItem::new(f.length, FieldValue::U64(tvb.u16_be(2).unwrap_or(0) as u64), 2, 2));
        root.push(ProtoItem::new(f.router_id, FieldValue::Ipv4(tvb.ipv4(4).unwrap_or(std::net::Ipv4Addr::UNSPECIFIED)), 4, 4));
        root.push(ProtoItem::new(f.area_id, FieldValue::Ipv4(tvb.ipv4(8).unwrap_or(std::net::Ipv4Addr::UNSPECIFIED)), 8, 4));
        tree.push(root);
        DissectResult::Ok(24)
    }
}
